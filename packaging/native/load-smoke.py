#!/usr/bin/env python3
"""Bounded, isolated SPFBL TCP load test for the native bundle smoke network."""

import argparse
import asyncio
import json
import math
import sys
import time


COMMANDS = {
    "spf": (
        "SPF '192.0.2.25' 'sender@audit.test' 'helo.audit.test' 'recipient@audit.test'\n",
        "LAN",
    ),
    "version": ("VERSION\n", "SPFBL-"),
}


def running_loop():
    # cPanel homologation still runs Python 3.6, which predates get_running_loop.
    getter = getattr(asyncio, "get_running_loop", None)
    return getter() if getter is not None else asyncio.get_event_loop()


def percentile(values, fraction):
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(math.ceil(fraction * len(ordered))) - 1))
    return round(ordered[index], 3)


async def query(host, port, scheduled_at, semaphore, timeout, command, expected_prefix):
    async with semaphore:
        loop = running_loop()
        started = loop.time()
        deadline = started + timeout
        connected_at = None
        phase = "connect"
        writer = None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            connected_at = loop.time()
            phase = "write"
            writer.write(command.encode("ascii"))
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            await asyncio.wait_for(writer.drain(), timeout=remaining)
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise asyncio.TimeoutError()
            phase = "response"
            response = await asyncio.wait_for(reader.read(1024), timeout=remaining)
            value = response.decode("iso-8859-1", "replace").strip()
            completed = loop.time()
            if not value.startswith(expected_prefix):
                return {
                    "ok": False,
                    "error": "unexpected_response",
                    "response_prefix": value[:80],
                    "connect_ms": (connected_at - started) * 1000,
                    "response_ms": (completed - connected_at) * 1000,
                    "dispatch_lag_ms": (started - scheduled_at) * 1000,
                    "end_to_end_ms": (completed - scheduled_at) * 1000,
                    "finished_at": completed,
                }
            return {
                "ok": True,
                "connect_ms": (connected_at - started) * 1000,
                "response_ms": (completed - connected_at) * 1000,
                "dispatch_lag_ms": (started - scheduled_at) * 1000,
                "end_to_end_ms": (completed - scheduled_at) * 1000,
                "service_ms": (completed - started) * 1000,
                "finished_at": completed,
            }
        except Exception as exc:
            completed = loop.time()
            return {
                "ok": False,
                "error": type(exc).__name__,
                "phase": phase,
                "connect_ms": None if connected_at is None else (connected_at - started) * 1000,
                "response_ms": None if connected_at is None else (completed - connected_at) * 1000,
                "dispatch_lag_ms": (started - scheduled_at) * 1000,
                "end_to_end_ms": (completed - scheduled_at) * 1000,
                "service_ms": (completed - started) * 1000,
                "finished_at": completed,
            }
        finally:
            if writer is not None:
                writer.close()
                wait_closed = getattr(writer, "wait_closed", None)
                if wait_closed is not None:
                    try:
                        await wait_closed()
                    except (OSError, RuntimeError):
                        pass


async def run_rate(host, port, rate, duration, max_inflight, timeout, command, expected_prefix):
    loop = running_loop()
    semaphore = asyncio.Semaphore(max_inflight)

    # Warm up the JVM and connection path outside the measured interval.
    for _ in range(20):
        result = await query(host, port, loop.time(), semaphore, timeout, command, expected_prefix)
        if not result["ok"]:
            raise RuntimeError("warm-up failed: " + result["error"])

    count = rate * duration
    start = loop.time() + 0.25
    tasks = []
    for index in range(count):
        scheduled_at = start + (index / float(rate))
        delay = scheduled_at - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        tasks.append(asyncio.ensure_future(
            query(host, port, scheduled_at, semaphore, timeout, command, expected_prefix)
        ))

    results = await asyncio.gather(*tasks)
    elapsed = loop.time() - start
    good = [result for result in results if result["ok"]]
    bad = [result for result in results if not result["ok"]]
    good_in_window = [result for result in good if result["finished_at"] <= start + duration]
    achieved = len(good_in_window) / duration if duration > 0 else 0.0
    completion_qps = len(good) / elapsed if elapsed > 0 else 0.0
    service = [result["service_ms"] for result in results if result.get("service_ms") is not None]
    end_to_end = [result["end_to_end_ms"] for result in results]
    connect = [result["connect_ms"] for result in results if result["connect_ms"] is not None]
    response = [result["response_ms"] for result in results if result["response_ms"] is not None]
    dispatch = [result["dispatch_lag_ms"] for result in results]
    p95_end_to_end = percentile(end_to_end, 0.95)
    max_end_to_end = round(max(end_to_end), 3) if end_to_end else None
    max_service = round(max(service), 3) if service else None
    throughput_pass = not bad and achieved >= rate * 0.95
    return {
        "target_qps": rate,
        "duration_s": duration,
        "offered_requests": count,
        "succeeded": len(good),
        "completed_within_window": len(good_in_window),
        "completion_tail_requests": len(good) - len(good_in_window),
        "failed": len(bad),
        "achieved_qps": round(achieved, 2),
        "completion_qps_including_tail": round(completion_qps, 2),
        "latency_end_to_end_ms": {
            "p50": percentile(end_to_end, 0.50),
            "p95": p95_end_to_end,
            "p99": percentile(end_to_end, 0.99),
            "max": max_end_to_end,
        },
        "latency_targets": {
            "p95_ideal_under_200ms": p95_end_to_end is not None and p95_end_to_end < 200,
            "max_service_within_1s_total_timeout": max_service is not None and max_service <= 1000,
        },
        "latency_service_ms": {
            "p50": percentile(service, 0.50),
            "p95": percentile(service, 0.95),
            "p99": percentile(service, 0.99),
            "max": max_service,
        },
        "latency_connect_ms": {
            "p50": percentile(connect, 0.50),
            "p95": percentile(connect, 0.95),
            "p99": percentile(connect, 0.99),
            "max": round(max(connect), 3) if connect else None,
        },
        "latency_response_after_connect_ms": {
            "p50": percentile(response, 0.50),
            "p95": percentile(response, 0.95),
            "p99": percentile(response, 0.99),
            "max": round(max(response), 3) if response else None,
        },
        "dispatch_lag_ms": {
            "p95": percentile(dispatch, 0.95),
            "max": round(max(dispatch), 3) if dispatch else None,
        },
        "error_samples": [
            {key: result[key] for key in ("error", "phase", "response_prefix") if key in result}
            for result in bad[:10]
        ],
        "throughput_pass": throughput_pass,
        "pass": throughput_pass and max_service is not None and max_service <= 1000,
    }


async def main_async(args):
    tests = []
    command, expected_prefix = COMMANDS[args.mode]
    for rate in args.rates:
        result = await run_rate(
            args.host,
            args.port,
            rate,
            args.duration,
            args.max_inflight,
            args.timeout,
            command,
            expected_prefix,
        )
        tests.append(result)
        print(json.dumps({"stage": result}, sort_keys=True), flush=True)
    return {
        "ok": all(test["pass"] for test in tests),
        "host": args.host,
        "port": args.port,
        "mode": args.mode,
        "command": command.strip(),
        "max_inflight": args.max_inflight,
        "tests": tests,
    }


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=9877)
    parser.add_argument("--mode", choices=sorted(COMMANDS), default="spf")
    parser.add_argument("--rates", default="100,500,1000")
    parser.add_argument("--duration", type=int, default=5, help="seconds per rate")
    parser.add_argument("--max-inflight", type=int, default=512)
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args(argv)
    try:
        args.rates = [int(value) for value in args.rates.split(",")]
    except ValueError:
        parser.error("--rates must be comma-separated positive integers")
    if not args.rates or any(rate <= 0 for rate in args.rates):
        parser.error("--rates must contain positive integers")
    if args.duration < 1 or args.duration > 60:
        parser.error("--duration must be between 1 and 60 seconds")
    if args.max_inflight < 1 or args.max_inflight > 2048:
        parser.error("--max-inflight must be between 1 and 2048")
    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be greater than 0 and no more than 30 seconds")
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be between 1 and 65535")
    return args


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])
    loop = asyncio.get_event_loop()
    try:
        report = loop.run_until_complete(main_async(args))
    finally:
        loop.close()
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
