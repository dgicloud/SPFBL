#!/usr/bin/env python3
"""Sequential TCP latency probe for SPFBL VERSION and SPF requests.

Compatible with Python 3.6 so it can run from a cPanel homologation host.
The SPF probe uses RFC 5737/example.test values and sends no SMTP messages.
"""

import argparse
import json
import math
import socket
import time


COMMANDS = {
    "version": (b"VERSION\n", ("SPFBL-",)),
    "spf": (
        b"SPF '192.0.2.25' 'sender@audit.test' 'helo.audit.test' 'recipient@audit.test'\n",
        ("LAN",),
    ),
}


def percentile(values, fraction):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(math.ceil(fraction * len(ordered))) - 1))
    return round(ordered[index], 3)


def request(host, port, payload, timeout):
    started = time.monotonic()
    response = b""
    with socket.create_connection((host, port), timeout=timeout) as client:
        client.settimeout(timeout)
        client.sendall(payload)
        response = client.recv(1024)
    return (time.monotonic() - started) * 1000.0, response.decode("latin1", "replace").strip()


def run_mode(host, port, mode, samples, timeout):
    payload, expected_prefixes = COMMANDS[mode]
    request(host, port, payload, timeout)  # warm-up, excluded from the measurements
    latencies = []
    responses = {}
    errors = []
    for index in range(samples):
        try:
            elapsed, response = request(host, port, payload, timeout)
            latencies.append(elapsed)
            responses[response] = responses.get(response, 0) + 1
            if not response.startswith(expected_prefixes):
                errors.append({"sample": index + 1, "error": "unexpected_response", "response": response[:120]})
        except Exception as exc:
            errors.append({"sample": index + 1, "error": type(exc).__name__})
    return {
        "mode": mode,
        "samples": samples,
        "successful_responses": len(latencies) - sum(1 for item in errors if item.get("error") == "unexpected_response"),
        "errors": errors,
        "latency_ms": {
            "p50": percentile(latencies, 0.50) if latencies else None,
            "p95": percentile(latencies, 0.95) if latencies else None,
            "max": round(max(latencies), 3) if latencies else None,
        },
        "responses": responses,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=9877)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--timeout", type=float, default=3.0)
    args = parser.parse_args()
    if args.port < 1 or args.port > 65535:
        parser.error("--port must be between 1 and 65535")
    if args.samples < 1 or args.samples > 200:
        parser.error("--samples must be between 1 and 200")
    if args.timeout <= 0 or args.timeout > 30:
        parser.error("--timeout must be greater than 0 and no more than 30 seconds")
    result = {
        "host": args.host,
        "port": args.port,
        "generated_at_unix": int(time.time()),
        "probes": [
            run_mode(args.host, args.port, mode, args.samples, args.timeout)
            for mode in ("version", "spf")
        ],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 1 if any(probe["errors"] for probe in result["probes"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
