#!/usr/bin/env python3
"""Sample a systemd service cgroup's CPU and memory without changing it."""

import argparse
import json
import os
import subprocess
import sys
import time


def read_int(path):
    with open(path, "r") as stream:
        return int(stream.read().strip())


def read_cpu_usec(path):
    with open(path, "r") as stream:
        for line in stream:
            key, value = line.split()
            if key == "usage_usec":
                return int(value)
    raise RuntimeError("cpu.stat does not contain usage_usec")


def process_rss_bytes(pid):
    path = "/proc/{0}/status".format(pid)
    with open(path, "r") as stream:
        for line in stream:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    return None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unit", default="spamfox-core.service")
    parser.add_argument("--duration", type=float, default=15.0)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args(argv)
    if args.duration <= 0 or args.duration > 300:
        parser.error("--duration must be greater than 0 and no more than 300 seconds")
    if args.interval < 0.05 or args.interval > 5:
        parser.error("--interval must be between 0.05 and 5 seconds")

    control_group = subprocess.check_output(
        ["systemctl", "show", "--property=ControlGroup", "--value", args.unit],
        universal_newlines=True,
    ).strip()
    pid = int(subprocess.check_output(
        ["systemctl", "show", "--property=MainPID", "--value", args.unit],
        universal_newlines=True,
    ).strip())
    cgroup = os.path.join("/sys/fs/cgroup", control_group.lstrip("/"))
    cpu_path = os.path.join(cgroup, "cpu.stat")
    memory_path = os.path.join(cgroup, "memory.current")
    if pid <= 0 or not os.path.isfile(cpu_path) or not os.path.isfile(memory_path):
        raise RuntimeError("service process or cgroup v2 metrics are unavailable")

    samples = []
    deadline = time.monotonic() + args.duration
    while True:
        stamp = time.monotonic()
        samples.append((stamp, read_cpu_usec(cpu_path), read_int(memory_path), process_rss_bytes(pid)))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(args.interval, remaining))

    elapsed = samples[-1][0] - samples[0][0] if len(samples) > 1 else 0.0
    cpu_seconds = (samples[-1][1] - samples[0][1]) / 1000000.0 if len(samples) > 1 else 0.0
    result = {
        "unit": args.unit,
        "pid": pid,
        "control_group": control_group,
        "duration_seconds": round(elapsed, 3),
        "interval_seconds": args.interval,
        "samples": len(samples),
        "cpu_seconds": round(cpu_seconds, 4),
        "average_cpu_one_core_percent": round(100.0 * cpu_seconds / elapsed, 2) if elapsed > 0 else None,
        "cgroup_memory_current_bytes": {
            "min": min(sample[2] for sample in samples),
            "max": max(sample[2] for sample in samples),
        },
        "process_rss_sampled_bytes": {
            "min": min(sample[3] for sample in samples if sample[3] is not None),
            "max": max(sample[3] for sample in samples if sample[3] is not None),
        },
    }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        sys.stderr.write("resource-sampler: {0}\n".format(exc))
        sys.exit(1)
