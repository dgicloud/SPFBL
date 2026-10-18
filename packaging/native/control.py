#!/usr/bin/env python3
"""Small loopback-only control client used by the native systemd unit."""

from __future__ import print_function

import socket
import subprocess
import sys
import time
import os


HOST = "127.0.0.1"
PORT = int(os.environ.get("SPAMFOX_ADMIN_PORT", os.environ.get("HAD_SPFBL_ADMIN_PORT", "9875")))
COMMANDS = {
    "version": ("VERSION", "SPFBL-"),
    "store": ("STORE", ("STARTING STORE", "ALREADY STORING")),
    "shutdown": ("SHUTDOWN", "OK"),
}
SYSTEMD = "/usr/bin/systemctl"
APP = "/opt/spfbl"
MAX_PEER_RESPONSE_BYTES = 65536


def request(name):
    command, expected = COMMANDS[name]
    main_pid = get_main_pid() if name == "shutdown" else None
    if name == "shutdown" and main_pid <= 0:
        raise RuntimeError("systemd has no main PID for the SPFBL service")
    with socket.create_connection((HOST, PORT), timeout=2.0) as connection:
        connection.settimeout(1.0 if name == "shutdown" else 5.0)
        connection.sendall((command + "\n").encode("ascii"))
        response = bytearray()
        if name == "shutdown":
            # Upstream closes its ADMIN listener while processing SHUTDOWN and
            # may never return a line. Keep ExecStop alive until systemd reports
            # that the JVM exited, or systemd sends TERM while it is still saving.
            try:
                chunk = connection.recv(512)
                response.extend(chunk)
            except (socket.timeout, OSError):
                pass
        else:
            while len(response) <= 4096:
                chunk = connection.recv(512)
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    line = bytes(response).split(b"\n", 1)[0].decode("iso-8859-1").strip()
    if name == "shutdown":
        wait_for_core_exit(main_pid)
        print("SHUTDOWN COMPLETE")
        return
    if isinstance(expected, tuple):
        valid = any(line.startswith(prefix) for prefix in expected)
    else:
        valid = line.startswith(expected)
    if not valid:
        raise RuntimeError("unexpected response to {0}: {1}".format(command, line[:160]))
    print(line)


def unit_state(unit):
    try:
        result = subprocess.run(
            [SYSTEMD, "is-active", unit], stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, universal_newlines=True,
        )
        return result.stdout.strip() or "unknown"
    except OSError:
        return "unknown"


def query_version():
    with socket.create_connection((HOST, PORT), timeout=2.0) as connection:
        connection.settimeout(3.0)
        connection.sendall(b"VERSION\n")
        response = bytearray()
        while len(response) <= 4096:
            chunk = connection.recv(512)
            if not chunk:
                break
            response.extend(chunk)
            if b"\n" in chunk:
                break
    line = bytes(response).split(b"\n", 1)[0].decode("iso-8859-1").strip()
    if not line.startswith("SPFBL-"):
        raise RuntimeError("unexpected SPFBL VERSION response: {0}".format(line[:160]))
    return line


def parse_peer_response(raw):
    """Return anonymized peer activity and reputation-cap counts only."""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("iso-8859-1")
    else:
        text = str(raw)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        raise RuntimeError("empty PEER SHOW response")
    if lines == ["EMPTY"]:
        lines = []

    stats = {
        "configured_count": 0,
        "recent_activity_count": 0,
        "stale_activity_count": 0,
        "unknown_activity_count": 0,
        "reputation_receive_mode_count": 0,
        "reputation_max_sum": 0,
        "reputation_max_positive_count": 0,
    }
    for line in lines:
        fields = line.split()
        if len(fields) < 6:
            raise RuntimeError("invalid PEER SHOW response")
        frequency = fields[4]
        try:
            reputation_max = int(fields[5])
        except ValueError:
            raise RuntimeError("invalid PEER SHOW response")
        if reputation_max < 0:
            raise RuntimeError("invalid PEER SHOW response")

        stats["configured_count"] += 1
        if frequency.startswith("~"):
            stats["recent_activity_count"] += 1
        elif frequency.startswith(">") or frequency == "DEAD":
            stats["stale_activity_count"] += 1
        else:
            # '<' means intervals below SPFBL's reporting floor; freshness is
            # not inferable from that marker. UNDEFINED is also unknown.
            stats["unknown_activity_count"] += 1
        if fields[3] == "REPUTATION":
            stats["reputation_receive_mode_count"] += 1
        stats["reputation_max_sum"] += reputation_max
        if reputation_max > 0:
            stats["reputation_max_positive_count"] += 1
    return stats


def query_peer_stats(timeout=1.0, max_response_bytes=MAX_PEER_RESPONSE_BYTES):
    """Query ADMIN locally and discard all peer identity fields after parsing."""
    response = bytearray()
    with socket.create_connection((HOST, PORT), timeout=timeout) as connection:
        connection.settimeout(timeout)
        connection.sendall(b"PEER SHOW\n")
        while len(response) <= max_response_bytes:
            chunk = connection.recv(min(4096, max_response_bytes + 1 - len(response)))
            if not chunk:
                break
            response.extend(chunk)
    if len(response) > max_response_bytes:
        raise RuntimeError("PEER SHOW response exceeds limit")
    return parse_peer_response(response)


def status():
    service_state = unit_state("spamfox-core.service")
    timer_state = unit_state("spamfox-store.timer")
    release = os.path.basename(os.path.realpath(os.path.join(APP, "current"))) or "unknown"
    version = None
    version_error = None
    peer_stats = None
    try:
        version = query_version()
    except (OSError, RuntimeError) as exc:
        version_error = str(exc)
    try:
        peer_stats = query_peer_stats()
    except (OSError, RuntimeError, socket.error):
        pass
    print("SpamFox")
    print("  Core service: {0}".format(service_state))
    print("  SPFBL: {0}".format(version or "unavailable"))
    print("  Release: {0}".format(release))
    print("  STORE timer: {0}".format(timer_state))
    if peer_stats is None:
        print("  P2P peer summary: unavailable")
    else:
        print(
            "  P2P peers: configured={configured_count} recent={recent_activity_count} "
            "stale={stale_activity_count} unknown={unknown_activity_count} "
            "receive_REPUTATION={reputation_receive_mode_count} "
            "positive_caps={reputation_max_positive_count}".format(**peer_stats)
        )
    if version_error:
        print("  Query error: {0}".format(version_error))
    return 0 if service_state == "active" and version else 1


def get_main_pid():
    output = subprocess.check_output(
        ["/usr/bin/systemctl", "show", "--property=MainPID", "--value", "spamfox-core.service"],
        stderr=subprocess.DEVNULL,
    )
    return int(output.decode("ascii").strip())


def wait_for_core_exit(main_pid, timeout=110.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        current_pid = get_main_pid()
        if current_pid == 0 or current_pid != main_pid:
            return
        time.sleep(0.5)
    raise RuntimeError("SPFBL core did not exit after SHUTDOWN")


def main(argv):
    if len(argv) == 2 and argv[1] == "status":
        return status()
    if len(argv) != 2 or argv[1] not in COMMANDS:
        print("Usage: control.py status|version|store|shutdown", file=sys.stderr)
        return 2
    if argv[1] == "shutdown" and hasattr(os, "geteuid") and os.geteuid() != 0:
        print("SpamFox control: shutdown requires root.", file=sys.stderr)
        return 2
    try:
        request(argv[1])
        return 0
    except (OSError, RuntimeError) as exc:
        print("SpamFox control failed: {0}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
