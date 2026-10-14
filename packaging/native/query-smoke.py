#!/usr/bin/env python3
"""Smoke test for the unchanged upstream public query protocol."""

import json
import socket
import sys
import time


def query(host, port, command, prefix):
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall((command + "\n").encode("ascii"))
            chunks = []
            while True:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
    except OSError as exc:
        raise RuntimeError("connect to %s:%s for %r failed: %s" % (host, port, command.split(" ", 1)[0], exc))
    result = b"".join(chunks).decode("iso-8859-1", "replace").strip()
    if not result.startswith(prefix):
        raise RuntimeError("unexpected response to %r: %r" % (command, result[:200]))
    return {"command": command.split(" ", 1)[0], "response": result[:160], "elapsed_ms": round((time.monotonic() - started) * 1000, 2)}


def main(argv):
    host = argv[1] if len(argv) > 1 else "127.0.0.1"
    port = int(argv[2]) if len(argv) > 2 else 9877
    admin_host = argv[3] if len(argv) > 3 else None
    results = [
        query(host, port, "VERSION", "SPFBL-"),
        query(host, port, "SPF '192.0.2.25' 'sender@audit.test' 'helo.audit.test' 'recipient@audit.test'", "LAN"),
        query(host, port, "FIREWALL", "#!/bin/bash"),
    ]
    print(json.dumps({"ok": True, "checks": results}, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        sys.exit(1)
