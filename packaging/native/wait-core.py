#!/usr/bin/env python3
"""Wait for a test core to finish loading its SPFBL data and answer VERSION."""

import socket
import sys
import time


host = sys.argv[1]
port = int(sys.argv[2])
deadline = time.monotonic() + (int(sys.argv[3]) if len(sys.argv) > 3 else 120)
last_error = "not ready"
while time.monotonic() < deadline:
    try:
        with socket.create_connection((host, port), timeout=1.5) as connection:
            connection.settimeout(1.5)
            connection.sendall(b"VERSION\n")
            response = connection.recv(256).decode("iso-8859-1", "replace")
        if response.startswith("SPFBL-"):
            print("Core answered VERSION: " + response.splitlines()[0])
            raise SystemExit(0)
        last_error = "unexpected VERSION response " + repr(response[:100])
    except (OSError, RuntimeError) as exc:
        last_error = str(exc)
    time.sleep(2)
raise SystemExit("Core did not become ready in time: " + last_error)
