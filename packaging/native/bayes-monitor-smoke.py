#!/usr/bin/env python3
"""Validate the passive, loopback-only native Bayes monitor protocol."""

import base64
import os
import socket
import sys

sys.path.insert(0, "/source/integrations/content_scan")
import spfbl_bayes

MAX_MESSAGE_BYTES = 5 * 1024 * 1024


def read_sample(path):
    with open(path, "rb") as stream:
        data = stream.read(MAX_MESSAGE_BYTES + 1)
    if not data or len(data) > MAX_MESSAGE_BYTES:
        raise RuntimeError("sample is empty or exceeds the 5 MiB Bayes limit")
    return data


def prove_non_loopback_rejected(host, port, source_ip, message):
    encoded = base64.b64encode(message)
    header = ("SFOX-BAYES/1.0\r\n"
              "Source-IP: {0}\r\n"
              "Content-Transfer-Encoding: base64\r\n"
              "Content-length: {1}\r\n\r\n").format(source_ip, len(encoded)).encode("ascii")
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(5)
        connection.sendall(header + encoded)
        connection.shutdown(socket.SHUT_WR)
        response = connection.recv(512)
    if not response.startswith(b"SFOX-BAYES/1.0 77 EX_NOPERM\r\n"):
        raise RuntimeError("core accepted a proxy IP header from a non-loopback peer")


def main(argv):
    if len(argv) != 7:
        raise SystemExit("Usage: bayes-monitor-smoke.py <host> <port> <spam.eml> <ham.eml> <source-ip> <non-loopback-host>")
    host, port, spam_path, ham_path, source_ip, remote_host = (
        argv[1], int(argv[2]), argv[3], argv[4], argv[5], argv[6])
    spam = read_sample(spam_path)
    ham = read_sample(ham_path)
    spam_result = spfbl_bayes.scan_with_core(spam, source_ip, host, port)
    ham_result = spfbl_bayes.scan_with_core(ham, source_ip, host, port)
    if spam_result.get("status") != "spam":
        raise RuntimeError("native Bayes did not flag its held-out SPAM control: %r" % spam_result)
    if ham_result.get("status") == "spam":
        raise RuntimeError("native Bayes falsely flagged its held-out HAM control: %r" % ham_result)
    prove_non_loopback_rejected(remote_host, port, source_ip, spam)
    print("PASS: passive monitor SPAM/HAM controls; SPAM=%s HAM=%s; non-loopback spoof rejected." %
          (spam_result.get("status"), ham_result.get("status")))


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
