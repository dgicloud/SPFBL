#!/usr/bin/env python3
"""Verify a learned Bayes decision through the SPFBL SPAMD wire protocol."""

import glob
import os
import re
import socket
import sys


MAX_MESSAGE_BYTES = 5 * 1024 * 1024
USER_EMAIL = "bayes-audit@example.com"
SYNTHETIC_RECEIVED = (
    "Received: from mail.example.net (mail.example.net [8.8.8.8] "
    "helo=mail.example.net) by mx.audit.example.net with ESMTP id audit123 "
    "envelope-from <audit@example.net> for <{0}>; Sat, 17 Oct 2026 12:00:00 +0000\r\n"
)


def prepare_message(raw):
    separator = b"\r\n\r\n"
    if separator in raw:
        header_bytes, body = raw.split(separator, 1)
    elif b"\n\n" in raw:
        header_bytes, body = raw.split(b"\n\n", 1)
    else:
        raise RuntimeError("SPAMD sample has no RFC822 header/body separator")
    headers = header_bytes.decode("iso-8859-1", "replace")
    # The cw-l corpus deliberately strips transport routing headers. Give the
    # isolated SPAMD test a deterministic SMTP hop; retain the original From
    # identity so SPFBL's normal pre-content checks see a structurally valid
    # message before exercising Bayes. The isolated smoke fixture seeds the
    # synthetic domain and FQDN locally; no external DNS or production data is
    # needed for this protocol check.
    headers = re.sub(
        r"(?im)^(?:from|to|return-path|received|received-spfbl|dkim-signature):"
        r"[^\r\n]*(?:\r?\n[ \t][^\r\n]*)*\r?\n?",
        "",
        headers,
    )
    synthetic = SYNTHETIC_RECEIVED.format(USER_EMAIL)
    normalized_headers = "\r\n".join(headers.splitlines())
    return (synthetic + "From: SpamFox Bayes Audit <audit@example.net>\r\n"
            + "To: <{0}>\r\n".format(USER_EMAIL)
            + normalized_headers + "\r\n\r\n").encode(
        "iso-8859-1", "replace"
    ) + body


def scan(host, port, path):
    with open(path, "rb") as source:
        message = prepare_message(source.read(MAX_MESSAGE_BYTES + 1))
    if not message or len(message) > MAX_MESSAGE_BYTES:
        raise RuntimeError("SPAMD sample is empty or exceeds the 5 MiB limit")
    header = ("REPORT SPAMC/1.2\r\n"
              "User: {0}\r\n"
              "Content-length: {1}\r\n"
              "\r\n").format(USER_EMAIL, len(message)).encode("ascii")
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(15)
        connection.sendall(header + message)
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        total = 0
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            total += len(chunk)
            if total > 1024 * 1024:
                raise RuntimeError("SPAMD response exceeds 1 MiB")
            chunks.append(chunk)
    return b"".join(chunks).decode("iso-8859-1", "replace")


def main(argv):
    if len(argv) != 5:
        raise SystemExit("Usage: bayes-spamd-smoke.py <host> <port> <spam-eml> <ham-directory>")
    host, port, spam_path, ham_directory = argv[1], int(argv[2]), argv[3], argv[4]
    if not os.path.basename(spam_path).startswith("spam-"):
        raise RuntimeError("SPAMD positive-control sample must come from held-out SPAM")
    ham_paths = sorted(glob.glob(os.path.join(ham_directory, "ham-*.eml")))
    if not ham_paths:
        raise RuntimeError("SPAMD negative-control sample is missing")

    spam_response = scan(host, port, spam_path)
    if (not spam_response.startswith("SPAMD/1.1 0 EX_OK\r\n")
            or "CONTENT_BAYES_SPAM" not in spam_response
            or "SFOX_BAYES_SPAM=" not in spam_response):
        raise RuntimeError("SPAMD did not return the expected Bayes spam decision: %r"
                           % spam_response[:500])

    ham_response = scan(host, port, ham_paths[0])
    if (not ham_response.startswith("SPAMD/1.1 0 EX_OK\r\n")
            or "SFOX_BAYES_SPAM=" in ham_response):
        raise RuntimeError("SPAMD incorrectly flagged the held-out HAM control: %r"
                           % ham_response[:500])
    print("PASS: SPAMD positive and negative controls; %s" % spam_response.splitlines()[-1][:180])


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
