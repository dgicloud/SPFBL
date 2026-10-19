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


def query(host, port, payload):
    with socket.create_connection((host, port), timeout=5) as connection:
        connection.settimeout(15)
        connection.sendall(payload.encode("iso-8859-1"))
        connection.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = connection.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("iso-8859-1", "replace")


def create_queue_ticket(host, port, queue_id):
    policy = (
        "request=smtpd_access_policy\n"
        "protocol_state=RCPT\n"
        "client_address=8.8.8.8\n"
        "sender=audit@example.net\n"
        "helo_name=mail.example.net\n"
        "recipient={0}\n\n"
    ).format(USER_EMAIL)
    policy_response = query(host, port, policy)
    ticket_match = re.search(
        r"(?im)^action=PREPEND Received-SPFBL:\s+\S+\s+([^\s\r\n]+)",
        policy_response,
    )
    if not ticket_match:
        raise RuntimeError("could not create Exim RCPT ticket for queue-ID SPAMD test: %r"
                           % policy_response[:500])
    ticket = ticket_match.group(1).rsplit("/", 1)[-1]
    header = (
        "HEADER {0} From:audit@example.net Message-ID:<{1}@audit.example.net> "
        "Queue-ID:{1}\n"
    ).format(ticket, queue_id)
    header_response = query(host, port, header)
    if header_response.startswith(("INVALID COMMAND", "NOT FOUND", "TIMEOUT")):
        raise RuntimeError("could not bind Exim queue ID to SPFBL ticket: %r"
                           % header_response[:300])
    return queue_id


def scan_queue_id(host, port, path, queue_id):
    with open(path, "rb") as source:
        message = prepare_message(source.read(MAX_MESSAGE_BYTES + 1))
    if not message or len(message) > MAX_MESSAGE_BYTES:
        raise RuntimeError("SPAMD sample is empty or exceeds the 5 MiB limit")
    header = ("REPORT SPAMC/1.2\r\n"
              "User: {0}\r\n"
              "Content-length: {1}\r\n"
              "\r\n").format(queue_id, len(message)).encode("ascii")
    response = query(host, port, (header + message).decode("iso-8859-1"))
    return response


def require_spam(response, path, route):
    if (not response.startswith("SPAMD/1.1 0 EX_OK\r\n")
            or "Spam: True ; 2 / 2" not in response
            or "CONTENT_BAYES_SPAM" not in response
            or "SFOX_BAYES_SPAM=" not in response):
        raise RuntimeError("Bayes failed to reject held-out SPAM via %s (%s): %r"
                           % (route, os.path.basename(path), response[:500]))


def require_ham(response, path, route):
    if (not response.startswith("SPAMD/1.1 0 EX_OK\r\n")
            or "Spam: True" in response
            or "SFOX_BAYES_SPAM=" in response):
        raise RuntimeError("Bayes incorrectly rejected held-out HAM via %s (%s): %r"
                           % (route, os.path.basename(path), response[:500]))


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
    require_spam(spam_response, spam_path, "email user")
    ham_response = scan(host, port, ham_paths[0])
    require_ham(ham_response, ham_paths[0], "email user")

    queue_spam_id = create_queue_ticket(host, port, "1xBAYE-000000000001-0A01")
    queue_spam = scan_queue_id(host, port, spam_path, queue_spam_id)
    require_spam(queue_spam, spam_path, "Exim queue ID")
    queue_ham_id = create_queue_ticket(host, port, "1xBAYH-000000000002-0A02")
    queue_ham = scan_queue_id(host, port, ham_paths[0], queue_ham_id)
    require_ham(queue_ham, ham_paths[0], "Exim queue ID")
    print("PASS: SPAMD rejects held-out SPAM and accepts held-out HAM via email and Exim queue-ID paths.")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except Exception as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
