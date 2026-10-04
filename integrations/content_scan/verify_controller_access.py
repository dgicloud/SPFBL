#!/usr/bin/env python3
"""Check that Rspamd controller writes require its root-only password."""

import argparse
import http.client
import os
import stat

TEST_MESSAGE = (
    b"From: controller-test@example.invalid\r\n"
    b"To: sink@example.invalid\r\n"
    b"Subject: synthetic controller access check\r\n"
    b"Message-ID: <controller-access-check@example.invalid>\r\n\r\n"
    b"Synthetic content used only to verify that unauthenticated learning is denied.\r\n"
)


def read_secret(path):
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise ValueError("controller secret must be root-owned and regular")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("controller secret permissions are too broad")
    with open(path, "r") as stream:
        secret = stream.read(256).strip()
    if len(secret) < 32 or not secret.isascii():
        raise ValueError("controller secret is invalid")
    return secret


def request(method, path, body=None, headers=None):
    connection = http.client.HTTPConnection("127.0.0.1", 11334, timeout=5)
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        response.read(65536)
        return response.status
    finally:
        connection.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--secret", default="/etc/had-antispam/rspamd-controller.secret")
    args = parser.parse_args(argv)
    secret = read_secret(args.secret)
    denied = []
    for endpoint in ("/learnspam", "/learnham"):
        status = request("POST", endpoint, TEST_MESSAGE,
                         {"Content-Type": "message/rfc822"})
        denied.append(status in (401, 403))
        print("%s_without_password=%d" % (endpoint, status))
    if not all(denied):
        raise SystemExit("controller accepted an unauthenticated learning request")
    status = request("GET", "/stat", headers={"Password": secret})
    print("authenticated_readonly_stat=%d" % status)
    if status != 200:
        raise SystemExit("controller secret did not authorize a read-only request")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
