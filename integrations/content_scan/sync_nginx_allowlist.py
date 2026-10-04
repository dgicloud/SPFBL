#!/usr/bin/env python3
"""Render the Nginx allow/deny directives from the SPFBL cPanel allowlist."""

from __future__ import print_function

import argparse
import ipaddress
import os
import tempfile


def render_allowlist(path):
    networks = set()
    with open(path, "r") as stream:
        for raw in stream:
            value = raw.strip()
            value = value.split("#", 1)[0].strip()
            if not value:
                continue
            network = ipaddress.ip_network(value, strict=False)
            if network.prefixlen == 0:
                raise ValueError("refusing a default route in the cPanel allowlist")
            networks.add(network)
    if not networks:
        raise ValueError("the cPanel allowlist is empty")
    ordered = sorted(networks, key=lambda item: (item.version, int(item.network_address), item.prefixlen))
    return "# Generated from the SPFBL cPanel allowlist; do not edit manually.\n" + "".join(
        "allow %s;\n" % item for item in ordered
    ) + "deny all;\n"


def write_atomic(path, content):
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o755)
    fd, temporary = tempfile.mkstemp(prefix=".had-sfox-allow-", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allowlist", default="/etc/had-antispam/allowed-cpanels.txt")
    parser.add_argument("--output", default="/etc/nginx/snippets/had-sfox-scan-allow.conf")
    args = parser.parse_args(argv)
    try:
        content = render_allowlist(args.allowlist)
        write_atomic(args.output, content)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print("Nginx SFOX scan allowlist synchronized from %s" % args.allowlist)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
