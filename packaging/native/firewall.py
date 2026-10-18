#!/usr/bin/env python3
"""Install a dedicated nftables input filter without replacing host rules."""

from __future__ import print_function

import argparse
import ipaddress
import os
import subprocess
import sys
import tempfile
import shutil


TABLE = "inet spamfox"
TABLE_NAME = "spamfox"
LEGACY_TABLE_NAME = "had_antispam"
MARKER = 'comment "managed by SpamFox"'
LEGACY_MARKER = 'comment "managed by HAD AntiSpam"'
NFT = shutil.which("nft") or "/usr/sbin/nft"


class FirewallError(RuntimeError):
    pass


def load_networks(path, allow_empty=False):
    networks = []
    with open(path, "r") as stream:
        for number, raw in enumerate(stream, 1):
            entry = raw.split("#", 1)[0].strip()
            if not entry:
                continue
            try:
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise FirewallError("invalid_allowlist_line_{0}".format(number)) from exc
    if not networks and not allow_empty:
        raise FirewallError("allowlist_is_empty_refusing_to_open_9877")
    return networks


def render_rules(networks):
    lines = [
        "table inet spamfox {",
        "    " + MARKER,
        "    chain input {",
        "        type filter hook input priority -10; policy accept;",
        "        iifname lo accept",
    ]
    for network in networks:
        if network.version == 4:
            lines.append("        ip saddr {0} tcp dport 9877 accept".format(network))
        else:
            lines.append("        ip6 saddr {0} tcp dport 9877 accept".format(network))
    lines.extend(
        [
            "        tcp dport 9877 drop",
            "        tcp dport 9875 drop",
            "        tcp dport 8080 drop",
            "    }",
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _run(command, input_text=None, check=True):
    try:
        result = subprocess.run(
            command,
            input=input_text,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            universal_newlines=True,
            timeout=5,
        )
    except subprocess.TimeoutExpired as exc:
        raise FirewallError("firewall command timed out") from exc
    if check and result.returncode != 0:
        raise FirewallError("{0}: {1}".format(" ".join(command), result.stdout.strip()[-1000:]))
    return result


def _existing_table(name=TABLE_NAME, marker=MARKER):
    result = _run([NFT, "--numeric", "list", "table", "inet", name], check=False)
    if result.returncode != 0:
        return None
    if marker not in result.stdout:
        raise FirewallError("inet {0} exists but is not managed by SpamFox".format(name))
    return result.stdout


def apply(path, allow_empty=False):
    networks = load_networks(path, allow_empty=allow_empty)
    rules = render_rules(networks)
    current = _existing_table()
    legacy = _existing_table(LEGACY_TABLE_NAME, LEGACY_MARKER)
    transaction = ""
    if current is not None:
        transaction += "delete table {0}\n".format(TABLE)
    if legacy is not None:
        transaction += "delete table inet {0}\n".format(LEGACY_TABLE_NAME)
    transaction += rules
    # nft applies a file as one transaction, so an update never leaves 9877
    # briefly unfiltered and a failed replacement keeps the old table intact.
    _run([NFT, "-c", "-f", "-"], input_text=transaction)
    _run([NFT, "-f", "-"], input_text=transaction)
    print("SpamFox nftables rules active: TCP 9877 allowlisted, TCP 9875/8080 private ({0} query networks).".format(len(networks)))


def remove():
    current = _existing_table()
    legacy = _existing_table(LEGACY_TABLE_NAME, LEGACY_MARKER)
    if current is None and legacy is None:
        print("SpamFox nftables table is already absent.")
        return
    transaction = ""
    if current is not None:
        transaction += "delete table {0}\n".format(TABLE)
    if legacy is not None:
        transaction += "delete table inet {0}\n".format(LEGACY_TABLE_NAME)
    _run([NFT, "-f", "-"], input_text=transaction)
    print("SpamFox nftables table removed; other firewall tables were left unchanged.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--allowlist", required=True)
    apply_parser.add_argument("--allow-empty", action="store_true", help="An empty list denies all external queries")
    subparsers.add_parser("remove")
    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            apply(args.allowlist, allow_empty=args.allow_empty)
        elif args.command == "remove":
            remove()
        else:
            parser.error("select apply or remove")
        return 0
    except (FirewallError, OSError) as exc:
        print("SpamFox firewall update failed: {0}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
