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


TABLE = "inet had_antispam"
MARKER = 'comment "managed by HAD AntiSpam"'
NFT = shutil.which("nft") or "/usr/sbin/nft"


class FirewallError(RuntimeError):
    pass


def load_networks(path):
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
    if not networks:
        raise FirewallError("allowlist_is_empty_refusing_to_open_9877")
    return networks


def render_rules(networks):
    lines = [
        "table inet had_antispam {",
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
    result = subprocess.run(
        command,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if check and result.returncode != 0:
        raise FirewallError("{0}: {1}".format(" ".join(command), result.stdout.strip()[-1000:]))
    return result


def _existing_table():
    result = _run([NFT, "list", "table", "inet", "had_antispam"], check=False)
    if result.returncode != 0:
        return None
    if MARKER not in result.stdout:
        raise FirewallError("inet had_antispam exists but is not managed by HAD")
    return result.stdout


def apply(path):
    networks = load_networks(path)
    rules = render_rules(networks)
    current = _existing_table()
    transaction = ("delete table inet had_antispam\n" if current is not None else "") + rules
    # nft applies a file as one transaction, so an update never leaves 9877
    # briefly unfiltered and a failed replacement keeps the old table intact.
    _run([NFT, "-c", "-f", "-"], input_text=transaction)
    _run([NFT, "-f", "-"], input_text=transaction)
    print("HAD nftables rules active: TCP 9877 allowlisted, TCP 9875/8080 private ({0} query networks).".format(len(networks)))


def remove():
    if _existing_table() is None:
        print("HAD nftables table is already absent.")
        return
    _run([NFT, "delete", "table", "inet", "had_antispam"])
    print("HAD nftables table removed; other firewall tables were left unchanged.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command")
    apply_parser = subparsers.add_parser("apply")
    apply_parser.add_argument("--allowlist", required=True)
    subparsers.add_parser("remove")
    args = parser.parse_args(argv)
    try:
        if args.command == "apply":
            apply(args.allowlist)
        elif args.command == "remove":
            remove()
        else:
            parser.error("select apply or remove")
        return 0
    except (FirewallError, OSError) as exc:
        print("HAD firewall update failed: {0}".format(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
