#!/usr/bin/env python3
"""Create or disable per-MTA bearer credentials for the scan gateway."""

from __future__ import print_function

import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import tempfile

CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
DEFAULT_CONFIG = "/etc/had-antispam/content-scan-clients.json"
DEFAULT_ALLOWLIST = "/etc/had-antispam/allowed-cpanels.txt"
SERVICE_GROUP = "had-content-scan"


def _read_allowlist(path):
    result = []
    with open(path, "r") as stream:
        for raw in stream:
            value = raw.strip()
            value = value.split("#", 1)[0].strip()
            if not value:
                continue
            result.append(ipaddress.ip_network(value, strict=False))
    return result


def _cidrs_allowed(requested, allowlist):
    for candidate in requested:
        if not any(candidate.version == parent.version and candidate.subnet_of(parent)
                   for parent in allowlist):
            raise ValueError("CIDR is not covered by the cPanel allowlist: " + str(candidate))


def _atomic_write(path, config):
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o750)
    fd, temporary = tempfile.mkstemp(prefix=".clients.", dir=directory)
    try:
        with os.fdopen(fd, "w") as stream:
            json.dump(config, stream, sort_keys=True, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o640)
        if hasattr(os, "chown"):
            try:
                import grp
                group_id = grp.getgrnam(SERVICE_GROUP).gr_gid
                os.chown(temporary, 0, group_id)
            except (KeyError, ImportError, OSError):
                try:
                    os.chown(temporary, 0, 0)
                except OSError:
                    pass
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def add_client(config_path, allowlist_path, client_id, cidr_values, rotate=False):
    if not CLIENT_ID_RE.fullmatch(client_id):
        raise ValueError("client id must use lowercase letters, numbers, dot, underscore or hyphen")
    requested = [ipaddress.ip_network(value, strict=False) for value in cidr_values]
    if not requested or any(item.prefixlen == 0 for item in requested):
        raise ValueError("provide at least one specific source CIDR; /0 is not allowed")
    _cidrs_allowed(requested, _read_allowlist(allowlist_path))
    if os.path.exists(config_path):
        with open(config_path, "r") as stream:
            config = json.load(stream)
    else:
        config = {"clients": {}}
    clients = config.setdefault("clients", {})
    if client_id in clients and not rotate:
        raise ValueError("client already exists; use --rotate to replace its credential")
    token = secrets.token_urlsafe(32)
    clients[client_id] = {
        "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
        "allowed_cidrs": sorted(set(str(item) for item in requested)),
        "enabled": True,
    }
    _atomic_write(config_path, config)
    return token


def disable_client(config_path, client_id):
    with open(config_path, "r") as stream:
        config = json.load(stream)
    client = config.get("clients", {}).get(client_id)
    if not isinstance(client, dict):
        raise ValueError("client does not exist")
    client["enabled"] = False
    _atomic_write(config_path, config)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    commands = parser.add_subparsers(dest="command")
    add = commands.add_parser("add", help="create a one-time token for a MTA host")
    add.add_argument("client_id")
    add.add_argument("--cidr", action="append", required=True)
    add.add_argument("--rotate", action="store_true")
    disable = commands.add_parser("disable", help="revoke a MTA host token")
    disable.add_argument("client_id")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("choose add or disable")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("run as root")
    try:
        if args.command == "add":
            token = add_client(args.config, args.allowlist, args.client_id,
                               args.cidr, args.rotate)
            print("client_id=" + args.client_id)
            print("token=" + token)
            print("The token is shown once. Copy it directly into the target MTA client config.")
        else:
            disable_client(args.config, args.client_id)
            print("disabled=" + args.client_id)
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
