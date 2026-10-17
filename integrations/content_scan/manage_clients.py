#!/usr/bin/env python3
"""Authorize or disable per-MTA source-IP profiles for the scan gateway."""

from __future__ import print_function

import argparse
import ipaddress
import json
import os
import re
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
            raise ValueError("CIDR is not covered by the MTA allowlist: " + str(candidate))


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


def _remove_legacy_autolearn(config):
    clients = config.get("clients", {}) if isinstance(config, dict) else {}
    if not isinstance(clients, dict):
        return False
    changed = False
    for client in clients.values():
        if isinstance(client, dict) and "autolearn_enabled" in client:
            del client["autolearn_enabled"]
            changed = True
    return changed


def _profile_id_for_cidrs(requested):
    network = requested[0]
    address = str(network.network_address).replace(".", "-").replace(":", "-")
    suffix = "" if len(requested) == 1 else "-plus-{0}".format(len(requested) - 1)
    return "ip-{0}-{1}{2}".format(address, network.prefixlen, suffix)


def add_client(config_path, allowlist_path, client_id, cidr_values, replace=False,
               spfbl_feedback_enabled=False):
    requested = [ipaddress.ip_network(value, strict=False) for value in cidr_values]
    if not requested or any(item.prefixlen == 0 for item in requested):
        raise ValueError("provide at least one specific source CIDR; /0 is not allowed")
    client_id = client_id or _profile_id_for_cidrs(requested)
    if not CLIENT_ID_RE.fullmatch(client_id):
        raise ValueError("profile name must use lowercase letters, numbers, dot, underscore or hyphen")
    _cidrs_allowed(requested, _read_allowlist(allowlist_path))
    if os.path.exists(config_path):
        with open(config_path, "r") as stream:
            config = json.load(stream)
    else:
        config = {"clients": {}}
    _remove_legacy_autolearn(config)
    clients = config.setdefault("clients", {})
    if client_id in clients and not replace:
        raise ValueError("profile already exists; it is already registered")
    for existing_id, existing in clients.items():
        if existing_id == client_id or not isinstance(existing, dict):
            continue
        for raw_network in existing.get("allowed_cidrs", []):
            try:
                current = ipaddress.ip_network(raw_network, strict=False)
            except (TypeError, ValueError):
                continue
            if any(candidate.version == current.version and candidate.overlaps(current)
                   for candidate in requested):
                raise ValueError("source CIDR overlaps profile {0}; use one profile per server IP".format(existing_id))
    clients[client_id] = {
        "allowed_cidrs": sorted(set(str(item) for item in requested)),
        "enabled": True,
        "native_bayes_enabled": True,
        "spfbl_feedback_enabled": bool(spfbl_feedback_enabled),
    }
    _atomic_write(config_path, config)
    return client_id


def disable_client(config_path, client_id):
    with open(config_path, "r") as stream:
        config = json.load(stream)
    client = config.get("clients", {}).get(client_id)
    if not isinstance(client, dict):
        raise ValueError("client does not exist")
    client["enabled"] = False
    _atomic_write(config_path, config)


def set_spfbl_feedback(config_path, client_id, enabled):
    with open(config_path, "r") as stream:
        config = json.load(stream)
    client = config.get("clients", {}).get(client_id)
    if not isinstance(client, dict):
        raise ValueError("client does not exist")
    if enabled and client.get("enabled", True) is not True:
        raise ValueError("cannot enable SPFBL feedback for a disabled client")
    if enabled and client.get("native_bayes_enabled") is not True:
        raise ValueError("enable native SPFBL Bayes before SPFBL feedback")
    client["spfbl_feedback_enabled"] = bool(enabled)
    _atomic_write(config_path, config)


def set_native_bayes(config_path, client_id, enabled):
    with open(config_path, "r") as stream:
        config = json.load(stream)
    client = config.get("clients", {}).get(client_id)
    if not isinstance(client, dict):
        raise ValueError("client does not exist")
    if enabled and client.get("enabled", True) is not True:
        raise ValueError("cannot enable native Bayes for a disabled client")
    client["native_bayes_enabled"] = bool(enabled)
    _atomic_write(config_path, config)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=DEFAULT_CONFIG)
    parser.add_argument("--allowlist", default=DEFAULT_ALLOWLIST)
    commands = parser.add_subparsers(dest="command")
    add = commands.add_parser("add", help="authorize one MTA source IP")
    add.add_argument("client_id", nargs="?", help="optional internal profile name; defaults to one derived from the IP")
    add.add_argument("--cidr", action="append", required=True)
    add.add_argument("--replace", action="store_true",
                     help="replace an existing profile with the same internal name")
    add.add_argument("--spfbl-feedback", action="store_true",
                     help="envia feedback SPAM de alta confiança ao ticket SPFBL correspondente")
    disable = commands.add_parser("disable", help="disable a MTA source-IP profile")
    disable.add_argument("client_id")
    feedback = commands.add_parser("spfbl-feedback", help="enable or disable high-confidence SPAM feedback to SPFBL")
    feedback.add_argument("client_id")
    feedback_switch = feedback.add_mutually_exclusive_group(required=True)
    feedback_switch.add_argument("--enable", action="store_true")
    feedback_switch.add_argument("--disable", action="store_true")
    native_bayes = commands.add_parser("native-bayes", help="enable or disable native SPFBL Bayes observation for a client")
    native_bayes.add_argument("client_id")
    native_bayes_switch = native_bayes.add_mutually_exclusive_group(required=True)
    native_bayes_switch.add_argument("--enable", action="store_true")
    native_bayes_switch.add_argument("--disable", action="store_true")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("choose add, disable, spfbl-feedback or native-bayes")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("run as root")
    try:
        if os.path.exists(args.config):
            with open(args.config, "r") as stream:
                current_config = json.load(stream)
            if _remove_legacy_autolearn(current_config):
                _atomic_write(args.config, current_config)
        if args.command == "add":
            client_id = add_client(args.config, args.allowlist, args.client_id,
                                   args.cidr, args.replace, args.spfbl_feedback)
            print("profile=" + client_id)
            print("authorized_cidrs=" + ",".join(args.cidr))
            print("MTA admission uses the Nginx allowlist and this source CIDR; no client ID or token is installed on the MTA.")
        elif args.command == "disable":
            disable_client(args.config, args.client_id)
            print("disabled=" + args.client_id)
        elif args.command == "spfbl-feedback":
            enabled = args.enable
            set_spfbl_feedback(args.config, args.client_id, enabled)
            print("spfbl_feedback_%s=%s" % ("enabled" if enabled else "disabled", args.client_id))
        else:
            enabled = args.enable
            set_native_bayes(args.config, args.client_id, enabled)
            print("native_bayes_%s=%s" % ("enabled" if enabled else "disabled", args.client_id))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
