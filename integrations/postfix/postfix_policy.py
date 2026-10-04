#!/usr/bin/env python3
"""Postfix SMTP policy adapter for the HAD SPFBL core (MONITOR only)."""

from __future__ import print_function

import argparse
import ipaddress
import json
import os
import sys
import time


HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)
LOCAL_COMMON = os.path.abspath(os.path.join(HERE, "..", "common"))
if os.path.isfile(os.path.join(LOCAL_COMMON, "spfbl_client.py")) and LOCAL_COMMON not in sys.path:
    sys.path.insert(0, LOCAL_COMMON)

from spfbl_client import Envelope, InputError, TransportConfig, query


MAX_REQUEST_BYTES = 16384
MAX_LINE_BYTES = 4096
MAX_FIELDS = 64
RESPONSE = b"action=DUNNO\n\n"


def load_config(path):
    """Read a small key=value file without evaluating shell syntax."""
    values = {}
    with open(path, "r") as stream:
        for raw_line in stream:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise ValueError("invalid_config_line")
            key, value = line.split("=", 1)
            key = key.strip().upper()
            value = value.strip()
            if key in values:
                raise ValueError("duplicate_config_key")
            values[key] = value

    server = values.get("SERVER", "")
    try:
        server = str(ipaddress.ip_address(server))
    except ValueError as exc:
        raise ValueError("SERVER_must_be_an_IP_literal") from exc
    try:
        port = int(values.get("PORT", "9877"))
    except ValueError as exc:
        raise ValueError("PORT_must_be_an_integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("PORT_out_of_range")
    if values.get("FAIL_OPEN", "true").lower() != "true":
        raise ValueError("FAIL_OPEN_must_remain_true")
    if values.get("MONITOR_MODE", "true").lower() != "true":
        raise ValueError("MONITOR_MODE_must_remain_true")
    return TransportConfig(server_ip=server, port=port)


def parse_policy_request(raw):
    """Parse one Postfix policy request; reject malformed/oversized records."""
    if not raw or len(raw) > MAX_REQUEST_BYTES or not raw.endswith(b"\n\n"):
        raise InputError("invalid_policy_request_size_or_terminator")
    fields = {}
    lines = raw[:-2].split(b"\n")
    if len(lines) > MAX_FIELDS:
        raise InputError("too_many_policy_fields")
    for line in lines:
        line = line.rstrip(b"\r")
        if len(line) > MAX_LINE_BYTES or b"=" not in line:
            raise InputError("invalid_policy_field")
        key, value = line.split(b"=", 1)
        try:
            key_text = key.decode("ascii")
            value_text = value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise InputError("invalid_policy_encoding") from exc
        if not key_text or key_text in fields:
            raise InputError("duplicate_or_empty_policy_key")
        if any(ord(character) < 32 or ord(character) == 127 for character in key_text + value_text):
            raise InputError("control_character_in_policy")
        fields[key_text] = value_text
    if fields.get("request") != "smtpd_access_policy":
        raise InputError("unsupported_policy_request")
    return fields


def _dunno(status, decision=None, latency_ms=0):
    """Emit a PII-free monitor event and always return Postfix DUNNO."""
    event = {
        "event": "had_antispam_postfix_policy",
        "mode": "MONITOR",
        "action": "DUNNO",
        "status": status,
        "decision": decision,
        "latency_ms": latency_ms,
    }
    print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)
    return RESPONSE


def process_request(raw, config, query_fn=None):
    started = time.monotonic()
    query_fn = query_fn or query
    try:
        fields = parse_policy_request(raw)
    except InputError as exc:
        return _dunno(str(exc), latency_ms=int((time.monotonic() - started) * 1000))

    if fields.get("protocol_state") != "RCPT":
        return _dunno("not_rcpt_stage", latency_ms=int((time.monotonic() - started) * 1000))

    sender = fields.get("sender", "")
    if sender == "<>":
        sender = ""
    envelope_data = {
        "client_ip": fields.get("client_address", ""),
        "mail_from": sender,
        "helo": fields.get("helo_name", ""),
        "rcpt_to": fields.get("recipient", ""),
        "recipient_exists": None,
    }
    try:
        envelope = Envelope.from_json(envelope_data)
    except (InputError, ValueError) as exc:
        return _dunno(str(exc), latency_ms=int((time.monotonic() - started) * 1000))

    try:
        result = query_fn(envelope, config)
    except Exception:
        return _dunno("adapter_internal_error", latency_ms=int((time.monotonic() - started) * 1000))
    return _dunno(
        result.status,
        result.decision,
        result.latency_ms,
    )


def read_request(stream):
    """Read one blank-line terminated policy record with hard size limits."""
    data = bytearray()
    while len(data) <= MAX_REQUEST_BYTES:
        line = stream.readline(min(MAX_LINE_BYTES + 1, MAX_REQUEST_BYTES + 1 - len(data)))
        if not line:
            return bytes(data) if not data else b""
        if len(line) > MAX_LINE_BYTES:
            return b"!oversized-line"
        data.extend(line)
        if data.endswith(b"\n\n"):
            return bytes(data)
    return b"!oversized-request"


def serve(stream_in, stream_out, config, query_fn=None):
    """Handle one or more Postfix records on a spawn(8) connection."""
    while True:
        request = read_request(stream_in)
        if not request:
            return
        response = process_request(request, config, query_fn=query_fn)
        stream_out.write(response)
        stream_out.flush()
        if request.startswith(b"!"):
            return


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="/etc/had-antispam/client.conf")
    args = parser.parse_args(argv)
    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        # Even an invalid local configuration cannot reject SMTP in MONITOR mode.
        print(json.dumps({
            "event": "had_antispam_postfix_policy",
            "mode": "MONITOR",
            "action": "DUNNO",
            "status": "config_error",
        }, separators=(",", ":")), file=sys.stderr, flush=True)
        config = None

    if config is None:
        while True:
            request = read_request(sys.stdin.buffer)
            if not request:
                break
            sys.stdout.buffer.write(RESPONSE)
            sys.stdout.buffer.flush()
        return 0

    serve(sys.stdin.buffer, sys.stdout.buffer, config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
