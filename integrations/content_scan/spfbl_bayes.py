#!/usr/bin/env python3
"""Query the native SPFBL Bayes classifier over its loopback-only protocol."""

from __future__ import print_function

import base64
import ipaddress
import re
import socket

MAX_MESSAGE_BYTES = 5 * 1024 * 1024
MAX_RESPONSE_BYTES = 4096
DECISION_RE = re.compile(r"^(SPAM|HAM|INCONCLUSIVE|DISABLED|NOT_ALLOWED)$")
PROBABILITY_RE = re.compile(r"^(?:0(?:\.\d{1,6})?|1(?:\.0{1,6})?)$")


def scan_with_core(message, source_ip, host="127.0.0.1", port=9877,
                   timeout=2.0, connection_factory=socket.create_connection):
    """Score a message in memory. Every failure is reported as fail-open state."""
    # The gateway's bounded HTTP readers return bytearray to avoid an extra
    # full-message copy. base64.b64encode accepts both bytes and bytearray.
    if not isinstance(message, (bytes, bytearray)) or not message:
        return {"status": "invalid_message"}
    if len(message) > MAX_MESSAGE_BYTES:
        return {"status": "message_too_large"}
    try:
        address = ipaddress.ip_address(source_ip)
        target = ipaddress.ip_address(host)
        if not target.is_loopback or not 1 <= int(port) <= 65535:
            return {"status": "target_invalid"}
    except (TypeError, ValueError):
        return {"status": "source_ip_invalid"}

    encoded_message = base64.b64encode(message)
    header = ("SFOX-BAYES/1.0\r\n"
              "Source-IP: {0}\r\n"
              "Content-Transfer-Encoding: base64\r\n"
              "Content-length: {1}\r\n"
              "\r\n").format(address, len(encoded_message)).encode("ascii")
    response = bytearray()
    try:
        with connection_factory((str(target), int(port)), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(header + encoded_message)
            connection.shutdown(socket.SHUT_WR)
            while len(response) <= MAX_RESPONSE_BYTES:
                chunk = connection.recv(min(1024, MAX_RESPONSE_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
    except socket.timeout:
        return {"status": "timeout"}
    except OSError:
        return {"status": "unavailable"}

    if not response or len(response) > MAX_RESPONSE_BYTES or b"\x00" in response:
        return {"status": "invalid_response"}
    try:
        lines = bytes(response).decode("ascii").splitlines()
    except UnicodeDecodeError:
        return {"status": "invalid_response"}
    if not lines or lines[0] != "SFOX-BAYES/1.0 0 OK":
        if lines and lines[0] == "SFOX-BAYES/1.0 77 EX_NOPERM":
            return {"status": "not_allowed"}
        if lines and lines[0] == "SFOX-BAYES/1.0 65 EX_DATAERR":
            return {"status": "invalid_message"}
        return {"status": "core_error"}

    fields = {}
    for line in lines[1:]:
        if not line:
            break
        if ":" not in line:
            return {"status": "invalid_response"}
        key, value = line.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key in fields:
            return {"status": "invalid_response"}
        fields[key] = value
    decision = fields.get("decision")
    if not isinstance(decision, str) or not DECISION_RE.fullmatch(decision):
        return {"status": "invalid_response"}
    result = {"status": decision.lower()}
    probability = fields.get("spam-probability")
    if probability is not None:
        if not PROBABILITY_RE.fullmatch(probability):
            return {"status": "invalid_response"}
        result["spam_probability"] = float(probability)
    known_features = fields.get("known-features")
    if known_features is not None:
        if not re.fullmatch(r"\d{1,5}", known_features):
            return {"status": "invalid_response"}
        result["known_features"] = int(known_features)
    return result
