#!/usr/bin/env python3
"""Submit high-confidence SpamFox content verdicts through SPFBL's native ticket API."""

from __future__ import print_function

import ipaddress
import math
import re
import socket

SPAM_SCORE_THRESHOLD = 15.0
BAYES_SPAM_FEEDBACK_MIN_SCORE = 4.0
BAYES_SPAM_FEEDBACK_MIN_PROBABILITY = 95.0
BAYES_SPAM_FEEDBACK_ACTIONS = frozenset(("greylist", "add header", "reject"))
TICKET_RE = re.compile(r"^[A-Za-z0-9_-]{44,512}$")
QUALIFIERS = frozenset(("PASS", "WHITE", "FLAG", "HOLD", "SOFTFAIL", "NEUTRAL", "NONE", "FAIL"))
MAX_RESPONSE_BYTES = 2048


def feedback_eligibility(metadata, ticket_record, result, feedback_enabled):
    """Return (action, reason) using conservative, privacy-safe gates."""
    metadata = metadata or {}
    if feedback_enabled is not True:
        return None, "client_feedback_disabled"
    if metadata.get("autolearn") is not True or metadata.get("autolearn_eligible") is not True:
        return None, "envelope_ineligible"
    try:
        source_ip = ipaddress.ip_address(metadata.get("ip", ""))
    except (TypeError, ValueError):
        return None, "source_ip_invalid"
    if not source_ip.is_global:
        return None, "source_ip_not_global"
    recipient_count = metadata.get("spfbl_recipient_count")
    if "spfbl_recipient_count" not in metadata:
        recipient_count = len(metadata.get("rcpt", []))
    if (isinstance(recipient_count, bool)
            or not isinstance(recipient_count, int)
            or recipient_count != 1):
        return None, "recipient_count"
    if not isinstance(ticket_record, dict):
        return None, "ticket_missing"
    qualifier = ticket_record.get("qualifier")
    ticket = ticket_record.get("ticket")
    if qualifier not in QUALIFIERS or not isinstance(ticket, str) or not TICKET_RE.fullmatch(ticket):
        return None, "ticket_invalid"
    # The MTA client and gateway inspect the ticket independently. Requiring
    # agreement prevents a forged or altered message header from becoming a
    # reputation complaint even if it parses as a syntactically valid ticket.
    if metadata.get("ticket_status_match") is not True:
        return None, "ticket_status_mismatch"

    score = result.get("score") if isinstance(result, dict) else None
    required_score = result.get("required_score") if isinstance(result, dict) else None
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        return None, "score_unavailable"
    threshold = SPAM_SCORE_THRESHOLD
    if (not isinstance(required_score, bool)
            and isinstance(required_score, (int, float))
            and math.isfinite(required_score)):
        threshold = max(threshold, float(required_score))
    if score >= threshold:
        return "spam", "high_confidence_spam"

    symbols = result.get("symbols") if isinstance(result, dict) else None
    action = result.get("action") if isinstance(result, dict) else None
    probability = result.get("bayes_spam_probability") if isinstance(result, dict) else None
    bayes_spam_candidate = (
        score >= BAYES_SPAM_FEEDBACK_MIN_SCORE
        and action in BAYES_SPAM_FEEDBACK_ACTIONS
        and isinstance(symbols, (list, tuple, set, frozenset))
        and "BAYES_SPAM" in symbols
        and not isinstance(probability, bool)
        and isinstance(probability, (int, float))
        and math.isfinite(probability)
        and probability >= BAYES_SPAM_FEEDBACK_MIN_PROBABILITY
    )
    if not bayes_spam_candidate:
        return None, "below_spam_threshold"
    return "spam", "bayes_spam_probability_95"


def submit_spam_ticket(ticket, host="127.0.0.1", port=9877, timeout=2.0,
                       connection_factory=socket.create_connection):
    """Send one native SPAM command; never retry an uncertain write."""
    if not isinstance(ticket, str) or not TICKET_RE.fullmatch(ticket):
        return "ticket_invalid"
    try:
        address = ipaddress.ip_address(host)
        if not address.is_loopback or not 1 <= int(port) <= 65535:
            return "target_invalid"
    except (TypeError, ValueError):
        return "target_invalid"

    request = ("SPAM " + ticket + "\n").encode("ascii")
    try:
        with connection_factory((str(address), int(port)), timeout=timeout) as connection:
            connection.settimeout(timeout)
            connection.sendall(request)
            response = bytearray()
            while len(response) <= MAX_RESPONSE_BYTES:
                chunk = connection.recv(min(512, MAX_RESPONSE_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
    except socket.timeout:
        return "timeout_uncertain"
    except OSError:
        return "transport_failed"

    if not response or len(response) > MAX_RESPONSE_BYTES or b"\x00" in response:
        return "response_invalid"
    line = bytes(response).split(b"\n", 1)[0].strip()
    if line == b"DUPLICATE COMPLAIN":
        return "unchanged"
    if line == b"OK" or line.startswith(b"OK "):
        return "accepted"
    if line == b"TICKET EXPIRED":
        return "ticket_expired"
    return "rejected"
