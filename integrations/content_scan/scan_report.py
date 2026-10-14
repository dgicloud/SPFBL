#!/usr/bin/env python3
"""Aggregate MONITOR logs without returning message identities or content."""

import argparse
from collections import Counter, deque
import json
import math
import re
import sys

CLIENT = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
EVENTS = {"message_queued", "scan_complete", "scan_failed", "request_dropped",
          "request_denied", "upload_queued", "upload_skipped", "reinject_deferred"}
ACTIONS = {"no action", "add header", "rewrite subject", "soft reject", "reject",
           "greylist", "quarantine", "discard"}
OUTCOME_EVENTS = {"scan_failed", "request_dropped", "upload_skipped", "reinject_deferred"}
SAFE_REASONS = {"capacity", "upload_limit", "queue_race", "message_too_large",
                "invalid_or_incomplete_body", "empty_message", "gateway_http_status",
                "transport_error", "invalid_config", "lock_unavailable",
                "local_lock_unavailable", "local_concurrency_limit",
                "sendmail_unavailable", "sendmail_input_error", "sendmail_failed"}
SAFE_FEEDBACK_STATUSES = {
    "client_feedback_disabled", "envelope_ineligible", "source_ip_invalid",
    "source_ip_not_global", "recipient_count", "ticket_missing", "ticket_invalid",
    "ticket_status_mismatch", "score_unavailable", "below_spam_threshold",
    "high_confidence_spam", "bayes_spam_probability_95", "accepted", "unchanged",
    "ticket_expired", "timeout_uncertain", "transport_failed", "response_invalid",
    "rejected", "target_invalid",
}
SAFE_TICKET_STATUSES = {
    "ticket_present", "ticket_missing", "ticket_invalid", "ticket_ambiguous",
    "ticket_not_issued", "header_unavailable", "unavailable",
}
SAFE_FEEDBACK_POLICIES = {"high_confidence_spam", "bayes_spam_probability_95"}
ANTIVIRUS_SYMBOLS = {"CLAM_VIRUS", "CLAM_VIRUS_FAIL",
                     "CLAM_VIRUS_ENCRYPTED", "CLAM_VIRUS_MACRO"}
SAFE_AUTOLEARN_REASONS = {
    "legacy_unknown", "eligible", "queue_id_missing", "null_sender", "sender_invalid",
    "client_ip_missing", "helo_missing", "received_port_invalid",
    "non_inbound_smtp_port", "authenticated", "received_port_missing",
}
SAMPLE_LIMIT = 10000
CLIENT_LIMIT = 256


def numeric(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def summary(values):
    ordered = sorted(values)
    if not ordered:
        return {"samples": 0}
    return {"samples": len(ordered), "p50": ordered[math.ceil(len(ordered) * .50)-1],
            "p95": ordered[math.ceil(len(ordered) * .95)-1], "max": ordered[-1]}


def report(lines, sample_limit=SAMPLE_LIMIT):
    clients = {}
    ignored = 0
    for line in lines:
        start = line.find("{")
        if start < 0:
            ignored += 1
            continue
        try:
            item = json.loads(line[start:])
        except (ValueError, TypeError):
            ignored += 1
            continue
        if (not isinstance(item, dict) or not isinstance(item.get("event"), str)
                or item["event"] not in EVENTS):
            ignored += 1
            continue
        client = item.get("client_id")
        if not isinstance(client, str) or not CLIENT.fullmatch(client):
            client = "unattributed"
        if client not in clients:
            if len(clients) >= CLIENT_LIMIT:
                ignored += 1
                continue
            clients[client] = {"events": Counter(), "actions": Counter(),
                               "outcomes": {},
                               "autolearn": {"profile_selected": Counter(),
                                             "eligibility": Counter()},
                               "spfbl": {"ticket_status": Counter(),
                                         "feedback": Counter(),
                                         "policy": Counter()},
                               "bayes_symbols": Counter(),
                               "antivirus_symbols": Counter(), "metrics": {
                                   key: deque(maxlen=sample_limit) for key in
                                   ("scan_ms", "queue_ms", "legacy_intake_and_queue_ms", "intake_ms",
                                    "latency_ms", "score", "bayes_ham_probability",
                                    "bayes_spam_probability")}}
        group = clients[client]
        event = item["event"]
        group["events"][event] += 1
        if event in OUTCOME_EVENTS:
            reason = item.get("reason")
            reason = reason if isinstance(reason, str) and reason in SAFE_REASONS else "other"
            group["outcomes"].setdefault(event, Counter())[reason] += 1
        if event == "scan_complete":
            action = item.get("action")
            group["actions"][action if isinstance(action, str) and action in ACTIONS
                             else "other"] += 1
            symbols = item.get("symbols")
            if isinstance(symbols, list):
                for symbol in ("BAYES_HAM", "BAYES_SPAM"):
                    if symbol in symbols:
                        group["bayes_symbols"][symbol] += 1
                for symbol in ANTIVIRUS_SYMBOLS:
                    if symbol in symbols:
                        group["antivirus_symbols"][symbol] += 1
            profile = item.get("autolearn_profile_selected")
            if "autolearn_profile_selected" not in item:
                group["autolearn"]["profile_selected"]["legacy_unknown"] += 1
            elif isinstance(profile, bool):
                group["autolearn"]["profile_selected"][
                    "selected" if profile else "not_selected"] += 1
            else:
                group["autolearn"]["profile_selected"]["other"] += 1
            eligibility = item.get("autolearn_eligibility")
            if "autolearn_eligibility" not in item:
                reasons = ["legacy_unknown"]
            elif isinstance(eligibility, str) and eligibility:
                reasons = eligibility.split(",")
            else:
                reasons = ["other"]
            for reason in reasons:
                reason = reason.strip()
                reason = reason if reason in SAFE_AUTOLEARN_REASONS else "other"
                group["autolearn"]["eligibility"][reason] += 1
            feedback = item.get("spfbl_feedback")
            if "spfbl_feedback" not in item:
                feedback = "legacy_unknown"
            elif not isinstance(feedback, str):
                feedback = "other"
            elif feedback not in SAFE_FEEDBACK_STATUSES:
                feedback = "other"
            group["spfbl"]["feedback"][feedback] += 1
            ticket_status = item.get("spfbl_ticket_status")
            if "spfbl_ticket_status" not in item:
                ticket_status = "legacy_unknown"
            elif not isinstance(ticket_status, str):
                ticket_status = "other"
            elif ticket_status not in SAFE_TICKET_STATUSES:
                ticket_status = "other"
            group["spfbl"]["ticket_status"][ticket_status] += 1
            policy = item.get("spfbl_feedback_policy")
            if "spfbl_feedback_policy" not in item:
                policy = "legacy_unknown"
            elif policy is None:
                policy = "none"
            elif not isinstance(policy, str):
                policy = "other"
            elif policy not in SAFE_FEEDBACK_POLICIES:
                policy = "other"
            group["spfbl"]["policy"][policy] += 1
        for key, values in group["metrics"].items():
            # Upload timing is distinct from classification timing. Failed
            # requests cannot contribute a successful scan score/latency.
            allowed = ((event == "scan_complete" and key in ("scan_ms", "score"))
                       or (event == "scan_complete" and key in ("bayes_ham_probability", "bayes_spam_probability"))
                       or (event == "scan_complete" and key == "queue_ms" and item.get("timing_version") == 2)
                       or (event == "scan_complete" and key == "legacy_intake_and_queue_ms" and item.get("timing_version") != 2)
                       or (event == "message_queued" and key == "intake_ms" and item.get("timing_version") == 2)
                       or (event in ("upload_queued", "upload_skipped") and key == "latency_ms"))
            value = item.get("queue_ms" if key == "legacy_intake_and_queue_ms" else key)
            if not allowed or not numeric(value):
                continue
            if key in ("bayes_ham_probability", "bayes_spam_probability"):
                if not 0 <= value <= 100:
                    continue
            elif key != "score" and value < 0:
                continue
            if key == "score" or key in ("bayes_ham_probability", "bayes_spam_probability") or value >= 0:
                values.append(value)
    return {"mode": "MONITOR", "ignored_lines": ignored,
            "metric_sample_limit_per_client": sample_limit,
            "metric_window": "most recent valid samples in supplied log window",
            "limitations": ["Actions are recommendations, not delivery outcomes.",
                            "Predictions are not reviewed labels or accuracy measurements.",
                            "Synthetic and real messages are both counted if supplied."],
            "clients": {name: {"events": dict(group["events"]),
                               "recommended_actions": dict(group["actions"]),
                               "outcomes": {event: dict(counts)
                                            for event, counts in sorted(group["outcomes"].items())},
                               "autolearn": {key: dict(counts)
                                             for key, counts in sorted(group["autolearn"].items())},
                               "spfbl": {key: dict(counts)
                                         for key, counts in sorted(group["spfbl"].items())},
                               "bayes_symbols": dict(group["bayes_symbols"]),
                               "antivirus_symbols": dict(group["antivirus_symbols"]),
                               "metrics": {key: summary(values) for key, values in group["metrics"].items()}}
                        for name, group in sorted(clients.items())}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", nargs="?", default="-", help="journal/syslog file or - for stdin")
    args = parser.parse_args(argv)
    if args.path == "-":
        result = report(sys.stdin)
    else:
        with open(args.path, encoding="utf-8", errors="replace") as stream:
            result = report(stream)
    print(json.dumps(result, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
