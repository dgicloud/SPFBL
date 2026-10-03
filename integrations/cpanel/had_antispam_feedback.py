#!/usr/bin/env python3
"""Submit an explicit, operator-reviewed SPFBL HAM/SPAM label by message ticket."""

from __future__ import print_function

import argparse
import collections
import hashlib
import hmac
import ipaddress
import json
import os
import re
import socket
import stat
import sys

COMMON_DIRS = (
    "/usr/local/libexec/had-antispam",
    os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "common")),
)
for common_dir in COMMON_DIRS:
    if os.path.isfile(os.path.join(common_dir, "technical_signals.py")):
        if common_dir not in sys.path:
            sys.path.insert(0, common_dir)
        break

from technical_signals import (
    SIGNAL_NAMES,
    SignalError,
    load_metadata_key,
    parse_signal_event_line,
    ticket_fingerprint,
)


CONFIG_PATH = "/etc/had-antispam/client.conf"
AUDIT_KEY_PATH = "/etc/had-antispam/feedback-hmac.key"
AUDIT_KEY_BYTES = 32
HEADER_NAME = b"x-had-antispam-ticket"
MAX_HEADER_BYTES = 65536
MAX_RESPONSE_BYTES = 2048
FEEDBACK_VALUE = re.compile(
    r"^(PASS|WHITE|FLAG|HOLD|SOFTFAIL|NEUTRAL|NONE) ([A-Za-z0-9_-]{44,512})$"
)
AUDIT_EVENT = re.compile(
    r"\bhad-antispam-feedback decision=(PASS|WHITE|FLAG|HOLD|SOFTFAIL|NEUTRAL|NONE) "
    r"action=(spam|ham) outcome=([a-z0-9_]{1,64})"
    r"(?: ticket_id=([a-f0-9]{64}))?(?: signal_id=([a-f0-9]{64}))?(?:\s|$)"
)
AUDIT_OUTCOMES = frozenset(
    (
        "accepted",
        "unchanged",
        "client_config_unavailable",
        "client_config_invalid",
        "client_config_permissions_invalid",
        "client_config_duplicate_key",
        "client_config_incomplete",
        "feedback_target_invalid",
        "feedback_timeout_uncertain",
        "feedback_transport_failed",
        "feedback_response_invalid",
        "feedback_rejected",
        "feedback_ticket_invalid",
        "feedback_ticket_missing_or_ambiguous",
        "message_file_invalid",
        "message_headers_too_large",
        "message_header_terminator_missing",
        "message_unavailable",
    )
)
CORE_REPLY_OUTCOMES = frozenset(("accepted", "unchanged"))
CORE_OK_OUTCOMES = frozenset(("accepted",))
QUALIFIER_GROUPS = {
    "FLAG": "suspected",
    "HOLD": "suspected",
    "PASS": "not_flagged",
    "WHITE": "not_flagged",
    "SOFTFAIL": "ambiguous",
    "NEUTRAL": "ambiguous",
    "NONE": "ambiguous",
}
DATASET_SIGNAL_FIELDS = SIGNAL_NAMES


class FeedbackError(ValueError):
    """A sanitized feedback error that never includes a ticket or server reply."""


def extract_feedback_record(stream):
    """Read one server-added decision/ticket pair, rejecting ambiguity."""
    raw = bytearray()
    while len(raw) <= MAX_HEADER_BYTES:
        line = stream.readline(MAX_HEADER_BYTES + 1 - len(raw))
        if not line:
            raise FeedbackError("message_header_terminator_missing")
        raw.extend(line)
        if len(raw) > MAX_HEADER_BYTES:
            raise FeedbackError("message_headers_too_large")
        if line in (b"\n", b"\r\n"):
            break
    else:
        raise FeedbackError("message_headers_too_large")
    header = bytes(raw)
    values = []
    current_name = None
    current_value = bytearray()

    def finish_field():
        if current_name == HEADER_NAME:
            values.append(bytes(current_value).strip())

    for line in re.split(br"\r?\n", header):
        if line.startswith((b" ", b"\t")):
            if current_name is not None:
                current_value.extend(b" " + line.strip())
            continue
        finish_field()
        current_name = None
        current_value = bytearray()
        name, separator, value = line.partition(b":")
        if separator:
            current_name = name.strip().lower()
            current_value.extend(value.strip())
    finish_field()

    if len(values) != 1:
        raise FeedbackError("feedback_ticket_missing_or_ambiguous")
    try:
        value = values[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise FeedbackError("feedback_ticket_invalid") from exc
    match = FEEDBACK_VALUE.fullmatch(value)
    if match is None:
        raise FeedbackError("feedback_ticket_invalid")
    return match.group(1), match.group(2)


def extract_feedback_ticket(stream):
    """Return only the opaque ticket for callers that do not need its class."""
    return extract_feedback_record(stream)[1]


def read_feedback_record(message_path):
    """Read an anonymous classification label and its ticket from a message."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(message_path, flags)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise FeedbackError("message_file_invalid")
        stream = os.fdopen(descriptor, "rb")
        descriptor = -1
        with stream:
            return extract_feedback_record(stream)
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def read_feedback_ticket(message_path):
    return read_feedback_record(message_path)[1]


def load_target(config_path=CONFIG_PATH, enforce_root_permissions=True):
    """Load the installed root-owned endpoint without accepting shell syntax."""
    try:
        info = os.lstat(config_path)
    except OSError as exc:
        raise FeedbackError("client_config_unavailable") from exc
    if not stat.S_ISREG(info.st_mode):
        raise FeedbackError("client_config_invalid")
    if enforce_root_permissions and os.name == "posix" and (
        info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise FeedbackError("client_config_permissions_invalid")

    values = {}
    try:
        with open(config_path, "r") as stream:
            for line in stream:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                key, separator, value = line.partition("=")
                if not separator or key not in ("HAD_SPFBL_HOST", "HAD_SPFBL_PORT"):
                    continue
                if key in values:
                    raise FeedbackError("client_config_duplicate_key")
                values[key] = value.strip()
    except OSError as exc:
        raise FeedbackError("client_config_unavailable") from exc

    host = values.get("HAD_SPFBL_HOST")
    port_text = values.get("HAD_SPFBL_PORT")
    if not host or not port_text:
        raise FeedbackError("client_config_incomplete")
    try:
        host = str(ipaddress.ip_address(host))
        port = int(port_text)
    except ValueError as exc:
        raise FeedbackError("client_config_invalid") from exc
    if not 1 <= port <= 65535:
        raise FeedbackError("client_config_invalid")
    return host, port


def serialize_feedback(action, ticket):
    if action not in ("spam", "ham"):
        raise FeedbackError("feedback_action_invalid")
    if not isinstance(ticket, str) or not re.fullmatch(r"[A-Za-z0-9_-]{44,512}", ticket):
        raise FeedbackError("feedback_ticket_invalid")
    return (action.upper() + " " + ticket + "\n").encode("ascii")


def submit_feedback(action, ticket, host, port, timeout=2.0):
    """Submit exactly once; a transport timeout is reported as uncertain."""
    request = serialize_feedback(action, ticket)
    try:
        ipaddress.ip_address(host)
        if not 1 <= int(port) <= 65535:
            raise ValueError("invalid port")
    except (TypeError, ValueError) as exc:
        raise FeedbackError("feedback_target_invalid") from exc

    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as connection:
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
    except socket.timeout as exc:
        raise FeedbackError("feedback_timeout_uncertain") from exc
    except OSError as exc:
        raise FeedbackError("feedback_transport_failed") from exc

    if not response or len(response) > MAX_RESPONSE_BYTES or b"\x00" in response:
        raise FeedbackError("feedback_response_invalid")
    line = bytes(response).split(b"\n", 1)[0].strip()
    if line == b"OK" or line.startswith(b"OK "):
        return "accepted"
    if line in (b"ALREADY REMOVED", b"DUPLICATE COMPLAIN"):
        return "unchanged"
    raise FeedbackError("feedback_rejected")


def _confirm(action):
    prompt = "Enviar feedback {} para esta mensagem? [s/N]: ".format(action.upper())
    try:
        answer = input(prompt).strip().lower()
    except EOFError:
        return False
    return answer in ("s", "sim", "y", "yes")


def _audit(action, outcome, decision="unknown", ticket_id=None, signal_id=None):
    try:
        import syslog
    except ImportError:
        return
    try:
        message = "had-antispam-feedback decision={} action={} outcome={}".format(
            decision, action, outcome
        )
        if isinstance(ticket_id, str) and re.fullmatch(r"[a-f0-9]{64}", ticket_id):
            message += " ticket_id=" + ticket_id
        if isinstance(signal_id, str) and re.fullmatch(r"[a-f0-9]{64}", signal_id):
            message += " signal_id=" + signal_id
        syslog.syslog(syslog.LOG_NOTICE, message)
    except OSError:
        print("Aviso: não foi possível gravar o evento de auditoria no syslog.", file=sys.stderr)


def _validate_audit_key_parent(path, enforce_root_permissions):
    directory = os.path.dirname(os.path.abspath(path))
    try:
        info = os.lstat(directory)
    except OSError as exc:
        raise FeedbackError("audit_key_directory_unavailable") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise FeedbackError("audit_key_directory_invalid")
    if enforce_root_permissions and os.name == "posix" and (
        info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise FeedbackError("audit_key_directory_permissions_invalid")


def load_or_create_audit_key(path=AUDIT_KEY_PATH, enforce_root_permissions=True):
    """Load or atomically create the root-only key used to pseudonymize tickets."""
    _validate_audit_key_parent(path, enforce_root_permissions)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    for attempt in range(2):
        try:
            descriptor = os.open(path, os.O_RDONLY | nofollow)
        except FileNotFoundError as exc:
            if attempt:
                raise FeedbackError("audit_key_unavailable") from exc
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                    0o600,
                )
            except FileExistsError:
                continue
            except OSError as create_error:
                raise FeedbackError("audit_key_unavailable") from create_error
            try:
                key = os.urandom(AUDIT_KEY_BYTES)
                with os.fdopen(descriptor, "wb") as stream:
                    descriptor = -1
                    stream.write(key)
                    stream.flush()
                    os.fsync(stream.fileno())
            except OSError as write_error:
                if descriptor >= 0:
                    os.close(descriptor)
                try:
                    os.unlink(path)
                except OSError:
                    pass
                raise FeedbackError("audit_key_unavailable") from write_error
            continue
        except OSError as exc:
            raise FeedbackError("audit_key_invalid") from exc

        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise FeedbackError("audit_key_invalid")
            if enforce_root_permissions and os.name == "posix" and (
                info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077
            ):
                raise FeedbackError("audit_key_permissions_invalid")
            key = os.read(descriptor, AUDIT_KEY_BYTES + 1)
            if len(key) != AUDIT_KEY_BYTES:
                raise FeedbackError("audit_key_invalid")
            return key
        finally:
            os.close(descriptor)
    raise FeedbackError("audit_key_unavailable")


def feedback_ticket_id(ticket, key):
    """Return a stable, keyed ticket fingerprint; never persist the ticket itself."""
    if not isinstance(ticket, str) or not re.fullmatch(r"[A-Za-z0-9_-]{44,512}", ticket):
        raise FeedbackError("feedback_ticket_invalid")
    if not isinstance(key, bytes) or len(key) != AUDIT_KEY_BYTES:
        raise FeedbackError("audit_key_invalid")
    return hmac.new(key, ticket.encode("ascii"), hashlib.sha256).hexdigest()


def summarize_feedback_log(lines):
    """Aggregate feedback events and keyed-ticket labels without returning log data."""
    counts = collections.Counter()
    ticket_states = {}
    signal_labels = {}
    signal_snapshots = {}
    corrected_tickets = set()
    accepted_ticket_events = 0
    for line in lines:
        signal_record = parse_signal_event_line(line)
        if signal_record is not None:
            signal_id, snapshot = signal_record
            signal_snapshots[signal_id] = snapshot
            continue
        match = AUDIT_EVENT.search(line)
        if match is None:
            continue
        decision, action, outcome, ticket_id, signal_id = match.groups()
        if outcome not in AUDIT_OUTCOMES:
            continue
        counts[(decision, action, outcome)] += 1
        if ticket_id is not None and outcome in CORE_OK_OUTCOMES:
            accepted_ticket_events += 1
            previous = ticket_states.get(ticket_id)
            if previous is not None and previous[1] != action:
                corrected_tickets.add(ticket_id)
            ticket_states[ticket_id] = (decision, action)
        if signal_id is not None and outcome in CORE_OK_OUTCOMES:
            signal_labels[signal_id] = action

    groups = {}
    for group_name in ("suspected", "not_flagged", "ambiguous"):
        spam = sum(
            count for (decision, action, outcome), count in counts.items()
            if QUALIFIER_GROUPS[decision] == group_name
            and action == "spam"
            and outcome in CORE_OK_OUTCOMES
        )
        ham = sum(
            count for (decision, action, outcome), count in counts.items()
            if QUALIFIER_GROUPS[decision] == group_name
            and action == "ham"
            and outcome in CORE_OK_OUTCOMES
        )
        total = spam + ham
        groups[group_name] = {
            "operator_spam_events": spam,
            "operator_ham_events": ham,
            "core_ok_feedback_events": total,
            "operator_spam_event_fraction": float(spam) / total if total else None,
        }

    unique_ticket_groups = {}
    for group_name in ("suspected", "not_flagged", "ambiguous"):
        spam = sum(
            1 for decision, action in ticket_states.values()
            if QUALIFIER_GROUPS[decision] == group_name and action == "spam"
        )
        ham = sum(
            1 for decision, action in ticket_states.values()
            if QUALIFIER_GROUPS[decision] == group_name and action == "ham"
        )
        total = spam + ham
        unique_ticket_groups[group_name] = {
            "operator_spam_tickets": spam,
            "operator_ham_tickets": ham,
            "unique_labelled_tickets": total,
            "operator_spam_ticket_fraction": float(spam) / total if total else None,
        }

    latest_labels_by_decision = {
        decision: {"operator_spam_tickets": 0, "operator_ham_tickets": 0}
        for decision in sorted(QUALIFIER_GROUPS)
    }
    for decision, action in ticket_states.values():
        metric = "operator_{}_tickets".format(action)
        latest_labels_by_decision[decision][metric] += 1

    override_indicators = {
        "flag_or_hold_labelled_ham": sum(
            1 for decision, action in ticket_states.values()
            if decision in ("FLAG", "HOLD") and action == "ham"
        ),
        "pass_or_white_labelled_spam": sum(
            1 for decision, action in ticket_states.values()
            if decision in ("PASS", "WHITE") and action == "spam"
        ),
    }

    feedback_events_by_decision_action_outcome = collections.OrderedDict()
    for (decision, action, outcome), count in sorted(counts.items()):
        feedback_events_by_decision_action_outcome[
            "{}|{}|{}".format(decision, action, outcome)
        ] = count

    core_replied = sum(
        count for (_, _, outcome), count in counts.items()
        if outcome in CORE_REPLY_OUTCOMES
    )
    core_ok = sum(
        count for (_, _, outcome), count in counts.items()
        if outcome in CORE_OK_OUTCOMES
    )
    feature_review_counts = collections.OrderedDict()
    linked_signal_tickets = 0
    unlinked_signal_tickets = 0
    for signal_id, action in signal_labels.items():
        snapshot = signal_snapshots.get(signal_id)
        if snapshot is None:
            unlinked_signal_tickets += 1
            continue
        linked_signal_tickets += 1
        for feature, raw_value in snapshot.items():
            value = "unknown" if raw_value is None else str(raw_value).lower()
            value_counts = feature_review_counts.setdefault(feature, collections.OrderedDict())
            label_counts = value_counts.setdefault(value, {"operator_spam": 0, "operator_ham": 0})
            label_counts["operator_" + action] += 1
    for value_counts in feature_review_counts.values():
        for label_counts in value_counts.values():
            label_counts["reviewed"] = label_counts["operator_spam"] + label_counts["operator_ham"]

    return {
        "record_granularity": "feedback_event",
        "deduplicated_by_ticket": False,
        "matched_feedback_events": sum(counts.values()),
        "core_replied_feedback_events": core_replied,
        "core_ok_feedback_events": core_ok,
        "core_ok_events_with_ticket_id": accepted_ticket_events,
        "unique_tickets_with_core_ok_feedback": len(ticket_states),
        "tickets_with_corrected_labels": len(corrected_tickets),
        "feedback_events_by_decision_action_outcome": feedback_events_by_decision_action_outcome,
        "reviewed_feedback_event_groups": groups,
        "latest_accepted_ticket_label_groups": unique_ticket_groups,
        "latest_accepted_ticket_labels_by_decision": latest_labels_by_decision,
        "operator_override_indicators": override_indicators,
        "latest_feedback_tickets_with_signal_id": len(signal_labels),
        "latest_feedback_tickets_with_signal_snapshot": linked_signal_tickets,
        "latest_feedback_tickets_without_signal_snapshot": unlinked_signal_tickets,
        "operator_labels_by_technical_signal": feature_review_counts,
        "interpretation": (
            "Counts are feedback audit events, not unique messages or tickets; correcting a prior label can add another event. "
            "Only core OK responses enter operator-label event fractions; unchanged replies are excluded. "
            "The additional unique-ticket view uses the latest accepted label in the supplied log order for events with a keyed ticket ID; older events without an ID are excluded from that view. "
            "Per-decision counts and override indicators describe operator-selected reviews only; they are not false-positive/false-negative rates, global accuracy, or a calibration set. "
            "OK confirms protocol processing, not a reputation counter change or peer delivery. "
            "Technical signal counts are local, metadata-only, and link to a ticket through a keyed pseudonym. "
            "Operator-selected events are not global precision, recall, classifier accuracy, or a calibration set."
        ),
    }


def read_feedback_report(log_path):
    """Read a syslog text file and return counts only, never source lines."""
    if log_path == "-":
        return summarize_feedback_log(sys.stdin)
    try:
        with open(log_path, "r", errors="replace") as stream:
            return summarize_feedback_log(stream)
    except OSError as exc:
        raise FeedbackError("audit_log_unavailable") from exc


def build_feedback_dataset(lines):
    """Build identity-free feature rows from the latest accepted human labels."""
    signal_snapshots = {}
    latest_labels = {}
    for line in lines:
        signal_record = parse_signal_event_line(line)
        if signal_record is not None:
            signal_id, snapshot = signal_record
            signal_snapshots[signal_id] = snapshot
            continue
        match = AUDIT_EVENT.search(line)
        if match is None:
            continue
        _, action, outcome, _, signal_id = match.groups()
        if outcome == "accepted" and signal_id is not None:
            latest_labels[signal_id] = action

    rows = []
    for signal_id in sorted(latest_labels):
        snapshot = signal_snapshots.get(signal_id)
        if snapshot is None:
            continue
        rows.append({
            "label": latest_labels[signal_id],
            "signals": {
                field: snapshot[field]
                for field in DATASET_SIGNAL_FIELDS
            },
        })
    return rows


def read_feedback_dataset(log_path):
    """Read a local syslog and return only allowlisted signal/label rows."""
    if log_path == "-":
        return build_feedback_dataset(sys.stdin)
    try:
        with open(log_path, "r", errors="replace") as stream:
            return build_feedback_dataset(stream)
    except OSError as exc:
        raise FeedbackError("audit_log_unavailable") from exc


def summarize_feedback_dataset(rows):
    """Report class balance and signal coverage without retaining identities."""
    labels = collections.Counter(row["label"] for row in rows)
    coverage = {}
    for field in DATASET_SIGNAL_FIELDS:
        known = sum(
            1 for row in rows
            if row["signals"][field] is not None
            and row["signals"][field] != "unknown"
        )
        total = len(rows)
        coverage[field] = {
            "known_count": known,
            "unknown_count": total - known,
            "known_fraction": float(known) / total if total else None,
        }
    patterns = {
        tuple(row["signals"][field] for field in DATASET_SIGNAL_FIELDS)
        for row in rows
    }
    return {
        "record_count": len(rows),
        "label_counts": {label: labels.get(label, 0) for label in ("ham", "spam")},
        "signal_coverage": coverage,
        "distinct_technical_patterns": len(patterns),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("spam", "ham", "report", "dataset"))
    parser.add_argument(
        "path",
        help="arquivo .eml para spam/ham ou log para report/dataset; use - para stdin",
    )
    parser.add_argument("--config", default=CONFIG_PATH, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if hasattr(os, "geteuid") and os.geteuid() != 0:
        print("Execute como root.", file=sys.stderr)
        return 2
    if args.action in ("report", "dataset"):
        try:
            if args.action == "report":
                report = read_feedback_report(args.path)
            else:
                rows = read_feedback_dataset(args.path)
        except FeedbackError as exc:
            print("Saída não gerada: {}".format(exc.args[0]), file=sys.stderr)
            return 1
        if args.action == "report":
            print(json.dumps(report, ensure_ascii=True, sort_keys=True))
        else:
            summary = summarize_feedback_dataset(rows)
            metadata = {
                "type": "dataset",
                "schema_version": 1,
                "record_count": summary["record_count"],
                "label_counts": summary["label_counts"],
                "signal_coverage": summary["signal_coverage"],
                "distinct_technical_patterns": summary["distinct_technical_patterns"],
                "features": list(DATASET_SIGNAL_FIELDS),
                "label_source": "accepted_operator_feedback",
                "limitations": [
                    "operator-selected labels are not a representative sample or ground truth",
                    "rows have no message identifiers or timestamps and are not a calibrated model",
                ],
            }
            print(json.dumps(metadata, ensure_ascii=True, sort_keys=True))
            for row in rows:
                print(json.dumps({"type": "sample", **row}, ensure_ascii=True, sort_keys=True))
        return 0

    if not sys.stdin.isatty() or not _confirm(args.action):
        _audit(args.action, "cancelled")
        print("Feedback cancelado.", file=sys.stderr)
        return 2

    decision = "unknown"
    ticket_id = None
    signal_id = None
    try:
        decision, ticket = read_feedback_record(args.path)
        try:
            audit_key = load_or_create_audit_key()
            ticket_id = feedback_ticket_id(ticket, audit_key)
        except FeedbackError as key_error:
            print(
                "Aviso: feedback continuará sem deduplicação no relatório ({}).".format(key_error.args[0]),
                file=sys.stderr,
            )
        try:
            signal_id = ticket_fingerprint(ticket, load_metadata_key())
        except SignalError:
            # Older installs and messages without the optional signals key remain usable.
            signal_id = None
        host, port = load_target(args.config)
        status = submit_feedback(args.action, ticket, host, port)
    except (FeedbackError, OSError) as exc:
        code = exc.args[0] if isinstance(exc, FeedbackError) and exc.args else "message_unavailable"
        _audit(args.action, code, decision, ticket_id, signal_id)
        print("Feedback não enviado: {}".format(code), file=sys.stderr)
        return 1

    _audit(args.action, status, decision, ticket_id, signal_id)
    if status == "accepted":
        print("Feedback enviado ao core SPFBL.")
        return 0
    print("O core informou que o feedback não alterou o estado.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
