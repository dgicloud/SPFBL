#!/usr/bin/env python3
"""Train Rspamd Bayes only from explicitly reviewed, local mail samples."""

from __future__ import print_function

import argparse
import datetime
import hashlib
import http.client
import json
import os
import re
import stat
import sys
import uuid

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
CHUNK_SIZE = 64 * 1024
CONTROLLER_HOST = "127.0.0.1"
CONTROLLER_PORT = 11334
SECRET_PATH = "/etc/had-antispam/rspamd-controller.secret"
AUDIT_PATH = "/var/lib/had-antispam/rspamd-learning/training.jsonl"
REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,79}$")
REVIEWER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{1,63}$")
CORRECTION_REASONS = (
    "reviewer_reclassified",
    "verified_user_feedback",
    "operator_label_error",
    "manual_retry_after_uncertain",
)


class LearningError(Exception):
    pass


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _validate_identity(reviewer, reference):
    if not REVIEWER_RE.fullmatch(reviewer or ""):
        raise LearningError("reviewer must use a short operator ID")
    if not REFERENCE_RE.fullmatch(reference or ""):
        raise LearningError("reference must be a ticket or review ID without spaces")


def _read_secret(path):
    info = os.stat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise LearningError("controller secret must be a root-owned regular file")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise LearningError("controller secret must not be accessible by group or others")
    with open(path, "r") as stream:
        secret = stream.read(256).strip()
    if len(secret) < 32 or not secret.isascii() or "\r" in secret or "\n" in secret:
        raise LearningError("controller secret file is invalid")
    return secret


def _open_reviewed_message(path):
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LearningError("cannot open reviewed sample (%s)" % exc.__class__.__name__)
    stream = os.fdopen(descriptor, "rb")
    try:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise LearningError("reviewed sample must be a regular file")
        if before.st_size <= 0 or before.st_size > MAX_MESSAGE_BYTES:
            raise LearningError("sample must be between 1 byte and 25 MiB")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_MESSAGE_BYTES:
                raise LearningError("sample exceeds 25 MiB")
            digest.update(chunk)
        after = os.fstat(stream.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise LearningError("sample changed while it was being read")
        if total != before.st_size:
            raise LearningError("sample size changed while it was being read")
        stream.seek(0)
        return stream, total, digest.hexdigest()
    except Exception:
        stream.close()
        raise


def _ensure_audit_directory(path):
    directory = os.path.dirname(path)
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700)
    info = os.stat(directory)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise LearningError("training audit directory must be root-owned")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise LearningError("training audit directory must have private permissions")


def _append_audit(path, record):
    _ensure_audit_directory(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
            raise LearningError("training audit file must be root-owned and regular")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LearningError("training audit file must be private")
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _prior_training_state(path, message_digest):
    if not os.path.exists(path):
        return None
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LearningError("cannot read training audit (%s)" % exc.__class__.__name__)
    records = []
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise LearningError("training audit file must be root-owned and private")
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            descriptor = -1
            for line_number, line in enumerate(stream, 1):
                try:
                    record = json.loads(line)
                except (ValueError, TypeError):
                    raise LearningError("training audit is invalid at line %d" % line_number)
                if not isinstance(record, dict):
                    raise LearningError("training audit is invalid at line %d" % line_number)
                if record.get("message_sha256") == message_digest:
                    records.append(record)
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    results = [record for record in records if record.get("event") == "learn_result"]
    return results[-1] if results else None


def _post_to_controller(stream, size, label, secret, connection_factory=None):
    connection_factory = connection_factory or http.client.HTTPConnection
    endpoint = "/learnspam" if label == "spam" else "/learnham"
    connection = connection_factory(CONTROLLER_HOST, CONTROLLER_PORT, timeout=20)
    try:
        connection.putrequest("POST", endpoint)
        connection.putheader("Content-Type", "message/rfc822")
        connection.putheader("Content-Length", str(size))
        connection.putheader("Password", secret)
        connection.endheaders()
        remaining = size
        while remaining:
            chunk = stream.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                raise LearningError("sample ended before its recorded size")
            connection.send(chunk)
            remaining -= len(chunk)
        response = connection.getresponse()
        response_body = response.read(4096).lower()
        return response.status, response_body
    finally:
        connection.close()


def learn_file(label, message_path, reviewer, reference, confirmed=False,
               correction_reason=None, secret_path=SECRET_PATH,
               audit_path=AUDIT_PATH, connection_factory=None):
    if label not in ("spam", "ham"):
        raise LearningError("label must be spam or ham")
    if not confirmed:
        raise LearningError("explicit --confirm-reviewed acknowledgement is required")
    _validate_identity(reviewer, reference)
    if correction_reason is not None and correction_reason not in CORRECTION_REASONS:
        raise LearningError("unsupported correction reason")

    secret = _read_secret(secret_path)
    stream, size, digest = _open_reviewed_message(message_path)
    try:
        previous = _prior_training_state(audit_path, digest)
        if previous and previous.get("outcome") in ("accepted", "already_learned", "unknown"):
            previous_label = previous.get("label")
            if previous_label == label and previous.get("outcome") != "unknown":
                raise LearningError("this exact sample is already recorded with the same label")
            if correction_reason is None:
                raise LearningError("sample has a prior or uncertain label; provide --correction-reason")
    except Exception:
        stream.close()
        raise
    event_id = uuid.uuid4().hex
    base = {
        "event_id": event_id,
        "timestamp": _utc_now(),
        "label": label,
        "reviewer": reviewer,
        "reference": reference,
        "message_sha256": digest,
        "bytes": size,
        "correction_reason": correction_reason,
    }
    try:
        _append_audit(audit_path, dict(base, event="learn_attempt"))
    except Exception:
        stream.close()
        raise

    outcome = "unknown"
    http_status = None
    error_class = None
    response_body = b""
    try:
        http_status, response_body = _post_to_controller(
            stream, size, label, secret, connection_factory)
        if 200 <= http_status < 300:
            outcome = "accepted"
        elif http_status == 404 and b"already learned" in response_body:
            outcome = "already_learned"
        elif http_status in (401, 403):
            outcome = "rejected_auth"
        elif 400 <= http_status < 500:
            outcome = "rejected"
        else:
            outcome = "unknown"
    except Exception as exc:
        # The controller may have received the whole message before a network error.
        # Rspamd's learn cache prevents same-class duplicates and supports relabeling.
        error_class = exc.__class__.__name__
    finally:
        stream.close()

    result = dict(base, event="learn_result", outcome=outcome,
                  http_status=http_status, error_class=error_class)
    _append_audit(audit_path, result)
    return result


def read_stats(secret_path=SECRET_PATH, connection_factory=None):
    secret = _read_secret(secret_path)
    connection_factory = connection_factory or http.client.HTTPConnection
    connection = connection_factory(CONTROLLER_HOST, CONTROLLER_PORT, timeout=5)
    try:
        connection.request("GET", "/stat", headers={"Password": secret})
        response = connection.getresponse()
        if response.status != 200:
            raise LearningError("authenticated Rspamd statistics request was rejected")
        payload = response.read(256 * 1024 + 1)
        if len(payload) > 256 * 1024:
            raise LearningError("Rspamd statistics response exceeded the size limit")
    except LearningError:
        raise
    except Exception as exc:
        raise LearningError("authenticated Rspamd statistics request failed (%s)" %
                            exc.__class__.__name__)
    finally:
        connection.close()

    try:
        data = json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise LearningError("Rspamd returned invalid statistics")
    if not isinstance(data, dict):
        raise LearningError("Rspamd returned invalid statistics")

    def counter(name):
        value = data.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise LearningError("Rspamd statistics are missing a valid %s counter" % name)
        return value

    lines = [
        "Messages scanned: %d" % counter("scanned"),
        "Messages learned: %d" % counter("learned"),
        "Total learns: %d" % counter("total_learns"),
        "Messages classified as HAM: %d" % counter("ham_count"),
        "Messages classified as SPAM: %d" % counter("spam_count"),
    ]
    statfiles = data.get("statfiles")
    if isinstance(statfiles, dict):
        for name in ("BAYES_HAM", "BAYES_SPAM"):
            values = statfiles.get(name)
            if not isinstance(values, dict):
                continue
            # These are Rspamd statfile/token metrics, not message training counts.
            fields = []
            for field in ("type", "total", "used", "size"):
                value = values.get(field)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    fields.append("%s=%d" % (field, value))
                elif (field == "type" and isinstance(value, str) and
                      re.fullmatch(r"[A-Za-z0-9_-]{1,32}", value)):
                    fields.append("type=%s" % value)
            if fields:
                lines.append("Statfile %s metrics (not message counts): %s" %
                             (name, ", ".join(fields)))
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command")
    learn = commands.add_parser("learn", help="train one operator-reviewed .eml sample")
    learn.add_argument("label", choices=("spam", "ham"))
    learn.add_argument("message", help="path to reviewed .eml; the tool does not copy it")
    learn.add_argument("--reviewer", required=True, help="short operator ID")
    learn.add_argument("--reference", required=True, help="ticket/review reference ID")
    learn.add_argument("--confirm-reviewed", action="store_true", required=True,
                       help="confirm a human reviewed and labeled this exact message")
    learn.add_argument("--correction-reason", choices=CORRECTION_REASONS,
                       help="required audit category when correcting a previous label")
    stats = commands.add_parser("stats", help="show scan and Bayes learn counts")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.error("choose learn or stats")
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("run as root")

    try:
        if args.command == "stats":
            print("\n".join(read_stats()))
            print("Bayes starts contributing after at least 200 reviewed learns in each class.")
            return 0
        result = learn_file(args.label, args.message, args.reviewer, args.reference,
                            confirmed=args.confirm_reviewed,
                            correction_reason=args.correction_reason)
    except LearningError as exc:
        parser.error(str(exc))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        parser.error("learning operation failed (%s)" % exc.__class__.__name__)

    print("label=%s outcome=%s bytes=%d sha256=%s" % (
        result["label"], result["outcome"], result["bytes"], result["message_sha256"]))
    if result["http_status"] is not None:
        print("controller_http_status=%d" % result["http_status"])
    if result["outcome"] == "unknown":
        print("The result may be uncertain; inspect had-rspamd-learn stats and the root-only audit before retrying.",
              file=sys.stderr)
        return 3
    if result["outcome"].startswith("rejected"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
