#!/usr/bin/env python3
"""Stream one accepted Exim/Postfix message to the HAD monitor gateway.

The message is read from stdin, held only in transit, and never written to a
file. This client intentionally exits successfully for all scanner failures:
content scanning is MONITOR-only and must not change mail acceptance/delivery.
Compatible with the Python 3.6 runtime shipped by supported cPanel releases.
"""

from __future__ import print_function

import http.client
import base64
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
from email.utils import getaddresses
from urllib.parse import urlsplit

CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT = 20.0
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
ADDRESS_RE = re.compile(r"^[^\s<>@,]+@[^\s<>@,]+$")
HELO_RE = re.compile(r"^[\x21-\x7e]{1,255}$")
AUTH_USER_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,256}$")
BSMTP_COMMAND_RE = re.compile(br"^(MAIL FROM|RCPT TO):\s*<([^>]*)>(?:\s+.*)?$", re.I)
MAX_BSMTP_LINE_BYTES = 8192
MAX_MESSAGE_HEADER_BYTES = 65536
SPFBL_FEEDBACK_HEADER = b"x-had-antispam-ticket"
SPFBL_NATIVE_HEADER = b"received-spfbl"
SPFBL_FEEDBACK_VALUE_RE = re.compile(
    br"^(PASS|WHITE|FLAG|HOLD|SOFTFAIL|NEUTRAL|NONE|FAIL) ([A-Za-z0-9_-]{44,512})$"
)
TICKET_STATUS_VALUES = frozenset((
    "ticket_present", "ticket_missing", "ticket_invalid", "ticket_ambiguous",
    "ticket_not_issued", "header_unavailable",
))


def log_event(event, **fields):
    """Write a privacy-safe event to the local syslog socket; never stdout."""
    import socket as socket_module

    record = {"event": event}
    record.update(fields)
    payload = ("<134>had-content-scan: " + json.dumps(
        record, sort_keys=True, separators=(",", ":")
    )).encode("utf-8")
    try:
        sock = socket_module.socket(socket_module.AF_UNIX, socket_module.SOCK_DGRAM)
        try:
            sock.sendto(payload, "/dev/log")
        finally:
            sock.close()
    except (OSError, AttributeError):
        # Logging must never write to Exim's pipe stdout/stderr or affect mail.
        pass


def load_config(path):
    info = os.stat(path)
    if stat.S_IMODE(info.st_mode) & 0o027:
        raise ValueError("client configuration is accessible by other users")
    with open(path, "r") as stream:
        config = json.load(stream)
    endpoint = config.get("endpoint")
    parsed = urlsplit(endpoint or "")
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("endpoint must be an HTTPS URL without embedded credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("endpoint must not contain a query or fragment")
    client_id = config.get("client_id", "")
    token = config.get("token", "")
    if not CLIENT_ID_RE.fullmatch(client_id):
        raise ValueError("invalid client_id")
    if not isinstance(token, str) or len(token) < 40 or "\r" in token or "\n" in token:
        raise ValueError("invalid client token")
    max_bytes = config.get("max_bytes", DEFAULT_MAX_BYTES)
    timeout = config.get("timeout_seconds", DEFAULT_TIMEOUT)
    if not isinstance(max_bytes, int) or max_bytes < 1024 or max_bytes > DEFAULT_MAX_BYTES:
        raise ValueError("max_bytes must be between 1 KiB and 25 MiB")
    if not isinstance(timeout, (int, float)) or timeout < 1 or timeout > 60:
        raise ValueError("timeout_seconds must be between 1 and 60")
    return parsed, client_id, token, max_bytes, float(timeout)


def _drain(stream):
    try:
        while stream.read(CHUNK_SIZE):
            pass
    except Exception:
        # The pipe is deliberately best-effort; never fail Exim's unseen copy.
        pass


def _connect(parsed, timeout):
    context = ssl.create_default_context()
    port = parsed.port or 443
    return http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=context)


def normalize_metadata(queue_id=None, sender=None, recipients=None, client_ip=None,
                       helo=None, auth_user=None, received_port=None):
    """Validate MTA envelope metadata; malformed values can never become HTTP headers."""
    metadata = {}
    if isinstance(queue_id, str) and queue_id != "-" and MESSAGE_ID_RE.fullmatch(queue_id):
        metadata["queue_id"] = queue_id

    sender = (sender or "").strip()
    if sender == "<>" or not sender:
        metadata["from"] = "<>"
    elif len(sender) <= 320 and ADDRESS_RE.fullmatch(sender):
        metadata["from"] = sender

    normalized_recipients = []
    recipient_values = list(recipients or [])
    recipients_valid = len(recipient_values) <= 100
    for address in recipient_values:
        if not isinstance(address, str):
            recipients_valid = False
            continue
        address = address.strip()
        if len(address) <= 320 and ADDRESS_RE.fullmatch(address):
            normalized_recipients.append(address)
        else:
            recipients_valid = False
    metadata["rcpt"] = list(dict.fromkeys(normalized_recipients))[:100]

    try:
        metadata["ip"] = str(ipaddress.ip_address((client_ip or "").strip()))
    except (ValueError, TypeError):
        pass
    helo = (helo or "").strip()
    if HELO_RE.fullmatch(helo):
        metadata["helo"] = helo
    received_port_invalid = False
    if received_port is not None:
        try:
            received_port = int(str(received_port).strip())
        except (TypeError, ValueError):
            received_port_invalid = True
        else:
            if 1 <= received_port <= 65535:
                metadata["received_port"] = received_port
            else:
                received_port_invalid = True
    auth_present = bool((auth_user or "").strip())
    auth_user = (auth_user or "").strip()
    if AUTH_USER_RE.fullmatch(auth_user):
        metadata["user"] = auth_user

    # Bayes learning is message-level; an Exim system-filter copy may omit or
    # fail to preserve recipient metadata. Keep only the queue/sender/source/
    # HELO and unauthenticated gates. SPFBL feedback applies the stricter
    # single-recipient rule separately.
    exclusion_reasons = []
    if not metadata.get("queue_id"):
        exclusion_reasons.append("queue_id_missing")
    if metadata.get("from") == "<>":
        exclusion_reasons.append("null_sender")
    elif not metadata.get("from"):
        exclusion_reasons.append("sender_invalid")
    if not metadata.get("ip"):
        exclusion_reasons.append("client_ip_missing")
    if not metadata.get("helo"):
        exclusion_reasons.append("helo_missing")
    if received_port_invalid:
        exclusion_reasons.append("received_port_invalid")
    elif received_port is not None and metadata.get("received_port") != 25:
        exclusion_reasons.append("non_inbound_smtp_port")
    if auth_present:
        exclusion_reasons.append("authenticated")
    metadata["autolearn_eligible"] = not exclusion_reasons
    metadata["autolearn_ineligibility_reason"] = (
        ",".join(exclusion_reasons) if exclusion_reasons else "eligible")
    return metadata


def require_received_port_for_bsmtp(metadata, bsmtp_envelope):
    """Fail closed for Exim BSMTP scans when the trusted ingress port is absent."""
    if bsmtp_envelope and metadata.get("received_port") is None:
        metadata["autolearn_eligible"] = False
        metadata["autolearn_ineligibility_reason"] = "received_port_missing"
    return metadata


def monitor_headers(metadata):
    """Return allowlisted headers for the authenticated collector-to-gateway hop."""
    headers = []
    for key, header in (("queue_id", "X-SFOX-SMTP-Queue-ID"),
                        ("from", "X-SFOX-SMTP-From"),
                        ("ip", "X-SFOX-SMTP-IP"),
                        ("helo", "X-SFOX-SMTP-HELO"),
                        ("user", "X-SFOX-SMTP-User"),
                        ("received_port", "X-SFOX-SMTP-Received-Port")):
        value = metadata.get(key)
        if value:
            headers.append((header, value))
    for recipient in metadata.get("rcpt", []):
        headers.append(("X-SFOX-SMTP-Rcpt", recipient))
    return headers


def _bounded_recipient_count(value):
    """Keep envelope diagnostics numeric and bounded; never emit addresses."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return min(value, 101)


def _message_header_parts(message, max_header_bytes=MAX_MESSAGE_HEADER_BYTES):
    """Split one RFC822 message without interpreting or retaining its body."""
    if not isinstance(message, (bytes, bytearray)):
        return None
    boundaries = []
    for marker in (b"\r\n\r\n", b"\n\n"):
        index = message.find(marker, 0, max_header_bytes + len(marker) + 1)
        if index >= 0:
            boundaries.append((index, marker))
    if not boundaries:
        return None
    index, marker = min(boundaries, key=lambda item: item[0])
    if index + len(marker) > max_header_bytes:
        return None
    return message[:index], marker, index + len(marker)


def extract_spfbl_feedback_ticket(message):
    """Return one SPFBL ticket from the Exim marker or native Postfix header.

    The caller must also enforce the MTA client, envelope, and single-recipient
    eligibility. The opaque ticket is never suitable for logs.
    """
    parts = _message_header_parts(message)
    if parts is None:
        return None, "header_unavailable"
    header = bytes(parts[0])
    values = []
    current_name = None
    current_value = bytearray()

    def finish_field():
        if current_name in (SPFBL_FEEDBACK_HEADER, SPFBL_NATIVE_HEADER):
            values.append((current_name, bytes(current_value).strip()))

    for line in header.splitlines():
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

    if not values:
        return None, "ticket_missing"
    if len(values) != 1:
        return None, "ticket_ambiguous"
    header_name, value = values[0]
    if header_name == SPFBL_FEEDBACK_HEADER:
        if value == b"NONE":
            return None, "ticket_not_issued"
        match = SPFBL_FEEDBACK_VALUE_RE.fullmatch(value)
        if match is None:
            return None, "ticket_invalid"
        qualifier, ticket = match.groups()
    else:
        fields = value.split()
        if len(fields) != 2 or fields[0] not in (
                b"PASS", b"WHITE", b"FLAG", b"HOLD", b"SOFTFAIL", b"NEUTRAL", b"NONE",
                b"FAIL"):
            return None, "ticket_invalid"
        candidate = fields[1]
        if candidate.startswith((b"http://", b"https://")):
            candidate = candidate.rsplit(b"/", 1)[-1]
        if not re.fullmatch(br"[A-Za-z0-9_-]{44,512}", candidate):
            return None, "ticket_invalid"
        qualifier, ticket = fields[0], candidate
    try:
        qualifier = qualifier.decode("ascii")
        ticket = ticket.decode("ascii")
    except UnicodeDecodeError:
        return None, "ticket_invalid"
    return {"qualifier": qualifier, "ticket": ticket}, "ticket_present"


class PrefixReplayStream(object):
    """Replay a bounded prefix before continuing to read the original stream."""

    def __init__(self, prefix, source):
        self.prefix = memoryview(prefix)
        self.offset = 0
        self.source = source

    def read(self, size=-1):
        remaining = len(self.prefix) - self.offset
        if size is None or size < 0:
            head = bytes(self.prefix[self.offset:])
            self.offset = len(self.prefix)
            return head + self.source.read()
        if size == 0:
            return b""
        if remaining >= size:
            start = self.offset
            self.offset += size
            return bytes(self.prefix[start:self.offset])
        head = bytes(self.prefix[self.offset:])
        self.offset = len(self.prefix)
        return head + self.source.read(size - len(head))


def capture_spfbl_ticket_status(stream):
    """Inspect only the bounded RFC822 header and return a replayable stream.

    This is diagnostic metadata only: the opaque ticket remains in the message
    and is independently parsed by the authenticated central gateway.
    """
    prefix = bytearray()
    max_prefix = MAX_MESSAGE_HEADER_BYTES + 4
    while len(prefix) < max_prefix:
        chunk = stream.read(min(CHUNK_SIZE, max_prefix - len(prefix)))
        if not chunk:
            break
        prefix.extend(chunk)
        if _message_header_parts(prefix) is not None:
            break
    _, status = extract_spfbl_feedback_ticket(prefix)
    if status not in TICKET_STATUS_VALUES:
        status = "header_unavailable"
    return PrefixReplayStream(bytes(prefix), stream), status


def strip_spfbl_feedback_header(message, remove_native=False):
    """Remove internal tickets before scoring; preserve native Received-SPFBL on delivery."""
    parts = _message_header_parts(message)
    if parts is None:
        return message
    header, separator, body_offset = parts
    kept = []
    removable = (SPFBL_FEEDBACK_HEADER, SPFBL_NATIVE_HEADER) if remove_native else (
        SPFBL_FEEDBACK_HEADER,)
    remove_current = False
    for line in header.splitlines(keepends=True):
        content = line.rstrip(b"\r\n")
        if content.startswith((b" ", b"\t")):
            if not remove_current:
                kept.append(line)
            continue
        name, field_separator, _value = content.partition(b":")
        remove_current = bool(field_separator and name.strip().lower() in removable)
        if not remove_current:
            kept.append(line)
    return b"".join(kept) + separator + bytes(message[body_offset:])


class FeedbackHeaderStripper(object):
    """Bounded streaming header filter used only on Postfix's delivery copy."""
    def __init__(self, max_header_bytes=MAX_MESSAGE_HEADER_BYTES):
        self.max_header_bytes = max_header_bytes
        self.pending = bytearray()
        self.finished = False

    def feed(self, chunk):
        if self.finished or not chunk:
            return chunk
        self.pending.extend(chunk)
        parts = _message_header_parts(self.pending, self.max_header_bytes)
        if parts is None and len(self.pending) <= self.max_header_bytes + 4:
            return b""
        if parts is None:
            output = bytes(self.pending)
        else:
            output = strip_spfbl_feedback_header(bytes(self.pending))
        self.pending.clear()
        self.finished = True
        return output

    def finish(self):
        if self.finished:
            return b""
        self.finished = True
        output = bytes(self.pending)
        self.pending.clear()
        return output


def _decode_exim_environment(name):
    """Decode one Exim-provided, base64-encoded metadata environment value."""
    value = os.environ.get(name)
    if value is None:
        return None
    try:
        return base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError, ValueError):
        return None


def _parse_exim_recipients(value):
    if not value:
        return []
    parsed = [address for _, address in getaddresses([value]) if address]
    if parsed:
        return parsed
    return [item.strip() for item in value.split(",") if item.strip()]


def exim_environment_metadata():
    """Read the Exim system-filter transport metadata without shell arguments."""
    return {
        "queue_id": _decode_exim_environment("HAD_SFOX_QUEUE_ID_B64"),
        "sender": _decode_exim_environment("HAD_SFOX_SENDER_B64"),
        "recipients": _parse_exim_recipients(
            _decode_exim_environment("HAD_SFOX_RECIPIENTS_B64") or ""
        ),
        "client_ip": _decode_exim_environment("HAD_SFOX_CLIENT_IP_B64"),
        "helo": _decode_exim_environment("HAD_SFOX_HELO_B64"),
        "received_port": _decode_exim_environment("HAD_SFOX_RECEIVED_PORT_B64"),
    }


def _read_bsmtp_command(stream):
    line = stream.readline(MAX_BSMTP_LINE_BYTES + 1)
    if not line or len(line) > MAX_BSMTP_LINE_BYTES or not line.endswith(b"\n"):
        raise ValueError("invalid BSMTP command line")
    try:
        return line.rstrip(b"\r\n").decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("invalid BSMTP command encoding")


class BSMTPMessageStream(object):
    """Expose the message body from Exim BSMTP as a de-stuffed byte stream."""

    def __init__(self, source):
        self.source = source
        self.pending = bytearray()
        self.finished = False

    def read(self, size=-1):
        if size is None or size < 0:
            chunks = []
            while True:
                chunk = self.read(CHUNK_SIZE)
                if not chunk:
                    return b"".join(chunks)
                chunks.append(chunk)
        if size == 0:
            return b""
        while len(self.pending) < size and not self.finished:
            line = self.source.readline(MAX_BSMTP_LINE_BYTES + 1)
            if not line:
                raise ValueError("BSMTP message is missing its terminator")
            if len(line) > MAX_BSMTP_LINE_BYTES or not line.endswith(b"\n"):
                raise ValueError("BSMTP message line exceeds the safety limit")
            if line.rstrip(b"\r\n") == b".":
                self.finished = True
                _drain(self.source)
                break
            if line.startswith(b".."):
                line = line[1:]
            self.pending.extend(line)
        if not self.pending:
            return b""
        result = bytes(self.pending[:size])
        del self.pending[:size]
        return result


def parse_exim_bsmtp(stream):
    """Extract the Exim pipe transport's envelope and return its RFC822 stream."""
    sender = None
    recipients = []
    while True:
        command = _read_bsmtp_command(stream)
        match = BSMTP_COMMAND_RE.match(command.encode("utf-8"))
        if match:
            try:
                address = match.group(2).decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError("invalid BSMTP address encoding")
            if match.group(1).upper() == b"MAIL FROM":
                if sender is not None:
                    raise ValueError("duplicate BSMTP sender")
                sender = address if address else "<>"
            else:
                recipients.append(address)
                if len(recipients) > 101:
                    recipients = recipients[:101]
            continue
        command_upper = command.upper()
        if command_upper.startswith("HELO ") or command_upper.startswith("EHLO "):
            continue
        if command_upper == "DATA":
            if sender is None or not recipients:
                raise ValueError("BSMTP envelope is incomplete")
            return BSMTPMessageStream(stream), sender, recipients
        raise ValueError("unexpected BSMTP envelope command")


def submit(stream, parsed, client_id, token, message_id, max_bytes, timeout,
           queue_id=None, sender=None, recipients=None, client_ip=None, helo=None,
           auth_user=None, received_port=None, bsmtp_envelope=False, bsmtp_recipient_count=None,
           exim_env_recipient_count=None):
    """Upload the input as HTTP chunked data without a persistent body copy."""
    if message_id and not MESSAGE_ID_RE.fullmatch(message_id):
        message_id = "-"
    connection = None
    sent = 0
    started = time.time()
    try:
        stream, client_ticket_status = capture_spfbl_ticket_status(stream)
        # DNS, connect, and TLS failures are part of fail-open MONITOR behavior.
        connection = _connect(parsed, timeout)
        path = parsed.path or "/"
        connection.putrequest("POST", path, skip_accept_encoding=True)
        connection.putheader("Content-Type", "message/rfc822")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.putheader("X-SFOX-Client", client_id)
        connection.putheader("X-SFOX-Client-Ticket-Status", client_ticket_status)
        if message_id:
            connection.putheader("X-SFOX-Message-ID", message_id)
        connection.putheader("X-SFOX-BSMTP-Envelope", "1" if bsmtp_envelope else "0")
        bsmtp_count = _bounded_recipient_count(bsmtp_recipient_count)
        exim_count = _bounded_recipient_count(exim_env_recipient_count)
        if bsmtp_count is not None:
            connection.putheader("X-SFOX-BSMTP-Recipient-Count", str(bsmtp_count))
        if exim_count is not None:
            connection.putheader("X-SFOX-Exim-Recipient-Count", str(exim_count))
        metadata = normalize_metadata(queue_id, sender, recipients, client_ip,
                                      helo, auth_user, received_port)
        for name, value in monitor_headers(metadata):
            connection.putheader(name, value)
        connection.putheader("Authorization", "Bearer " + token)
        connection.endheaders()

        while True:
            chunk = stream.read(CHUNK_SIZE)
            if not chunk:
                break
            sent += len(chunk)
            if sent > max_bytes:
                connection.close()
                connection = None
                _drain(stream)
                log_event("upload_skipped", client_id=client_id, message_id=message_id,
                          reason="message_too_large", bytes_seen=sent)
                return False
            connection.send(("%X\r\n" % len(chunk)).encode("ascii"))
            connection.send(chunk)
            connection.send(b"\r\n")
        if sent == 0:
            connection.close()
            log_event("upload_skipped", client_id=client_id, message_id=message_id,
                      reason="empty_message")
            return False
        connection.send(b"0\r\n\r\n")
        response = connection.getresponse()
        response.read(4096)
        elapsed_ms = int((time.time() - started) * 1000)
        if response.status == 202:
            log_event("upload_queued", client_id=client_id, message_id=message_id,
                      bytes=sent, latency_ms=elapsed_ms,
                      client_ticket_status=client_ticket_status,
                      smtp_recipient_count=len(metadata.get("rcpt", [])),
                      bsmtp_envelope=bool(bsmtp_envelope),
                      bsmtp_recipient_count=bsmtp_count,
                      exim_env_recipient_count=exim_count)
            return True
        log_event("upload_skipped", client_id=client_id, message_id=message_id,
                  reason="gateway_http_status", http_status=response.status,
                  bytes=sent, latency_ms=elapsed_ms)
        return False
    except Exception as exc:
        log_event("upload_skipped", client_id=client_id, message_id=message_id,
                  reason="transport_error", error=exc.__class__.__name__, bytes=sent,
                  latency_ms=int((time.time() - started) * 1000))
        return False
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass


def run(config_path, lock_path, stream=None, message_id=None, queue_id=None,
        sender=None, recipients=None, client_ip=None, helo=None, auth_user=None,
        received_port=None, bsmtp_envelope=False, bsmtp_recipient_count=None,
        exim_env_recipient_count=None):
    stream = stream or sys.stdin.buffer
    message_id = message_id or os.environ.get("MESSAGE_ID", "-")
    try:
        parsed, client_id, token, max_bytes, timeout = load_config(config_path)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        log_event("upload_skipped", reason="invalid_config", error=exc.__class__.__name__)
        _drain(stream)
        return 0

    try:
        lock = open(lock_path, "a+")
    except OSError as exc:
        log_event("upload_skipped", client_id=client_id, message_id=message_id,
                  reason="lock_unavailable", error=exc.__class__.__name__)
        _drain(stream)
        return 0

    try:
        try:
            import fcntl
        except ImportError:
            log_event("upload_skipped", client_id=client_id, message_id=message_id,
                      reason="local_lock_unavailable")
            _drain(stream)
            return 0
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except (IOError, OSError):
            log_event("upload_skipped", client_id=client_id, message_id=message_id,
                      reason="local_concurrency_limit")
            _drain(stream)
            return 0
        submit(stream, parsed, client_id, token, message_id, max_bytes, timeout,
               queue_id=queue_id, sender=sender, recipients=recipients,
               client_ip=client_ip, helo=helo, auth_user=auth_user,
               received_port=received_port,
               bsmtp_envelope=bsmtp_envelope,
               bsmtp_recipient_count=bsmtp_recipient_count,
               exim_env_recipient_count=exim_env_recipient_count)
        return 0
    finally:
        lock.close()


def main(argv=None):
    import argparse

    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config_path", nargs="?", default="/etc/had-content-scan/client.json")
    parser.add_argument("lock_path", nargs="?", default="/run/lock/had-content-scan.lock")
    parser.add_argument("--message-id", default=None)
    parser.add_argument("--queue-id", default=None)
    parser.add_argument("--sender", default=None)
    parser.add_argument("--recipient", action="append", default=[])
    parser.add_argument("--recipient-list", default="")
    parser.add_argument("--client-ip", default=None)
    parser.add_argument("--helo", default=None)
    parser.add_argument("--auth-user", default=None)
    parser.add_argument("--received-port", default=None)
    args = parser.parse_args(argv)
    input_stream = sys.stdin.buffer
    exim_metadata = exim_environment_metadata()
    bsmtp_sender = None
    bsmtp_recipients = []
    bsmtp_envelope = os.environ.get("HAD_SFOX_BSMTP") == "1"
    bsmtp_recipient_count = None
    if bsmtp_envelope:
        try:
            input_stream, bsmtp_sender, bsmtp_recipients = parse_exim_bsmtp(input_stream)
            bsmtp_recipient_count = len(bsmtp_recipients)
        except (OSError, ValueError) as exc:
            log_event("upload_skipped", reason="invalid_bsmtp_envelope",
                      error=exc.__class__.__name__)
            _drain(input_stream)
            return 0
    recipients = list(args.recipient)
    if args.recipient_list:
        recipients.extend(_parse_exim_recipients(args.recipient_list))
    elif not recipients:
        recipients = bsmtp_recipients or exim_metadata["recipients"]
    queue_id = args.queue_id or exim_metadata["queue_id"]
    sender = args.sender if args.sender is not None else (bsmtp_sender or exim_metadata["sender"])
    if sender is None:
        sender = os.environ.get("SENDER")
    message_id = args.message_id or queue_id or os.environ.get("MESSAGE_ID")
    return run(args.config_path, args.lock_path, stream=input_stream, message_id=message_id,
               queue_id=queue_id, sender=sender, recipients=recipients,
               client_ip=args.client_ip or exim_metadata["client_ip"],
               helo=args.helo or exim_metadata["helo"], auth_user=args.auth_user,
               received_port=args.received_port or exim_metadata["received_port"],
               bsmtp_envelope=bsmtp_envelope,
               bsmtp_recipient_count=bsmtp_recipient_count,
               exim_env_recipient_count=len(exim_metadata["recipients"]))


if __name__ == "__main__":
    raise SystemExit(main())
