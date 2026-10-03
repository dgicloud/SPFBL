#!/usr/bin/env python3
"""Isolated HAD envelope-query adapter; this first version is MONITOR-only."""

import asyncio
import argparse
import ipaddress
import json
import os
import re
import signal
import socket
import stat
import sys
import time
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Optional, Tuple


MAX_INPUT_BYTES = 4096
MAX_LOCAL_RECORD_BYTES = 24576
MAX_RESPONSE_BYTES = 2048
MAX_REQUEST_BYTES = 2048
MAX_HEADER_FIELD_BYTES = 2048
MAX_HEADER_TICKETS = 64
CONNECT_TIMEOUT_SECONDS = 0.5
TOTAL_TIMEOUT_SECONDS = 0.8
LOCAL_READ_TIMEOUT_SECONDS = 0.25
MAX_LOCAL_CLIENTS = 64
MAX_CONCURRENT_QUERIES = 16
LOCAL_FIELD_SEPARATOR = b"\x1f"
DECISIONS_WITH_OPTIONAL_TICKET = frozenset(
    {"PASS", "WHITE", "FLAG", "HOLD", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE", "LISTED", "BLOCKED"}
)
DECISIONS_WITHOUT_ARGUMENT = frozenset(
    {"GREYLIST", "SPAMTRAP", "NXDOMAIN", "INVALID", "LAN", "INEXISTENT", "NXSENDER", "BANNED"}
)
DECISIONS = DECISIONS_WITH_OPTIONAL_TICKET | DECISIONS_WITHOUT_ARGUMENT
DECISIONS_WITH_FEEDBACK_TICKET = frozenset(
    {"PASS", "WHITE", "FLAG", "HOLD", "FAIL", "SOFTFAIL", "NEUTRAL", "NONE"}
)
TICKET_TOKEN = re.compile(r"^[A-Za-z0-9_-]{1,512}$")
HEADER_MARKER = re.compile(
    r"(?:^| )(?:DKIM|From|Reply-To|ReplyTo|Message-ID|In-Reply-To|Queue-ID|Date|List-Unsubscribe|Subject):",
    re.IGNORECASE,
)
HEADER_STATUS = frozenset(
    {"CLEAR", "WHITE", "FLAG", "HOLD", "BLOCKED", "REJECT", "NOT FOUND", "INVALID COMMAND"}
)
SERVICE_ERRORS = frozenset(
    {"TIMEOUT", "OUT OF SERVICE", "TOO MANY CONNECTIONS", "HOST NOT FOUND", "SYSTEM SHUTDOWN"}
)


class InputError(ValueError):
    """Input cannot be represented safely in the upstream wire protocol."""


class Envelope:
    __slots__ = ("client_ip", "mail_from", "helo", "rcpt_to", "recipient_exists")

    def __init__(
        self,
        client_ip: str,
        mail_from: str,
        helo: str,
        rcpt_to: str,
        recipient_exists: Optional[bool] = None,
    ) -> None:
        self.client_ip = client_ip
        self.mail_from = mail_from
        self.helo = helo
        self.rcpt_to = rcpt_to
        self.recipient_exists = recipient_exists

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, Envelope) and (
            self.client_ip,
            self.mail_from,
            self.helo,
            self.rcpt_to,
            self.recipient_exists,
        ) == (
            other.client_ip,
            other.mail_from,
            other.helo,
            other.rcpt_to,
            other.recipient_exists,
        )

    @classmethod
    def from_json(cls, value: Any) -> "Envelope":
        if not isinstance(value, dict):
            raise InputError("input_must_be_object")

        client_ip = _string_field(value, "client_ip", maximum=45)
        try:
            normalized_ip = str(ipaddress.ip_address(client_ip))
        except ValueError as exc:
            raise InputError("invalid_client_ip") from exc

        mail_from = _string_field(
            value,
            "mail_from",
            maximum=320,
            allow_empty=True,
            allow_single_quote=True,
        )
        helo = _string_field(value, "helo", maximum=255)
        rcpt_to = _string_field(
            value,
            "rcpt_to",
            maximum=320,
            allow_single_quote=True,
        )
        if any(character.isspace() for character in helo):
            raise InputError("invalid_helo")
        if any(character.isspace() for character in rcpt_to):
            raise InputError("invalid_rcpt_to")
        if any(character == "'" and next_character.isspace() for character, next_character in zip(mail_from, mail_from[1:])):
            # SPF.java stops reassembling sender tokens on an apostrophe before whitespace.
            raise InputError("unrepresentable_mail_from")

        recipient_exists = value.get("recipient_exists")
        if recipient_exists is not None and not isinstance(recipient_exists, bool):
            raise InputError("invalid_recipient_exists")

        return cls(normalized_ip, mail_from, helo, rcpt_to, recipient_exists)


class HeaderMessage:
    __slots__ = (
        "tickets", "dkim", "from_header", "reply_to", "message_id", "in_reply_to",
        "queue_id", "date", "list_unsubscribe", "subject",
    )

    def __init__(self, tickets, dkim, from_header, reply_to, message_id, in_reply_to,
                 queue_id, date, list_unsubscribe, subject):
        self.tickets = tickets
        self.dkim = dkim
        self.from_header = from_header
        self.reply_to = reply_to
        self.message_id = message_id
        self.in_reply_to = in_reply_to
        self.queue_id = queue_id
        self.date = date
        self.list_unsubscribe = list_unsubscribe
        self.subject = subject

    @classmethod
    def from_values(cls, tickets, dkim, from_header, reply_to, message_id, in_reply_to,
                    queue_id, date, list_unsubscribe, subject):
        if not isinstance(tickets, str) or len(tickets) > MAX_HEADER_FIELD_BYTES:
            raise InputError("invalid_header_ticket_set")
        ticket_values = []
        if tickets:
            for ticket in tickets.split(";"):
                if not TICKET_TOKEN.fullmatch(ticket):
                    raise InputError("invalid_header_ticket")
                if ticket not in ticket_values:
                    ticket_values.append(ticket)
                if len(ticket_values) > MAX_HEADER_TICKETS:
                    raise InputError("too_many_header_tickets")

        values = []
        for name, value in (
            ("dkim", dkim), ("from", from_header), ("reply_to", reply_to),
            ("message_id", message_id), ("in_reply_to", in_reply_to),
            ("queue_id", queue_id), ("date", date),
            ("list_unsubscribe", list_unsubscribe), ("subject", subject),
        ):
            values.append(_header_value(name, value))
        if not any(values[index] for index in (1, 2, 3, 6, 7, 8)):
            raise InputError("header_metadata_missing")
        return cls(tuple(ticket_values), *values)


class HeaderResult:
    __slots__ = ("status", "latency_ms", "ticket_count")

    def __init__(self, status, latency_ms=0, ticket_count=0):
        self.status = status
        self.latency_ms = latency_ms
        self.ticket_count = ticket_count


def _header_value(name, value):
    if not isinstance(value, str):
        raise InputError("invalid_header_" + name)
    if len(value.encode("utf-8")) > MAX_HEADER_FIELD_BYTES:
        raise InputError("oversized_header_" + name)
    if any(ord(character) < 32 and character not in "\t\r\n" for character in value):
        raise InputError("unsafe_header_" + name)
    normalized = re.sub(r"[\t\r\n ]+", " ", value).strip()
    if HEADER_MARKER.search(normalized):
        raise InputError("ambiguous_header_" + name)
    return normalized


class TransportConfig:
    __slots__ = ("server_ip", "server_socket", "port", "connect_timeout", "total_timeout")

    def __init__(
        self,
        server_ip: Optional[str] = None,
        port: int = 9877,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        total_timeout: float = TOTAL_TIMEOUT_SECONDS,
        server_socket: Optional[str] = None,
    ) -> None:
        if server_ip is None and server_socket is None:
            server_ip = "127.0.0.1"
        if server_ip is not None and server_socket is not None:
            raise ValueError("choose_one_upstream_transport")
        if server_socket is not None:
            if not os.path.isabs(server_socket) or len(os.fsencode(server_socket)) > 103:
                raise ValueError("invalid_server_socket_path")
            if not hasattr(socket, "AF_UNIX"):
                raise ValueError("unix_sockets_unavailable")
            self.server_ip = None
            self.server_socket = server_socket
        else:
            try:
                ipaddress.ip_address(server_ip)
            except (TypeError, ValueError) as exc:
                raise ValueError("server_must_be_ip_literal") from exc
            self.server_ip = server_ip
            self.server_socket = None
        self.port = port
        self.connect_timeout = connect_timeout
        self.total_timeout = total_timeout
        self.__post_init__()

    def __post_init__(self) -> None:
        if not 1 <= self.port <= 65535:
            raise ValueError("invalid_server_port")
        if not 0 < self.connect_timeout <= CONNECT_TIMEOUT_SECONDS:
            raise ValueError("connect_timeout_must_be_at_most_500ms")
        if not 0 < self.total_timeout <= TOTAL_TIMEOUT_SECONDS:
            raise ValueError("total_timeout_must_be_at_most_1s")


class QueryResult:
    __slots__ = ("mode", "action", "status", "decision", "ticket_present", "latency_ms", "ticket")

    def __init__(
        self,
        mode: str,
        action: str,
        status: str,
        decision: Optional[str],
        ticket_present: bool,
        latency_ms: int,
        ticket: Optional[str] = None,
    ) -> None:
        self.mode = mode
        self.action = action
        self.status = status
        self.decision = decision
        self.ticket_present = ticket_present
        self.latency_ms = latency_ms
        # Kept only for the local Exim handoff. Never expose it in JSON/events.
        self.ticket = ticket

    def as_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode,
            "action": self.action,
            "status": self.status,
            "decision": self.decision,
            "ticket_present": self.ticket_present,
            "latency_ms": self.latency_ms,
        }


def _string_field(
    value: Dict[str, Any],
    name: str,
    *,
    maximum: int,
    allow_empty: bool = False,
    allow_single_quote: bool = False,
) -> str:
    field = value.get(name)
    if not isinstance(field, str):
        raise InputError(f"invalid_{name}")
    if not field and not allow_empty:
        raise InputError(f"empty_{name}")
    if len(field) > maximum:
        raise InputError(f"oversized_{name}")
    if ("'" in field and not allow_single_quote) or any(
        ord(character) < 32 or ord(character) == 127 for character in field
    ):
        raise InputError(f"unsafe_{name}")
    return field


def parse_local_record(raw: bytes) -> Envelope:
    """Decode Exim's fixed five-field UDS record, separated by ASCII US."""
    if not raw or len(raw) > MAX_INPUT_BYTES:
        raise InputError("invalid_local_record_size")
    fields = raw.split(LOCAL_FIELD_SEPARATOR)
    if len(fields) != 5:
        raise InputError("invalid_local_record_shape")
    try:
        client_ip, mail_from, helo, rcpt_to, exists = (
            field.decode("utf-8") for field in fields
        )
    except UnicodeDecodeError as exc:
        raise InputError("invalid_local_record_encoding") from exc

    exists_value = exists.lower()
    if exists_value in {"", "null"}:
        recipient_exists = None
    elif exists_value == "true":
        recipient_exists = True
    elif exists_value == "false":
        recipient_exists = False
    else:
        raise InputError("invalid_recipient_exists")
    return Envelope.from_json(
        {
            "client_ip": client_ip,
            "mail_from": mail_from,
            "helo": helo,
            "rcpt_to": rcpt_to,
            "recipient_exists": recipient_exists,
        }
    )


def parse_local_header_record(raw: bytes) -> HeaderMessage:
    """Decode Exim's DATA metadata request without retaining message headers."""
    if not raw or len(raw) > MAX_LOCAL_RECORD_BYTES:
        raise InputError("invalid_local_record_size")
    fields = raw.split(LOCAL_FIELD_SEPARATOR)
    if len(fields) != 11:
        raise InputError("invalid_header_record_shape")
    try:
        values = [field.decode("utf-8") for field in fields]
    except UnicodeDecodeError as exc:
        raise InputError("invalid_local_record_encoding") from exc
    if values[0] != "HEADER":
        raise InputError("invalid_header_record_type")
    return HeaderMessage.from_values(*values[1:])


def serialize_header(message: HeaderMessage) -> bytes:
    """Serialize the upstream HEADER command using its original text protocol."""
    if not message.tickets:
        raise InputError("header_without_ticket")
    fields = ["HEADER " + ";".join(message.tickets)]
    for label, value in (
        ("DKIM", message.dkim),
        ("From", message.from_header),
        ("Reply-To", message.reply_to),
        ("Message-ID", message.message_id),
        ("In-Reply-To", message.in_reply_to),
        ("Queue-ID", message.queue_id),
        ("Date", message.date),
        ("List-Unsubscribe", message.list_unsubscribe),
        ("Subject", message.subject),
    ):
        if value:
            fields.append(label + ":" + value)
    request = (" ".join(fields) + "\n").encode("utf-8")
    if len(request) > MAX_REQUEST_BYTES:
        raise InputError("oversized_header_request")
    return request


def parse_header_response(raw: bytes) -> str:
    if not raw or len(raw) > MAX_RESPONSE_BYTES or b"\x00" in raw:
        raise InputError("invalid_header_response")
    line = raw.decode("iso-8859-1").strip()
    if not line or "\n" in line or "\r" in line:
        raise InputError("invalid_header_response")
    if line.startswith("ERROR:") or line in SERVICE_ERRORS:
        raise LookupError("upstream_error")
    parts = line.upper().split()
    if parts[0] == "NOT" and parts[1:] == ["FOUND"]:
        return "NOT_FOUND"
    if parts[0] == "INVALID" and parts[1:] == ["COMMAND"]:
        return "INVALID_COMMAND"
    status = parts[0]
    if status not in HEADER_STATUS:
        raise LookupError("unknown_header_status")
    if status != "BLOCKED" and len(parts) != 1:
        raise LookupError("invalid_header_status_shape")
    return status


def format_local_header_result(result: HeaderResult) -> bytes:
    return "CONTINUE|header|{}|{}".format(result.status, result.latency_ms).encode("ascii")


def format_local_result(result: QueryResult) -> bytes:
    """Return a bounded response; the final field is secret message state."""
    decision = result.decision or "-"
    ticket = result.ticket or "-"
    return (
        f"CONTINUE|{result.status}|{decision}|{result.latency_ms}|{ticket}".encode("ascii")
    )


async def _read_local_record(reader: asyncio.StreamReader) -> bytes:
    data = bytearray()
    while len(data) <= MAX_LOCAL_RECORD_BYTES:
        chunk = await reader.read(min(1024, MAX_LOCAL_RECORD_BYTES + 1 - len(data)))
        if not chunk:
            return bytes(data)
        data.extend(chunk)
    return bytes(data)


async def serve_local_socket(path: str, config: TransportConfig) -> None:
    """Serve MONITOR requests to Exim over a permission-restricted Unix socket."""
    socket_path = Path(path)
    if socket_path.exists() or socket_path.is_symlink():
        raise FileExistsError("socket_path_already_exists")

    semaphore = asyncio.Semaphore(MAX_CONCURRENT_QUERIES)
    active_clients = 0

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal active_clients
        active_clients += 1
        started = time.monotonic()
        try:
            if active_clients > MAX_LOCAL_CLIENTS:
                result = _result("adapter_busy", None, False, started)
                writer.write(format_local_result(result))
                await writer.drain()
                _emit_event(result)
            else:
                try:
                    raw = await asyncio.wait_for(
                        _read_local_record(reader), timeout=LOCAL_READ_TIMEOUT_SECONDS
                    )
                except asyncio.TimeoutError:
                    result = _result("local_socket_timeout", None, False, started)
                    writer.write(format_local_result(result))
                    await writer.drain()
                    _emit_event(result)
                else:
                    if raw.startswith(b"HEADER" + LOCAL_FIELD_SEPARATOR):
                        try:
                            message = parse_local_header_record(raw)
                        except InputError as exc:
                            header_result = HeaderResult(str(exc), _elapsed_ms(started))
                        else:
                            if not message.tickets:
                                header_result = HeaderResult("no_ticket", _elapsed_ms(started))
                            else:
                                try:
                                    await asyncio.wait_for(semaphore.acquire(), timeout=0.05)
                                except asyncio.TimeoutError:
                                    header_result = HeaderResult("adapter_busy", _elapsed_ms(started))
                                else:
                                    try:
                                        loop = asyncio.get_event_loop()
                                        header_result = await loop.run_in_executor(
                                            None, submit_header, message, config
                                        )
                                    finally:
                                        semaphore.release()
                        writer.write(format_local_header_result(header_result))
                        await writer.drain()
                        _emit_header_event(header_result)
                    else:
                        try:
                            envelope = parse_local_record(raw)
                        except InputError as exc:
                            result = _result(str(exc), None, False, started)
                        else:
                            try:
                                await asyncio.wait_for(semaphore.acquire(), timeout=0.05)
                            except asyncio.TimeoutError:
                                result = _result("adapter_busy", None, False, started)
                            else:
                                try:
                                    loop = asyncio.get_event_loop()
                                    result = await loop.run_in_executor(None, query, envelope, config)
                                finally:
                                    semaphore.release()
                        writer.write(format_local_result(result))
                        await writer.drain()
                        _emit_event(result)
        except OSError:
            # The Exim process may already have reached its readsocket deadline.
            pass
        finally:
            active_clients -= 1
            writer.close()
            wait_closed = getattr(writer, "wait_closed", None)
            if wait_closed is not None:
                try:
                    await wait_closed()
                except OSError:
                    pass

    server = await asyncio.start_unix_server(handle, path=path, backlog=MAX_LOCAL_CLIENTS)
    os.chmod(path, 0o660)
    socket_info = os.stat(path, follow_symlinks=False)
    socket_identity = (socket_info.st_dev, socket_info.st_ino)
    stopped = asyncio.Event()
    loop = asyncio.get_event_loop()
    installed_signals: List[int] = []
    for signum in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(signum, stopped.set)
            installed_signals.append(signum)
        except (NotImplementedError, RuntimeError):
            pass

    try:
        await stopped.wait()
    finally:
        server.close()
        server_wait_closed = getattr(server, "wait_closed", None)
        if server_wait_closed is not None:
            await server_wait_closed()
        for signum in installed_signals:
            loop.remove_signal_handler(signum)
        current = None
        try:
            current = os.stat(path, follow_symlinks=False)
        except FileNotFoundError:
            pass
        if current is not None and stat.S_ISSOCK(current.st_mode):
            if (current.st_dev, current.st_ino) == socket_identity:
                socket_path.unlink()


def _emit_event(result: QueryResult) -> None:
    event = {
        "event": "had_antispam_query",
        "mode": result.mode,
        "action": result.action,
        "status": result.status,
        "decision": result.decision,
        "ticket_present": result.ticket_present,
        "latency_ms": result.latency_ms,
    }
    print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)


def _emit_header_event(result: HeaderResult) -> None:
    event = {
        "event": "had_antispam_header",
        "mode": "MONITOR",
        "action": "continue",
        "status": result.status,
        "ticket_count": result.ticket_count,
        "latency_ms": result.latency_ms,
    }
    print(json.dumps(event, separators=(",", ":")), file=sys.stderr, flush=True)


def serialize_query(envelope: Envelope) -> bytes:
    fields = (envelope.client_ip, envelope.mail_from, envelope.helo, envelope.rcpt_to)
    exists = "" if envelope.recipient_exists is None else f" {str(envelope.recipient_exists).lower()}"
    request = "SPF " + " ".join(f"'{field}'" for field in fields) + exists + "\n"
    encoded = request.encode("utf-8")
    if len(encoded) > MAX_REQUEST_BYTES:
        raise InputError("oversized_request")
    return encoded


def parse_response(raw: bytes) -> Tuple[str, bool, Optional[str]]:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise InputError("invalid_response_size")
    if b"\x00" in raw:
        raise InputError("invalid_response_bytes")
    line = raw.decode("iso-8859-1").strip()
    if not line or "\n" in line or "\r" in line:
        raise InputError("invalid_response_line")

    if line.startswith("ERROR:"):
        raise LookupError("server_error")
    if line in SERVICE_ERRORS or line.startswith("TOTP "):
        raise LookupError("service_status")

    parts = line.split()
    qualifier = parts[0].upper()
    if qualifier not in DECISIONS:
        raise LookupError("unknown_status")
    if qualifier in DECISIONS_WITHOUT_ARGUMENT and len(parts) != 1:
        raise LookupError("invalid_decision_shape")
    if qualifier in DECISIONS_WITH_OPTIONAL_TICKET and len(parts) > 2:
        raise LookupError("invalid_decision_shape")
    if qualifier == "INVALID" and len(parts) > 1:
        # Upstream also uses INVALID <detail> for a request/protocol error.
        raise LookupError("invalid_decision_shape")
    ticket_present = len(parts) == 2
    ticket = None
    if ticket_present and qualifier in DECISIONS_WITH_FEEDBACK_TICKET:
        candidate = parts[1]
        if candidate.startswith("http://") or candidate.startswith("https://"):
            candidate = candidate.rsplit("/", 1)[-1]
        if TICKET_TOKEN.fullmatch(candidate):
            ticket = candidate
    return qualifier, ticket_present, ticket


def _result(
    status: str,
    decision: Optional[str],
    ticket_present: bool,
    started: float,
    ticket: Optional[str] = None,
) -> QueryResult:
    elapsed = max(0.0, time.monotonic() - started)
    return QueryResult(
        mode="MONITOR",
        action="continue",
        status=status,
        decision=decision,
        ticket_present=ticket_present,
        latency_ms=round(elapsed * 1000),
        ticket=ticket,
    )


def _elapsed_ms(started: float) -> int:
    return round(max(0.0, time.monotonic() - started) * 1000)


def query(envelope: Envelope, config: TransportConfig) -> QueryResult:
    """Query the SPFBL core and always return a MONITOR/continue action."""
    started = time.monotonic()
    try:
        request = serialize_query(envelope)
    except InputError as exc:
        return _result(str(exc), None, False, started)

    deadline = started + config.total_timeout
    try:
        # TCP destinations are numeric IPs; a local Unix socket is also supported.
        if config.server_socket is not None:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(
                min(config.connect_timeout, max(0.001, deadline - time.monotonic()))
            )
            connection.connect(config.server_socket)
        else:
            connection = socket.create_connection(
                (config.server_ip, config.port),
                timeout=min(config.connect_timeout, max(0.001, deadline - time.monotonic())),
            )
        with connection:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return _result("total_timeout", None, False, started)
            connection.settimeout(remaining)
            connection.sendall(request)

            response = bytearray()
            while len(response) <= MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return _result("total_timeout", None, False, started)
                connection.settimeout(remaining)
                chunk = connection.recv(min(512, MAX_RESPONSE_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break

        raw_response = bytes(response)
        line, separator, trailing = raw_response.partition(b"\n")
        if separator and trailing.strip(b" \t\r"):
            return _result("invalid_response_line", None, False, started)
        decision, ticket_present, ticket = parse_response(line.rstrip(b"\r"))
        return _result("decision", decision, ticket_present, started, ticket)
    except socket.timeout:
        return _result("total_timeout", None, False, started)
    except OSError:
        return _result("connect_or_io_error", None, False, started)
    except InputError as exc:
        return _result(str(exc), None, False, started)
    except LookupError as exc:
        return _result(str(exc), None, False, started)


def submit_header(message: HeaderMessage, config: TransportConfig) -> HeaderResult:
    """Send the upstream HEADER metadata command; Exim policy remains MONITOR."""
    started = time.monotonic()
    ticket_count = len(message.tickets)
    if not ticket_count:
        return HeaderResult("no_ticket", _elapsed_ms(started), 0)
    try:
        request = serialize_header(message)
    except InputError as exc:
        return HeaderResult(str(exc), _elapsed_ms(started), ticket_count)

    deadline = started + config.total_timeout
    try:
        timeout = min(config.connect_timeout, max(0.001, deadline - time.monotonic()))
        if config.server_socket is not None:
            connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            connection.settimeout(timeout)
            connection.connect(config.server_socket)
        else:
            connection = socket.create_connection((config.server_ip, config.port), timeout=timeout)
        with connection:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return HeaderResult("total_timeout", _elapsed_ms(started), ticket_count)
            connection.settimeout(remaining)
            connection.sendall(request)
            response = bytearray()
            while len(response) <= MAX_RESPONSE_BYTES:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return HeaderResult("total_timeout", _elapsed_ms(started), ticket_count)
                connection.settimeout(remaining)
                chunk = connection.recv(min(512, MAX_RESPONSE_BYTES + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break

        raw_response = bytes(response)
        line, separator, trailing = raw_response.partition(b"\n")
        if separator and trailing.strip(b" \t\r"):
            return HeaderResult("invalid_header_response", _elapsed_ms(started), ticket_count)
        status = parse_header_response(line.rstrip(b"\r"))
        return HeaderResult(status, _elapsed_ms(started), ticket_count)
    except socket.timeout:
        return HeaderResult("total_timeout", _elapsed_ms(started), ticket_count)
    except OSError:
        return HeaderResult("connect_or_io_error", _elapsed_ms(started), ticket_count)
    except InputError as exc:
        return HeaderResult(str(exc), _elapsed_ms(started), ticket_count)
    except LookupError as exc:
        return HeaderResult(str(exc), _elapsed_ms(started), ticket_count)


def _read_envelope(stream: BinaryIO) -> Envelope:
    raw = stream.readline(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise InputError("input_too_large")
    if not raw.strip():
        raise InputError("empty_input")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError("invalid_json") from exc
    return Envelope.from_json(value)


def _emit_result(result: QueryResult) -> None:
    # Do not include envelope data, ticket values, or raw server responses.
    print(json.dumps(result.as_dict(), separators=(",", ":")))
    event = {
        "event": "had_antispam_query",
        "mode": result.mode,
        "action": result.action,
        "status": result.status,
        "decision": result.decision,
        "ticket_present": result.ticket_present,
        "latency_ms": result.latency_ms,
    }
    print(json.dumps(event, separators=(",", ":")), file=sys.stderr)


class _FailOpenArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise InputError("invalid_cli_arguments")


def main(argv: Optional[List[str]] = None) -> int:
    started = time.monotonic()
    try:
        parser = _FailOpenArgumentParser(description=__doc__)
        parser.add_argument(
            "--server",
            default=os.environ.get("HAD_SPFBL_HOST"),
            help="numeric IPv4/IPv6 address for the SPFBL core (DNS is intentionally not used)",
        )
        parser.add_argument("--port", type=int, default=os.environ.get("HAD_SPFBL_PORT", "9877"))
        parser.add_argument(
            "--server-socket",
            default=os.environ.get("HAD_SPFBL_SOCKET"),
            help="local Unix socket used as the SPFBL query endpoint",
        )
        parser.add_argument(
            "--listen-socket",
            help="serve local Exim requests from this Unix domain socket instead of reading JSON",
        )
        args = parser.parse_args(argv)
        config = TransportConfig(
            server_ip=args.server,
            port=args.port,
            server_socket=args.server_socket,
        )
        if args.listen_socket:
            coroutine = serve_local_socket(args.listen_socket, config)
            if hasattr(asyncio, "run"):
                asyncio.run(coroutine)
            else:
                loop = asyncio.new_event_loop()
                try:
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(coroutine)
                finally:
                    asyncio.set_event_loop(None)
                    loop.close()
            return 0
        envelope = _read_envelope(sys.stdin.buffer)
        result = query(envelope, config)
    except (InputError, ValueError) as exc:
        result = _result(str(exc), None, False, started)
    _emit_result(result)
    # The caller can continue the existing Exim ACL in every MONITOR outcome.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
