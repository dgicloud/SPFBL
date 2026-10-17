#!/usr/bin/env python3
"""Bounded, RAM-only HTTP ingress and asynchronous native SPFBL Bayes gateway."""

from __future__ import print_function

import http.client
import ipaddress
import json
import os
import queue
import re
import socket
import sys
import threading
import time
from time import monotonic
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

import scan_client
import spfbl_bayes
import spfbl_feedback

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
TICKET_STATUS_VALUES = scan_client.TICKET_STATUS_VALUES
DEFAULT_MTA_ALLOWLIST = "/etc/had-antispam/allowed-cpanels.txt"


def emit_log(event, **fields):
    record = {"event": event}
    record.update(fields)
    sys.stdout.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def parse_client_config(path):
    with open(path, "r") as stream:
        config = json.load(stream)
    clients = config.get("clients")
    if not isinstance(clients, dict):
        raise ValueError("client config must contain a clients object")
    return clients


def _allowlist_profile(source_ip, allowlist_path):
    """Return a conservative profile for a source admitted by SPFBL itself."""
    try:
        address = ipaddress.ip_address(source_ip)
        networks = set()
        with open(allowlist_path, "r") as stream:
            for raw in stream:
                value = raw.split("#", 1)[0].strip()
                if not value:
                    continue
                network = ipaddress.ip_network(value, strict=False)
                if network.prefixlen != 0:
                    networks.add(network)
    except (OSError, ValueError, TypeError):
        return None
    if not any(address in network for network in networks):
        return None
    return "allowlist-" + str(address).replace(".", "-").replace(":", "-"), {
        "allowed_cidrs": [],
        "enabled": True,
        # Native SPFBL Bayes is the default engine; the core still enforces
        # its own per-client BAYES CLIENT authorization.
        "native_bayes_enabled": True,
        # Sending a SPAM ticket to SPFBL stays opt-in per explicit profile.
        "spfbl_feedback_enabled": False,
    }


def resolve_client(clients, source_ip, allowlist_path=DEFAULT_MTA_ALLOWLIST):
    """Resolve one enabled internal profile from an explicitly allowed source IP."""
    try:
        address = ipaddress.ip_address(source_ip)
    except (ValueError, TypeError):
        return None

    matches = []
    for client_id, client in clients.items():
        if not CLIENT_ID_RE.fullmatch(client_id or "") or not isinstance(client, dict):
            continue
        if client.get("enabled", True) is not True:
            continue
        cidr_values = client.get("allowed_cidrs", [])
        if not isinstance(cidr_values, list):
            continue
        try:
            networks = [ipaddress.ip_network(item, strict=False) for item in cidr_values]
        except (ValueError, TypeError):
            continue
        if any(address in network for network in networks):
            matches.append((client_id, client))

    # Overlapping explicit profiles are ambiguous and fail closed.
    if len(matches) > 1:
        return None
    if not matches:
        return _allowlist_profile(source_ip, allowlist_path)
    client_id, client = matches[0]
    try:
        networks = [ipaddress.ip_network(item, strict=False)
                    for item in client.get("allowed_cidrs", [])]
    except (ValueError, TypeError):
        return None
    if any(address in network for network in networks):
        return client_id, client
    return None


def read_chunked(stream, max_bytes):
    body = bytearray()
    chunk_count = 0
    while True:
        line = stream.readline(128)
        if not line.endswith(b"\r\n"):
            raise ValueError("invalid chunk framing")
        size_text = line[:-2].split(b";", 1)[0]
        if not size_text or not re.match(br"^[0-9A-Fa-f]+$", size_text):
            raise ValueError("invalid chunk size")
        size = int(size_text, 16)
        if size == 0:
            trailer_bytes = 0
            while True:
                trailer = stream.readline(8193)
                if not trailer:
                    raise ValueError("incomplete chunk terminator")
                trailer_bytes += len(trailer)
                if trailer_bytes > 8192:
                    raise ValueError("trailers exceed limit")
                if trailer in (b"\r\n", b"\n"):
                    return body
        if size > max_bytes - len(body):
            raise OverflowError("message exceeds configured limit")
        chunk_count += 1
        if chunk_count > 65536:
            raise ValueError("too many chunks")
        chunk = stream.read(size)
        if len(chunk) != size or stream.read(2) != b"\r\n":
            raise ValueError("truncated chunk")
        body.extend(chunk)


def read_content_length(stream, length, max_bytes):
    if length <= 0 or length > max_bytes:
        raise OverflowError("invalid or oversized content length")
    body = bytearray()
    remaining = length
    while remaining:
        chunk = stream.read(min(64 * 1024, remaining))
        if not chunk:
            raise ValueError("truncated request body")
        body.extend(chunk)
        remaining -= len(chunk)
    return body


def metadata_fields_present(metadata):
    """Return only fixed field names; never expose SMTP metadata values in logs."""
    metadata = metadata or {}
    fields = []
    if metadata.get("queue_id"):
        fields.append("queue_id")
    if metadata.get("from") not in (None, "", "<>"):
        fields.append("sender")
    if metadata.get("rcpt"):
        fields.append("recipient")
    if metadata.get("ip"):
        fields.append("client_ip")
    if metadata.get("helo"):
        fields.append("helo")
    if metadata.get("received_port"):
        fields.append("received_port")
    return fields


def bounded_diagnostic_count(headers, name):
    """Read a client-supplied count without accepting unbounded log values."""
    value = headers.get(name, "")
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,3}", value):
        return None
    count = int(value)
    return count if count <= 101 else None


class ScanHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HAD-Content-Scan"
    sys_version = ""

    def log_message(self, fmt, *args):
        # BaseHTTPRequestHandler logs request paths and client-supplied strings.
        # All gateway events are emitted explicitly with a safe field allowlist.
        return

    def _reply(self, status, payload):
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (OSError, socket.error):
            pass
        self.close_connection = True

    def do_GET(self):
        if self.path == "/healthz":
            self._reply(200, {"ok": True})
        else:
            self._reply(404, {"error": "not_found"})

    def do_POST(self):
        if self.path != "/v1/scan":
            self._reply(404, {"error": "not_found"})
            return
        if self.client_address[0] not in ("127.0.0.1", "::1"):
            self._reply(403, {"error": "proxy_only"})
            return

        try:
            source_ip = str(ipaddress.ip_address(self.headers.get("X-Real-IP", "")))
            clients = parse_client_config(self.server.clients_path)
        except (OSError, ValueError, TypeError):
            self._reply(503, {"error": "gateway_configuration"})
            return
        client_match = resolve_client(clients, source_ip, self.server.allowlist_path)
        if client_match is None:
            emit_log("request_denied", reason="source_not_allowed", source_ip=source_ip)
            self._reply(403, {"error": "forbidden"})
            return
        client_id, registered_client = client_match

        transfer_encoding = self.headers.get("Transfer-Encoding", "").lower().strip()
        content_length_values = self.headers.get_all("Content-Length", []) or []
        if transfer_encoding and content_length_values:
            self._reply(400, {"error": "ambiguous_body_framing"})
            return
        if transfer_encoding not in ("", "chunked"):
            self._reply(400, {"error": "unsupported_transfer_encoding"})
            return
        if not transfer_encoding and len(content_length_values) != 1:
            self._reply(411, {"error": "length_required"})
            return
        content_length = None
        if not transfer_encoding:
            try:
                content_length = int(content_length_values[0])
            except (TypeError, ValueError):
                self._reply(400, {"error": "invalid_content_length"})
                return
            if content_length <= 0 or content_length > self.server.max_message_bytes:
                self._reply(413, {"error": "message_too_large"})
                return

        if not self.server.pending_slots.acquire(False):
            emit_log("request_dropped", reason="capacity", client_id=client_id)
            self._reply(503, {"error": "busy"})
            return
        if not self.server.upload_slots.acquire(False):
            self.server.pending_slots.release()
            emit_log("request_dropped", reason="upload_limit", client_id=client_id)
            self._reply(503, {"error": "busy"})
            return

        message_id = self.headers.get("X-SFOX-Message-ID", "-")
        if not MESSAGE_ID_RE.fullmatch(message_id):
            message_id = "-"
        client_ticket_status = self.headers.get("X-SFOX-Client-Ticket-Status")
        if client_ticket_status not in TICKET_STATUS_VALUES:
            client_ticket_status = ("unavailable" if client_ticket_status is None
                                    else "invalid")
        metadata = scan_client.normalize_metadata(
            queue_id=self.headers.get("X-SFOX-SMTP-Queue-ID"),
            sender=self.headers.get("X-SFOX-SMTP-From"),
            recipients=self.headers.get_all("X-SFOX-SMTP-Rcpt", []) or [],
            client_ip=self.headers.get("X-SFOX-SMTP-IP"),
            helo=self.headers.get("X-SFOX-SMTP-HELO"),
            auth_user=self.headers.get("X-SFOX-SMTP-User"),
            received_port=self.headers.get("X-SFOX-SMTP-Received-Port"),
        )
        bsmtp_envelope_header = self.headers.get("X-SFOX-BSMTP-Envelope")
        metadata["diagnostic_bsmtp_envelope"] = (
            bsmtp_envelope_header == "1" if bsmtp_envelope_header in ("0", "1") else None
        )
        scan_client.require_received_port_for_bsmtp(
            metadata, metadata["diagnostic_bsmtp_envelope"] is True)
        metadata["diagnostic_bsmtp_recipient_count"] = bounded_diagnostic_count(
            self.headers, "X-SFOX-BSMTP-Recipient-Count")
        metadata["diagnostic_exim_env_recipient_count"] = bounded_diagnostic_count(
            self.headers, "X-SFOX-Exim-Recipient-Count")
        # Exim's after-queue BSMTP envelope is authoritative for feedback
        # cardinality. Its RCPT syntax may not pass the optional address
        # validator, so never infer a multi/single-recipient verdict from the
        # (possibly empty) normalized address list when BSMTP is present.
        if metadata["diagnostic_bsmtp_envelope"] is True:
            metadata["spfbl_recipient_count"] = metadata[
                "diagnostic_bsmtp_recipient_count"]
        else:
            metadata["spfbl_recipient_count"] = len(metadata.get("rcpt", []))
        metadata["native_bayes_enabled"] = bool(
            isinstance(registered_client, dict)
            and registered_client.get("native_bayes_enabled") is True
        )
        metadata["spfbl_feedback_enabled"] = bool(
            isinstance(registered_client, dict)
            and registered_client.get("spfbl_feedback_enabled") is True
        )
        max_bytes = self.server.max_message_bytes
        started = monotonic()
        try:
            if transfer_encoding == "chunked":
                body = read_chunked(self.rfile, max_bytes)
            else:
                body = read_content_length(self.rfile, content_length, max_bytes)
            if not body:
                raise ValueError("empty message")
            ticket_record, ticket_status = scan_client.extract_spfbl_feedback_ticket(body)
            metadata["spfbl_ticket"] = ticket_record
            metadata["spfbl_ticket_status"] = ticket_status
            metadata["client_ticket_status"] = client_ticket_status
            metadata["ticket_status_match"] = (
                client_ticket_status == ticket_status
                if client_ticket_status in TICKET_STATUS_VALUES else None
            )
            queued_at = monotonic()
            self.server.work_queue.put_nowait((source_ip, client_id, message_id, body, len(body),
                                               queued_at, metadata))
            self.server.upload_slots.release()
            emit_log("message_queued", client_id=client_id, message_id=message_id,
                     bytes=len(body), queue_depth=self.server.work_queue.qsize(),
                     intake_ms=max(0, int((queued_at - started) * 1000)), timing_version=2,
                     smtp_metadata_fields_present=metadata_fields_present(metadata),
                     smtp_recipient_count=len(metadata.get("rcpt", [])),
                     client_ticket_status=client_ticket_status,
                     spfbl_ticket_status=ticket_status,
                     ticket_status_match=metadata["ticket_status_match"],
                     spfbl_feedback_recipient_count=metadata.get("spfbl_recipient_count"),
                     bsmtp_envelope=metadata.get("diagnostic_bsmtp_envelope"),
                     bsmtp_recipient_count=metadata.get("diagnostic_bsmtp_recipient_count"),
                     exim_env_recipient_count=metadata.get("diagnostic_exim_env_recipient_count"),
                     feedback_eligibility=metadata.get("feedback_ineligibility_reason",
                                                       "ineligible"))
            self._reply(202, {"queued": True})
        except queue.Full:
            self.server.upload_slots.release()
            self.server.pending_slots.release()
            emit_log("request_dropped", reason="queue_race", client_id=client_id,
                     message_id=message_id)
            self._reply(503, {"error": "busy"})
        except OverflowError:
            self.server.upload_slots.release()
            self.server.pending_slots.release()
            emit_log("request_dropped", reason="message_too_large", client_id=client_id,
                     message_id=message_id)
            self._reply(413, {"error": "message_too_large"})
        except (OSError, ValueError, http.client.HTTPException) as exc:
            self.server.upload_slots.release()
            self.server.pending_slots.release()
            emit_log("request_dropped", reason="invalid_or_incomplete_body", client_id=client_id,
                     message_id=message_id, error=exc.__class__.__name__)
            self._reply(400, {"error": "invalid_body"})


class BoundedThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, clients_path, max_message_bytes,
                 queue_size, worker_count, max_handlers,
                 allowlist_path=DEFAULT_MTA_ALLOWLIST):
        self.clients_path = clients_path
        self.allowlist_path = allowlist_path
        self.max_message_bytes = max_message_bytes
        self.worker_count = worker_count
        self.work_queue = queue.Queue(maxsize=queue_size + worker_count)
        self.pending_slots = threading.BoundedSemaphore(queue_size + worker_count)
        self.upload_slots = threading.BoundedSemaphore(max_handlers)
        self.handler_slots = threading.BoundedSemaphore(max_handlers + 8)
        super(BoundedThreadingHTTPServer, self).__init__(address, handler)

    def process_request(self, request, client_address):
        if not self.handler_slots.acquire(False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            except (OSError, socket.error):
                pass
            self.shutdown_request(request)
            return
        try:
            super(BoundedThreadingHTTPServer, self).process_request(request, client_address)
        except Exception:
            self.handler_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super(BoundedThreadingHTTPServer, self).process_request_thread(request, client_address)
        finally:
            self.handler_slots.release()

    def start_workers(self):
        for index in range(self.worker_count):
            thread = threading.Thread(target=self._worker, name="sfox-content-scan-%d" % index)
            thread.daemon = True
            thread.start()

    def _worker(self):
        while True:
            item = self.work_queue.get()
            if item is None:
                self.work_queue.task_done()
                return
            source_ip, client_id, message_id, body, size, queued_at, metadata = item
            started = monotonic()
            try:
                # The internal SPFBL ticket is a control value, never a content signal.
                clean_body = scan_client.strip_spfbl_feedback_header(
                    body, remove_native=True)
                native_bayes_started = monotonic()
                if metadata.get("native_bayes_enabled") is True:
                    try:
                        native_bayes = spfbl_bayes.scan_with_core(clean_body, source_ip)
                    except Exception as exc:
                        native_bayes = {"status": "internal_error"}
                        emit_log("native_bayes_failed", client_id=client_id,
                                 reason=exc.__class__.__name__)
                else:
                    native_bayes = {"status": "disabled"}
                native_bayes_latency_ms = max(
                    0, int((monotonic() - native_bayes_started) * 1000))
                feedback_action, feedback_reason = spfbl_feedback.feedback_eligibility(
                    metadata, metadata.get("spfbl_ticket"), native_bayes,
                    metadata.get("spfbl_feedback_enabled") is True)
                feedback_status = feedback_reason
                feedback_policy = feedback_reason if feedback_action == "spam" else None
                feedback_latency_ms = 0
                if feedback_action == "spam":
                    feedback_started = monotonic()
                    feedback_status = spfbl_feedback.submit_spam_ticket(
                        metadata["spfbl_ticket"]["ticket"])
                    feedback_latency_ms = max(0, int((monotonic() - feedback_started) * 1000))
                emit_log("scan_complete", client_id=client_id, message_id=message_id,
                         bytes=size, queue_ms=max(0, int((started - queued_at) * 1000)),
                         scan_ms=max(0, int((monotonic() - started) * 1000)), timing_version=2,
                         feedback_metadata_complete=metadata.get("feedback_eligible") is True,
                         feedback_eligibility=metadata.get("feedback_ineligibility_reason",
                                                           "ineligible"),
                         spfbl_feedback_enabled=metadata.get("spfbl_feedback_enabled") is True,
                         smtp_recipient_count=len(metadata.get("rcpt", [])),
                         client_ticket_status=metadata.get("client_ticket_status"),
                         spfbl_ticket_status=metadata.get("spfbl_ticket_status"),
                         ticket_status_match=metadata.get("ticket_status_match"),
                         spfbl_feedback_recipient_count=metadata.get("spfbl_recipient_count"),
                         bsmtp_envelope=metadata.get("diagnostic_bsmtp_envelope"),
                         bsmtp_recipient_count=metadata.get("diagnostic_bsmtp_recipient_count"),
                         exim_env_recipient_count=metadata.get("diagnostic_exim_env_recipient_count"),
                         engine="spfbl_native_bayes",
                         native_bayes_status=native_bayes.get("status"),
                         native_bayes_spam_probability=native_bayes.get("spam_probability"),
                         native_bayes_known_features=native_bayes.get("known_features"),
                         native_bayes_latency_ms=native_bayes_latency_ms,
                         spfbl_feedback=feedback_status,
                         spfbl_feedback_policy=feedback_policy,
                         spfbl_feedback_latency_ms=feedback_latency_ms)
            except Exception as exc:
                emit_log("scan_failed", client_id=client_id, message_id=message_id,
                         bytes=size, error=exc.__class__.__name__,
                         elapsed_ms=max(0, int((monotonic() - started) * 1000)), timing_version=2)
            finally:
                del body
                self.pending_slots.release()
                self.work_queue.task_done()


def run_server(bind="127.0.0.1", port=11335, clients_path="/etc/had-antispam/content-scan-clients.json",
               allowlist_path=DEFAULT_MTA_ALLOWLIST,
               max_message_bytes=MAX_MESSAGE_BYTES, queue_size=4, worker_count=2,
               max_handlers=2):
    address = (bind, port)
    server = BoundedThreadingHTTPServer(address, ScanHandler, clients_path,
                                        max_message_bytes, queue_size, worker_count,
                                        max_handlers, allowlist_path)
    server.start_workers()
    emit_log("gateway_started", bind=bind, port=port, engine="spfbl_native_bayes",
             max_message_bytes=max_message_bytes,
             queue_size=queue_size, worker_count=worker_count)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=11335)
    parser.add_argument("--clients", default="/etc/had-antispam/content-scan-clients.json")
    parser.add_argument("--allowlist", default=DEFAULT_MTA_ALLOWLIST)
    parser.add_argument("--max-message-bytes", type=int, default=MAX_MESSAGE_BYTES)
    parser.add_argument("--queue-size", type=int, default=4)
    parser.add_argument("--workers", type=int, default=2)
    args = parser.parse_args(argv)
    if args.bind not in ("127.0.0.1", "::1"):
        parser.error("gateway bind address must be loopback")
    if not 1 <= args.port <= 65535 or not 1 <= args.max_message_bytes <= MAX_MESSAGE_BYTES:
        parser.error("invalid port or message limit")
    if not 1 <= args.queue_size <= 16 or not 1 <= args.workers <= 4:
        parser.error("queue/workers outside supported bounds")
    run_server(args.bind, args.port, args.clients, args.allowlist, args.max_message_bytes,
               args.queue_size, args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
