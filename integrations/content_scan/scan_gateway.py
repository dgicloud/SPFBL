#!/usr/bin/env python3
"""Bounded, RAM-only HTTP ingress and asynchronous Rspamd scanner gateway."""

from __future__ import print_function

import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import queue
import re
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

MAX_MESSAGE_BYTES = 25 * 1024 * 1024
MAX_RSPAMD_RESPONSE_BYTES = 1024 * 1024
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")
SYMBOL_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")


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


def validate_client(clients, client_id, token, source_ip):
    if not CLIENT_ID_RE.fullmatch(client_id or ""):
        return False
    client = clients.get(client_id)
    if not isinstance(client, dict) or client.get("enabled", True) is not True:
        return False
    saved_digest = client.get("token_sha256", "")
    supplied_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not isinstance(saved_digest, str) or len(saved_digest) != 64:
        return False
    if not hmac.compare_digest(saved_digest, supplied_digest):
        return False
    try:
        address = ipaddress.ip_address(source_ip)
        networks = [ipaddress.ip_network(item, strict=False)
                    for item in client.get("allowed_cidrs", [])]
    except (ValueError, TypeError):
        return False
    return any(address in network for network in networks)


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


def _safe_summary(response_body):
    result = json.loads(response_body.decode("utf-8"))
    if not isinstance(result, dict):
        raise ValueError("Rspamd response is not a JSON object")
    action = result.get("action", "unknown")
    action = action if isinstance(action, str) else "unknown"
    action = re.sub(r"[^A-Za-z0-9 _-]", "", action)[:32] or "unknown"
    score = result.get("score")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        score = None
    required_score = result.get("required_score")
    if (isinstance(required_score, bool) or not isinstance(required_score, (int, float))
            or not math.isfinite(required_score)):
        required_score = None
    symbols = result.get("symbols", {})
    names = []
    if isinstance(symbols, dict):
        names = sorted(name for name in symbols if isinstance(name, str) and SYMBOL_RE.match(name))
    return {"action": action, "score": score, "required_score": required_score,
            "symbols": names[:64]}


def scan_with_rspamd(body, host="127.0.0.1", port=11333, timeout=12.0):
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        connection.putrequest("POST", "/checkv2")
        connection.putheader("Content-Type", "message/rfc822")
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Flags", "no_log")
        connection.endheaders()
        view = memoryview(body)
        for offset in range(0, len(view), 64 * 1024):
            connection.send(view[offset:offset + 64 * 1024])
        response = connection.getresponse()
        if response.status != 200:
            response.read(4096)
            raise RuntimeError("Rspamd HTTP status %d" % response.status)
        data = response.read(MAX_RSPAMD_RESPONSE_BYTES + 1)
        if len(data) > MAX_RSPAMD_RESPONSE_BYTES:
            raise RuntimeError("Rspamd response exceeds limit")
        return _safe_summary(data)
    finally:
        connection.close()


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

        client_id = self.headers.get("X-SFOX-Client", "")
        token_header = self.headers.get("Authorization", "")
        token = token_header[7:] if token_header.startswith("Bearer ") else ""
        try:
            source_ip = str(ipaddress.ip_address(self.headers.get("X-Real-IP", "")))
            clients = parse_client_config(self.server.clients_path)
        except (OSError, ValueError, TypeError):
            self._reply(503, {"error": "gateway_configuration"})
            return
        if not token or not validate_client(clients, client_id, token, source_ip):
            emit_log("request_denied", reason="auth_or_source", client_id=client_id[:64])
            self._reply(403, {"error": "forbidden"})
            return

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
        max_bytes = self.server.max_message_bytes
        started = time.time()
        try:
            if transfer_encoding == "chunked":
                body = read_chunked(self.rfile, max_bytes)
            else:
                body = read_content_length(self.rfile, content_length, max_bytes)
            if not body:
                raise ValueError("empty message")
            self.server.work_queue.put_nowait((client_id, message_id, body, len(body), started))
            self.server.upload_slots.release()
            emit_log("message_queued", client_id=client_id, message_id=message_id,
                     bytes=len(body), queue_depth=self.server.work_queue.qsize())
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
                 queue_size, worker_count, max_handlers):
        self.clients_path = clients_path
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
            thread = threading.Thread(target=self._worker, name="rspamd-scan-%d" % index)
            thread.daemon = True
            thread.start()

    def _worker(self):
        while True:
            item = self.work_queue.get()
            if item is None:
                self.work_queue.task_done()
                return
            client_id, message_id, body, size, queued_at = item
            started = time.time()
            try:
                result = scan_with_rspamd(body)
                emit_log("scan_complete", client_id=client_id, message_id=message_id,
                         bytes=size, queue_ms=max(0, int((started - queued_at) * 1000)),
                         scan_ms=max(0, int((time.time() - started) * 1000)),
                         score=result["score"], required_score=result["required_score"],
                         action=result["action"], symbols=result["symbols"])
            except Exception as exc:
                emit_log("scan_failed", client_id=client_id, message_id=message_id,
                         bytes=size, error=exc.__class__.__name__,
                         elapsed_ms=max(0, int((time.time() - started) * 1000)))
            finally:
                del body
                self.pending_slots.release()
                self.work_queue.task_done()


def run_server(bind="127.0.0.1", port=11335, clients_path="/etc/had-antispam/content-scan-clients.json",
               max_message_bytes=MAX_MESSAGE_BYTES, queue_size=4, worker_count=2,
               max_handlers=2):
    address = (bind, port)
    server = BoundedThreadingHTTPServer(address, ScanHandler, clients_path,
                                        max_message_bytes, queue_size, worker_count,
                                        max_handlers)
    server.start_workers()
    emit_log("gateway_started", bind=bind, port=port, max_message_bytes=max_message_bytes,
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
    run_server(args.bind, args.port, args.clients, args.max_message_bytes,
               args.queue_size, args.workers)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
