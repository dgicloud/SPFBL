#!/usr/bin/env python3
"""Stream one accepted Exim/Postfix message to the HAD monitor gateway.

The message is read from stdin, held only in transit, and never written to a
file. This client intentionally exits successfully for all scanner failures:
content scanning is MONITOR-only and must not change mail acceptance/delivery.
Compatible with the Python 3.6 runtime shipped by supported cPanel releases.
"""

from __future__ import print_function

import http.client
import json
import os
import re
import socket
import ssl
import stat
import sys
import time
from urllib.parse import urlsplit

CHUNK_SIZE = 64 * 1024
DEFAULT_MAX_BYTES = 25 * 1024 * 1024
DEFAULT_TIMEOUT = 20.0
CLIENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,128}$")


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


def submit(stream, parsed, client_id, token, message_id, max_bytes, timeout):
    """Upload the input as HTTP chunked data without a persistent body copy."""
    if message_id and not MESSAGE_ID_RE.fullmatch(message_id):
        message_id = "-"
    connection = None
    sent = 0
    started = time.time()
    try:
        # DNS, connect, and TLS failures are part of fail-open MONITOR behavior.
        connection = _connect(parsed, timeout)
        path = parsed.path or "/"
        connection.putrequest("POST", path, skip_accept_encoding=True)
        connection.putheader("Content-Type", "message/rfc822")
        connection.putheader("Transfer-Encoding", "chunked")
        connection.putheader("X-SFOX-Client", client_id)
        if message_id:
            connection.putheader("X-SFOX-Message-ID", message_id)
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
                      bytes=sent, latency_ms=elapsed_ms)
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


def run(config_path, lock_path, stream=None, message_id=None):
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
        submit(stream, parsed, client_id, token, message_id, max_bytes, timeout)
        return 0
    finally:
        lock.close()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) not in (0, 2):
        return 0
    config_path = argv[0] if argv else "/etc/had-antispam/content-scan-client.json"
    lock_path = argv[1] if len(argv) == 2 else "/run/lock/had-content-scan.lock"
    return run(config_path, lock_path)


if __name__ == "__main__":
    raise SystemExit(main())
