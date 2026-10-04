#!/usr/bin/env python3
"""After-queue MONITOR copy for Postfix with safe local reinjection.

Postfix has already accepted and queued the message before invoking this
transport. The script forwards the unchanged message to sendmail for normal
delivery while streaming a best-effort copy to the central content scanner.
Scanner failures never block reinjection. A failed local reinjection is
temporary so Postfix retains and retries the original queue entry.
"""

from __future__ import print_function

import argparse
import json
import os
import subprocess
import sys
import time


HERE = os.path.dirname(os.path.abspath(__file__))
def _scan_client_directory(script_dir):
    """Find scan_client.py both in the source tree and installed side-by-side."""
    candidates = (
        script_dir,
        os.path.abspath(os.path.join(script_dir, "..", "content_scan")),
    )
    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "scan_client.py")):
            return candidate
    raise ImportError("scan_client.py is missing from the package")


LOCAL_SCAN_CLIENT = _scan_client_directory(HERE)
if LOCAL_SCAN_CLIENT not in sys.path:
    sys.path.insert(0, LOCAL_SCAN_CLIENT)

import scan_client


TEMPFAIL = 75


def _emit(event, **fields):
    fields["mta"] = "postfix"
    scan_client.log_event(event, **fields)


def _drain(stream):
    try:
        while stream.read(scan_client.CHUNK_SIZE):
            pass
    except Exception:
        pass


def _lock_nonblocking(lock):
    """Acquire one upload slot; use the platform's advisory file lock."""
    if os.name == "nt":
        import msvcrt
        lock.seek(0)
        if not lock.read(1):
            lock.write("0")
            lock.flush()
        lock.seek(0)
        try:
            msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
            return True
        except (IOError, OSError):
            return False
    import fcntl
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (IOError, OSError):
        return False


def _unlock(lock):
    if os.name == "nt":
        import msvcrt
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _acquire_upload_slot(lock_path):
    """Claim one of the two bounded upload slots without delaying delivery."""
    for candidate in (lock_path, lock_path + ".1"):
        try:
            lock = open(candidate, "a+")
        except OSError:
            continue
        if _lock_nonblocking(lock):
            return lock
        lock.close()
    return None


def _sendmail_command(sendmail, sender, recipients):
    """Build argv without a shell; keep envelope values out of logs."""
    command = [sendmail, "-G", "-i", "-f", sender or "<>", "--"]
    command.extend(recipients)
    return command


def _open_upload(config, message_id):
    parsed, client_id, token, max_bytes, timeout = config
    connection = scan_client._connect(parsed, timeout)
    connection.putrequest("POST", parsed.path or "/", skip_accept_encoding=True)
    connection.putheader("Content-Type", "message/rfc822")
    connection.putheader("Transfer-Encoding", "chunked")
    connection.putheader("X-SFOX-Client", client_id)
    if message_id:
        connection.putheader("X-SFOX-Message-ID", message_id)
    connection.putheader("Authorization", "Bearer " + token)
    connection.endheaders()
    return connection, client_id, max_bytes


def _upload_chunk(connection, chunk):
    connection.send(("%X\r\n" % len(chunk)).encode("ascii"))
    connection.send(chunk)
    connection.send(b"\r\n")


def _upload_result(connection, client_id, message_id, sent, started):
    connection.send(b"0\r\n\r\n")
    response = connection.getresponse()
    response.read(4096)
    elapsed_ms = int((time.time() - started) * 1000)
    if response.status == 202:
        _emit("upload_queued", client_id=client_id, message_id=message_id,
              bytes=sent, latency_ms=elapsed_ms)
    else:
        _emit("upload_skipped", client_id=client_id, message_id=message_id,
              reason="gateway_http_status", http_status=response.status,
              bytes=sent, latency_ms=elapsed_ms)


def process_message(stream, sender, recipients, message_id, config_path,
                    lock_path, sendmail="/usr/sbin/sendmail", popen=None):
    """Reinject an accepted Postfix message and upload a bounded scan copy."""
    popen = popen or subprocess.Popen
    config = None
    try:
        config = scan_client.load_config(config_path)
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        _emit("upload_skipped", reason="invalid_config", error=exc.__class__.__name__)

    try:
        reinject = popen(_sendmail_command(sendmail, sender, recipients),
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
    except OSError as exc:
        _emit("reinject_deferred", reason="sendmail_unavailable",
              error=exc.__class__.__name__)
        _drain(stream)
        return TEMPFAIL

    lock = None
    connection = None
    client_id = None
    max_bytes = 0
    sent = 0
    upload_started = time.time()
    upload_reason = None
    try:
        if config is not None:
            client_id = config[1]
            max_bytes = config[3]
            try:
                lock = _acquire_upload_slot(lock_path)
                if lock is None:
                    upload_reason = "local_concurrency_limit"
                else:
                    connection, client_id, max_bytes = _open_upload(config, message_id)
            except Exception as exc:
                if connection is not None:
                    try:
                        connection.close()
                    except Exception:
                        pass
                    connection = None
                upload_reason = "transport_error"
                parsed, configured_client_id, _, _, _ = config
                client_id = configured_client_id
                _emit("upload_skipped", client_id=client_id, message_id=message_id,
                      reason=upload_reason, error=exc.__class__.__name__,
                      latency_ms=int((time.time() - upload_started) * 1000))

        while True:
            chunk = stream.read(scan_client.CHUNK_SIZE)
            if not chunk:
                break
            try:
                reinject.stdin.write(chunk)
            except (IOError, OSError, BrokenPipeError) as exc:
                _emit("reinject_deferred", reason="sendmail_input_error",
                      error=exc.__class__.__name__)
                _drain(stream)
                try:
                    reinject.stdin.close()
                except Exception:
                    pass
                try:
                    reinject.kill()
                except Exception:
                    pass
                reinject.wait()
                return TEMPFAIL

            if connection is not None:
                sent += len(chunk)
                if sent > max_bytes:
                    connection.close()
                    connection = None
                    upload_reason = "message_too_large"
                    continue
                try:
                    _upload_chunk(connection, chunk)
                except Exception as exc:
                    try:
                        connection.close()
                    except Exception:
                        pass
                    connection = None
                    upload_reason = "transport_error"
                    _emit("upload_skipped", client_id=client_id,
                          message_id=message_id, reason=upload_reason,
                          error=exc.__class__.__name__, bytes=sent,
                          latency_ms=int((time.time() - upload_started) * 1000))

        try:
            reinject.stdin.close()
        except (IOError, OSError, BrokenPipeError) as exc:
            _emit("reinject_deferred", reason="sendmail_input_error",
                  error=exc.__class__.__name__)
            try:
                reinject.kill()
            except Exception:
                pass
            reinject.wait()
            return TEMPFAIL
        return_code = reinject.wait()
        if return_code != 0:
            _emit("reinject_deferred", reason="sendmail_failed",
                  exit_status=return_code)
            return TEMPFAIL

        _emit("reinject_accepted", message_id=message_id)
        if connection is not None:
            try:
                if sent == 0:
                    upload_reason = "empty_message"
                    connection.close()
                    _emit("upload_skipped", client_id=client_id,
                          message_id=message_id, reason=upload_reason, bytes=0)
                else:
                    _upload_result(connection, client_id, message_id, sent,
                                   upload_started)
            except Exception as exc:
                upload_reason = "transport_error"
                _emit("upload_skipped", client_id=client_id,
                      message_id=message_id, reason=upload_reason,
                      error=exc.__class__.__name__, bytes=sent,
                      latency_ms=int((time.time() - upload_started) * 1000))
        elif upload_reason:
            _emit("upload_skipped", client_id=client_id,
                  message_id=message_id, reason=upload_reason, bytes=sent)
        return 0
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
        if lock is not None:
            try:
                _unlock(lock)
            except Exception:
                pass
            lock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sender", required=True)
    parser.add_argument("--recipient", action="append", required=True)
    parser.add_argument("--queue-id", default="-")
    parser.add_argument("--config", default="/etc/had-content-scan/postfix/client.json")
    parser.add_argument("--lock", default="/var/lib/had-content-scan/postfix/upload.lock")
    parser.add_argument("--sendmail", default="/usr/sbin/sendmail")
    args = parser.parse_args(argv)
    return process_message(sys.stdin.buffer, args.sender, args.recipient,
                           args.queue_id, args.config, args.lock, args.sendmail)


if __name__ == "__main__":
    raise SystemExit(main())
