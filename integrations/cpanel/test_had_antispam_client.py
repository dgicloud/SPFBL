import io
import json
import os
import shutil
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager
from typing import Dict, Optional
from unittest.mock import patch

from had_antispam_client import (
    MAX_RESPONSE_BYTES,
    Envelope,
    HeaderMessage,
    QueryResult,
    TransportConfig,
    format_local_header_result,
    format_local_result,
    main,
    parse_header_response,
    parse_local_header_record,
    parse_local_record,
    query,
    serialize_header,
    serialize_query,
    submit_header,
    LOCAL_FIELD_SEPARATOR,
)


class _ReplyHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        self.server.received = self.rfile.readline(8193)  # type: ignore[attr-defined]
        self.server.received_requests.append(self.server.received)  # type: ignore[attr-defined]
        if self.server.delay:  # type: ignore[attr-defined]
            time.sleep(self.server.delay)  # type: ignore[attr-defined]
        reply = self.server.reply  # type: ignore[attr-defined]
        if self.server.received.startswith(b"HEADER ") and self.server.header_reply is not None:  # type: ignore[attr-defined]
            reply = self.server.header_reply  # type: ignore[attr-defined]
        if reply is not None:
            self.wfile.write(reply)


class _ReplyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, reply: Optional[bytes], delay: float = 0.0,
                 header_reply: Optional[bytes] = None) -> None:
        super().__init__(("127.0.0.1", 0), _ReplyHandler)
        self.reply = reply
        self.header_reply = header_reply
        self.delay = delay
        self.received = b""
        self.received_requests = []
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=1)


@contextmanager
def reply_server(reply: Optional[bytes], delay: float = 0.0,
                 header_reply: Optional[bytes] = None):
    server = _ReplyServer(reply, delay, header_reply)
    try:
        yield server
    finally:
        server.close()


def sample_envelope(**overrides: object) -> Envelope:
    values: Dict[str, object] = {
        "client_ip": "192.0.2.25",
        "mail_from": "sender@example.test",
        "helo": "mx.example.test",
        "rcpt_to": "recipient@example.test",
        "recipient_exists": True,
    }
    values.update(overrides)
    return Envelope.from_json(values)


class EnvelopeProtocolTests(unittest.TestCase):
    def test_serialization_preserves_protocol_order(self) -> None:
        wire = serialize_query(sample_envelope())
        self.assertEqual(
            wire,
            b"SPF '192.0.2.25' 'sender@example.test' 'mx.example.test' 'recipient@example.test' true\n",
        )

    def test_rejects_quote_and_line_injection(self) -> None:
        for value in ("sender' SPF '127.0.0.1", "sender@example.test\r\nCLIENT ADD"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                sample_envelope(mail_from=value)

    def test_requires_numeric_server_ip(self) -> None:
        with self.assertRaisesRegex(ValueError, "server_must_be_ip_literal"):
            TransportConfig(server_ip="antispam.hadcloud.srv.br")

    def test_unix_socket_transport_requires_absolute_path(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid_server_socket_path"):
            TransportConfig(server_socket="relative/upstream.sock")
        with self.assertRaisesRegex(ValueError, "choose_one_upstream_transport"):
            TransportConfig(server_ip="127.0.0.1", server_socket="/run/upstream.sock")

    def test_allows_apostrophe_mailboxes_when_upstream_can_parse_them(self) -> None:
        envelope = sample_envelope(
            mail_from='"O\'Connor Person"@example.test',
            rcpt_to="o'connor@example.test",
        )
        self.assertIn(b"O'Connor Person", serialize_query(envelope))
        self.assertIn(b"o'connor@example.test", serialize_query(envelope))

    def test_rejects_only_upstream_unrepresentable_address_shapes(self) -> None:
        with self.assertRaisesRegex(ValueError, "unrepresentable_mail_from"):
            sample_envelope(mail_from="O' Connor@example.test")
        with self.assertRaisesRegex(ValueError, "invalid_rcpt_to"):
            sample_envelope(rcpt_to='"local part"@example.test')

    def test_parses_fixed_local_record(self) -> None:
        record = LOCAL_FIELD_SEPARATOR.join(
            (
                b"192.0.2.25",
                b"sender@example.test",
                b"mx.example.test",
                b"recipient@example.test",
                b"true",
            )
        )
        envelope = parse_local_record(record)
        self.assertEqual(envelope, sample_envelope())

    def test_local_response_is_compact_and_contains_no_ticket_value(self) -> None:
        result = QueryResult("MONITOR", "continue", "decision", "FLAG", True, 17)
        self.assertEqual(format_local_result(result), b"CONTINUE|decision|FLAG|17|-")

    def test_local_response_forwards_valid_ticket_but_json_does_not(self) -> None:
        ticket = "a" * 44
        result = QueryResult("MONITOR", "continue", "decision", "PASS", True, 9, ticket)

        self.assertEqual(format_local_result(result), ("CONTINUE|decision|PASS|9|" + ticket).encode("ascii"))
        self.assertNotIn(ticket, json.dumps(result.as_dict()))


def sample_header(**overrides):
    values = {
        "tickets": "ticket-one;ticket-two",
        "dkim": "example.test,mail.example.test",
        "from_header": "Sender Name <sender@example.test>",
        "reply_to": "reply@example.test",
        "message_id": "<message-1@example.test>",
        "in_reply_to": "",
        "queue_id": "1xABC-0000000001-xyz",
        "date": "Fri, 02 Oct 2026 10:00:00 -0300",
        "list_unsubscribe": "<mailto:unsubscribe@example.test>",
        "subject": "Quarterly report",
    }
    values.update(overrides)
    return HeaderMessage.from_values(**values)


class HeaderProtocolTests(unittest.TestCase):
    def test_header_wire_matches_upstream_command_shape(self):
        self.assertEqual(
            serialize_header(sample_header()),
            b"HEADER ticket-one;ticket-two DKIM:example.test,mail.example.test "
            b"From:Sender Name <sender@example.test> Reply-To:reply@example.test "
            b"Message-ID:<message-1@example.test> Queue-ID:1xABC-0000000001-xyz "
            b"Date:Fri, 02 Oct 2026 10:00:00 -0300 "
            b"List-Unsubscribe:<mailto:unsubscribe@example.test> Subject:Quarterly report\n",
        )

    def test_local_header_record_accepts_exim_metadata(self):
        record = LOCAL_FIELD_SEPARATOR.join(
            value.encode("utf-8")
            for value in (
                "HEADER", "ticket-one;ticket-two", "example.test", "Sender <sender@example.test>",
                "reply@example.test", "<message-1@example.test>", "", "queue-1", "Fri, 02 Oct 2026",
                "<mailto:unsubscribe@example.test>", "Quarterly report",
            )
        )
        message = parse_local_header_record(record)
        self.assertEqual(message.tickets, ("ticket-one", "ticket-two"))
        self.assertEqual(message.queue_id, "queue-1")

    def test_header_values_are_flattened_and_reserved_markers_rejected(self):
        flattened = sample_header(subject="line one\r\nline two")
        self.assertIn(b"Subject:line one line two\n", serialize_header(flattened))
        with self.assertRaisesRegex(ValueError, "ambiguous_header_subject"):
            sample_header(subject="regular text Date: forged")

    def test_invalid_ticket_set_and_large_header_fail_closed_to_monitor(self):
        with self.assertRaisesRegex(ValueError, "invalid_header_ticket"):
            sample_header(tickets="ticket-one;ticket two")
        with self.assertRaisesRegex(ValueError, "oversized_header_request"):
            serialize_header(sample_header(subject="x" * 2000))

    def test_header_responses_are_reduced_to_safe_status(self):
        self.assertEqual(parse_header_response(b"CLEAR\n"), "CLEAR")
        self.assertEqual(parse_header_response(b"BLOCKED https://example.test/appeal\n"), "BLOCKED")
        self.assertEqual(parse_header_response(b"NOT FOUND\n"), "NOT_FOUND")
        with self.assertRaisesRegex(LookupError, "upstream_error"):
            parse_header_response(b"OUT OF SERVICE\n")

    def test_submit_header_sends_upstream_command_and_never_returns_url(self):
        with reply_server(b"BLOCKED https://example.test/appeal\n") as server:
            result = submit_header(
                sample_header(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertEqual(result.status, "BLOCKED")
        self.assertEqual(result.ticket_count, 2)
        self.assertTrue(server.received.startswith(b"HEADER ticket-one;ticket-two "))
        self.assertNotIn(b"appeal", format_local_header_result(result))

    def test_submit_header_is_monitor_and_fail_open_on_connect_error(self):
        with patch("had_antispam_client.socket.create_connection", side_effect=ConnectionRefusedError):
            result = submit_header(sample_header(), TransportConfig(server_ip="127.0.0.1"))
        self.assertEqual(result.status, "connect_io_error")
        self.assertEqual(result.ticket_count, 2)
        self.assertEqual(result.connect_attempts, 2)
        self.assertEqual(format_local_header_result(result).split(b"|")[:3],
                         [b"CONTINUE", b"header", b"connect_io_error"])

    def test_submit_header_retries_connect_timeout_once(self):
        with reply_server(b"CLEAR\n") as server:
            original_connect = socket.create_connection
            calls = []

            def transient_connect(address, timeout):
                calls.append(timeout)
                if len(calls) == 1:
                    raise socket.timeout()
                return original_connect(address, timeout)

            with patch("had_antispam_client.socket.create_connection",
                       side_effect=transient_connect):
                result = submit_header(
                    sample_header(),
                    TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
                )
        self.assertEqual((result.status, result.connect_attempts), ("CLEAR", 2))
        self.assertEqual(len(calls), 2)
        self.assertTrue(server.received.startswith(b"HEADER ticket-one;ticket-two "))


class QueryTests(unittest.TestCase):
    def test_monitor_records_flag_and_does_not_return_ticket(self) -> None:
        with reply_server(b"FLAG secret-ticket\n") as server:
            result = query(
                sample_envelope(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertEqual(result.mode, "MONITOR")
        self.assertEqual(result.action, "continue")
        self.assertEqual(result.status, "decision")
        self.assertEqual(result.decision, "FLAG")
        self.assertTrue(result.ticket_present)
        self.assertEqual(result.ticket, "secret-ticket")
        self.assertNotIn("secret-ticket", json.dumps(result.as_dict()))
        self.assertIn(b"SPF '", server.received)

    def test_url_ticket_is_reduced_to_opaque_token_for_exim(self) -> None:
        ticket = "A_-09" * 9
        with reply_server(("PASS https://matrix.example.test/feedback/" + ticket + "\n").encode()) as server:
            result = query(
                sample_envelope(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertEqual(result.ticket, ticket)
        self.assertEqual(format_local_result(result).split(b"|")[-1], ticket.encode("ascii"))

    def test_appeal_url_is_not_forwarded_as_feedback_ticket(self) -> None:
        with reply_server(b"BLOCKED https://matrix.example.test/unblock/token-123\n") as server:
            result = query(
                sample_envelope(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertEqual(result.decision, "BLOCKED")
        self.assertTrue(result.ticket_present)
        self.assertIsNone(result.ticket)
        self.assertEqual(format_local_result(result).split(b"|")[-1], b"-")

    def test_invalid_feedback_ticket_is_not_forwarded(self) -> None:
        with reply_server(b"FLAG token;INJECTED\n") as server:
            result = query(
                sample_envelope(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertTrue(result.ticket_present)
        self.assertIsNone(result.ticket)
        self.assertEqual(format_local_result(result).split(b"|")[-1], b"-")

    def test_fail_with_ticket_remains_observation_only(self) -> None:
        with reply_server(b"FAIL ticket-1\n") as server:
            result = query(
                sample_envelope(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertEqual((result.decision, result.action, result.ticket_present), ("FAIL", "continue", True))

    def test_fail_without_ticket_is_distinguished(self) -> None:
        with reply_server(b"FAIL\n") as server:
            result = query(
                sample_envelope(),
                TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
            )
        self.assertEqual((result.decision, result.ticket_present), ("FAIL", False))

    def test_service_and_unknown_statuses_fail_open(self) -> None:
        cases = (
            (b"ERROR: fatal\n", "server_error"),
            (b"UNEXPECTED\n", "unknown_status"),
            (b"LAN\nFLAG ticket\n", "invalid_response_line"),
            (b"", "invalid_response_size"),
            (b"X" * (MAX_RESPONSE_BYTES + 1), "invalid_response_size"),
        )
        for reply, expected in cases:
            with self.subTest(reply=reply), reply_server(reply) as server:
                result = query(
                    sample_envelope(),
                    TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
                )
            self.assertEqual(
                (result.status, result.action, result.decision),
                (expected, "continue", None),
            )

    def test_required_upstream_decision_matrix_remains_monitor_only(self) -> None:
        # The core status strings are synthetic protocol replies here. This proves
        # the HAD adapter parses every required decision and never enforces it.
        with_ticket = (
            "PASS", "WHITE", "FLAG", "LISTED", "BLOCKED", "FAIL",
            "SOFTFAIL", "NEUTRAL", "NONE", "HOLD",
        )
        without_ticket = ("GREYLIST", "SPAMTRAP", "NXDOMAIN", "INVALID")
        for decision in with_ticket + without_ticket:
            ticket_present = decision in with_ticket
            response = decision + (" synthetic-value" if ticket_present else "") + "\n"
            with self.subTest(decision=decision), reply_server(response.encode()) as server:
                result = query(
                    sample_envelope(),
                    TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
                )
            self.assertEqual(
                (result.status, result.action, result.decision, result.ticket_present),
                ("decision", "continue", decision, ticket_present),
            )

    def test_blackhole_obeys_total_timeout_and_fails_open(self) -> None:
        with reply_server(None, delay=0.3) as server:
            started = time.monotonic()
            result = query(
                sample_envelope(),
                TransportConfig(
                    server_ip="127.0.0.1",
                    port=server.server_address[1],
                    connect_timeout=0.05,
                    total_timeout=0.1,
                ),
            )
            elapsed = time.monotonic() - started
        self.assertEqual((result.status, result.action), ("read_timeout", "continue"))
        self.assertEqual(result.connect_attempts, 1)
        self.assertLess(elapsed, 0.25)

    def test_connection_refused_fails_open(self) -> None:
        with patch("had_antispam_client.socket.create_connection", side_effect=ConnectionRefusedError):
            result = query(sample_envelope(), TransportConfig(server_ip="127.0.0.1"))
        self.assertEqual(
            (result.status, result.action, result.decision, result.connect_attempts),
            ("connect_io_error", "continue", None, 2),
        )

    def test_retries_transient_connect_timeout_once_without_duplicate_request(self) -> None:
        with reply_server(b"LAN\n") as server:
            original_connect = socket.create_connection
            calls = []

            def transient_connect(address, timeout):
                calls.append(timeout)
                if len(calls) == 1:
                    raise socket.timeout()
                return original_connect(address, timeout)

            with patch("had_antispam_client.socket.create_connection",
                       side_effect=transient_connect):
                result = query(
                    sample_envelope(),
                    TransportConfig(server_ip="127.0.0.1", port=server.server_address[1]),
                )
        self.assertEqual((result.status, result.decision), ("decision", "LAN"))
        self.assertEqual(result.connect_attempts, 2)
        self.assertEqual(len(calls), 2)
        self.assertEqual(server.received.count(b"SPF "), 1)

    @unittest.skipIf(os.name == "nt" or not hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
    def test_query_uses_unix_socket_for_private_transport(self) -> None:
        with tempfile.TemporaryDirectory(prefix="had-antispam-upstream-") as directory:
            socket_path = os.path.join(directory, "core.sock")
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            listener.bind(socket_path)
            listener.listen(1)
            received = []

            def reply() -> None:
                connection, _ = listener.accept()
                with connection:
                    received.append(connection.recv(2048))
                    connection.sendall(b"FLAG synthetic-ticket\n")

            thread = threading.Thread(target=reply, daemon=True)
            thread.start()
            try:
                result = query(sample_envelope(), TransportConfig(server_socket=socket_path))
                thread.join(timeout=2)
            finally:
                listener.close()
            self.assertFalse(thread.is_alive(), "Unix upstream did not finish")
            self.assertEqual((result.decision, result.ticket_present, result.action), ("FLAG", True, "continue"))
            self.assertTrue(received[0].startswith(b"SPF '192.0.2.25'"))

    def test_cli_emits_monitor_json_without_envelope_values(self) -> None:
        payload = json.dumps(
            {
                "client_ip": "192.0.2.25",
                "mail_from": "private-sender@example.test",
                "helo": "mx.example.test",
                "rcpt_to": "private-recipient@example.test",
                "recipient_exists": False,
            }
        ).encode()
        with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload))):
            # CLI transport defaults to loopback; a refused connection still continues.
            with patch("sys.stdout", new_callable=io.StringIO) as stdout, patch(
                "sys.stderr", new_callable=io.StringIO
            ) as stderr:
                exit_code = main([])
        self.assertEqual(exit_code, 0)
        self.assertIn('"action":"continue"', stdout.getvalue())
        self.assertNotIn("private-sender", stdout.getvalue() + stderr.getvalue())
        self.assertNotIn("private-recipient", stdout.getvalue() + stderr.getvalue())

    def test_invalid_cli_config_still_returns_monitor_continue(self) -> None:
        with patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"{}\n"))):
            with patch("sys.stdout", new_callable=io.StringIO) as stdout, patch(
                "sys.stderr", new_callable=io.StringIO
            ):
                exit_code = main(["--port", "not-a-port"])
        self.assertEqual(exit_code, 0)
        self.assertIn('"action":"continue"', stdout.getvalue())
        self.assertIn('"status":"invalid_cli_arguments"', stdout.getvalue())

    def test_installed_entrypoint_imports_shared_client_from_sibling_directory(self) -> None:
        source_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        entrypoint = os.path.join(source_dir, "cpanel", "had_antispam_client.py")
        shared_client = os.path.join(source_dir, "common", "spfbl_client.py")
        with tempfile.TemporaryDirectory(prefix="had-antispam-installed-client-") as directory:
            installed_entrypoint = os.path.join(directory, "had_antispam_client.py")
            shutil.copyfile(entrypoint, installed_entrypoint)
            shutil.copyfile(shared_client, os.path.join(directory, "spfbl_client.py"))
            result = subprocess.run(
                [sys.executable, installed_entrypoint, "--help"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=5,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage:", result.stdout)


@unittest.skipIf(os.name == "nt" or not hasattr(socket, "AF_UNIX"), "Unix sockets are unavailable")
class LocalSocketServiceTests(unittest.TestCase):
    def test_service_handles_exim_request_and_stops_cleanly(self) -> None:
        with tempfile.TemporaryDirectory(prefix="had-antispam-uds-") as directory:
            socket_path = os.path.join(directory, "monitor.sock")
            adapter_path = os.path.join(os.path.dirname(__file__), "had_antispam_client.py")
            with reply_server(b"LAN\n", header_reply=b"CLEAR\n") as upstream:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        adapter_path,
                        "--server",
                        "127.0.0.1",
                        "--port",
                        str(upstream.server_address[1]),
                        "--listen-socket",
                        socket_path,
                    ],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                try:
                    deadline = time.monotonic() + 3
                    while not os.path.exists(socket_path) and time.monotonic() < deadline:
                        if process.poll() is not None:
                            self.fail("Adapter stopped before creating socket: exit=%r" % process.returncode)
                        time.sleep(0.01)
                    self.assertTrue(os.path.exists(socket_path), "Adapter did not create its Unix socket")

                    def send_local(record):
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                            client.settimeout(2)
                            client.connect(socket_path)
                            client.sendall(record)
                            client.shutdown(socket.SHUT_WR)
                            return client.recv(256)

                    envelope_record = LOCAL_FIELD_SEPARATOR.join(
                        (b"192.0.2.25", b"sender@example.test", b"mx.example.test",
                         b"recipient@example.test", b"null")
                    )
                    query_response = send_local(envelope_record)
                    self.assertTrue(query_response.startswith(b"CONTINUE|decision|LAN|"), query_response)

                    header_record = LOCAL_FIELD_SEPARATOR.join(
                        value.encode("utf-8")
                        for value in (
                            "HEADER", "synthetic-ticket", "example.test", "Sender <sender@example.test>",
                            "reply@example.test", "<message@example.test>", "", "queue-1",
                            "Fri, 02 Oct 2026", "<mailto:unsubscribe@example.test>", "Smoke test",
                        )
                    )
                    header_response = send_local(header_record)
                    self.assertTrue(header_response.startswith(b"CONTINUE|header|CLEAR|"), header_response)
                    no_ticket_record = header_record.replace(
                        b"HEADER\x1fsynthetic-ticket", b"HEADER\x1f"
                    )
                    no_ticket_response = send_local(no_ticket_record)
                    self.assertTrue(
                        no_ticket_response.startswith(b"CONTINUE|header|no_ticket|"),
                        no_ticket_response,
                    )
                    self.assertEqual(len(upstream.received_requests), 2)
                    self.assertTrue(upstream.received_requests[0].startswith(b"SPF '192.0.2.25'"))
                    self.assertTrue(upstream.received_requests[1].startswith(b"HEADER synthetic-ticket "))
                finally:
                    if process.poll() is None:
                        process.terminate()
                    process.wait(timeout=3)
                self.assertEqual(process.returncode, 0, "Adapter shutdown failed")
                self.assertFalse(os.path.exists(socket_path), "Adapter left a stale Unix socket")


if __name__ == "__main__":
    unittest.main()
