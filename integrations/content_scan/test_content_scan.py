import base64
import http.client
import io
import math
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock
from http.server import BaseHTTPRequestHandler, HTTPServer

import manage_clients
import scan_client
import scan_gateway
import spfbl_feedback
import spfbl_bayes
import install_nginx_location
import sync_nginx_allowlist


class ContentScanTests(unittest.TestCase):
    def test_client_cli_defaults_match_the_cpanel_collector_install_paths(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(scan_client, "run", return_value=0) as run:
            self.assertEqual(0, scan_client.main([]))

        run.assert_called_once_with(
            "/etc/sfox-content-scan/client.json",
            "/run/lock/sfox-content-scan.lock",
            stream=scan_client.sys.stdin.buffer,
            message_id=None, queue_id=None, sender=None, recipients=[],
            client_ip=None, helo=None, auth_user=None, received_port=None,
            bsmtp_envelope=False,
            bsmtp_recipient_count=None, exim_env_recipient_count=0,
        )

    def test_client_config_needs_only_endpoint_and_limits(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-client-")
        path = os.path.join(temp_dir, "client.json")
        try:
            with open(path, "w") as stream:
                json.dump({"endpoint": "https://matrix.hadcloud.srv.br/internal/sfox/scan",
                           "max_bytes": 1024, "timeout_seconds": 4}, stream)
            with mock.patch.object(scan_client.os, "stat",
                                   return_value=mock.Mock(st_mode=0o100600)):
                parsed, max_bytes, timeout = scan_client.load_config(path)
            self.assertEqual("matrix.hadcloud.srv.br", parsed.hostname)
            self.assertEqual(1024, max_bytes)
            self.assertEqual(4.0, timeout)
        finally:
            os.unlink(path)
            os.rmdir(temp_dir)

    def test_exim_client_metadata_is_read_from_validated_base64_environment(self):
        values = {
            "HAD_SFOX_QUEUE_ID_B64": "1xABC-000000000001-xyz",
            "HAD_SFOX_SENDER_B64": "sender@example.invalid",
            "HAD_SFOX_RECIPIENTS_B64": "one@example.invalid, two@example.invalid",
            "HAD_SFOX_CLIENT_IP_B64": "2001:db8::25",
            "HAD_SFOX_HELO_B64": "mx.example.invalid",
            "HAD_SFOX_RECEIVED_PORT_B64": "25",
        }
        encoded = {name: base64.b64encode(value.encode("utf-8")).decode("ascii")
                   for name, value in values.items()}
        with mock.patch.dict(os.environ, encoded, clear=True):
            self.assertEqual({
                "queue_id": values["HAD_SFOX_QUEUE_ID_B64"],
                "sender": values["HAD_SFOX_SENDER_B64"],
                "recipients": ["one@example.invalid", "two@example.invalid"],
                "client_ip": values["HAD_SFOX_CLIENT_IP_B64"],
                "helo": values["HAD_SFOX_HELO_B64"],
                "received_port": values["HAD_SFOX_RECEIVED_PORT_B64"],
            }, scan_client.exim_environment_metadata())

    def test_invalid_exim_environment_encoding_is_ignored(self):
        with mock.patch.dict(os.environ, {
            "HAD_SFOX_QUEUE_ID_B64": "%%%not-base64%%%",
            "HAD_SFOX_CLIENT_IP_B64": "%%%not-base64%%%",
            "HAD_SFOX_RECEIVED_PORT_B64": "%%%not-base64%%%",
        }, clear=True):
            metadata = scan_client.exim_environment_metadata()
        self.assertIsNone(metadata["queue_id"])
        self.assertIsNone(metadata["client_ip"])
        self.assertIsNone(metadata["received_port"])

    def test_exim_bsmtp_envelope_is_removed_and_dot_stuffing_is_reversed(self):
        payload = (
            b"From: sender@example.invalid\r\n"
            b"Subject: real-looking message\r\n\r\n"
            b"first line\r\n.leading dot\r\n..two dots\r\n"
        )
        bsmtp = io.BytesIO(
            b"MAIL FROM:<sender@example.invalid> SIZE=200\r\n"
            b"RCPT TO:<recipient-one@example.invalid>\r\n"
            b"RCPT TO:<recipient-two@example.invalid>\r\n"
            b"DATA\r\n"
            b"From: sender@example.invalid\r\n"
            b"Subject: real-looking message\r\n\r\n"
            b"first line\r\n..leading dot\r\n...two dots\r\n.\r\nQUIT\r\n"
        )

        message, sender, recipients = scan_client.parse_exim_bsmtp(bsmtp)

        self.assertEqual(sender, "sender@example.invalid")
        self.assertEqual(recipients, ["recipient-one@example.invalid",
                                      "recipient-two@example.invalid"])
        self.assertEqual(message.read(), payload)

    def test_bsmtp_ticket_diagnostic_reads_header_and_replays_message_unchanged(self):
        ticket = b"T" * 48
        payload = (b"Received-SPFBL: PASS https://matrix.hadcloud.srv.br/"
                   + ticket + b"\r\nSubject: sample\r\n\r\nbody\r\n")
        bsmtp = io.BytesIO(
            b"MAIL FROM:<sender@example.invalid>\r\n"
            b"RCPT TO:<recipient@example.invalid>\r\n"
            b"DATA\r\n" + payload + b".\r\nQUIT\r\n"
        )
        message, _, _ = scan_client.parse_exim_bsmtp(bsmtp)
        replay, status = scan_client.capture_spfbl_ticket_status(message)
        self.assertEqual("ticket_present", status)
        self.assertEqual(payload, replay.read())

    def test_ticket_diagnostic_does_not_log_or_return_ticket_value(self):
        message = io.BytesIO(b"Subject: ordinary\r\n\r\nbody")
        replay, status = scan_client.capture_spfbl_ticket_status(message)
        self.assertEqual("ticket_missing", status)
        self.assertEqual(b"Subject: ordinary\r\n\r\nbody", replay.read())

    def test_exim_bsmtp_rejects_an_incomplete_envelope(self):
        with self.assertRaises(ValueError):
            scan_client.parse_exim_bsmtp(io.BytesIO(
                b"MAIL FROM:<sender@example.invalid>\nDATA\nbody\n.\n"))

    def test_chunk_decoder_accepts_exact_payload_and_rejects_oversize(self):
        payload = b"Subject: demo\r\n\r\nbody"
        wire = (b"%X\r\n" % len(payload)) + payload + b"\r\n0\r\n\r\n"
        self.assertEqual(bytes(scan_gateway.read_chunked(io.BytesIO(wire), 1024)), payload)
        with self.assertRaises(OverflowError):
            scan_gateway.read_chunked(io.BytesIO(wire), 4)

    def test_content_length_reader_requires_complete_bounded_body(self):
        self.assertEqual(scan_gateway.read_content_length(io.BytesIO(b"hello"), 5, 5), b"hello")
        with self.assertRaises(OverflowError):
            scan_gateway.read_content_length(io.BytesIO(b"hello"), 5, 4)
        with self.assertRaises(ValueError):
            scan_gateway.read_content_length(io.BytesIO(b"hey"), 5, 10)

    def test_monitor_metadata_requires_complete_unauthenticated_smtp_envelope(self):
        metadata = scan_client.normalize_metadata(
            queue_id="1xABC-000000000001-xyz", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="198.51.100.25",
            helo="mx.example.invalid")
        self.assertTrue(metadata["feedback_eligible"])
        self.assertEqual(metadata["queue_id"], "1xABC-000000000001-xyz")
        self.assertEqual(metadata["rcpt"], ["recipient@example.invalid"])

        # An Exim after-queue copy may lack recipients and can still be scored;
        # SPFBL ticket feedback remains gated separately.
        without_rcpt = scan_client.normalize_metadata(
            queue_id="1xABC-000000000001-xyz", sender="sender@example.invalid",
            recipients=[], client_ip="8.8.8.8", helo="mx.example.invalid")
        self.assertTrue(without_rcpt["feedback_eligible"])
        self.assertEqual(without_rcpt["rcpt"], [])
        invalid_rcpt = scan_client.normalize_metadata(
            queue_id="1xABC-000000000001-xyz", sender="sender@example.invalid",
            recipients=["not-an-address"], client_ip="8.8.8.8",
            helo="mx.example.invalid")
        self.assertTrue(invalid_rcpt["feedback_eligible"])
        self.assertEqual(invalid_rcpt["feedback_ineligibility_reason"], "eligible")
        self.assertEqual(
            (None, "recipient_count"),
            spfbl_feedback.feedback_eligibility(
                dict(without_rcpt, feedback_eligible=True),
                {"qualifier": "PASS", "ticket": "T" * 48},
                {"score": 18.0, "required_score": 15.0}, True))

        self.assertFalse(scan_client.normalize_metadata(
            queue_id="-", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="198.51.100.25",
            helo="mx.example.invalid")["feedback_eligible"])
        self.assertFalse(scan_client.normalize_metadata(
            queue_id="QID123", sender="<>", recipients=["recipient@example.invalid"],
            client_ip="198.51.100.25", helo="mx.example.invalid")["feedback_eligible"])
        self.assertFalse(scan_client.normalize_metadata(
            queue_id="QID123", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="198.51.100.25",
            helo="mx.example.invalid", auth_user="mailbox@example.invalid")["feedback_eligible"])
        inbound = scan_client.normalize_metadata(
            queue_id="QID123", sender="sender@example.invalid",
            client_ip="198.51.100.25", helo="mx.example.invalid", received_port="25")
        self.assertTrue(inbound["feedback_eligible"])
        self.assertEqual(inbound["received_port"], 25)
        submission = scan_client.normalize_metadata(
            queue_id="QID123", sender="sender@example.invalid",
            client_ip="198.51.100.25", helo="mx.example.invalid", received_port="587")
        self.assertFalse(submission["feedback_eligible"])
        self.assertEqual(submission["feedback_ineligibility_reason"], "non_inbound_smtp_port")
        missing_exim_port = scan_client.require_received_port_for_bsmtp(
            scan_client.normalize_metadata(
                queue_id="QID123", sender="sender@example.invalid",
                client_ip="198.51.100.25", helo="mx.example.invalid"), True)
        self.assertFalse(missing_exim_port["feedback_eligible"])
        self.assertEqual(missing_exim_port["feedback_ineligibility_reason"],
                         "received_port_missing")
        self.assertTrue(scan_client.require_received_port_for_bsmtp(inbound.copy(), True)[
            "feedback_eligible"])
        self.assertTrue(scan_client.require_received_port_for_bsmtp(
            scan_client.normalize_metadata(
                queue_id="QID123", sender="sender@example.invalid",
                client_ip="198.51.100.25", helo="mx.example.invalid"), False
        )["feedback_eligible"])
        self.assertNotIn("X-SFOX-SMTP-HELO", dict(scan_client.monitor_headers(
            scan_client.normalize_metadata(queue_id="QID123", helo="bad\r\nIP: 127.0.0.1"))))

    def test_spfbl_ticket_header_is_parsed_once_and_removed_before_scoring(self):
        ticket = "T" * 48
        message = (b"From: sender@example.invalid\r\n"
                   b"X-HAD-AntiSpam-Ticket: PASS\r\n"
                   b" " + ticket.encode("ascii") + b"\r\n"
                   b"Subject: keep this\r\n\r\nbody\r\n")
        record, status = scan_client.extract_spfbl_feedback_ticket(message)
        self.assertEqual({"qualifier": "PASS", "ticket": ticket}, record)
        self.assertEqual("ticket_present", status)
        self.assertEqual(
            b"From: sender@example.invalid\r\nSubject: keep this\r\n\r\nbody\r\n",
            scan_client.strip_spfbl_feedback_header(message))

        ambiguous = message.replace(
            b"Subject: keep this", b"X-HAD-AntiSpam-Ticket: NONE\r\nSubject: keep this")
        self.assertEqual((None, "ticket_ambiguous"),
                         scan_client.extract_spfbl_feedback_ticket(ambiguous))

    def test_native_postfix_received_spfbl_ticket_is_read_without_removing_delivery_header(self):
        ticket = "T" * 48
        message = (b"Received-SPFBL: NONE https://matrix.hadcloud.srv.br/"
                   + ticket.encode("ascii") + b"\r\nSubject: keep\r\n\r\nbody")
        self.assertEqual(
            ({"qualifier": "NONE", "ticket": ticket}, "ticket_present"),
            scan_client.extract_spfbl_feedback_ticket(message))
        self.assertEqual(message, scan_client.strip_spfbl_feedback_header(message))
        self.assertNotIn(
            b"Received-SPFBL",
            scan_client.strip_spfbl_feedback_header(message, remove_native=True))

    def test_native_spfbl_fail_ticket_is_preserved_for_content_feedback(self):
        ticket = "F" * 48
        message = (b"Received-SPFBL: FAIL https://matrix.hadcloud.srv.br/pt/"
                   + ticket.encode("ascii") + b"\r\nSubject: sample\r\n\r\nbody")
        self.assertEqual(
            ({"qualifier": "FAIL", "ticket": ticket}, "ticket_present"),
            scan_client.extract_spfbl_feedback_ticket(message))

    def test_spfbl_ticket_stream_filter_handles_chunk_boundaries_and_plain_mail(self):
        ticket = "T" * 48
        source = (b"X-HAD-AntiSpam-Ticket: PASS " + ticket.encode("ascii")
                  + b"\r\nSubject: x\r\n\r\nbody")
        stripper = scan_client.FeedbackHeaderStripper()
        self.assertEqual(b"", stripper.feed(source[:17]))
        output = stripper.feed(source[17:64]) + stripper.feed(source[64:])
        output += stripper.finish()
        self.assertEqual(b"Subject: x\r\n\r\nbody", output)

        plain = scan_client.FeedbackHeaderStripper()
        self.assertEqual(b"", plain.feed(b"Subject: y\r\n"))
        self.assertEqual(b"Subject: y\r\n\r\nbody", plain.feed(b"\r\nbody"))

    def test_spfbl_feedback_requires_opt_in_and_native_confident_spam(self):
        metadata = {
            "feedback_eligible": True,
            "ip": "8.8.8.8",
            "rcpt": ["recipient@example.invalid"],
            "ticket_status_match": True,
        }
        ticket = {"qualifier": "PASS", "ticket": "T" * 48}
        self.assertEqual(("spam", "native_bayes_confident_spam"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"status": "spam", "spam_probability": 0.999}, True))
        fail_ticket = {"qualifier": "FAIL", "ticket": "F" * 48}
        self.assertEqual(("spam", "native_bayes_confident_spam"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, fail_ticket,
                             {"status": "spam", "spam_probability": 0.999}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"status": "spam", "spam_probability": 0.994}, True))
        mismatch = dict(metadata, ticket_status_match=False)
        self.assertEqual((None, "ticket_status_mismatch"),
                         spfbl_feedback.feedback_eligibility(
                             mismatch, ticket,
                             {"status": "spam", "spam_probability": 0.999}, True))
        missing_diagnostic = dict(metadata)
        del missing_diagnostic["ticket_status_match"]
        self.assertEqual((None, "ticket_status_mismatch"),
                         spfbl_feedback.feedback_eligibility(
                             missing_diagnostic, ticket,
                             {"status": "spam", "spam_probability": 0.999}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket, {"status": "ham", "spam_probability": 0.001}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket, {"status": "inconclusive"}, True))
        self.assertEqual((None, "native_bayes_unavailable"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket, {"status": "unavailable"}, True))
        multi = dict(metadata, rcpt=["one@example.invalid", "two@example.invalid"])
        self.assertEqual((None, "recipient_count"),
                         spfbl_feedback.feedback_eligibility(
                             multi, ticket, {"status": "spam", "spam_probability": 0.999}, True))
        self.assertEqual((None, "client_feedback_disabled"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket, {"status": "spam", "spam_probability": 0.999}, False))
        private = dict(metadata, ip="10.1.2.3")
        self.assertEqual((None, "source_ip_not_global"),
                         spfbl_feedback.feedback_eligibility(
                             private, ticket, {"status": "spam", "spam_probability": 0.999}, True))
        bsmtp = dict(metadata, rcpt=[], spfbl_recipient_count=1)
        self.assertEqual(("spam", "native_bayes_confident_spam"),
                         spfbl_feedback.feedback_eligibility(
                             bsmtp, ticket, {"status": "spam", "spam_probability": 0.999}, True))
        bsmtp_multi = dict(metadata, rcpt=["recipient@example.invalid"],
                           spfbl_recipient_count=2)
        self.assertEqual((None, "recipient_count"),
                         spfbl_feedback.feedback_eligibility(
                             bsmtp_multi, ticket, {"status": "spam", "spam_probability": 0.999}, True))

    def test_spfbl_feedback_submits_one_native_spam_command_to_loopback(self):
        class FakeConnection(object):
            def __init__(self):
                self.sent = []

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _value):
                pass

            def sendall(self, value):
                self.sent.append(value)

            def recv(self, _size):
                return b"OK\n"

        connection = FakeConnection()
        targets = []

        def connect(target, timeout):
            targets.append((target, timeout))
            return connection

        self.assertEqual("accepted", spfbl_feedback.submit_spam_ticket(
            "T" * 48, connection_factory=connect))
        self.assertEqual([(("127.0.0.1", 9877), 2.0)], targets)
        self.assertEqual([("SPAM " + "T" * 48 + "\n").encode("ascii")], connection.sent)
        self.assertEqual("target_invalid", spfbl_feedback.submit_spam_ticket(
            "T" * 48, host="matrix.hadcloud.srv.br", connection_factory=connect))

    def test_allowlisted_source_ip_resolves_one_internal_profile(self):
        clients = {"mx-one": {
            "allowed_cidrs": ["198.51.100.16/28"],
            "enabled": True,
        }}
        self.assertEqual("mx-one", scan_gateway.resolve_client(
            clients, "198.51.100.18")[0])
        self.assertIsNone(scan_gateway.resolve_client(
            clients, "198.51.100.40"))

    def test_core_allowlist_admits_monitor_without_a_second_profile(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-allowlist-")
        allowlist = os.path.join(temp_dir, "allowed-cpanels.txt")
        try:
            with open(allowlist, "w") as stream:
                stream.write("198.51.100.26/32 # postfix two\n")
            client_id, profile = scan_gateway.resolve_client(
                {}, "198.51.100.26", allowlist)
            self.assertEqual("allowlist-198-51-100-26", client_id)
            self.assertFalse(profile["spfbl_feedback_enabled"])
            self.assertTrue(profile["native_bayes_enabled"])
            self.assertIsNone(scan_gateway.resolve_client({}, "198.51.100.27", allowlist))
        finally:
            try:
                os.unlink(allowlist)
                os.rmdir(temp_dir)
            except OSError:
                pass

    def test_overlapping_source_ranges_fail_closed_instead_of_choosing_a_profile(self):
        clients = {
            "mx-one": {"allowed_cidrs": ["198.51.100.0/24"]},
            "mx-two": {"allowed_cidrs": ["198.51.100.18/32"]},
        }
        self.assertIsNone(scan_gateway.resolve_client(clients, "198.51.100.18"))

    def test_gateway_queues_chunked_message_then_worker_scans_it(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-")
        config_path = os.path.join(temp_dir, "clients.json")
        with open(config_path, "w") as stream:
            json.dump({"clients": {"mx-one": {
                "allowed_cidrs": ["198.51.100.25/32"],
                "enabled": True,
                "native_bayes_enabled": True,
            }}}, stream)

        scanned = []
        scanned_event = threading.Event()
        logs = []
        clock = [100.0]
        original_read_chunked = scan_gateway.read_chunked

        def simulated_slow_upload(*args):
            payload = original_read_chunked(*args)
            clock[0] += 120.0
            return payload

        def fake_native_scan(body, source_ip):
            scanned.append((bytes(body), source_ip))
            scanned_event.set()
            return {"status": "ham", "spam_probability": 0.001,
                    "known_features": 12}

        with mock.patch.object(spfbl_bayes, "scan_with_core", side_effect=fake_native_scan), \
                mock.patch.object(scan_gateway, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(scan_gateway, "read_chunked", side_effect=simulated_slow_upload), \
                mock.patch.object(scan_gateway, "emit_log", side_effect=lambda event, **fields: logs.append((event, fields))):
            server = scan_gateway.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), scan_gateway.ScanHandler, config_path,
                1024 * 1024, 2, 1, 1)
            server.start_workers()
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.daemon = True
            thread.start()
            try:
                payload = b"From: sender@example.invalid\r\nSubject: synthetic\r\n\r\nbody"
                connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                connection.putrequest("POST", "/v1/scan")
                connection.putheader("Transfer-Encoding", "chunked")
                connection.putheader("Content-Type", "message/rfc822")
                connection.putheader("X-SFOX-Message-ID", "1xTEST-000000000001")
                connection.putheader("X-SFOX-SMTP-Queue-ID", "1xTEST-000000000001")
                connection.putheader("X-SFOX-SMTP-From", "sender@example.invalid")
                connection.putheader("X-SFOX-SMTP-IP", "198.51.100.25")
                connection.putheader("X-SFOX-SMTP-HELO", "mx.example.invalid")
                connection.putheader("X-SFOX-SMTP-Received-Port", "25")
                connection.putheader("X-SFOX-BSMTP-Envelope", "1")
                connection.putheader("X-SFOX-BSMTP-Recipient-Count", "1")
                connection.putheader("X-SFOX-Exim-Recipient-Count", "0")
                connection.putheader("X-SFOX-Client-Ticket-Status", "ticket_present")
                connection.putheader("X-Real-IP", "198.51.100.25")
                connection.endheaders()
                connection.send(("%X\r\n" % len(payload)).encode("ascii") + payload + b"\r\n0\r\n\r\n")
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                self.assertEqual(json.loads(response.read().decode("utf-8")), {"queued": True})
                self.assertTrue(scanned_event.wait(2))
                server.work_queue.join()
                self.assertEqual(scanned[0], (payload, "198.51.100.25"))
                self.assertTrue(any(event == "scan_complete" for event, _ in logs))
                queued = next(fields for event, fields in logs if event == "message_queued")
                complete = next(fields for event, fields in logs if event == "scan_complete")
                self.assertEqual("mx-one", queued["client_id"])
                self.assertEqual(queued["smtp_metadata_fields_present"],
                                 ["queue_id", "sender", "client_ip", "helo", "received_port"])
                self.assertEqual(queued["client_ticket_status"], "ticket_present")
                self.assertEqual(queued["spfbl_ticket_status"], "ticket_missing")
                self.assertFalse(queued["ticket_status_match"])
                self.assertTrue(complete["feedback_metadata_complete"])
                self.assertEqual(complete["client_ticket_status"], "ticket_present")
                self.assertEqual(complete["spfbl_ticket_status"], "ticket_missing")
                self.assertFalse(complete["ticket_status_match"])
                self.assertFalse(complete["spfbl_feedback_enabled"])
                self.assertEqual(0, queued["smtp_recipient_count"])
                self.assertEqual(1, queued["spfbl_feedback_recipient_count"])
                self.assertTrue(queued["bsmtp_envelope"])
                self.assertEqual(1, queued["bsmtp_recipient_count"])
                self.assertEqual(0, queued["exim_env_recipient_count"])
                self.assertEqual(0, complete["smtp_recipient_count"])
                self.assertEqual(1, complete["spfbl_feedback_recipient_count"])
                self.assertEqual(queued["intake_ms"], 120000)
                self.assertEqual(complete["queue_ms"], 0)
                self.assertEqual(complete["timing_version"], 2)
                self.assertNotIn("sender@example.invalid", json.dumps(logs))
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
        try:
            os.unlink(config_path)
            os.rmdir(temp_dir)
        except OSError:
            pass

    def test_gateway_scores_with_native_bayes_and_reports_confident_spam_ticket(self):
        ticket = "T" * 48
        body = (b"From: sender@example.invalid\r\n"
                b"Received-SPFBL: PASS https://matrix.hadcloud.srv.br/" + ticket.encode("ascii")
                + b"\r\nSubject: spam sample\r\n\r\nbody")
        metadata = scan_client.normalize_metadata(
            queue_id="1xTEST-000000000001", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="8.8.8.8",
            helo="mx.example.invalid")
        metadata["feedback_eligible"] = True
        metadata["spfbl_feedback_enabled"] = True
        metadata["native_bayes_enabled"] = True
        metadata["spfbl_ticket"], metadata["spfbl_ticket_status"] = \
            scan_client.extract_spfbl_feedback_ticket(body)
        metadata["ticket_status_match"] = True

        temp_dir = tempfile.mkdtemp(prefix="had-content-feedback-")
        config_path = os.path.join(temp_dir, "clients.json")
        with open(config_path, "w") as stream:
            json.dump({"clients": {}}, stream)
        server = scan_gateway.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), scan_gateway.ScanHandler, config_path,
            1024 * 1024, 1, 1, 1)
        server.pending_slots.acquire()
        server.work_queue.put(("198.51.100.25", "mx-one", "1xTEST-000000000001", bytearray(body),
                               len(body), scan_gateway.monotonic(), metadata))
        server.work_queue.put(None)
        submitted = []
        logs = []

        native_scans = []

        def fake_native_scan(message, source_ip):
            native_scans.append((bytes(message), source_ip))
            return {"status": "spam", "spam_probability": 0.9991,
                    "known_features": 83}

        worker = threading.Thread(target=server._worker)
        with mock.patch.object(spfbl_bayes, "scan_with_core", side_effect=fake_native_scan), \
                mock.patch.object(spfbl_feedback, "submit_spam_ticket",
                                  side_effect=lambda value: submitted.append(value) or "accepted"), \
                mock.patch.object(scan_gateway, "emit_log",
                                  side_effect=lambda event, **fields: logs.append((event, fields))):
            worker.start()
            worker.join(2)
        try:
            self.assertFalse(worker.is_alive())
            self.assertEqual([(scan_client.strip_spfbl_feedback_header(
                body, remove_native=True), "198.51.100.25")], native_scans)
            self.assertEqual([ticket], submitted)
            complete = next(fields for event, fields in logs if event == "scan_complete")
            self.assertEqual("accepted", complete["spfbl_feedback"])
            self.assertEqual("native_bayes_confident_spam",
                             complete["spfbl_feedback_policy"])
            self.assertEqual("spam", complete["native_bayes_status"])
            self.assertEqual(0.9991, complete["native_bayes_spam_probability"])
            self.assertEqual(83, complete["native_bayes_known_features"])
            self.assertNotIn(ticket, json.dumps(logs))
        finally:
            server.server_close()
            os.unlink(config_path)
            os.rmdir(temp_dir)

    def test_gateway_rejects_source_ip_not_in_the_allowlist_before_reading_body(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-")
        config_path = os.path.join(temp_dir, "clients.json")
        with open(config_path, "w") as stream:
            json.dump({"clients": {"mx-one": {
                "allowed_cidrs": ["198.51.100.25/32"], "enabled": True,
            }}}, stream)
        with mock.patch.object(scan_gateway, "emit_log"):
            server = scan_gateway.BoundedThreadingHTTPServer(
                ("127.0.0.1", 0), scan_gateway.ScanHandler, config_path,
                1024, 1, 1, 1)
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
            thread.daemon = True
            thread.start()
            try:
                connection = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=3)
                connection.request("POST", "/v1/scan", body=b"", headers={
                    "X-Real-IP": "198.51.100.26", "Content-Length": "0",
                })
                response = connection.getresponse()
                self.assertEqual(response.status, 403)
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
        try:
            os.unlink(config_path)
            os.rmdir(temp_dir)
        except OSError:
            pass

    def test_gateway_preflight_empty_chunked_post_confirms_allowlisted_source_without_queueing(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-preflight-")
        config_path = os.path.join(temp_dir, "clients.json")
        with open(config_path, "w") as stream:
            json.dump({"clients": {"mx-one": {
                "allowed_cidrs": ["198.51.100.25/32"], "enabled": True,
            }}}, stream)
        server = scan_gateway.BoundedThreadingHTTPServer(
            ("127.0.0.1", 0), scan_gateway.ScanHandler, config_path,
            1024, 1, 1, 1)
        with mock.patch.object(scan_gateway, "emit_log"):
            thread = threading.Thread(target=server.serve_forever,
                                     kwargs={"poll_interval": 0.01})
            thread.daemon = True
            thread.start()
            try:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", server.server_address[1], timeout=3)
                connection.putrequest("POST", "/v1/scan")
                connection.putheader("Transfer-Encoding", "chunked")
                connection.putheader("X-Real-IP", "198.51.100.25")
                connection.endheaders()
                connection.send(b"0\r\n\r\n")
                response = connection.getresponse()
                self.assertEqual(400, response.status)
                self.assertEqual({"error": "invalid_body"}, json.loads(response.read()))
                self.assertEqual(0, server.work_queue.qsize())
                connection.close()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(2)
        os.unlink(config_path)
        os.rmdir(temp_dir)

    def test_client_upload_streams_without_local_body_file(self):
        class Response(object):
            status = 202

            def read(self, limit):
                return b'{"queued":true}'

        class FakeConnection(object):
            def __init__(self):
                self.sent = bytearray()
                self.headers = []
                self.path = None

            def putrequest(self, method, path, **kwargs):
                self.path = path

            def putheader(self, name, value):
                self.headers.append((name, value))

            def endheaders(self):
                pass

            def send(self, value):
                self.sent.extend(value)

            def getresponse(self):
                return Response()

            def close(self):
                pass

        connection = FakeConnection()
        endpoint = scan_client.urlsplit("https://matrix.example.invalid/internal/sfox/scan")
        message = b"Subject: private\r\n\r\nbody"
        with mock.patch.object(scan_client, "_connect", return_value=connection), \
                mock.patch.object(scan_client, "log_event") as log_event:
            result = scan_client.submit(io.BytesIO(message), endpoint,
                                        "1xTEST", 1024, 2, queue_id="1xTEST",
                                        sender="sender@example.invalid",
                                        recipients=["recipient@example.invalid",
                                                    "recipient-two@example.invalid"],
                                        client_ip="198.51.100.25",
                                        helo="mx.example.invalid", bsmtp_envelope=True,
                                        bsmtp_recipient_count=2,
                                        exim_env_recipient_count=1)
        self.assertTrue(result)
        self.assertIn(("Transfer-Encoding", "chunked"), connection.headers)
        self.assertIn(("X-SFOX-SMTP-Queue-ID", "1xTEST"), connection.headers)
        self.assertIn(("X-SFOX-SMTP-From", "sender@example.invalid"), connection.headers)
        self.assertIn(("X-SFOX-SMTP-Rcpt", "recipient@example.invalid"), connection.headers)
        self.assertIn(("X-SFOX-SMTP-Rcpt", "recipient-two@example.invalid"), connection.headers)
        self.assertIn(("X-SFOX-BSMTP-Envelope", "1"), connection.headers)
        self.assertIn(("X-SFOX-BSMTP-Recipient-Count", "2"), connection.headers)
        self.assertIn(("X-SFOX-Exim-Recipient-Count", "1"), connection.headers)
        self.assertIn(("X-SFOX-Client-Ticket-Status", "ticket_missing"),
                      connection.headers)
        self.assertNotIn("X-SFOX-Client", [name for name, _ in connection.headers])
        self.assertNotIn("Authorization", [name for name, _ in connection.headers])
        self.assertEqual(log_event.call_args[0][0], "upload_queued")
        self.assertEqual(log_event.call_args[1]["client_ticket_status"], "ticket_missing")
        self.assertEqual(log_event.call_args[1]["smtp_recipient_count"], 2)
        self.assertTrue(log_event.call_args[1]["bsmtp_envelope"])
        self.assertEqual(log_event.call_args[1]["bsmtp_recipient_count"], 2)
        self.assertEqual(log_event.call_args[1]["exim_env_recipient_count"], 1)
        self.assertNotIn("recipient@example.invalid", repr(log_event.call_args))
        self.assertEqual(bytes(connection.sent),
                         ("%X\r\n" % len(message)).encode("ascii") + message + b"\r\n0\r\n\r\n")

    def test_client_fails_open_when_connection_setup_fails(self):
        endpoint = scan_client.urlsplit("https://matrix.example.invalid/internal/sfox/scan")
        with mock.patch.object(scan_client, "_connect", side_effect=OSError("offline")), \
                mock.patch.object(scan_client, "log_event") as log_event:
            result = scan_client.submit(io.BytesIO(b"message"), endpoint,
                                        "1xTEST", 1024, 2)
        self.assertFalse(result)
        self.assertEqual(log_event.call_args[0][0], "upload_skipped")
        self.assertEqual(log_event.call_args[1]["reason"], "transport_error")

    def test_client_stops_upload_and_drains_oversized_message(self):
        class FakeConnection(object):
            def __init__(self):
                self.sent = bytearray()
                self.closed = False

            def putrequest(self, *args, **kwargs): pass
            def putheader(self, *args): pass
            def endheaders(self): pass
            def send(self, value): self.sent.extend(value)
            def close(self): self.closed = True

        connection = FakeConnection()
        endpoint = scan_client.urlsplit("https://matrix.example.invalid/internal/sfox/scan")
        message = b"x" * (scan_client.CHUNK_SIZE + 32)
        stream = io.BytesIO(message)
        with mock.patch.object(scan_client, "_connect", return_value=connection), \
                mock.patch.object(scan_client, "log_event") as log_event:
            result = scan_client.submit(stream, endpoint, "1xTEST", 1024, 2)
        self.assertFalse(result)
        self.assertTrue(connection.closed)
        self.assertEqual(stream.read(), b"")
        self.assertEqual(log_event.call_args[1]["reason"], "message_too_large")

    def test_client_registry_requires_core_allowlist_and_defaults_to_native_bayes(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-admin-")
        allowlist = os.path.join(temp_dir, "allowlist.txt")
        config = os.path.join(temp_dir, "clients.json")
        with open(allowlist, "w") as stream:
            stream.write("198.51.100.0/24 # primary cPanel\n")
        profile = manage_clients.add_client(config, allowlist, "mx-one", ["198.51.100.25/32"])
        with open(config, "r") as stream:
            written = json.load(stream)
        self.assertEqual(profile, "mx-one")
        self.assertNotIn("token_sha256", written["clients"]["mx-one"])
        self.assertFalse(written["clients"]["mx-one"]["spfbl_feedback_enabled"])
        self.assertTrue(written["clients"]["mx-one"]["native_bayes_enabled"])
        written["clients"]["mx-one"]["autolearn_enabled"] = True
        with open(config, "w") as stream:
            json.dump(written, stream)
        auto_profile = manage_clients.add_client(
            config, allowlist, None, ["198.51.100.26/32"])
        self.assertEqual("ip-198-51-100-26-32", auto_profile)
        with open(config, "r") as stream:
            written = json.load(stream)
        self.assertTrue(written["clients"][auto_profile]["native_bayes_enabled"])
        self.assertNotIn("autolearn_enabled", written["clients"]["mx-one"])
        manage_clients.set_spfbl_feedback(config, auto_profile, True)
        with open(config, "r") as stream:
            self.assertTrue(json.load(stream)["clients"][auto_profile]["spfbl_feedback_enabled"])
        no_learning_profile = manage_clients.add_client(
            config, allowlist, None, ["198.51.100.27/32"])
        manage_clients.set_native_bayes(config, no_learning_profile, False)
        with self.assertRaises(ValueError):
            manage_clients.set_spfbl_feedback(config, no_learning_profile, True)
        manage_clients.set_spfbl_feedback(config, auto_profile, False)
        manage_clients.set_native_bayes(config, auto_profile, True)
        with open(config, "r") as stream:
            self.assertTrue(json.load(stream)["clients"][auto_profile]["native_bayes_enabled"])
        manage_clients.set_native_bayes(config, auto_profile, False)
        with self.assertRaises(ValueError):
            manage_clients.add_client(config, allowlist, "mx-two", ["203.0.113.25/32"])
        with self.assertRaisesRegex(ValueError, "overlaps profile"):
            manage_clients.add_client(config, allowlist, "overlap", ["198.51.100.24/29"])
        manage_clients.disable_client(config, "mx-one")
        with open(config, "r") as stream:
            self.assertFalse(json.load(stream)["clients"]["mx-one"]["enabled"])
        self.assertNotIn("autolearn_enabled", written["clients"]["mx-one"])
        self.assertNotIn("token_sha256", written["clients"]["mx-one"])
        try:
            os.unlink(config)
            os.unlink(allowlist)
            os.rmdir(temp_dir)
        except OSError:
            pass

    def test_native_bayes_scanner_is_loopback_only_and_uses_authenticated_source_ip(self):
        class FakeConnection:
            def __init__(self, response):
                self.response = bytearray(response)
                self.sent = bytearray()
                self.shutdown_how = None

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                pass

            def sendall(self, payload):
                self.sent.extend(payload)

            def shutdown(self, how):
                self.shutdown_how = how

            def recv(self, size):
                chunk = bytes(self.response[:size])
                del self.response[:size]
                return chunk

        payload = b"From: sender@example.invalid\r\nSubject: sample\r\n\r\nbody"
        response = (b"SFOX-BAYES/1.0 0 OK\r\nDecision: SPAM\r\n"
                    b"Spam-Probability: 0.999100\r\nKnown-Features: 83\r\n\r\n")
        connection = FakeConnection(response)
        targets = []

        def connect(target, timeout):
            targets.append((target, timeout))
            return connection

        result = spfbl_bayes.scan_with_core(
            bytearray(payload), "177.39.18.160", connection_factory=connect)
        self.assertEqual({"status": "spam", "spam_probability": 0.9991,
                          "known_features": 83}, result)
        self.assertEqual([(("127.0.0.1", 9877), 2.0)], targets)
        request, body = bytes(connection.sent).split(b"\r\n\r\n", 1)
        self.assertIn(b"Source-IP: 177.39.18.160", request)
        self.assertIn(b"Content-Transfer-Encoding: base64", request)
        self.assertEqual(base64.b64encode(payload), body)
        self.assertEqual(socket.SHUT_WR, connection.shutdown_how)

        self.assertEqual("target_invalid", spfbl_bayes.scan_with_core(
            payload, "177.39.18.160", host="198.51.100.5",
            connection_factory=connect)["status"])
        self.assertEqual("not_allowed", spfbl_bayes.scan_with_core(
            payload, "177.39.18.160",
            connection_factory=lambda *_args, **_kwargs: FakeConnection(
                b"SFOX-BAYES/1.0 77 EX_NOPERM\r\n\r\n"))["status"])

    def test_nginx_allowlist_is_specific_and_rejects_default_route(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-nginx-")
        allowlist = os.path.join(temp_dir, "allowlist.txt")
        with open(allowlist, "w") as stream:
            stream.write("# cPanels\n198.51.100.25/32 # valinor\n2001:db8::5/128 # v6\n")
        rendered = sync_nginx_allowlist.render_allowlist(allowlist)
        self.assertIn("allow 198.51.100.25/32;", rendered)
        self.assertIn("allow 2001:db8::5/128;", rendered)
        self.assertTrue(rendered.endswith("deny all;\n"))
        with open(allowlist, "w") as stream:
            stream.write("0.0.0.0/0\n")
        with self.assertRaises(ValueError):
            sync_nginx_allowlist.render_allowlist(allowlist)
        try:
            os.unlink(allowlist)
            os.rmdir(temp_dir)
        except OSError:
            pass

    def test_nginx_injector_targets_only_matrix_tls_server(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-vhost-")
        vhost = os.path.join(temp_dir, "matrix.conf")
        source = '''http {
  server {
    listen 80;
    server_name matrix.example.test;
  }
  server {
    listen 443 ssl http2;
    server_name matrix.example.test;
    location / { proxy_pass http://127.0.0.1:8080; }
  }
}
'''
        with open(vhost, "w") as stream:
            stream.write(source)
        self.assertTrue(install_nginx_location.inject_include(vhost, "matrix.example.test"))
        with open(vhost, "r") as stream:
            updated = stream.read()
        self.assertEqual(updated.count(install_nginx_location.MARKER), 1)
        self.assertIn("location / { proxy_pass http://127.0.0.1:8080; }", updated)
        self.assertFalse(install_nginx_location.inject_include(vhost, "matrix.example.test"))
        try:
            os.unlink(vhost)
            os.unlink(vhost + ".had-content-scan.bak")
            os.rmdir(temp_dir)
        except OSError:
            pass

    def test_nginx_injector_refuses_incomplete_managed_marker(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-marker-")
        vhost = os.path.join(temp_dir, "matrix.conf")
        with open(vhost, "w") as stream:
            stream.write('server {\n listen 443 ssl;\n server_name matrix.example.test;\n'
                         ' # HAD-SFOX-SCAN-LOCATION\n}\n')
        with self.assertRaises(ValueError):
            install_nginx_location.inject_include(vhost, "matrix.example.test")
        self.assertFalse(os.path.exists(vhost + ".had-content-scan.bak"))
        try:
            os.unlink(vhost)
            os.rmdir(temp_dir)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
