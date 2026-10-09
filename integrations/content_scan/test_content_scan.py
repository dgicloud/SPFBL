import hashlib
import base64
import http.client
import io
import math
import json
import os
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
import install_nginx_location
import sync_nginx_allowlist


class ContentScanTests(unittest.TestCase):
    def test_rspamd_safe_summary_extracts_only_valid_bayes_probabilities(self):
        result = scan_gateway._safe_summary(json.dumps({
            "action": "add header",
            "score": 8.0,
            "required_score": 15.0,
            "symbols": {
                "BAYES_SPAM": {"score": 3.2, "options": ["97.50%"]},
                "BAYES_HAM": {"score": -0.8, "options": ["99.99%"]},
                "SUBJ_ALL_CAPS": {"score": 0.5, "options": ["subject"]},
            },
        }).encode("utf-8"))
        self.assertEqual(97.5, result["bayes_spam_probability"])
        self.assertEqual(99.99, result["bayes_ham_probability"])
        self.assertEqual(["BAYES_HAM", "BAYES_SPAM", "SUBJ_ALL_CAPS"], result["symbols"])

        missing = scan_gateway._safe_summary(json.dumps({
            "symbols": {"BAYES_SPAM": {"options": ["101%"]},
                        "BAYES_HAM": {"options": ["private-token"]}},
        }).encode("utf-8"))
        self.assertIsNone(missing["bayes_spam_probability"])
        self.assertIsNone(missing["bayes_ham_probability"])

    def test_client_cli_defaults_match_the_cpanel_collector_install_paths(self):
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(scan_client, "run", return_value=0) as run:
            self.assertEqual(0, scan_client.main([]))

        run.assert_called_once_with(
            "/etc/had-content-scan/client.json",
            "/run/lock/had-content-scan.lock",
            stream=scan_client.sys.stdin.buffer,
            message_id=None, queue_id=None, sender=None, recipients=[],
            client_ip=None, helo=None, auth_user=None, received_port=None,
            bsmtp_envelope=False,
            bsmtp_recipient_count=None, exim_env_recipient_count=0,
        )

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
        self.assertTrue(metadata["autolearn_eligible"])
        self.assertEqual(metadata["queue_id"], "1xABC-000000000001-xyz")
        self.assertEqual(metadata["rcpt"], ["recipient@example.invalid"])

        # An Exim after-queue copy may lack recipients. It is still eligible for
        # message-level Bayes learning; SPFBL feedback remains gated separately.
        without_rcpt = scan_client.normalize_metadata(
            queue_id="1xABC-000000000001-xyz", sender="sender@example.invalid",
            recipients=[], client_ip="8.8.8.8", helo="mx.example.invalid")
        self.assertTrue(without_rcpt["autolearn_eligible"])
        self.assertEqual(without_rcpt["rcpt"], [])
        invalid_rcpt = scan_client.normalize_metadata(
            queue_id="1xABC-000000000001-xyz", sender="sender@example.invalid",
            recipients=["not-an-address"], client_ip="8.8.8.8",
            helo="mx.example.invalid")
        self.assertTrue(invalid_rcpt["autolearn_eligible"])
        self.assertEqual(invalid_rcpt["autolearn_ineligibility_reason"], "eligible")
        self.assertEqual(
            (None, "recipient_count"),
            spfbl_feedback.feedback_eligibility(
                dict(without_rcpt, autolearn=True),
                {"qualifier": "PASS", "ticket": "T" * 48},
                {"score": 18.0, "required_score": 15.0}, True))

        self.assertFalse(scan_client.normalize_metadata(
            queue_id="-", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="198.51.100.25",
            helo="mx.example.invalid")["autolearn_eligible"])
        self.assertFalse(scan_client.normalize_metadata(
            queue_id="QID123", sender="<>", recipients=["recipient@example.invalid"],
            client_ip="198.51.100.25", helo="mx.example.invalid")["autolearn_eligible"])
        self.assertFalse(scan_client.normalize_metadata(
            queue_id="QID123", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="198.51.100.25",
            helo="mx.example.invalid", auth_user="mailbox@example.invalid")["autolearn_eligible"])
        inbound = scan_client.normalize_metadata(
            queue_id="QID123", sender="sender@example.invalid",
            client_ip="198.51.100.25", helo="mx.example.invalid", received_port="25")
        self.assertTrue(inbound["autolearn_eligible"])
        self.assertEqual(inbound["received_port"], 25)
        submission = scan_client.normalize_metadata(
            queue_id="QID123", sender="sender@example.invalid",
            client_ip="198.51.100.25", helo="mx.example.invalid", received_port="587")
        self.assertFalse(submission["autolearn_eligible"])
        self.assertEqual(submission["autolearn_ineligibility_reason"], "non_inbound_smtp_port")
        missing_exim_port = scan_client.require_received_port_for_bsmtp(
            scan_client.normalize_metadata(
                queue_id="QID123", sender="sender@example.invalid",
                client_ip="198.51.100.25", helo="mx.example.invalid"), True)
        self.assertFalse(missing_exim_port["autolearn_eligible"])
        self.assertEqual(missing_exim_port["autolearn_ineligibility_reason"],
                         "received_port_missing")
        self.assertTrue(scan_client.require_received_port_for_bsmtp(inbound.copy(), True)[
            "autolearn_eligible"])
        self.assertTrue(scan_client.require_received_port_for_bsmtp(
            scan_client.normalize_metadata(
                queue_id="QID123", sender="sender@example.invalid",
                client_ip="198.51.100.25", helo="mx.example.invalid"), False
        )["autolearn_eligible"])
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

    def test_spfbl_feedback_requires_opted_in_autolearn_and_confident_spam(self):
        metadata = {
            "autolearn": True,
            "autolearn_eligible": True,
            "ip": "8.8.8.8",
            "rcpt": ["recipient@example.invalid"],
            "ticket_status_match": True,
        }
        ticket = {"qualifier": "PASS", "ticket": "T" * 48}
        self.assertEqual(("spam", "high_confidence_spam"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 18.0, "required_score": 15.0}, True))
        fail_ticket = {"qualifier": "FAIL", "ticket": "F" * 48}
        self.assertEqual(("spam", "high_confidence_spam"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, fail_ticket,
                             {"score": 18.0, "required_score": 15.0}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 14.99, "required_score": 15.0}, True))
        mismatch = dict(metadata, ticket_status_match=False)
        self.assertEqual((None, "ticket_status_mismatch"),
                         spfbl_feedback.feedback_eligibility(
                             mismatch, ticket,
                             {"score": 50.0, "required_score": 15.0}, True))
        missing_diagnostic = dict(metadata)
        del missing_diagnostic["ticket_status_match"]
        self.assertEqual((None, "ticket_status_mismatch"),
                         spfbl_feedback.feedback_eligibility(
                             missing_diagnostic, ticket,
                             {"score": 50.0, "required_score": 15.0}, True))
        self.assertEqual(("spam", "bayes_spam_probability_95"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 8.0, "required_score": 15.0,
                              "action": "add header", "symbols": ["BAYES_SPAM"],
                              "bayes_spam_probability": 95.0}, True))
        self.assertEqual(("spam", "bayes_spam_probability_95"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 4.0, "required_score": 15.0,
                              "action": "greylist", "symbols": ["BAYES_SPAM"],
                              "bayes_spam_probability": 95.0}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 3.99, "required_score": 15.0,
                              "action": "greylist", "symbols": ["BAYES_SPAM"],
                              "bayes_spam_probability": 99.0}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 8.0, "required_score": 15.0,
                              "action": "add header", "symbols": ["BAYES_SPAM"],
                              "bayes_spam_probability": 94.99}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 8.0, "required_score": 15.0,
                              "action": "add header", "symbols": ["BAYES_SPAM"]}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 8.0, "required_score": 15.0,
                              "action": "add header", "symbols": ["BAYES_HAM"]}, True))
        self.assertEqual((None, "below_spam_threshold"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 8.0, "required_score": 15.0,
                              "action": "no action", "symbols": ["BAYES_SPAM"]}, True))
        multi = dict(metadata, rcpt=["one@example.invalid", "two@example.invalid"])
        self.assertEqual((None, "recipient_count"),
                         spfbl_feedback.feedback_eligibility(
                             multi, ticket,
                             {"score": 50.0, "required_score": 15.0}, True))
        self.assertEqual((None, "client_feedback_disabled"),
                         spfbl_feedback.feedback_eligibility(
                             metadata, ticket,
                             {"score": 50.0, "required_score": 15.0}, False))
        private = dict(metadata, ip="10.1.2.3")
        self.assertEqual((None, "source_ip_not_global"),
                         spfbl_feedback.feedback_eligibility(
                             private, ticket,
                             {"score": 50.0, "required_score": 15.0}, True))
        bsmtp = dict(metadata, rcpt=[], spfbl_recipient_count=1)
        self.assertEqual(("spam", "high_confidence_spam"),
                         spfbl_feedback.feedback_eligibility(
                             bsmtp, ticket,
                             {"score": 18.0, "required_score": 15.0}, True))
        bsmtp_multi = dict(metadata, rcpt=["recipient@example.invalid"],
                           spfbl_recipient_count=2)
        self.assertEqual((None, "recipient_count"),
                         spfbl_feedback.feedback_eligibility(
                             bsmtp_multi, ticket,
                             {"score": 50.0, "required_score": 15.0}, True))

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

    def test_client_token_is_bound_to_client_and_source_cidr(self):
        token = "t" * 48
        clients = {"mx-one": {
            "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
            "allowed_cidrs": ["198.51.100.16/28"],
            "enabled": True,
        }}
        self.assertTrue(scan_gateway.validate_client(clients, "mx-one", token, "198.51.100.18"))
        self.assertFalse(scan_gateway.validate_client(clients, "mx-one", token, "198.51.100.40"))
        self.assertFalse(scan_gateway.validate_client(clients, "mx-one", "wrong", "198.51.100.18"))

    def test_gateway_queues_chunked_message_then_worker_scans_it(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-")
        config_path = os.path.join(temp_dir, "clients.json")
        token = "x" * 48
        with open(config_path, "w") as stream:
            json.dump({"clients": {"mx-one": {
                "token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(),
                "allowed_cidrs": ["198.51.100.25/32"],
                "enabled": True, "autolearn_enabled": True,
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

        def fake_scan(body, *args, **kwargs):
            scanned.append((bytes(body), kwargs.get("metadata")))
            scanned_event.set()
            return {"action": "no action", "score": 1.25,
                    "required_score": 15.0, "symbols": ["BAYES_HAM"]}

        with mock.patch.object(scan_gateway, "scan_with_rspamd", side_effect=fake_scan), \
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
                connection.putheader("X-SFOX-Client", "mx-one")
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
                connection.putheader("Authorization", "Bearer " + token)
                connection.endheaders()
                connection.send(("%X\r\n" % len(payload)).encode("ascii") + payload + b"\r\n0\r\n\r\n")
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                self.assertEqual(json.loads(response.read().decode("utf-8")), {"queued": True})
                self.assertTrue(scanned_event.wait(2))
                server.work_queue.join()
                self.assertEqual(scanned[0][0], payload)
                self.assertTrue(scanned[0][1]["autolearn"])
                self.assertEqual(scanned[0][1]["queue_id"], "1xTEST-000000000001")
                self.assertTrue(any(event == "scan_complete" for event, _ in logs))
                queued = next(fields for event, fields in logs if event == "message_queued")
                complete = next(fields for event, fields in logs if event == "scan_complete")
                self.assertEqual(queued["smtp_metadata_fields_present"],
                                 ["queue_id", "sender", "client_ip", "helo", "received_port"])
                self.assertEqual(queued["client_ticket_status"], "ticket_present")
                self.assertEqual(queued["spfbl_ticket_status"], "ticket_missing")
                self.assertFalse(queued["ticket_status_match"])
                self.assertTrue(complete["smtp_metadata_complete"])
                self.assertEqual(complete["client_ticket_status"], "ticket_present")
                self.assertEqual(complete["spfbl_ticket_status"], "ticket_missing")
                self.assertFalse(complete["ticket_status_match"])
                self.assertTrue(complete["autolearn_profile_selected"])
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

    def test_gateway_sends_bayes_spam_ticket_once_after_rspamd_scan(self):
        ticket = "T" * 48
        body = (b"From: sender@example.invalid\r\n"
                b"Received-SPFBL: PASS https://matrix.hadcloud.srv.br/" + ticket.encode("ascii")
                + b"\r\nSubject: spam sample\r\n\r\nbody")
        metadata = scan_client.normalize_metadata(
            queue_id="1xTEST-000000000001", sender="sender@example.invalid",
            recipients=["recipient@example.invalid"], client_ip="8.8.8.8",
            helo="mx.example.invalid")
        metadata["autolearn"] = True
        metadata["spfbl_feedback_enabled"] = True
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
        server.work_queue.put(("mx-one", "1xTEST-000000000001", bytearray(body),
                               len(body), scan_gateway.monotonic(), metadata))
        server.work_queue.put(None)
        scanned = []
        submitted = []
        logs = []

        def fake_scan(message, metadata=None):
            scanned.append((message, metadata))
            return {"action": "greylist", "score": 4.240314,
                    "required_score": 15.0, "symbols": ["BAYES_SPAM"],
                    "bayes_spam_probability": 96.83}

        worker = threading.Thread(target=server._worker)
        with mock.patch.object(scan_gateway, "scan_with_rspamd", side_effect=fake_scan), \
                mock.patch.object(spfbl_feedback, "submit_spam_ticket",
                                  side_effect=lambda value: submitted.append(value) or "accepted"), \
                mock.patch.object(scan_gateway, "emit_log",
                                  side_effect=lambda event, **fields: logs.append((event, fields))):
            worker.start()
            worker.join(2)
        try:
            self.assertFalse(worker.is_alive())
            self.assertEqual(1, len(scanned))
            self.assertNotIn(b"Received-SPFBL", scanned[0][0])
            self.assertEqual([ticket], submitted)
            complete = next(fields for event, fields in logs if event == "scan_complete")
            self.assertEqual("accepted", complete["spfbl_feedback"])
            self.assertEqual("bayes_spam_probability_95",
                             complete["spfbl_feedback_policy"])
            self.assertEqual(96.83, complete["bayes_spam_probability"])
            self.assertNotIn(ticket, json.dumps(logs))
        finally:
            server.server_close()
            os.unlink(config_path)
            os.rmdir(temp_dir)

    def test_gateway_rejects_bad_token_before_reading_body(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-")
        config_path = os.path.join(temp_dir, "clients.json")
        with open(config_path, "w") as stream:
            json.dump({"clients": {}}, stream)
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
                    "X-SFOX-Client": "unknown", "X-Real-IP": "198.51.100.25",
                    "Authorization": "Bearer " + ("x" * 48), "Content-Length": "0",
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

    def test_rspamd_transport_appears_in_native_history_and_returns_only_safe_summary(self):
        observed = {}
        payload = b"Subject: synthetic\r\n\r\nbody"

        class FakeRspamdHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                observed["path"] = self.path
                observed["flags"] = self.headers.get("Flags")
                observed["payload"] = self.rfile.read(int(self.headers["Content-Length"]))
                body = json.dumps({
                    "action": "no action", "score": 0.25, "required_score": 15.0,
                    "symbols": {"BAYES_HAM": {"score": -0.4}},
                    "subject": "must not escape", "from": "private@example.invalid",
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), FakeRspamdHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        try:
            result = scan_gateway.scan_with_rspamd(payload, port=server.server_address[1])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.assertEqual(observed["path"], "/checkv2")
        self.assertIsNone(observed["flags"])
        self.assertEqual(observed["payload"], payload)
        self.assertEqual(result, {"action": "no action", "score": 0.25,
                                  "required_score": 15.0, "symbols": ["BAYES_HAM"],
                                  "bayes_spam_probability": None,
                                  "bayes_ham_probability": None})
        self.assertNotIn("private@example.invalid", json.dumps(result))

    def test_rspamd_transport_passes_only_normalized_metadata_and_explicit_profile(self):
        observed = {}

        class FakeRspamdHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                observed["headers"] = self.headers
                self.rfile.read(int(self.headers["Content-Length"]))
                body = json.dumps({"action": "no action", "score": 0.0,
                                   "required_score": 15.0, "symbols": {}}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, fmt, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), FakeRspamdHandler)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        metadata = {"queue_id": "QID123", "from": "sender@example.invalid",
                    "rcpt": ["recipient@example.invalid"], "ip": "198.51.100.25",
                    "helo": "mx.example.invalid", "autolearn": True}
        try:
            scan_gateway.scan_with_rspamd(b"Subject: test\r\n\r\nbody",
                                          metadata=metadata, port=server.server_address[1])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
        headers = observed["headers"]
        self.assertEqual(headers.get("Queue-Id"), "QID123")
        self.assertEqual(headers.get("From"), "sender@example.invalid")
        self.assertEqual(headers.get_all("Rcpt"), ["recipient@example.invalid"])
        self.assertEqual(headers.get("IP"), "198.51.100.25")
        self.assertEqual(headers.get("Helo"), "mx.example.invalid")
        self.assertEqual(headers.get("Settings-ID"), "spamfox_content_autolearn")

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
            result = scan_client.submit(io.BytesIO(message), endpoint, "mx-one", "t" * 48,
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
            result = scan_client.submit(io.BytesIO(b"message"), endpoint, "mx-one", "t" * 48,
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
            result = scan_client.submit(stream, endpoint, "mx-one", "t" * 48,
                                        "1xTEST", 1024, 2)
        self.assertFalse(result)
        self.assertTrue(connection.closed)
        self.assertEqual(stream.read(), b"")
        self.assertEqual(log_event.call_args[1]["reason"], "message_too_large")

    def test_client_registry_requires_core_allowlist_and_rotates_secret(self):
        temp_dir = tempfile.mkdtemp(prefix="had-content-scan-admin-")
        allowlist = os.path.join(temp_dir, "allowlist.txt")
        config = os.path.join(temp_dir, "clients.json")
        with open(allowlist, "w") as stream:
            stream.write("198.51.100.0/24 # primary cPanel\n")
        token = manage_clients.add_client(config, allowlist, "mx-one", ["198.51.100.25/32"])
        with open(config, "r") as stream:
            written = json.load(stream)
        self.assertNotEqual(written["clients"]["mx-one"]["token_sha256"], token)
        self.assertEqual(len(written["clients"]["mx-one"]["token_sha256"]), 64)
        self.assertFalse(written["clients"]["mx-one"]["autolearn_enabled"])
        self.assertFalse(written["clients"]["mx-one"]["spfbl_feedback_enabled"])
        manage_clients.add_client(config, allowlist, "mx-one-auto",
                                  ["198.51.100.25/32"], autolearn_enabled=True)
        with open(config, "r") as stream:
            self.assertTrue(json.load(stream)["clients"]["mx-one-auto"]["autolearn_enabled"])
        manage_clients.set_spfbl_feedback(config, "mx-one-auto", True)
        with open(config, "r") as stream:
            self.assertTrue(json.load(stream)["clients"]["mx-one-auto"]["spfbl_feedback_enabled"])
        with self.assertRaises(ValueError):
            manage_clients.set_spfbl_feedback(config, "mx-one", True)
        manage_clients.set_spfbl_feedback(config, "mx-one-auto", False)
        with self.assertRaises(ValueError):
            manage_clients.add_client(config, allowlist, "mx-two", ["203.0.113.25/32"])
        manage_clients.disable_client(config, "mx-one")
        with open(config, "r") as stream:
            self.assertFalse(json.load(stream)["clients"]["mx-one"]["enabled"])
        with self.assertRaises(ValueError):
            manage_clients.set_autolearn(config, "mx-one", True)
        manage_clients.set_autolearn(config, "mx-one-auto", False)
        with open(config, "r") as stream:
            saved = json.load(stream)["clients"]
        self.assertFalse(saved["mx-one-auto"]["autolearn_enabled"])
        self.assertEqual(len(saved["mx-one-auto"]["token_sha256"]), 64)
        manage_clients.set_autolearn(config, "mx-one-auto", True)
        with open(config, "r") as stream:
            self.assertTrue(json.load(stream)["clients"]["mx-one-auto"]["autolearn_enabled"])
        try:
            os.unlink(config)
            os.unlink(allowlist)
            os.rmdir(temp_dir)
        except OSError:
            pass

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
    server_name matrix.hadcloud.srv.br;
  }
  server {
    listen 443 ssl http2;
    server_name matrix.hadcloud.srv.br;
    location / { proxy_pass http://127.0.0.1:8080; }
  }
}
'''
        with open(vhost, "w") as stream:
            stream.write(source)
        self.assertTrue(install_nginx_location.inject_include(vhost))
        with open(vhost, "r") as stream:
            updated = stream.read()
        self.assertEqual(updated.count(install_nginx_location.MARKER), 1)
        self.assertIn("location / { proxy_pass http://127.0.0.1:8080; }", updated)
        self.assertFalse(install_nginx_location.inject_include(vhost))
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
            stream.write('server {\n listen 443 ssl;\n server_name matrix.hadcloud.srv.br;\n'
                         ' # HAD-SFOX-SCAN-LOCATION\n}\n')
        with self.assertRaises(ValueError):
            install_nginx_location.inject_include(vhost)
        self.assertFalse(os.path.exists(vhost + ".had-content-scan.bak"))
        try:
            os.unlink(vhost)
            os.rmdir(temp_dir)
        except OSError:
            pass


if __name__ == "__main__":
    unittest.main()
