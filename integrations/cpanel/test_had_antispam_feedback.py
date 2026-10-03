import io
import json
import os
import socketserver
import tempfile
import threading
import unittest
from unittest.mock import patch

import had_antispam_feedback
from technical_signals import (
    SignalError,
    ensure_metadata_key,
    format_signal_event,
    load_metadata_key,
    normalize_exim_signals,
    parse_signal_event_line,
    ticket_fingerprint,
)
from had_antispam_feedback import (
    FeedbackError,
    MAX_HEADER_BYTES,
    _audit,
    extract_feedback_record,
    extract_feedback_ticket,
    feedback_ticket_id,
    load_target,
    load_or_create_audit_key,
    main,
    build_feedback_dataset,
    read_feedback_report,
    read_feedback_record,
    read_feedback_ticket,
    serialize_feedback,
    submit_feedback,
    summarize_feedback_log,
)


TICKET = "u2QbRApbumU-hCrf-vhKQd7NInkDRkwlrKnz9WaJBlatLpxXWR8C8Qwbw5LEe4bGz91CMbTzv_2nNS0LQv3C18z9oWgP6t7jr1N0qLmsuEk"


class _FeedbackHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.received = self.rfile.readline(2048)
        self.wfile.write(self.server.reply)


class _FeedbackServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, reply):
        super(_FeedbackServer, self).__init__(("127.0.0.1", 0), _FeedbackHandler)
        self.reply = reply
        self.received = b""
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(timeout=1)


class _TTYInput(io.StringIO):
    def isatty(self):
        return True


class FeedbackTicketTests(unittest.TestCase):
    def test_metadata_key_is_stable_local_and_never_created_by_a_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "signals-hmac.key")
            with self.assertRaisesRegex(SignalError, "signal_key_unavailable"):
                load_metadata_key(path, enforce_root_permissions=False)
            key = ensure_metadata_key(path, enforce_root_permissions=False)
            self.assertEqual(len(key), 32)
            self.assertEqual(key, load_metadata_key(path, enforce_root_permissions=False))
            self.assertEqual(key, ensure_metadata_key(path, enforce_root_permissions=False))

    def test_signal_event_parser_returns_only_allowlisted_values(self):
        key = b"s" * 32
        state = normalize_exim_signals({
            "spf_result": "pass",
            "spfbl_decision": "FLAG",
        })
        event = format_signal_event(TICKET, key, state)
        fingerprint = ticket_fingerprint(TICKET, key)
        parsed = parse_signal_event_line("Oct 03 host " + event)
        self.assertEqual(parsed[0], fingerprint)
        self.assertEqual(parsed[1]["spf"], "pass")
        self.assertEqual(parsed[1]["spfbl"], "flag")
        self.assertIsNone(parse_signal_event_line("Oct 03 host " + event + " sender=private@example.test"))
        self.assertNotIn(TICKET, event)

    def test_reads_only_one_ticket_header_and_ignores_body(self):
        message = (
            b"From: sender@example.test\r\n"
            b"X-HAD-AntiSpam-Ticket: PASS " + TICKET.encode("ascii")
            + b"\r\n\r\nX-HAD-AntiSpam-Ticket: FLAG forged-in-body\r\n"
        )
        self.assertEqual(extract_feedback_ticket(io.BytesIO(message)), TICKET)
        self.assertEqual(
            extract_feedback_record(io.BytesIO(message)),
            ("PASS", TICKET),
        )

    def test_large_message_body_does_not_count_against_header_limit(self):
        message = (
            b"X-HAD-AntiSpam-Ticket: PASS " + TICKET.encode("ascii")
            + b"\r\n\r\n" + b"x" * (MAX_HEADER_BYTES + 1)
        )
        stream = io.BytesIO(message)
        self.assertEqual(extract_feedback_ticket(stream), TICKET)
        self.assertEqual(stream.tell(), message.index(b"\r\n\r\n") + 4)

    def test_accepts_a_folded_header(self):
        message = b"X-HAD-AntiSpam-Ticket: FLAG\r\n " + TICKET.encode("ascii") + b"\r\n\r\n"
        self.assertEqual(extract_feedback_ticket(io.BytesIO(message)), TICKET)

    def test_rejects_missing_duplicate_and_invalid_tickets(self):
        cases = (
            b"From: sender@example.test\r\n\r\nbody\r\n",
            b"X-HAD-AntiSpam-Ticket: PASS " + TICKET.encode("ascii")
            + b"\r\nX-HAD-AntiSpam-Ticket: PASS " + TICKET.encode("ascii") + b"\r\n\r\n",
            b"X-HAD-AntiSpam-Ticket: SPAM " + TICKET.encode("ascii") + b"\r\n\r\n",
            b"X-HAD-AntiSpam-Ticket: PASS not-a-ticket\r\n\r\n",
        )
        for message in cases:
            with self.subTest(message=message[:80]), self.assertRaises(FeedbackError):
                extract_feedback_ticket(io.BytesIO(message))

    def test_header_size_is_bounded(self):
        message = b"X-Long: " + b"x" * 65536
        with self.assertRaisesRegex(FeedbackError, "message_headers_too_large"):
            extract_feedback_ticket(io.BytesIO(message))

    def test_reads_ticket_from_a_regular_message_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            stream.write(
                b"X-HAD-AntiSpam-Ticket: FLAG " + TICKET.encode("ascii") + b"\r\n\r\nbody\r\n"
            )
            path = stream.name
        try:
            self.assertEqual(read_feedback_ticket(path), TICKET)
        finally:
            os.unlink(path)

    def test_reads_anonymous_decision_label_from_message(self):
        with tempfile.NamedTemporaryFile(delete=False) as stream:
            stream.write(
                b"X-HAD-AntiSpam-Ticket: FLAG " + TICKET.encode("ascii") + b"\r\n\r\n"
            )
            path = stream.name
        try:
            self.assertEqual(read_feedback_record(path), ("FLAG", TICKET))
        finally:
            os.unlink(path)

    @unittest.skipUnless(getattr(os, "O_NOFOLLOW", 0), "O_NOFOLLOW is unavailable")
    def test_refuses_a_symbolic_link_as_message_path(self):
        with tempfile.TemporaryDirectory() as directory:
            source = os.path.join(directory, "message.eml")
            link = os.path.join(directory, "linked.eml")
            with open(source, "wb") as stream:
                stream.write(b"X-HAD-AntiSpam-Ticket: PASS " + TICKET.encode("ascii") + b"\r\n\r\n")
            os.symlink(source, link)
            with self.assertRaises(OSError):
                read_feedback_ticket(link)

    def test_serializes_only_explicit_spam_or_ham_commands(self):
        self.assertEqual(serialize_feedback("spam", TICKET), ("SPAM " + TICKET + "\n").encode("ascii"))
        self.assertEqual(serialize_feedback("ham", TICKET), ("HAM " + TICKET + "\n").encode("ascii"))
        with self.assertRaisesRegex(FeedbackError, "feedback_action_invalid"):
            serialize_feedback("block", TICKET)
        with self.assertRaisesRegex(FeedbackError, "feedback_ticket_invalid"):
            serialize_feedback("spam", "ticket injected\nHAM")

    def test_loads_a_root_only_client_endpoint_config(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:
            stream.write("HAD_SPFBL_HOST=151.242.41.35\nHAD_SPFBL_PORT=9877\n")
            path = stream.name
        try:
            if os.name == "posix":
                os.chmod(path, 0o600)
            self.assertEqual(
                load_target(path, enforce_root_permissions=False),
                ("151.242.41.35", 9877),
            )
        finally:
            os.unlink(path)

    def test_rejects_duplicate_or_non_numeric_endpoint_config(self):
        configs = (
            "HAD_SPFBL_HOST=127.0.0.1\nHAD_SPFBL_HOST=127.0.0.2\nHAD_SPFBL_PORT=9877\n",
            "HAD_SPFBL_HOST=matrix.example.test\nHAD_SPFBL_PORT=9877\n",
        )
        for content in configs:
            with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:
                stream.write(content)
                path = stream.name
            try:
                if os.name == "posix":
                    os.chmod(path, 0o600)
                with self.subTest(content=content), self.assertRaises(FeedbackError):
                    load_target(path, enforce_root_permissions=False)
            finally:
                os.unlink(path)

    def test_submits_ticket_once_and_redacts_it_from_result(self):
        server = _FeedbackServer(b"OK {example.test}\n")
        try:
            status = submit_feedback("spam", TICKET, "127.0.0.1", server.server_address[1])
            self.assertEqual(status, "accepted")
            self.assertEqual(server.received, ("SPAM " + TICKET + "\n").encode("ascii"))
            self.assertNotIn(TICKET.encode("ascii"), status.encode("ascii"))
        finally:
            server.close()

    def test_non_successful_core_response_is_sanitized(self):
        server = _FeedbackServer(b"ERROR: DECRYPTION\n")
        try:
            with self.assertRaisesRegex(FeedbackError, "feedback_rejected"):
                submit_feedback("ham", TICKET, "127.0.0.1", server.server_address[1])
        finally:
            server.close()

    def test_audit_logs_decision_action_and_outcome_without_ticket(self):
        class FakeSyslog(object):
            LOG_NOTICE = 5

            def __init__(self):
                self.events = []

            def syslog(self, priority, message):
                self.events.append((priority, message))

        fake_syslog = FakeSyslog()
        with patch.dict("sys.modules", {"syslog": fake_syslog}):
            _audit("spam", "accepted", "FLAG")
        self.assertEqual(
            fake_syslog.events,
            [(5, "had-antispam-feedback decision=FLAG action=spam outcome=accepted")],
        )
        self.assertNotIn(TICKET, fake_syslog.events[0][1])

    def test_audit_logs_only_a_keyed_ticket_fingerprint(self):
        class FakeSyslog(object):
            LOG_NOTICE = 5

            def __init__(self):
                self.events = []

            def syslog(self, priority, message):
                self.events.append((priority, message))

        fingerprint = "a" * 64
        fake_syslog = FakeSyslog()
        with patch.dict("sys.modules", {"syslog": fake_syslog}):
            _audit("spam", "accepted", "FLAG", fingerprint)
        self.assertIn("ticket_id=" + fingerprint, fake_syslog.events[0][1])
        self.assertNotIn(TICKET, fake_syslog.events[0][1])

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
        "the CLI contract test needs root-owned config and audit key files",
    )
    def test_cli_feedback_sends_raw_ticket_to_core_but_audits_only_hmac(self):
        server = _FeedbackServer(b"OK {example.test}\n")
        try:
            with tempfile.TemporaryDirectory() as directory:
                message_path = os.path.join(directory, "message.eml")
                config_path = os.path.join(directory, "client.conf")
                key_path = os.path.join(directory, "feedback-hmac.key")
                with open(message_path, "wb") as stream:
                    stream.write(
                        b"X-HAD-AntiSpam-Ticket: FLAG "
                        + TICKET.encode("ascii")
                        + b"\r\n\r\n"
                    )
                with open(config_path, "w") as stream:
                    stream.write(
                        "HAD_SPFBL_HOST=127.0.0.1\nHAD_SPFBL_PORT={}\n".format(
                            server.server_address[1]
                        )
                    )
                os.chmod(config_path, 0o600)

                class FakeSyslog(object):
                    LOG_NOTICE = 5

                    def __init__(self):
                        self.events = []

                    def syslog(self, priority, message):
                        self.events.append((priority, message))

                fake_syslog = FakeSyslog()
                stdout = io.StringIO()
                stderr = io.StringIO()
                with patch.object(
                    had_antispam_feedback,
                    "load_or_create_audit_key",
                    lambda: load_or_create_audit_key(key_path),
                ):
                    with patch.dict("sys.modules", {"syslog": fake_syslog}):
                        with patch("sys.stdin", _TTYInput("s\n")):
                            with patch("sys.stdout", stdout), patch("sys.stderr", stderr):
                                result = main(
                                    ["spam", message_path, "--config", config_path]
                                )

                self.assertEqual(result, 0)
                self.assertEqual(
                    server.received,
                    ("SPAM " + TICKET + "\n").encode("ascii"),
                )
                self.assertEqual(len(fake_syslog.events), 1)
                audit_message = fake_syslog.events[0][1]
                expected_fingerprint = feedback_ticket_id(
                    TICKET,
                    load_or_create_audit_key(key_path),
                )
                self.assertIn("ticket_id=" + expected_fingerprint, audit_message)
                for output in (stdout.getvalue(), stderr.getvalue(), audit_message):
                    self.assertNotIn(TICKET, output)
        finally:
            server.close()

    def test_local_audit_key_is_private_stable_and_generates_pseudonymous_ticket_id(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "feedback-hmac.key")
            key = load_or_create_audit_key(path, enforce_root_permissions=False)
            second_read = load_or_create_audit_key(path, enforce_root_permissions=False)
            self.assertEqual(len(key), 32)
            self.assertEqual(key, second_read)
            if os.name == "posix":
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
            fingerprint = feedback_ticket_id(TICKET, key)
            self.assertEqual(fingerprint, feedback_ticket_id(TICKET, second_read))
            self.assertEqual(len(fingerprint), 64)
            self.assertNotIn(TICKET, fingerprint)
            self.assertNotEqual(fingerprint, feedback_ticket_id(TICKET, b"x" * 32))

    def test_audit_key_rejects_invalid_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "feedback-hmac.key")
            with open(path, "wb") as stream:
                stream.write(b"short")
            with self.assertRaisesRegex(FeedbackError, "audit_key_invalid"):
                load_or_create_audit_key(path, enforce_root_permissions=False)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0,
        "root-only ownership can be asserted only in a POSIX root test",
    )
    def test_audit_key_enforces_root_owned_private_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "feedback-hmac.key")
            key = load_or_create_audit_key(path)
            info = os.stat(path)
            self.assertEqual(info.st_uid, 0)
            self.assertEqual(info.st_mode & 0o777, 0o600)
            self.assertEqual(len(key), 32)

    def test_report_aggregates_only_confirmed_labels_and_discards_log_data(self):
        secret_ticket = "private-ticket-value"
        lines = (
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=accepted "
            "sender=private@example.test ticket=" + secret_ticket,
            "Oct 02 had-antispam-feedback decision=HOLD action=ham outcome=unchanged "
            "subject=private subject",
            "Oct 02 had-antispam-feedback decision=FLAG action=ham outcome=accepted",
            "Oct 02 had-antispam-feedback decision=PASS action=spam outcome=accepted",
            "Oct 02 had-antispam-feedback decision=PASS action=ham outcome=accepted",
            "Oct 02 had-antispam-feedback decision=NONE action=spam outcome=feedback_timeout_uncertain",
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=untrustedvalue",
            "ordinary mail log sender=private@example.test",
        )
        report = summarize_feedback_log(lines)
        self.assertEqual(report["record_granularity"], "feedback_event")
        self.assertFalse(report["deduplicated_by_ticket"])
        self.assertEqual(report["matched_feedback_events"], 6)
        self.assertEqual(report["core_replied_feedback_events"], 5)
        self.assertEqual(report["core_ok_feedback_events"], 4)
        self.assertEqual(
            report["reviewed_feedback_event_groups"]["suspected"],
            {
                "operator_spam_events": 1,
                "operator_ham_events": 1,
                "core_ok_feedback_events": 2,
                "operator_spam_event_fraction": 1.0 / 2.0,
            },
        )
        self.assertEqual(
            report["reviewed_feedback_event_groups"]["not_flagged"]["operator_spam_events"],
            1,
        )
        self.assertEqual(
            report["reviewed_feedback_event_groups"]["ambiguous"]["core_ok_feedback_events"],
            0,
        )
        self.assertIn("not a reputation counter change or peer delivery", report["interpretation"])
        serialized = str(report)
        self.assertNotIn(secret_ticket, serialized)
        self.assertNotIn("private@example.test", serialized)
        self.assertNotIn("private subject", serialized)

    def test_report_deduplicates_keyed_tickets_and_uses_latest_accepted_label(self):
        ticket_one = "a" * 64
        ticket_two = "b" * 64
        ticket_unchanged = "c" * 64
        lines = (
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=accepted ticket_id=" + ticket_one,
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=accepted ticket_id=" + ticket_one,
            "Oct 02 had-antispam-feedback decision=FLAG action=ham outcome=accepted ticket_id=" + ticket_one,
            "Oct 02 had-antispam-feedback decision=PASS action=spam outcome=accepted ticket_id=" + ticket_two,
            "Oct 02 had-antispam-feedback decision=HOLD action=ham outcome=unchanged ticket_id=" + ticket_unchanged,
        )
        report = summarize_feedback_log(lines)
        self.assertEqual(report["matched_feedback_events"], 5)
        self.assertEqual(report["core_ok_events_with_ticket_id"], 4)
        self.assertEqual(report["unique_tickets_with_core_ok_feedback"], 2)
        self.assertEqual(report["tickets_with_corrected_labels"], 1)
        self.assertEqual(
            report["latest_accepted_ticket_label_groups"]["suspected"],
            {
                "operator_spam_tickets": 0,
                "operator_ham_tickets": 1,
                "unique_labelled_tickets": 1,
                "operator_spam_ticket_fraction": 0.0,
            },
        )
        self.assertEqual(
            report["latest_accepted_ticket_label_groups"]["not_flagged"]["operator_spam_tickets"],
            1,
        )
        self.assertEqual(
            report["latest_accepted_ticket_labels_by_decision"]["FLAG"],
            {"operator_spam_tickets": 0, "operator_ham_tickets": 1},
        )
        self.assertEqual(
            report["latest_accepted_ticket_labels_by_decision"]["PASS"],
            {"operator_spam_tickets": 1, "operator_ham_tickets": 0},
        )
        self.assertEqual(
            report["operator_override_indicators"],
            {
                "flag_or_hold_labelled_ham": 1,
                "pass_or_white_labelled_spam": 1,
            },
        )
        self.assertIn("not false-positive/false-negative rates", report["interpretation"])
        serialized = json.dumps(report)
        self.assertNotIn(ticket_one, serialized)
        self.assertNotIn(ticket_two, serialized)

    def test_report_joins_only_keyed_technical_signals_to_latest_manual_label(self):
        key = b"k" * 32
        signal_id = ticket_fingerprint(TICKET, key)
        root_ticket_id = "f" * 64
        state = normalize_exim_signals({
            "spf_result": "pass",
            "dkim_verify_status": "pass",
            "dmarc_status": "accept",
            "dmarc_alignment_spf": "yes",
            "dmarc_alignment_dkim": "yes",
            "spfbl_decision": "FLAG",
            "rspamd_bucket": "",
            "reverse_dns_valid": "",
            "authenticated_smtp": "false",
            "tls_in_cipher": "true",
        })
        signal_event = format_signal_event(TICKET, key, state)
        lines = (
            "Oct 02 " + signal_event,
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=accepted "
            "ticket_id=" + root_ticket_id + " signal_id=" + signal_id,
            "Oct 02 had-antispam-feedback decision=FLAG action=ham outcome=accepted "
            "ticket_id=" + root_ticket_id + " signal_id=" + signal_id,
        )
        report = summarize_feedback_log(lines)
        self.assertEqual(report["latest_feedback_tickets_with_signal_id"], 1)
        self.assertEqual(report["latest_feedback_tickets_with_signal_snapshot"], 1)
        self.assertEqual(report["latest_feedback_tickets_without_signal_snapshot"], 0)
        self.assertEqual(
            report["operator_labels_by_technical_signal"]["spf"]["pass"],
            {"operator_spam": 0, "operator_ham": 1, "reviewed": 1},
        )
        self.assertEqual(
            report["operator_labels_by_technical_signal"]["spfbl"]["flag"]["operator_ham"],
            1,
        )
        serialized = json.dumps(report)
        for secret in (TICKET, signal_id, root_ticket_id, "sender@example.test", "subject"):
            self.assertNotIn(secret, serialized)

    def test_dataset_contains_only_allowlisted_features_and_latest_accepted_label(self):
        key = b"d" * 32
        signal_id = ticket_fingerprint(TICKET, key)
        root_ticket_id = "e" * 64
        state = normalize_exim_signals({
            "spf_result": "pass",
            "dkim_verify_status": "pass",
            "dmarc_status": "accept",
            "dmarc_alignment_spf": "yes",
            "dmarc_alignment_dkim": "no",
            "spfbl_decision": "FLAG",
            "rspamd_bucket": "",
            "reverse_dns_valid": "",
            "authenticated_smtp": "false",
            "tls_in_cipher": "true",
        })
        lines = (
            "Oct 02 " + format_signal_event(TICKET, key, state),
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=accepted "
            "ticket_id=" + root_ticket_id + " signal_id=" + signal_id +
            " sender=private@example.test subject=private-subject",
            "Oct 02 had-antispam-feedback decision=FLAG action=ham outcome=accepted "
            "ticket_id=" + root_ticket_id + " signal_id=" + signal_id,
            "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=unchanged "
            "ticket_id=" + root_ticket_id + " signal_id=" + signal_id,
            "Oct 02 had-antispam-feedback decision=PASS action=spam outcome=accepted "
            "signal_id=" + "f" * 64,
        )

        rows = build_feedback_dataset(lines)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["label"], "ham")
        self.assertEqual(set(rows[0]["signals"]), {
            "spf", "dkim", "dmarc", "dmarc_alignment_spf",
            "dmarc_alignment_dkim", "spfbl", "rspamd",
            "reverse_dns_valid", "authenticated_smtp", "smtp_tls",
        })
        self.assertEqual(rows[0]["signals"]["spfbl"], "flag")
        serialized = json.dumps(rows, sort_keys=True)
        for secret in (TICKET, signal_id, root_ticket_id, "private@example.test", "private-subject"):
            self.assertNotIn(secret, serialized)

    def test_dataset_cli_emits_local_jsonl_schema_and_rows(self):
        key = b"q" * 32
        signal_id = ticket_fingerprint(TICKET, key)
        state = normalize_exim_signals({
            "spf_result": "",
            "dkim_verify_status": "",
            "dmarc_status": "",
            "dmarc_alignment_spf": "",
            "dmarc_alignment_dkim": "",
            "spfbl_decision": "PASS",
            "rspamd_bucket": "",
            "reverse_dns_valid": "",
            "authenticated_smtp": "true",
            "tls_in_cipher": "",
        })
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:
            stream.write("Oct 02 " + format_signal_event(TICKET, key, state) + "\n")
            stream.write(
                "Oct 02 had-antispam-feedback decision=PASS action=spam outcome=accepted "
                "signal_id=" + signal_id + " sender=secret@example.test\n"
            )
            path = stream.name
        try:
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(main(["dataset", path]), 0)
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(records[0]["type"], "dataset")
            self.assertEqual(records[0]["record_count"], 1)
            self.assertEqual(records[0]["label_counts"], {"ham": 0, "spam": 1})
            self.assertEqual(records[0]["distinct_technical_patterns"], 1)
            self.assertEqual(
                records[0]["signal_coverage"]["spf"],
                {"known_count": 0, "unknown_count": 1, "known_fraction": 0.0},
            )
            self.assertEqual(
                records[0]["signal_coverage"]["spfbl"],
                {"known_count": 1, "unknown_count": 0, "known_fraction": 1.0},
            )
            self.assertEqual(
                records[0]["signal_coverage"]["authenticated_smtp"]["known_count"],
                1,
            )
            self.assertEqual(records[1]["type"], "sample")
            self.assertEqual(records[1]["label"], "spam")
            self.assertNotIn(TICKET, output.getvalue())
            self.assertNotIn(signal_id, output.getvalue())
            self.assertNotIn("secret@example.test", output.getvalue())
        finally:
            os.unlink(path)

    def test_dataset_cli_accepts_journal_input_on_stdin(self):
        key = b"r" * 32
        signal_id = ticket_fingerprint(TICKET, key)
        state = normalize_exim_signals({
            "spf_result": "",
            "dkim_verify_status": "",
            "dmarc_status": "",
            "dmarc_alignment_spf": "",
            "dmarc_alignment_dkim": "",
            "spfbl_decision": "WHITE",
            "rspamd_bucket": "",
            "reverse_dns_valid": "",
            "authenticated_smtp": "false",
            "tls_in_cipher": "false",
        })
        journal = "\n".join((
            "Oct 02 " + format_signal_event(TICKET, key, state),
            "Oct 02 had-antispam-feedback decision=WHITE action=ham outcome=accepted "
            "signal_id=" + signal_id,
        ))
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO(journal)), patch("sys.stdout", output):
            self.assertEqual(main(["dataset", "-"]), 0)
        records = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(records[0]["record_count"], 1)
        self.assertEqual(records[0]["signal_coverage"]["smtp_tls"]["known_count"], 1)
        self.assertEqual(records[1]["label"], "ham")

    def test_report_reads_syslog_and_returns_no_events_without_leaking_lines(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:
            stream.write("private@example.test no feedback here\n")
            path = stream.name
        try:
            report = read_feedback_report(path)
            self.assertEqual(report["matched_feedback_events"], 0)
            self.assertIsNone(
                report["reviewed_feedback_event_groups"]["suspected"]["operator_spam_event_fraction"]
            )
        finally:
            os.unlink(path)

    def test_report_cli_emits_aggregates_only(self):
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as stream:
            stream.write(
                "Oct 02 had-antispam-feedback decision=FLAG action=spam outcome=accepted "
                "sender=secret@example.test ticket=" + TICKET + "\n"
            )
            path = stream.name
        try:
            output = io.StringIO()
            with patch("sys.stdout", output):
                self.assertEqual(main(["report", path]), 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["matched_feedback_events"], 1)
            self.assertNotIn("secret@example.test", output.getvalue())
            self.assertNotIn(TICKET, output.getvalue())
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
