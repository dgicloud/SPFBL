import io
import json
import unittest
from contextlib import redirect_stderr

from postfix_policy import (
    RESPONSE,
    parse_policy_request,
    process_request,
    serve,
)
from spfbl_client import QueryResult, TransportConfig


def policy_request(**overrides):
    values = {
        "request": "smtpd_access_policy",
        "protocol_state": "RCPT",
        "client_address": "192.0.2.25",
        "sender": "sender@example.test",
        "helo_name": "mx.example.test",
        "recipient": "recipient@example.test",
    }
    values.update(overrides)
    return "".join("{0}={1}\n".format(key, value) for key, value in values.items()).encode("utf-8") + b"\n"


class PostfixPolicyTests(unittest.TestCase):
    def setUp(self):
        self.config = TransportConfig(server_ip="127.0.0.1", port=19877)
        self.calls = []

    def fake_query(self, envelope, config):
        self.calls.append((envelope, config))
        return QueryResult("MONITOR", "continue", "decision", "BLOCKED", True, 3)

    def test_rcpt_query_is_mapped_to_dunno_even_when_core_says_blocked(self):
        events = io.StringIO()
        with redirect_stderr(events):
            output = process_request(policy_request(), self.config, self.fake_query)
        self.assertEqual(RESPONSE, output)
        self.assertEqual(1, len(self.calls))
        envelope, config = self.calls[0]
        self.assertEqual("192.0.2.25", envelope.client_ip)
        self.assertEqual("sender@example.test", envelope.mail_from)
        self.assertEqual("mx.example.test", envelope.helo)
        self.assertEqual("recipient@example.test", envelope.rcpt_to)
        self.assertIs(config, self.config)
        event = json.loads(events.getvalue())
        self.assertEqual("MONITOR", event["mode"])
        self.assertEqual("DUNNO", event["action"])
        self.assertEqual("BLOCKED", event["decision"])
        self.assertNotIn("recipient@example.test", events.getvalue())

    def test_null_sender_is_normalized_and_non_rcpt_stages_are_ignored(self):
        with redirect_stderr(io.StringIO()):
            process_request(policy_request(sender="<>"), self.config, self.fake_query)
        self.assertEqual("", self.calls[0][0].mail_from)
        before = len(self.calls)
        with redirect_stderr(io.StringIO()):
            process_request(policy_request(protocol_state="DATA"), self.config, self.fake_query)
        self.assertEqual(before, len(self.calls))

    def test_errors_and_unknown_inputs_fail_open(self):
        for raw in (b"bad\n\n", policy_request(client_address="bad-ip"), b"!oversized-line"):
            with self.subTest(raw=raw):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(RESPONSE, process_request(raw, self.config, self.fake_query))
        self.assertEqual([], self.calls)

    def test_unexpected_client_error_is_still_dunno(self):
        def broken_query(_envelope, _config):
            raise RuntimeError("simulated adapter bug")

        with redirect_stderr(io.StringIO()):
            self.assertEqual(RESPONSE, process_request(policy_request(), self.config, broken_query))

    def test_duplicate_attributes_are_rejected(self):
        raw = policy_request()[:-2] + b"\nclient_address=198.51.100.1\n\n"
        with redirect_stderr(io.StringIO()):
            self.assertEqual(RESPONSE, process_request(raw, self.config, self.fake_query))
        self.assertEqual([], self.calls)

    def test_server_handles_multiple_policy_requests(self):
        source = io.BytesIO(policy_request() + policy_request(recipient="second@example.test"))
        output = io.BytesIO()
        with redirect_stderr(io.StringIO()):
            serve(source, output, self.config, self.fake_query)
        self.assertEqual(RESPONSE + RESPONSE, output.getvalue())
        self.assertEqual(2, len(self.calls))


if __name__ == "__main__":
    unittest.main()
