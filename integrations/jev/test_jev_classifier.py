import json
import unittest

from jev_classifier import (
    AdviceStatus,
    AuthResult,
    BaselineDecision,
    JevBusy,
    JevChoice,
    JevClient,
    JevError,
    RspamdBucket,
    SPFBLResult,
    TechnicalMetadata,
    advise_if_uncertain,
)


class FakeTransport:
    def __init__(self, response=None, error=None):
        self.response = response or {
            "id": "mock-decision-1",
            "model": "typesafe/jev-1.13-test",
            "answers": {
                "classification": {
                    "type": "choice",
                    "choice": "spam",
                    "probabilities": {"ham": 0.04, "spam": 0.91, "review": 0.05},
                    "confidence": 0.86,
                }
            },
            "usage": {"input_tokens": 96, "output_tokens": 8, "cost": 0.000004},
        }
        self.error = error
        self.calls = []

    def post(self, url, headers, body, timeout):
        self.calls.append((url, headers, body, timeout))
        if self.error:
            raise self.error
        return json.dumps(self.response).encode("utf-8")


class JevClassifierTests(unittest.TestCase):
    def setUp(self):
        self.metadata = TechnicalMetadata(
            spf=AuthResult.FAIL,
            dkim=AuthResult.NONE,
            dmarc=AuthResult.FAIL,
            spfbl=SPFBLResult.GREYLIST,
            rspamd=RspamdBucket.BORDERLINE,
            reverse_dns_valid=False,
            authenticated_smtp=False,
            smtp_tls=True,
        )

    def test_confident_local_decision_skips_provider(self):
        transport = FakeTransport()
        client = JevClient("test-key", 0.5, transport=transport)
        result = advise_if_uncertain(
            BaselineDecision.HAM, self.metadata, 0.95, 0.95, client)
        self.assertEqual(AdviceStatus.SKIPPED_CONFIDENT, result.status)
        self.assertEqual(BaselineDecision.HAM, result.effective_decision)
        self.assertEqual([], transport.calls)

    def test_missing_local_confidence_never_triggers_ai(self):
        transport = FakeTransport()
        client = JevClient("test-key", 0.5, transport=transport)
        result = advise_if_uncertain(
            BaselineDecision.REVIEW, self.metadata, None, 0.95, client)
        self.assertEqual(AdviceStatus.SKIPPED_NO_CONFIDENCE, result.status)
        self.assertEqual([], transport.calls)

    def test_uncertain_decision_sends_only_allowlisted_metadata_and_stays_advisory(self):
        transport = FakeTransport()
        client = JevClient("test-key", 0.5, max_in_flight=1, transport=transport)
        result = advise_if_uncertain(
            BaselineDecision.REVIEW, self.metadata, 0.61, 0.95, client)
        self.assertEqual(AdviceStatus.ADVICE, result.status)
        self.assertEqual(BaselineDecision.REVIEW, result.effective_decision)
        self.assertEqual(JevChoice.SPAM, result.advice.choice)
        self.assertEqual(0.86, result.advice.confidence)
        self.assertEqual(96, result.advice.input_tokens)
        self.assertEqual(0.000004, result.advice.cost)
        self.assertEqual(1, len(transport.calls))

        url, headers, body, timeout = transport.calls[0]
        payload = json.loads(body.decode("utf-8"))
        self.assertEqual("https://openrouter.ai/api/alpha/decisions", url)
        self.assertEqual("Bearer test-key", headers["Authorization"])
        self.assertEqual(0.5, timeout)
        state = payload["state"]
        self.assertEqual({"baseline_decision", "local_confidence", "technical_metadata"}, set(state))
        self.assertEqual({
            "spf", "dkim", "dmarc", "spfbl", "rspamd", "dmarc_alignment",
            "reverse_dns_valid", "authenticated_smtp", "smtp_tls",
        }, set(state["technical_metadata"]))
        serialized = body.decode("utf-8").lower()
        for field in ("subject", "body", "sender_email", "recipient_email",
                      "client_ip", "sender_domain"):
            self.assertNotIn(field, serialized)
        self.assertNotIn("@", serialized)
        self.assertNotIn("192.0.2.", serialized)

    def test_unknown_or_personal_metadata_fields_are_rejected(self):
        for field in ("subject", "body", "sender_email", "client_ip", "sender_domain"):
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    TechnicalMetadata.from_mapping({field: "sensitive"})

    def test_invalid_enum_or_boolean_is_rejected(self):
        with self.assertRaises(ValueError):
            TechnicalMetadata.from_mapping({"spf": "probably"})
        with self.assertRaises(ValueError):
            TechnicalMetadata.from_mapping({"smtp_tls": "yes"})

    def test_provider_failure_preserves_the_baseline_decision(self):
        transport = FakeTransport(error=JevError("provider failed"))
        client = JevClient("test-key", 0.5, transport=transport)
        result = advise_if_uncertain(
            BaselineDecision.SPAM, self.metadata, 0.4, 0.95, client)
        self.assertEqual(AdviceStatus.UNAVAILABLE, result.status)
        self.assertEqual(BaselineDecision.SPAM, result.effective_decision)

    def test_concurrency_limit_returns_busy_without_changing_decision(self):
        transport = FakeTransport()
        client = JevClient("test-key", 0.5, max_in_flight=1, transport=transport)
        self.assertTrue(client._slots.acquire(blocking=False))
        try:
            result = advise_if_uncertain(
                BaselineDecision.REVIEW, self.metadata, 0.4, 0.95, client)
        finally:
            client._slots.release()
        self.assertEqual(AdviceStatus.BUSY, result.status)
        self.assertEqual(BaselineDecision.REVIEW, result.effective_decision)
        self.assertEqual([], transport.calls)

    def test_malformed_provider_reply_is_unavailable_not_a_mail_decision(self):
        transport = FakeTransport(response={"answers": {"classification": {"choice": "block"}}})
        client = JevClient("test-key", 0.5, transport=transport)
        result = advise_if_uncertain(
            BaselineDecision.REVIEW, self.metadata, 0.2, 0.95, client)
        self.assertEqual(AdviceStatus.UNAVAILABLE, result.status)
        self.assertEqual(BaselineDecision.REVIEW, result.effective_decision)

    def test_no_client_is_explicitly_not_configured(self):
        result = advise_if_uncertain(
            BaselineDecision.REVIEW, self.metadata, 0.2, 0.95, None)
        self.assertEqual(AdviceStatus.NOT_CONFIGURED, result.status)
        self.assertEqual(BaselineDecision.REVIEW, result.effective_decision)


if __name__ == "__main__":
    unittest.main()
