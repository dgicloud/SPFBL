import hashlib
import json
import os
import tempfile
import unittest
from unittest import mock

import learn_reviewed


class FakeResponse(object):
    def __init__(self, status, body=b""):
        self.status = status
        self.body = body

    def read(self, limit):
        return self.body[:limit]


class FakeConnection(object):
    def __init__(self, status=204, body=b""):
        self.status = status
        self.body = body
        self.headers = []
        self.sent = bytearray()
        self.method = None
        self.path = None
        self.closed = False

    def putrequest(self, method, path):
        self.method = method
        self.path = path

    def putheader(self, name, value):
        self.headers.append((name, value))

    def endheaders(self):
        pass

    def send(self, value):
        self.sent.extend(value)

    def getresponse(self):
        return FakeResponse(self.status, self.body)

    def close(self):
        self.closed = True


class FakeStatConnection(object):
    def __init__(self, body, status=200):
        self.body = body
        self.status = status
        self.request_args = None
        self.closed = False

    def request(self, method, path, headers=None):
        self.request_args = (method, path, headers or {})

    def getresponse(self):
        return FakeResponse(self.status, self.body)

    def close(self):
        self.closed = True


class ReviewedLearningTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="had-rspamd-learn-")
        self.message_path = os.path.join(self.temp_dir, "reviewed.eml")
        self.audit_path = os.path.join(self.temp_dir, "learning.jsonl")
        self.message = (b"From: private-sender@example.invalid\r\n"
                        b"To: private-recipient@example.invalid\r\n"
                        b"Subject: private reviewed content\r\n\r\n"
                        b"reviewed body content\r\n")
        with open(self.message_path, "wb") as stream:
            stream.write(self.message)

    def tearDown(self):
        try:
            os.unlink(self.message_path)
            if os.path.exists(self.audit_path):
                os.unlink(self.audit_path)
            os.rmdir(self.temp_dir)
        except OSError:
            pass

    def _run_learning(self, connection, **kwargs):
        audit_records = []
        with mock.patch.object(learn_reviewed, "_read_secret", return_value="s" * 64), \
                mock.patch.object(learn_reviewed, "_append_audit",
                                  side_effect=lambda path, record: audit_records.append(record)), \
                mock.patch.object(learn_reviewed, "_prior_training_state", return_value=None):
            result = learn_reviewed.learn_file(
                "spam", self.message_path, "reviewer1", "CASE-1234", confirmed=True,
                audit_path=self.audit_path,
                connection_factory=lambda *args, **unused: connection,
                **kwargs)
        return result, audit_records

    def test_explicit_review_streams_to_privileged_controller_and_logs_no_message(self):
        connection = FakeConnection(status=204)
        result, audit = self._run_learning(connection)
        self.assertEqual(result["outcome"], "accepted")
        self.assertEqual(connection.method, "POST")
        self.assertEqual(connection.path, "/learnspam")
        self.assertEqual(bytes(connection.sent), self.message)
        self.assertIn(("Password", "s" * 64), connection.headers)
        self.assertTrue(connection.closed)
        self.assertEqual([item["event"] for item in audit], ["learn_attempt", "learn_result"])
        serialized = json.dumps(audit)
        self.assertEqual(audit[0]["message_sha256"], hashlib.sha256(self.message).hexdigest())
        self.assertNotIn("private-sender", serialized)
        self.assertNotIn("private-recipient", serialized)
        self.assertNotIn("private reviewed content", serialized)
        self.assertNotIn("reviewed body content", serialized)
        self.assertNotIn(self.message_path, serialized)
        self.assertNotIn("s" * 64, serialized)

    def test_ham_uses_learnham_endpoint_and_404_duplicate_is_safe(self):
        connection = FakeConnection(status=404, body=b"Message has already learned as ham")
        audit_records = []
        with mock.patch.object(learn_reviewed, "_read_secret", return_value="s" * 64), \
                mock.patch.object(learn_reviewed, "_append_audit",
                                  side_effect=lambda path, record: audit_records.append(record)), \
                mock.patch.object(learn_reviewed, "_prior_training_state", return_value=None):
            result = learn_reviewed.learn_file(
                "ham", self.message_path, "reviewer1", "CASE-1234", confirmed=True,
                audit_path=self.audit_path,
                connection_factory=lambda *args, **unused: connection)
        self.assertEqual(connection.path, "/learnham")
        self.assertEqual(result["outcome"], "already_learned")
        self.assertNotIn("Message has already", json.dumps(audit_records))

    def test_existing_label_requires_explicit_correction_reason(self):
        prior = {"event": "learn_result", "outcome": "accepted", "label": "spam"}
        with mock.patch.object(learn_reviewed, "_read_secret", return_value="s" * 64), \
                mock.patch.object(learn_reviewed, "_prior_training_state", return_value=prior), \
                mock.patch.object(learn_reviewed, "_append_audit") as append, \
                mock.patch.object(learn_reviewed, "_post_to_controller") as post:
            with self.assertRaises(learn_reviewed.LearningError):
                learn_reviewed.learn_file("ham", self.message_path, "reviewer1", "CASE-1234",
                                          confirmed=True, audit_path=self.audit_path)
            self.assertFalse(append.called)
            self.assertFalse(post.called)

    def test_unauthorized_controller_response_is_not_reported_as_learned(self):
        connection = FakeConnection(status=401)
        result, _audit = self._run_learning(connection)
        self.assertEqual(result["outcome"], "rejected_auth")

    def test_unreviewed_and_oversized_samples_are_rejected_before_audit(self):
        with self.assertRaises(learn_reviewed.LearningError):
            learn_reviewed.learn_file("spam", self.message_path, "reviewer1", "CASE-1234",
                                      confirmed=False)
        too_large = os.path.join(self.temp_dir, "large.eml")
        with open(too_large, "wb") as stream:
            stream.write(b"123456")
        try:
            with mock.patch.object(learn_reviewed, "MAX_MESSAGE_BYTES", 5):
                with self.assertRaises(learn_reviewed.LearningError):
                    learn_reviewed._open_reviewed_message(too_large)
        finally:
            os.unlink(too_large)

    def test_stats_exposes_only_scan_and_bayes_counts(self):
        stats = {
            "scanned": 17,
            "learned": 2,
            "total_learns": 2,
            "ham_count": 1,
            "spam_count": 1,
            "statfiles": {
                "BAYES_HAM": {"type": "redis", "total": 10, "used": 8, "size": 4},
                "BAYES_SPAM": {"type": "redis", "total": 12, "used": 9, "size": 5},
            },
        }
        connection = FakeStatConnection(json.dumps(stats).encode("utf-8"))
        with mock.patch.object(learn_reviewed, "_read_secret", return_value="s" * 64):
            lines = learn_reviewed.read_stats(
                connection_factory=lambda *args, **unused: connection)
        self.assertIn("Messages scanned: 17", lines)
        self.assertIn("Messages learned: 2", lines)
        self.assertIn("Messages classified as HAM: 1", lines)
        self.assertTrue(any("BAYES_HAM metrics (not message counts)" in line for line in lines))
        self.assertEqual(connection.request_args[0:2], ("GET", "/stat"))
        self.assertEqual(connection.request_args[2]["Password"], "s" * 64)
        self.assertTrue(connection.closed)
        self.assertFalse(any("sender" in line.lower() or "subject" in line.lower()
                             for line in lines))

    def test_stats_rejects_unauthorized_and_invalid_controller_response(self):
        with mock.patch.object(learn_reviewed, "_read_secret", return_value="s" * 64):
            with self.assertRaises(learn_reviewed.LearningError):
                learn_reviewed.read_stats(connection_factory=lambda *args, **unused:
                                           FakeStatConnection(b"{}", status=401))
            with self.assertRaises(learn_reviewed.LearningError):
                learn_reviewed.read_stats(connection_factory=lambda *args, **unused:
                                           FakeStatConnection(b"not-json"))


if __name__ == "__main__":
    unittest.main()
