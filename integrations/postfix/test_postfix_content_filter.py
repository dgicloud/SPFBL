import io
import os
import shutil
import tempfile
import unittest
from unittest import mock

import postfix_content_filter as content_filter


class _Input(object):
    def __init__(self):
        self.data = bytearray()
        self.closed = False

    def write(self, value):
        self.data.extend(value)

    def close(self):
        self.closed = True


class _Process(object):
    def __init__(self, returncode=0):
        self.stdin = _Input()
        self.returncode = returncode
        self.killed = False

    def wait(self):
        return self.returncode

    def kill(self):
        self.killed = True


class _Response(object):
    status = 202

    def read(self, limit):
        return b'{"queued":true}'


class _Connection(object):
    def __init__(self, fail_on_send=False):
        self.headers = []
        self.wire = bytearray()
        self.closed = False
        self.fail_on_send = fail_on_send
        self.send_calls = 0

    def putrequest(self, method, path, **kwargs):
        self.request = (method, path)

    def putheader(self, name, value):
        self.headers.append((name, value))

    def endheaders(self):
        pass

    def send(self, value):
        self.send_calls += 1
        if self.fail_on_send and self.send_calls == 2:
            raise OSError("gateway closed")
        self.wire.extend(value)

    def getresponse(self):
        return _Response()

    def close(self):
        self.closed = True


class PostfixContentFilterTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="had-postfix-content-")
        self.lock_path = os.path.join(self.directory, "scan.lock")
        self.config = (content_filter.scan_client.urlsplit(
            "https://matrix.example.invalid/scan"), "mx-one", "t" * 48, 1024, 2.0)
        self.payload = b"From: private@example.invalid\r\nSubject: private\r\n\r\nbody\r\n"
        self.process = _Process()
        self.command = None
        self.events = []

    def tearDown(self):
        shutil.rmtree(self.directory)

    def _popen(self, command, **kwargs):
        self.command = command
        self.popen_kwargs = kwargs
        return self.process

    def _run(self, connection=None, max_bytes=1024, load_error=None,
             returncode=0, sender="sender@example.invalid", busy_lock_paths=()):
        self.process = _Process(returncode)
        self.events = []
        config = (content_filter.scan_client.urlsplit(
            "https://matrix.example.invalid/scan"), "mx-one", "t" * 48,
                  max_bytes, 2.0)
        loader = mock.Mock(return_value=config)
        if load_error:
            loader.side_effect = load_error
        real_lock_nonblocking = content_filter._lock_nonblocking

        def acquire_unless_busy(lock):
            if lock.name in busy_lock_paths:
                return False
            return real_lock_nonblocking(lock)

        with mock.patch.object(content_filter.scan_client, "load_config", loader), \
                mock.patch.object(content_filter.scan_client, "_connect",
                                  return_value=connection) as connector, \
                mock.patch.object(content_filter, "_emit",
                                  side_effect=lambda event, **fields: self.events.append((event, fields))), \
                mock.patch.object(content_filter, "_lock_nonblocking",
                                  side_effect=acquire_unless_busy):
            result = content_filter.process_message(
                io.BytesIO(self.payload), sender,
                ["recipient@example.invalid"], "QID12345", "/tmp/client.json",
                self.lock_path, popen=self._popen)
        return result, loader, connector

    def test_installed_layout_finds_scan_client_beside_filter(self):
        installed_dir = os.path.join(self.directory, "libexec")
        os.mkdir(installed_dir)
        client_path = os.path.join(installed_dir, "scan_client.py")
        with open(client_path, "wb") as stream:
            stream.write(b"# staged client\n")

        self.assertEqual(content_filter._scan_client_directory(installed_dir),
                         installed_dir)

    def test_source_layout_finds_shared_content_scan_client(self):
        postfix_dir = os.path.join(self.directory, "postfix")
        content_scan_dir = os.path.join(self.directory, "content_scan")
        os.mkdir(postfix_dir)
        os.mkdir(content_scan_dir)
        with open(os.path.join(content_scan_dir, "scan_client.py"), "wb") as stream:
            stream.write(b"# staged client\n")

        self.assertEqual(content_filter._scan_client_directory(postfix_dir),
                         content_scan_dir)

    def test_reinjects_original_and_streams_same_bytes_to_gateway(self):
        connection = _Connection()
        result, _, _ = self._run(connection)

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        self.assertTrue(self.process.stdin.closed)
        self.assertEqual(connection.request, ("POST", "/scan"))
        self.assertIn(("Transfer-Encoding", "chunked"), connection.headers)
        self.assertIn(("X-SFOX-Message-ID", "QID12345"), connection.headers)
        self.assertEqual(bytes(connection.wire),
                         ("%X\r\n" % len(self.payload)).encode("ascii") +
                         self.payload + b"\r\n0\r\n\r\n")
        self.assertEqual(self.command[-1], "recipient@example.invalid")
        self.assertIn("sender@example.invalid", self.command)
        self.assertEqual(self.events[-1][0], "upload_queued")
        self.assertNotIn("sender@example.invalid", repr(self.events))
        self.assertNotIn("recipient@example.invalid", repr(self.events))

    def test_gateway_failure_is_fail_open_for_delivery(self):
        self.process = _Process()
        self.events = []
        with mock.patch.object(content_filter.scan_client, "load_config",
                               return_value=self.config), \
                mock.patch.object(content_filter, "_open_upload",
                                  side_effect=OSError("unavailable")), \
                mock.patch.object(content_filter, "_emit",
                                  side_effect=lambda event, **fields: self.events.append((event, fields))):
            result = content_filter.process_message(
                io.BytesIO(self.payload), "sender@example.invalid",
                ["recipient@example.invalid"], "QID12345", "/tmp/client.json",
                self.lock_path, popen=self._popen)

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        self.assertTrue(any(event == "upload_skipped" for event, _ in self.events))

    def test_oversized_message_is_still_reinjected_unchanged(self):
        connection = _Connection()
        result, _, _ = self._run(connection, max_bytes=8)

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        self.assertTrue(connection.closed)
        self.assertNotIn(b"0\r\n\r\n", bytes(connection.wire))
        self.assertEqual(self.events[-1][1]["reason"], "message_too_large")

    def test_invalid_configuration_does_not_prevent_reinjection(self):
        result, _, connector = self._run(load_error=ValueError("invalid"))

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        connector.assert_not_called()
        self.assertEqual(self.events[0][1]["reason"], "invalid_config")

    def test_failed_sendmail_requeues_original_temporarily(self):
        connection = _Connection()
        result, _, _ = self._run(connection, returncode=67)

        self.assertEqual(result, content_filter.TEMPFAIL)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        self.assertTrue(any(event == "reinject_deferred" for event, _ in self.events))

    def test_null_sender_is_reinjected_as_a_null_reverse_path(self):
        result, _, _ = self._run(sender="")

        self.assertEqual(result, 0)
        sender_flag = self.command.index("-f")
        self.assertEqual(self.command[sender_flag + 1], "<>")

    def test_midstream_gateway_failure_does_not_change_message_bytes(self):
        connection = _Connection(fail_on_send=True)
        result, _, _ = self._run(connection)

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        self.assertTrue(any(event == "upload_skipped" and
                            fields.get("reason") == "transport_error"
                            for event, fields in self.events))

    def test_uses_second_slot_when_first_upload_is_busy(self):
        connection = _Connection()
        result, _, connector = self._run(
            connection, busy_lock_paths=(self.lock_path,))

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        connector.assert_called_once()
        self.assertEqual(self.events[-1][0], "upload_queued")

    def test_delivery_continues_when_both_upload_slots_are_busy(self):
        connection = _Connection()
        second_slot = self.lock_path + ".1"
        result, _, connector = self._run(
            connection, busy_lock_paths=(self.lock_path, second_slot))

        self.assertEqual(result, 0)
        self.assertEqual(bytes(self.process.stdin.data), self.payload)
        connector.assert_not_called()
        self.assertEqual(self.events[-1][1]["reason"], "local_concurrency_limit")


if __name__ == "__main__":
    unittest.main()
