import importlib.util
import os
import unittest
from unittest import mock


MODULE_PATH = os.path.join(os.path.dirname(__file__), "control.py")
SPEC = importlib.util.spec_from_file_location("had_control", MODULE_PATH)
control = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(control)


class FakeConnection(object):
    def __init__(self, response):
        self.response = response
        self.sent = b""

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def settimeout(self, timeout):
        pass

    def sendall(self, data):
        self.sent += data

    def recv(self, size):
        if isinstance(self.response, Exception):
            raise self.response
        response, self.response = self.response, b""
        return response


class ControlTests(unittest.TestCase):
    def test_status_reports_core_version_release_and_store_timer(self):
        printed = []
        with mock.patch.object(control, "unit_state", side_effect=["active", "active"]):
            with mock.patch.object(control, "query_version", return_value="SPFBL-3.0.0"):
                with mock.patch.object(control, "query_peer_stats", return_value={
                    "configured_count": 1,
                    "recent_activity_count": 1,
                    "stale_activity_count": 0,
                    "unknown_activity_count": 0,
                    "reputation_receive_mode_count": 1,
                    "reputation_max_sum": 0,
                    "reputation_max_positive_count": 0,
                }):
                    with mock.patch.object(control.os.path, "realpath", return_value="/opt/spfbl/releases/1.2.0"):
                        with mock.patch("builtins.print", side_effect=printed.append):
                            result = control.status()
        self.assertEqual(result, 0)
        self.assertIn("  Core service: active", printed)
        self.assertIn("  SPFBL: SPFBL-3.0.0", printed)
        self.assertIn("  Release: 1.2.0", printed)
        self.assertIn("  STORE timer: active", printed)
        self.assertIn(
            "  P2P peers: configured=1 recent=1 stale=0 unknown=0 receive_REPUTATION=1 positive_caps=0",
            printed,
        )

    def test_status_is_nonzero_when_core_is_unavailable(self):
        printed = []
        with mock.patch.object(control, "unit_state", side_effect=["inactive", "active"]):
            with mock.patch.object(control, "query_version", side_effect=OSError("connection refused")):
                with mock.patch.object(control, "query_peer_stats", side_effect=OSError("connection refused")):
                    with mock.patch.object(control.os.path, "realpath", return_value="/opt/spfbl/releases/1.2.0"):
                        with mock.patch("builtins.print", side_effect=printed.append):
                            result = control.status()
        self.assertEqual(result, 1)
        self.assertIn("  SPFBL: unavailable", printed)
        self.assertIn("  Query error: connection refused", printed)

    def test_peer_summary_failure_does_not_hide_core_health(self):
        printed = []
        with mock.patch.object(control, "unit_state", side_effect=["active", "active"]):
            with mock.patch.object(control, "query_version", return_value="SPFBL-3.0.0"):
                with mock.patch.object(control, "query_peer_stats", side_effect=OSError("private details")):
                    with mock.patch.object(control.os.path, "realpath", return_value="/opt/spfbl/releases/1.2.0"):
                        with mock.patch("builtins.print", side_effect=printed.append):
                            result = control.status()
        self.assertEqual(result, 0)
        self.assertIn("  P2P peer summary: unavailable", printed)
        self.assertFalse(any("private details" in line for line in printed))

    def test_peer_parser_keeps_only_aggregate_counts(self):
        stats = control.parse_peer_response(
            b"peer-secret.example:9877 2.8 REPUTATION REPUTATION ~119ms 0\n"
            b"192.0.2.1:9877 2.8 REPUTATION NEVER >2s 64\n"
        )
        self.assertEqual(stats["configured_count"], 2)
        self.assertEqual(stats["recent_activity_count"], 1)
        self.assertEqual(stats["stale_activity_count"], 1)
        self.assertEqual(stats["reputation_receive_mode_count"], 1)
        self.assertEqual(stats["reputation_max_positive_count"], 1)
        self.assertNotIn("peer-secret.example", repr(stats))
        self.assertNotIn("192.0.2.1", repr(stats))

    def test_query_peer_stats_sends_only_read_only_command_and_bounds_response(self):
        connection = FakeConnection(b"peer.example:9877 2.8 REPUTATION REPUTATION ~119ms 0\n")
        with mock.patch.object(control.socket, "create_connection", return_value=connection):
            stats = control.query_peer_stats()
        self.assertEqual(connection.sent, b"PEER SHOW\n")
        self.assertEqual(stats["configured_count"], 1)
        self.assertEqual(stats["reputation_max_positive_count"], 0)

        connection = FakeConnection(b"x" * 2049)
        with mock.patch.object(control.socket, "create_connection", return_value=connection):
            with self.assertRaisesRegex(RuntimeError, "response exceeds limit"):
                control.query_peer_stats(max_response_bytes=2048)

    def test_shutdown_cli_refuses_non_root(self):
        with mock.patch.object(control.os, "geteuid", return_value=1001, create=True):
            with mock.patch("builtins.print") as output:
                self.assertEqual(control.main(["control.py", "shutdown"]), 2)
        self.assertTrue(output.called)

    def test_wait_for_core_exit_polls_systemd_main_pid(self):
        with mock.patch.object(control, "get_main_pid", side_effect=[4242, 0]):
            with mock.patch.object(control.time, "sleep") as sleep:
                control.wait_for_core_exit(4242)
        sleep.assert_called_once_with(0.5)

    def test_wait_for_core_exit_accepts_systemd_main_pid_zero(self):
        with mock.patch.object(control, "get_main_pid", return_value=0):
            with mock.patch.object(control.time, "sleep") as sleep:
                control.wait_for_core_exit(4242)
        sleep.assert_not_called()

    def test_shutdown_waits_for_systemd_main_process_exit(self):
        connection = FakeConnection(b"")
        with mock.patch.object(control.socket, "create_connection", return_value=connection):
            with mock.patch.object(control, "get_main_pid", return_value=4242):
                with mock.patch.object(control, "wait_for_core_exit") as wait:
                    with mock.patch("builtins.print"):
                        control.request("shutdown")
        wait.assert_called_once_with(4242)
        self.assertEqual(b"SHUTDOWN\n", connection.sent)

    def test_shutdown_accepts_success_response_and_waits_for_exit(self):
        connection = FakeConnection(b"OK\n")
        with mock.patch.object(control.socket, "create_connection", return_value=connection):
            with mock.patch.object(control, "get_main_pid", return_value=4242):
                with mock.patch.object(control, "wait_for_core_exit") as wait:
                    with mock.patch("builtins.print"):
                        control.request("shutdown")
        wait.assert_called_once_with(4242)


if __name__ == "__main__":
    unittest.main()
