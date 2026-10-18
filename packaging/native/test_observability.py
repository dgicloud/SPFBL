import json
import os
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen
from unittest import mock

import observability


class ObservabilityTests(unittest.TestCase):
    def test_status_uses_core_version_and_release_without_exposing_errors(self):
        with mock.patch.object(observability.control, "unit_state", side_effect=["active", "active"]):
            with mock.patch.object(observability.control, "query_version", return_value="SPFBL-3.0.0"):
                with mock.patch.object(observability, "_release", return_value="1.1.7-test"):
                    status = observability.collect_status()
        self.assertTrue(status["healthy"])
        self.assertEqual("SPFBL-3.0.0", status["version"])
        self.assertEqual("1.1.7-test", status["release"])

    def test_health_fails_when_core_or_admin_query_is_unavailable(self):
        with mock.patch.object(observability.control, "unit_state", side_effect=["inactive", "active"]):
            with mock.patch.object(observability.control, "query_version", side_effect=OSError("private error")):
                with mock.patch.object(observability, "_release", return_value="unknown"):
                    status = observability.collect_status()
        self.assertFalse(status["healthy"])
        self.assertIsNone(status["version"])

    def test_peer_query_failure_does_not_mark_core_unhealthy(self):
        old_cache = (
            observability._peer_stats_cache_checked_at,
            observability._peer_stats_cache_value,
            observability._peer_stats_cache_failed,
        )
        observability._peer_stats_cache_checked_at = None
        observability._peer_stats_cache_value = None
        observability._peer_stats_cache_failed = False
        try:
            with mock.patch.object(observability.control, "unit_state", side_effect=["active", "active"]):
                with mock.patch.object(observability.control, "query_version", return_value="SPFBL-3.0.0"):
                    with mock.patch.object(observability, "_query_peer_stats", side_effect=OSError("private error")):
                        with mock.patch.object(observability, "_release", return_value="1.1.7-test"):
                            status = observability.collect_status(include_peers=True)
        finally:
            (observability._peer_stats_cache_checked_at,
             observability._peer_stats_cache_value,
             observability._peer_stats_cache_failed) = old_cache
        self.assertTrue(status["healthy"])
        self.assertIsNone(status["peer_stats"])

    def test_peer_stats_cache_limits_admin_queries_and_refreshes_after_ttl(self):
        old_cache = (
            observability._peer_stats_cache_checked_at,
            observability._peer_stats_cache_value,
            observability._peer_stats_cache_failed,
        )
        observability._peer_stats_cache_checked_at = None
        observability._peer_stats_cache_value = None
        observability._peer_stats_cache_failed = False
        stats = {"configured_count": 1}
        try:
            with mock.patch.object(observability.time, "monotonic", side_effect=[100.0, 110.0, 131.0]):
                with mock.patch.object(observability, "_query_peer_stats", return_value=stats) as query:
                    self.assertEqual(stats, observability._cached_peer_stats())
                    self.assertEqual(stats, observability._cached_peer_stats())
                    self.assertEqual(stats, observability._cached_peer_stats())
                    self.assertEqual(2, query.call_count)
        finally:
            (observability._peer_stats_cache_checked_at,
             observability._peer_stats_cache_value,
             observability._peer_stats_cache_failed) = old_cache

    def test_peer_stats_failure_cache_avoids_repeated_admin_timeouts(self):
        old_cache = (
            observability._peer_stats_cache_checked_at,
            observability._peer_stats_cache_value,
            observability._peer_stats_cache_failed,
        )
        observability._peer_stats_cache_checked_at = None
        observability._peer_stats_cache_value = None
        observability._peer_stats_cache_failed = False
        try:
            with mock.patch.object(observability.time, "monotonic", side_effect=[100.0, 102.0, 106.0]):
                with mock.patch.object(observability, "_query_peer_stats", side_effect=OSError("private error")) as query:
                    self.assertIsNone(observability._cached_peer_stats())
                    self.assertIsNone(observability._cached_peer_stats())
                    self.assertIsNone(observability._cached_peer_stats())
                    self.assertEqual(2, query.call_count)
        finally:
            (observability._peer_stats_cache_checked_at,
             observability._peer_stats_cache_value,
             observability._peer_stats_cache_failed) = old_cache

    def test_parse_peer_response_summarizes_activity_without_retaining_identity(self):
        response = (
            "matrix.spfbl.net:9877 2.8 REPUTATION REPUTATION ~128ms 0 <peer@example.test>\n"
            "stale.example:9877 2.8 REPUTATION REPUTATION >5min 17 <other@example.test>\n"
            "fast.example:9877 2.8 NEVER REPUTATION <100ms 0\n"
            "dead.example:9877 2.8 REPUTATION REPUTATION DEAD 0\n"
            "new.example:9877 2.8 REPUTATION NEVER UNDEFINED 0\n"
        )
        stats = observability.parse_peer_response(response.encode("iso-8859-1"))
        self.assertEqual(5, stats["configured_count"])
        self.assertEqual(1, stats["recent_activity_count"])
        self.assertEqual(2, stats["stale_activity_count"])
        self.assertEqual(2, stats["unknown_activity_count"])
        self.assertEqual(4, stats["reputation_receive_mode_count"])
        self.assertEqual(17, stats["reputation_max_sum"])
        self.assertEqual(1, stats["reputation_max_positive_count"])
        self.assertNotIn("matrix.spfbl.net", repr(stats))
        self.assertNotIn("peer@example.test", repr(stats))

    def test_parse_empty_and_invalid_peer_responses(self):
        self.assertEqual(0, observability.parse_peer_response(b"EMPTY\n")["configured_count"])
        with self.assertRaises(RuntimeError):
            observability.parse_peer_response(b"not a peer row\n")
        with self.assertRaises(RuntimeError):
            observability.parse_peer_response(b"")

    def test_metrics_expose_bounded_gauges_and_escape_labels(self):
        status = {
            "core": "active", "store_timer": "inactive", "version": 'SPFBL-"3.0"',
            "release": "r\\1\n", "healthy": True,
            "peer_stats": {
                "configured_count": 1, "recent_activity_count": 1,
                "stale_activity_count": 0, "unknown_activity_count": 0,
                "reputation_receive_mode_count": 1, "reputation_max_sum": 0,
                "reputation_max_positive_count": 0,
            },
        }
        with mock.patch.object(observability, "_main_pid", return_value=None):
            rendered = observability.render_metrics(status)
        self.assertIn("spamfox_core_up 1", rendered)
        self.assertIn("spamfox_admin_query_up 1", rendered)
        self.assertIn("spamfox_store_timer_active 0", rendered)
        self.assertIn("spamfox_peer_query_up 1", rendered)
        self.assertIn("spamfox_peer_recent_activity_count 1", rendered)
        self.assertIn("spamfox_peer_reputation_max_sum 0", rendered)
        self.assertIn('version="SPFBL-\\\"3.0\\\""', rendered)
        self.assertIn('release="r\\\\1\\n"', rendered)

    def test_http_routes_health_metrics_and_404(self):
        status = {
            "core": "active", "store_timer": "active", "version": "SPFBL-3.0.0",
            "release": "1.1.7-test", "healthy": True,
        }
        with mock.patch.object(observability, "collect_status", return_value=status):
            with mock.patch.object(observability, "render_metrics", return_value="spamfox_core_up 1\n"):
                server = observability.create_server("127.0.0.1", 0)
                thread = threading.Thread(target=server.serve_forever)
                thread.daemon = True
                thread.start()
                try:
                    base = "http://127.0.0.1:{0}".format(server.server_address[1])
                    with urlopen(base + "/health", timeout=2) as response:
                        self.assertEqual(200, response.status)
                        self.assertEqual("no-store", response.headers["Cache-Control"])
                        self.assertEqual("ok", json.loads(response.read().decode())["status"])
                    with urlopen(base + "/metrics", timeout=2) as response:
                        self.assertIn("spamfox_core_up 1", response.read().decode())
                    with self.assertRaises(HTTPError) as error:
                        urlopen(base + "/", timeout=2)
                    self.assertEqual(404, error.exception.code)
                finally:
                    server.shutdown()
                    server.server_close()
                    thread.join(timeout=2)

    def test_unhealthy_endpoint_returns_503(self):
        status = {
            "core": "inactive", "store_timer": "inactive", "version": None,
            "release": "unknown", "healthy": False,
        }
        with mock.patch.object(observability, "collect_status", return_value=status):
            server = observability.create_server("127.0.0.1", 0)
            thread = threading.Thread(target=server.serve_forever)
            thread.daemon = True
            thread.start()
            try:
                with self.assertRaises(HTTPError) as error:
                    urlopen("http://127.0.0.1:{0}/health".format(server.server_address[1]), timeout=2)
                self.assertEqual(503, error.exception.code)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
