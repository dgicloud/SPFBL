#!/usr/bin/env python3
"""Loopback-only health and Prometheus metrics for the native SPFBL service."""

from __future__ import print_function

import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from http.server import ThreadingHTTPServer
except ImportError:  # Python 3.6 compatibility for the packaged cPanel/VM tools.
    from socketserver import ThreadingMixIn

    class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True

import control


HOST = "127.0.0.1"
PORT = int(os.environ.get("HAD_ANTISPAM_OBSERVABILITY_PORT", "9911"))
APP = "/opt/spfbl"
CORE_UNIT = "had-antispam-core.service"
STORE_UNIT = "had-antispam-store.timer"
PEER_STATS_CACHE_TTL_SECONDS = 30.0
PEER_STATS_ERROR_CACHE_TTL_SECONDS = 5.0
_peer_stats_cache_lock = threading.Lock()
_peer_stats_cache_checked_at = None
_peer_stats_cache_value = None
_peer_stats_cache_failed = False


def _release():
    return os.path.basename(os.path.realpath(os.path.join(APP, "current"))) or "unknown"


def _main_pid():
    try:
        result = subprocess.run(
            [control.SYSTEMD, "show", "--property=MainPID", "--value", CORE_UNIT],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, universal_newlines=True,
            timeout=2.0,
        )
        if result.returncode == 0:
            value = int(result.stdout.strip())
            return value if value > 0 else None
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return None


def _process_metrics(pid):
    if not pid:
        return {}
    root = "/proc/{0}".format(pid)
    metrics = {}
    try:
        with open(os.path.join(root, "status"), "r") as status_file:
            for line in status_file:
                if line.startswith("VmRSS:"):
                    metrics["had_antispam_core_resident_memory_bytes"] = int(line.split()[1]) * 1024
                    break
        metrics["had_antispam_core_open_fds"] = len(os.listdir(os.path.join(root, "fd")))
        with open(os.path.join(root, "stat"), "r") as stat_file:
            contents = stat_file.read()
        # The process name in /proc/<pid>/stat can contain spaces and parentheses.
        fields = contents[contents.rfind(")") + 2:].split()
        ticks = int(fields[11]) + int(fields[12])  # utime + stime (fields 14 and 15)
        metrics["had_antispam_core_cpu_seconds_total"] = ticks / float(os.sysconf("SC_CLK_TCK"))
    except (IOError, OSError, ValueError, IndexError, KeyError):
        return metrics
    return metrics


parse_peer_response = control.parse_peer_response


def _query_peer_stats():
    return control.query_peer_stats(max_response_bytes=control.MAX_PEER_RESPONSE_BYTES)


def _cached_peer_stats():
    """Limit ADMIN PEER SHOW calls while keeping failures visible in metrics."""
    global _peer_stats_cache_checked_at
    global _peer_stats_cache_value
    global _peer_stats_cache_failed

    with _peer_stats_cache_lock:
        now = time.monotonic()
        if _peer_stats_cache_checked_at is not None:
            ttl = (PEER_STATS_ERROR_CACHE_TTL_SECONDS if _peer_stats_cache_failed
                   else PEER_STATS_CACHE_TTL_SECONDS)
            if now - _peer_stats_cache_checked_at < ttl:
                if _peer_stats_cache_failed:
                    return None
                return dict(_peer_stats_cache_value)

        try:
            stats = _query_peer_stats()
        except (OSError, RuntimeError, socket.error):
            _peer_stats_cache_checked_at = now
            _peer_stats_cache_value = None
            _peer_stats_cache_failed = True
            return None

        _peer_stats_cache_checked_at = now
        _peer_stats_cache_value = dict(stats)
        _peer_stats_cache_failed = False
        return dict(stats)


def collect_status(include_peers=False):
    core_state = control.unit_state(CORE_UNIT)
    timer_state = control.unit_state(STORE_UNIT)
    version = None
    try:
        version = control.query_version()
    except (OSError, RuntimeError, socket.error):
        pass
    status = {
        "core": core_state,
        "store_timer": timer_state,
        "version": version,
        "release": _release(),
        "healthy": core_state == "active" and version is not None,
    }
    if include_peers:
        status["peer_stats"] = _cached_peer_stats()
    return status


def _escape_label(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render_metrics(status=None):
    status = status or collect_status(include_peers=True)
    core_up = status["core"] == "active"
    query_up = status["version"] is not None
    timer_up = status["store_timer"] == "active"
    lines = [
        "# HELP had_antispam_core_up Whether the SPFBL systemd service is active.",
        "# TYPE had_antispam_core_up gauge",
        "had_antispam_core_up {0}".format(int(core_up)),
        "# HELP had_antispam_admin_query_up Whether the local SPFBL ADMIN VERSION query succeeds.",
        "# TYPE had_antispam_admin_query_up gauge",
        "had_antispam_admin_query_up {0}".format(int(query_up)),
        "# HELP had_antispam_store_timer_active Whether the periodic STORE timer is active.",
        "# TYPE had_antispam_store_timer_active gauge",
        "had_antispam_store_timer_active {0}".format(int(timer_up)),
        "# HELP had_antispam_peer_query_up Whether the local SPFBL ADMIN PEER SHOW query succeeds.",
        "# TYPE had_antispam_peer_query_up gauge",
        "had_antispam_peer_query_up {0}".format(int(status.get("peer_stats") is not None)),
        "# HELP had_antispam_build_info Release and upstream core version labels.",
        "# TYPE had_antispam_build_info gauge",
    ]
    labels = 'version="{0}",release="{1}"'.format(
        _escape_label(status["version"] or "unavailable"), _escape_label(status["release"]),
    )
    lines.append("had_antispam_build_info{{{0}}} 1".format(labels))
    peer_stats = status.get("peer_stats")
    if peer_stats is not None:
        peer_metrics = (
            ("configured_count", "Number of peers configured in SPFBL."),
            ("recent_activity_count", "Peers whose SPFBL activity marker is '~'; this is an interval estimate, not a persistent socket."),
            ("stale_activity_count", "Peers whose SPFBL activity marker is '>' or DEAD."),
            ("unknown_activity_count", "Peers whose SPFBL activity marker does not establish freshness."),
            ("reputation_receive_mode_count", "Peers configured with receive mode REPUTATION."),
            ("reputation_max_sum", "Sum of SPFBL per-peer reputation caps calculated from correlation; not a count of decisions using peer data."),
            ("reputation_max_positive_count", "Peers with a positive SPFBL per-peer reputation cap."),
        )
        for suffix, help_text in peer_metrics:
            name = "had_antispam_peer_" + suffix
            lines.append("# HELP {0} {1}".format(name, help_text))
            lines.append("# TYPE {0} gauge".format(name))
            lines.append("{0} {1}".format(name, peer_stats[suffix]))
    for name, value in _process_metrics(_main_pid()).items():
        lines.append("# TYPE {0} gauge".format(name))
        lines.append("{0} {1}".format(name, value))
    return "\n".join(lines) + "\n"


def create_server(host=HOST, port=PORT):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HAD-AntiSpam-Monitor/1"

        def do_GET(self):
            if self.path == "/health":
                status = collect_status()
                body = json.dumps({
                    "status": "ok" if status["healthy"] else "unhealthy",
                    "core": status["core"],
                    "version": status["version"],
                    "release": status["release"],
                    "store_timer": status["store_timer"],
                }, sort_keys=True).encode("utf-8") + b"\n"
                self._respond(200 if status["healthy"] else 503, "application/json; charset=utf-8", body)
            elif self.path == "/metrics":
                status = collect_status(include_peers=True)
                self._respond(200, "text/plain; version=0.0.4; charset=utf-8", render_metrics(status).encode("utf-8"))
            else:
                self._respond(404, "text/plain; charset=utf-8", b"not found\n")

        def _respond(self, code, content_type, body):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format_string, *args):
            return

    return ThreadingHTTPServer((host, port), Handler)


def main():
    server = create_server()
    print("HAD AntiSpam observability listening on {0}:{1}".format(*server.server_address))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
