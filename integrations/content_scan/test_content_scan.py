import hashlib
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
import install_nginx_location
import sync_nginx_allowlist


class ContentScanTests(unittest.TestCase):
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
                "enabled": True,
            }}}, stream)

        scanned = []
        scanned_event = threading.Event()
        logs = []

        def fake_scan(body, *args, **kwargs):
            scanned.append(bytes(body))
            scanned_event.set()
            return {"action": "no action", "score": 1.25,
                    "required_score": 15.0, "symbols": ["BAYES_HAM"]}

        with mock.patch.object(scan_gateway, "scan_with_rspamd", side_effect=fake_scan), \
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
                connection.putheader("X-Real-IP", "198.51.100.25")
                connection.putheader("Authorization", "Bearer " + token)
                connection.endheaders()
                connection.send(("%X\r\n" % len(payload)).encode("ascii") + payload + b"\r\n0\r\n\r\n")
                response = connection.getresponse()
                self.assertEqual(response.status, 202)
                self.assertEqual(json.loads(response.read().decode("utf-8")), {"queued": True})
                self.assertTrue(scanned_event.wait(2))
                self.assertEqual(scanned, [payload])
                self.assertTrue(any(event == "scan_complete" for event, _ in logs))
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

    def test_rspamd_transport_uses_no_log_and_returns_only_safe_summary(self):
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
        self.assertEqual(observed["flags"], "no_log")
        self.assertEqual(observed["payload"], payload)
        self.assertEqual(result, {"action": "no action", "score": 0.25,
                                  "required_score": 15.0, "symbols": ["BAYES_HAM"]})
        self.assertNotIn("private@example.invalid", json.dumps(result))

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
                mock.patch.object(scan_client, "log_event"):
            result = scan_client.submit(io.BytesIO(message), endpoint, "mx-one", "t" * 48,
                                        "1xTEST", 1024, 2)
        self.assertTrue(result)
        self.assertIn(("Transfer-Encoding", "chunked"), connection.headers)
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
        with self.assertRaises(ValueError):
            manage_clients.add_client(config, allowlist, "mx-two", ["203.0.113.25/32"])
        manage_clients.disable_client(config, "mx-one")
        with open(config, "r") as stream:
            self.assertFalse(json.load(stream)["clients"]["mx-one"]["enabled"])
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
