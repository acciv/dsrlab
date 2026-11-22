"""Tests for secret redaction and the local-only HTTP/WebSocket client."""

import contextlib
import io
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from dsrlab import integration, logging as dslog, mockclient

SYNTHETIC_TOKEN = "100000000000000001.ABCDEF." + ("DUMMMY" * 4 + "DDD")
SYNTHETIC_SECRET = "123456:" + ("EXAMPLEKEY" * 4)


def _mock_available() -> bool:
    try:
        return Path(integration.find_mock()).is_file()
    except integration.ToolNotFoundError:
        return False


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        elif self.path == "/rate":
            self.send_response(429)
            self.send_header("Retry-After", "1")
            self.end_headers()
            self.wfile.write(b"slow down")
        else:
            self.send_response(302)
            self.send_header("Location", "http://discord.com/")
            self.end_headers()

    def log_message(self, *_args):
        return


class MockClientTests(unittest.TestCase):
    def test_redact_token_and_generic_secret(self):
        message = f"token={SYNTHETIC_TOKEN} secret={SYNTHETIC_SECRET}"
        cleaned = dslog.redact(message)
        self.assertEqual(cleaned.count("[REDACTED]"), 2)
        self.assertNotIn(SYNTHETIC_TOKEN, cleaned)
        self.assertNotIn(SYNTHETIC_SECRET, cleaned)
        self.assertEqual(dslog.redact("nothing to hide"), "nothing to hide")

    def test_log_writes_redacted_line_to_stderr(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            dslog.log("error", "bad token " + SYNTHETIC_TOKEN)
            dslog.log("info", "all local")
        output = stderr.getvalue()
        self.assertIn("ERROR: bad token [REDACTED]", output)
        self.assertIn("INFO: all local", output)
        self.assertNotIn(SYNTHETIC_TOKEN, output)

    def test_headers_dict_is_case_insensitive(self):
        headers = mockclient.HeadersDict({"Retry-After": "1"})
        self.assertEqual(headers["retry-after"], "1")
        self.assertIn("RETRY-AFTER", headers)
        self.assertEqual(headers.get("X-Missing", "fallback"), "fallback")

    def test_http_request_only_on_loopback_without_following_external_redirects(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            status, headers, text = mockclient.http_request(server.server_port, "/health")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(text), {"ok": True})
            status, headers, _unused = mockclient.http_request(server.server_port, "/rate")
            self.assertEqual(status, 429)
            self.assertEqual(headers["retry-after"], "1")
            with self.assertRaises(ValueError):
                mockclient.http_request(server.server_port, "/redirect")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    @unittest.skipUnless(_mock_available(), "dsmock binary is not built")
    def test_rest_health_endpoint(self):
        process = integration.start_mock()
        try:
            status, _headers, text = mockclient.http_request(process.port, "/health")
        finally:
            process.close()
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(text)["ok"])

    @unittest.skipUnless(_mock_available(), "dsmock binary is not built")
    def test_rest_user_endpoint(self):
        process = integration.start_mock()
        try:
            status, _headers, text = mockclient.http_request(process.port, "/api/v10/users/@me")
        finally:
            process.close()
        self.assertEqual(status, 200)
        self.assertIn("DUMMY", text)

    @unittest.skipUnless(_mock_available(), "dsmock binary is not built")
    def test_rest_rate_limit_headers(self):
        process = integration.start_mock()
        try:
            status, headers, _text = mockclient.http_request(process.port, "/api/v10/rate-limited")
        finally:
            process.close()
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)

    @unittest.skipUnless(_mock_available(), "dsmock binary is not built")
    def test_oauth_mock_endpoint(self):
        process = integration.start_mock()
        try:
            status, _headers, text = mockclient.http_request(
                process.port, "/api/v10/oauth2/token", method="POST", body={}
            )
        finally:
            process.close()
        self.assertEqual(status, 200)
        self.assertIn("DUMMY_ACCESS_TOKEN", text)

    @unittest.skipUnless(_mock_available(), "dsmock binary is not built")
    def test_websocket_gateway_events(self):
        process = integration.start_mock()
        client = mockclient.WebSocketClient(process.port)
        try:
            client.connect()
            hello = client.recv_json(timeout=5)
            self.assertEqual(hello.get("op"), 10)
            client.send_identify()
            seen = set()
            for _ in range(20):
                message = client.recv_json(timeout=5)
                if message.get("t"):
                    seen.add(message["t"])
                if {"READY", "MESSAGE_CREATE"}.issubset(seen):
                    break
            self.assertIn("READY", seen)
            self.assertIn("MESSAGE_CREATE", seen)
            client.send_heartbeat()
            for _ in range(10):
                if client.heartbeat_acks:
                    break
                client.recv_json(timeout=5)
            self.assertGreaterEqual(client.heartbeat_acks, 1)
        finally:
            client.close()
            process.close()


if __name__ == "__main__":
    unittest.main()
