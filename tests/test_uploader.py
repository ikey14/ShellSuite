"""Tests for shellshock.uploader and `shock upload`."""

from __future__ import annotations

import contextlib
import io
import os
import socket
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from shellshock import uploader
from shellsuite import cli


def _start_server(status: int):
    """Start a local HTTP server that records the POST and replies ``status``."""

    class Handler(BaseHTTPRequestHandler):
        received: dict = {}

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            Handler.received = {
                "body": self.rfile.read(length),
                "content_type": self.headers.get("Content-Type", ""),
                "cookie": self.headers.get("Cookie"),
                "x_test": self.headers.get("X-Test"),
            }
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, Handler


def _url(server) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}/upload"


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _ServerTest(unittest.TestCase):
    def start_server(self, status: int):
        server, handler = _start_server(status)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server, handler


class UploaderTests(_ServerTest):
    def test_success_200(self):
        server, handler = self.start_server(200)
        with tempfile.TemporaryDirectory() as tmp:
            shell = Path(tmp) / "shell.php"
            shell.write_text("<?php echo 1;", encoding="utf-8")
            result = uploader.upload(
                shell,
                _url(server),
                field="uploaded",
                form={"Upload": "Upload"},
                cookie="PHPSESSID=abc",
                headers={"X-Test": "yes"},
            )
        self.assertTrue(result.success)
        self.assertEqual(result.status, 200)
        self.assertEqual(result.final_url, _url(server))
        self.assertIn(b'name="uploaded"', handler.received["body"])
        self.assertIn(b'filename="shell.php"', handler.received["body"])
        self.assertIn(b'name="Upload"', handler.received["body"])
        self.assertEqual(handler.received["cookie"], "PHPSESSID=abc")
        self.assertEqual(handler.received["x_test"], "yes")
        self.assertTrue(
            handler.received["content_type"].startswith("multipart/form-data; boundary=")
        )

    def test_failure_500(self):
        server, _ = self.start_server(500)
        with tempfile.TemporaryDirectory() as tmp:
            shell = Path(tmp) / "shell.php"
            shell.write_bytes(b"x")
            result = uploader.upload(shell, _url(server))
        self.assertFalse(result.success)
        self.assertEqual(result.status, 500)

    def test_unreachable_reports_error(self):
        port = _free_port()
        with tempfile.TemporaryDirectory() as tmp:
            shell = Path(tmp) / "shell.php"
            shell.write_bytes(b"x")
            result = uploader.upload(
                shell, f"http://127.0.0.1:{port}/upload", timeout=2
            )
        self.assertFalse(result.success)
        self.assertIsNone(result.status)
        self.assertIsNotNone(result.error)


class UploadCliTests(_ServerTest):
    def test_relative_file_resolves_under_shells_dir_and_succeeds(self):
        server, handler = self.start_server(200)
        with tempfile.TemporaryDirectory() as tmp:
            shells = Path(tmp) / "shells"
            shells.mkdir()
            (shells / "web.php").write_text("<?php", encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = cli.main(
                        ["shock", "upload", "--file", "web.php",
                         "--url", _url(server), "--form", "Upload=Upload"]
                    )
        self.assertEqual(rc, 0, err.getvalue())
        self.assertIn("Upload succeeded (HTTP 200)", out.getvalue())
        self.assertIn(b'name="uploaded"', handler.received["body"])

    def test_missing_file_returns_2(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = cli.main(
                        ["shock", "upload", "--file", "nope.php",
                         "--url", "http://127.0.0.1:1/"]
                    )
        self.assertEqual(rc, 2)
        self.assertIn("webshell not found", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_invalid_form_returns_2(self):
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            shells = Path(tmp) / "shells"
            shells.mkdir()
            (shells / "web.php").write_text("x", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = cli.main(
                        ["shock", "upload", "--file", "web.php",
                         "--url", "http://127.0.0.1:1/", "--form", "bad"]
                    )
        self.assertEqual(rc, 2)
        self.assertIn("invalid --form", err.getvalue())

    def test_failure_status_returns_1(self):
        server, _ = self.start_server(500)
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            shells = Path(tmp) / "shells"
            shells.mkdir()
            (shells / "web.php").write_text("x", encoding="utf-8")
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    rc = cli.main(
                        ["shock", "upload", "--file", "web.php", "--url", _url(server)]
                    )
        self.assertEqual(rc, 1)
        self.assertIn("Upload failed (HTTP 500)", err.getvalue())


if __name__ == "__main__":
    unittest.main()
