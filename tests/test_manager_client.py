"""Tests for the Manager client and `shock manage connect`."""

from __future__ import annotations

import contextlib
import hashlib
import io
import socket
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from shellshock.manager import client
from shellsuite import cli, crypto
from shellsuite.protocol import contract, encoding


def _start_shell_server(secret: str):
    """A minimal webshell emulator: decode, verify auth, decrypt, reply framed."""

    class Handler(BaseHTTPRequestHandler):
        def _respond(self):
            cmd_raw, cred_raw = self._read()
            cmd = encoding.decode(cmd_raw)
            cred = encoding.decode(cred_raw)

            mode = "plain"
            if cred_raw:
                mode = "encrypted" if cmd.startswith(contract.ENCRYPTED_PREFIX) else "auth"

            ok = True
            if mode in ("auth", "encrypted"):
                ok = bool(cred) and (
                    hashlib.sha256(cred.encode("utf-8")).hexdigest()
                    == hashlib.sha256(secret.encode("utf-8")).hexdigest()
                )
            if ok and mode == "encrypted":
                try:
                    cmd = crypto.decrypt(cmd, cred)
                except ValueError:
                    ok = False

            if ok and cmd:
                payload = (
                    crypto.encrypt(f"ran:{cmd}", cred)
                    if mode == "encrypted"
                    else f"ran:{cmd}"
                )
                body = contract.RESPONSE_BEGIN + payload + contract.RESPONSE_END
            else:
                body = ""

            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _read(self):
            cookie_header = self.headers.get("Cookie")
            if cookie_header and contract.PARAM_NAMES["cookie"] + "=" in cookie_header:
                jar = {}
                for part in cookie_header.split(";"):
                    part = part.strip()
                    if "=" in part:
                        key, value = part.split("=", 1)
                        jar[key] = value
                return (
                    jar.get(contract.PARAM_NAMES["cookie"], ""),
                    jar.get(contract.AUTH_PARAM_NAMES["cookie"], ""),
                )

            if self.headers.get(contract.PARAM_NAMES["header"]):
                return (
                    self.headers.get(contract.PARAM_NAMES["header"], ""),
                    self.headers.get(contract.AUTH_PARAM_NAMES["header"], ""),
                )

            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length).decode("ascii") if length else ""
            fields = urllib.parse.parse_qs(raw)
            return (
                fields.get(contract.PARAM_NAMES["post"], [""])[0],
                fields.get(contract.AUTH_PARAM_NAMES["post"], [""])[0],
            )

        do_GET = _respond
        do_POST = _respond

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _start_status_server(status: int):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(status)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _url(server) -> str:
    host, port = server.server_address
    return f"http://{host}:{port}/shell.php"


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class _ServerTest(unittest.TestCase):
    def start(self, server):
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def start_shell(self, secret: str = "hunter2"):
        return self.start(_start_shell_server(secret))


class ManagerClientTests(_ServerTest):
    def test_all_vector_mode_combinations(self):
        server = self.start_shell("hunter2")
        command = "cat /etc/passwd; echo 100% + done"
        for vector in contract.VECTORS:
            for mode in contract.MODES:
                secret = None if mode == "plain" else "hunter2"
                shell = client.WebShell(
                    url=_url(server), vector=vector, mode=mode, secret=secret
                )
                result = client.run(shell, command)
                self.assertTrue(result.success, (vector, mode, result.error))
                self.assertEqual(result.output, f"ran:{command}", (vector, mode))

    def test_non_ascii_secret(self):
        server = self.start_shell("ñonga")
        for vector in contract.VECTORS:
            for mode in ("auth", "encrypted"):
                shell = client.WebShell(
                    url=_url(server), vector=vector, mode=mode, secret="ñonga"
                )
                result = client.run(shell, "id")
                self.assertTrue(result.success, (vector, mode, result.error))

    def test_wrong_secret_fails(self):
        server = self.start_shell("hunter2")
        shell = client.WebShell(
            url=_url(server), vector="cookie", mode="encrypted", secret="wrong"
        )
        result = client.run(shell, "id")
        self.assertFalse(result.success)
        self.assertIn("no framed output", result.error or "")

    def test_validate_requires_secret(self):
        for mode in ("auth", "encrypted"):
            shell = client.WebShell(
                url="http://127.0.0.1:1/x", vector="cookie", mode=mode
            )
            with self.assertRaises(ValueError):
                client.run(shell, "id")

    def test_unreachable_reports_error(self):
        port = _free_port()
        shell = client.WebShell(
            url=f"http://127.0.0.1:{port}/x", vector="cookie", mode="plain"
        )
        result = client.run(shell, "id", timeout=2)
        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)

    def test_http_error_reports_status(self):
        server = self.start(_start_status_server(500))
        shell = client.WebShell(url=_url(server), vector="cookie", mode="plain")
        result = client.run(shell, "id")
        self.assertFalse(result.success)
        self.assertEqual(result.status, 500)


class ManagerCliTests(_ServerTest):
    def test_connect_success(self):
        server = self.start_shell("hunter2")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(
                ["shock", "manage", "connect", "--url", _url(server),
                 "--vector", "post", "--mode", "plain"]
            )
        self.assertEqual(rc, 0, err.getvalue())
        self.assertIn("ran:id", out.getvalue())

    def test_connect_missing_secret_returns_2(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(
                ["shock", "manage", "connect", "--url", "http://127.0.0.1:1/x",
                 "--vector", "cookie", "--mode", "encrypted"]
            )
        self.assertEqual(rc, 2)
        self.assertIn("requires a secret", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_connect_failure_returns_1(self):
        server = self.start_shell("hunter2")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(
                ["shock", "manage", "connect", "--url", _url(server),
                 "--vector", "header", "--mode", "auth", "--secret", "wrong"]
            )
        self.assertEqual(rc, 1)
        self.assertIn("connect failed", err.getvalue())


if __name__ == "__main__":
    unittest.main()
