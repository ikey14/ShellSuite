"""Tests for the Manager client and `shock manage connect`."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import socket
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from shellshock.manager import client, registry, sessions
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


class ManagerRegistryCliTests(_ServerTest):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_connect_registers_shell(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, _out, err = self._run(
                    ["shock", "manage", "connect", "--url", _url(server),
                     "--vector", "post", "--mode", "auth", "--secret", "hunter2",
                     "--name", "web1"]
                )
                self.assertEqual(rc, 0, err)
                store = registry.Registry()
                store.load()
                records = store.all()
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].name, "web1")
                self.assertEqual(records[0].url, _url(server))
                self.assertEqual(records[0].vector, "post")
                self.assertEqual(records[0].mode, "auth")
                self.assertTrue(records[0].has_secret)

    def test_connect_failure_does_not_register(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, _out, err = self._run(
                    ["shock", "manage", "connect", "--url", _url(server),
                     "--vector", "cookie", "--mode", "auth", "--secret", "wrong"]
                )
                self.assertEqual(rc, 1, err)
                store = registry.Registry()
                store.load()
                self.assertEqual(store.all(), [])

    def test_reconnect_updates_without_duplicate(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                for name in (None, "renamed"):
                    argv = ["shock", "manage", "connect", "--url", _url(server),
                            "--vector", "cookie", "--mode", "plain"]
                    if name:
                        argv += ["--name", name]
                    rc, _out, err = self._run(argv)
                    self.assertEqual(rc, 0, err)
                store = registry.Registry()
                store.load()
                self.assertEqual(len(store.all()), 1)
                self.assertEqual(store.all()[0].name, "renamed")

    def test_list_human_and_json(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, _out, err = self._run(
                    ["shock", "manage", "connect", "--url", _url(server),
                     "--vector", "post", "--mode", "plain", "--name", "web1"]
                )
                self.assertEqual(rc, 0, err)

                rc, out, err = self._run(["shock", "manage", "list", "shells"])
                self.assertEqual(rc, 0, err)
                self.assertIn("== web1 ==", out)
                self.assertIn(_url(server), out)

                rc, out, err = self._run(["shock", "manage", "list", "shells", "--json"])
                self.assertEqual(rc, 0, err)
                data = json.loads(out)
                self.assertEqual(data["version"], registry.REGISTRY_VERSION)
                self.assertEqual(data["shells"][0]["name"], "web1")

    def test_list_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, out, err = self._run(["shock", "manage", "list", "shells"])
                self.assertEqual(rc, 0, err)
                self.assertIn("no shells registered", out)

    def test_list_order_and_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                store = registry.Registry()
                store.load()
                store.upsert(
                    url="http://x/a.php", vector="cookie", mode="plain",
                    has_secret=False, name="Alpha",
                    now="2026-01-01T00:00:00+00:00",
                )
                store.upsert(
                    url="http://x/b.php", vector="post", mode="auth",
                    has_secret=True, name="beta",
                    now="2026-01-02T00:00:00+00:00",
                )
                store.save()

                rc, out, err = self._run(
                    ["shock", "manage", "list", "shells", "--filter", "has_secret == true"]
                )
                self.assertEqual(rc, 0, err)
                self.assertIn("== beta ==", out)
                self.assertNotIn("== Alpha ==", out)

    def test_list_invalid_filter_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, _out, err = self._run(
                    ["shock", "manage", "list", "shells", "--filter", "bogus"]
                )
                self.assertEqual(rc, 2)
                self.assertIn("invalid --filter", err)

    def test_list_corrupt_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                (Path(tmp) / "registry.json").write_text("{nope", encoding="utf-8")
                rc, _out, err = self._run(["shock", "manage", "list", "shells"])
                self.assertEqual(rc, 1)
                self.assertIn("cannot read registry", err)

    def _seed(self):
        store = registry.Registry()
        store.load()
        record = store.upsert(
            url="http://x/a.php",
            vector="post",
            mode="plain",
            has_secret=False,
            name="Alpha",
            now="2026-01-01T00:00:00+00:00",
        )
        store.save()
        return record

    def _seed_shell(self, url, vector, mode, has_secret, name="web1"):
        store = registry.Registry()
        store.load()
        record = store.upsert(
            url=url,
            vector=vector,
            mode=mode,
            has_secret=has_secret,
            name=name,
            now="2026-01-01T00:00:00+00:00",
        )
        store.save()
        return record

    def test_edit_changes_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed()
                rc, out, err = self._run(
                    ["shock", "manage", "edit", "shell", record.id, "--name", "Renamed"]
                )
                self.assertEqual(rc, 0, err)
                self.assertIn("updated", out)
                store = registry.Registry()
                store.load()
                self.assertEqual(store.get(record.id).name, "Renamed")

    def test_edit_clears_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed()
                rc, _out, err = self._run(
                    ["shock", "manage", "edit", "shell", record.id, "--name", ""]
                )
                self.assertEqual(rc, 0, err)
                store = registry.Registry()
                store.load()
                self.assertIsNone(store.get(record.id).name)

    def test_edit_clear_name_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed()
                rc, _out, err = self._run(
                    ["shock", "manage", "edit", "shell", record.id, "--clear-name"]
                )
                self.assertEqual(rc, 0, err)
                store = registry.Registry()
                store.load()
                self.assertIsNone(store.get(record.id).name)

    def test_edit_name_and_clear_conflict(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    with self.assertRaises(SystemExit) as caught:
                        cli.main(
                            ["shock", "manage", "edit", "shell", record.id,
                             "--name", "x", "--clear-name"]
                        )
                self.assertNotEqual(caught.exception.code, 0)

    def test_edit_no_fields_returns_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed()
                rc, _out, err = self._run(["shock", "manage", "edit", "shell", record.id])
                self.assertEqual(rc, 2)
                self.assertIn("nothing to edit", err)

    def test_edit_unknown_id_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, _out, err = self._run(
                    ["shock", "manage", "edit", "shell", "missing", "--name", "x"]
                )
                self.assertEqual(rc, 1)
                self.assertIn("no shell with id", err)

    def test_delete_removes_shell(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed()
                rc, out, err = self._run(
                    ["shock", "manage", "delete", "shell", record.id]
                )
                self.assertEqual(rc, 0, err)
                self.assertIn("deleted", out)
                store = registry.Registry()
                store.load()
                self.assertIsNone(store.get(record.id))

    def test_delete_unknown_id_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                rc, _out, err = self._run(
                    ["shock", "manage", "delete", "shell", "missing"]
                )
                self.assertEqual(rc, 1)
                self.assertIn("no shell with id", err)

    def test_terminal_runs_commands_until_exit(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server), "post", "plain", False)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch("sys.stdin", io.StringIO("id\nexit\n")):
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = cli.main(["shock", "manage", "terminal", record.id])
                self.assertEqual(rc, 0, err.getvalue())
                self.assertIn("ran:id", out.getvalue())

    def test_terminal_json_mode(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server), "cookie", "plain", False)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch("sys.stdin", io.StringIO("id\nexit\n")):
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = cli.main(
                            ["shock", "manage", "terminal", record.id, "--json"]
                        )
                self.assertEqual(rc, 0, err.getvalue())
                events = [json.loads(line) for line in out.getvalue().splitlines()]
                self.assertEqual(events[0]["event"], "session")
                self.assertEqual(len(events), 2)
                self.assertEqual(events[1]["command"], "id")
                self.assertTrue(events[1]["success"])
                self.assertIn("ran:id", events[1]["output"])

    def test_terminal_missing_secret_returns_2(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server), "post", "auth", True)
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    rc = cli.main(["shock", "manage", "terminal", record.id])
                self.assertEqual(rc, 2)
                self.assertIn("requires --secret", err.getvalue())

    def test_terminal_wrong_secret_exits_1(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server), "post", "auth", True)
                out, err = io.StringIO(), io.StringIO()
                with mock.patch("sys.stdin", io.StringIO("id\nexit\n")):
                    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                        rc = cli.main(
                            ["shock", "manage", "terminal", record.id,
                             "--secret", "wrong"]
                        )
                self.assertEqual(rc, 1)
                self.assertIn("error:", err.getvalue())

    def test_terminal_unknown_id_returns_1(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                err = io.StringIO()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                    rc = cli.main(["shock", "manage", "terminal", "missing"])
                self.assertEqual(rc, 1)
                self.assertIn("no shell with id", err.getvalue())


class ManagerSessionCliTests(_ServerTest):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def _seed_shell(self, url, vector="post", mode="plain", has_secret=False, name="web1"):
        store = registry.Registry()
        store.load()
        record = store.upsert(
            url=url, vector=vector, mode=mode, has_secret=has_secret,
            name=name, now="2026-01-01T00:00:00+00:00",
        )
        store.save()
        return record

    def _terminal(self, record, lines, extra=()):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdin", io.StringIO(lines)):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                rc = cli.main(["shock", "manage", "terminal", record.id, *extra])
        return rc, out.getvalue(), err.getvalue()

    def test_terminal_records_session_and_lists(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server))
                rc, _out, err = self._terminal(record, "id\nexit\n")
                self.assertEqual(rc, 0, err)

                summaries = sessions.list_sessions()
                self.assertEqual(len(summaries), 1)
                self.assertEqual(summaries[0].status, sessions.STATUS_COMPLETED)
                self.assertEqual(summaries[0].commands, 1)
                self.assertEqual(summaries[0].shell, "web1")

                rc, out, err = self._run(["shock", "manage", "list", "sessions"])
                self.assertEqual(rc, 0, err)
                self.assertIn(summaries[0].id, out)

                rc, out, err = self._run(
                    ["shock", "manage", "list", "sessions", "--json"]
                )
                self.assertEqual(rc, 0, err)
                data = json.loads(out)
                self.assertEqual(data["sessions"][0]["shell"], "web1")

                rc, out, err = self._run(
                    ["shock", "manage", "list", "sessions", "--id", record.id]
                )
                self.assertEqual(rc, 0, err)
                self.assertIn(summaries[0].id, out)

    def test_show_session_and_shell(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server))
                self._terminal(record, "id\nexit\n")
                session_id = sessions.list_sessions()[0].id

                rc, out, err = self._run(
                    ["shock", "manage", "show", "session", "--id", session_id]
                )
                self.assertEqual(rc, 0, err)
                self.assertIn("$ id", out)
                self.assertIn("ran:id", out)

                rc, out, err = self._run(
                    ["shock", "manage", "show", "session", "--id", session_id, "--json"]
                )
                self.assertEqual(rc, 0, err)
                data = json.loads(out)
                self.assertEqual(data["session"]["id"], session_id)

                rc, out, err = self._run(
                    ["shock", "manage", "show", "shell", "--id", record.id]
                )
                self.assertEqual(rc, 0, err)
                self.assertIn("== web1 ==", out)

                rc, out, err = self._run(
                    ["shock", "manage", "show", "shell", "--id", record.id, "--json"]
                )
                self.assertEqual(rc, 0, err)
                self.assertEqual(json.loads(out)["shell"]["id"], record.id)

    def test_terminal_json_start_event(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server))
                rc, out, err = self._terminal(record, "id\nexit\n", extra=("--json",))
                self.assertEqual(rc, 0, err)
                lines = [json.loads(line) for line in out.splitlines()]
                self.assertEqual(lines[0]["event"], "session")
                self.assertIsNotNone(lines[0]["id"])
                self.assertEqual(lines[1]["command"], "id")
                self.assertTrue(lines[1]["success"])

    def test_session_name_tracks_rename(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server), name="before")
                self._terminal(record, "id\nexit\n")
                rc, _out, err = self._run(
                    ["shock", "manage", "edit", "shell", record.id, "--name", "after"]
                )
                self.assertEqual(rc, 0, err)
                rc, out, err = self._run(["shock", "manage", "list", "sessions"])
                self.assertEqual(rc, 0, err)
                self.assertIn("== after", out)
                self.assertNotIn("== before", out)

    def test_delete_shell_keeps_sessions_and_delete_session(self):
        server = self.start_shell("hunter2")
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"SHELLSUITE_HOME": tmp}):
                record = self._seed_shell(_url(server), name="web1")
                self._terminal(record, "id\nexit\n")

                rc, _out, err = self._run(
                    ["shock", "manage", "delete", "shell", record.id]
                )
                self.assertEqual(rc, 0, err)

                summaries = sessions.list_sessions()
                self.assertEqual(len(summaries), 1)
                self.assertEqual(summaries[0].shell, _url(server))

                rc, _out, err = self._run(
                    ["shock", "manage", "delete", "session", "--id", summaries[0].id]
                )
                self.assertEqual(rc, 0, err)
                self.assertEqual(sessions.list_sessions(), [])


if __name__ == "__main__":
    unittest.main()
