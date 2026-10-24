"""Unit tests for the interactive terminal loop."""

from __future__ import annotations

import io
import json
import unittest

from shellshock.manager import client, terminal


def _shell(**overrides) -> client.WebShell:
    values = dict(
        url="http://x/shell.php", vector="post", mode="plain", secret=None, name="web1"
    )
    values.update(overrides)
    return client.WebShell(**values)


class _Reader:
    def __init__(self, lines):
        self.lines = list(lines)

    def __call__(self, prompt):
        return self.lines.pop(0) if self.lines else None


class TerminalTests(unittest.TestCase):
    def _run(self, lines, *, results=None, json_mode=False):
        out, err = io.StringIO(), io.StringIO()
        calls = []

        def fake_run(shell, command, timeout=15.0):
            calls.append(command)
            if results is not None:
                return results.pop(0)
            return client.ShellResult(success=True, output=f"ran:{command}")

        rc = terminal.interact(
            _shell(),
            read_line=_Reader(lines),
            write=out.write,
            write_err=err.write,
            run_command=fake_run,
            json_mode=json_mode,
        )
        return rc, out.getvalue(), err.getvalue(), calls

    def test_runs_until_exit(self):
        rc, out, err, calls = self._run(["id", "pwd", "exit"])
        self.assertEqual(rc, 0)
        self.assertEqual(calls, ["id", "pwd"])
        self.assertEqual(out, "ran:id\nran:pwd\n")

    def test_quit_exits(self):
        rc, out, err, calls = self._run(["quit"])
        self.assertEqual(rc, 0)
        self.assertEqual(calls, [])

    def test_exit_is_case_insensitive(self):
        rc, out, err, calls = self._run(["ID", "EXIT"])
        self.assertEqual(rc, 0)
        self.assertEqual(calls, ["ID"])

    def test_empty_lines_skipped(self):
        rc, out, err, calls = self._run(["", "   ", "id", "exit"])
        self.assertEqual(rc, 0)
        self.assertEqual(calls, ["id"])

    def test_eof_exits(self):
        rc, out, err, calls = self._run(["id"])
        self.assertEqual(rc, 0)
        self.assertEqual(calls, ["id"])

    def test_error_prints_and_exits_1(self):
        failure = client.ShellResult(success=False, error="boom")
        rc, out, err, calls = self._run(["id", "pwd"], results=[failure])
        self.assertEqual(rc, 1)
        self.assertEqual(calls, ["id"])
        self.assertIn("error: boom", err)

    def test_output_newline_normalization(self):
        result = client.ShellResult(success=True, output="no-newline")
        rc, out, err, calls = self._run(["id", "exit"], results=[result])
        self.assertEqual(rc, 0)
        self.assertEqual(out, "no-newline\n")

    def test_json_mode(self):
        rc, out, err, calls = self._run(["id", "exit"], json_mode=True)
        self.assertEqual(rc, 0)
        events = [json.loads(line) for line in out.splitlines()]
        self.assertEqual(
            events,
            [{"command": "id", "success": True, "output": "ran:id", "error": None}],
        )

    def test_json_error_emits_object_and_exits(self):
        failure = client.ShellResult(success=False, error="boom")
        rc, out, err, calls = self._run(
            ["id", "exit"], results=[failure], json_mode=True
        )
        self.assertEqual(rc, 1)
        event = json.loads(out.splitlines()[0])
        self.assertFalse(event["success"])
        self.assertEqual(event["error"], "boom")

    def test_on_event(self):
        events = []
        rc = terminal.interact(
            _shell(),
            read_line=_Reader(["id", "exit"]),
            write=io.StringIO().write,
            write_err=io.StringIO().write,
            run_command=lambda shell, command, timeout=15.0: client.ShellResult(
                success=True, output="x"
            ),
            on_event=events.append,
        )
        self.assertEqual(rc, 0)
        self.assertEqual(events[0]["command"], "id")
        self.assertTrue(events[0]["success"])


if __name__ == "__main__":
    unittest.main()
