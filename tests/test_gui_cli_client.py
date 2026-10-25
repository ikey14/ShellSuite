"""Tests for the GUI's CLI bridge (headless; no Tk)."""

from __future__ import annotations

import json
import subprocess
import unittest
from unittest import mock

from shellsuite.gui import cli_client


def _completed(returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=stderr)


class CliClientTests(unittest.TestCase):
    def test_list_shells_builds_args_and_parses(self):
        stdout = json.dumps({"version": 1, "shells": [{"id": "1", "name": "a"}]})
        with mock.patch.object(
            cli_client.subprocess, "run", return_value=_completed(stdout=stdout)
        ) as run:
            shells = cli_client.list_shells("name", False, ["vector == post"])

        args = run.call_args.args[0]
        self.assertIn("shells", args)
        self.assertIn("--asc", args)
        self.assertNotIn("--desc", args)
        self.assertIn("--filter", args)
        self.assertEqual(shells, [{"id": "1", "name": "a"}])

    def test_list_sessions_with_shell_id(self):
        stdout = json.dumps({"version": 1, "sessions": [{"id": "s1"}]})
        with mock.patch.object(
            cli_client.subprocess, "run", return_value=_completed(stdout=stdout)
        ) as run:
            sessions = cli_client.list_sessions("shell-1", "started_at", True, ())

        args = run.call_args.args[0]
        self.assertIn("sessions", args)
        self.assertIn("--id", args)
        self.assertIn("shell-1", args)
        self.assertIn("--desc", args)
        self.assertEqual(sessions, [{"id": "s1"}])

    def test_run_json_error_raises(self):
        with mock.patch.object(
            cli_client.subprocess, "run",
            return_value=_completed(returncode=2, stderr="error: bad filter"),
        ):
            with self.assertRaises(cli_client.CliError) as caught:
                cli_client.list_shells()
        self.assertIn("bad filter", str(caught.exception))

    def test_invalid_json_raises(self):
        with mock.patch.object(
            cli_client.subprocess, "run", return_value=_completed(stdout="not json")
        ):
            with self.assertRaises(cli_client.CliError):
                cli_client.list_shells()

    def test_edit_shell_clear_uses_flag(self):
        with mock.patch.object(
            cli_client.subprocess, "run", return_value=_completed(stdout="updated")
        ) as run:
            cli_client.edit_shell_name("abc", None)
        args = run.call_args.args[0]
        self.assertIn("--clear-name", args)
        self.assertNotIn("--name", args)

    def test_edit_shell_name_uses_value(self):
        with mock.patch.object(
            cli_client.subprocess, "run", return_value=_completed(stdout="updated")
        ) as run:
            cli_client.edit_shell_name("abc", "new name")
        args = run.call_args.args[0]
        self.assertIn("--name", args)
        self.assertIn("new name", args)

    def test_spawn_terminal_arguments(self):
        fake = mock.Mock()
        with mock.patch.object(
            cli_client.subprocess, "Popen", return_value=fake
        ) as popen:
            result = cli_client.spawn_terminal("abc", "pw")
        args = popen.call_args.args[0]
        self.assertIn("-u", args)
        self.assertIn("terminal", args)
        self.assertIn("--json", args)
        self.assertIn("--secret", args)
        self.assertIs(result, fake)

    def test_spawn_terminal_without_secret(self):
        fake = mock.Mock()
        with mock.patch.object(
            cli_client.subprocess, "Popen", return_value=fake
        ) as popen:
            cli_client.spawn_terminal("abc")
        args = popen.call_args.args[0]
        self.assertNotIn("--secret", args)


if __name__ == "__main__":
    unittest.main()
