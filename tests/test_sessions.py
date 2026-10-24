"""Tests for the session recorder, listing, show and delete."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from unittest import mock

from shellshock.manager import registry, sessions


class _SessionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"SHELLSUITE_HOME": self.tmp.name})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _shell(self, name="web1", url="http://x/shell.php", vector="post",
               mode="plain", has_secret=False):
        store = registry.Registry()
        store.load()
        record = store.upsert(
            url=url, vector=vector, mode=mode, has_secret=has_secret,
            name=name, now="2026-01-01T00:00:00+00:00",
        )
        store.save()
        return record

    def _record_session(self, shell, *, finish=True, commands=1):
        recorder = sessions.SessionRecorder.start(shell)
        for index in range(commands):
            recorder.record(
                {"command": f"cmd{index}", "success": True, "output": "ok", "error": None}
            )
        if finish:
            recorder.finish(sessions.STATUS_COMPLETED)
        return recorder

    def _lines(self, recorder):
        return [
            json.loads(line)
            for line in recorder.path.read_text(encoding="utf-8").splitlines()
        ]


class RecorderTests(_SessionTest):
    def test_start_writes_metadata(self):
        shell = self._shell(mode="auth", has_secret=True)
        recorder = sessions.SessionRecorder.start(shell)
        meta = self._lines(recorder)[0]
        self.assertEqual(meta["type"], "session")
        self.assertEqual(meta["id"], recorder.id)
        self.assertEqual(meta["shell_id"], shell.id)
        self.assertEqual(meta["url"], shell.url)
        self.assertEqual(meta["vector"], "post")
        self.assertEqual(meta["mode"], "auth")
        self.assertTrue(meta["has_secret"])
        self.assertIn("started_at", meta)
        self.assertNotIn('"secret"', recorder.path.read_text(encoding="utf-8"))

    def test_record_and_finish(self):
        recorder = self._record_session(self._shell(), commands=2)
        lines = self._lines(recorder)
        self.assertEqual([line["type"] for line in lines], ["session", "command", "command", "end"])
        self.assertEqual(lines[3]["status"], "completed")
        self.assertEqual(lines[3]["commands"], 2)
        self.assertFalse(lines[3]["truncated"])
        self.assertIn("duration_seconds", lines[3])

    def test_incomplete_when_not_finished(self):
        recorder = self._record_session(self._shell(), finish=False)
        summaries = sessions.list_sessions()
        self.assertEqual(len(summaries), 1)
        self.assertEqual(summaries[0].status, sessions.STATUS_INCOMPLETE)
        self.assertIsNone(summaries[0].ended_at)
        self.assertEqual(summaries[0].commands, 1)

    def test_size_cap_truncates(self):
        recorder = sessions.SessionRecorder.start(self._shell())
        with mock.patch.object(sessions, "MAX_BYTES", recorder._size + 120):
            recorder.record({"command": "big", "success": True, "output": "x" * 500, "error": None})
            recorder.record({"command": "later", "success": True, "output": "y", "error": None})
        recorder.finish(sessions.STATUS_COMPLETED)
        lines = self._lines(recorder)
        self.assertIn("truncated", [line["type"] for line in lines])
        self.assertNotIn("later", [line.get("command") for line in lines])
        self.assertTrue(lines[-1]["truncated"])

    def test_unwritable_dir_raises_session_error(self):
        shell = self._shell()
        with mock.patch.object(sessions.config, "sessions_dir", side_effect=OSError("nope")):
            with self.assertRaises(sessions.SessionError):
                sessions.SessionRecorder.start(shell)


class ListingTests(_SessionTest):
    def test_list_resolves_name_from_registry(self):
        shell = self._shell(name="web1")
        self._record_session(shell)
        self.assertEqual(sessions.list_sessions()[0].shell, "web1")

    def test_name_follows_rename(self):
        shell = self._shell(name="before")
        self._record_session(shell)
        store = registry.Registry()
        store.load()
        store.update(shell.id, {"name": "after"})
        store.save()
        self.assertEqual(sessions.list_sessions()[0].shell, "after")

    def test_name_falls_back_to_url_when_shell_deleted(self):
        shell = self._shell(name="gone", url="http://x/gone.php")
        self._record_session(shell)
        store = registry.Registry()
        store.load()
        store.delete(shell.id)
        store.save()
        self.assertEqual(sessions.list_sessions()[0].shell, "http://x/gone.php")

    def test_filter_by_shell_id_and_fields(self):
        first = self._shell(url="http://x/a.php", name="a")
        second = self._shell(url="http://x/b.php", name="b", mode="auth", has_secret=True)
        self._record_session(first)
        self._record_session(second)

        self.assertEqual(len(sessions.list_sessions()), 2)
        self.assertEqual(
            [summary.shell for summary in sessions.list_sessions(shell_id=first.id)], ["a"]
        )
        self.assertEqual(
            [summary.shell for summary in sessions.list_sessions(filters_expr=("mode == auth",))],
            ["b"],
        )

    def test_order_by_started_at(self):
        shell = self._shell()
        stamps = iter(["2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"])
        with mock.patch.object(sessions, "_now_iso", side_effect=lambda: next(stamps)):
            self._record_session(shell, finish=False)
            self._record_session(shell, finish=False)
        ascending = sessions.list_sessions(order="started_at", descending=False)
        self.assertEqual(
            [summary.started_at for summary in ascending],
            ["2026-01-01T00:00:00+00:00", "2026-01-02T00:00:00+00:00"],
        )

    def test_check_query_rejects_bad_input(self):
        for order, filters_expr in (("bogus", ()), ("started_at", ("nope",))):
            with self.assertRaises(sessions.SessionError):
                sessions.check_query(order, filters_expr)


class ShowDeleteTests(_SessionTest):
    def test_show_session(self):
        recorder = self._record_session(self._shell(name="web1"))
        data = sessions.show_session(recorder.id)
        self.assertEqual(data["summary"].id, recorder.id)
        self.assertEqual(data["summary"].shell, "web1")
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["command"], "cmd0")

    def test_show_unknown(self):
        with self.assertRaises(sessions.SessionError):
            sessions.show_session("missing")

    def test_delete_session(self):
        recorder = self._record_session(self._shell())
        summary = sessions.delete_session(recorder.id)
        self.assertEqual(summary.id, recorder.id)
        self.assertFalse(recorder.path.exists())
        with self.assertRaises(sessions.SessionError):
            sessions.delete_session(recorder.id)

    def test_torn_trailing_line_tolerated(self):
        recorder = self._record_session(self._shell())
        with recorder.path.open("a", encoding="utf-8") as stream:
            stream.write('{"type": "command", broken\n')
        data = sessions.show_session(recorder.id)
        self.assertEqual(len(data["events"]), 1)


if __name__ == "__main__":
    unittest.main()
