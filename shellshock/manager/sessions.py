"""Persistent per-run terminal sessions (append-only JSONL).

One ``manage terminal`` run is one session. Each session is a JSONL file under
``~/.shellsuite/sessions/<id>.jsonl``: a metadata line, one line per command,
and a final ``end`` line. Sessions are read-only once closed; the shell name is
resolved live from the registry (falling back to the stored URL if the shell was
deleted), and the secret is never stored.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from shellsuite import config

from . import filters, registry as registry_module

SESSION_VERSION = 1
MAX_BYTES = 4 * 1024 * 1024

STATUS_COMPLETED = "completed"
STATUS_ERROR = "error"
STATUS_INTERRUPTED = "interrupted"
STATUS_INCOMPLETE = "incomplete"

SESSION_FIELDS: tuple[str, ...] = (
    "id",
    "shell_id",
    "shell",
    "url",
    "vector",
    "mode",
    "status",
    "started_at",
    "ended_at",
    "duration",
    "commands",
)
SESSION_DATE_FIELDS: tuple[str, ...] = ("started_at", "ended_at")


class SessionError(Exception):
    """Raised for unreadable/invalid session state or invalid query input."""


@dataclass(frozen=True)
class SessionSummary:
    id: str
    shell_id: str
    shell: str
    url: str
    vector: str
    mode: str
    has_secret: bool
    started_at: str
    ended_at: str | None
    duration: int | None
    status: str
    commands: int

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "shell_id": self.shell_id,
            "shell": self.shell,
            "url": self.url,
            "vector": self.vector,
            "mode": self.mode,
            "has_secret": self.has_secret,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "duration": self.duration,
            "status": self.status,
            "commands": self.commands,
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _duration_seconds(started_at: str, ended_at: str) -> int:
    start = datetime.fromisoformat(started_at)
    end = datetime.fromisoformat(ended_at)
    return max(0, int((end - start).total_seconds()))


def _restrict(path: Path) -> None:
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _append(path: Path, record: dict) -> int:
    data = (json.dumps(record) + "\n").encode("utf-8")
    with path.open("ab") as stream:
        stream.write(data)
    return len(data)


class SessionRecorder:
    """Append-only writer for one terminal run."""

    def __init__(self, path: Path, session_id: str, started_at: str):
        self.path = path
        self.id = session_id
        self.started_at = started_at
        self.commands = 0
        self.truncated = False
        self._size = 0

    @classmethod
    def start(cls, shell) -> "SessionRecorder":
        session_id = uuid.uuid4().hex
        started_at = _now_iso()
        metadata = {
            "type": "session",
            "version": SESSION_VERSION,
            "id": session_id,
            "shell_id": shell.id,
            "url": shell.url,
            "vector": shell.vector,
            "mode": shell.mode,
            "has_secret": shell.has_secret,
            "started_at": started_at,
        }
        try:
            path = config.sessions_dir() / f"{session_id}.jsonl"
            with path.open("w", encoding="utf-8") as stream:
                stream.write(json.dumps(metadata) + "\n")
            _restrict(path)
            size = path.stat().st_size
        except OSError as exc:
            raise SessionError(f"cannot create session file: {exc}") from exc

        recorder = cls(path, session_id, started_at)
        recorder._size = size
        return recorder

    def record(self, event: dict) -> None:
        if self.truncated:
            return
        line = (
            json.dumps(
                {
                    "type": "command",
                    "command": event.get("command"),
                    "success": event.get("success"),
                    "output": event.get("output"),
                    "error": event.get("error"),
                }
            )
            + "\n"
        ).encode("utf-8")
        if self._size + len(line) > MAX_BYTES:
            self._write(
                {"type": "truncated", "reason": "size_cap", "at": _now_iso()}
            )
            self.truncated = True
            return
        self._write_raw(line)
        self.commands += 1

    def finish(self, status: str) -> None:
        ended_at = _now_iso()
        try:
            duration = _duration_seconds(self.started_at, ended_at)
        except ValueError:
            duration = 0
        self._write(
            {
                "type": "end",
                "ended_at": ended_at,
                "duration_seconds": duration,
                "status": status,
                "commands": self.commands,
                "truncated": self.truncated,
            }
        )

    def _write(self, record: dict) -> None:
        try:
            self._size += _append(self.path, record)
        except OSError:
            self.truncated = True

    def _write_raw(self, line: bytes) -> None:
        try:
            with self.path.open("ab") as stream:
                stream.write(line)
            self._size += len(line)
        except OSError:
            self.truncated = True


def _read_session(path: Path) -> dict | None:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SessionError(f"cannot read session {path}: {exc}") from exc

    metadata = None
    events: list[dict] = []
    end = None
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue  # tolerate a torn trailing line
        kind = record.get("type")
        if kind == "session" and metadata is None:
            metadata = record
        elif kind == "end":
            end = record
        elif kind in ("command", "truncated"):
            events.append(record)

    if metadata is None:
        return None
    return {"metadata": metadata, "events": events, "end": end}


def _shell_titles() -> dict[str, str]:
    try:
        store = registry_module.Registry()
        store.load()
    except registry_module.RegistryError:
        return {}
    return {record.id: (record.name or record.url) for record in store.all()}


def _summarize(path: Path, titles: dict[str, str]) -> SessionSummary | None:
    parsed = _read_session(path)
    if parsed is None:
        return None
    meta = parsed["metadata"]
    end = parsed["end"]
    command_events = sum(1 for event in parsed["events"] if event.get("type") == "command")
    shell_id = str(meta.get("shell_id", ""))
    return SessionSummary(
        id=str(meta.get("id", path.stem)),
        shell_id=shell_id,
        shell=titles.get(shell_id, str(meta.get("url", ""))),
        url=str(meta.get("url", "")),
        vector=str(meta.get("vector", "")),
        mode=str(meta.get("mode", "")),
        has_secret=bool(meta.get("has_secret", False)),
        started_at=str(meta.get("started_at", "")),
        ended_at=str(end["ended_at"]) if end and end.get("ended_at") else None,
        duration=int(end["duration_seconds"]) if end and "duration_seconds" in end else None,
        status=str(end["status"]) if end and end.get("status") else STATUS_INCOMPLETE,
        commands=int(end.get("commands", command_events)) if end else command_events,
    )


def _value(summary: SessionSummary, field: str) -> str:
    if field == "duration":
        return "" if summary.duration is None else str(summary.duration)
    if field == "commands":
        return str(summary.commands)
    if field == "ended_at":
        return summary.ended_at or ""
    return str(getattr(summary, field))


def _matches(summary: SessionSummary, flt: tuple[str, str, str]) -> bool:
    attr, op, value = flt
    return filters.matches(_value(summary, attr), op, value)


def _sort_key(summary: SessionSummary, field: str):
    if field == "duration":
        return float("-inf") if summary.duration is None else summary.duration
    if field == "commands":
        return summary.commands
    value = _value(summary, field)
    return value.lower() if field in ("shell", "url", "vector", "mode", "status") else value


def check_query(order: str, filters_expr=()) -> None:
    """Validate order/filter input (raise SessionError if invalid)."""
    if order not in SESSION_FIELDS:
        raise SessionError(f"invalid --order: {order!r}")
    for item in filters_expr:
        try:
            filters.parse(item, SESSION_FIELDS)
        except filters.FilterError as exc:
            raise SessionError(str(exc)) from exc


def list_sessions(
    *,
    shell_id: str | None = None,
    order: str = "started_at",
    descending: bool = True,
    filters_expr=(),
) -> list[SessionSummary]:
    check_query(order, filters_expr)
    parsed_filters = [filters.parse(item, SESSION_FIELDS) for item in filters_expr]

    titles = _shell_titles()
    summaries: list[SessionSummary] = []
    for path in sorted(config.sessions_dir().glob("*.jsonl")):
        summary = _summarize(path, titles)
        if summary is None:
            continue
        if shell_id is not None and summary.shell_id != shell_id:
            continue
        if all(_matches(summary, flt) for flt in parsed_filters):
            summaries.append(summary)

    summaries.sort(key=lambda summary: summary.id)
    summaries.sort(key=lambda summary: _sort_key(summary, order), reverse=descending)
    return summaries


def show_session(session_id: str) -> dict:
    path = config.sessions_dir() / f"{session_id}.jsonl"
    if not path.is_file():
        raise SessionError(f"no session with id {session_id!r}")
    parsed = _read_session(path)
    summary = _summarize(path, _shell_titles())
    if parsed is None or summary is None:
        raise SessionError(f"invalid session file: {path}")
    return {"summary": summary, "events": parsed["events"], "end": parsed["end"]}


def delete_session(session_id: str) -> SessionSummary:
    path = config.sessions_dir() / f"{session_id}.jsonl"
    if not path.is_file():
        raise SessionError(f"no session with id {session_id!r}")
    summary = _summarize(path, _shell_titles())
    try:
        path.unlink()
    except OSError as exc:
        raise SessionError(f"cannot delete session {session_id}: {exc}") from exc
    if summary is None:
        raise SessionError(f"invalid session file: {path}")
    return summary
