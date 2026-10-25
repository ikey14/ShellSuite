"""Thin bridge between the GUI and the ``shellsuite`` CLI (Tk-free)."""

from __future__ import annotations

import json
import subprocess
import sys

_CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class CliError(Exception):
    """Raised when the CLI fails or returns unusable output."""


def _base() -> list[str]:
    return [sys.executable, "-m", "shellsuite"]


def _run(args, timeout: float = 30.0) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            _base() + list(args),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=_CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CliError(str(exc)) from exc


def _run_json(args, timeout: float = 30.0) -> dict:
    process = _run(args, timeout)
    if process.returncode != 0:
        message = (process.stderr or process.stdout or f"exit {process.returncode}").strip()
        raise CliError(message)
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        raise CliError(f"invalid CLI output: {exc}") from exc


def _check(args, timeout: float = 30.0) -> str:
    process = _run(args, timeout)
    if process.returncode != 0:
        message = (process.stderr or process.stdout or f"exit {process.returncode}").strip()
        raise CliError(message)
    return process.stdout


def list_shells(order: str = "last_used", descending: bool = True, filters=()) -> list[dict]:
    args = ["shock", "manage", "list", "shells", "--order", order, "--json",
            "--desc" if descending else "--asc"]
    for expression in filters:
        args += ["--filter", expression]
    return _run_json(args)["shells"]


def list_sessions(shell_id: str | None = None, order: str = "started_at",
                  descending: bool = True, filters=()) -> list[dict]:
    args = ["shock", "manage", "list", "sessions", "--order", order, "--json",
            "--desc" if descending else "--asc"]
    if shell_id:
        args += ["--id", shell_id]
    for expression in filters:
        args += ["--filter", expression]
    return _run_json(args)["sessions"]


def show_shell(shell_id: str) -> dict:
    return _run_json(["shock", "manage", "show", "shell", "--id", shell_id, "--json"])["shell"]


def show_session(session_id: str) -> dict:
    return _run_json(["shock", "manage", "show", "session", "--id", session_id, "--json"])


def connect(url: str, vector: str, mode: str, secret: str | None = None,
            name: str | None = None) -> str:
    args = ["shock", "manage", "connect", "--url", url, "--vector", vector, "--mode", mode]
    if secret is not None:
        args += ["--secret", secret]
    if name:
        args += ["--name", name]
    return _check(args, timeout=60.0)


def edit_shell_name(shell_id: str, name: str | None) -> str:
    args = ["shock", "manage", "edit", "shell", shell_id]
    if name is None:
        args.append("--clear-name")
    else:
        args += ["--name", name]
    return _check(args)


def delete_shell(shell_id: str) -> str:
    return _check(["shock", "manage", "delete", "shell", shell_id])


def delete_session(session_id: str) -> str:
    return _check(["shock", "manage", "delete", "session", "--id", session_id])


def spawn_terminal(shell_id: str, secret: str | None = None) -> subprocess.Popen:
    args = [sys.executable, "-u", "-m", "shellsuite",
            "shock", "manage", "terminal", shell_id, "--json"]
    if secret is not None:
        args += ["--secret", secret]
    return subprocess.Popen(
        args,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
        creationflags=_CREATE_NO_WINDOW,
    )
