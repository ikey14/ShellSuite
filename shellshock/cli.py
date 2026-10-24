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
from .manager import client, registry

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


def _cmd_manage_list(args: argparse.Namespace) -> int:
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

    blocks = []
    for record in records:
        title = record.name or record.url
        blocks.append(
            f"== {title} ==\n"
            f"id:         {record.id}\n"
            f"url:        {record.url}\n"
            f"vector:     {record.vector}\n"
            f"mode:       {record.mode}\n"
            f"has_secret: {'yes' if record.has_secret else 'no'}\n"
            f"created:    {record.created_at}\n"
            f"last_used:  {record.last_used}"
        )
    print("\n\n".join(blocks))
    return 0


def _cmd_manage_edit(args: argparse.Namespace) -> int:
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


def _cmd_manage_delete(args: argparse.Namespace) -> int:
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

    list_cmd = manage_actions.add_parser("list", help="list known webshells")
    list_cmd.add_argument(
        "--order",
        choices=registry.ORDER_FIELDS,
        default="last_used",
        help="sort field (default: last_used)",
    )
    direction = list_cmd.add_mutually_exclusive_group()
    direction.add_argument("--asc", action="store_true", help="ascending order")
    direction.add_argument("--desc", action="store_true", help="descending order")
    list_cmd.add_argument(
        "--filter",
        action="append",
        default=[],
        help="filter 'attr op value' (repeatable, ANDed)",
    )
    list_cmd.add_argument("--json", action="store_true", help="machine-readable JSON")
    list_cmd.set_defaults(handler=_cmd_manage_list)

    edit = manage_actions.add_parser("edit", help="edit a known webshell")
    edit.add_argument("id", help="shell id (see 'manage list')")
    name_group = edit.add_mutually_exclusive_group()
    name_group.add_argument(
        "--name",
        default=None,
        help="new name (an empty string clears it in shells that pass empty args)",
    )
    name_group.add_argument(
        "--clear-name",
        action="store_true",
        help="remove the name (title falls back to the URL)",
    )
    edit.set_defaults(handler=_cmd_manage_edit)

    delete = manage_actions.add_parser("delete", help="delete a known webshell")
    delete.add_argument("id", help="shell id (see 'manage list')")
    delete.set_defaults(handler=_cmd_manage_delete)
