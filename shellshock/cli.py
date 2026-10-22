"""ShellShock CLI: `shellsuite shock <action>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsuite import config
from shellsuite.protocol import contract
from shellshock.creator import generator
from shellshock.creator.spec import WebShellSpec

#For some reason this won't work with just "creator", it has to be ".creator".
from .creator import drivers
from . import uploader

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
