"""ShellShock CLI: `shellsuite shock <action>`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from shellsuite.protocol import contract
from shellshock.creator import generator
from shellshock.creator.spec import WebShellSpec

#For some reason this won't work with just "creator", it has to be ".creator".
from .creator import drivers

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


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(COMMAND, help="webshell creation and management")
    actions = parser.add_subparsers(dest="action", metavar="<action>")

    create = actions.add_parser("create", help="generate a webshell")
    create.add_argument("--vector", choices = contract.VECTORS, required=True)
    create.add_argument("--mode", choices = ["plain", "auth"], required=True)
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

    # `upload` (objective 1.4) is added later as its own action.
