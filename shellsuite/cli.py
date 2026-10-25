"""Top-level ``shellsuite`` command.

    shellsuite <module> <action> [options]

The dispatcher knows nothing about what a module does: each module exposes a
``cli`` submodule with a ``register_parser(subparsers)`` function. Modules are
imported lazily and any that are missing/empty/broken are skipped, so
ShellShock keeps working when ShellBlock is absent.
"""

from __future__ import annotations

import argparse
import importlib
import sys

from . import __version__, config, logging_setup


def _load_module_parser(name: str, subparsers: argparse._SubParsersAction) -> bool:
    """Attach ``name``'s subcommand to ``subparsers``; return True on success.

    A module that cannot be imported (absent, empty or broken) is skipped
    instead of crashing the CLI.
    """
    try:
        module = importlib.import_module(f"{name}.cli")
    except ImportError:
        return False
    register = getattr(module, "register_parser", None)
    if register is None:
        return False
    register(subparsers)
    return True


def _cmd_gui(_args: argparse.Namespace) -> int:
    try:
        from .gui.app import run
    except ImportError as exc:
        print(f"error: the GUI is unavailable: {exc}", file=sys.stderr)
        return 1
    run()
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="shellsuite",
        description="ShellSuite: webshell generation and management.",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="verbose output")

    subparsers = parser.add_subparsers(dest="module", metavar="<module>")
    for name in config.MODULE_NAMES:
        _load_module_parser(name, subparsers)

    gui = subparsers.add_parser("gui", help="launch the graphical interface")
    gui.set_defaults(handler=_cmd_gui)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging_setup.configure(args.verbose)

    if args.module is None:
        parser.print_help()
        return 0

    handler = getattr(args, "handler", None)
    if handler is None:  # module registered but no action handler
        parser.error(f"no action provided for module '{args.module}'")
    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
