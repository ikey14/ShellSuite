"""ShellBlock CLI: `shellsuite block <action>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shellblock.rules import LoadRules, ValidateRules
from shellsuite import config

# The word the user types after `shellsuite` (the package is still `shellshock`).
COMMAND = "block"

def _CmdTest(args: argparse.Namespace):
    if(args.serious):
        print("Here to establish cli file")
    else:
        print("Testing")

def _CmdRules(args: argparse.Namespace) -> int:
    if args.validate:
        errors = ValidateRules()
        if args.json:
            print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
            return 0 if not errors else 1
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            return 1
        print("rules.json OK")
        return 0

    rules = LoadRules()
    if args.json:
        print(json.dumps({"rules": rules}, indent=2))
        return 0
    for rule in rules:
        print(f"{rule['id']} ({rule['kind']}): {rule['title']}")
    return 0

def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(COMMAND, help="webshell detection and risk scoring")
    actions = parser.add_subparsers(dest="action", metavar="<action>")

    
    test = actions.add_parser("test", help = "Don't worry, I won't be here for long")
    test.add_argument("--serious", action = "store_true", help = "A bit more serious")
    test.set_defaults(handler = _CmdTest)

    rules = actions.add_parser("rules", help = "list the rules applied on analysis")
    rules.add_argument("--validate", action = "store_true", help = "validate the rules")
    rules.add_argument("--json", action = "store_true", help = "machine-readable JSON")
    rules.set_defaults(handler = _CmdRules)

