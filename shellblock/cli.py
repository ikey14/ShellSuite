"""ShellBlock CLI: `shellsuite block <action>`."""

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
# from .creator import drivers
# from . import uploader
# from .manager import client, registry, sessions, terminal

# The word the user types after `shellsuite` (the package is still `shellshock`).
COMMAND = "block"

def _CmdTest(args: argparse.Namespace):
    if(args.serious):
        print("Here to establish cli file")
    else:
        print("Testing")

def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(COMMAND, help="webshell detection and risk scoring")
    actions = parser.add_subparsers(dest="action", metavar="<action>")

    
    test = actions.add_parser("test", help = "Don't worry, I won't be here for long")
    test.add_argument("--serious", action = "store_true", help = "A bit more serious")
    test.set_defaults(handler = _CmdTest)

