"""Shared configuration: filesystem locations and module names.

Every location the modules must agree on is resolved here, so there is one
source of truth for where ShellSuite keeps its state.
"""

from __future__ import annotations

import os
from pathlib import Path

MODULE_NAMES: tuple[str, ...] = ("shellshock", "shellblock")

_ENV_HOME = "SHELLSUITE_HOME"
_DEFAULT_DIRNAME = ".shellsuite"


def data_dir() -> Path:
    """Directory holding ShellSuite's persistent state.

    Overridable with SHELLSUITE_HOME; defaults to ~/.shellsuite.
    Created on first use.
    """
    override = os.environ.get(_ENV_HOME)
    base = Path(override).expanduser() if override else Path.home() / _DEFAULT_DIRNAME
    base.mkdir(parents=True, exist_ok=True)
    return base


def registry_path() -> Path:
    """Path to the CLI-owned JSON registry (webshells + sessions)."""
    return data_dir() / "registry.json"


def log_path() -> Path:
    """Path to the shared log file."""
    return data_dir() / "shellsuite.log"
