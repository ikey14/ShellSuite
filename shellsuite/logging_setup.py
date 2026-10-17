"""Shared logging configuration.

Modules never configure logging themselves; they call configure() so all of
ShellSuite's output is formatted and stored consistently.
"""

from __future__ import annotations

import logging

from . import config

_LOGGER_NAME = "shellsuite"


def configure(verbose: bool = False) -> logging.Logger:
    """Configure and return the top-level ShellSuite logger."""
    logger = logging.getLogger(_LOGGER_NAME)
    if logger.handlers:  # already configured (e.g. repeated calls in tests)
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")

    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(fmt)
    logger.addHandler(console)

    file_handler = logging.FileHandler(config.log_path(), encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger
