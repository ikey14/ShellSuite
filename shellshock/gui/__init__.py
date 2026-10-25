"""ShellShock GUI contribution: Shells and Sessions sections."""

from __future__ import annotations

from .sessions import SessionsSection
from .shells import ShellsSection


def register(app) -> None:
    app.add_section("Shells", "globe", ShellsSection(app))
    app.add_section("Sessions", "clock", SessionsSection(app))
