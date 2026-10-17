"""The description of a webshell to generate, plus its validation."""

from __future__ import annotations

from dataclasses import dataclass

from shellsuite.protocol import contract

from . import drivers


@dataclass(frozen=True)
class WebShellSpec:
    """Everything needed to render one webshell.

    type = vector x mode (AGENTS.md section 4). ``driver`` is the PHP
    execution function; None means the contract default.
    """

    vector: str
    mode: str
    name: str = "shell"
    secret: str | None = None
    driver: str | None = None

    def validate(self) -> None:
        if self.vector not in contract.VECTORS:
            raise ValueError(f"unknown vector: {self.vector!r}")
        if self.mode not in contract.MODES:
            raise ValueError(f"unknown mode: {self.mode!r}")
        if self.driver is not None and self.driver not in drivers.DRIVERS:
            raise ValueError(f"unknown driver: {self.driver!r}")
        if self.mode == "encrypted" and not self.secret:
            raise ValueError("encrypted mode requires a secret")

    @property
    def resolved_driver(self) -> str:
        """The driver actually embedded: the chosen one, or the default."""
        return self.driver or drivers.DEFAULT_DRIVER
