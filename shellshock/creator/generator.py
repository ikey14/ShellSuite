"""Render a WebShellSpec into PHP and write it to disk."""

from __future__ import annotations

import importlib.resources
from pathlib import Path

from shellsuite import config
from shellsuite.protocol import contract

from .spec import WebShellSpec

from . import drivers

_TEMPLATES = importlib.resources.files("shellshock.creator") / "templates"


def _render(text: str, values: dict[str, str]) -> str:
    """Replace {{token}} placeholders; fail loudly on any left over."""
    for key, value in values.items():
        text = text.replace("{{" + key + "}}", value)
    if "{{" in text:
        raise ValueError("unfilled placeholder in generated output")
    return text


def _context(spec: WebShellSpec) -> dict[str, str]:
    driver = spec.resolved_driver
    body = drivers.DRIVER_BODIES.get(driver)
    if body is None:
        raise ValueError(f"driver not implemented: {driver!r}")
    return {
        "param_name": contract.PARAM_NAMES[spec.vector],
        "driver_body": body,
        "response_begin": contract.RESPONSE_BEGIN,
        "response_end": contract.RESPONSE_END,
    }


def generate(spec: WebShellSpec) -> str:
    """Return the PHP source for ``spec`` (no file I/O)."""
    spec.validate()
    template = (_TEMPLATES / f"{spec.vector}.php.tmpl").read_text(encoding="utf-8")
    return _render(template, _context(spec))


def write(spec: WebShellSpec, out: Path | None = None) -> Path:
    """Write the webshell to ``out`` (default: ~/.shellsuite/shells/<name>.php)."""
    dest = out or (config.shells_dir() / f"{spec.name}.php")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(generate(spec), encoding="utf-8")
    return dest
