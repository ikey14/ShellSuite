"""Carga de los ficheros JSON que acompañan al módulo ShellBlock."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_PACKAGE_ROOT = Path(__file__).resolve().parent.parent


def load_json(name: str | Path) -> Any:
    """Carga un JSON del paquete; los nombres relativos parten de ``shellblock/``."""
    path = Path(name)
    if not path.is_absolute():
        path = _PACKAGE_ROOT / path
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)
