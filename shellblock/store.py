"""Almacenamiento de resultados: escritura atómica en el directorio de análisis."""

from __future__ import annotations
import os
import tempfile
from pathlib import Path
from shellblock.result import Result
from shellsuite import config

RESULT_SUFFIX = "_result.json"
def result_path(target_name: str) -> Path:
    """Computes path of analysis output file"""
    return config.analysis_dir() / f"{target_name}{RESULT_SUFFIX}"


def write_result(result: Result) -> Path:
    """Writes result as json and returns path of the output file"""
    path = result_path(str(result.target["name"]))
    _write_atomic(path, result.to_json())
    return path


def _write_atomic(path: Path, text: str) -> None:
    """Atomic write, first to temp file and then to output path"""
    descriptor, temporary = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
        os.replace(temporary, path)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
