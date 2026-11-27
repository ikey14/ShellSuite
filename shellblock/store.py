"""Almacenamiento de resultados: escritura atómica en el directorio de análisis."""

from __future__ import annotations
import json
import os
import tempfile
from pathlib import Path
from shellblock.result import Result
from shellsuite import config

RESULT_SUFFIX = "_result.json"
SCORE_SUFFIX = "_score.json"


class StoreError(Exception):
    """Raised when an analysis file is missing, unreadable or not JSON."""


def result_path(target_name: str) -> Path:
    """Computes path of analysis output file"""
    return config.analysis_dir() / f"{_basename(target_name)}{RESULT_SUFFIX}"


def score_path(target_name: str) -> Path:
    """Computes path of the score file written from that result"""
    return config.score_dir() / f"{_basename(target_name)}{SCORE_SUFFIX}"


def write_result(result: Result) -> Path:
    """Writes result as json and returns path of the output file"""
    path = result_path(str(result.target["name"]))
    _write_atomic(path, result.to_json())
    return path


def write_score(payload: dict) -> Path:
    """Escribe el score file y devuelve su ruta."""
    path = score_path(str(payload["target"]["name"]))
    text = json.dumps(payload, indent=2, ensure_ascii=False)
    _write_atomic(path, text)
    return path


def read_analysis(path: Path) -> dict:
    """Lee un fichero de análisis concreto, sin deducir su nombre del contenido."""
    return _read_json(path)


def read_result(target_name: str) -> dict:
    """Lee el result file de ``target_name`` (nombre o ruta)."""
    return _read_json(result_path(target_name))


def read_score(target_name: str) -> dict:
    """Lee el score file de ``target_name`` (nombre o ruta)."""
    return _read_json(score_path(target_name))


def result_files() -> list[Path]:
    """Todos los result files del directorio de análisis, ordenados por nombre."""
    return sorted(config.analysis_dir().glob(f"*{RESULT_SUFFIX}"))


def score_files() -> list[Path]:
    """Todos los score files del directorio de scores, ordenados por nombre."""
    return sorted(config.score_dir().glob(f"*{SCORE_SUFFIX}"))


def name_from_path(path: Path, suffix: str) -> str:
    """Nombre del objetivo a partir del fichero de análisis (``x.jpg`` de ``x.jpg_result.json``)."""
    name = path.name[: -len(suffix)] if path.name.endswith(suffix) else path.name
    return name


def _read_json(path: Path) -> dict:
    if not path.is_file():
        raise StoreError(f"no such analysis file: {path}")
    try:
        with path.open(encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise StoreError(f"unreadable analysis file {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise StoreError(f"unexpected analysis file {path}: top level is not an object")
    return data


def _basename(target_name: str) -> str:
    """Acepta tanto ``photo.jpg`` como ``/ruta/photo.jpg``."""
    return Path(target_name).name


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
