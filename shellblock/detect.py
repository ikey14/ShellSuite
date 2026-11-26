"""Type detection: magic bytes versus the extension a file claims."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from shellblock.helpers.jsonLoader import load_json

_INFO = load_json("info.json")
_MAGIC_ENTRIES: list[dict] = _INFO["magicNumbers"]
_EXTENSIONS: dict[str, list[str]] = _INFO["extensions"]
_EXTENSION_TYPES: dict[str, str] = {
    extension: type_name
    for type_name, extensions in _EXTENSIONS.items()
    for extension in extensions
}
_HEADER_BYTES = max(
    entry["offset"] + max(len(pattern) // 2 for pattern in entry["magic"])
    for entry in _MAGIC_ENTRIES
)
MAGICS: dict[str, tuple[bytes, ...]] = {
    entry["type"]: tuple(bytes.fromhex(pattern) for pattern in entry["magic"])
    for entry in _MAGIC_ENTRIES
}


@dataclass(frozen=True)
class Detection:
    """Facts the detect stage reports; findings belong to the rules stage."""

    extension: str
    extension_type: str
    detected_type: str
    type_mismatch: bool
    size: int


def detect(path: Path, *, extension_claims: bool = True) -> Detection:
    """Return the claimed type, the detected type and the mismatch fact.

    ``extension_claims`` says whether the file name is a claim worth judging.
    Parts carved out of a capture carry the uploaded filename, so they keep the
    claim; whole bodies are named after the request URI by tshark, so they pass
    ``False`` and are typed by magic alone — a response to ``shell.php`` is not
    PHP source and its name contradicts nothing.
    """
    header = _read_header(path)
    extension = path.suffix.lower().lstrip(".")
    extension_type = (
        _EXTENSION_TYPES.get(extension, "unknown") if extension_claims else "unknown"
    )
    detected_type = _match_magic(header)
    if extension_claims and detected_type == "unknown" and extension_type == "php":
        detected_type = "php"
    return Detection(
        extension=extension,
        extension_type=extension_type,
        detected_type=detected_type,
        type_mismatch=(
            extension_type != "unknown" and detected_type != extension_type
        ),
        size=path.stat().st_size,
    )


def _read_header(path: Path) -> bytes:
    with path.open("rb") as handle:
        return handle.read(_HEADER_BYTES)


def _match_magic(header: bytes) -> str:
    for entry in _MAGIC_ENTRIES:
        start = entry["offset"]
        for pattern in entry["magic"]:
            length = len(pattern) // 2
            if header[start : start + length].hex() == pattern.lower():
                return entry["type"]
    return "unknown"
