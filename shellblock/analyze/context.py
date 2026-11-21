"""Estado compartido por los detectores estructurales."""

from __future__ import annotations
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal
from shellblock.detect import Detection

RegionKind = Literal["prefix", "segment", "chunk", "trailing"]

@dataclass(frozen=True)
class Region:
    """Section of the file with it's real byte size (derived with start and end)"""
    start: int
    end: int
    kind: RegionKind  # "prefix" | "segment" | "chunk" | "trailing"
    name: str  # "COM", "APP0", "tEXt", "GIF-comment", "trailing", "pre-SOI"

@dataclass
class Context:
    """Context about the file given to each detector (buffer, detected type, etc)"""
    buffer: bytes
    detection: Detection
    path: Path
    errors: list[str] = field(default_factory=list)
    image_regions: list[Region] | None = None
