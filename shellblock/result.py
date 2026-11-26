"""Result contract (schema 1): findings, stages and the JSON shape."""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from shellsuite import __version__

SCHEMA = 1
TOOL_NAME = "shellblock"
EVIDENCE_LIMIT = 120


def escape_evidence(raw: bytes) -> str:
    """Printable ASCII, everything else as \\xNN; at most 120 characters."""
    chunks: list[str] = []
    length = 0
    for byte in raw:
        chunk = chr(byte) if 0x20 <= byte <= 0x7E else f"\\x{byte:02x}"
        if length + len(chunk) > EVIDENCE_LIMIT:
            break
        chunks.append(chunk)
        length += len(chunk)
    return "".join(chunks)


@dataclass(frozen=True)
class Finding:
    """One flat finding, shaped exactly like contract section 4."""

    rule_id: str
    subject: str
    severity: str
    location: dict[str, object]
    evidence: str
    detail: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "subject": self.subject,
            "severity": self.severity,
            "location": self.location,
            "evidence": self.evidence,
            "detail": self.detail,
        }


def sort_key(finding: Finding, category: str) -> tuple[str, int, str]:
    """Contract order: (category, location.offset, rule_id)."""
    return (category, int(finding.location.get("offset", 0)), finding.rule_id)


@dataclass(frozen=True)
class Stage:
    """One pipeline stage; counters are omitted from the JSON when unused."""

    name: str
    status: str
    duration_ms: int
    rules: int | None = None
    matched: int | None = None
    units: int | None = None
    frames: int | None = None
    kept: int | None = None

    def to_dict(self) -> dict[str, object]:
        data: dict[str, object] = {
            "name": self.name,
            "status": self.status,
            "duration_ms": self.duration_ms,
        }
        for key in ("rules", "matched", "units", "frames", "kept"):
            value = getattr(self, key)
            if value is not None:
                data[key] = value
        return data


@dataclass
class Result:
    """One analysis result: the only thing `score` is allowed to read."""

    target: dict[str, object]
    stages: list[Stage]
    findings: list[Finding]
    notes: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "tool": {"name": TOOL_NAME, "version": __version__},
            "target": self.target,
            "stages": [stage.to_dict() for stage in self.stages],
            "findings": [finding.to_dict() for finding in self.findings],
            "notes": self.notes,
            "errors": self.errors,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
