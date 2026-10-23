"""CLI-owned registry of known webshells.

A versioned JSON file (``~/.shellsuite/registry.json`` by default) holding one
record per deployed webshell. Records are keyed by URL on upsert, so
re-connecting updates ``last_used`` instead of creating duplicates. Only whether
a credential exists is stored (``has_secret``); the secret itself is not.
"""

from __future__ import annotations

import json
import os
import tempfile
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from shellsuite import config

REGISTRY_VERSION = 1

ORDER_FIELDS: tuple[str, ...] = (
    "name",
    "url",
    "vector",
    "mode",
    "has_secret",
    "created_at",
    "last_used",
)
DATE_FIELDS: tuple[str, ...] = ("created_at", "last_used")
FILTER_OPS: tuple[str, ...] = ("==", "!=", "contains")


class RegistryError(Exception):
    """Raised for unreadable/invalid registry state or invalid query input."""


@dataclass(frozen=True)
class ShellRecord:
    id: str
    url: str
    vector: str
    mode: str
    has_secret: bool
    created_at: str
    last_used: str
    name: str | None = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "url": self.url,
            "vector": self.vector,
            "mode": self.mode,
            "has_secret": self.has_secret,
            "created_at": self.created_at,
            "last_used": self.last_used,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ShellRecord":
        try:
            return cls(
                id=str(data["id"]),
                url=str(data["url"]),
                vector=str(data["vector"]),
                mode=str(data["mode"]),
                has_secret=bool(data.get("has_secret", False)),
                created_at=str(data["created_at"]),
                last_used=str(data["last_used"]),
                name=data.get("name"),
            )
        except (KeyError, TypeError) as exc:
            raise RegistryError(f"invalid shell record: {exc}") from exc


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _field_value(record: ShellRecord, field: str) -> str:
    if field == "name":
        return record.name or record.url
    if field == "has_secret":
        return "true" if record.has_secret else "false"
    return str(getattr(record, field))


def _sort_key(record: ShellRecord, field: str) -> str:
    value = _field_value(record, field)
    return value.lower() if field in ("name", "url") else value


def parse_filter(expression: str) -> tuple[str, str, str]:
    """Parse ``"attr op value"`` into ``(attr, op, value)``."""
    parts = expression.split(None, 2)
    if len(parts) != 3:
        raise RegistryError(
            f"invalid --filter: {expression!r} (expected 'attr op value')"
        )
    attr, op, value = parts
    if attr not in ORDER_FIELDS:
        raise RegistryError(f"invalid --filter attribute: {attr!r}")
    if op not in FILTER_OPS:
        raise RegistryError(f"invalid --filter operator: {op!r} (use ==, !=, contains)")
    return attr, op, value


def _matches(record: ShellRecord, flt: tuple[str, str, str]) -> bool:
    attr, op, value = flt
    actual = _field_value(record, attr)
    if op == "contains":
        return value.lower() in actual.lower()
    if op == "==":
        return actual == value
    return actual != value


class Registry:
    """Load/query/save the registry file."""

    def __init__(self, path: Path | str | None = None):
        self.path = Path(path) if path is not None else config.registry_path()
        self.shells: list[ShellRecord] = []

    def load(self) -> None:
        if not self.path.exists():
            self.shells = []
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RegistryError(f"cannot read registry {self.path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise RegistryError(f"invalid registry {self.path}: expected an object")

        version = raw.get("version", REGISTRY_VERSION)
        if not isinstance(version, int) or version > REGISTRY_VERSION:
            raise RegistryError(
                f"registry version {version!r} is not supported "
                f"(max {REGISTRY_VERSION})"
            )

        records = raw.get("shells", [])
        if not isinstance(records, list):
            raise RegistryError(f"invalid registry {self.path}: 'shells' must be a list")
        self.shells = [ShellRecord.from_dict(item) for item in records]

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": REGISTRY_VERSION,
            "shells": [record.to_dict() for record in self.shells],
        }
        text = json.dumps(payload, indent=2) + "\n"

        handle, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".registry-", suffix=".tmp"
        )
        try:
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(text)
            os.replace(tmp_name, self.path)
        except OSError:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
            raise

    def upsert(
        self,
        *,
        url: str,
        vector: str,
        mode: str,
        has_secret: bool,
        name: str | None = None,
        now: str | None = None,
    ) -> ShellRecord:
        """Insert a new shell or update the one with the same URL."""
        now = now or _now_iso()
        for index, record in enumerate(self.shells):
            if record.url == url:
                updated = ShellRecord(
                    id=record.id,
                    url=record.url,
                    vector=vector,
                    mode=mode,
                    has_secret=has_secret,
                    created_at=record.created_at,
                    last_used=now,
                    name=name if name is not None else record.name,
                )
                self.shells[index] = updated
                return updated

        record = ShellRecord(
            id=uuid.uuid4().hex,
            url=url,
            vector=vector,
            mode=mode,
            has_secret=has_secret,
            created_at=now,
            last_used=now,
            name=name,
        )
        self.shells.append(record)
        return record

    def all(self) -> list[ShellRecord]:
        return list(self.shells)

    def query(
        self,
        *,
        order: str = "last_used",
        descending: bool = True,
        filters: tuple[str, ...] = (),
    ) -> list[ShellRecord]:
        if order not in ORDER_FIELDS:
            raise RegistryError(f"invalid --order: {order!r}")
        parsed = [parse_filter(item) for item in filters]

        selected = [
            record
            for record in self.shells
            if all(_matches(record, flt) for flt in parsed)
        ]
        selected.sort(key=lambda record: (record.url.lower(), record.id))
        selected.sort(key=lambda record: _sort_key(record, order), reverse=descending)
        return selected
