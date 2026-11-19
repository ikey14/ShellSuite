"""Etapa de firmas: un único emparejador, guiado por rules.json."""

from __future__ import annotations
import re
from shellblock.result import Finding, escape_evidence

_PATTERNS: dict[tuple[str, str], re.Pattern] = {}

def run_signatures(buffer: bytes, rules: list[dict]) -> list[Finding]:
    """Searches the file buffer (up to max size) to see if any
    signatures are found in it, and reports findings
    """
    text = buffer.decode("latin-1") if _needs_text(rules) else ""
    findings: list[Finding] = []

    for rule in rules:
        pattern = _compile(rule)
        haystack = buffer if rule["scope"] == "bytes" else text
        for match in pattern.finditer(haystack):
            findings.append(_finding(rule, buffer, match.start(), match.end()))

    return findings


def _needs_text(rules: list[dict]) -> bool:
    """True if any of the rules to be applied has text scope (their pattern ain't work on raw bytes)"""
    return any(rule["scope"] == "text" for rule in rules)


def _compile(rule: dict) -> re.Pattern:
    """Compiles patterns (same way as rule validator) and caches them so they don't
    need to be recomputed constantly
    """
    key = (rule["scope"], rule["pattern"])
    pattern = _PATTERNS.get(key)

    if pattern is None:
        if rule["scope"] == "bytes":
            pattern = re.compile(rule["pattern"].encode("ascii"))
        else:
            pattern = re.compile(rule["pattern"], re.IGNORECASE)
        _PATTERNS[key] = pattern

    return pattern


def _finding(rule: dict, buffer: bytes, start: int, end: int) -> Finding:
    """Puts the signature match given into the Finding format"""
    return Finding(
        rule_id=rule["id"],
        subject="file",
        severity=rule["severity"],
        location={"kind": "byte_offset", "offset": start},
        evidence=escape_evidence(buffer[start:end]),
        detail={"scope": rule["scope"], "length": end - start},
    )
