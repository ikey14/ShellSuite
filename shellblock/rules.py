"""Rule table: loading, validation and the detector registry."""

from __future__ import annotations

import re

from shellblock.helpers.jsonLoader import load_json

# Populated by the static stage: structural rule id -> detector function.
DETECTORS: dict = {}

_BASE_FIELDS = (
    "id",
    "kind",
    "title",
    "category",
    "points",
    "severity",
    "applies_to",
    "rationale",
)
_REQUIRED_FIELDS = {
    "signature": _BASE_FIELDS + ("scope", "pattern"),
    "structural": _BASE_FIELDS,
}
_TYPES = {"jpeg", "png", "gif", "php", "pcap", "upload", "unknown"}
_SCOPES = {"bytes", "text"}


def LoadRules() -> list[dict]:
    """Return the rule entries declared in rules.json."""
    return load_json("rules.json")["rules"]


def ValidateRules(data: dict | None = None) -> list[str]:
    """Validate the rule table; return the errors (empty means valid)."""
    if data is None:
        data = load_json("rules.json")
    if not isinstance(data, dict):
        return ["table: the top level must be a JSON object"]

    errors: list[str] = []

    version = data.get("version")
    if not isinstance(version, str) or not version.strip():
        errors.append("table: 'version' missing or empty")

    categories = data.get("categories")
    if not isinstance(categories, dict) or not categories:
        errors.append("table: 'categories' must be a non-empty object")
        categories = {}

    rules = data.get("rules")
    if not isinstance(rules, list):
        return errors + ["table: 'rules' must be a list"]

    seen: set[str] = set()
    for position, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            errors.append(f"rule #{position}: not a JSON object")
            continue

        raw_id = rule.get("id")
        label = raw_id if isinstance(raw_id, str) and raw_id else f"rule #{position}"
        if not isinstance(raw_id, str) or not raw_id.strip():
            errors.append(f"{label}: 'id' missing or empty")
        elif raw_id in seen:
            errors.append(f"{label}: duplicate id")
        else:
            seen.add(raw_id)

        kind = rule.get("kind")
        if kind not in _REQUIRED_FIELDS:
            errors.append(
                f"{label}: 'kind' must be one of {sorted(_REQUIRED_FIELDS)}"
            )
            continue

        missing = [field for field in _REQUIRED_FIELDS[kind] if field not in rule]
        if missing:
            errors.append(f"{label}: missing fields: {', '.join(missing)}")

        if "category" in rule and rule["category"] not in categories:
            errors.append(f"{label}: unknown category {rule['category']!r}")

        if "points" in rule:
            points = rule["points"]
            if not isinstance(points, int) or isinstance(points, bool) or points < 0:
                errors.append(f"{label}: 'points' must be an integer >= 0")
            elif points == 0 and kind != "signature":
                errors.append(
                    f"{label}: points 0 is reserved for signature rules"
                )

        if "applies_to" in rule and not _is_type_list(rule["applies_to"]):
            errors.append(f"{label}: 'applies_to' is not a list of known types")

        if kind == "signature" and "scope" in rule and "pattern" in rule:
            scope = rule["scope"]
            if scope not in _SCOPES:
                errors.append(f"{label}: 'scope' must be one of {sorted(_SCOPES)}")
            else:
                problem = _compile_problem(rule["pattern"], scope)
                if problem:
                    errors.append(f"{label}: pattern does not compile ({problem})")

    structural_ids = {
        rule.get("id")
        for rule in rules
        if isinstance(rule, dict)
        and rule.get("kind") == "structural"
        and isinstance(rule.get("id"), str)
    }
    for rule_id in sorted(set(DETECTORS) - structural_ids):
        errors.append(f"{rule_id}: in DETECTORS without a structural rule")
    for rule_id in sorted(structural_ids - set(DETECTORS)):
        errors.append(f"{rule_id}: structural rule without a detector")

    return errors


def _is_type_list(value: object) -> bool:
    """True when ``value`` is a non-empty list of detected types."""
    return (
        isinstance(value, list)
        and bool(value)
        and all(isinstance(item, str) for item in value)
        and set(value) <= _TYPES
    )


def _compile_problem(pattern: object, scope: str) -> str | None:
    """Compile with the matcher's own encoding; return the error, if any."""
    if not isinstance(pattern, str) or not pattern:
        return "empty or non-text pattern"
    try:
        if scope == "bytes":
            re.compile(pattern.encode("ascii"))
        else:
            re.compile(pattern, re.IGNORECASE)
    except (re.error, UnicodeEncodeError) as exc:
        return str(exc)
    return None
