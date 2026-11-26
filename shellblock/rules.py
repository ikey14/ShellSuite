"""Rule table: loading, validation and the detector registry."""

from __future__ import annotations

import re

from shellblock.helpers.jsonLoader import load_json
from shellblock.analyze import capture_static, image_static, php_static

# Populated by the static stage: structural rule id -> detector function.
DETECTORS: dict = {
    "IMG_PHP_BEFORE_SOI": image_static.find_php_before_soi,
    "IMG_HIDDEN_PHP": image_static.find_hidden_php,
    "IMG_SCRIPT_IN_SEGMENT": image_static.find_script_in_segment,
    "IMG_ZIP_AFTER_EOI": image_static.find_zip_after_eoi,
    "IMG_TRAILING_DATA": image_static.find_trailing_data,
    "TYPE_MAGIC_MISMATCH": image_static.find_type_mismatch,
    "DOUBLE_EXTENSION": image_static.find_double_extension,
    "PHP_EVAL_OF_INPUT": php_static.find_eval_of_input,
    "PHP_OS_EXEC_OF_INPUT": php_static.find_os_exec_of_input,
    "PHP_DYNAMIC_CALL_OF_INPUT": php_static.find_dynamic_call_of_input,
    "PHP_INCLUDE_OF_INPUT": php_static.find_include_of_input,
    "PHP_WRITE_OF_INPUT": php_static.find_write_of_input,
    "PHP_OBFUSCATION_LADDER": php_static.find_obfuscation_ladder,
    "PHP_KNOWN_FAMILY": php_static.find_known_family,
    "PHP_EXEC_SINK_ONLY": php_static.find_exec_sink_only,
    "PHP_AUTH_GATE": php_static.find_auth_gate,
    "PHP_REQUEST_HEADER_SOURCE": php_static.find_request_header_source,
    "PHP_BASE64_BLOB": php_static.find_base64_blob,
    "PHP_HIGH_ENTROPY": php_static.find_high_entropy,
    "PHP_ONE_LINER": php_static.find_one_liner,
    "PHP_PADDED_TAG": php_static.find_padded_tag,
    "PCAP_TLS_OPAQUE": capture_static.find_tls_opaque,
    "PCAP_DISGUISED_UPLOAD": capture_static.find_disguised_upload,
    "PCAP_PHP_UPLOAD": capture_static.find_php_upload,
    "PCAP_SHELL_REQUEST": capture_static.find_shell_request,
    "PCAP_COMMAND_PARAM": capture_static.find_command_param,
    "PCAP_SHELL_RESPONSE": capture_static.find_shell_response,
    "PCAP_MISMATCHED_UPLOAD_RESPONSE": capture_static.find_mismatched_upload_response,
    "PCAP_BEACONING": capture_static.find_beaconing,
}

_RULES: list = []

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
    if not _RULES:
        rules = load_json("rules.json")["rules"]
        for rule in rules:
            _RULES.append(rule)
    
    return _RULES


def signature_rules(detected_type: str) -> list[dict]:
    """Las reglas de firma cuyo ``applies_to`` cubre el tipo detectado."""
    return [
        rule
        for rule in LoadRules()
        if rule.get("kind") == "signature"
        and detected_type in rule.get("applies_to", ())
    ]

def structural_rules(detected_type: str) -> list[dict]:
    """Las reglas estructurales cuyo ``applies_to`` cubre el tipo detectado."""
    return [
        rule
        for rule in LoadRules()
        if rule.get("kind") == "structural"
        and detected_type in rule.get("applies_to", ())
    ]

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
