"""Score de ShellBlock (schema 1): pesos desde ``rules.json``, nunca desde el fichero."""

from __future__ import annotations
import hashlib
from collections import Counter
from pathlib import Path

from shellblock import store
from shellblock.helpers.jsonLoader import load_json
from shellblock.result import SCHEMA
from shellblock.rules import LoadRules

SCORE_SCHEMA = 1
SCORE_CAP = 100
CORROBORATION_STEP = 10
CORROBORATION_CAP = 20
TOP_CONTRIBUTIONS = 3

_RULES_FILE = Path(__file__).resolve().parent.parent / "rules.json"


class ScoreError(Exception):
    """El resultado no se puede puntuar: schema desconocido o ``rule_id`` sin regla."""


def ruleset() -> str:
    """``version`` de la tabla + los primeros 8 hex del sha256 de ``rules.json``."""
    digest = hashlib.sha256(_RULES_FILE.read_bytes()).hexdigest()[:8]
    return f"{load_json('rules.json')['version']}+{digest}"


def compute(result: dict, rules: list[dict] | None = None) -> dict:
    """Construye el score file a partir de un result file ya cargado.

    Solo cuentan las reglas con ``points > 0``, una vez por regla por muchas veces
    que haya disparado. El bonus de corroboración nunca supera los 20 puntos.
    """
    if result.get("schema") != SCHEMA:
        raise ScoreError(f"unsupported result schema: {result.get('schema')!r}")

    table = {rule["id"]: rule for rule in (rules if rules is not None else LoadRules())}
    counts = Counter(finding["rule_id"] for finding in result.get("findings", []))

    unknown = sorted(rule_id for rule_id in counts if rule_id not in table)
    if unknown:
        raise ScoreError(f"unknown rule_id(s) in the result: {', '.join(unknown)}")

    weights = {
        rule_id: table[rule_id]["points"]
        for rule_id in counts
        if table[rule_id]["points"] > 0
    }
    by_category: dict[str, int] = {}
    for rule_id, points in sorted(weights.items()):
        category = table[rule_id]["category"]
        by_category[category] = by_category.get(category, 0) + points

    corroboration = (
        min(CORROBORATION_CAP, CORROBORATION_STEP * (len(by_category) - 1))
        if by_category
        else 0
    )
    raw_points = sum(weights.values()) + corroboration

    ranked = sorted(weights.items(), key=lambda item: (-item[1], item[0]))
    contributions = [
        {
            "rule_id": rule_id,
            "title": table[rule_id]["title"],
            "points": points,
            "count": counts[rule_id],
        }
        for rule_id, points in ranked[:TOP_CONTRIBUTIONS]
    ]

    target = result.get("target", {})
    return {
        "schema": SCORE_SCHEMA,
        "target": {"name": target.get("name"), "sha256": target.get("sha256")},
        "score": min(SCORE_CAP, raw_points),
        "raw_points": raw_points,
        "ruleset": ruleset(),
        "contributions": contributions,
        "breakdown": {
            "by_category": by_category,
            "corroboration": corroboration,
            "capped": raw_points > SCORE_CAP,
        },
    }


def score_target(target_name: str) -> tuple[dict, dict]:
    """Lee el result file de ``target_name``, lo puntúa y escribe el score file."""
    result = store.read_result(target_name)
    payload = compute(result)
    store.write_score(payload)
    return result, payload
