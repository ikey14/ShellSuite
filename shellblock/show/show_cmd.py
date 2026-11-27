"""``block show``: un resultado (y su score) como bloque de ancho fijo."""

from __future__ import annotations

import argparse
import json
import sys

from shellblock import store
from shellblock.score import scoring

KIND = "show"

EVIDENCE_WIDTH = 60
TOP_FINDINGS = 5


def Register(actions: argparse._SubParsersAction) -> None:
    """Registra ``block show``."""
    parser = actions.add_parser(KIND, help="render one result and its score")
    parser.add_argument("--file", required=True, metavar="NAME",
                        help="target name (or path) already analysed")
    parser.add_argument("--all", action="store_true",
                        help=f"show every finding instead of the top {TOP_FINDINGS} by weight")
    parser.add_argument("--json", action="store_true", help="machine-readable JSON")
    parser.set_defaults(handler=Run)


def Run(args: argparse.Namespace) -> int:
    """Imprime el bloque y devuelve el código de salida (1 si falta el resultado)."""
    name = args.file
    try:
        result = store.read_result(name)
    except store.StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(f"hint: run 'shellsuite block analyze --file {name}'", file=sys.stderr)
        return 1

    try:
        score = store.read_score(name)
    except store.StoreError:
        score = None

    if args.json:
        print(json.dumps({"result": result, "score": score}, indent=2, ensure_ascii=False))
        return 0

    for line in render(result, score, show_all=args.all):
        print(line)
    return 0


def render(result: dict, score: dict | None, show_all: bool = False) -> list[str]:
    """Líneas del bloque: target, stages, findings y score.

    Por defecto solo se listan las ``TOP_FINDINGS`` reglas que más puntos aportan;
    ``show_all`` lista todos los findings del resultado.
    """
    target = result.get("target", {})
    lines = [f"{target.get('name')}"]

    lines.append(
        f"  target     {target.get('detected_type')}, {target.get('size')} bytes, "
        f"sha256 {str(target.get('sha256'))[:12]}…"
        f"{', truncated' if target.get('truncated') else ''}"
        f"{', extension contradicts the magic bytes' if target.get('type_mismatch') else ''}"
    )
    lines.append(f"  source     {target.get('path')}  ({target.get('analyzed_at')})")
    lines.append(f"  stages     {_stages(result.get('stages', []))}")

    findings = result.get("findings", [])
    ranked = _rank(findings)
    shown = ranked if show_all else ranked[:TOP_FINDINGS]
    rules = sorted({finding.get("rule_id") for finding in findings})
    header = f"  findings   {len(findings)} ({len(rules)} rule(s))"
    if len(shown) < len(findings):
        header += f", top {TOP_FINDINGS} by weight"
    lines.append(header)
    for finding in shown:
        lines.append(
            "    {rule:<30} {severity:<9} @{offset:<6} {subject:<34} {evidence}".format(
                rule=finding.get("rule_id", ""),
                severity=finding.get("severity", ""),
                offset=finding.get("location", {}).get("offset", 0),
                subject=str(finding.get("subject", ""))[:34],
                evidence=_evidence(finding.get("evidence", "")),
            ).rstrip()
        )
    hidden = len(findings) - len(shown)
    if hidden:
        lines.append(f"    … {hidden} more finding(s), use --all to list them")

    if result.get("errors"):
        lines.append(f"  errors     {'; '.join(result['errors'])[:200]}")
    for note in result.get("notes", []):
        lines.append(f"  note       {note[:200]}")

    lines.extend(render_score(score))
    return lines


def _stages(stages: list[dict]) -> str:
    parts = []
    for stage in stages:
        counters = []
        if stage.get("rules") is not None:
            counters.append(f"{stage.get('matched')}/{stage.get('rules')} rules")
        if stage.get("units") is not None:
            units = stage.get("units")
            counters.append(f"{units} unit" + ("" if units == 1 else "s"))
        if stage.get("frames") is not None:
            counters.append(f"{stage.get('kept')}/{stage.get('frames')} frames")
        suffix = f" ({', '.join(counters)})" if counters else ""
        parts.append(f"{stage.get('name')} {stage.get('duration_ms')} ms{suffix}")
    return " · ".join(parts)


def render_score(score: dict | None) -> list[str]:
    """Bloque de score con la puntuación al final y separada del detalle."""
    if score is None:
        return ["  score      not scored yet — run 'block score'"]
    breakdown = score.get("breakdown", {})
    contributions = score.get("contributions", [])
    lines = ["  contributions"]
    for item in contributions:
        lines.append(
            f"    {item.get('rule_id'):<28} {item.get('points'):>3} ×{item.get('count'):<3}"
            f"{item.get('title')}"
        )
    if not contributions:
        lines.append("    none")
    categories = " · ".join(
        f"{name} {points}" for name, points in breakdown.get("by_category", {}).items()
    )
    corroboration = breakdown.get("corroboration", 0)
    capped = " · capped" if breakdown.get("capped") else ""
    lines.append(f"  categories {categories or 'none'} · corroboration +{corroboration}{capped}")
    lines.append(
        f"  ruleset    {score.get('ruleset')} · raw {score.get('raw_points')}"
    )
    lines.append("")
    lines.append("  " + "-" * 58)
    lines.append(f"  SCORE  {score.get('score')}/100 ({score.get('score')} %)")
    lines.append("  " + "-" * 58)
    return lines


def _rank(findings: list[dict]) -> list[dict]:
    """Ordena por peso de la regla: las que suman puntos primero, luego por id y offset."""
    from shellblock.rules import LoadRules

    points = {rule["id"]: rule["points"] for rule in LoadRules()}
    return sorted(
        findings,
        key=lambda finding: (
            -points.get(finding.get("rule_id"), 0),
            finding.get("rule_id") or "",
            int(finding.get("location", {}).get("offset", 0)),
        ),
    )


def _evidence(text: str) -> str:
    """La evidencia ya viene escapada; a la tabla solo se le pone un tope de ancho."""
    return text if len(text) <= EVIDENCE_WIDTH else text[: EVIDENCE_WIDTH - 1] + "…"
