"""``block list``: el directorio de análisis como tabla, con ``shellsuite.filters``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shellblock import store
from shellsuite import config, filters

KIND = "list"

RESULTS_FIELDS: tuple[str, ...] = (
    "name",
    "detected_type",
    "extension",
    "size",
    "findings",
    "errors",
    "analyzed_at",
    "type_mismatch",
)
SCORES_FIELDS: tuple[str, ...] = (
    "name",
    "score",
    "raw_points",
    "categories",
    "ruleset",
    "capped",
    "sha256",
)

RESULTS_COLUMNS: tuple[str, ...] = (
    "name", "detected_type", "size", "findings", "errors", "analyzed_at",
)
SCORES_COLUMNS: tuple[str, ...] = (
    "name", "score", "raw_points", "categories", "ruleset",
)

_NUMERIC = {"size", "findings", "errors", "score", "raw_points", "categories"}
_DATE = {"analyzed_at"}


def results(
    *, order: str = "analyzed_at", descending: bool = True, filters_expr=()
) -> list[dict]:
    """Una fila por result file del directorio de análisis."""
    records = [
        _result_record(path, store.name_from_path(path, store.RESULT_SUFFIX))
        for path in store.result_files()
    ]
    return _query(records, RESULTS_FIELDS, order, descending, filters_expr)


def scores(
    *, order: str = "score", descending: bool = True, filters_expr=()
) -> list[dict]:
    """Una fila por score file; un resultado sin puntuar no aparece."""
    records = [
        _score_record(path, store.name_from_path(path, store.SCORE_SUFFIX))
        for path in store.score_files()
    ]
    return _query(records, SCORES_FIELDS, order, descending, filters_expr)


def render(records: list[dict], columns: tuple[str, ...]) -> str:
    """Tabla de ancho fijo; la última columna no se rellena."""
    header = [column.upper() for column in columns]
    rows = [[_text(record.get(column)) for column in columns] for record in records]
    widths = [
        max([len(header[index])] + [len(row[index]) for row in rows])
        for index in range(len(columns))
    ]
    lines = [_line(header, widths), _line(["-" * width for width in widths], widths)]
    lines.extend(_line(row, widths) for row in rows)
    return "\n".join(lines)


def Register(actions: argparse._SubParsersAction) -> None:
    """Registra ``block list results`` y ``block list scores``."""
    listing = actions.add_parser(KIND, help="list analysis results and scores")
    kinds = listing.add_subparsers(dest="kind", metavar="<results|scores>")

    for name, help_text, default_order in (
        ("results", "one row per analysed file", "analyzed_at"),
        ("scores", "one row per scored file", "score"),
    ):
        parser = kinds.add_parser(name, help=help_text)
        parser.add_argument(
            "--order", default=default_order, metavar="FIELD",
            help=f"sort field (default {default_order})",
        )
        direction = parser.add_mutually_exclusive_group()
        direction.add_argument(
            "--asc", dest="descending", action="store_false", help="ascending order"
        )
        direction.add_argument(
            "--desc", dest="descending", action="store_true",
            help="descending order (default)",
        )
        parser.add_argument(
            "--filter", action="append", default=[], metavar="EXPR",
            help="'attr op value' (repeatable, AND)",
        )
        parser.add_argument("--json", action="store_true", help="machine-readable JSON")
        parser.set_defaults(handler=Run, listing=name, descending=True)


def Run(args: argparse.Namespace) -> int:
    """Ejecuta el listado pedido y devuelve el código de salida."""
    try:
        if args.listing == "results":
            records = results(
                order=args.order,
                descending=args.descending,
                filters_expr=args.filter,
            )
            columns = RESULTS_COLUMNS
        else:
            records = scores(
                order=args.order,
                descending=args.descending,
                filters_expr=args.filter,
            )
            columns = SCORES_COLUMNS
    except (filters.FilterError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {"kind": args.listing, "count": len(records), "entries": records},
                indent=2,
                ensure_ascii=False,
            )
        )
        return 0
    if not records:
        directory = (
            config.score_dir() if args.listing == "scores" else config.analysis_dir()
        )
        print(f"no {args.listing} in {directory}")
        return 0
    print(render(records, columns))
    return 0


# --------------------------------------------------------------------------
# Filas y consulta
# --------------------------------------------------------------------------
def _result_record(path: Path, fallback_name: str) -> dict:
    data = store.read_analysis(path)
    target = data.get("target", {})
    return {
        "name": target.get("name") or fallback_name,
        "detected_type": target.get("detected_type"),
        "extension": target.get("extension"),
        "size": target.get("size"),
        "findings": len(data.get("findings", [])),
        "errors": len(data.get("errors", [])),
        "analyzed_at": target.get("analyzed_at"),
        "type_mismatch": target.get("type_mismatch"),
    }


def _score_record(path: Path, fallback_name: str) -> dict:
    data = store.read_analysis(path)
    breakdown = data.get("breakdown", {})
    target = data.get("target", {})
    return {
        "name": target.get("name") or fallback_name,
        "score": data.get("score"),
        "raw_points": data.get("raw_points"),
        "categories": len(breakdown.get("by_category", {})),
        "ruleset": data.get("ruleset"),
        "capped": breakdown.get("capped"),
        "sha256": target.get("sha256"),
    }


def _query(
    records: list[dict], fields, order: str, descending: bool, filters_expr
) -> list[dict]:
    if order not in fields:
        raise ValueError(f"invalid --order: {order!r}")
    parsed = [filters.parse(item, fields) for item in filters_expr]
    selected = [
        record for record in records if all(_matches(record, item) for item in parsed)
    ]
    ordered = sorted(selected, key=lambda record: str(record.get("name") or "").lower())
    ordered.sort(key=lambda record: _sort_key(record, order), reverse=descending)
    return ordered


def _matches(record: dict, parsed: tuple[str, str, str]) -> bool:
    attr, op, value = parsed
    return filters.matches(_text(record.get(attr)), op, value, date=attr in _DATE)


def _sort_key(record: dict, order: str):
    value = record.get(order)
    if order in _NUMERIC:
        return float("-inf") if value is None else float(value)
    return str(value or "").lower()


def _line(cells: list[str], widths: list[int]) -> str:
    return "  ".join(
        cell.ljust(widths[index]) if index < len(cells) - 1 else cell
        for index, cell in enumerate(cells)
    ).rstrip()


def _text(value: object) -> str:
    """Los filtros trabajan sobre texto: un booleano se compara como ``true``/``false``."""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)
