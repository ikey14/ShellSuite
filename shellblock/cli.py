"""ShellBlock CLI: `shellsuite block <action>`."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from shellblock import pipeline, store
from shellblock.analyze.capture_static import CaptureError
from shellblock.list import list_cmd
from shellblock.result import Result
from shellblock.score import scoring
from shellblock.show import show_cmd

from shellblock.rules import LoadRules, ValidateRules
from shellsuite import config

# The word the user types after `shellsuite` (the package is still `shellshock`).
COMMAND = "block"

def _CmdRules(args: argparse.Namespace) -> int:
    if args.validate:
        errors = ValidateRules()
        if args.json:
            print(json.dumps({"valid": not errors, "errors": errors}, indent=2))
            return 0 if not errors else 1
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
            return 1
        print("rules.json OK")
        return 0

    rules = LoadRules()
    if args.json:
        print(json.dumps({"rules": rules}, indent=2))
        return 0
    for rule in rules:
        print(f"{rule['id']} ({rule['kind']}): {rule['title']}")
    return 0


def _CmdScore(args: argparse.Namespace) -> int:
    """Puntúa un result file ya escrito; nunca abre el fichero original."""
    try:
        result, score = scoring.score_target(args.file)
    except store.StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            f"hint: run 'shellsuite block analyze --file {args.file}' first",
            file=sys.stderr,
        )
        return 1
    except scoring.ScoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(score, indent=2, ensure_ascii=False))
        return 0

    print(f"score: {score['score']}/100 ({score['score']} %)")
    for item in score["contributions"]:
        print(f"  {item['rule_id']:<32} {item['points']:>3} ×{item['count']}  {item['title']}")
    print(
        f"ruleset {score['ruleset']} · "
        f"{store.score_path(str(result['target']['name']))}"
    )
    return 0


def _CmdAnalyze(args: argparse.Namespace) -> int:
    path = Path(args.file).expanduser()

    if not path.is_file():
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    
    try:
        result = pipeline.analyze(
            path,
            max_size=args.max_size * 1024 * 1024,
            hosts=args.host,
            keep_objects=args.keep_objects,
            dump_json=args.dump_json,
        )
    except CaptureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    saved = store.write_result(result)

    score = None
    if args.score:
        try:
            _, score = scoring.score_target(str(result.target["name"]))
        except scoring.ScoreError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    
    if args.json:
        print(result.to_json())
        return 0
    
    _PrintSummary(result, saved)
    if score is not None:
        for line in show_cmd.render_score(score):
            print(line)
    return 0


def _PrintSummary(result: Result, saved: Path) -> None:
    target = result.target
    suffix = " (truncated)" if target["truncated"] else ""

    print(f"{target['name']}: {target['detected_type']}, {target['size']} bytes{suffix}")

    for stage in result.stages:
        if stage.frames is not None:
            print(f"  frames: {stage.kept or 0} of {stage.frames} kept for analysis")
    
    if target["type_mismatch"]:
        print(f"  extension .{target['extension']} contradicts the magic bytes")
    
    if not result.findings:
        print("  no findings")
    
    for finding in result.findings:
        offset = finding.location.get("offset", 0)
        print(f"  {finding.rule_id:<22} @{offset:<7} {finding.evidence}")
    
    for note in result.notes:
        print(f"note: {note}", file=sys.stderr)

    raw_points = scoring.compute(result.to_dict())["raw_points"]
    print(
        f"  {len(result.findings)} findings, {raw_points} raw points "
        f"→ run 'shellsuite block score --file {target['name']}'"
    )
    print(f"result: {saved}")


def register_parser(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(COMMAND, help="webshell detection and risk scoring")
    actions = parser.add_subparsers(dest="action", metavar="<action>")

    rules = actions.add_parser("rules", help = "list the rules applied on analysis")
    rules.add_argument("--validate", action = "store_true", help = "validate the rules")
    rules.add_argument("--json", action = "store_true", help = "machine-readable JSON")
    rules.set_defaults(handler = _CmdRules)

    analyze = actions.add_parser("analyze", help="analyse one file and write its result")
    analyze.add_argument("--file", required=True, help="file to analyse")
    analyze.add_argument("--json", action="store_true", help="print the result JSON")
    analyze.add_argument(
        "--max-size", type=int, default=64, metavar="MB",
        help="read at most MB megabytes (default 64)",
    )
    analyze.add_argument(
        "--host", action="append", default=[], metavar="IP",
        help="only analyse packets to/from IP (repeatable)",
    )
    analyze.add_argument(
        "--dump-json", action="store_true",
        help="save the normalised HTTP/TLS capture model",
    )
    analyze.add_argument(
        "--keep-objects", nargs="?", const=True, default=None, metavar="DIR",
        help="keep the objects carved from HTTP bodies (optionally in DIR)",
    )
    analyze.add_argument(
        "--score", action="store_true",
        help="score the result immediately (chains analyze + score)",
    )
    analyze.set_defaults(handler = _CmdAnalyze)

    score = actions.add_parser("score", help="score one analysis result")
    score.add_argument(
        "--file", required=True, metavar="NAME",
        help="target name (or path) already analysed",
    )
    score.add_argument("--json", action="store_true", help="print the score JSON")
    score.set_defaults(handler = _CmdScore)

    list_cmd.Register(actions)
    show_cmd.Register(actions)
