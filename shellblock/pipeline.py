"""Pipeline de análisis: detect -> signature -> un único Result."""

from __future__ import annotations
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from shellblock.analyze.context import Context
from shellblock.analyze.signatures import run_signatures
from shellblock.detect import detect
from shellblock.result import Finding, Result, Stage, sort_key
from shellblock.rules import DETECTORS, LoadRules, signature_rules, structural_rules

DEFAULT_MAX_SIZE = 64 * 1024 * 1024

def analyze(
    path: Path,
    max_size: int = DEFAULT_MAX_SIZE,
    *,
    hosts: list[str] | None = None,
    keep_objects: str | bool | None = None,
    dump_json: bool = False,
    allow_capture: bool = True,
    from_body: bool = False,
) -> Result:
    """Executes the applicable analysis stages (magic detection, signature matching, static analysis) to the 
    file on the path, and returns the result in Result format

    ``from_body`` marks a body carved whole out of a capture: tshark names those
    after the request URI, so the name is not a claim and the type comes from the
    magic bytes alone (see ``detect``).
    """
    started = time.perf_counter()
    detection = detect(path, extension_claims=not from_body)
    detect_ms = _elapsed(started)

    if detection.detected_type == "pcapng":
        from shellblock.analyze.capture_static import CaptureError

        raise CaptureError(
            f"{path.name} is a pcapng capture; save it as Wireshark/tcpdump pcap"
        )

    if allow_capture and detection.detected_type == "pcap":
        from shellblock.analyze import capture_static

        return capture_static.analyze(
            path,
            detection,
            max_size,
            list(hosts or []),
            keep_objects,
            dump_json,
            detect_ms,
        )

    buffer, truncated = _read_capped(path, max_size, detection.size)
    notes = []
    if truncated:
        notes.append(
            f"file truncated at {max_size} bytes "
            f"(sha256 covers the analyzed prefix)"
        )

    rules = signature_rules(detection.detected_type)
    started = time.perf_counter()
    findings = run_signatures(buffer, rules)
    signature_ms = _elapsed(started)
    signature_matched = len({finding.rule_id for finding in findings})

    static_set = structural_rules(detection.detected_type)
    context = Context(buffer=buffer, detection=detection, path=path)
    started = time.perf_counter()
    static_findings = [
        finding
        for rule in static_set
        for finding in DETECTORS[rule["id"]](context, rule)
    ]
    static_ms = _elapsed(started)
    
    findings.extend(static_findings)
    _sort(findings)
    
    static_stage = (
        Stage(
            "static",
            "ok",
            static_ms,
            rules=len(static_set),
            matched=len({finding.rule_id for finding in static_findings}),
            units=1,
        )
        if static_set
        else Stage("static", "skipped", static_ms)
    )


    return Result(
        target={
            "path": str(path.resolve()),
            "name": path.name,
            "size": detection.size,
            "sha256": hashlib.sha256(buffer).hexdigest(),
            "extension": detection.extension,
            "detected_type": detection.detected_type,
            "type_mismatch": detection.type_mismatch,
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "truncated": truncated,
        },
        stages=[
            Stage("detect", "ok", detect_ms),
            Stage("signature", "ok", signature_ms, rules=len(rules), matched=signature_matched),
            static_stage
        ],
        findings=findings,
        notes=notes,
        errors=list(context.errors)
    )


def _read_capped(path: Path, max_size: int, size: int) -> tuple[bytes, bool]:
    """Reads up to max size of the file on the path, also returns indication of truncation (or not)"""
    with path.open("rb") as handle:
        return handle.read(max_size), size > max_size

    
def _sort(findings: list[Finding]) -> None:
    """Sorts finding by category, then offset, then rule id"""
    categories = {rule["id"]: rule["category"] for rule in LoadRules()}
    findings.sort(key=lambda finding: sort_key(finding, categories[finding.rule_id]))


def _elapsed(started: float) -> int:
    """ms between given time and current time"""
    return int((time.perf_counter() - started) * 1000)
