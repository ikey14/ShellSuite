"""Capture stage: filter with tshark, normalise with pyshark, carve bodies.

Only HTTP content is readable; TLS contributes the handshake SNI and nothing
else. Carved objects are analysed by the file pipeline and their findings are
reported with an ``upload:<name>`` subject. Communication rules run on the
normalised model (headers, bodies, timings).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import statistics
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

import pyshark
from pyshark.tshark.tshark import TSharkNotFoundException

from shellblock.analyze.context import Context
from shellblock.analyze.signatures import run_signatures
from shellblock.detect import Detection
from shellblock.result import Finding, Result, Stage, escape_evidence, sort_key
from shellsuite import config

_HTTP_FILTER = "(http.request or http.response)"
_TLS_FILTER = "tls.handshake.extensions_server_name"
_TSHARK_HINT = "install Wireshark and make sure tshark and capinfos are on PATH"

_SAMPLE_BYTES = 32768
_SHELL_REQUEST = re.compile(rb"\b(?:system|eval|assert)\s*\(|`|SSENC1\.")
_UID = re.compile(rb"uid=\d+\(")
_PASSWD = re.compile(rb"root:x:0:0")
_INDEX = re.compile(rb"Index of /")
_IIS = re.compile(rb"\[To Parent Directory\]")
_LS_LINE = re.compile(rb"(?m)^[bcdlps-][rwxstST-]{9}[.+@]?\s+\d+\s+\S+\s+\S+")
_WWW_DATA = re.compile(rb"www-data")
_QUERY_COMMAND = re.compile(r"(?:^|[?&])(cmd|c|exec|shell|action)=", re.IGNORECASE)
_SHELL_CHANNELS = {
    "shellshock",
    "shellshock_auth",
    "x-shellshock",
    "x-shellshock-auth",
}
_PHP_EXTENSIONS = {"php", "php3", "php4", "php5", "php7", "phtml", "phar"}
_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif"}


class CaptureError(RuntimeError):
    """The capture could not be read by tshark or pyshark."""


@dataclass(frozen=True)
class HttpMessage:
    """One packet the HTTP dissector recognised, reduced to the useful fields."""

    stream: int | None
    src: str | None
    src_port: int | None
    dst: str | None
    dst_port: int | None
    frame: int | None = None
    timestamp: float | None = None
    length: int | None = None
    head: str | None = None
    method: str | None = None
    uri: str | None = None
    full_uri: str | None = None
    cookie: str | None = None
    user_agent: str | None = None
    content_type: str | None = None
    content_length: int | None = None
    response_code: int | None = None


@dataclass(frozen=True)
class TlsFlow:
    """One encrypted flow, identified only by its endpoints and SNI."""

    stream: int | None
    src: str | None
    src_port: int | None
    dst: str | None
    dst_port: int | None
    sni: str | None


@dataclass(frozen=True)
class BodyInfo:
    """One carved request/response body with head/tail samples."""

    stream: int | None
    direction: str
    name: str
    size: int
    detected_type: str
    head: str
    tail: str
    truncated: bool


@dataclass(frozen=True)
class UploadInfo:
    """One file part of a multipart upload."""

    stream: int | None
    filename: str
    content_type: str
    size: int
    extension: str
    detected_type: str
    type_mismatch: bool
    is_php: bool


@dataclass(frozen=True)
class ResponseInfo:
    """One carved response body with head/tail samples."""

    stream: int | None
    status: int | None
    uri: str | None
    size: int
    detected_type: str
    head: str
    tail: str
    truncated: bool


@dataclass
class CaptureModel:
    """Normalised capture: HTTP packets, TLS flows, bodies and accounting."""

    messages: list[HttpMessage] = field(default_factory=list)
    tls: list[TlsFlow] = field(default_factory=list)
    bodies: list[BodyInfo] = field(default_factory=list)
    uploads: list[UploadInfo] = field(default_factory=list)
    responses: list[ResponseInfo] = field(default_factory=list)
    frames: int = 0
    kept: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": 1,
            "frames": self.frames,
            "kept": self.kept,
            "messages": [asdict(message) for message in self.messages],
            "tls": [asdict(flow) for flow in self.tls],
            "bodies": [asdict(body) for body in self.bodies],
            "uploads": [asdict(upload) for upload in self.uploads],
            "responses": [asdict(response) for response in self.responses],
        }


def read_capture(path: Path, hosts: list[str]) -> CaptureModel:
    """Read the HTTP subset and the TLS handshakes of ``path``."""
    frames = _total_frames(path)
    clause = _host_clause(hosts)
    messages = _http_messages(path, _HTTP_FILTER + clause)
    tls = _tls_flows(path, _TLS_FILTER + clause)
    return CaptureModel(messages=messages, tls=tls, frames=frames, kept=len(messages))


def analyze(
    path: Path,
    detection: Detection,
    max_size: int,
    hosts: list[str],
    keep_objects: str | bool | None,
    dump_json: bool,
    detect_ms: int,
) -> Result:
    """Analyse a capture: filter, normalise, carve and run both capture stages."""
    started = time.perf_counter()

    model = read_capture(path, hosts)
    notes: list[str] = []
    errors: list[str] = []

    if hosts:
        notes.append(f"host filter: {', '.join(hosts)}")
    else:
        servers = sorted(
            {
                f"{message.dst}:{message.dst_port}"
                for message in model.messages
                if message.method and message.dst
            }
        )
        if servers:
            notes.append("all hosts analysed; HTTP servers: " + ", ".join(servers[:8]))

    if model.tls:
        snis = sorted({flow.sni for flow in model.tls if flow.sni})
        notes.append(
            f"{len(model.tls)} encrypted flow(s)"
            + (f"; SNI: {', '.join(snis)}" if snis else "")
        )

    if dump_json:
        model_path = config.analysis_dir() / f"{path.name}_http.json"
        model_path.write_text(
            json.dumps(model.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        notes.append(f"HTTP model saved to {model_path}")

    directory, cleanup = _carve(
        path,
        sorted({message.stream for message in model.messages if message.stream is not None})
        if hosts
        else None,
        keep_objects,
    )
    try:
        object_findings, object_errors, objects, unmatched, body_signatures = (
            _collect_objects(directory, max_size, model)
        )
    finally:
        if cleanup:
            shutil.rmtree(directory, ignore_errors=True)
        else:
            notes.append(f"carved objects kept at {directory}")

    errors.extend(object_errors)
    if unmatched:
        notes.append(f"{unmatched} carved object(s) could not be linked to a stream")

    wire_findings, wire_signatures = _wire_signatures(model)

    context = Context(
        buffer=b"",
        detection=detection,
        path=path,
        capture_model=model,
    )
    from shellblock.rules import DETECTORS, signature_rules, structural_rules

    capture_rules = structural_rules(detection.detected_type)
    capture_findings = [
        finding
        for rule in capture_rules
        for finding in DETECTORS[rule["id"]](context, rule)
    ]
    findings = wire_findings + object_findings + capture_findings
    _sort(findings)

    signature_ruleset = signature_rules("pcap")
    signature_ids = wire_signatures | body_signatures
    static_ms = _elapsed(started)
    static_matched = len({finding.rule_id for finding in capture_findings})

    return Result(
        target={
            "path": str(path.resolve()),
            "name": path.name,
            "size": detection.size,
            "sha256": _sha256(path),
            "extension": detection.extension,
            "detected_type": detection.detected_type,
            "type_mismatch": detection.type_mismatch,
            "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "truncated": False,
        },
        stages=[
            Stage("detect", "ok", detect_ms),
            Stage(
                "signature",
                "ok",
                0,
                rules=len(signature_ruleset),
                matched=len(signature_ids),
            ),
            Stage(
                "static",
                "ok",
                static_ms,
                rules=len(capture_rules),
                matched=static_matched,
                units=1 + objects,
                frames=model.frames,
                kept=model.kept,
            ),
        ],
        findings=findings,
        notes=notes,
        errors=errors,
    )


# --------------------------------------------------------------------------
# Capture structural detectors (DETECTORS: rule_id -> function)
# --------------------------------------------------------------------------
def find_tls_opaque(ctx: Context, rule: dict) -> list[Finding]:
    """One finding per encrypted flow; the SNI is the only evidence available."""
    model = ctx.capture_model
    if model is None:
        return []
    return [
        _finding_span(
            rule,
            _flow_subject(flow.src, flow.src_port, flow.dst, flow.dst_port),
            0,
            escape_evidence((flow.sni or "TLS handshake").encode("latin-1")),
            {"sni": flow.sni, "encrypted": True},
            kind="stream",
        )
        for flow in model.tls
    ]


def find_php_upload(ctx: Context, rule: dict) -> list[Finding]:
    """A multipart part whose filename asks for PHP execution."""
    model = ctx.capture_model
    if model is None:
        return []
    hits: list[Finding] = []
    for upload in model.uploads:
        if upload.extension not in _PHP_EXTENSIONS:
            continue
        hits.append(
            _finding_span(
                rule,
                _upload_subject(model, upload),
                0,
                escape_evidence(upload.filename.encode("latin-1")),
                {
                    "stream": upload.stream,
                    "filename": upload.filename,
                    "size": upload.size,
                    "declared_type": upload.extension,
                },
            )
        )
    return hits


def find_disguised_upload(ctx: Context, rule: dict) -> list[Finding]:
    """An image-named part whose bytes are PHP or contradict the image claim."""
    model = ctx.capture_model
    if model is None:
        return []
    hits: list[Finding] = []
    for upload in model.uploads:
        declared_image = (
            upload.extension in _IMAGE_EXTENSIONS
            or upload.content_type.lower().startswith("image/")
        )
        if not declared_image:
            continue
        if not (upload.is_php or upload.type_mismatch or upload.detected_type == "php"):
            continue
        hits.append(
            _finding_span(
                rule,
                _upload_subject(model, upload),
                0,
                escape_evidence(upload.filename.encode("latin-1")),
                {
                    "stream": upload.stream,
                    "filename": upload.filename,
                    "declared_type": upload.extension,
                    "detected_type": upload.detected_type,
                    "is_php": upload.is_php,
                },
            )
        )
    return hits


def find_shell_request(ctx: Context, rule: dict) -> list[Finding]:
    """A request carrying command execution syntax or a ShellShock envelope."""
    model = ctx.capture_model
    if model is None:
        return []
    hits: list[Finding] = []
    for message in model.messages:
        if not message.method:
            continue
        buffers = [(_text_bytes(message.head), "http", "request-head")]
        buffers.extend(
            (_body_bytes(body), "byte_offset", "request-body")
            for body in model.bodies
            if body.stream == message.stream and body.direction == "request"
        )
        for buffer, kind, name in buffers:
            match = _SHELL_REQUEST.search(buffer)
            if match is None:
                continue
            hits.append(
                _finding_span(
                    rule,
                    _flow(message),
                    match.start(),
                    escape_evidence(buffer[match.start() : match.start() + 120]),
                    {
                        "stream": message.stream,
                        "frame": message.frame,
                        "uri": message.uri,
                        "buffer": name,
                    },
                    kind=kind,
                )
            )
            break
    return hits


def find_command_param(ctx: Context, rule: dict) -> list[Finding]:
    """A command-carrying query parameter on a PHP script."""
    model = ctx.capture_model
    if model is None:
        return []
    hits: list[Finding] = []
    for message in model.messages:
        if not message.method or not message.uri:
            continue
        parts = urlsplit(message.uri)
        if not parts.path.lower().endswith(".php"):
            continue
        if _QUERY_COMMAND.search(message.uri) is None:
            continue
        hits.append(
            _finding_span(
                rule,
                _flow(message),
                0,
                escape_evidence(message.uri.encode("latin-1")[:120]),
                {
                    "stream": message.stream,
                    "frame": message.frame,
                    "uri": message.uri,
                },
            )
        )
    return hits


def find_shell_response(ctx: Context, rule: dict) -> list[Finding]:
    """Command output or a directory listing in a response body."""
    model = ctx.capture_model
    if model is None:
        return []
    hits: list[Finding] = []
    for response in model.responses:
        buffer = _body_bytes(response)
        marker = _response_marker(buffer)
        if marker is None:
            continue
        if marker == b"www-data" and not _companion_signal(model, response.stream):
            continue
        hits.append(
            _finding_span(
                rule,
                _flow_from_stream(model, response.stream),
                0,
                escape_evidence(marker),
                {
                    "stream": response.stream,
                    "status": response.status,
                    "uri": response.uri,
                    "marker": marker.decode("latin-1"),
                },
            )
        )
    return hits


def find_mismatched_upload_response(ctx: Context, rule: dict) -> list[Finding]:
    """An upload answered 200 with a body echoing the uploaded filename."""
    model = ctx.capture_model
    if model is None:
        return []
    hits: list[Finding] = []
    for upload in model.uploads:
        if upload.stream is None:
            continue
        for response in model.responses:
            if response.stream != upload.stream or response.status != 200:
                continue
            if upload.filename.lower().encode("latin-1") not in _body_bytes(response).lower():
                continue
            hits.append(
                _finding_span(
                    rule,
                    _flow_from_stream(model, upload.stream),
                    0,
                    escape_evidence(upload.filename.encode("latin-1")),
                    {
                        "stream": upload.stream,
                        "filename": upload.filename,
                        "status": response.status,
                    },
                )
            )
            break
    return hits


def find_beaconing(ctx: Context, rule: dict) -> list[Finding]:
    """Five or more regular, similarly sized requests to one path."""
    model = ctx.capture_model
    if model is None:
        return []
    groups: dict[tuple[str, str], list[HttpMessage]] = {}
    for message in model.messages:
        if not message.method or not message.uri or not message.dst:
            continue
        path = urlsplit(message.uri).path
        groups.setdefault((message.dst, path), []).append(message)

    hits: list[Finding] = []
    for (_, path), messages in groups.items():
        if len(messages) < 5:
            continue
        stamps = sorted(
            message.timestamp for message in messages if message.timestamp is not None
        )
        lengths = [message.length for message in messages if message.length is not None]
        if len(stamps) < 5 or len(lengths) < 5:
            continue
        intervals = [later - earlier for earlier, later in zip(stamps, stamps[1:])]
        mean = statistics.mean(intervals)
        if mean <= 0:
            continue
        variation = statistics.pstdev(intervals) / mean
        if max(lengths) - min(lengths) > 16 or variation > 0.2:
            continue
        first = messages[0]
        hits.append(
            _finding_span(
                rule,
                _flow(first),
                0,
                escape_evidence(path.encode("latin-1")[:120]),
                {
                    "stream": first.stream,
                    "path": path,
                    "requests": len(messages),
                    "mean_interval": round(mean, 2),
                    "variation": round(variation, 3),
                    "length_min": min(lengths),
                    "length_max": max(lengths),
                },
            )
        )
    return hits


# --------------------------------------------------------------------------
# Signature stage
# --------------------------------------------------------------------------
def _wire_signatures(model: CaptureModel) -> tuple[list[Finding], set[str]]:
    from shellblock.rules import signature_rules

    rules = signature_rules("pcap")
    findings: list[Finding] = []
    matched: set[str] = set()
    for message in model.messages:
        if not message.head:
            continue
        buffer = message.head.encode("latin-1")
        segment = "request" if message.method else "response"
        for finding in run_signatures(buffer, rules):
            matched.add(finding.rule_id)
            findings.append(
                replace(
                    finding,
                    subject=_flow(message),
                    location={
                        "kind": "http",
                        "offset": finding.location.get("offset", 0),
                        "segment": segment,
                    },
                    detail={
                        "stream": message.stream,
                        "frame": message.frame,
                        "uri": message.uri,
                    },
                )
            )
    return findings, matched


# --------------------------------------------------------------------------
# Object collection and correlation
# --------------------------------------------------------------------------
def _collect_objects(
    directory: Path, max_size: int, model: CaptureModel
) -> tuple[list[Finding], list[str], int, int, set[str]]:
    from shellblock.pipeline import analyze as analyze_file
    from shellblock.rules import LoadRules

    rules_by_id = {rule["id"]: rule for rule in LoadRules()}
    findings: list[Finding] = []
    errors: list[str] = []
    matched: set[str] = set()
    count = 0
    unmatched = 0

    paths = [
        path
        for path in sorted(directory.iterdir())
        if path.is_file() and not path.name.startswith("_part")
    ]
    assignments = _assign_messages(paths, model.messages)

    for object_path in paths:
        data = object_path.read_bytes()[:max_size]
        message = assignments.get(object_path)
        if data.startswith(b"--"):
            parts = _multipart_parts(data)
            if parts:
                for index, (filename, content_type, content) in enumerate(parts):
                    safe_name = Path(filename).name or f"part{index}"
                    part_path = directory / f"_part{index}_{safe_name}"
                    part_path.write_bytes(content)
                    result = analyze_file(
                        part_path, max_size=max_size, allow_capture=False
                    )
                    findings.extend(
                        replace(finding, subject=f"upload:{filename}")
                        for finding in result.findings
                    )
                    errors.extend(
                        f"{filename}: {error}" for error in result.errors
                    )
                    target = result.target
                    safe_name = Path(filename).name or f"part{index}"
                    upload = UploadInfo(
                        stream=message.stream if message is not None else None,
                        filename=filename,
                        content_type=content_type,
                        size=len(content),
                        extension=Path(filename).suffix.lower().lstrip("."),
                        detected_type=str(target["detected_type"]),
                        type_mismatch=bool(target["type_mismatch"]),
                        is_php=content.lstrip().startswith(b"<?"),
                    )
                    model.uploads.append(upload)
                    missing = _missing_signatures(
                        rules_by_id,
                        upload.detected_type,
                        {"SIG_SS_ENVELOPE"},
                        content,
                        _flow_from_stream(model, upload.stream)
                        if upload.stream is not None
                        else f"upload:{safe_name}",
                        _flow_meta(message),
                    )
                    findings.extend(missing)
                    matched.update(finding.rule_id for finding in missing)
                    count += 1

                upload_rule = rules_by_id.get("SIG_UPLOAD_PART")
                if upload_rule is not None:
                    subject = f"upload:{parts[0][0]}" if parts[0][0] else f"upload:{object_path.name}"
                    for finding in run_signatures(data, [upload_rule]):
                        matched.add(finding.rule_id)
                        findings.append(
                            replace(
                                finding,
                                subject=subject,
                                detail={
                                    "stream": message.stream if message else None,
                                    "object": object_path.name,
                                },
                            )
                        )
                if message is not None:
                    model.bodies.append(
                        _body_info(message, "request", object_path, data, "unknown")
                    )
                continue

        result = analyze_file(object_path, max_size=max_size, allow_capture=False)
        findings.extend(
            replace(finding, subject=f"upload:{object_path.name}")
            for finding in result.findings
        )
        errors.extend(f"{object_path.name}: {error}" for error in result.errors)
        count += 1
        if message is None:
            unmatched += 1
            continue

        detected = str(result.target["detected_type"])
        if message.method:
            model.bodies.append(
                _body_info(message, "request", object_path, data, detected)
            )
            missing = _missing_signatures(
                rules_by_id,
                detected,
                {"SIG_SS_ENVELOPE"},
                data,
                _flow(message),
                _flow_meta(message),
            )
        else:
            model.responses.append(
                ResponseInfo(
                    stream=message.stream,
                    status=message.response_code,
                    uri=message.uri,
                    size=len(data),
                    detected_type=detected,
                    head=_head(data),
                    tail=_tail(data),
                    truncated=len(data) > 2 * _SAMPLE_BYTES,
                )
            )
            missing = _missing_signatures(
                rules_by_id,
                detected,
                {"SIG_SS_RESPONSE", "SIG_SS_ENVELOPE"},
                data,
                _flow(message),
                _flow_meta(message),
            )
        for finding in missing:
            matched.add(finding.rule_id)
        findings.extend(missing)
    return findings, errors, count, unmatched, matched


def _assign_messages(
    paths: list[Path], messages: list[HttpMessage]
) -> dict[Path, HttpMessage | None]:
    """Assign duplicate object names to duplicate messages in packet order."""
    buckets: dict[tuple[str, int, bool], list[Path]] = {}
    for path in paths:
        size = path.stat().st_size
        with path.open("rb") as handle:
            multipart = handle.read(2) == b"--"
        buckets.setdefault((_natural_name(path.name), size, multipart), []).append(path)

    assigned: dict[Path, HttpMessage | None] = {}
    for (name, size, multipart), group in buckets.items():
        candidates = [message for message in messages if message.content_length == size]
        if multipart:
            candidates = [
                message
                for message in candidates
                if message.method
                and (message.content_type or "").lower().startswith("multipart/form-data")
            ] or candidates
        else:
            candidates = [
                message for message in candidates if message.response_code is not None
            ] or candidates

        named = [
            message
            for message in candidates
            if name.lower()
            and (_uri_name(message.uri) or "").lower().startswith(name.lower())
        ]
        pool = sorted(named or candidates, key=lambda message: message.frame or 0)
        for path, message in zip(sorted(group, key=_suffix_index), pool):
            assigned[path] = message
        for path in sorted(group, key=_suffix_index)[len(pool) :]:
            assigned[path] = None
    return assigned


def _natural_name(name: str) -> str:
    return re.sub(r"\(\d+\)(?=(\.[^.]+)?$)", "", name)


def _suffix_index(path: Path) -> int:
    match = re.search(r"\((\d+)\)(?=(\.[^.]+)?$)", path.name)
    return int(match.group(1)) if match else 0


def _uri_name(uri: str | None) -> str:
    if not uri:
        return ""
    path = urlsplit(uri).path
    name = unquote(path.rsplit("/", 1)[-1])
    name = re.sub(r"\(\d+\)(?=\.[^.]+$)", "", name)
    return unquote(name)


def _multipart_parts(data: bytes) -> list[tuple[str, str, bytes]]:
    """File parts of a multipart/form-data body: filename, content type, bytes."""
    if not data.startswith(b"--"):
        return []
    line_end = data.find(b"\r\n")
    if line_end < 0:
        return []
    boundary = data[2:line_end]
    if not boundary:
        return []

    parts: list[tuple[str, str, bytes]] = []
    for chunk in data.split(b"--" + boundary)[1:]:
        if chunk.startswith(b"--"):
            break
        chunk = chunk.lstrip(b"\r\n")
        header_end = chunk.find(b"\r\n\r\n")
        if header_end < 0:
            continue
        headers = chunk[:header_end].decode("latin-1", "replace")
        body = chunk[header_end + 4 :]
        if body.endswith(b"\r\n"):
            body = body[:-2]
        match = re.search(r'filename="?([^";\r\n]+)', headers, re.IGNORECASE)
        if match is None:
            continue
        content_type = ""
        type_match = re.search(r"Content-Type:\s*([^\r\n;]+)", headers, re.IGNORECASE)
        if type_match is not None:
            content_type = type_match.group(1).strip()
        parts.append((match.group(1), content_type, body))
    return parts


def _missing_signatures(
    rules_by_id: dict,
    detected_type: str,
    rule_ids: set[str],
    data: bytes,
    subject: str,
    detail: dict,
) -> list[Finding]:
    rules = [
        rules_by_id[rule_id]
        for rule_id in sorted(rule_ids)
        if rule_id in rules_by_id
        and detected_type not in rules_by_id[rule_id].get("applies_to", ())
    ]
    if not rules:
        return []
    return [
        replace(
            finding,
            subject=subject,
            detail={**detail, "body_length": len(data)},
        )
        for finding in run_signatures(data, rules)
    ]


def _body_info(
    message: HttpMessage,
    direction: str,
    object_path: Path,
    data: bytes,
    detected_type: str,
) -> BodyInfo:
    return BodyInfo(
        stream=message.stream,
        direction=direction,
        name=object_path.name,
        size=len(data),
        detected_type=detected_type,
        head=_head(data),
        tail=_tail(data),
        truncated=len(data) > 2 * _SAMPLE_BYTES,
    )


def _head(data: bytes) -> str:
    return data[:_SAMPLE_BYTES].decode("latin-1")


def _tail(data: bytes) -> str:
    """Last sample bytes, shortened so the tail never overlaps the head."""
    remaining = len(data) - _SAMPLE_BYTES
    if remaining <= 0:
        return ""
    return data[-min(_SAMPLE_BYTES, remaining) :].decode("latin-1")


def _body_bytes(body: BodyInfo | ResponseInfo) -> bytes:
    """Head plus a non-overlapping tail; a body up to 2x the sample is complete."""
    head = body.head.encode("latin-1")
    if body.size <= _SAMPLE_BYTES:
        return head
    return head + body.tail.encode("latin-1")


# --------------------------------------------------------------------------
# Per-flow tshark / pyshark plumbing
# --------------------------------------------------------------------------
def _http_messages(path: Path, display_filter: str) -> list[HttpMessage]:
    messages: list[HttpMessage] = []
    capture = _open_capture(path, display_filter)
    try:
        for packet in capture:
            http = getattr(packet, "http", None)
            if http is None:
                continue
            tcp = getattr(packet, "tcp", None)
            ip = getattr(packet, "ip", None)
            payload = _tcp_payload(tcp)
            messages.append(
                HttpMessage(
                    stream=_as_int(getattr(tcp, "stream", None)),
                    src=getattr(ip, "src", None),
                    src_port=_as_int(getattr(tcp, "srcport", None)),
                    dst=getattr(ip, "dst", None),
                    dst_port=_as_int(getattr(tcp, "dstport", None)),
                    frame=_as_int(getattr(packet, "number", None)),
                    timestamp=_as_float(getattr(packet, "sniff_timestamp", None)),
                    length=len(payload) if payload else None,
                    head=_head_text(payload),
                    method=getattr(http, "request_method", None),
                    uri=getattr(http, "request_uri", None),
                    full_uri=getattr(http, "request_full_uri", None),
                    cookie=getattr(http, "cookie", None),
                    user_agent=getattr(http, "user_agent", None),
                    content_type=getattr(http, "content_type", None),
                    content_length=_as_int(getattr(http, "content_length", None)),
                    response_code=_as_int(getattr(http, "response_code", None)),
                )
            )
    finally:
        capture.close()
    return messages


def _tcp_payload(tcp) -> bytes:
    payload = getattr(tcp, "payload", None)
    if payload is None:
        return b""
    text = str(payload)
    try:
        return bytes.fromhex(text.replace(":", ""))
    except ValueError:
        return b""


def _head_text(payload: bytes) -> str | None:
    if not payload:
        return None
    head_end = payload.find(b"\r\n\r\n")
    head = payload[: head_end + 4] if head_end >= 0 else payload
    return head[:_SAMPLE_BYTES].decode("latin-1")


def _tls_flows(path: Path, display_filter: str) -> list[TlsFlow]:
    flows: dict[int, TlsFlow] = {}
    capture = _open_capture(path, display_filter)
    try:
        for packet in capture:
            tls = getattr(packet, "tls", None)
            sni = getattr(tls, "handshake_extensions_server_name", None)
            if sni is None:
                continue
            tcp = getattr(packet, "tcp", None)
            ip = getattr(packet, "ip", None)
            stream = _as_int(getattr(tcp, "stream", None))
            key = stream if stream is not None else id(packet)
            flows[key] = TlsFlow(
                stream=stream,
                src=getattr(ip, "src", None),
                src_port=_as_int(getattr(tcp, "srcport", None)),
                dst=getattr(ip, "dst", None),
                dst_port=_as_int(getattr(tcp, "dstport", None)),
                sni=sni,
            )
    finally:
        capture.close()
    return list(flows.values())


def _open_capture(path: Path, display_filter: str):
    try:
        return pyshark.FileCapture(
            str(path),
            display_filter=display_filter,
            keep_packets=False,
        )
    except (TSharkNotFoundException, FileNotFoundError, OSError) as exc:
        raise CaptureError(f"tshark is unavailable ({exc}); {_TSHARK_HINT}") from exc


def _total_frames(path: Path) -> int:
    try:
        completed = subprocess.run(
            ["capinfos", "-c", "-M", str(path)],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise CaptureError(f"capinfos not found; {_TSHARK_HINT}") from exc
    except subprocess.CalledProcessError as exc:
        raise CaptureError(
            f"capinfos could not read {path}: {(exc.stderr or '').strip()}"
        ) from exc

    for line in completed.stdout.splitlines():
        if line.lower().startswith("number of packets"):
            _, _, value = line.partition(":")
            return int(value.strip())
    raise CaptureError(f"capinfos reported no frame count for {path}")


def _carve(
    path: Path,
    streams: list[int] | None,
    keep_objects: str | bool | None,
) -> tuple[Path, bool]:
    if isinstance(keep_objects, str):
        directory = Path(keep_objects).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        cleanup = False
    else:
        directory = Path(tempfile.mkdtemp(prefix="shellblock_objects_"))
        cleanup = keep_objects is None

    temporary: Path | None = None
    try:
        source = path
        if streams is not None:
            if not streams:
                return directory, cleanup
            descriptor, temporary_name = tempfile.mkstemp(
                prefix="shellblock_filtered_", suffix=".pcap"
            )
            os.close(descriptor)
            temporary = Path(temporary_name)
            _run_tshark(
                [
                    "-r",
                    str(path),
                    "-Y",
                    " or ".join(f"tcp.stream=={stream}" for stream in streams),
                    "-w",
                    str(temporary),
                ]
            )
            source = temporary

        _run_tshark(
            [
                "-r",
                str(source),
                "-q",
                "--export-objects",
                f"http,{directory}",
            ]
        )
        return directory, cleanup
    except CaptureError:
        if cleanup:
            shutil.rmtree(directory, ignore_errors=True)
        raise
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _run_tshark(arguments: list[str]) -> None:
    try:
        subprocess.run(
            ["tshark", *arguments],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise CaptureError(f"tshark not found; {_TSHARK_HINT}") from exc
    except subprocess.CalledProcessError as exc:
        raise CaptureError(
            f"tshark failed: {(exc.stderr or '').strip() or exc}"
        ) from exc


# --------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------
def _host_clause(hosts: list[str]) -> str:
    hosts = [host.strip() for host in hosts if host.strip()]
    if not hosts:
        return ""
    return " and (" + " or ".join(f"ip.addr=={host}" for host in hosts) + ")"


def _as_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_float(value: object) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _text_bytes(text: str | None) -> bytes:
    return text.encode("latin-1") if text else b""


def _flow(message: HttpMessage) -> str:
    return _flow_subject(message.src, message.src_port, message.dst, message.dst_port)


def _flow_subject(
    src: str | None, src_port: int | None, dst: str | None, dst_port: int | None
) -> str:
    return f"flow:{src}:{src_port}->{dst}:{dst_port}"


def _flow_from_stream(model: CaptureModel, stream: int | None) -> str:
    for message in model.messages:
        if message.stream == stream:
            return _flow(message)
    return f"flow:unknown:{stream}"


def _flow_meta(message: HttpMessage | None) -> dict:
    if message is None:
        return {}
    return {"stream": message.stream, "frame": message.frame, "uri": message.uri}


def _upload_subject(model: CaptureModel, upload: UploadInfo) -> str:
    if upload.stream is not None:
        return _flow_from_stream(model, upload.stream)
    return f"upload:{upload.filename}"


def _companion_signal(model: CaptureModel, stream: int | None) -> bool:
    for message in model.messages:
        if message.stream != stream or not message.method or not message.uri:
            continue
        if not urlsplit(message.uri).path.lower().endswith(".php"):
            continue
        text = (message.head or "").lower()
        if any(channel in text for channel in _SHELL_CHANNELS):
            return True
        if _QUERY_COMMAND.search(message.uri):
            return True
        for body in model.bodies:
            if body.stream == stream and body.direction == "request":
                if "shellshock" in (body.head + body.tail).lower():
                    return True
    return False


def _response_marker(buffer: bytes) -> bytes | None:
    for pattern in (_UID, _PASSWD, _INDEX, _IIS, _LS_LINE, _WWW_DATA):
        match = pattern.search(buffer)
        if match is not None:
            return match.group(0)
    return None


def _finding_span(
    rule: dict,
    subject: str,
    offset: int,
    evidence: str,
    detail: dict,
    kind: str = "http",
) -> Finding:
    return Finding(
        rule_id=rule["id"],
        subject=subject,
        severity=rule["severity"],
        location={"kind": kind, "offset": offset},
        evidence=evidence,
        detail=detail,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sort(findings: list[Finding]) -> None:
    from shellblock.rules import LoadRules

    categories = {rule["id"]: rule["category"] for rule in LoadRules()}
    findings.sort(key=lambda finding: sort_key(finding, categories[finding.rule_id]))


def _elapsed(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)
