"""Capture stage: filter with tshark, normalise with pyshark, carve bodies.

Only HTTP content is readable; TLS contributes the handshake SNI and nothing
else. Carved objects are analysed by the file pipeline and their findings are
reported with an ``upload:<name>`` subject.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path

import pyshark
from pyshark.tshark.tshark import TSharkNotFoundException

from shellblock.analyze.context import Context
from shellblock.detect import Detection
from shellblock.result import Finding, Result, Stage, escape_evidence, sort_key
from shellsuite import config

_HTTP_FILTER = "(http.request or http.response)"
_TLS_FILTER = "tls.handshake.extensions_server_name"
_TSHARK_HINT = "install Wireshark and make sure tshark and capinfos are on PATH"


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


@dataclass
class CaptureModel:
    """Normalised capture: HTTP packets, TLS flows and frame accounting."""

    messages: list[HttpMessage] = field(default_factory=list)
    tls: list[TlsFlow] = field(default_factory=list)
    frames: int = 0
    kept: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": 1,
            "frames": self.frames,
            "kept": self.kept,
            "messages": [asdict(message) for message in self.messages],
            "tls": [asdict(flow) for flow in self.tls],
        }


def read_capture(path: Path, hosts: list[str]) -> CaptureModel:
    """Read the HTTP subset and the TLS handshakes of ``path``."""
    frames = _total_frames(path)
    clause = _host_clause(hosts)
    messages = _http_messages(path, _HTTP_FILTER + clause)
    tls = _tls_flows(path, _TLS_FILTER + clause)
    return CaptureModel(messages, tls, frames, len(messages))


def analyze(
    path: Path,
    detection: Detection,
    max_size: int,
    hosts: list[str],
    keep_objects: str | bool | None,
    dump_json: bool,
    detect_ms: int,
) -> Result:
    """Analyse a capture: filter, normalise, carve and recurse into the files."""
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
        upload_findings, upload_errors, objects = _analyze_objects(
            directory, max_size
        )
    finally:
        if cleanup:
            shutil.rmtree(directory, ignore_errors=True)
        else:
            notes.append(f"carved objects kept at {directory}")

    errors.extend(upload_errors)

    context = Context(
        buffer=b"",
        detection=detection,
        path=path,
        capture_model=model,
    )
    from shellblock.rules import DETECTORS, LoadRules, structural_rules

    capture_rules = structural_rules(detection.detected_type)
    capture_findings = [
        finding
        for rule in capture_rules
        for finding in DETECTORS[rule["id"]](context, rule)
    ]
    findings = capture_findings + upload_findings
    _sort(findings)

    static_ms = _elapsed(started)
    matched = len({finding.rule_id for finding in capture_findings})

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
            Stage("signature", "skipped", 0),
            Stage(
                "static",
                "ok",
                static_ms,
                rules=len(capture_rules),
                matched=matched,
                units=1 + objects,
                frames=model.frames,
                kept=model.kept,
            ),
        ],
        findings=findings,
        notes=notes,
        errors=errors,
    )


def find_tls_opaque(ctx: Context, rule: dict) -> list[Finding]:
    """One finding per encrypted flow; the SNI is the only evidence available."""
    model = ctx.capture_model
    if model is None:
        return []
    return [
        Finding(
            rule_id=rule["id"],
            subject=(
                f"flow:{flow.src}:{flow.src_port}->{flow.dst}:{flow.dst_port}"
            ),
            severity=rule["severity"],
            location={"kind": "stream", "offset": 0},
            evidence=escape_evidence((flow.sni or "TLS handshake").encode("latin-1")),
            detail={"sni": flow.sni, "encrypted": True},
        )
        for flow in model.tls
    ]


# --------------------------------------------------------------------------
# tshark / pyshark plumbing
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
            messages.append(
                HttpMessage(
                    stream=_as_int(getattr(tcp, "stream", None)),
                    src=getattr(ip, "src", None),
                    src_port=_as_int(getattr(tcp, "srcport", None)),
                    dst=getattr(ip, "dst", None),
                    dst_port=_as_int(getattr(tcp, "dstport", None)),
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


def _analyze_objects(
    directory: Path, max_size: int
) -> tuple[list[Finding], list[str], int]:
    from shellblock.pipeline import analyze as analyze_file

    findings: list[Finding] = []
    errors: list[str] = []
    count = 0
    for object_path in sorted(directory.iterdir()):
        if not object_path.is_file() or object_path.name.startswith("_part"):
            continue

        data = object_path.read_bytes()[:max_size]
        parts = _multipart_parts(data)
        if parts:
            for index, (filename, content) in enumerate(parts):
                name = Path(filename).name or f"part{index}"
                part_path = directory / f"_part{index}_{name}"
                part_path.write_bytes(content)
                result = analyze_file(
                    part_path, max_size=max_size, allow_capture=False
                )
                findings.extend(
                    replace(finding, subject=f"upload:{name}")
                    for finding in result.findings
                )
                errors.extend(f"{name}: {error}" for error in result.errors)
                count += 1
            continue

        result = analyze_file(object_path, max_size=max_size, allow_capture=False)
        findings.extend(
            replace(finding, subject=f"upload:{object_path.name}")
            for finding in result.findings
        )
        errors.extend(
            f"{object_path.name}: {error}" for error in result.errors
        )
        count += 1
    return findings, errors, count


def _multipart_parts(data: bytes) -> list[tuple[str, bytes]]:
    """File parts of a multipart/form-data body, as (filename, content)."""
    if not data.startswith(b"--"):
        return []
    line_end = data.find(b"\r\n")
    if line_end < 0:
        return []
    boundary = data[2:line_end]
    if not boundary:
        return []

    parts: list[tuple[str, bytes]] = []
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
        if match is not None:
            parts.append((match.group(1), body))
    return parts


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
