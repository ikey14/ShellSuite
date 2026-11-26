"""Etapa estática de imágenes: recorrido del contenedor y reglas estructurales.
El fichero nunca se decodifica: se leen las cabeceras que dicen cuánto mide cada
bloque, se avanza, y se guardan las regiones (segmentos, chunks, cola) para que
las reglas busquen dentro de ellas con offsets reales.
"""

from __future__ import annotations
import re
from shellblock.analyze.context import Context, Region
from shellblock.detect import MAGICS
from shellblock.result import EVIDENCE_LIMIT, Finding, escape_evidence

_PHP_TAG = re.compile(rb"<\?(?!xml)")
_SCRIPT = re.compile(rb"<script|onerror\s*=", re.IGNORECASE)
_DOUBLE_EXTENSION = re.compile(r"\.(php\d?|phtml|phar)\.(jpe?g|png|gif)$", re.IGNORECASE)
_JPEG_SOI = MAGICS["jpeg"][0]
_PNG_SIGNATURE = MAGICS["png"][0]
_GIF_SIGNATURES = MAGICS["gif"]
_PNG_TEXT_CHUNKS = (b"tEXt", b"iTXt", b"zTXt")
_IMAGE_MAGICS = (*_GIF_SIGNATURES, _PNG_SIGNATURE, _JPEG_SOI)
_EVIDENCE_BYTES = EVIDENCE_LIMIT

# --------------------------------------------------------------------------
# Regiones del contenedor
# --------------------------------------------------------------------------
def regions(ctx: Context) -> list[Region]:
    """Regiones del fichero, recorridas una sola vez por análisis."""
    if ctx.image_regions is None:
        walk = {
            "jpeg": _walk_jpeg,
            "png": _walk_png,
            "gif": _walk_gif,
        }.get(ctx.detection.detected_type)
        ctx.image_regions = walk(ctx) if walk else []
    return ctx.image_regions


def _walk_jpeg(ctx: Context) -> list[Region]:
    """Recorre marcadores hasta SOS; desde ahí solo busca el EOI."""
    data = ctx.buffer
    soi = data.find(_JPEG_SOI)
    
    if soi < 0:
        return []
    
    found: list[Region] = []
    
    if soi:
        found.append(Region(0, soi, "prefix", "pre-SOI"))
    
    offset = soi + 2
    
    while offset + 2 <= len(data):
        if data[offset] != 0xFF:
            ctx.errors.append(f"unreadable JPEG marker at {offset}")
            return found
        
        while offset + 1 < len(data) and data[offset + 1] == 0xFF:
            offset += 1  # bytes de relleno antes del marcador
        marker = data[offset + 1]
        
        if marker == 0xD9:  # EOI sin SOS (raro, pero posible)
            if offset + 2 < len(data):
                found.append(Region(offset + 2, len(data), "trailing", "trailing"))
            return found
        
        if marker == 0xD8 or marker == 0x01 or 0xD0 <= marker <= 0xD7:
            offset += 2
            continue
        
        if marker == 0xDA:  # SOS: aquí empieza el flujo comprimido
            eoi = data.find(b"\xff\xd9", offset)
            if eoi < 0:
                ctx.errors.append("JPEG entropy data without EOI")
                return found
            if eoi + 2 < len(data):
                found.append(Region(eoi + 2, len(data), "trailing", "trailing"))
            return found
        
        if offset + 4 > len(data):
            ctx.errors.append(f"truncated JPEG segment at {offset}")
            return found
        length = int.from_bytes(data[offset + 2:offset + 4], "big")
        
        if length < 2:
            ctx.errors.append(f"unreadable JPEG segment at {offset}")
            return found
        start = offset + 4
        end = min(offset + 2 + length, len(data))
        
        if marker == 0xFE:
            found.append(Region(start, end, "segment", "COM"))
        elif 0xE0 <= marker <= 0xEF:
            found.append(Region(start, end, "segment", f"APP{marker - 0xE0}"))
        offset += 2 + length
    
    ctx.errors.append("JPEG walk ended without EOI")
    return found


def _walk_png(ctx: Context) -> list[Region]:
    """Cadena de chunks: longitud, tipo, datos, CRC."""
    data = ctx.buffer
    signature = data.find(_PNG_SIGNATURE)
    
    if signature < 0:
        return []
    
    found: list[Region] = []
    
    if signature:
        found.append(Region(0, signature, "prefix", "pre-SOI"))
    
    offset = signature + len(_PNG_SIGNATURE)
    while offset + 8 <= len(data):
        length = int.from_bytes(data[offset:offset + 4], "big")
        kind = data[offset + 4:offset + 8]
        start = offset + 8
        end = min(start + length, len(data))
        
        if kind in _PNG_TEXT_CHUNKS:
            found.append(Region(start, end, "chunk", kind.decode("ascii")))
        offset = start + length + 4
        
        if kind == b"IEND":
            if offset < len(data):
                found.append(Region(offset, len(data), "trailing", "trailing"))
            return found
    
    ctx.errors.append("PNG walk ended without IEND")
    return found


def _walk_gif(ctx: Context) -> list[Region]:
    """Bloques GIF: extensiones (21), imágenes (2C) y tráiler (3B)."""
    data = ctx.buffer
    positions = [data.find(sig) for sig in _GIF_SIGNATURES]
    positions = [position for position in positions if position >= 0]
    
    if not positions:
        return []
    
    signature = min(positions)
    found: list[Region] = []
    
    if signature:
        found.append(Region(0, signature, "prefix", "pre-SOI"))
    
    offset = signature + 6
    
    if offset + 7 > len(data):
        return found
    
    packed = data[offset + 4]
    offset += 7
    
    if packed & 0x80:  # tabla de color global
        offset += 3 * (2 ** ((packed & 0x07) + 1))
    while offset < len(data):
        block = data[offset]
        if block == 0x3B:  # tráiler
            if offset + 1 < len(data):
                found.append(Region(offset + 1, len(data), "trailing", "trailing"))
            return found
        if block == 0x21:  # extensión
            label = data[offset + 1]
            body = offset + 2
            offset = _skip_sub_blocks(data, body)
            if label == 0xFE:
                found.append(Region(body, offset, "segment", "GIF-comment"))
            continue
        if block == 0x2C:  # descriptor de imagen
            if offset + 10 > len(data):
                ctx.errors.append(f"truncated GIF image descriptor at {offset}")
                return found
            packed = data[offset + 9]
            offset += 10
            if packed & 0x80:
                offset += 3 * (2 ** ((packed & 0x07) + 1))
            offset = _skip_sub_blocks(data, offset + 1)  # +1: tamaño mínimo LZW
            continue
        ctx.errors.append(f"unreadable GIF block at {offset}")
        return found
    ctx.errors.append("GIF walk ended without trailer")
    return found


def _skip_sub_blocks(data: bytes, offset: int) -> int:
    """Avanza sub-bloques (longitud de 1 byte) hasta el terminador 0x00."""
    while offset < len(data) and data[offset]:
        offset += 1 + data[offset]
    return offset + 1


# --------------------------------------------------------------------------
# Detectors (DETECTORS: rule_id -> function)
# --------------------------------------------------------------------------
def find_php_before_soi(ctx: Context, rule: dict) -> list[Finding]:
    """PHP delante de la firma de imagen: el fichero es PHP disfrazado."""
    magic_at = _first_image_magic(ctx.buffer)
    if magic_at is None or magic_at == 0:
        return []
    match = _PHP_TAG.search(ctx.buffer, 0, magic_at)
    if match is None:
        return []
    return [
        _finding(
            rule, ctx, match.start(), min(match.start() + _EVIDENCE_BYTES, magic_at),
            kind="byte_offset", segment="pre-SOI",
            detail={"image_offset": magic_at},
        )
    ]


def find_hidden_php(ctx: Context, rule: dict) -> list[Finding]:
    """PHP dentro de un metadato o después del final del contenedor."""
    hits: list[Finding] = []
    for region in regions(ctx):
        if region.kind not in ("segment", "chunk", "trailing"):
            continue
        match = _PHP_TAG.search(ctx.buffer, region.start, region.end)
        if match is None:
            continue
        tags = len(_PHP_TAG.findall(ctx.buffer, region.start, region.end))
        hits.append(
            _finding(
                rule, ctx, match.start(),
                min(match.start() + _EVIDENCE_BYTES, region.end),
                kind=_location_kind(region), segment=region.name,
                detail={
                    "segment_length": region.end - region.start,
                    "tags": tags,
                },
            )
        )
    return hits


def find_script_in_segment(ctx: Context, rule: dict) -> list[Finding]:
    """`<script`/`onerror=` dentro de metadatos: portador de XSS almacenado."""
    hits: list[Finding] = []
    for region in regions(ctx):
        if region.kind not in ("segment", "chunk"):
            continue
        match = _SCRIPT.search(ctx.buffer, region.start, region.end)
        if match is None:
            continue
        hits.append(
            _finding(
                rule, ctx, match.start(),
                min(match.start() + _EVIDENCE_BYTES, region.end),
                kind=_location_kind(region), segment=region.name,
                detail={"segment_length": region.end - region.start},
            )
        )
    return hits


def find_zip_after_eoi(ctx: Context, rule: dict) -> list[Finding]:
    """`PK\\x03\\x04` en la cola: políglota imagen + ZIP (PHAR)."""
    for region in regions(ctx):
        if region.kind == "trailing" and ctx.buffer.startswith(b"PK\x03\x04", region.start):
            return [
                _finding(
                    rule, ctx, region.start, region.start + 8,
                    kind="byte_offset", segment="trailing",
                    detail={"trailing_length": region.end - region.start},
                )
            ]
    return []


def find_trailing_data(ctx: Context, rule: dict) -> list[Finding]:
    """Cola no vacía que no es PHP ni ZIP; la regla específica gana."""
    for region in regions(ctx):
        if region.kind != "trailing" or region.end <= region.start:
            continue
        if ctx.buffer.startswith(b"PK\x03\x04", region.start):
            continue
        if _PHP_TAG.search(ctx.buffer, region.start, region.end):
            continue
        return [
            _finding(
                rule, ctx, region.start, region.start + _EVIDENCE_BYTES,
                kind="byte_offset", segment="trailing",
                detail={"trailing_length": region.end - region.start},
            )
        ]
    return []


def find_type_mismatch(ctx: Context, rule: dict) -> list[Finding]:
    """La extensión dice un tipo y los bytes mágicos dicen otro."""
    detection = ctx.detection
    if not detection.type_mismatch:
        return []
    magic = " ".join(f"{byte:02x}" for byte in ctx.buffer[:8])
    return [
        _finding(
            rule, ctx, 0, len(magic) // 3,
            kind="byte_offset", segment="magic",
            detail={
                "extension": detection.extension,
                "extension_type": detection.extension_type,
                "detected_type": detection.detected_type,
            },
        )
    ]


def find_double_extension(ctx: Context, rule: dict) -> list[Finding]:
    """`shell.php.jpg`: extensión ejecutable escondida tras una de imagen."""
    name = ctx.path.name
    if _DOUBLE_EXTENSION.search(name) is None:
        return []
    return [
        _finding(
            rule, ctx, 0, len(name),
            kind="byte_offset", segment="name",
            detail={"name": name},
        )
    ]


# --------------------------------------------------------------------------
# Utilities
# --------------------------------------------------------------------------
def _first_image_magic(data: bytes) -> int | None:
    """Offset de la primera firma de imagen, o None si no hay ninguna."""
    positions = [data.find(magic) for magic in _IMAGE_MAGICS]
    positions = [position for position in positions if position >= 0]
    return min(positions) if positions else None


def _location_kind(region: Region) -> str:
    """`kind` legal del contrato para la región; la cola es un byte_offset."""
    return region.kind if region.kind in ("segment", "chunk") else "byte_offset"


def _finding(
    rule: dict,
    ctx: Context,
    start: int,
    stop: int,
    kind: str,
    segment: str,
    detail: dict,
) -> Finding:
    """Finding con evidencia imprimible y offset real dentro del fichero."""
    stop = min(stop, len(ctx.buffer))
    return Finding(
        rule_id=rule["id"],
        subject="file",
        severity=rule["severity"],
        location={"kind": kind, "offset": start, "segment": segment},
        evidence=escape_evidence(ctx.buffer[start:stop]),
        detail=detail,
    )
