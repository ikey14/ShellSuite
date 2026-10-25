"""Icon assets and Canvas-drawn fallbacks.

The PNGs in ``assets/`` are pre-scaled to the exact pixel sizes and tinted to
the theme colours used by the GUI (``<kind>-<size>-<role>.png``). The original
large images live in ``assets/source/``. If a matching asset is missing, the
Canvas drawing is used instead.
"""

from __future__ import annotations

import tkinter as tk
from pathlib import Path

from . import theme

ASSETS = Path(__file__).parent / "assets"

_COLOR_ROLES = {
    theme.TEXT: "text",
    theme.MUTED: "muted",
    theme.ACCENT: "accent",
    theme.ACCENT_HOVER: "accent-hover",
}

_CACHE: dict[tuple[str, int, str], tk.PhotoImage] = {}


def load_asset(kind: str, size: int, color: str):
    """Return the exact sized/tinted PNG for ``kind``, or None."""
    role = _COLOR_ROLES.get(color)
    if role is None:
        return None
    key = (kind, size, role)
    cached = _CACHE.get(key)
    if cached is not None:
        return cached
    path = ASSETS / f"{kind}-{size}-{role}.png"
    if not path.is_file():
        return None
    try:
        image = tk.PhotoImage(file=str(path))
    except tk.TclError:
        return None
    _CACHE[key] = image
    return image


def draw_icon(canvas: tk.Canvas, kind: str, color: str, size: int = 22,
              offset: tuple[int, int] = (0, 0)) -> None:
    """Clear ``canvas`` and draw ``kind`` in ``color`` centred in a ``size`` box."""
    canvas.delete("all")
    unit = size / 24.0
    width = max(1.5, size / 11.0)
    ox, oy = offset

    def point(x: float, y: float) -> tuple[float, float]:
        return (ox + x * unit, oy + y * unit)

    def line(*coords, w=width):
        canvas.create_line(
            *(c for pair in coords for c in point(*pair)),
            fill=color, width=w, capstyle=tk.ROUND, joinstyle=tk.ROUND,
        )

    def rectangle(x1, y1, x2, y2, w=width):
        canvas.create_rectangle(
            *point(x1, y1), *point(x2, y2),
            outline=color, width=w,
        )

    def oval(x1, y1, x2, y2, w=width):
        canvas.create_oval(*point(x1, y1), *point(x2, y2), outline=color, width=w)

    def polygon(*coords, fill=True):
        canvas.create_polygon(
            *(c for pair in coords for c in point(*pair)),
            fill=color if fill else "", outline=color, width=width,
        )

    if kind == "terminal":
        line((5, 6), (11, 12), (5, 18))
        line((13, 18), (19, 18))
    elif kind == "close":
        line((6, 6), (18, 18))
        line((18, 6), (6, 18))
    elif kind == "plus":
        line((12, 5), (12, 19))
        line((5, 12), (19, 12))
    elif kind == "chevron":
        line((9, 6), (15, 12), (9, 18))
    elif kind == "edit":
        line((4, 4), (4, 20), (15, 20), (15, 13))
        line((9, 17), (18, 8))
        line((16, 5), (20, 9))
        polygon((7, 19), (7.5, 16), (10, 18.5))
    elif kind == "trash":
        line((5, 6), (19, 6), w=width * 1.3)
        line((10, 4), (14, 4))
        polygon((7, 8), (17, 8), (16, 20), (8, 20))
    elif kind == "globe":
        oval(3, 3, 21, 21)
        oval(8, 3, 16, 21)
        line((3, 12), (21, 12))
        rectangle(8, 8, 16, 16, w=max(1.2, width * 0.8))
        line((10.5, 10.5), (8.5, 12), (10.5, 13.5), w=max(1.2, width * 0.8))
        line((13.5, 10.5), (15.5, 12), (13.5, 13.5), w=max(1.2, width * 0.8))
        line((13, 9.5), (11, 14.5), w=max(1.2, width * 0.8))
    elif kind == "clock":
        oval(4, 4, 20, 20)
        line((12, 12), (12, 7.5))
        line((12, 12), (16, 14.5))
        polygon((3, 8), (8.5, 6.5), (5.5, 11.5))
    elif kind == "logo":
        rectangle(3, 8, 21, 20)
        line((3, 11), (21, 11))
        line((7, 14), (10, 16.5), (7, 19))
        line((12, 19), (17, 19))
        oval(15, 2, 22, 9, w=max(1.2, width * 0.8))
        line((18.5, 2), (18.5, 5))
    else:
        rectangle(4, 4, 20, 20)
