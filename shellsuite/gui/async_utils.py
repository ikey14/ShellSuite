"""Tiny helper to run blocking work off the Tk thread."""

from __future__ import annotations

import threading
import tkinter as tk
from typing import Callable


def _dispatch(widget: tk.Misc, callback: Callable, value) -> None:
    try:
        widget.after(0, lambda: callback(value))
    except tk.TclError:
        # The widget was destroyed while the worker was running.
        pass


def run_async(widget: tk.Misc, func: Callable, on_success: Callable, on_error: Callable) -> None:
    """Run ``func`` in a daemon thread and marshal the result back to Tk."""

    def worker() -> None:
        try:
            result = func()
        except Exception as exc:  # noqa: BLE001 - surfaced to the UI
            _dispatch(widget, on_error, exc)
        else:
            _dispatch(widget, on_success, result)

    threading.Thread(target=worker, daemon=True).start()
