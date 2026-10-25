"""Dark date entry with a popup calendar (stdlib only)."""

from __future__ import annotations

import calendar
from datetime import date, datetime, timezone
import tkinter as tk
from tkinter import ttk

from . import icons, theme


def is_date_text(value: str) -> bool:
    """True when ``value`` starts with a valid ISO date (YYYY-MM-DD)."""
    if len(value) < 10:
        return False
    try:
        date.fromisoformat(value[:10])
    except ValueError:
        return False
    return True


def _small_button(parent, text: str, command):
    return tk.Button(
        parent, text=text, command=command,
        bg=theme.CARD, fg=theme.TEXT, activebackground=theme.HOVER_BG,
        activeforeground=theme.TEXT, relief="flat", bd=0, padx=6, pady=2,
        font=theme.FONT_SMALL, cursor="hand2",
    )


class DateEntry(tk.Frame):
    """A text entry plus a calendar button that opens a date picker."""

    def __init__(self, parent, *, textvariable=None):
        super().__init__(parent, bg=theme.BG)
        self.var = textvariable if textvariable is not None else tk.StringVar()
        self._popup: tk.Toplevel | None = None
        self._year = 0
        self._month = 0

        self.entry = ttk.Entry(self, textvariable=self.var, width=8)
        self.entry.pack(side="left", fill="x", expand=True)

        self.button = tk.Canvas(
            self, width=18, height=18, bg=theme.BG, highlightthickness=0,
            bd=0, cursor="hand2",
        )
        self.button.pack(side="right", padx=(2, 0))
        self._paint_button(theme.MUTED)
        self.button.bind("<Button-1>", lambda _e: self.open_calendar())
        self.button.bind("<Enter>", lambda _e: self._paint_button(theme.TEXT))
        self.button.bind("<Leave>", lambda _e: self._paint_button(theme.MUTED))

    def _paint_button(self, color: str) -> None:
        self.button.delete("all")
        icons.draw_icon(self.button, "calendar", color, 14, (2, 2))

    def _anchor_date(self) -> date:
        text = self.var.get().strip()
        if len(text) >= 10:
            try:
                return date.fromisoformat(text[:10])
            except ValueError:
                pass
        return datetime.now(timezone.utc).date()

    def open_calendar(self) -> None:
        if self._popup is not None:
            self._popup.lift()
            return

        popup = tk.Toplevel(self)
        popup.configure(bg=theme.BG)
        popup.title("Date")
        popup.resizable(False, False)
        popup.transient(self.winfo_toplevel())
        popup.protocol("WM_DELETE_WINDOW", self._close)
        popup.bind("<Escape>", lambda _e: self._close())
        self._popup = popup

        anchor = self._anchor_date()
        self._year = anchor.year
        self._month = anchor.month

        header = tk.Frame(popup, bg=theme.BG)
        header.pack(fill="x", padx=8, pady=(8, 4))
        _small_button(header, "<", lambda: self._shift(-1)).pack(side="left")
        self._month_label = tk.Label(
            header, text="", bg=theme.BG, fg=theme.TEXT, font=theme.FONT_SMALL,
        )
        self._month_label.pack(side="left", expand=True)
        _small_button(header, ">", lambda: self._shift(1)).pack(side="right")

        self._days = tk.Frame(popup, bg=theme.BG)
        self._days.pack(padx=8, pady=4)

        footer = tk.Frame(popup, bg=theme.BG)
        footer.pack(fill="x", padx=8, pady=(4, 8))
        _small_button(footer, "Today", self._today).pack(side="left")
        _small_button(footer, "Clear", self._clear).pack(side="left", padx=(4, 0))
        _small_button(footer, "Close", self._close).pack(side="right")

        self._render_days()
        popup.update_idletasks()
        x = self.entry.winfo_rootx()
        y = self.entry.winfo_rooty() + self.entry.winfo_height() + 2
        x = max(0, min(x, popup.winfo_screenwidth() - popup.winfo_width()))
        y = max(0, min(y, popup.winfo_screenheight() - popup.winfo_height()))
        popup.geometry(f"+{x}+{y}")
        popup.grab_set()
        popup.focus_force()

    def _shift(self, delta: int) -> None:
        month = self._month + delta
        year = self._year + (month - 1) // 12
        month = (month - 1) % 12 + 1
        self._year, self._month = year, month
        self._render_days()

    def _render_days(self) -> None:
        self._month_label.configure(
            text=f"{calendar.month_name[self._month]} {self._year}"
        )
        for child in self._days.winfo_children():
            child.destroy()

        for column, name in enumerate(calendar.day_abbr):
            tk.Label(
                self._days, text=name, bg=theme.BG, fg=theme.MUTED,
                font=theme.FONT_SMALL, width=3,
            ).grid(row=0, column=column, padx=1, pady=(0, 2))

        selected = self._anchor_date()
        today = datetime.now(timezone.utc).date()
        weeks = calendar.monthcalendar(self._year, self._month)
        for row, week in enumerate(weeks, start=1):
            for column, day in enumerate(week):
                if day == 0:
                    tk.Label(self._days, text="", bg=theme.BG, width=3).grid(
                        row=row, column=column
                    )
                    continue
                current = date(self._year, self._month, day)
                bg = theme.SHELL_BORDER if current == selected else theme.BG
                fg = theme.BORDER if current == today else theme.TEXT
                button = tk.Button(
                    self._days, text=str(day), command=lambda d=day: self._select(d),
                    bg=bg, fg=fg, activebackground=theme.SHELL_HOVER,
                    activeforeground=theme.TEXT, relief="flat", bd=0,
                    width=3, font=theme.FONT_SMALL, cursor="hand2",
                )
                button.grid(row=row, column=column, padx=1, pady=1)

    def _select(self, day: int) -> None:
        self.var.set(date(self._year, self._month, day).isoformat())
        self._close()

    def _today(self) -> None:
        self.var.set(datetime.now(timezone.utc).date().isoformat())
        self._close()

    def _clear(self) -> None:
        self.var.set("")
        self._close()

    def _close(self) -> None:
        popup = self._popup
        self._popup = None
        if popup is not None:
            try:
                popup.grab_release()
            except tk.TclError:
                pass
            popup.destroy()
        try:
            self.entry.focus_set()
        except tk.TclError:
            pass
