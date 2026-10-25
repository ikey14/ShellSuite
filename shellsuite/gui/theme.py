"""Dark palette, fonts and ttk styles for the ShellSuite GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

# Core palette (specified by the project owner)
BG = "#1E1E1E"              # window / surfaces background
CARD = "#252526"            # card and dialog surfaces
SESSION_BORDER = "#3C3C3C"  # session cards
SHELL_BORDER = "#141496"    # webshell cards, selected terminal accent
BORDER = "#AF1414"          # all borders that are not card borders
TEXT = "#D4D4D4"            # primary text
MUTED = "#9D9D9D"           # secondary / de-emphasised text
ACCENT = "#D20A0A"          # destructive / close / exit

# Derived interaction tints
HOVER_BG = "#2E2E2F"
SIDEBAR_HOVER = "#1C1C3C"   # subtle #141496 tint
SHELL_HOVER = "#2A2AC0"
SHELL_ACTIVE = "#3D3DE0"
SESSION_HOVER = "#5A5A5A"
SESSION_ACTIVE = "#6E6E6E"
ACCENT_HOVER = "#E8261F"
ACCENT_ACTIVE = "#B00808"

# Terminal surface (pitch black, like a native console)
TERMINAL_BG = "#000000"

FONT = ("Segoe UI", 10)
FONT_TITLE = ("Segoe UI", 15)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_SMALL = ("Segoe UI", 9)
FONT_MONO = ("Consolas", 10)
FONT_MONO_BOLD = ("Consolas", 10, "bold")


def apply(root: tk.Tk) -> None:
    """Apply the dark theme to ``root`` and its ttk widgets."""
    root.configure(bg=BG)
    root.option_add("*TCombobox*Listbox.background", CARD)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", SHELL_BORDER)
    root.option_add("*TCombobox*Listbox.selectForeground", TEXT)

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        ".",
        background=BG,
        foreground=TEXT,
        fieldbackground=CARD,
        bordercolor=BORDER,
        lightcolor=BORDER,
        darkcolor=BORDER,
        troughcolor=BG,
        focuscolor=BORDER,
        font=FONT,
    )
    style.configure(
        "TCombobox",
        fieldbackground=CARD,
        background=CARD,
        foreground=TEXT,
        arrowcolor=TEXT,
        bordercolor=BORDER,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", CARD)],
        foreground=[("readonly", TEXT)],
        bordercolor=[("focus", BORDER)],
    )
    style.configure(
        "TEntry", fieldbackground=CARD, foreground=TEXT, insertcolor=TEXT,
        bordercolor=BORDER,
    )
    style.configure(
        "Vertical.TScrollbar",
        background=CARD,
        troughcolor=BG,
        bordercolor=BG,
        arrowcolor=MUTED,
    )


def make_button(parent, text: str, command, *, fg: str = TEXT, bg: str = CARD):
    """Create a flat, dark text button."""
    return tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=HOVER_BG,
        activeforeground=fg,
        relief="flat",
        bd=0,
        padx=12,
        pady=5,
        font=FONT,
        cursor="hand2",
        highlightthickness=1,
        highlightbackground=BORDER,
        highlightcolor=BORDER,
    )


def make_label(parent, text: str = "", *, fg: str = TEXT, bg: str = BG,
               font=FONT, anchor: str = "w", **kwargs):
    return tk.Label(parent, text=text, bg=bg, fg=fg, font=font, anchor=anchor, **kwargs)
