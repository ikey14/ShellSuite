"""Dark modal dialogs for the ShellShock GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from shellsuite.protocol import contract
from shellsuite.gui import async_utils, cli_client, theme, widgets


def _center(dialog: tk.Toplevel, parent: tk.Misc) -> None:
    dialog.update_idletasks()
    width = dialog.winfo_width()
    height = dialog.winfo_height()
    x = parent.winfo_rootx() + max(0, (parent.winfo_width() - width) // 2)
    y = parent.winfo_rooty() + max(0, (parent.winfo_height() - height) // 2)
    dialog.geometry(f"+{x}+{y}")


def _entry(parent) -> ttk.Entry:
    return ttk.Entry(parent)


class SecretDialog(tk.Toplevel):
    """Ask for a shell password without storing it."""

    def __init__(self, parent, prompt: str):
        super().__init__(parent)
        self.configure(bg=theme.BG)
        self.title("Password")
        self.resizable(False, False)
        self.transient(parent)
        self.result: str | None = None

        widgets.label(self, prompt, bg=theme.BG).pack(anchor="w", padx=16, pady=(16, 6))
        self.entry = _entry(self)
        self.entry.configure(show="*")
        self.entry.pack(fill="x", padx=16, pady=(0, 12))

        row = tk.Frame(self, bg=theme.BG)
        row.pack(fill="x", padx=16, pady=(0, 16))
        theme.make_button(row, "Cancel", self._cancel).pack(side="right", padx=(6, 0))
        theme.make_button(row, "OK", self._ok).pack(side="right")

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.grab_set()
        _center(self, parent)
        self.after(20, self.entry.focus_set)
        self.wait_window()

    def _ok(self) -> None:
        self.result = self.entry.get()
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(cls, parent, prompt: str) -> str | None:
        return cls(parent, prompt).result


class RenameDialog(tk.Toplevel):
    """Rename a shell (empty value clears the name)."""

    def __init__(self, parent, current: str | None):
        super().__init__(parent)
        self.configure(bg=theme.BG)
        self.title("Rename shell")
        self.resizable(False, False)
        self.transient(parent)
        self.result: tuple[bool, str | None] = (False, None)

        widgets.label(self, "Shell name", bg=theme.BG).pack(anchor="w", padx=16, pady=(16, 6))
        self.entry = _entry(self)
        self.entry.insert(0, current or "")
        self.entry.pack(fill="x", padx=16, pady=(0, 4))
        widgets.label(
            self, "Leave empty to clear the name", muted=True,
            font=theme.FONT_SMALL, bg=theme.BG,
        ).pack(anchor="w", padx=16, pady=(0, 12))

        row = tk.Frame(self, bg=theme.BG)
        row.pack(fill="x", padx=16, pady=(0, 16))
        theme.make_button(row, "Cancel", self._cancel).pack(side="right", padx=(6, 0))
        theme.make_button(row, "Save", self._ok).pack(side="right")

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.grab_set()
        _center(self, parent)
        self.after(20, self.entry.focus_set)
        self.wait_window()

    def _ok(self) -> None:
        value = self.entry.get().strip()
        self.result = (True, value or None)
        self.destroy()

    def _cancel(self) -> None:
        self.result = (False, None)
        self.destroy()

    @classmethod
    def ask(cls, parent, current: str | None) -> tuple[bool, str | None]:
        return cls(parent, current).result


class ConnectDialog(tk.Toplevel):
    """Collect the details of a new shell and register it via the CLI."""

    def __init__(self, parent, on_success):
        super().__init__(parent)
        self.configure(bg=theme.BG)
        self.title("Connect to a webshell")
        self.resizable(False, False)
        self.transient(parent)
        self._on_success = on_success
        self._busy = False

        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="both", expand=True, padx=16, pady=16)

        widgets.label(body, "URL", bg=theme.BG).grid(row=0, column=0, sticky="w", pady=(0, 2))
        self.url = _entry(body)
        self.url.configure(width=48)
        self.url.grid(row=1, column=0, columnspan=2, sticky="ew", pady=(0, 10))

        widgets.label(body, "Vector", muted=True, font=theme.FONT_SMALL, bg=theme.BG).grid(
            row=2, column=0, sticky="w"
        )
        widgets.label(body, "Mode", muted=True, font=theme.FONT_SMALL, bg=theme.BG).grid(
            row=2, column=1, sticky="w", padx=(8, 0)
        )
        self.vector = tk.StringVar(value="post")
        self.mode = tk.StringVar(value="plain")
        ttk.Combobox(
            body, textvariable=self.vector, values=contract.VECTORS, state="readonly"
        ).grid(row=3, column=0, sticky="ew", pady=(2, 10))
        ttk.Combobox(
            body, textvariable=self.mode, values=contract.MODES, state="readonly"
        ).grid(row=3, column=1, sticky="ew", padx=(8, 0), pady=(2, 10))

        widgets.label(body, "Secret", muted=True, font=theme.FONT_SMALL, bg=theme.BG).grid(
            row=4, column=0, sticky="w"
        )
        widgets.label(body, "Name (optional)", muted=True, font=theme.FONT_SMALL, bg=theme.BG).grid(
            row=4, column=1, sticky="w", padx=(8, 0)
        )
        self.secret = _entry(body)
        self.secret.configure(show="*")
        self.secret.grid(row=5, column=0, sticky="ew", pady=(2, 4))
        self.name = _entry(body)
        self.name.grid(row=5, column=1, sticky="ew", padx=(8, 0), pady=(2, 4))

        self.hint = widgets.label(
            body, "", muted=True, font=theme.FONT_SMALL, bg=theme.BG
        )
        self.hint.grid(row=6, column=0, columnspan=2, sticky="w", pady=(0, 12))

        row = tk.Frame(body, bg=theme.BG)
        row.grid(row=7, column=0, columnspan=2, sticky="ew")
        self.connect_button = theme.make_button(row, "Connect", self._submit)
        self.connect_button.pack(side="right")
        theme.make_button(row, "Cancel", self.destroy).pack(side="right", padx=(0, 6))

        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        self.mode.trace_add("write", lambda *_: self._update_hint())
        self._update_hint()
        self.bind("<Escape>", lambda _e: self.destroy())
        self.grab_set()
        _center(self, parent)
        self.after(20, self.url.focus_set)

    def _update_hint(self) -> None:
        needs_secret = self.mode.get() in ("auth", "encrypted")
        self.hint.configure(
            text="The secret is required for this mode." if needs_secret
            else "Plain shells take no secret."
        )

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        self.connect_button.configure(state="disabled" if busy else "normal")

    def _submit(self) -> None:
        if self._busy:
            return
        url = self.url.get().strip()
        mode = self.mode.get()
        vector = self.vector.get()
        secret = self.secret.get()
        name = self.name.get().strip() or None

        if not url:
            messagebox.showerror("Connect", "A URL is required.", parent=self)
            return
        if mode in ("auth", "encrypted") and not secret:
            messagebox.showerror("Connect", "This mode requires a secret.", parent=self)
            return

        self._set_busy(True)

        def worker():
            return cli_client.connect(
                url, vector, mode,
                secret if mode != "plain" else None,
                name,
            )

        def done(_result):
            self.destroy()
            self._on_success()

        def failed(exc):
            self._set_busy(False)
            messagebox.showerror("Connect failed", str(exc), parent=self)

        async_utils.run_async(self, worker, done, failed)
