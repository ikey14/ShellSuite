"""Shells section: cards, connect, rename and delete."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox

from shellsuite.gui import async_utils, cli_client, theme, widgets
from shellsuite.gui.app import Section
from shellshock.manager import registry

from . import terminal
from .dialogs import ConnectDialog, RenameDialog


class ShellsSection(Section):
    def _build(self, parent: tk.Widget) -> None:
        outer = tk.Frame(parent, bg=theme.BG)
        outer.pack(fill="both", expand=True, padx=16, pady=16)

        self.panel = widgets.FilterOrderPanel(
            outer,
            fields=registry.ORDER_FIELDS,
            date_fields=registry.DATE_FIELDS,
            on_apply=self.refresh,
            default_order="last_used",
            default_descending=True,
        )
        self.panel.pack(side="right", fill="y", padx=(16, 0))

        list_area = tk.Frame(outer, bg=theme.BG)
        list_area.pack(side="left", fill="both", expand=True)
        self.scroll = widgets.ScrollableFrame(list_area)
        self.scroll.pack(fill="both", expand=True)

        bottom = tk.Frame(list_area, bg=theme.BG)
        bottom.pack(fill="x", pady=(8, 0))
        widgets.IconButton(
            bottom, "plus", self._connect, size=26,
            color=theme.TEXT, hover_color=theme.TEXT, bg=theme.BG,
        ).pack()

    def refresh(self) -> None:
        order, descending, _shell_id, filters = self.panel.values()
        async_utils.run_async(
            self.app.root,
            lambda: cli_client.list_shells(order, descending, filters),
            self._render,
            self._error,
        )

    def _render(self, shells: list[dict]) -> None:
        for child in self.scroll.inner.winfo_children():
            child.destroy()

        if not shells:
            widgets.label(
                self.scroll.inner, "No shells registered", muted=True
            ).pack(anchor="w", pady=10)
        else:
            for shell in shells:
                self._card(shell)
        self.scroll.sync()

    def _card(self, shell: dict) -> None:
        card = widgets.HoverCard(
            self.scroll.inner,
            border=theme.SHELL_BORDER,
            hover_border=theme.SHELL_HOVER,
        )
        card.pack(fill="x", pady=(0, 10))

        title = shell.get("name") or shell.get("url") or shell.get("id")
        widgets.label(
            card, title, bold=True, bg=theme.CARD, font=theme.FONT_TITLE
        ).pack(side="left", padx=14, pady=12)

        actions = tk.Frame(card, bg=theme.CARD)
        actions.pack(side="right", padx=10)
        widgets.IconButton(
            actions, "terminal", lambda s=shell: terminal.open_terminal(self.app, s),
            size=35, color=theme.TEXT, bg=theme.CARD,
        ).pack(side="left", padx=2)
        widgets.IconButton(
            actions, "edit", lambda s=shell: self._edit(s),
            size=35, color=theme.TEXT, bg=theme.CARD,
        ).pack(side="left", padx=2)
        widgets.IconButton(
            actions, "trash", lambda s=shell: self._delete(s),
            size=35, color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, bg=theme.CARD,
        ).pack(side="left", padx=2)

        card.enable_hover()
        self.scroll.bind_wheel(card)

    def _edit(self, shell: dict) -> None:
        changed, name = RenameDialog.ask(self.app.root, shell.get("name"))
        if not changed:
            return
        async_utils.run_async(
            self.app.root,
            lambda: cli_client.edit_shell_name(shell["id"], name),
            lambda _result: self.refresh(),
            self._error,
        )

    def _delete(self, shell: dict) -> None:
        title = shell.get("name") or shell.get("url") or shell["id"]
        if not messagebox.askyesno(
            "Delete shell", f"Delete {title}?", parent=self.app.root
        ):
            return

        def worker():
            cli_client.delete_shell(shell["id"])
            return shell["id"]

        def done(shell_id: str) -> None:
            self.app.force_close_terminal(shell_id)
            self.app.notify_changed()

        async_utils.run_async(self.app.root, worker, done, self._error)

    def _connect(self) -> None:
        ConnectDialog(self.app.root, on_success=self.refresh)

    def _error(self, exc: Exception) -> None:
        messagebox.showerror("ShellShock", str(exc), parent=self.app.root)
