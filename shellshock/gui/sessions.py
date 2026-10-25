"""Sessions section: cards, filters, transcript and terminal shortcut."""

from __future__ import annotations

import tkinter as tk
from tkinter import messagebox, ttk

from shellsuite.gui import async_utils, cli_client, query, theme, widgets
from shellsuite.gui.app import Section
from shellshock.manager import sessions as sessions_data
from shellshock.manager import filters

from . import terminal


class SessionTranscriptView(tk.Frame):
    """Read-only transcript of a past session."""

    def __init__(self, app, data: dict):
        super().__init__(app.content, bg=theme.BG)
        self.app = app
        summary = data["session"]
        title = query.session_title(
            summary.get("shell") or summary.get("url") or summary.get("shell_id", ""),
            summary.get("started_at", ""),
            summary.get("status", ""),
        )

        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=14, pady=(12, 8))
        widgets.label(
            header, title, bold=True, bg=theme.BG, font=theme.FONT_TITLE
        ).pack(side="left")
        widgets.IconButton(
            header, "close", app.return_to_section, size=18,
            color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, bg=theme.BG,
        ).pack(side="right")
        tk.Frame(self, bg=theme.BORDER, height=1).pack(fill="x")

        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="both", expand=True, padx=14, pady=10)
        self.text = tk.Text(
            body, bg=theme.CARD, fg=theme.TEXT, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=theme.BORDER,
            font=theme.FONT_MONO, wrap="word", padx=10, pady=10,
        )
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.text.yview)
        self.text.configure(yscrollcommand=scrollbar.set)
        self.text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self.text.tag_configure("muted", foreground=theme.MUTED)
        self.text.tag_configure("cmd", foreground=theme.TEXT, font=theme.FONT_MONO_BOLD)
        self.text.tag_configure("error", foreground=theme.ACCENT)

        self._fill(summary, data.get("events", []))
        self.text.configure(state="disabled")

    def _fill(self, summary: dict, events: list[dict]) -> None:
        def add(value: str, tag: str | None = None) -> None:
            self.text.insert("end", value, tag or ())

        add(f"session:   {summary.get('id', '')}\n", "muted")
        add(f"shell_id:  {summary.get('shell_id', '')}\n", "muted")
        add(f"url:       {summary.get('url', '')}\n", "muted")
        add(f"vector:    {summary.get('vector', '')}\n", "muted")
        add(f"mode:      {summary.get('mode', '')}\n", "muted")
        add(f"status:    {summary.get('status', '')}\n", "muted")
        add(f"started:   {summary.get('started_at', '')}\n", "muted")
        add(f"ended:     {summary.get('ended_at') or '-'}\n", "muted")
        add(f"duration:  {summary.get('duration') if summary.get('duration') is not None else '-'}\n", "muted")
        add(f"commands:  {summary.get('commands', 0)}\n", "muted")
        add("-" * 60 + "\n", "muted")

        for event in events:
            if event.get("type") == "truncated":
                add("\n[transcript truncated]\n", "muted")
                continue
            add(f"\n$ {event.get('command')}\n", "cmd")
            if event.get("success"):
                output = event.get("output") or ""
                add(output)
                if output and not output.endswith("\n"):
                    add("\n")
            else:
                add(f"error: {event.get('error')}\n", "error")


class SessionsSection(Section):
    def _build(self, parent: tk.Widget) -> None:
        outer = tk.Frame(parent, bg=theme.BG)
        outer.pack(fill="both", expand=True, padx=16, pady=16)

        self.panel = widgets.FilterOrderPanel(
            outer,
            fields=sessions_data.SESSION_FIELDS,
            operators = filters.FILTER_OPS,
            date_fields=sessions_data.SESSION_DATE_FIELDS,
            on_apply=self._load_sessions,
            default_order="started_at",
            default_descending=True,
            shell_choices=[],
        )
        self.panel.pack(side="right", fill="y", padx=(16, 0))

        list_area = tk.Frame(outer, bg=theme.BG)
        list_area.pack(side="left", fill="both", expand=True)
        self.scroll = widgets.ScrollableFrame(list_area)
        self.scroll.pack(fill="both", expand=True)

    def refresh(self) -> None:
        async_utils.run_async(
            self.app.root,
            lambda: cli_client.list_shells("last_used", True, []),
            self._on_shells,
            self._error,
        )

    def _on_shells(self, shells: list[dict]) -> None:
        self.panel.set_shells(
            [
                (shell["id"], shell.get("name") or shell.get("url") or shell["id"])
                for shell in shells
            ]
        )
        self._load_sessions()

    def _load_sessions(self) -> None:
        order, descending, shell_id, filters = self.panel.values()
        async_utils.run_async(
            self.app.root,
            lambda: cli_client.list_sessions(shell_id, order, descending, filters),
            self._render,
            self._error,
        )

    def _render(self, sessions: list[dict]) -> None:
        for child in self.scroll.inner.winfo_children():
            child.destroy()

        if not sessions:
            widgets.label(
                self.scroll.inner, "No sessions recorded", muted=True
            ).pack(anchor="w", pady=10)
        else:
            for session in sessions:
                self._card(session)
        self.scroll.sync()

    def _card(self, session: dict) -> None:
        card = widgets.HoverCard(
            self.scroll.inner,
            border=theme.SESSION_BORDER,
            hover_border=theme.SESSION_HOVER,
        )
        card.pack(fill="x", pady=(0, 10))

        title = query.session_title(
            session.get("shell") or session.get("url") or session.get("shell_id", ""),
            session.get("started_at", ""),
            session.get("status", ""),
        )
        widgets.label(
            card, title, bold=True, bg=theme.CARD, font=theme.FONT_TITLE
        ).pack(side="left", padx=14, pady=12)

        actions = tk.Frame(card, bg=theme.CARD)
        actions.pack(side="right", padx=10)
        widgets.IconButton(
            actions, "terminal",
            lambda s=session: self._open_terminal(s),
            size=35, color=theme.TEXT, bg=theme.CARD,
        ).pack(side="left", padx=2)
        widgets.IconButton(
            actions, "trash",
            lambda s=session: self._delete(s),
            size=35, color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, bg=theme.CARD,
        ).pack(side="left", padx=2)

        self._bind_double(card, session)
        card.enable_hover()
        self.scroll.bind_wheel(card)

    def _bind_double(self, widget, session: dict) -> None:
        widget.bind(
            "<Double-Button-1>", lambda _e, s=session: self._open_session(s), add="+"
        )
        for child in widget.winfo_children():
            self._bind_double(child, session)

    def _open_terminal(self, session: dict) -> None:
        async_utils.run_async(
            self.app.root,
            lambda: cli_client.show_shell(session["shell_id"]),
            lambda shell: terminal.open_terminal(self.app, shell),
            self._error,
        )

    def _open_session(self, session: dict) -> None:
        async_utils.run_async(
            self.app.root,
            lambda: cli_client.show_session(session["id"]),
            lambda data: self.app.show_content(SessionTranscriptView(self.app, data)),
            self._error,
        )

    def _delete(self, session: dict) -> None:
        title = query.session_title(
            session.get("shell") or session.get("url") or session.get("shell_id", ""),
            session.get("started_at", ""),
            session.get("status", ""),
        )
        if not messagebox.askyesno(
            "Delete session", f"Delete {title}?", parent=self.app.root
        ):
            return

        def done(_result) -> None:
            self._load_sessions()

        async_utils.run_async(
            self.app.root,
            lambda: cli_client.delete_session(session["id"]),
            done,
            self._error,
        )

    def _error(self, exc: Exception) -> None:
        messagebox.showerror("ShellShock", str(exc), parent=self.app.root)
