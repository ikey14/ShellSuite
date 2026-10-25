"""ShellSuite main window and section discovery."""

from __future__ import annotations

import importlib
import sys
import tkinter as tk

from shellsuite import config

from . import icons, theme, widgets

SIDEBAR_WIDTH = 200


def _set_windows_app_id() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "ShellSuite.Desktop"
        )
    except (AttributeError, OSError):
        pass


class Section:
    """A module-contributed view (e.g. Shells, Sessions)."""

    def __init__(self, app):
        self.app = app
        self.frame = None

    def build(self, parent: tk.Widget) -> tk.Frame:
        self.frame = tk.Frame(parent, bg=theme.BG)
        self._build(self.frame)
        return self.frame

    def _build(self, parent: tk.Widget) -> None:  # pragma: no cover - UI
        raise NotImplementedError

    def refresh(self) -> None:  # pragma: no cover - UI
        pass

    def on_show(self) -> None:
        self.refresh()


class ShellSuiteApp:
    def __init__(self):
        _set_windows_app_id()
        self.root = tk.Tk()
        self.root.title("ShellSuite")
        self.root.geometry("1400x620")
        self.root.minsize(1000, 500)
        theme.apply(self.root)
        self._window_icons: list[tk.PhotoImage] = []
        self._apply_window_icon()

        self.sections: list[Section] = []
        self.current_index = 0
        self._tabs: list[dict] = []
        self._current_content: tk.Widget | None = None
        self.active_terminals: dict[str, dict] = {}

        self._build_layout()
        self._discover_sections()
        if self.sections:
            self.select_section(0)
        self.root.protocol("WM_DELETE_WINDOW", self.quit)

    # -- layout --------------------------------------------------------------
    def _apply_window_icon(self) -> None:
        for size in (256, 64, 48, 32, 16):
            path = icons.ASSETS / f"appicon-{size}.png"
            if not path.is_file():
                continue
            try:
                self._window_icons.append(tk.PhotoImage(file=str(path)))
            except tk.TclError:
                continue
        if self._window_icons:
            try:
                self.root.iconphoto(True, *self._window_icons)
            except tk.TclError:
                pass

    def _build_layout(self) -> None:
        topbar = tk.Frame(self.root, bg=theme.BG)
        topbar.pack(side="top", fill="x")
        tk.Frame(self.root, bg=theme.BORDER, height=1).pack(side="top", fill="x")

        logo = widgets.IconButton(
            topbar, "logo", None, size=90, color=theme.TEXT, hover=False
        )
        logo.pack(side="left", padx=(16, 10), pady=10)
        spacer = max(
            0, SIDEBAR_WIDTH + 1 - (16 + logo.winfo_reqwidth() + 10)
        )
        tk.Frame(topbar, bg=theme.BG, width=spacer).pack(side="left")
        self.tabs_frame = tk.Frame(topbar, bg=theme.BG)
        self.tabs_frame.pack(side="left", fill="y")

        exit_button = tk.Button(
            topbar, text="Exit", command=self.quit,
            bg=theme.BG, fg=theme.ACCENT, activebackground=theme.BG,
            activeforeground=theme.ACCENT_HOVER, relief="flat", bd=0,
            font=theme.FONT, cursor="hand2",
        )
        exit_button.pack(side="right", padx=20)

        body = tk.Frame(self.root, bg=theme.BG)
        body.pack(side="top", fill="both", expand=True)

        self.terminal_sidebar = tk.Frame(body, bg=theme.BG, width=SIDEBAR_WIDTH)
        self.terminal_sidebar.pack(side="left", fill="y")
        self.terminal_sidebar.pack_propagate(False)
        tk.Frame(body, bg=theme.BORDER, width=1).pack(side="left", fill="y")

        self.content = tk.Frame(body, bg=theme.BG)
        self.content.pack(side="left", fill="both", expand=True)

        self._placeholder = widgets.label(
            self.terminal_sidebar, "No active terminals", muted=True, bg=theme.BG
        )
        self._placeholder.pack(anchor="w", padx=14, pady=14)

    def _discover_sections(self) -> None:
        for name in config.MODULE_NAMES:
            try:
                module = importlib.import_module(f"{name}.gui")
            except ImportError:
                continue
            register = getattr(module, "register", None)
            if callable(register):
                register(self)

    # -- sections / tabs -----------------------------------------------------
    def add_section(self, title: str, icon: str, section: Section) -> None:
        index = len(self.sections)
        self.sections.append(section)
        section.build(self.content)

        tab = tk.Frame(self.tabs_frame, bg=theme.BG, cursor="hand2")
        tab.pack(side="left", padx=(0, 22), pady=8)

        underline = tk.Frame(tab, bg=theme.BG, height=2)
        underline.pack(side="bottom", fill="x")

        icon_button = widgets.IconButton(
            tab, icon, lambda i=index: self.select_section(i),
            size=60, color=theme.MUTED, bg=theme.BG, hover=False,
        )
        icon_button.pack(side="left")

        text = tk.Label(
            tab, text=title, bg=theme.BG, fg=theme.MUTED,
            font=theme.FONT_TITLE, cursor="hand2",
        )
        text.pack(side="left", padx=(6, 0))

        entry = {"tab": tab, "icon": icon_button, "label": text, "underline": underline}
        self._tabs.append(entry)

        for target in (tab, text, underline):
            target.bind("<Button-1>", lambda _e, i=index: self.select_section(i))
            target.bind("<Enter>", lambda _e, i=index: self._tab_hover(i, True), add="+")
            target.bind("<Leave>", lambda _e, i=index: self._tab_hover(i, False), add="+")
        icon_button.bind("<Button-1>", lambda _e, i=index: self.select_section(i))

    def _tab_hover(self, index: int, hovering: bool) -> None:
        if index == self.current_index:
            return
        entry = self._tabs[index]
        entry["label"].configure(fg=theme.TEXT if hovering else theme.MUTED)

    def _update_tabs(self) -> None:
        for index, entry in enumerate(self._tabs):
            active = index == self.current_index
            entry["label"].configure(fg=theme.TEXT if active else theme.MUTED)
            entry["icon"].set_color(theme.TEXT if active else theme.MUTED)
            entry["underline"].configure(bg=theme.BORDER if active else theme.BG)

    def select_section(self, index: int) -> None:
        if not self.sections:
            return
        self.current_index = index
        self._update_tabs()
        section = self.sections[index]
        self.show_content(section.frame)
        section.on_show()

    def return_to_section(self) -> None:
        self.select_section(self.current_index)

    def notify_changed(self) -> None:
        for section in self.sections:
            if section.frame is not None:
                section.refresh()

    # -- content -------------------------------------------------------------
    def show_content(self, widget: tk.Widget) -> None:
        for section in self.sections:
            if section.frame is not None and section.frame is not widget:
                section.frame.pack_forget()
        if self._current_content is not None and self._current_content is not widget:
            try:
                self._current_content.pack_forget()
            except tk.TclError:
                pass
        widget.pack(fill="both", expand=True)
        self._current_content = widget

    # -- active terminals ----------------------------------------------------
    def get_active_terminal(self, key: str):
        entry = self.active_terminals.get(key)
        return entry["view"] if entry else None

    def add_active_terminal(self, key: str, title: str, view) -> None:
        if key in self.active_terminals:
            self.show_content(self.active_terminals[key]["view"])
            return

        self._placeholder.pack_forget()
        row = tk.Frame(self.terminal_sidebar, bg=theme.BG, cursor="hand2")
        row.pack(fill="x")
        accent = tk.Frame(row, bg=theme.BG, width=3)
        accent.pack(side="left", fill="y")
        chevron = widgets.IconButton(
            row, "chevron", lambda k=key: self._select_terminal(k),
            size=14, color=theme.MUTED, bg=theme.BG,
        )
        chevron.pack(side="left", padx=(6, 0))
        text = tk.Label(
            row, text=title, bg=theme.BG, fg=theme.TEXT,
            font=theme.FONT, anchor="w", cursor="hand2",
        )
        text.pack(side="left", fill="x", expand=True, padx=(4, 8))

        entry = {
            "row": row, "accent": accent, "chevron": chevron, "label": text,
            "view": view, "selected": False,
        }
        self.active_terminals[key] = entry

        for target in (row, text, chevron):
            target.bind("<Button-1>", lambda _e, k=key: self._select_terminal(k))
            target.bind("<Enter>", lambda e, k=key: self._terminal_hover(k, True), add="+")
            target.bind("<Leave>", lambda e, k=key: self._terminal_hover(k, False), add="+")

        self._select_terminal(key)

    def _terminal_hover(self, key: str, hovering: bool) -> None:
        entry = self.active_terminals.get(key)
        if entry is None or entry["selected"]:
            return
        bg = theme.SIDEBAR_HOVER if hovering else theme.BG
        entry["row"].configure(bg=bg)
        entry["label"].configure(bg=bg)
        entry["chevron"].set_bg(bg)

    def _select_terminal(self, key: str) -> None:
        entry = self.active_terminals.get(key)
        if entry is None:
            return
        for other in self.active_terminals.values():
            other["selected"] = other is entry
            self._paint_terminal_row(other)
        self.show_content(entry["view"])

    def _paint_terminal_row(self, entry: dict) -> None:
        if entry["selected"]:
            entry["row"].configure(bg=theme.CARD)
            entry["label"].configure(bg=theme.CARD)
            entry["chevron"].set_bg(theme.CARD)
            entry["accent"].configure(bg=theme.SHELL_BORDER)
        else:
            entry["row"].configure(bg=theme.BG)
            entry["label"].configure(bg=theme.BG)
            entry["chevron"].set_bg(theme.BG)
            entry["accent"].configure(bg=theme.BG)

    def on_terminal_closed(self, key: str) -> None:
        entry = self.active_terminals.pop(key, None)
        if entry is None:
            return
        view = entry["view"]
        entry["row"].destroy()
        if not self.active_terminals:
            self._placeholder.pack(anchor="w", padx=14, pady=14)
        if self._current_content is view:
            self.select_section(self.current_index)
        self.notify_changed()

    def force_close_terminal(self, key: str) -> None:
        entry = self.active_terminals.get(key)
        if entry is None:
            return
        try:
            entry["view"].terminate()
        except Exception:  # noqa: BLE001 - best effort
            pass
        self.on_terminal_closed(key)

    # -- lifecycle -----------------------------------------------------------
    def quit(self) -> None:
        for entry in list(self.active_terminals.values()):
            try:
                entry["view"].terminate()
            except Exception:  # noqa: BLE001 - best effort
                pass
        self.root.destroy()


def run() -> None:
    app = ShellSuiteApp()
    app.root.mainloop()
