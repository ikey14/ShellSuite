"""Embedded live terminal view for a webshell."""

from __future__ import annotations

import json
import queue
import threading
import tkinter as tk
import tkinter.font as tkfont
from tkinter import ttk

from shellsuite.gui import cli_client, theme, widgets

from .dialogs import SecretDialog


class TerminalView(tk.Frame):
    """One live terminal (one per shell)."""

    def __init__(self, app, shell: dict, secret: str | None):
        super().__init__(app.content, bg=theme.BG)
        self.app = app
        self.shell = shell
        self.key = shell["id"]
        self.title = shell.get("name") or shell.get("url") or self.key
        self.prompt = f"{self.title}> "
        self._queue: queue.Queue = queue.Queue()
        self._closed = False
        self._after_id = None
        self._process = None
        self._session_id = None
        self._entry: tk.Entry | None = None
        self._input_window: tk.Frame | None = None
        self._prompt_start = None
        self._history: list[str] = []
        self._history_index = 0
        self._mono = tkfont.Font(font=theme.FONT_MONO)

        self._build()
        if self._start_process(secret):
            self._show_prompt()
        self._poll()

    # -- UI ------------------------------------------------------------------
    def _build(self) -> None:
        header = tk.Frame(self, bg=theme.BG)
        header.pack(fill="x", padx=14, pady=(12, 8))
        title = widgets.label(
            header, self.title, bold=True, bg=theme.BG, font=theme.FONT_TITLE
        )
        title.pack(side="left")
        widgets.IconButton(
            header, "close", self.request_close, size=18,
            color=theme.ACCENT, hover_color=theme.ACCENT_HOVER, bg=theme.BG,
        ).pack(side="right")
        tk.Frame(self, bg=theme.BORDER, height=1).pack(fill="x")

        body = tk.Frame(self, bg=theme.TERMINAL_BG)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        self.output = tk.Text(
            body, bg=theme.TERMINAL_BG, fg=theme.TEXT, insertbackground=theme.TEXT,
            selectbackground=theme.SHELL_BORDER, selectforeground=theme.TEXT,
            inactiveselectbackground=theme.SHELL_BORDER,
            relief="flat", bd=0, highlightthickness=0,
            font=theme.FONT_MONO, wrap="char", state="disabled",
            padx=8, pady=8, cursor="xterm",
        )
        scrollbar = ttk.Scrollbar(body, orient="vertical", command=self.output.yview)
        self.output.configure(yscrollcommand=scrollbar.set)
        self.output.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.output.tag_configure("prompt", foreground=theme.BORDER)
        self.output.tag_configure("muted", foreground=theme.MUTED)
        self.output.tag_configure("error", foreground=theme.ACCENT)
        self.output.bind("<Configure>", lambda _event: self._resize_entry())
        self.output.bind("<Button-1>", self._click_to_type, add="+")
        self.output.bind("<Control-c>", self._copy_selection, add="+")
        for target in (body, header, title, self):
            target.bind("<Button-1>", self._click_to_type, add="+")

    # -- process -------------------------------------------------------------
    def _start_process(self, secret: str | None) -> bool:
        try:
            self._process = cli_client.spawn_terminal(self.key, secret)
        except Exception as exc:  # noqa: BLE001
            self._append(f"error: {exc}\n", "error")
            self.after(10, self._finalize)
            return False
        threading.Thread(target=self._read_stdout, daemon=True).start()
        threading.Thread(target=self._read_stderr, daemon=True).start()
        return True

    def _read_stdout(self) -> None:
        try:
            for line in self._process.stdout:
                self._queue.put(("out", line.rstrip("\r\n")))
        finally:
            self._queue.put(("eof", None))

    def _read_stderr(self) -> None:
        try:
            for line in self._process.stderr:
                self._queue.put(("err", line.rstrip("\r\n")))
        except (OSError, ValueError):
            pass

    # -- event loop ----------------------------------------------------------
    def _poll(self) -> None:
        if self._closed:
            return
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if self._closed:
                    return
                if kind == "out":
                    self._handle_output(payload)
                elif kind == "err":
                    self._append(payload + "\n", "muted")
                elif kind == "eof":
                    self._finalize()
                    return
        except queue.Empty:
            pass
        try:
            self._after_id = self.after(50, self._poll)
        except tk.TclError:
            pass

    def _handle_output(self, payload: str) -> None:
        if not payload:
            return
        try:
            event = json.loads(payload)
        except json.JSONDecodeError:
            self._append(payload + "\n", "muted")
            self._show_prompt()
            return

        if event.get("event") == "session":
            self._session_id = event.get("id")
            return

        if event.get("success"):
            output = event.get("output") or ""
            if output:
                self._append(output)
                if not output.endswith("\n"):
                    self._append("\n")
            self._show_prompt()
        else:
            self._append(f"error: {event.get('error')}\n", "error")

    def _append(self, text: str, tag: str | None = None) -> None:
        if self._closed:
            return
        text = text.replace("\r\n", "\n").replace("\r", "")
        self.output.configure(state="normal")
        self.output.insert("end", text, tag or ())
        self.output.see("end")
        self.output.configure(state="disabled")

    # -- inline prompt -------------------------------------------------------
    def _show_prompt(self) -> None:
        if self._closed or self._entry is not None:
            return

        self.output.configure(state="normal")
        self._prompt_start = self.output.index("end-1c")
        self.output.insert("end", self.prompt, "prompt")

        frame = tk.Frame(self.output, bg=theme.TERMINAL_BG)
        entry = tk.Entry(
            frame, bg=theme.TERMINAL_BG, fg=theme.TEXT,
            insertbackground=theme.TEXT, selectbackground=theme.SHELL_BORDER,
            selectforeground=theme.TEXT, relief="flat", bd=0,
            highlightthickness=0, font=theme.FONT_MONO, width=10,
        )
        entry.pack(side="left", fill="both", expand=True)
        entry.bind("<Return>", self._submit)
        entry.bind("<Up>", self._history_up)
        entry.bind("<Down>", self._history_down)
        entry.bind("<Control-c>", self._copy_selection, add="+")
        self.output.window_create("end", window=frame)
        self.output.see("end")
        self.output.configure(state="disabled")

        self._input_window = frame
        self._entry = entry
        self._resize_entry()
        self.after(10, self._focus_entry)

    def _focus_entry(self) -> None:
        if self._entry is not None and not self._closed and self.winfo_ismapped():
            self._entry.focus_set()

    def _click_to_type(self, _event=None) -> None:
        if self._entry is not None and not self._closed:
            self.after_idle(self._focus_entry)

    def _copy_selection(self, _event=None):
        if not self.output.tag_ranges("sel"):
            return None
        try:
            text = self.output.get("sel.first", "sel.last")
        except tk.TclError:
            return None
        self.clipboard_clear()
        self.clipboard_append(text)
        return "break"

    def _resize_entry(self) -> None:
        if self._entry is None:
            return
        width = self.output.winfo_width()
        if width <= 1:
            return
        char_width = max(1, self._mono.measure("0"))
        prompt_width = self._mono.measure(self.prompt)
        columns = max(8, (width - prompt_width - 24) // char_width)
        self._entry.configure(width=columns)

    def _remove_prompt(self) -> None:
        self._entry = None
        if self._prompt_start is not None:
            self.output.configure(state="normal")
            self.output.delete(self._prompt_start, "end-1c")
            self.output.configure(state="disabled")
            self._prompt_start = None
        if self._input_window is not None:
            self._input_window.destroy()
            self._input_window = None

    def _echo(self, command: str) -> None:
        self.output.configure(state="normal")
        self.output.insert("end", self.prompt, "prompt")
        self.output.insert("end", command + "\n")
        self.output.see("end")
        self.output.configure(state="disabled")

    def _history_up(self, _event=None) -> str:
        if self._entry is None or not self._history:
            return "break"
        self._history_index = max(0, self._history_index - 1)
        self._set_entry_text(self._history[self._history_index])
        return "break"

    def _history_down(self, _event=None) -> str:
        if self._entry is None or not self._history:
            return "break"
        if self._history_index < len(self._history) - 1:
            self._history_index += 1
            self._set_entry_text(self._history[self._history_index])
        else:
            self._history_index = len(self._history)
            self._set_entry_text("")
        return "break"

    def _set_entry_text(self, text: str) -> None:
        self._entry.delete(0, "end")
        self._entry.insert(0, text)
        self._entry.icursor("end")

    # -- input / close -------------------------------------------------------
    def _submit(self, _event=None) -> str:
        if self._entry is None:
            return "break"
        command = self._entry.get().strip()
        if not command:
            return "break"

        self._history.append(command)
        self._history_index = len(self._history)
        self._remove_prompt()
        self._echo(command)
        try:
            self._process.stdin.write(command + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError, AttributeError):
            self._finalize()
        return "break"

    def request_close(self) -> None:
        if self._closed:
            return
        try:
            self._process.stdin.write("exit\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError, AttributeError):
            pass
        self.after(800, self._force_terminate)

    def _force_terminate(self) -> None:
        if self._closed:
            return
        if self._process is not None and self._process.poll() is None:
            try:
                self._process.terminate()
            except OSError:
                pass
        self._finalize()

    def _finalize(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._after_id is not None:
            try:
                self.after_cancel(self._after_id)
            except tk.TclError:
                pass
        if self._process is not None and self._process.poll() is None:
            try:
                self._process.terminate()
            except OSError:
                pass
        try:
            self.destroy()
        except tk.TclError:
            pass
        self.app.on_terminal_closed(self.key)

    def terminate(self) -> None:
        """Kill the process without triggering the close callbacks (app exit)."""
        if self._closed:
            return
        self._closed = True
        if self._after_id is not None:
            try:
                self.after_cancel(self._after_id)
            except tk.TclError:
                pass
        if self._process is not None and self._process.poll() is None:
            try:
                self._process.terminate()
            except OSError:
                pass
        try:
            self.destroy()
        except tk.TclError:
            pass


def open_terminal(app, shell: dict) -> None:
    """Open (or focus) the terminal for a shell, prompting for a secret if needed."""
    key = shell["id"]
    existing = app.get_active_terminal(key)
    if existing is not None:
        app.show_content(existing)
        return

    secret = None
    if shell.get("has_secret"):
        prompt = f"Password for {shell.get('name') or shell.get('url') or key}"
        secret = SecretDialog.ask(app.root, prompt)
        if secret is None:
            return

    view = TerminalView(app, shell, secret)
    app.add_active_terminal(key, view.title, view)
