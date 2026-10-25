"""Reusable dark-theme widgets for the ShellSuite GUI."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from . import icons, query, theme
from .date_picker import DateEntry, is_date_text


def label(parent, text: str = "", *, muted: bool = False, bold: bool = False,
          bg: str = theme.BG, font=None, **kwargs):
    resolved_font = font or (theme.FONT_BOLD if bold else theme.FONT)
    return theme.make_label(
        parent, text, fg=theme.MUTED if muted else theme.TEXT, bg=bg,
        font=resolved_font, **kwargs
    )


class IconButton(tk.Canvas):
    """A clickable Canvas icon with hover feedback."""

    def __init__(self, parent, kind: str, command=None, *, size: int = 22,
                 color: str = theme.TEXT, hover_color: str | None = None,
                 bg: str = theme.BG, hover_bg: str = theme.HOVER_BG, pad: int = 4,
                 hover: bool = True):
        side = size + pad * 2
        super().__init__(
            parent, width=side, height=side, bg=bg, highlightthickness=0,
            bd=0, cursor="hand2" if command else "arrow",
        )
        self._kind = kind
        self._size = size
        self._pad = pad
        self._color = color
        self._hover_color = hover_color or color
        self._bg = bg
        self._hover_bg = hover_bg
        self._command = command
        self._image = None
        self._render(self._color, self._bg)

        if hover:
            self.bind("<Enter>", lambda _e: self._render(self._hover_color, self._hover_bg))
            self.bind("<Leave>", lambda _e: self._render(self._color, self._bg))
        if command is not None:
            self.bind("<Button-1>", lambda _e: command())

    def _render(self, color: str, bg: str) -> None:
        self.configure(bg=bg)
        self.delete("all")
        image = icons.load_asset(self._kind, self._size, color)
        if image is not None:
            self._image = image
            center = self._pad + self._size / 2
            self.create_image(center, center, image=image)
        else:
            self._image = None
            icons.draw_icon(self, self._kind, color, self._size, (self._pad, self._pad))

    def set_bg(self, bg: str) -> None:
        self._bg = bg
        self.configure(bg=bg)

    def set_color(self, color: str, hover_color: str | None = None) -> None:
        self._color = color
        self._hover_color = hover_color or color
        self._render(self._color, self._bg)


class ScrollableFrame(tk.Frame):
    """A vertically scrollable container."""

    def __init__(self, parent, *, bg: str = theme.BG):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")
        self._scrollbar_visible = True

        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self._sync_pending = False
        self.inner.bind("<Configure>", lambda _e: self.sync())
        self.canvas.bind("<Configure>", self._resize_inner)
        self.bind_wheel(self.canvas)
        self.bind_wheel(self.inner)
        self.sync()

    def _resize_inner(self, event) -> None:
        self.canvas.itemconfigure(self._window, width=event.width)
        self.sync()

    def sync(self) -> None:
        """Recompute the scrollregion and the scrollbar state after a change."""
        if self._sync_pending:
            return
        self._sync_pending = True
        try:
            self.after_idle(self._apply_sync)
        except tk.TclError:
            self._sync_pending = False

    def _apply_sync(self) -> None:
        self._sync_pending = False
        if not self.winfo_exists():
            return
        height = self.inner.winfo_reqheight()
        self.canvas.configure(
            scrollregion=(0, 0, self.canvas.winfo_width(), height)
        )
        if height <= self.canvas.winfo_height():
            self.canvas.yview_moveto(0)
            if self._scrollbar_visible:
                self.scrollbar.pack_forget()
                self._scrollbar_visible = False
        else:
            if not self._scrollbar_visible:
                self.scrollbar.pack(side="right", fill="y")
                self._scrollbar_visible = True
            self.scrollbar.state(["!disabled"])

    def bind_wheel(self, widget) -> None:
        widget.bind("<MouseWheel>", self._wheel, add="+")
        widget.bind("<Button-4>", self._wheel, add="+")
        widget.bind("<Button-5>", self._wheel, add="+")

    def _wheel(self, event) -> str:
        if self.inner.winfo_reqheight() <= self.canvas.winfo_height():
            self.canvas.yview_moveto(0)
            return "break"
        number = getattr(event, "num", None)
        if number == 4:
            step = -1
        elif number == 5:
            step = 1
        else:
            step = -1 if getattr(event, "delta", 0) > 0 else 1
        self.canvas.yview_scroll(step, "units")
        return "break"


class HoverCard(tk.Frame):
    """A bordered card that brightens its border on hover."""

    def __init__(self, parent, *, border: str, hover_border: str, bg: str = theme.CARD):
        super().__init__(
            parent, bg=bg, highlightthickness=1,
            highlightbackground=border, highlightcolor=border, bd=0,
        )
        self._border = border
        self._hover_border = hover_border

    def enable_hover(self) -> None:
        self._bind_tree(self)

    def _bind_tree(self, widget) -> None:
        widget.bind("<Enter>", self._enter, add="+")
        widget.bind("<Leave>", self._leave, add="+")
        for child in widget.winfo_children():
            self._bind_tree(child)

    def _set_border(self, color: str) -> None:
        self.configure(highlightbackground=color, highlightcolor=color)

    def _enter(self, _event) -> None:
        self._set_border(self._hover_border)

    def _leave(self, event) -> None:
        under = self.winfo_containing(event.x_root, event.y_root)
        if under is not None and self._is_descendant(under):
            return
        self._set_border(self._border)

    def _is_descendant(self, widget) -> bool:
        current = widget
        while current is not None:
            if current is self:
                return True
            current = getattr(current, "master", None)
        return False


class FilterOrderPanel(tk.Frame):
    """Structured order + filter controls shared by the list views."""

    def __init__(self, parent, *, fields, operators, date_fields, on_apply,
                 default_order: str, default_descending: bool = True,
                 shell_choices=None):
        super().__init__(
            parent, bg=theme.BG, highlightthickness=1,
            highlightbackground=theme.BORDER, bd=0, width=320,
        )
        self.pack_propagate(False)
        self._fields = tuple(fields)
        self._operators = tuple(operators)
        if not self._operators:
            raise ValueError("operators must not be empty")
        self._date_fields = tuple(date_fields)
        self._on_apply = on_apply
        self._rows: list[dict] = []
        self._shell_map: dict[str, str | None] = {}

        body = tk.Frame(self, bg=theme.BG)
        body.pack(fill="both", expand=True, padx=12, pady=12)

        label(body, "Filters and ordering", bold=True).pack(anchor="w", pady=(0, 10))

        label(body, "Order", muted=True, font=theme.FONT_SMALL).pack(anchor="w")
        self.order_var = tk.StringVar(value=default_order)
        self.order_combo = ttk.Combobox(
            body, textvariable=self.order_var, values=self._fields, state="readonly"
        )
        self.order_combo.pack(fill="x", pady=(2, 8))

        label(body, "Direction", muted=True, font=theme.FONT_SMALL).pack(anchor="w")
        self.direction_var = tk.StringVar(
            value="Descending" if default_descending else "Ascending"
        )
        self.direction_combo = ttk.Combobox(
            body, textvariable=self.direction_var,
            values=("Descending", "Ascending"), state="readonly",
        )
        self.direction_combo.pack(fill="x", pady=(2, 8))

        self.shell_combo = None
        if shell_choices is not None:
            label(body, "Shell", muted=True, font=theme.FONT_SMALL).pack(anchor="w")
            self.shell_var = tk.StringVar(value="All")
            self.shell_combo = ttk.Combobox(
                body, textvariable=self.shell_var, values=("All",), state="readonly"
            )
            self.shell_combo.pack(fill="x", pady=(2, 8))
            self.set_shells(shell_choices)

        label(body, "Filters", muted=True, font=theme.FONT_SMALL).pack(anchor="w")
        self.rows_frame = tk.Frame(body, bg=theme.BG)
        self.rows_frame.pack(fill="x", pady=(2, 6))

        add = theme.make_button(body, "+ Add filter", self.add_filter_row)
        add.configure(padx=8, pady=3, font=theme.FONT_SMALL)
        add.pack(anchor="w", pady=(0, 10))

        apply = theme.make_button(body, "Apply", self._on_apply)
        apply.pack(fill="x", pady=(0, 4))

        self.add_filter_row()

    # -- shells selector -----------------------------------------------------
    def current_shell_id(self) -> str | None:
        if self.shell_combo is None:
            return None
        return self._shell_map.get(self.shell_var.get())

    def set_shells(self, choices) -> None:
        if self.shell_combo is None:
            return
        current = self.current_shell_id()
        mapping: dict[str, str | None] = {"All": None}
        seen: dict[str, int] = {}
        for shell_id, title in choices:
            candidate = title or shell_id
            seen[candidate] = seen.get(candidate, 0) + 1
            if seen[candidate] > 1:
                candidate = f"{candidate} ({shell_id[:6]})"
            mapping[candidate] = shell_id
        self._shell_map = mapping
        self.shell_combo.configure(values=tuple(mapping))
        restore = next((name for name, sid in mapping.items() if sid == current), "All")
        self.shell_var.set(restore)

    # -- filter rows ---------------------------------------------------------
    def add_filter_row(self) -> None:
        row = tk.Frame(self.rows_frame, bg=theme.BG)
        row.pack(fill="x", pady=(0, 4))

        field_var = tk.StringVar(value=self._fields[0])
        field_combo = ttk.Combobox(
            row, textvariable=field_var, values=self._fields,
            state="readonly", width=8,
        )
        field_combo.pack(side="left", fill="x", expand=True)

        operator_var = tk.StringVar(value=self._operators[0])
        operator_combo = ttk.Combobox(
            row, textvariable=operator_var, values=self._operators,
            state="readonly", width=9,
        )
        operator_combo.pack(side="left", padx=(4, 4))

        holder = tk.Frame(row, bg=theme.BG)
        holder.pack(side="left", fill="x", expand=True)

        value_var = tk.StringVar()
        data = {
            "frame": row, "field": field_var, "op": operator_var,
            "value": value_var, "holder": holder,
            "value_widget": None, "is_date": None,
        }

        remove = IconButton(
            row, "close", lambda: self._remove_row(data), size=12,
            color=theme.MUTED, bg=theme.BG,
        )
        remove.pack(side="left", padx=(4, 0))
        self._rows.append(data)
        field_combo.bind(
            "<<ComboboxSelected>>",
            lambda _event, item=data: self._on_field_changed(item),
            add="+",
        )
        self._make_value_widget(data)

    def _make_value_widget(self, data: dict) -> None:
        for child in data["holder"].winfo_children():
            child.destroy()

        date_field = data["field"].get() in self._date_fields
        current = data["value"].get().strip()
        if date_field and current and not is_date_text(current):
            data["value"].set("")

        if date_field:
            widget = DateEntry(data["holder"], textvariable=data["value"])
        else:
            widget = ttk.Entry(data["holder"], textvariable=data["value"], width=8)
        widget.pack(fill="x", expand=True)
        data["value_widget"] = widget
        data["is_date"] = date_field

    def _on_field_changed(self, data: dict) -> None:
        is_date = data["field"].get() in self._date_fields
        if is_date == data["is_date"]:
            return
        self._make_value_widget(data)

    def _remove_row(self, data: dict) -> None:
        data["frame"].destroy()
        if data in self._rows:
            self._rows.remove(data)

    # -- values --------------------------------------------------------------
    def values(self):
        descending = self.direction_var.get().startswith("Desc")
        expressions = query.build_filters(
            (row["field"].get(), row["op"].get(), row["value"].get())
            for row in self._rows
        )
        return self.order_var.get(), descending, self.current_shell_id(), expressions
