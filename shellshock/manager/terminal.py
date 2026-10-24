"""Interactive terminal for a deployed webshell.

A webshell is stateless per request, so commands do not share a shell: there is
no persistent cwd, environment or job control between them. The loop reads a
line, sends it, prints the framed output and repeats until ``exit``/``quit`` or
EOF. Any command error ends the terminal (the CLI must not silently continue).
"""

from __future__ import annotations

import json
from typing import Callable

from . import client

EXIT_WORDS = frozenset({"exit", "quit"})


def interact(
    shell: client.WebShell,
    *,
    read_line: Callable[[str], str | None],
    write: Callable[[str], None],
    write_err: Callable[[str], None],
    run_command: Callable[..., client.ShellResult] = client.run,
    timeout: float = 15.0,
    json_mode: bool = False,
    on_event: Callable[[dict], None] | None = None,
) -> int:
    """Run the terminal loop. Returns the process exit code."""
    prompt = "" if json_mode else f"{shell.name or shell.url}> "

    while True:
        raw = read_line(prompt)
        if raw is None:  # EOF / Ctrl-D
            return 0

        command = raw.strip()
        if command == "":
            continue
        if command.lower() in EXIT_WORDS:
            return 0

        result = run_command(shell, command, timeout=timeout)
        event = {
            "command": command,
            "success": result.success,
            "output": result.output,
            "error": result.error,
        }

        if json_mode:
            write(json.dumps(event) + "\n")
        elif result.success:
            write(result.output)
            if not result.output.endswith("\n"):
                write("\n")
        else:
            write_err(f"error: {result.error}\n")

        if on_event is not None:
            on_event(event)

        if not result.success:
            return 1
