"""Creator <-> Manager protocol contract (FROZEN).

The webshell PHP the Creator emits and the requests the Manager sends both
implement this contract. Anything here is shared by both modules, so changing
it changes both at once (AGENTS.md section 4).

Generated PHP targets PHP 5.2+ (the lab runs an old interpreter), so templates
must avoid newer syntax (e.g. no null-coalescing `??`, no short-array `[]`).
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

# Credential channel per vector, for auth (and later encrypted) modes.
AUTH_PARAM_NAMES: dict[str, str] = {
    "cookie": "shellshock_auth",
    "header": "X-ShellShock-Auth",
    "post": "shellshock_auth",
}

# --- Response framing ------------------------------------------------------

RESPONSE_BEGIN = "<!--SSB-->"
RESPONSE_END = "<!--SSE-->"
