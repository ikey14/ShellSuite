# ShellBlock — Working Brief (delivery 29 Nov 2026)

Context for coding agents (Opencode / GitHub Copilot). **This file is
self-contained**: everything needed to implement ShellBlock is here — contracts,
rule table, scoring, pipeline behaviour, plan. If something is missing, ask;
do not invent it.

## 1. Context

- Academic project for the course *Proyectos de Ciberseguridad*. Delivery:
  **Sunday 29 November 2026** — code + demo video + a short memoria.
- **ShellShock is delivered and frozen.** Do not modify `shellshock/` beyond the
  one shared-code change in §3, and never make it depend on `shellblock/`.
- **Scope of this delivery = ShellBlock only**, two modules:
  1. **Archivo** — file analysis: signature stage, static stage, hidden webshells
     (PHP inside a JPEG, extension/magic mismatch), risk score.
  2. **Capturas** — capture analysis: packet filtering to reduce processing load,
     signature stage, static stage, risk score.
- The memoria and the video are written by the student, not by you. Do not write
  them unless explicitly asked.

## 2. Architecture (non-negotiable)

```
ShellSuite/
├── shellsuite/     # ONLY what both modules share (config, protocol, crypto, filters)
├── shellshock/     # delivered October. Frozen.
└── shellblock/
    ├── cli.py              # register_parser(): `shellsuite block <action>`
    ├── rules.json          # THE rule table: id, kind, title, category, points, pattern
    ├── rules.py            # loader + validator + DETECTORS: rule_id -> detector fn
    ├── pipeline.py         # detect -> signature -> static -> write result
    ├── detect.py           # magic bytes vs extension, type table, size limits
    ├── result.py           # Finding/Result dataclasses, JSON I/O, evidence escaping
    ├── store.py            # read/write/glob the analysis dir, atomic writes
    ├── analyze/            # signatures.py, php_static.py, image_static.py, capture_static.py
    ├── score/              # scoring.py
    ├── list/               # list_cmd.py
    └── show/               # show_cmd.py
```

Rules:

1. **Independence:** ShellShock must keep working with `shellblock/` absent or
   broken. Zero imports from `shellblock` inside `shellshock`.
2. **Shared code lives only in `shellsuite/`.** Nothing is duplicated between
   modules, and no module imports from the other.
3. **CLI-first:** every capability is a CLI subcommand. No GUI in this delivery.
4. **No AI inside the tool.** No LLM, no models, no API calls at runtime.
5. **Analysis never judges; scoring never re-analyses.** `analyze` writes findings;
   `score` reads that JSON and nothing else — it never opens the original file.
6. **The analyzer never executes a payload and never sends traffic.** Read-only.

## 3. One shared-code change, up front

`shellshock/manager/filters.py` moves to **`shellsuite/filters.py`** (both modules
filter listings with the same `attr op value` grammar — rule 2).
`shellshock/manager/filters.py` stays as a one-line re-export so
`tests/test_filters.py` and `registry.py` keep working untouched.

Add to `shellsuite/config.py`, next to the existing helpers:

```python
def analysis_dir() -> Path:
    """Directory holding per-file analysis results and scores."""
    directory = data_dir() / "analysis"
    directory.mkdir(parents=True, exist_ok=True)
    return directory
```

## 4. Contract A — the result file

`~/.shellsuite/analysis/<basename>_result.json` (extension kept in the name, so
`shell.php` and `shell.jpg` do not collide):

```json
{
  "schema": 1,
  "tool": {"name": "shellblock", "version": "0.1.0"},
  "target": {
    "path": "/abs/path/photo.jpg", "name": "photo.jpg", "size": 84213,
    "sha256": "…", "extension": "jpg", "detected_type": "jpeg",
    "type_mismatch": false, "analyzed_at": "2026-11-17T10:04:11+00:00",
    "truncated": false
  },
  "stages": [
    {"name": "detect",    "status": "ok", "duration_ms": 0},
    {"name": "signature", "status": "ok", "duration_ms": 3, "rules": 48, "matched": 2},
    {"name": "static",    "status": "ok", "duration_ms": 11, "units": 1}
  ],
  "findings": [
    {"rule_id": "IMG_HIDDEN_PHP", "subject": "file", "severity": "critical",
     "location": {"kind": "byte_offset", "offset": 24, "segment": "COM"},
     "evidence": "<?php system($_GET['c']); ?>",
     "detail": {"segment_length": 30}}
  ],
  "notes": [],
  "errors": []
}
```

Field meanings:

| field | meaning |
|---|---|
| `schema` | format version (1). Bumped only when a field changes meaning; `score` refuses a file it does not understand. |
| `target.truncated` | `true` when the file exceeded `--max-size` and only the first N MB were read. `size` keeps the real size. |
| `stages[].status` | `ok` · `skipped` (not applicable to this type) · `error` (see `errors[]`). Always present. |
| `stages[].rules` | rules of that stage's kind in `rules.json`. On a capture the stage spans the wire heads **and** the carved bodies, so this is the whole kind, not the subset applicable to `pcap`. |
| `stages[].matched` | how many of them produced ≥ 1 finding anywhere in the result, wire or carved body (`matched ≤ rules`). |
| `stages[].units` | structural units walked: 1 per file; for a capture, 1 + one per TCP conversation + one per uploaded file part. |
| `findings[].detail` | per-rule extras for `show` (segment length, nesting depth, HTTP status). **Never scored**, never parsed by `score`. |
| `notes[]` | detector remarks that are not evidence: TLS flow opaque + SNI, file truncated, h2 not decoded. |
| `errors[]` | what failed: tshark exit 2, malformed multipart part, unreadable JPEG segment. |

Invariants (tests assert them):

1. `findings` is **flat** — never nested, never grouped.
2. Every `rule_id` exists in `rules.json`. `score` fails loudly on an unknown id.
3. `evidence` is printable: bytes outside 0x20–0x7E become `\xNN`, max 120 chars.
   The JSON never carries raw binary.
4. Findings are sorted by `(category, location.offset, rule_id)` — two runs on the
   same file are byte-identical.
5. `subject`: `"file"`, `"flow:<src>:<sport>-><dst>:<dport>"`, or `"upload:<name>"`.
   A `flow:` subject is per **direction**, so one TCP conversation yields two
   (request-side findings on `client->server`, response-side on `server->client`).
   An `upload:` subject is a carved HTTP body named after the request URI; its
   `detail` carries `frame`, `stream`, `role` (`upload` / `request` / `response`)
   and the tshark object name, because two bodies can share one name.
6. `location.kind` ∈ `byte_offset` · `line` · `segment` · `chunk` · `packet` ·
   `stream` · `http`. `score` never parses `location`; `show` does.

## 5. Contract B — the score file

`~/.shellsuite/analysis/<basename>_score.json`, written from the result file only:

```json
{
  "schema": 1,
  "target": {"name": "photo.jpg", "sha256": "…"},
  "score": 87, "raw_points": 87,
  "ruleset": "2026-11-17+ab12cd34",
  "contributions": [
    {"rule_id": "IMG_HIDDEN_PHP", "title": "PHP code hidden in an image", "points": 45, "count": 1},
    {"rule_id": "PHP_OS_EXEC_OF_INPUT", "title": "OS command built from request input", "points": 30, "count": 1},
    {"rule_id": "PHP_OBFUSCATION_LADDER", "title": "Nested decode chain", "points": 12, "count": 1}
  ],
  "breakdown": {"by_category": {"hidden_payload": 45, "code_execution": 30, "obfuscation": 12},
                "corroboration": 0, "capped": false}
}
```

- `score` **is** the likelihood percentage (0–100). There is no verdict field —
  do not add one. `show` prints `87/100 (87 %)`.
- `contributions` = top 3 by points, ties broken by `rule_id` (deterministic).
- `count` = times the rule fired; the weight is added **once**.
- `raw_points` = sum before the 100 cap. `ruleset` = `rules.json` `version` +
  first 8 hex of its sha256 — two scores are comparable only if it matches.
- `breakdown` = points per category after the once-per-rule rule, the corroboration
  bonus granted, and whether the cap bit.

## 6. Rules: `rules.json` + `rules.py` + the table

### 6.1 `rules.json`

Single registry. The repo currently has `categories` as a bare list and no `rules`
— upgrade it to this shape:

```json
{
  "version": "2026-11-17",
  "categories": {
    "hidden_payload": "code or markup hidden inside a non-code container",
    "code_execution": "code or command execution reachable from request input",
    "obfuscation": "encoded, layered or padded payload",
    "identity": "the file is not what it claims to be",
    "network": "upload or command traffic inside a capture",
    "metadata": "shape and statistics of the file itself"
  },
  "rules": [
    {"id": "IMG_HIDDEN_PHP", "kind": "structural", "title": "PHP code hidden in an image",
     "category": "hidden_payload", "points": 45, "severity": "critical",
     "applies_to": ["jpeg", "png", "gif"],
     "rationale": "A picture never contains PHP; the segment or the tail carries a payload."},
    {"id": "SIG_PHP_TAG", "kind": "signature", "title": "PHP open tag",
     "category": "metadata", "points": 0, "severity": "info",
     "applies_to": ["jpeg", "png", "gif", "unknown"],
     "scope": "bytes", "pattern": "<\\?(php|=)?",
     "rationale": "Gate only: scores nothing, unlocks the hidden-payload rules."}
  ]
}
```

- `kind: "signature"` → executed from data: `pattern` is a Python `re` pattern,
  `scope` is `bytes` (raw buffer) or `text` (latin-1 decode, for case-insensitive
  markers). Adding one is a JSON edit only.
- `kind: "structural"` → the detector is Python, registered in `DETECTORS`.
- `points: 0` = gate/context rule, whatever its `kind`: it appears in findings, it
  can enable a structural rule, it contributes nothing to the score **and nothing
  to the category count**. A structural rule may be a gate (`PCAP_TLS_OPAQUE`
  reports ciphertext that must never be scored); a signature rule is **always**
  a gate, because a byte pattern alone is the weakest evidence there is.
- `applies_to` = detected types the rule is considered for. PHP inside a `.jpg`
  fires; the same bytes in a `.php` do not. That context check is the difference
  between a rule engine and a grep.

### 6.2 `rules.py`

Thin on purpose — loader, categories, and the registry. Detector bodies live in
`analyze/<format>_static.py`, never here:

```python
from shellblock.analyze import capture_static, image_static, php_static

DETECTORS = {
    "IMG_HIDDEN_PHP": image_static.find_hidden_php,
    "PHP_EVAL_OF_INPUT": php_static.find_eval_of_input,
    "PCAP_PHP_UPLOAD": capture_static.find_php_upload,
}
```

`block rules --validate` fails on:

1. duplicate or empty `id`;
2. `points > 0` with a category missing from `categories`;
3. `signature` without `pattern` + `scope` + `applies_to`, or a pattern that will
   not compile;
4. `structural` with no `DETECTORS` entry (defined, never implemented);
5. a `DETECTORS` entry with no `structural` rule (implemented, never weighted);
6. a `points: 0` rule that a `signature` field claims to score (signatures are
   gates: `points` must be 0 when `kind` is `signature`);
7. a result file that emits a `rule_id` the table does not declare, or whose
   `ruleset` does not match.

### 6.3 The rules to ship (transcribe verbatim, do not invent)

Tiers: **A 45–60** proof-class in that file type · **B 25–35** strong · **C 10–20**
moderate · **D 5–10** corroboration.

**Files — hidden payload / identity**

| rule_id | category | tier | pts | fires when |
|---|---|---|---|---|
| `IMG_PHP_BEFORE_SOI` | hidden_payload | A | 50 | `<?php` before the image start-of-image marker: the "image" is a PHP file wearing a `.jpg` name |
| `IMG_HIDDEN_PHP` | hidden_payload | A | 45 | `<?`/`<?php` inside a COM/APPn/text chunk (`location.kind=segment`) **or** after the end-of-image marker (`location.kind=trailing`) |
| `IMG_SCRIPT_IN_SEGMENT` | hidden_payload | B | 20 | `<script`/`onerror=` inside metadata (stored-XSS carrier) |
| `IMG_ZIP_AFTER_EOI` | hidden_payload | B | 35 | `PK\x03\x04` after EOI (PHAR polyglot) |
| `IMG_TRAILING_DATA` | metadata | C | 15 | non-empty data after EOI that is not PHP |
| `TYPE_MAGIC_MISMATCH` | identity | C | 20 | extension says image, magic says something else |
| `DOUBLE_EXTENSION` | identity | D | 10 | `shell.php.jpg` |

**Files — PHP statics**

| rule_id | category | tier | pts | fires when |
|---|---|---|---|---|
| `PHP_EVAL_OF_INPUT` | code_execution | A | 60 | `eval`/`assert` whose argument reaches `$_GET/$_POST/$_COOKIE/$_SERVER['HTTP_*']/php://input` |
| `PHP_OS_EXEC_OF_INPUT` | code_execution | A | 50 | `system/exec/shell_exec/passthru/popen/proc_open` or backticks, argument reaches input |
| `PHP_DYNAMIC_CALL_OF_INPUT` | code_execution | A | 50 | `call_user_func`/`$f()`/`array_map('assert', …)` with input or a decoder result |
| `PHP_INCLUDE_OF_INPUT` | code_execution | B | 30 | `include`/`require` with input (RFI/LFI; also legitimate → not A) |
| `PHP_WRITE_OF_INPUT` | code_execution | B | 30 | `file_put_contents`/`move_uploaded_file`/`fwrite` with input (dropper) |
| `PHP_OBFUSCATION_LADDER` | obfuscation | B | 30 | ≥ 2 **nested** decoders: `eval(gzinflate(base64_decode(…)))` |
| `PHP_KNOWN_FAMILY` | identity | B | 35 | family fingerprint: China Chopper `@eval($_POST[`, `c99shell`, `r57shell`, `b374k`, `WSO `, `P.A.S.` |
| `PHP_EXEC_SINK_ONLY` | code_execution | C | 18 | execution sink with no traceable source (still suspicious in a webroot) |
| `PHP_AUTH_GATE` | metadata | C | 15 | credential comparison immediately guarding an execution sink (all ShellShock shells) |
| `PHP_REQUEST_HEADER_SOURCE` | metadata | C | 12 | `getallheaders()` / `$_SERVER['HTTP_*']` (header-vector shells) |
| `PHP_BASE64_BLOB` | obfuscation | D | 8 | base64 literal ≥ 120 chars |
| `PHP_HIGH_ENTROPY` | obfuscation | D | 8 | Shannon entropy > 5.5 over a `.php` file (never for images: photos are always high) |
| `PHP_ONE_LINER` | metadata | D | 10 | ≤ 3 lines with an exec sink |
| `PHP_PADDED_TAG` | obfuscation | D | 10 | `<?php` after ≥ 1 KB of whitespace/NULs — grep won't find it, we do |

**Captures**

| rule_id | category | tier | pts | fires when |
|---|---|---|---|---|
| `PCAP_DISGUISED_UPLOAD` | network | A | 50 | multipart part with an image extension/`Content-Type` whose bytes are PHP or whose magic contradicts the declared type |
| `PCAP_PHP_UPLOAD` | network | A | 40 | multipart part with a `.php`/`.phtml` filename |
| `PCAP_SHELL_REQUEST` | network | A | 45 | request param/cookie/header carrying `system(`, `eval(`, `assert(`, backticks, or a ShellShock envelope (`SSENC1.`) |
| `PCAP_COMMAND_PARAM` | network | B | 20 | `?cmd=`, `?c=`, `?exec=`, `?shell=` on a `.php` path |
| `PCAP_SHELL_RESPONSE` | network | C | 18 | response body with `uid=\d+\(`, `www-data`, `root:x:0:0`, dir-listing markers |
| `PCAP_MISMATCHED_UPLOAD_RESPONSE` | network | C | 15 | upload answered 200 + body echoing the filename |
| `PCAP_BEACONING` | metadata | D | 10 | ≥ 5 requests, same path, near-identical length, regular interval |
| `PCAP_TLS_OPAQUE` | network | — | 0 | gate/notes rule: an encrypted flow exists; scores nothing, lands in `notes[]` with SNI |

**Signature rules (gates, `points: 0`)**

Every signature rule is a byte-level gate: it fires, it appears in `findings[]` with
its offset, and it hands the evidence to the structural rule that interprets it.
None of them scores — a byte pattern alone is the weakest evidence a detector can
claim, and the weight belongs to the rule that understands it. A signature hit with
no structural rule behind it stays in the result at 0 points, which is exactly what
`show` needs to prove the signature stage ran.

| rule_id | category | scope | applies_to | fires when | gates |
|---|---|---|---|---|---|
| `SIG_PHP_TAG` | hidden_payload | bytes | jpeg, png, gif, unknown | a PHP open tag or echo tag in a container that should not hold PHP | `IMG_HIDDEN_PHP`, `IMG_PHP_BEFORE_SOI` |
| `SIG_PHP_SINK_NAME` | code_execution | text | php, jpeg, png, gif, unknown | a call to a function that executes code or commands | `PHP_EVAL_OF_INPUT`, `PHP_OS_EXEC_OF_INPUT`, `PHP_DYNAMIC_CALL_OF_INPUT`, `PHP_EXEC_SINK_ONLY` |
| `SIG_PHP_SUPERGLOBAL` | code_execution | text | php, jpeg, png, gif, unknown | the file reads request input (`$_GET`, `$_POST`, …) | the `*_OF_INPUT` family |
| `SIG_PHP_DECODER` | obfuscation | text | php, unknown | a decoder call (`base64_decode`, `gzinflate`, …) | `PHP_OBFUSCATION_LADDER` |
| `SIG_BASE64_BLOB` | obfuscation | bytes | php, unknown | a base64 literal of ≥ 120 chars | `PHP_BASE64_BLOB`, `PHP_HIGH_ENTROPY` |
| `SIG_SHELL_FAMILY` | identity | text | php, jpeg, png, gif, unknown | a known webshell family fingerprint (c99, r57, b374k, WSO, P.A.S., China Chopper) | `PHP_KNOWN_FAMILY` |
| `SIG_SS_PARAM` | metadata | text | php, pcap | ShellShock's own channel names (`shellshock`, `shellshock_auth`, `X-ShellShock`, `X-ShellShock-Auth`) | `PHP_AUTH_GATE`, `PCAP_SHELL_REQUEST` |
| `SIG_SS_ENVELOPE` | obfuscation | bytes | php, unknown, pcap, upload | the `SSENC1.` (or future SSENC versions) encrypted-payload prefix | `PCAP_SHELL_REQUEST`, `PHP_OBFUSCATION_LADDER` |
| `SIG_SS_RESPONSE` | network | bytes | pcap, upload | ShellShock's response framing `<!--SSB-->` / `<!--SSE-->` in a body | `PCAP_SHELL_RESPONSE` |
| `SIG_UPLOAD_PART` | network | text | pcap, upload | a multipart part declaring a `.php`/`.phtml`/`.phar` filename | `PCAP_PHP_UPLOAD`, `PCAP_DISGUISED_UPLOAD` |
| `SIG_HTTP_PHP_URI` | network | bytes | pcap | an HTTP request line targeting a `.php` script | `PCAP_COMMAND_PARAM` |

Exact patterns for `rules.json` (Python `re`, JSON-escaped — the double backslashes
are part of the JSON string; `scope: "text"` always compiles with `re.IGNORECASE`,
`scope: "bytes"` is case-sensitive):

```json
"SIG_PHP_TAG":         {"scope": "bytes", "pattern": "<\\?(php|=|\\s)"},
"SIG_PHP_SINK_NAME":   {"scope": "text",  "pattern": "\\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open|call_user_func|create_function)\\s*\\("},
"SIG_PHP_SUPERGLOBAL": {"scope": "text",  "pattern": "\\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\\b"},
"SIG_PHP_DECODER":     {"scope": "text",  "pattern": "\\b(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|hex2bin|urldecode)\\s*\\("},
"SIG_BASE64_BLOB":     {"scope": "bytes", "pattern": "[A-Za-z0-9+/]{120,}={0,2}"},
"SIG_SHELL_FAMILY":    {"scope": "text",  "pattern": "(c99shell|r57shell|b374k|WSO [0-9]|P\\.A\\.S\\.|@eval\\s*\\(\\s*\\$_POST\\[)"},
"SIG_SS_PARAM":        {"scope": "text",  "pattern": "(shellshock_auth|shellshock|X-ShellShock(-Auth)?)"},
"SIG_SS_ENVELOPE":     {"scope": "bytes", "pattern": "SSENC"},
"SIG_SS_RESPONSE":     {"scope": "bytes", "pattern": "<!--SS[BE]-->"},
"SIG_UPLOAD_PART":     {"scope": "text",  "pattern": "filename=[\"']?[^\"';]+\\.(php[0-9]?|phtml|phar)"},
"SIG_HTTP_PHP_URI":    {"scope": "bytes", "pattern": "(GET|POST|HEAD) [^ ]*\\.php[? ]"}
```

`applies_to` values are the detected types from §8.1; `pcap` and `upload` mean the
capture stage's carved request/response bodies. `SIG_SS_PARAM`, `SIG_SS_ENVELOPE`
and `SIG_SS_RESPONSE` come straight from ShellShock's frozen protocol contract
(`shellsuite/protocol/contract.py`) — that is why the tool can recognise its own
generated shells, which is the demo beat.

### 6.4 The formula

```
score = min(100, Σ points of distinct rules with points > 0
                 + min(20, 10 × (distinct categories − 1)))
```

- Σ points: independent facts add; two real signals must beat one.
- distinct rules: a rule contributes once however often it fires — otherwise a
  4 000-packet capture reaches 100 by repetition alone.
- categories: +10 per *additional* kind of evidence; `− 1` because the first is
  already inside the sum. Corroboration capped at 20 so it can nudge, never carry.
- Only `points > 0` rules count toward categories, so a gate rule cannot
  manufacture one.
- **Specificity rule**: at one call site the most specific rule wins.
  `eval($_POST['x'])` emits `PHP_EVAL_OF_INPUT`, not also `PHP_EXEC_SINK_ONLY`.
  Same for `IMG_HIDDEN_PHP` vs `IMG_TRAILING_DATA`.
- Integers only. No floats, no negatives.

Worked example: PHP in a JPEG comment (45, hidden_payload) + `system($_GET)` in the
same file (50, code_execution) = 95, two categories → +10 → 105 → **100**.
A lone `TYPE_MAGIC_MISMATCH` (20, identity) = **20**.

## 7. Stack

- **Python 3.10+**, `argparse`, stdlib elsewhere. Match the repo's style and its
  `unittest` tests; add no test framework.
- Approved dependencies — nothing else without asking:
  - `pyshark` + the **tshark binary** (a Wireshark install; not a pip package).
  - `tree-sitter` + `tree-sitter-php` for PHP parsing.
- **`pyshark` is the interface, not a portability fix** — it shells out to tshark,
  so the binary is still the requirement. Its value: we read packet objects instead
  of a `-T fields` text grid, so a tshark version renaming a field breaks inside
  pyshark, not inside our parser. It has no equivalent of `--export-objects`, so
  carving stays one direct `tshark` call.
- **Never tshark in tests.** `capture_static.py` normalises packets into one
  `HttpMessage` model; `--dump-json` saves that model once from a real capture and
  the tests replay it. This dev container has no tshark and no root to install it:
  a test that needs the binary is a broken test.
- **`.pcap` only.** A pcapng file (magic `0A0D0D0A`) is refused with
  "save as *Wireshark/tcpdump pcap*", exit code 2 — never a traceback. The magic is
  in `info.json` (`pcapng`), so `detect.py` names it; `pipeline.analyze` is what
  refuses it. Do not let the name fall through to the `unknown` type, or a capture
  saved in Wireshark's default format is silently "clean".
- **After adding a package or a new `__init__.py`, re-run `pip install -e .`.** The
  editable-install finder is generated at install time and only maps packages that
  existed then: create `shellblock/analyze/` and, until you reinstall,
  `shellsuite block` silently disappears from the CLI (skipped as broken, rule 1).
  Verify with `shellsuite block --help` after every new package.
- Generated webshells come from `shellsuite shock create` — never hand-write a
  positive fixture when the real generator can produce it.

## 8. How each stage works

### 8.1 Type detection (`detect.py`)

Magic bytes decide the type; the extension only claims one. Aliases: `jpg`↔`jpeg`,
`phtml`/`php3`/`php4`/`php5`/`php7` → `php`.

| type | magic |
|---|---|
| `jpeg` | `FF D8 FF` |
| `png` | `89 50 4E 47 0D 0A 1A 0A` |
| `gif` | `GIF87a` / `GIF89a` |
| `php` | starts with `<?php` or `<?` (and the extension is php-ish) |
| `pcap` | `D4 C3 B2 A1` / `A1 B2 C3 D4` (and the ns variants `4D 3C B2 A1` / `A1 B2 3C 4D`) |
| `unknown` | anything else |

A `.jpg` that is really a PNG is `TYPE_MAGIC_MISMATCH`, not an error. Never compare
`extension == detected_type` without the alias table (that flags every JPEG).

`detect(path, extension_claims=False)` is for a body carved **whole** out of a
capture: tshark names those after the request URI, so the name is not a claim — the
type comes from the magic bytes alone and no mismatch is reported. Multipart
**parts** keep the claim (the filename is the attacker's), which is what lets
`PCAP_DISGUISED_UPLOAD` see a `.jpg` whose magic is not a picture.

### 8.2 Signature stage (`analyze/signatures.py`)

One matcher, driven by `rules.json`:

- `scope: "bytes"` → `re` over the raw buffer; `scope: "text"` → `re` over a
  latin-1 decode (every byte maps 1:1 to a code point, so decoding arbitrary
  binary never fails and no byte is lost) for case-insensitive markers.
- `finditer` reports **byte offsets**, so every finding is locatable and `show` can
  print `@offset 1069`.
- A few predicates need Python and are registered by id (e.g. `PHP_PADDED_TAG`
  needs "preceded by ≥ 1 KB of whitespace/NULs", which a regex cannot express
  cheaply).
- Cost: O(n). A 4 MB image is milliseconds.

### 8.3 PHP statics (`analyze/php_static.py`)

Parse with `tree-sitter` + `tree-sitter-php` (wheels on all three platforms; every
node carries `start_byte`/`end_byte`, which is what `location.offset` needs). No
PHP binary required. Malformed but runnable shells parse into error nodes around
the damage — tolerate them. (`phply` is unmaintained, PHP 5-era grammar: reject.)

1. **Walk**: collect `function_call_expression` / `member_call_expression` nodes
   with function name, byte range and argument node. Comments, strings,
   heredoc/nowdoc and `?>` inline HTML are the grammar's problem, not ours.
2. **Symbol table** (one hop): `$x = <expr>` records whether the expression is
   `input`, `decoder(input)`, `literal` or `call`. This is what makes
   `$b = base64_decode($_POST['x']); eval($b);` a hit: `eval($b)` has no `$_POST`
   in its own argument, the table supplies it. One hop = straight assignments only;
   `$b = helper()` where the input is read inside `helper()` is a documented miss.
3. **Sink × source**: a *sink* executes — `eval`, `assert`, `system`, `shell_exec`,
   `passthru`, `popen`, `proc_open`, backticks, `call_user_func`. A *source* is
   attacker input — `$_GET`, `$_POST`, `$_COOKIE`, `$_SERVER['HTTP_*']`,
   `php://input`. Sink whose argument resolves to a source ⇒
   `PHP_EVAL_OF_INPUT` / `PHP_OS_EXEC_OF_INPUT`. Nesting for
   `PHP_OBFUSCATION_LADDER` is measured by **node containment** (one call node
   inside another), never by counting decoder names near the sink — a window count
   flags two sibling `urldecode()` calls on adjacent lines as a "chain".
4. **Families**: scan the raw bytes for the family strings; no extra parse.
5. **Entropy**: Shannon over 256-byte windows, one rule, low weight, PHP only.

### 8.4 Image statics (`analyze/image_static.py`)

- **JPEG**: walk from SOI `FFD8`: each marker is `FFxx` + big-endian 2-byte length
  (standalone markers excepted), body follows; `COM`=`FFFE`, `APPn`=`FFE0..FFEF`;
  at `SOS` (`FFDA`) the entropy data starts — find `FFD9` (EOI) from there.
  Segment bodies are scanned for PHP/`<script`; everything after EOI is trailing
  data. PHP before SOI is `IMG_PHP_BEFORE_SOI`.
- **PNG**: 8-byte signature, then `length(4 BE) | type(4) | data | crc(4)` until
  `IEND`; scan `tEXt`/`iTXt`/`zTXt` bodies; anything after `IEND` is trailing.
- **GIF**: header `GIF87a`/`GIF89a`, blocks, extension introducer `21` with `F9`
  (graphic control) / `FE` (comment) / `FF` (application); trailer `3B`. Data after
  `3B` is trailing; `GIF89a` + immediate `<?php` is the classic polyglot.
- The tail is located once, so a 40 MB photo costs one scan of the tail, not of the
  whole file. Size cap default 64 MB (`--max-size`) sets `truncated`.

### 8.5 Captures (`analyze/capture_static.py`)

tshark does the wire work; we do the judgement. Every step feeds a `stages[]`
counter.

1. **Refuse** pcapng early (§7).
2. **Metadata + filter** via `pyshark.FileCapture(path,
   display_filter="http.request or http.response", keep_packets=False)`: read
   `pkt.http.request_method`, `pkt.http.request_uri`, `pkt.http.request_full_uri`,
   `pkt.http.request_cookie`, `pkt.http.user_agent`, `pkt.http.content_type`,
   `pkt.http.content_length`, `pkt.http.response_code`, `pkt.tcp.stream`,
   `pkt.ip.src/dst`. Normalise each packet into one internal `HttpMessage` record;
   `--dump-json` writes that model to disk. The rest of the module and the tests
   speak only that model.
3. **Bodies**: one direct call — `tshark -r <pcap> --export-objects http,<tmpdir> -q`
   — carves every object the dissector sees as a file body: uploads **and** ordinary
   responses such as page HTML or a JPEG. Carved files go through the file pipeline
   with `subject="upload:<name>"`, so upload detection and file analysis are the
   same code path. The temp dir is **deleted after the run by default**;
   `--keep-objects [DIR]` keeps it and reports the path in `notes[]`.
4. **Correlate** on `tcp.stream`: request URI → `PCAP_COMMAND_PARAM`; cookie and
   carved request bodies → `PCAP_SHELL_REQUEST`; `response_code` + carved response
   bodies → `PCAP_SHELL_RESPONSE`, `PCAP_MISMATCHED_UPLOAD_RESPONSE`; multipart
   parts → `PCAP_PHP_UPLOAD` / `PCAP_DISGUISED_UPLOAD`; repeated uniform requests →
   `PCAP_BEACONING`.
5. **Pre-filter accounting**: total frames vs the HTTP subset into `stages[]` — this
   is the "reduce the processing load" evidence.
6. **TLS**: SNI (`tls.handshake.extensions_server_name`) → `notes[]` +
   `PCAP_TLS_OPAQUE`. Never scored. Pretending to read ciphertext is a claim the
   tribunal will ask you to prove.
7. Cleartext HTTP/2 on a non-standard port needs `-d tcp.port==<p>,http2`; expose it
   as a flag only if the lab ever uses one.

## 9. CLI surface

```
shellsuite block analyze --file <path> [--json] [--max-size MB] [--keep-objects [DIR]] [--dump-json]
shellsuite block score   --file <name> [--json]
shellsuite block analyze --file <path> --score        # chain, for the demo
shellsuite block list results [--order <field>] [--asc|--desc] [--filter 'attr op value'] [--json]
shellsuite block list scores  [--order score] [--asc|--desc] [--filter 'score > 70'] [--json]
shellsuite block show --file <name> [--json]
shellsuite block rules [--json] [--validate]
```

- `analyze` writes the result file and prints one line:
  `photo.jpg: 2 findings, 45 raw points → run 'block score'`.
- `score` reads the result file only, writes the score file, prints
  `score: 87/100 (87 %)` + the top 3.
- `list` globs the analysis dir; filtering/ordering reuse `shellsuite.filters`, so
  the grammar matches `shock manage list` exactly.
- `show` renders result + score as a fixed-width block: target, stages, findings
  with `@offset`, score with contributions and breakdown.
- `--json` on every query action; never `print()` in a `--json` path.
- Exit codes: `0` ok · `1` target/stage error · `2` bad arguments. `analyze` exits
  `0` even when the file is malicious — a detector is not a gate.
- Remove the current `block test` placeholder when the first real action lands.

## 10. Objectives with acceptance criteria

| ID | Objective | Done when |
|---|---|---|
| A1 | File analysis, signature stage | `block analyze` reports known webshell markers/strings in PHP and image files, with byte offsets |
| A2 | File analysis, static stage | PHP is parsed and sinks fed by request input are reported; image structure is walked (segments, trailing data) |
| A3 | Hidden webshells | PHP inside JPEG/PNG metadata or after the image end is found and located; extension/magic mismatch is reported |
| A4 | File risk score | `block score` writes 0–100 + top 3 contributions from the result file alone |
| C1 | Capture filtering | A capture is filtered to HTTP before analysis; total vs analysed frames reported in `stages[]` |
| C2 | Capture signature stage | Uploads, shell requests and encoded/encrypted envelopes matched by rules |
| C3 | Capture static stage | Multipart parts carved and analysed by the file pipeline; request/response semantics inspected |
| C4 | Capture risk score | Same scoring contract, with per-flow `subject` values |
| T1 | Layout | §2, with `shellblock/` importing nothing from `shellshock` |
| T2 | CLI-first | Every capability via `shellsuite block …`; `--json` on every query action |
| T3 | git | One small, readable commit per task |
| T4 | `AI.log` | Append-only, one entry per task (format in §12) |
| T5 | Real verification | Fixtures + a real lab capture; numbers, not claims |
| T6 | README | Prerequisites (Wireshark/tshark, `python3-tk`, pyshark, tree-sitter), pcap save steps, every subcommand with an example |

## 11. Verification

**Fixture corpus** — generated by `tools/make_fixtures.py` and committed:

| Clean (must score ≤ 10) | Malicious (must score ≥ 45) |
|---|---|
| real photo `.jpg`, real `.png` | `hidden_comment.jpg`, `hidden_trailing.jpg` |
| legit `.php` page (PDO, `htmlspecialchars`) | `fake.jpg` (PNG bytes named `.jpg`), `double.php.jpg` |
| normal browsing `.pcap` | `polyglot.gif`, `zip_after_eoi.jpg` |
| | `china_chopper.php`, `obfuscated.php`, `padded.php` |
| | the 9 ShellShock outputs (3 vectors × 3 modes), all ≥ 70 |
| | `upload.pcap`, `exec.pcap`, `encrypted_exec.pcap` |
| | `--dump-json` output for each capture (the test model) |

**Rule matrix** — `tools/rule_matrix.py`: rows = fixtures, columns = rules, cell =
hit count. Every rule fires on ≥ 1 fixture; every clean fixture is all-zero. A rule
with nothing to fire on is deleted, not kept "for later". This matrix is the
calibration table for the memoria.

**Assertions**: malicious ≥ 45 and ShellShock variants ≥ 70; clean ≤ 25;
`hidden_trailing.jpg` reports `offset == file_size - len(payload)`; two scoring runs
produce identical bytes; unknown `rule_id` → exit 1 with a clear message;
`rules.json` validates; a rule emitted by code but missing from the table is
reported; pcapng → exit 2 with the instruction; tshark absent → exit 2 with the
install hint.

**Evidence**: a pcap with synthesised Ethernet/IP framing is a unit-test fixture,
never proof. The memoria's annex needs a capture taken on the lab network
(Wireshark on the laptop: DVWA upload + command execution + normal browsing as
control). Label anything synthetic.

## 12. How you must work (mandatory flow)

Per feature: 1. objective → 2. your proposed approach → 3. my review → 4. task
breakdown → 5. implementation → 6. my review → 7. validation → 8. documentation.

Self-validation before handing anything over:

- Does it meet the stated objective?
- Does it fit the rest of the code and break nothing else?
- Would a human read it without asking you a question?

Style:

- Identifiers in **English**
- Compact, readable files; keep type annotations.
- No defensive scaffolding nobody asked for (no import fallbacks, no type guards).
- Do not refactor modules unrelated to the task.

`AI.log` (append-only; the old brief called it `IA.log`, the file in the repo is
`AI.log` — use that one):

```
[2026-11-17 18:40] Task: <one line>.

What was done:
- …
What was tested:
- …   (real commands and real output)
Notes:
- …
```

## 13. Calendar and gates

Capacity: ~2 h per weekday, ~5 h per weekend day, minus ~20 % for exams. Days
below are the target; the gates are what matter.

| Day | h | Work | Gate |
|---|---|---|---|
| Mon 16 | 2 | `shellsuite/filters.py` + re-export; `config.analysis_dir()`; `rules.json` upgraded (categories mapping + first rules); `rules.py` loader/validator + `DETECTORS`; `result.py`, `store.py`, `detect.py`; `block analyze` writes an empty-but-valid result | `block analyze --file x.jpg` → schema-valid JSON; `block rules --validate` green |
| Tue 17 | 2 | signature matcher driven by `rules.json`; signature rules with byte offsets | hidden-PHP fixtures flagged by the signature stage alone |
| Wed 18 | 2 | image statics (JPEG/PNG/GIF, trailing data); `tools/make_fixtures.py` | image fixtures ≥ 45, clean images 0 findings |
| Thu 19 | 2 | PHP: tree-sitter walk, symbol table, sink×source | China Chopper, `obfuscated.php`, a generated shell ≥ 45 |
| Fri 20 | 2 | obfuscation/auth/family/padded rules; specificity dedupe | 9 ShellShock shells flagged, FP set 0 → **GATE 1: file module done** |
| Sat 21 | 5 | `capture_static.py`: pcapng refusal, `FileCapture` + display filter, `HttpMessage` model, `--dump-json` | recorded model parses with neither tshark nor pyshark installed |
| Sun 22 | 5 | carving (`--export-objects`, `--keep-objects`), recursion into the file pipeline, capture rules, TLS notes | `upload.pcap` → `subject=upload:…`; `exec.pcap` ≥ 70 → **GATE 2: capture module done** |
| Mon 23 | 2 | `scoring.py`: weights from `rules.json`, contributions top-3, breakdown, `ruleset` hash; `block score` | malicious ≥ 45, clean ≤ 10 |
| Tue 24 | 2 | `list/` + `show/` packages (filters parity, `--json`) | CLI feature-complete |
| Wed 25 | 2 | tests over fixtures; rule matrix; edge cases (empty, 200 MB, capped, non-UTF8, pcapng, no tshark) | suite green, matrix clean → **GATE 3: gradeable core frozen** |
| Thu 26 | 2 | real Wireshark captures in the lab (upload, exec, browsing control) + weight calibration | 3 real pcaps; no clean file over 20 |
| Fri 27 | 2 | README: prerequisites, pcap save steps, every subcommand | reproducible from scratch |
| Sat 28 | 5 | memoria + video script + first recording | draft complete, video ≤ 10 min |
| Sun 29 | 5 | buffer: re-record what looked bad, `AI.log` audit, rubric pass, submit | submitted |

If a day slips, cut in this order: beaconing → GIF/PNG beyond trailing data →
`list` filters → inherited findings for carved uploads (keep the upload rule).
Never cut: image statics, PHP sink×source, upload detection, scoring.

## 14. Out of scope (do not do it)

- Any GUI for ShellBlock.
- Any AI/LLM inside the tool, in any form.
- Executing a payload, sending traffic to a target, "detonating" anything.
- `.pcapng`, HTTPS decryption, live capture (`tshark -i`).
- Languages other than PHP; archives, Office, PDF.
- Modifying `shellshock/` beyond §3; changing ShellShock's frozen taxonomy.
- Writing the memoria or the video script.
