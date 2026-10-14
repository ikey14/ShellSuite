# ShellSuite — Working Brief (ShellShock, delivery 25 Oct 2026)

Context for coding agents (Opencode / GitHub Copilot). Read it in full before touching code.
If something is not in this brief, ask before inventing it.

## 1. Context

- Academic project for the course *Proyectos de Ciberseguridad*. Delivery date: **Sunday 25 October 2026**.
- **Scope of this delivery = ShellShock only**, made up of two modules:
  1. **Webshell Creator** (webshell generation)
  2. **Webshell Manager** (webshell management)
- **ShellBlock** (file analysis + pcap capture analysis) is the **November** delivery: it is **out of scope**. Do not implement it, and **ShellShock must not depend on it**.
- There is a written report for the delivery. **Do not write it**: it gets assembled at the end from git history, `IA.log` and the README.

## 2. Architecture (non-negotiable)

ShellSuite/
├── shellsuite/      # ONLY what both share: libs, config, protocol/client, crypto, registry, logging
├── shellshock/      # Creator + Manager  <-- October delivery
└── shellblock/      # November. For now: empty placeholder, no logic at all

Rules:

1. **Independence:** ShellShock must work with ShellBlock absent, empty or broken. Zero imports from `shellblock` inside `shellshock`.
2. **Shared code lives only at the ShellSuite level:** anything both modules need goes in `shellsuite/`, never duplicated and never imported from one module into the other.
3. **CLI-first:** *every* capability is implemented as a CLI subcommand. No GUI-only logic exists.
4. **The GUI is a thin layer:** it invokes the CLI (subprocess) and displays its output. If something works in the GUI, it must work from the CLI without the GUI.
5. **Single source of truth:** the webshell and session registry is CLI-owned state (JSON), and the GUI reads/writes it through the CLI.
6. **No AI inside the tool.** This is a documented design decision: no LLM, no models, no agents, no AI API calls at runtime. AI is only used to develop it (that is, you).

## 3. Stack

- **Python 3.10+**. Prefer stdlib (`argparse`, `json`, `subprocess`, `sqlite3`/json, `tkinter`) over adding dependencies.
- **GUI:** Tkinter (stdlib), wrapping the CLI.
- **git** for version control, from day one, small commits.
- **Generated webshells: PHP** (all of them).
- **Tshark** does not apply in October (it belongs to ShellBlock).
- Lab environment: **DVWA** (VM on laptop or NAS). Testing only.

## 4. Webshell types (frozen taxonomy)

**Type = vector × payload mode**

- Vector: `cookie` | `header` (HTTP header) | `post`
- Mode: `plain` (no auth) | `auth` (requires a credential) | `encrypted` (encrypted; forces authentication)

All PHP. This taxonomy is the interface between Creator and Manager: it is **frozen** — a change hits both modules at once.

## 5. Objectives with acceptance criteria

| ID | Objective | Done when |
|---|---|---|
| 1.1 | Generate several webshell types | The CLI generates webshells of several types from the §4 taxonomy |
| 1.2 | Add authentication to a webshell | An optional flag adds auth; the shell does not execute without the right credential |
| 1.3 | Encrypt the webshell | An optional flag encrypts the payload; **decrypting requires the password** (auth is mandatory, not decorative) |
| 1.4 | Upload a webshell to a remote endpoint | The CLI takes an endpoint and attempts the upload, reporting success/failure |
| 1.5 | cookie/header/POST vectors | All three vectors genuinely work in code (this is the differentiator vs Webacoo; do not ship cookies only) |
| 2.1 | Operate from a graphical interface | GUI covers: listing/managing webshells, sessions, terminal and command execution |
| 2.2 | Communicate with webshells of several types | The Manager talks to every type the Creator produces |
| 2.3 | Run encrypted webshells | Prompts the user for the password, decrypts and executes |
| 2.4 | Terminal for the webshell | Interactive terminal per shell |
| 2.5 | Remember past sessions | Sessions persist across restarts and can be reopened |
| 2.6 | Add / delete / edit webshells | Full CRUD over the managed registry |
| T1 | ShellSuite/ShellShock/ShellBlock layout | The §2 structure, and ShellShock starts with ShellBlock absent |
| T2 | CLI-first, GUI as wrapper | Everything the GUI does is invocable from the CLI |
| T3 | git version control | Small, readable commit history from day one |
| T4 | `IA.log` | Log file with **one timestamped entry per task**, written by you (see §6) |
| T5 | Real verification | Every objective tested against the DVWA lab, with evidence |
| T6 | README | Install, usage of each subcommand, how to stand up the lab, examples |

## 6. How you must work (mandatory flow)

Per feature:

1. Objective → 2. your proposed approach → 3. my review/correction → 4. task breakdown → 5. implementation → 6. my review/correction → 7. validation → 8. documentation and end.

Self-validation before handing anything to me as finished (the three criteria we are held to):

- Does it meet the proposed objective?
- Does it fit the rest of the code and break nothing else?
- Is it readable and understandable by a human?

If any of them fails, go back to the review phase.

**`IA.log`:** append one entry per task, **append-only**, with timestamp plus what was done and tested. Never rewrite history.

**Working style rules:** do not add dependencies without justifying them; do not refactor modules unrelated to the task; every new capability ships with a runnable check; never change the §4 taxonomy without telling me.

## 7. Calendar and gates

Real capacity: ~2 h per weekday and ~5 h per weekend day. With exams in the window, work with ~20 % less margin.

| Day | Hours | Work | Objectives |
|---|---|---|---|
| Wed 14 | 2 | Repo, §2 layout, venv, CLI entrypoint, git init, `IA.log` + agent rules, spec skeleton | T1-T4 |
| Thu 15 | 2 | **Freeze the specs**: taxonomy + Creator↔Manager protocol contract. Stand up the DVWA lab and decide which host is the "endpoint" | T1, T5 |
| Fri 16 | 2 | Creator skeleton + template engine; `cookie` vector | 1.1, 1.5 |
| Sat 17 | 5 | `header` and `post` vectors, second type, auth | 1.1, 1.2, 1.5 |
| Sun 18 | 5 | Encryption (auth mandatory) + endpoint upload + tests → **GATE 1: Creator finished and verified** | 1.3, 1.4 |
| Mon 19 | 2 | Manager: protocol/client layer for every type | 2.2 |
| Tue 20 | 2 | Run encrypted shells with a password; registry CRUD in the CLI | 2.3, 2.6 |
| Wed 21 | 2 | Interactive terminal → **GATE 2: Manager works end-to-end via CLI** | 2.4 |
| Thu 22 | 2 | Session persistence/recall + tests | 2.5 |
| Fri 23 | 2 | GUI: shell and session listing, CRUD, command panel (through the CLI) | 2.1, T2 |
| Sat 24 | 5 | GUI: terminal, password prompt, sessions → **GATE 3: feature freeze**; then E2E against DVWA, README, `IA.log` audit, packaging | 2.1, T4-T6 |
| Sun 25 | 5 | Buffer only: fix whatever the E2E turned up, capture evidence, final pass against §5 and submit | — |

The gates are what matter: **Gate 1 (Sun 18)** and **Gate 3 (Sat 24)** decide the delivery.

## 8. Scope cuts (in this order, if time gets tight)

1. Second webshell type → keep PHP only with the three vectors (still beats the Webacoo claim).
2. Terminal view in the GUI → simple embedded console; keep CRUD, sessions and the command panel.
3. Configurable encryption → one solid scheme, no options.
4. **Never cut:** 1.1-1.4 and 2.2-2.6 must exist as something working, because each one is a literal line of the planteamiento.

## 9. Out of scope (do not do it)

- Any ShellBlock functionality (file analysis, pcap analysis, tshark).
- Any AI/LLM inside the tool, in any form.
- Webshells in languages other than PHP.
- Webshells aimed at anything other than the test lab.
- Writing the delivery report.
- Changes to the §4 taxonomy without explicit confirmation.
