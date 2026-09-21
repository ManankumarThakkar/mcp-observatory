# MCP Security Observatory

A public risk index for the Model Context Protocol server ecosystem — and an
honest measurement of how often that index is right.

> **Status: pre-launch.** The analyzer and pipeline are being built in the open.
> No ecosystem-wide numbers are published yet, and this README will not claim
> any until they are.

## Why this exists

**Situation.** AI assistants such as Claude Code and Cursor extend themselves by
loading plugins called MCP servers. Close to ten thousand have been published.
They run on a developer's own machine, with that developer's own privileges — no
sandbox, no review, and in most editors they start automatically when a project
is opened.

**Challenge.** A plugin describes its own tools in plain English, and the
assistant acts on those descriptions. That turns the description into an
instruction channel pointed straight at the model: text hidden inside it can
tell the assistant to do something the developer never asked for. Published
research found critical flaws in roughly a third of the servers it examined, and
path-traversal bugs in 82% of the ones that touch files. Checking a plugin means
reading the source of untrusted software — software you must never run in order
to inspect it.

**Action.** This project reads published MCP servers without executing a single
line of them. Five rules look for the specific ways these plugins go wrong:
characters hidden from human eyes, instructions smuggled into tool descriptions,
unchecked file paths, unsafe shell commands, and permissions far wider than the
plugin needs. Clear-cut cases are decided by code alone. Genuinely ambiguous
ones are referred to a language model — and every one of those judgements is
scored against a hand-labelled answer key.

**Result.** A continuously updated public risk index, published with its own
accuracy beside it. If the tool is wrong fifteen percent of the time, the
dashboard says fifteen percent. Serious findings go privately to maintainers
first, and a maintainer who asks to be excluded is excluded.

## What makes it different

Plenty of tools will scan a repository. Very few will tell you how often they
are wrong. The measured accuracy is the point of this project — a scanner whose
error rate nobody knows is an opinion, not evidence. A result showing the
ecosystem is healthier than reported is just as publishable as an alarming one.

## How it works

```
Crawler    finds published servers
   ↓
Fetcher    shallow-clones each one, read-only, never executed
   ↓
Rules      deterministic detection over the parsed source
   ↓
Triage     a language model adjudicates only the ambiguous findings
   ↓
Report     disclosure gate, then SARIF + JSONL committed to data/
   ↓
Web        static dashboard, including the accuracy numbers
```

## Running it

Requires Python 3.11 or newer.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Scan a single public server
mcp-observatory --repo-url https://github.com/owner/repo --server-id owner/repo

# Scan a whole index of servers
mcp-observatory --index data/server_index.jsonl
```

Output is JSON on stdout; a full run writes `data/findings.jsonl` and
`data/findings.sarif`. The SARIF file uploads directly to GitHub code scanning.

```bash
pytest -v        # test suite
ruff check .     # lint
```

## Repository layout

| Path | Purpose |
|---|---|
| `analyzer/crawler/` | Discovers servers from the official registry and GitHub |
| `analyzer/fetcher/` | Shallow-clones a server at a pinned commit, read-only |
| `analyzer/rules/` | Deterministic detection rules (tree-sitter based) |
| `analyzer/triage/` | LLM adjudication of ambiguous findings, content-hash cached |
| `analyzer/report/` | Disclosure gate, SARIF and JSONL output |
| `evals/golden/` | Hand-labeled findings used to measure the triage layer |
| `evals/harness/` | Precision / recall / F1 measurement, runs in CI |
| `fixtures/` | Deliberately vulnerable and known-clean servers for rule tests |
| `data/` | Committed scan artifacts; git history provides the time series |
| `web/` | Static dashboard |

## Principles

- **Never execute a scanned server.** The fetcher may invoke `git` and nothing
  else. This is enforced by a test, not by convention.
- **Publish the error rate.** Per-rule precision ships next to the findings.
- **Disclose before publishing.** Serious findings are withheld pending a
  private disclosure window, enforced in code.
- **No exploit code, ever.**

See [`SECURITY.md`](SECURITY.md) for the disclosure policy,
[`DECISIONS.md`](DECISIONS.md) for the engineering log, and
[`docs/specs/`](docs/specs/) for the design.
