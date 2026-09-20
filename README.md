# MCP Security Observatory

A continuously-updated public risk index for the Model Context Protocol
server ecosystem.

**Status:** pre-launch, private. See `docs/specs/` for the design.

## What this is

MCP servers are plugins that AI assistants load to gain new capabilities.
A server describes its own tools in natural language, and the assistant acts
on those descriptions — so a server's own metadata is an instruction channel
into the model. Editors including Cursor and Claude Code auto-launch
project-defined servers with the developer's OS privileges.

This project reads the published source of MCP servers without executing
them, flags dangerous patterns, uses a language model to adjudicate the
ambiguous cases, measures how often that adjudication is correct, and
publishes the results.

## Repository layout

| Path | Purpose |
|---|---|
| `analyzer/crawler/` | Discovers servers from the official registry and GitHub |
| `analyzer/fetcher/` | Shallow-clones a server at a pinned commit, read-only |
| `analyzer/rules/` | Deterministic detection rules (tree-sitter based) |
| `analyzer/triage/` | LLM adjudication of ambiguous findings, content-hash cached |
| `analyzer/report/` | Emits SARIF and JSONL |
| `evals/golden/` | Hand-labeled findings used to measure the triage layer |
| `evals/harness/` | Precision / recall / F1 measurement, runs in CI |
| `fixtures/` | Deliberately vulnerable and known-clean servers for rule tests |
| `data/` | Committed scan artifacts; git history provides the time series |
| `web/` | Static dashboard |

## Principles

Static analysis only — never execute a scanned server. See `SECURITY.md`
for the disclosure policy and `DECISIONS.md` for the engineering log.
