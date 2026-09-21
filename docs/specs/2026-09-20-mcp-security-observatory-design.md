# MCP Security Observatory — Design

**Date:** 2026-09-20
**Status:** Awaiting review

## 1. Problem

MCP servers are plugins that AI assistants load to gain capabilities. A server
declares its tools in natural language, and the assistant acts on those
declarations — making a server's own metadata an instruction channel into the
model. Published research reports that 33% of 1,000 scanned servers carried
critical vulnerabilities, 82% of file-operation implementations were vulnerable
to path traversal, and roughly 5.5% showed tool poisoning. Editors including
Cursor, Claude Code, Gemini CLI, Copilot and Amazon Q auto-execute
project-defined servers with the developer's OS privileges and no process
isolation.

The official registry held 9,652 servers as of May 2026. No continuously
updated, independently measured public risk index exists for that corpus.

## 2. What we are building

A nightly pipeline that discovers public MCP servers, analyzes their source
without executing it, adjudicates ambiguous findings with a language model,
measures the accuracy of that adjudication against hand-labeled data, and
publishes both the aggregate results and the accuracy numbers to a static
dashboard.

## 3. Non-goals

- Not a runtime monitor, proxy, or gateway.
- Not a general-purpose SAST tool. Rules target MCP-specific hazards only.
- Not a vulnerability database or CVE issuer.
- No on-demand user-submitted scanning in v1. (Possible phase 2.)
- No exploit generation, ever.

## 4. Constraints

| Constraint | Value |
|---|---|
| Hosting | Static site, free tier |
| Analyzer language | Python 3.11+, tree-sitter |
| Triage model | `claude-haiku-4-5-20251001` |
| Runtime dependencies | tree-sitter and its grammars only |
| Source material | Public repositories only |

## 5. Architecture

```
GitHub Actions (nightly cron)
      |
      v
  Crawler      discovers servers -> server_index.jsonl
      |
      v
  Fetcher      shallow clone at pinned SHA, read-only
      |
      v
  Rules engine deterministic, tree-sitter AST -> raw findings
      |
      v
  Triage       LLM adjudicates semantic findings (cached)
      |
      v
  Report       SARIF + findings.jsonl -> committed to data/
      |
      v
  Web          static build -> Render -> public URL
```

The eval harness runs against `evals/golden/` on every pull request and gates
merges on regression. It is not part of the nightly path.

## 6. Components

Each component is independently testable and communicates by file.

### 6.1 Crawler (`analyzer/crawler/`)
Enumerates candidate servers from the official MCP registry API, supplemented by
GitHub code search for MCP SDK imports.
**Output:** `server_index.jsonl` — `{server_id, repo_url, commit_sha, language, discovered_via, stars, archived}`.
**Depends on:** network, GitHub API token.

### 6.2 Fetcher (`analyzer/fetcher/`)
Shallow-clones each repo at its pinned `commit_sha` into an ephemeral directory.
Never installs dependencies, never builds, never executes.
**Caps:** 50 MB per repo, 5,000 files, 60 s per clone.
**Output:** a read-only path on disk.

### 6.3 Rules engine (`analyzer/rules/`)
Parses server source with tree-sitter and applies detection rules. Each rule is
a module exposing `analyze(tree, source, manifest) -> list[Finding]`.
**Output:** raw findings, high recall, tolerant of false positives.

### 6.4 Triage (`analyzer/triage/`)
Sends semantic findings to the model with a structured-output schema and
receives `{verdict, confidence, rationale}`. Cached by
`sha256(rule_id + evidence)` so a repeated finding across nightly runs costs
nothing.
**Output:** findings annotated with a triage verdict.

### 6.5 Report (`analyzer/report/`)
Emits SARIF 2.1.0 (so results drop into GitHub code scanning) and
`findings.jsonl`. Applies the disclosure gate before anything reaches `data/`.

### 6.6 Eval harness (`evals/harness/`)
Scores triage verdicts against `evals/golden/` and emits per-rule precision,
recall, and F1. Fails CI if any rule's precision drops more than 5 points below
its recorded baseline.

### 6.7 Web (`web/`)
Static dashboard. Reads `data/` at build time. No runtime backend.

## 7. Rule set (v1)

| Rule ID | Detects | Severity | LLM-adjudicated |
|---|---|---|---|
| `UNICODE-CONCEAL` | Unicode TAG blocks (U+E0000–U+E007F), bidi overrides, zero-width characters in tool metadata | critical | No |
| `TOOL-DESC-INJECTION` | Imperative or adversarial instructions embedded in tool descriptions | high | Yes |
| `PATH-TRAVERSAL` | File operations on unvalidated tool-input paths | high | Partial |
| `SHELL-EXEC-UNSAFE` | Subprocess invocation with interpolated tool input and no allowlist | critical | Partial |
| `SCOPE-OVERBROAD` | Declared filesystem or network scope materially wider than the declared tools require | medium | Yes |

**"Partial" adjudication** means the rule fires deterministically when the taint
path from tool input to the dangerous sink is direct, and is routed to the model
only when the path is indirect (passes through a helper, a conditional, or a
reassignment). Direct cases never spend a model call.

Five rules, deliberately. More rules than can be held to the required
measurement quality is worse than fewer. `SCOPE-OVERBROAD` is the first to cut if time runs short.

## 8. Finding schema

```json
{
  "finding_id": "sha256(server_id|rule_id|location|evidence_hash)",
  "server_id": "owner/repo",
  "commit_sha": "abc123...",
  "rule_id": "TOOL-DESC-INJECTION",
  "severity": "critical|high|medium|low|info",
  "confidence": "high|medium|low",
  "location": { "file": "src/index.ts", "line": 42 },
  "evidence": "redacted source excerpt",
  "triage": {
    "adjudicated": true,
    "verdict": "true_positive|false_positive|uncertain",
    "model": "claude-haiku-4-5-20251001",
    "rationale": "one sentence",
    "cached": false
  },
  "first_seen": "2026-09-20T00:00:00Z",
  "last_seen": "2026-09-20T00:00:00Z",
  "disclosure_state": "withheld|disclosed|published|opted_out"
}
```

`finding_id` is deterministic, so the same issue across nightly runs is one
record with an updated `last_seen` — which is what produces the time series.

## 9. Error handling

- **Per-server isolation.** One repo failing to clone or parse must never fail
  the run. Each server is analyzed in a try/except with its outcome recorded.
- **Partial-run tolerance.** The index builder merges new results over the last
  known-good `data/` state. A run covering 60% of the corpus updates 60%.
- **Rate limits.** GitHub API calls use exponential backoff and honor
  `X-RateLimit-Reset`. The crawler checkpoints so a run resumes where it stopped.
- **Model failures.** A triage timeout or malformed response marks the finding
  `uncertain` rather than dropping it. Uncertain findings are withheld from
  publication and surfaced for manual labeling.
- **Resource caps.** Enforced in the fetcher (§6.2); exceeded caps skip the
  server and record the reason.
- **Never execute.** Enforced structurally: the fetcher has no install or build
  path to invoke.

## 10. Testing

- **Fixtures.** `fixtures/vulnerable/` holds a deliberately vulnerable server per
  rule; `fixtures/clean/` holds near-miss servers that must *not* trigger. These
  are the rule unit tests and they run on every commit.
- **Golden set.** A hand-labeled sample of real findings, target 200–300 across
  rules, stored in `evals/golden/`. This is the ground truth for triage accuracy.
- **Regression gate.** CI fails if per-rule precision falls more than 5 points
  below baseline.
- **Snapshot tests.** SARIF output is snapshot-tested for schema validity.
- **Published accuracy.** Per-rule precision appears on the dashboard. The
  project states its own error rate.

## 11. Disclosure

Governed by `SECURITY.md`. Summary: aggregate statistics publish immediately;
`high` and `critical` per-server findings are withheld pending a 90-day private
disclosure window; exploit code is never published; maintainer opt-out is
honored unconditionally.

The disclosure gate is enforced in code, in `analyzer/report/`, not by
convention — a finding cannot reach `data/` in a publishable state without
passing it.

## 12. Deployment

- **Compute:** GitHub Actions, nightly cron. Free for this workload.
- **Hosting:** Render static site, free tier.
- **Storage:** the git repository. No database.
- **Secrets:** `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` as Actions secrets.
- **Estimated run cost:** the first full scan is the only expensive one. At a
  v1 target of ~1,000 servers averaging roughly two semantic findings each,
  that is ~2,000 uncached triage calls of a few hundred tokens apiece — low
  single-digit dollars on Haiku. Subsequent nightly runs approach zero, because
  `finding_id` is deterministic and the cache absorbs every unchanged finding.
- **Hard spend guard:** the triage layer enforces a configurable maximum of
  3,000 model calls per run. Exceeding it stops adjudication, marks the
  remainder `uncertain`, and completes the run rather than silently spending.

## 13. Delivery phases

Each phase produces something that works on its own.

| Phase | Scope | Complete when |
|---|---|---|
| 1 | Analyzer core: fetcher, rule engine, first rule, CLI | The CLI emits valid JSON for a real server repository |
| 2 | Ecosystem scan: crawler, tree-sitter, remaining four rules, SARIF, disclosure gate, time series | A full corpus scan writes gated, merged results |
| 3 | Triage and measurement: model adjudication, cache, eval harness, CI regression gate | Per-rule precision is measured against the golden set |
| 4 | Publication: dashboard, deploy, writeup | A live public URL with more than one point in the time series |

If a phase runs short, `SCOPE-OVERBROAD` (§7) is cut before the eval harness.
The measurement is the differentiator; a fifth rule is not.

## 14. Risks

| Risk | Mitigation |
|---|---|
| Registry API shape changes or is rate-limited | Crawler checkpoints; GitHub code search as a fallback source |
| Triage precision too low to publish | Eval harness surfaces this in week 5, before launch; fall back to publishing deterministic rules only |
| Golden-set labeling takes longer than estimated | Reduce target to 150 findings concentrated on the two LLM-adjudicated rules |
| Scope creep into on-demand scanning | Explicit non-goal (§3) |
| A maintainer objects to publication | Opt-out honored unconditionally; disclosure gate is code, not policy |

## 15. Success criteria

**v1 ships when:**
1. A public URL shows scan results across at least 1,000 real servers.
2. Per-rule precision is measured against the golden set and published.
2a. Per-language coverage is stated alongside every aggregate figure. The
    four tree-sitter rules cover Python in v1 (see `DECISIONS.md` D6); a
    Python-derived percentage is never presented as an ecosystem-wide one.
3. The nightly job runs unattended and the time series has more than one point.
4. `SECURITY.md` is live and the disclosure gate is enforced in code.
5. A technical writeup explains the architecture, the measured accuracy, and the
   limitations.

**Explicitly not success criteria:** GitHub stars, or number of vulnerabilities
found. A result showing the ecosystem is healthier than reported is an equally
valid and publishable outcome.
