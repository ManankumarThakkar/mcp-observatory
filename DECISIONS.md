# Engineering Decision Log

Each entry records a decision, the alternatives considered, and why.

---

## D1 — Static analysis only; never execute a scanned server

**Decision.** The analyzer reads source. It never runs `npm install`,
`pip install`, a build step, or the server itself.

**Why.** The vulnerability class this project studies is that MCP servers
execute with the developer's privileges and obey instructions embedded in
their own metadata. A scanner that executes them reproduces the exact hazard
it exists to detect. This constraint is load-bearing, not a precaution.

**Cost.** Some dynamic behavior is undetectable. Accepted.

---

## D2 — Commit scan results to the repository instead of hosting a database

**Decision.** Findings are written to `data/` as JSONL and committed.

**Why.** Git already provides versioning, history, and auditability. A
committed artifact gives time-series data for free, keeps hosting at zero,
and lets the dashboard build from a file with no runtime dependency.

**Alternatives.** Postgres on Render (adds cost, a live dependency, and a
backup burden for data that is append-mostly and small).

---

## D3 — Python analyzer with tree-sitter, rather than per-language tooling

**Decision.** One analyzer, written in Python, parsing both Python and
TypeScript servers through tree-sitter.

**Why.** The ecosystem is roughly 45% Python and 30-35% TypeScript, so
covering one language would halve the credibility of any ecosystem claim.
tree-sitter parses both through a single interface. Python also keeps the
LLM triage and eval layers in the ecosystem with the best tooling.

**Cost.** tree-sitter is lower-level than the TypeScript compiler API, so
TypeScript-specific semantics take more work. Accepted.

**Amended by D6.** The parsing harness covers both languages as decided here,
but the v1 detection rules cover Python only. See D6.

---

## D4 — Small model for triage, not a frontier model

**Decision.** `claude-haiku-4-5-20251001` adjudicates ambiguous findings.

**Why.** Adjudication is a bounded classification task with a short input
and a structured output. A frontier model costs substantially more across
thousands of findings for judgment that the eval harness can verify is
sufficient. If measured precision proves inadequate, the harness will show
it and the decision gets revisited with evidence.

---

## D5 — Measure the triage layer rather than trusting it

**Decision.** A hand-labeled golden set, with per-rule precision, recall,
and F1 tracked in CI and gating merges on regression.

**Why.** An unmeasured scanner is an opinion. This is the component that
distinguishes the project from every other scanner repository, and it is
the part that demonstrates evaluation skill directly.

---

## D6 — v1 deep rules cover Python only, and the dashboard says so

**Decision.** `UNICODE-CONCEAL` runs against every server in the corpus, because
it is a character scan that needs no parser. The four tree-sitter rules —
`TOOL-DESC-INJECTION`, `PATH-TRAVERSAL`, `SHELL-EXEC-UNSAFE`, `SCOPE-OVERBROAD`
— cover Python servers only in v1. The published results state per-language
coverage explicitly rather than presenting a Python figure as an ecosystem one.

**Why.** D3 chose tree-sitter precisely so both languages could be covered, and
that remains the destination. But TypeScript rules are not a translation of the
Python ones: the taint analysis differs, each rule needs a second query and its
own fixtures, and the work would delay every other part of the project
— including the accuracy measurement, which is the thing that actually
distinguishes this work.

Shipping a measured, honest half beats delaying a complete one. The failure mode
to avoid is not narrow coverage; it is *undisclosed* narrow coverage. A reader
who is told "450 of 1,000 servers were deep-scanned, all 1,000 were checked for
concealment" can judge the result. A reader shown a bare ecosystem percentage
cannot.

**Cost.** The v1 ecosystem claim is narrower than D3 envisaged, and the
TypeScript share of the corpus gets concealment detection only. Accepted, and
stated wherever results are published.

**Revisit when.** TypeScript rules are the first post-v1 work, ahead of any
sixth rule.
