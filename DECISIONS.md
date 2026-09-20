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
