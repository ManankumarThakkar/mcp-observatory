# Engineering Decision Log

Each entry records a decision, the alternatives considered, and why.

---

## D1 - Static analysis only; never execute a scanned server

**Decision.** The analyzer reads source. It never runs `npm install`,
`pip install`, a build step, or the server itself.

**Why.** The vulnerability class this project studies is that MCP servers
execute with the developer's privileges and obey instructions embedded in
their own metadata. A scanner that executes them reproduces the exact hazard
it exists to detect. This constraint is load-bearing, not a precaution.

**Cost.** Some dynamic behavior is undetectable. Accepted.

---

## D2 - Commit scan results to the repository instead of hosting a database

**Decision.** Findings are written to `data/` as JSONL and committed.

**Why.** Git already provides versioning, history, and auditability. A
committed artifact gives time-series data for free, keeps hosting at zero,
and lets the dashboard build from a file with no runtime dependency.

**Alternatives.** Postgres on Render (adds cost, a live dependency, and a
backup burden for data that is append-mostly and small).

---

## D3 - Python analyzer with tree-sitter, rather than per-language tooling

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

## D4 - Small model for triage, not a frontier model

**Decision.** `claude-haiku-4-5-20251001` adjudicates ambiguous findings.

**Why.** Adjudication is a bounded classification task with a short input
and a structured output. A frontier model costs substantially more across
thousands of findings for judgment that the eval harness can verify is
sufficient. If measured precision proves inadequate, the harness will show
it and the decision gets revisited with evidence.

---

## D5 - Measure the triage layer rather than trusting it

**Decision.** A hand-labeled golden set, with per-rule precision, recall,
and F1 tracked in CI and gating merges on regression.

**Why.** An unmeasured scanner is an opinion.

**Amended by D7.** Measuring accuracy is no longer novel on its own; at least
one other MCP scanner does it. What the golden set must therefore be is a
*random sample of real findings*, never a corpus curated to match our own
rules. See D7.

---

## D6 - v1 deep rules cover Python only, and the dashboard says so

**Decision.** `UNICODE-CONCEAL` runs against every server in the corpus, because
it is a character scan that needs no parser. The four tree-sitter rules -
`TOOL-DESC-INJECTION`, `PATH-TRAVERSAL`, `SHELL-EXEC-UNSAFE`, `SCOPE-OVERBROAD`
- cover Python servers only in v1. The published results state per-language
coverage explicitly rather than presenting a Python figure as an ecosystem one.

**Why.** D3 chose tree-sitter precisely so both languages could be covered, and
that remains the destination. But TypeScript rules are not a translation of the
Python ones: the taint analysis differs, each rule needs a second query and its
own fixtures, and the work would delay every other part of the project
- including the accuracy measurement, which is the thing that actually
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

---

## D7 - Narrow the claim to what is genuinely ours

**Decision.** Stop claiming "we measure our own accuracy" as the
differentiator. Claim three narrower things instead: accuracy measured on a
**random** sample of real findings, a **published trend over time**, and
**disclosure to maintainers before publication**.

**Why.** A review of the MCP security tooling landscape in September 2026 found
the space is not empty. Static scanners exist and some are good. At least one
measures and publishes its own accuracy. Another crawls the ecosystem
continuously, though it scores maintenance quality rather than security. So
measurement on its own is not a differentiator, and claiming it as one would not
survive a conversation with anyone who knows the field.

The accuracy figures published elsewhere are generally measured against a
corpus the tool's own authors assembled, and they tend toward perfect scores.
That is the expected outcome when the rules and the examples are developed
together: it measures whether the rules match the cases they were written from,
not how the tool behaves on an arbitrary server in the wild.

So the golden set here is sampled randomly from real scan output, never
curated, and the sampling method is published beside the numbers. A precision of
71% honestly obtained on a random sample is worth more than a perfect score on a
hand-picked one, and is far more useful to somebody deciding whether to trust a
finding.

**What the field leaves unclaimed.** Nothing reviewed publishes a time series,
so "is this ecosystem getting safer" is currently unanswerable by anyone.
Nothing reviewed documents notifying a maintainer before publishing a finding
about their code. Nothing reviewed combines continuous ecosystem coverage with
security analysis; the tools that scan deeply wait to be pointed at a target,
and the one that runs continuously does not analyse security.

**Why this record names no products.** A decision log is a record of our own
reasoning, not a comparison page. Naming specific tools and quoting their
numbers would date this document the moment any of them changes, and would turn
an engineering record into an argument with peers. What shaped the decision is
which capabilities exist in the field, not who ships them.

**Cost.** The headline is narrower and harder to say in one line. Accepted: a
claim that survives scrutiny is worth more than a broad one that does not.

---

## D8 - Publish the golden set as an open benchmark

**Decision.** `evals/golden/` ships publicly, with the sampling method, the
labeling guide, and a scoring script that any scanner can be run against. Our
own numbers are published alongside, produced by that same script.

**Why.** The labeled corpus gets built regardless, because D5 requires it. The
marginal cost of publishing it is documentation and a runner.

No open, randomly sampled, hand-labeled corpus of real MCP findings exists.
Labeled corpora that do exist sit inside individual scanners and were curated to
those scanners' own rules, which is exactly the circularity D7 describes. A
shared benchmark lets tools be compared on the same footing instead of each
quoting a figure from its own private collection.

"Score your scanner against this" is a stronger position than "trust our
number", and it turns the most tedious part of the project into the part most
likely to be used by other people.

**Cost.** A public benchmark implies a duty to maintain it, and labels will be
disputed. Both are acceptable; a disputed label is a conversation about
methodology, which is the conversation this project wants to be in.

**Not doing.** Running other scanners against the corpus and publishing a
league table. The benchmark is an invitation, not an attack, and numbers
produced by us running somebody else's tool would rightly be questioned.
