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

**Why.** Covering one language would halve the credibility of any ecosystem
claim. tree-sitter parses both through a single interface. Python also keeps
the LLM triage and eval layers in the ecosystem with the best tooling.

**Amended 2026-09-22.** This was argued from "roughly 45% Python and 30-35%
TypeScript", which predates having a corpus. Measured over 463 real
repositories across both populations, the split is the other way round:

| | registry | code-search candidates |
| --- | ---: | ---: |
| TypeScript | 33% | 39% |
| Python | 26% | 38% |
| JavaScript | 16% | 11% |
| everything else | 24% | 12% |

The conclusion is unchanged and better supported: one analyzer covering both.
The ordering it implied is not, and D6 is amended accordingly. Covering
JavaScript needs no extra grammar, because the tsx grammar reads the whole
JavaScript family including JSX inside a `.js` file, which the plain TypeScript
grammar rejects.

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

## D6 - v1 deep rules cover TypeScript and JavaScript, and the dashboard says so

**Decision.** `UNICODE-CONCEAL` runs against every server in the corpus,
because it is a character scan that needs no parser. The four tree-sitter rules
- `TOOL-DESC-INJECTION`, `PATH-TRAVERSAL`, `SHELL-EXEC-UNSAFE`,
`SCOPE-OVERBROAD` - cover TypeScript and JavaScript servers in v1. Python is
the first post-v1 work. The published results state per-language coverage
explicitly rather than presenting one language's figure as an ecosystem one.

**Why.** This decision originally read "Python only", on the basis that Python
was the larger half of the ecosystem. A measurement of 463 real repositories
showed it is not: TypeScript and JavaScript together are 50% of both the
registry and the code-search populations, against Python's 26% and 38%. See the
table in D3.

Writing one language's rules first is still right, for the reasons the original
decision gave: the rules are not translations of each other, the taint analysis
differs, each needs its own queries and fixtures, and doing both would delay the
accuracy measurement, which is the thing that actually distinguishes this work.
What changed is only which language goes first, and the answer should follow the
corpus rather than an assumption about it.

The JavaScript half comes almost free. One grammar covers `.ts`, `.tsx`, `.js`,
`.jsx`, `.mjs` and `.cjs`, so the rules reach half the ecosystem for roughly one
language's effort, where Python-first would have reached a quarter to a third.

Shipping a measured, honest half beats delaying a complete one. The failure mode
to avoid is not narrow coverage; it is *undisclosed* narrow coverage. A reader
who is told which servers were deep-scanned and which were only checked for
concealment can judge the result. A reader shown a bare ecosystem percentage
cannot.

**Cost.** Python servers get concealment detection only in v1, which is a
quarter of the registry and over a third of the candidates. The Python
vulnerable and clean fixtures written for Plan 1 remain useful but are no longer
the ones v1 ships against, so TypeScript fixtures have to be written. Accepted,
and stated wherever results are published.

**Revisit when.** Python rules are the first post-v1 work, ahead of any sixth
rule. If a later measurement moves the split materially, this ordering is the
thing to re-check, not the choice to do one language at a time.

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

---

## D9 - Cap the size of any single file the scanner will read

**Decision.** The scanner skips a file larger than 1 MB. The fetcher's 50 MB
cap on a whole repository stays as it is.

**Why.** The repository cap permits one file using all of it, and that case was
measured rather than estimated:

| | 48.6 MB file | with the cap |
|---|---|---|
| Scan time | 23.35 s | 0.001 s |
| Peak memory | 235 MB | negligible |

A thousand-server nightly run of such repositories would take 6.4 hours and
exceed the CI job limit. Padding a repository costs an attacker nothing, which
makes this a cheap way to slow down the run that exists to watch them. Most of
the memory came from splitting 3 million lines into a list, not from the file
itself.

1 MB is generous for source code. What exceeds it is minified bundles,
generated code and vendored blobs, none of which should be attributed to the
repository that happens to contain them.

**Cost, stated plainly.** A finding inside a very large but legitimate file
goes undetected. That is a real recall loss, accepted because the alternative
is a nightly run that can be stalled by anyone who pads a repository.

**Not yet handled.** Nothing records *which* files were skipped. A skip that
nobody can see is the same shape of problem as a rule that silently does not
run (D7 reasoning, and the argument that replaced the rule registry). It is
bounded and rare here rather than systemic, but per-file skip reporting belongs
with the per-server outcome model in the scan orchestrator, and should be added
when that exists.

---

## D10 - Treat cost the way we treat accuracy: measure it and publish it

**Decision.** Track tokens and money per server scanned, publish the figure
beside the precision figure, and publish the share of findings that never
reached a model at all. Design for someone running the scanner on their own
servers, not only for our nightly run.

**Why.** The same argument as D5. An unmeasured error rate is an opinion; so is
"it's cheap". A scanner someone else can run costs them real money, and a
number they can check is worth more than an adjective.

It is also a genuine property of the design rather than a claim bolted on.
Spec section 7's partial adjudication means a direct taint path never reaches a
model, `UNICODE-CONCEAL` is never adjudicated at all, and findings are cached by
content hash so an unchanged finding costs nothing on the next run. Most servers
should cost nothing to scan.

**What the arithmetic says**, at $1.00 per million input tokens and $5.00 per
million output on `claude-haiku-4-5`, estimating ~600 input and ~100 output
tokens per adjudication:

| | Standard | Batch API |
|---|---|---|
| One adjudicated finding | $0.0011 | $0.00055 |
| A typical server, 2 findings | $0.0022 | $0.0011 |
| A clean server | $0 | $0 |

**Three consequences for the triage layer.**

*Use the Batch API.* It is 50% cheaper and asynchronous, and a nightly run has
no latency requirement at all. This is the largest lever available and it costs
nothing but a different call shape: submit, poll, collect. That reshapes the
triage layer, so it is a design input rather than an optimisation.

*Check whether prompt caching even applies.* The minimum cacheable prefix is
512 to 4096 tokens depending on model. A triage system prompt may well be
shorter than that, in which case caching silently does nothing and the cache
hit rate is zero. Measure `usage.cache_read_input_tokens` rather than assuming.

*Measure tokens, do not estimate them.* `messages.count_tokens` is free and
exact. The numbers above are arithmetic on real prices applied to estimated
token counts, and the estimate is the weak half.

**What this changes about sampling.** A full corpus scan of 25,977 servers is
roughly 52,000 adjudications, about $28 batched, against a stated ceiling of
$20-30 a month, and only on the first run because the content-hash cache
absorbs everything unchanged afterwards. The 3,000-call spend guard in spec
section 12 works out to about $1.65, which is roughly twenty times more
conservative than the budget it was meant to protect. It was set from intuition
rather than arithmetic and should be recalibrated once the token counts are
measured.

**Cost.** Publishing a cost figure invites the same scrutiny as publishing an
accuracy figure, and a number that moves with model pricing needs a date
attached. Both are acceptable, and both are the point.
