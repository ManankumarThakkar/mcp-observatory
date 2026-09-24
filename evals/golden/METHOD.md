# How the golden set is drawn

This file is part of the benchmark. A label without a published method is an
opinion, and a number without one is a claim nobody can check.

## Where the findings come from

A reproducible subset of the crawled corpus, scanned on 2026-09-23.

| | |
|---|---|
| Corpus | 21,492 distinct repositories, collapsed from 35,009 registry entries |
| Subset | 2,000 repositories, seed `20260923` |
| Scanned | 1,642 (358 skipped as unproven servers, 0 failed) |
| Findings | 1,269 across 306 servers |
| Drawn | 300, sixty per rule, across 140 servers |

Regenerate the subset with:

```bash
mcp-observatory crawl
mcp-observatory scan --index .cache/server_index.jsonl --sample 2000 --seed 20260923
```

The draw orders candidates by `sha256("<seed>:<identity>")` and takes the
first n. That is the whole method: it can be reimplemented in any language,
and it does not depend on the order the findings arrived in. A seeded shuffle
would depend on the language's own random implementation, which is not a
promise any of them make across versions.

## Sixty per rule, not three hundred at random

Sampling uniformly would satisfy "drawn from real output, never curated" and
then fail its purpose. Two rules account for 71% of all findings, so a uniform
sample of 300 would draw about seven `UNICODE-CONCEAL` findings and report a
precision for that rule that means nothing.

**The consequence, which matters wherever these numbers are quoted: the
unweighted precision over this sample is not the precision over the corpus.**
Quiet rules are deliberately over-represented. The corpus figure is a
population-weighted average, each rule weighted by its real share of findings,
and the scoring script reports both.

## Growing the set without losing labels

Re-drawing after a later scan keeps every finding already drawn and tops each
rule up toward the target. An item's position in the hash order is stable, but
the sixtieth place is not: a new finding that outranks a drawn one would
otherwise replace it and detach a label already made. Entry ids are
append-only and never refer to two different findings.

## What a published entry contains, and what it does not

Published: the rule, severity, the rule's own confidence, the language, a
twenty-five line window of source, which line in that window was flagged, and
the label.

Not published: the server name, repository URL, commit, file path, or
`finding_id`. The last is the non-obvious one - it hashes the server name,
rule, path, line and evidence, all of which are either public already or
published here, so it could be recomputed for every candidate server and
matched back. A hash over public inputs is a lookup key, not an anonymiser.

Redaction is not the only control, because it is not sufficient. The window is
verbatim source and a search engine that has indexed the repository can find
it. Measured on 2026-09-24 against GitHub's code search API, a distinctive
line from one sampled repository returned nothing while a control query
returned 52,864 matches, so that repository is not indexed - which makes
re-identification unreliable rather than impossible, and unreliable is not a
control.

So entries are also gated by the same ninety-day disclosure window the
dashboard uses. An entry is published when its finding was never withheld, or
when its window has closed, and never when the maintainer has opted out.

**As a result this benchmark currently publishes one rule of five.**
`SCOPE-OVERBROAD` is the only rule emitting below `high`, and no disclosure
window has opened, because nothing in this project sends notifications yet.
The full 300 are labelled and measured; the published file grows as windows
close. Saying so is better than publishing a number whose coverage is not
what a reader would assume.
