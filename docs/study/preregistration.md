# Pre-registration: annotation context and verdict stability

Registered by merge to `main`, before any person has labelled any entry.

- Frozen snapshot digest:
  `3252f9da7b059be5b61a87ed4bb0294c3e67c050098fe11c0dcd1e9c34ffd79d`
- 566 entries, frozen 2026-10-01T13:59:31Z from the code at `af5219426bc9`.
- The digest covers what each judge was shown and nothing written afterwards, so
  labelling the snapshot leaves the digest unchanged, while any change to the
  code shown alters it.

## Question

When an LLM judge triages a static-analysis finding, how often does its verdict
depend only on how much surrounding code it is shown, and when the two views
disagree, which one is wrong, and in which direction?

## What was already observed before registering

Stated so a reader can see which results this design was shaped by.

- **Verdict flips with context.** On the earlier 177-finding paired pool, 33
  findings (18.6%) received a different verdict from a 25-line window than from the
  enclosing function; on a 259-finding pool drawn on 2026-10-01, 53 (20.5%). One
  server contributed 12 of those 53, all PATH-TRAVERSAL across eight functions in
  seven files, ten of them the window calling a finding real that the function did
  not; without that server the rate was 17.4% (41 of 235) across 28 servers.
- **The frozen pool itself.** The judges were run on this snapshot before it was
  registered, so its headline figures are already known: 69 of 369 paired
  findings (18.7%) change verdict, across 34 servers. The same server contributes
  22 of them, 20 with the window calling the finding real; without it the rate is
  14.4% (47 of 326). Across all 69, the window judge says real in 43 and the
  function judge in 26. That lean is a property of the two judges, not of their
  errors: which of them is wrong is what only a person's label can say, and none
  exists.
- **The judge's own noise floor.** Asked every question twice against an empty
  cache, verdicts changed on identical input for 1.7% (window) and 1.1% (function)
  of findings, and 30 of the first pool's 33 context flips recurred. The two runs
  were four to six days apart, so this bounds randomness and model drift together.
- **Decisiveness.** A test that the enclosing function makes the judge more decisive
  was null on all three pools (sign test p = 0.25, 0.77 and 0.19). On the frozen
  pool one rule, SHELL-EXEC-UNSAFE, reached p = 0.024 uncorrected, which does not
  survive correction for five rules and is not a hypothesis here.
- **A model-labelled signal motivated H1.** On 28 disagreements, labels produced by
  Claude, a model, suggested the window judge errs credulously about 16:1. Those
  labels are model output, not ground truth, and **no analysis below uses them**
  except H4's comparison of model against human labels.

## Population and sampling

- **Population.** Findings produced by five static rules over a seeded random
  sample of 2,000 repositories from the official MCP registry as crawled on
  2026-09-23 (21,492 repositories), scanned on 2026-09-25, restricted to findings
  the current rules still produce at each repository's head when captured.
- **Pool.** Drawn per rule with the project's hashed sampling method at
  `--per-rule 165`, the size of the larger taint population, so both taint rules
  (PATH-TRAVERSAL, SHELL-EXEC-UNSAFE) are included in full. That number was fixed
  from population counts alone before the pool's disagreement count was read. The
  draw selected 703 findings; 137 could not be captured, 135 because the current
  rules no longer produce them at the repository's head and 2 because the clone
  failed. Of the 566 captured entries, 369 have an enclosing function
  and so carry both conditions.
- **Unit of analysis:** the finding. **Cluster:** the server. Findings within a
  server, and especially within one function, are not independent.

## Conditions

- **Window:** the flagged line and twelve lines either side.
- **Function:** the smallest function enclosing the flagged line that opens at or
  before its first non-whitespace character, up to 12,000 characters.
- **Judge:** the Jev decision model, given identical questions in both conditions,
  answering a probability. A verdict is "real" at 0.5 or above. The midpoint is not
  tuned, so no threshold is fitted to these data. The judge's API reports no model
  version, so the version cannot be pinned; instead every probability the analysis
  uses is stored in the frozen snapshot, and no judge is called again.

## Hypotheses

- **H1 (primary, confirmatory).** Among findings where the two conditions'
  verdicts disagree and a person has labelled the finding real or not real, the
  window judge's errors are predominantly credulous: it calls real what the person
  calls not real. Test: two-sided exact sign test on credulous against missed
  window errors, alpha 0.05. The test is decided by which judge the person sides
  with on each disagreement, not by the lean between the judges reported above.
  Interval: 95% percentile bootstrap resampling servers, 2,000 resamples, seed
  20260926. Sensitivity: the same test keeping one finding per server.
- **H2 (estimate).** The share of paired findings whose verdict changes with the
  context, with a 95% server-clustered interval, reported beside the test-retest
  noise floor above. Not a replication: the pool contains the findings it was first
  observed on, and its point estimate is already stated above, so only the interval
  is new. Sensitivity: the same estimate with the server contributing the most
  disagreements left out, because one server already contributes 22 of the 69 in
  this pool.
- **H3 (exploratory).** The accuracy gap between the conditions against human
  labels. Underpowered by design: a 60/40 split needs 194 decided disagreements,
  which at this pool's rate, allowing for 15% unsure, is about 1,200 paired
  findings. Reported descriptively, with no claim.
- **H4 (descriptive).** Calibration of the judge on the random control sample only:
  Brier score, expected calibration error and the reliability table, per condition.
  And agreement between Claude's earlier labels and the human labels (kappa).

## Sample for human labelling

Every disagreement in the frozen snapshot (69) plus a random control of 60 drawn
from all paired findings with seed 20260926. Because the control is drawn from
every paired finding, 13 of its 60 are also disagreements, so the queue holds 116
findings in total. The size is fixed now. No human label is compared with any
judge, and no analysis is run, until annotation is complete.

## Annotation

- **Who:** the author, who is also responsible for the rules that produced the
  findings. That conflict of interest is a stated limitation, and it is why
  blinding below is structural rather than procedural.
- **Blinding:** the annotator works from an exported file holding only the code
  (both contexts), the rule's claim and the language. It contains no probability,
  model label or reason, scanner severity or confidence, server or file path. The
  queue interleaves disputed and control findings by hashed identity, so position
  does not reveal which is which.
- **Rubric:** `evals/golden/LABELLING.md`. "Real" means an assistant-supplied
  argument reaches the sink with nothing constraining it, judged from what is
  shown. That establishes a reachable weakness from static reading, not a
  confirmed vulnerability; no exploit is attempted. `unsure` is a permitted answer.
- **Reliability:** a second annotator labels a random 40 of the queue (seed
  20260927), blind to the first; kappa and raw agreement are reported, and conflicts
  are adjudicated with a recorded reason. If no second annotator is available, the
  author re-labels the same 40 after a washout of at least two weeks, and
  intra-rater agreement is reported in its place, with the limitation stated.

## Exclusions and stopping

- Human `unsure` answers are excluded from H1 and H3, and their count is reported.
- The analysis refuses to run if the snapshot's digest no longer matches this
  registration.
- The sample size is fixed above. There is no interim analysis and no optional
  stopping.

## Deviations

Any departure from this plan is reported in the paper with its reason, and analyses
not listed here are labelled exploratory.

## Ethics

No scanned repository is executed. Maintainers are notified only of findings a
person has verified as real, privately and before submission. Findings above
medium severity are never published individually before their maintainers have
been told, and the paper reports them only in aggregate until then.
