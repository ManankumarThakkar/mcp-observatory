# Disclosure Policy

This project performs **static analysis only**. It never installs, builds, or
executes any server it analyzes.

## What is published immediately

**Aggregate statistics.** Example: "N servers scanned, X% match pattern Y."
These identify no project.

**Per-server findings at `medium` or `low` severity**, naming the server, its
repository, the file and the line. Amended 2026-09-25, after the first
publication made the earlier wording untrue rather than merely incomplete: the
policy described only a non-attributable category and the dashboard was
publishing attributable findings, which is a contradiction a reader would find
before we did.

The reasoning for publishing this class without prior notice, stated so it can
be disagreed with. These findings are observations about configuration in code
that is already public - "listens on every interface", "accepts any origin" -
they carry no exploit and no proof of concept, and the same class is published
openly by other scanners in this space. Withholding them would make the index
empty for months while notification is built, and an index that shows nothing
teaches nobody anything.

What that costs, stated too: a maintainer learns about a `medium` finding by
reading the dashboard rather than from us first. The opt-out below is the
remedy, and it is honoured without argument.

## What is withheld

Per-server findings at `high` or `critical` severity are withheld from the
public dashboard until the disclosure process below completes. This is enforced
in `analyzer/report/`, not by convention: a finding cannot reach `data/` in a
publishable state without passing the gate.

**No maintainer has been notified yet.** The record of notices exists and the
gate reads it every night, but nothing has been sent, so no window has opened
and every high and critical finding is withheld. That fails closed, which is
the right direction, and it means this project currently publishes one rule of
five.

## Disclosure process

1. **Only findings a person has verified are reported.** Static analysis
   produces false positives, and reporting every alert would send maintainers
   mostly false alarms. A finding is reported only after a person has read the
   code and labelled it real. This is enforced in code: a notice naming an
   unverified finding cannot be recorded.
2. **The maintainer is told privately**, in this order of preference: a GitHub
   private vulnerability report; the contact in the repository's `SECURITY.md`;
   or, failing both, a public issue that asks only for a security contact and
   describes nothing. Each notice is written and sent by a person, never in an
   automated batch.
3. **A 90-day window opens for each finding a notice names**, from the date the
   notice was sent. A notice opens no window for a finding it did not name, and
   a request for a contact opens none at all.
4. **After a finding's window closes, it may be published.**
5. **A finding that was never verified and reported is never published
   individually.** It appears only in aggregate counts.

## Never published

Exploit code or proof-of-concept payloads. Findings describe the pattern and
its location; they do not provide a working attack.

## False positives

Static analysis produces false positives. Every finding carries a confidence
level. Per-rule precision will be measured against findings drawn at random and
labelled by a person, and published alongside the results - **that measurement
has not been made yet.** 566 findings are drawn and frozen, and 116 are queued
for a person to label; none is labelled yet. Until they are, treat every
finding as a candidate rather than a confirmed problem. Maintainers may dispute
a finding by opening an issue.

## Opt-out

Any maintainer may request exclusion. Requests are honored without argument and
without requiring justification.
