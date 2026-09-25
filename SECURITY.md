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

**Notification is not implemented yet, and nothing has been notified.** Step 1
below describes the intended process, not a process that has run. A window opens
only when a notification is recorded, so today no window has opened and every
high and critical finding is withheld indefinitely. That fails closed, which is
the right direction, and it means this project currently publishes one rule of
five. Saying so is better than a policy that reads as though the process were
running.

## Disclosure process

**Intended, not yet implemented.** See the note above.

1. Maintainer is notified privately via GitHub Security Advisory.
2. A 90-day window opens from the date of notification.
3. After the window closes, or once a fix ships, the finding may be published.
4. Findings for archived or clearly abandoned projects are published as
   `unmaintained` after notification is attempted.

## Never published

Exploit code or proof-of-concept payloads. Findings describe the pattern and
its location; they do not provide a working attack.

## False positives

Static analysis produces false positives. Every finding carries a confidence
level. Per-rule precision is measured against a hand-labelled golden set and
published alongside the results - **that measurement has not been made yet.**
288 findings have been drawn at random and captured for labelling; none are
labelled. Until they are, treat every finding as a candidate rather than a
confirmed problem. Maintainers may dispute a finding by opening an
issue.

## Opt-out

Any maintainer may request exclusion. Requests are honored without argument and
without requiring justification.
