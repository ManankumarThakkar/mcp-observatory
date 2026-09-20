# Disclosure Policy

This project performs **static analysis only**. It never installs, builds, or
executes any server it analyzes.

## What is published immediately

Aggregate, non-attributable statistics. Example: "N servers scanned, X% match
pattern Y." These identify no project and enable no attack.

## What is withheld

Per-server findings at `high` or `critical` severity are withheld from the
public dashboard until the disclosure process below completes.

## Disclosure process

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
level, and per-rule precision is measured against a hand-labeled golden set and
published alongside the results. Maintainers may dispute a finding by opening an
issue.

## Opt-out

Any maintainer may request exclusion. Requests are honored without argument and
without requiring justification.
