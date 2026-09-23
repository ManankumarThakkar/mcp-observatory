"""The canonical record for a single detection."""

import hashlib
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any, Literal, get_args

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]

# Derived from the annotations above rather than restated, so the static type
# and the runtime check cannot drift apart. Widening either Literal widens the
# guard automatically.
SEVERITIES: tuple[str, ...] = get_args(Severity)
CONFIDENCES: tuple[str, ...] = get_args(Confidence)


def _require_one_of(value: str, allowed: tuple[str, ...], field: str) -> None:
    if value not in allowed:
        raise ValueError(f"{field} must be one of {', '.join(allowed)}, got {value!r}")


@dataclass(frozen=True)
class Location:
    file: str
    line: int


@dataclass(frozen=True)
class Finding:
    server_id: str
    commit_sha: str
    rule_id: str
    severity: Severity
    confidence: Confidence
    location: Location
    evidence: str

    def __post_init__(self) -> None:
        """Reject an unknown severity or confidence at construction.

        The Literal annotations above are enforced only by a type checker, and
        none runs here yet. Without this a typo such as "hgh" would travel
        unnoticed into the report layer, where an unrecognised severity maps to
        the lowest SARIF level and a critical finding is published as a note.
        Failing at construction keeps a bad value out of the record entirely.
        """
        _require_one_of(self.severity, SEVERITIES, "severity")
        _require_one_of(self.confidence, CONFIDENCES, "confidence")

    @property
    def finding_id(self) -> str:
        """Identity of this finding, stable across nightly runs.

        `commit_sha` is deliberately excluded. Including it would give every
        finding a fresh identity on every commit, so nothing could be
        recognised as the same issue seen again and the time series would
        collapse into a pile of single-night records. Evidence is included, so
        a material change to the surrounding code does correctly produce a
        different finding.

        Evidence is hashed to a fixed-length field before being joined, rather
        than embedded directly. Both the file path and the evidence come from a
        repository we do not control, and a POSIX filename may contain ":" and
        "|". Embedded raw, those characters can impersonate the boundary
        between the location and the evidence, so two genuinely different
        findings join to the same string and silently merge into one record.
        `test_finding_id_resists_delimiter_injection_from_a_hostile_repository`
        holds a worked example.
        """
        evidence_hash = hashlib.sha256(self.evidence.encode("utf-8")).hexdigest()
        parts = [
            self.server_id,
            self.rule_id,
            f"{self.location.file}:{self.location.line}",
            evidence_hash,
        ]
        return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()

    @classmethod
    def from_dict(cls, record: Mapping[str, Any]) -> "Finding":
        """Rebuild a finding from the record `to_dict` produced.

        The pipeline reads the history back to decide what may be published,
        and rebuilding by hand at that call site would restate the field list
        in a second place that drifts the moment a field is added.

        Keys the later layers add - first_seen, last_seen, disclosure_state -
        are ignored rather than rejected. They belong to the history rather
        than to the finding, and refusing them would make the history
        unreadable by the layer that wrote it.
        """
        location = record["location"]
        return cls(
            server_id=record["server_id"],
            commit_sha=record["commit_sha"],
            rule_id=record["rule_id"],
            severity=record["severity"],
            confidence=record["confidence"],
            location=Location(file=location["file"], line=location["line"]),
            evidence=record["evidence"],
        )

    def to_dict(self) -> dict[str, object]:
        """Render the subset of spec section 8 that this plan produces.

        `triage`, `first_seen`, `last_seen` and `disclosure_state` are absent
        by design. They are filled by layers that do not exist yet, and a
        placeholder would be a value the schema promises but nothing supplies.

        `asdict` renders the location rather than naming its fields here, so
        the two cannot drift apart.
        """
        return {
            "finding_id": self.finding_id,
            "server_id": self.server_id,
            "commit_sha": self.commit_sha,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "location": asdict(self.location),
            "evidence": self.evidence,
        }
