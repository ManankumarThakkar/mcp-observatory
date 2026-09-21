"""The canonical record for a single detection."""

import hashlib
from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["critical", "high", "medium", "low", "info"]
Confidence = Literal["high", "medium", "low"]


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

    def to_dict(self) -> dict:
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
