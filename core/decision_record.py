"""Canonical decision record.

Every verdict emits one of these. Non-negotiable.

{
  "packet_hash": "...",
  "schema_version": "1.0.0",
  "verdict": "DENY",
  "reason_code": "AUTHORITY_STALE",
  "proof_status": "FAILED",
  "paradox_class": null,
  "state_change": "NONE",
  "trace": ["PARSE_OK", "CANONICAL_OK", "PROOF_FAIL:authority_fresh", "VERDICT:DENY"]
}

Auditability. Replayability. Exact comparison between implementations.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.version import SCHEMA_VERSION
from core.canonical import canonical_json, canonical_hash


@dataclass
class DecisionRecord:
    """Immutable decision record. Emitted on every verdict."""
    packet_hash: str
    schema_version: str
    verdict: str
    reason_code: str
    proof_status: str           # "PASSED", "FAILED", "NOT_CHECKED"
    paradox_class: Optional[str]
    state_change: str           # always "NONE" for now
    trace: list[str] = field(default_factory=list)
    executed: bool = False

    def to_dict(self) -> dict:
        return {
            "packet_hash": self.packet_hash,
            "schema_version": self.schema_version,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "proof_status": self.proof_status,
            "paradox_class": self.paradox_class,
            "state_change": self.state_change,
            "trace": self.trace,
            "executed": self.executed,
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_dict())
