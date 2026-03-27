"""Canonical decision record.

Every verdict emits one of these. Non-negotiable. Immutable.

{
  "decision_id": "...",
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

v1.1 — Added decision_id (SHA-256 of canonical record).
v1.2 — DecisionRecord is now truly immutable (frozen dataclass).
        state_after_hash removed from this object — it belongs on
        CommittedRecord, which is produced by the commit gate.
        The record does not mutate after construction. Ever.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from core.version import SCHEMA_VERSION
from core.canonical import canonical_json, canonical_hash


def _compute_decision_id(
    packet_hash: str,
    schema_version: str,
    verdict: str,
    reason_code: str,
    proof_status: str,
    paradox_class: Optional[str],
    state_change: str,
    trace: list[str],
    executed: bool,
) -> str:
    """SHA-256 of the canonical decision dict.

    This is a pure function: same inputs → same hash. Always.
    """
    core = {
        "packet_hash": packet_hash,
        "schema_version": schema_version,
        "verdict": verdict,
        "reason_code": reason_code,
        "proof_status": proof_status,
        "paradox_class": paradox_class,
        "state_change": state_change,
        "trace": trace,
        "executed": executed,
    }
    return canonical_hash(core)


@dataclass(frozen=True)
class DecisionRecord:
    """Immutable decision record. Emitted on every verdict. Never mutated.

    decision_id: SHA-256 of the canonical core fields.
                 Computed at construction, immutable thereafter.
    """
    packet_hash: str
    schema_version: str
    verdict: str
    reason_code: str
    proof_status: str           # "PASSED", "FAILED", "NOT_CHECKED"
    paradox_class: Optional[str]
    state_change: str           # always "NONE" for now
    trace: tuple[str, ...] = ()
    executed: bool = False
    decision_id: str = ""

    def __post_init__(self):
        """Compute decision_id if not already set.

        Uses object.__setattr__ because the dataclass is frozen.
        """
        if not self.decision_id:
            computed = _compute_decision_id(
                self.packet_hash,
                self.schema_version,
                self.verdict,
                self.reason_code,
                self.proof_status,
                self.paradox_class,
                self.state_change,
                list(self.trace),
                self.executed,
            )
            object.__setattr__(self, "decision_id", computed)

    def to_dict(self) -> dict:
        return {
            "decision_id": self.decision_id,
            "packet_hash": self.packet_hash,
            "schema_version": self.schema_version,
            "verdict": self.verdict,
            "reason_code": self.reason_code,
            "proof_status": self.proof_status,
            "paradox_class": self.paradox_class,
            "state_change": self.state_change,
            "trace": list(self.trace),
            "executed": self.executed,
        }

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_dict())
