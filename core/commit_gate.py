"""COMMIT_GATE_v1.2 — Execution-binding commit boundary (pure).

The commit gate is the Layer 2 mechanism that converts the Decision Record
from an *output* of evaluation into a *required input* for state mutation.

Canonical invariant (frozen):
    No valid Decision Record at commit time = no state mutation.

Design constraints:
    - Pure function.  No hidden state.  No side effects.  No mutation.
    - Deterministic: same inputs → same outputs.
    - Fail-closed: any doubt → CommitDenied.
    - DecisionRecord is frozen (immutable). The gate never touches it.
    - State binding lives on CommittedRecord, a separate immutable object
      returned only on success.

v1.0 — Initial commit gate.
v1.1 — Fixed purity/immutability contradiction.
v1.2 — Gap 5: state oracle wired in (state_before_hash verified against
        actual state).
        Gap 4: boundary context wired in (environment + boundary class
        validated).
        Both are optional — backward compatible with v1.1 callers.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from core.algebra import Action, Verdict
from core.canonical import Packet
from core.decision_record import DecisionRecord
from core.version import SCHEMA_VERSION
from core.state_oracle import StateOracle
from core.boundary_context import BoundaryContext, validate_boundary


# ---------------------------------------------------------------------------
# Authority scope policy (Gap 1)
# ---------------------------------------------------------------------------

AUTHORITY_SCOPE: dict[str, frozenset[str]] = {
    "read":   frozenset({"admin", "operator", "reviewer"}),
    "write":  frozenset({"admin", "operator"}),
    "delete": frozenset({"admin"}),
    "deploy": frozenset({"admin"}),
    "commit": frozenset({"admin"}),
}


def authority_sufficient(action_type: str, authority_type: str) -> bool:
    """Return True if authority_type is sufficient for action_type."""
    allowed = AUTHORITY_SCOPE.get(action_type)
    if allowed is None:
        return False
    return authority_type in allowed


# ---------------------------------------------------------------------------
# Committed record — the state binding object
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CommittedRecord:
    """Immutable proof that a commit was authorised.

    Binds a decision_id to the resulting state hash.
    Produced only by the commit gate on success.
    """
    decision_id: str
    packet_hash: str
    state_before_hash: str
    state_after_hash: str


# ---------------------------------------------------------------------------
# Commit result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CommitResult:
    """Immutable result of a commit gate evaluation."""
    permitted: bool
    committed: Optional[CommittedRecord] = None
    denial_reason: str = ""
    denial_code: str = ""

    @property
    def decision_id(self) -> str:
        return self.committed.decision_id if self.committed else ""

    @property
    def state_after_hash(self) -> Optional[str]:
        return self.committed.state_after_hash if self.committed else None


# ---------------------------------------------------------------------------
# Denial codes (maps to canonical failure set)
# ---------------------------------------------------------------------------

class DenialCode:
    NO_RECORD            = "no_decision_record"
    MALFORMED_RECORD     = "malformed_decision_record"
    MISSING_FIELDS       = "missing_mandatory_fields"
    VERDICT_NOT_ALLOW    = "verdict_not_allow"
    HASH_MISMATCH        = "packet_hash_mismatch"
    SCHEMA_MISMATCH      = "schema_version_mismatch"
    NOT_EXECUTED         = "executed_flag_false"
    AUTHORITY_SCOPE      = "authority_scope_invalid"
    AUTHORITY_STALE      = "authority_stale"
    STATE_HASH_MISMATCH  = "state_hash_mismatch"
    STATE_UNKNOWN        = "state_unknown"
    BOUNDARY_MISMATCH    = "commit_boundary_mismatch"


# ---------------------------------------------------------------------------
# Commit gate (pure function)
# ---------------------------------------------------------------------------

def commit_gate(
    record: Optional[DecisionRecord],
    packet: Packet,
    state_before_hash: str,
    state_after_hash: str,
    *,
    state_oracle: Optional[StateOracle] = None,
    boundary: Optional[BoundaryContext] = None,
) -> CommitResult:
    """The commit boundary.  Pure function.  No mutation.  No side effects.

    Args:
        record:            The DecisionRecord that must authorise this commit.
        packet:            The original Packet that was evaluated.
        state_before_hash: Hash of state before the proposed mutation.
        state_after_hash:  Hash of state after the proposed mutation.
        state_oracle:      Optional. If provided, state_before_hash is verified
                           against the oracle's view of current state.
                           If not provided, state verification is skipped
                           (backward compatible).
        boundary:          Optional. If provided, the commit boundary
                           (environment + boundary class) is validated.
                           If not provided, boundary validation is skipped
                           (backward compatible).

    Returns:
        CommitResult with permitted=True and a CommittedRecord,
        or CommitResult with permitted=False and a denial reason.
    """

    # --- Failure 1: No decision record ---
    if record is None:
        return CommitResult(
            permitted=False,
            denial_reason="No Decision Record provided.",
            denial_code=DenialCode.NO_RECORD,
        )

    # --- Failure 2: Malformed decision record (missing decision_id) ---
    if not record.decision_id:
        return CommitResult(
            permitted=False,
            denial_reason="Decision Record has no decision_id.",
            denial_code=DenialCode.MALFORMED_RECORD,
        )

    # --- Failure 3: Missing mandatory fields ---
    for field_name in ("packet_hash", "verdict", "reason_code", "schema_version"):
        val = getattr(record, field_name, None)
        if not val:
            return CommitResult(
                permitted=False,
                denial_reason=f"Decision Record missing mandatory field: {field_name}.",
                denial_code=DenialCode.MISSING_FIELDS,
            )

    # --- Schema version check ---
    if record.schema_version != SCHEMA_VERSION:
        return CommitResult(
            permitted=False,
            denial_reason=(
                f"Schema mismatch: record={record.schema_version}, "
                f"expected={SCHEMA_VERSION}."
            ),
            denial_code=DenialCode.SCHEMA_MISMATCH,
        )

    # --- Verdict must be ALLOW ---
    if record.verdict != Verdict.ALLOW.value:
        return CommitResult(
            permitted=False,
            denial_reason=f"Verdict is {record.verdict}, not ALLOW.",
            denial_code=DenialCode.VERDICT_NOT_ALLOW,
        )

    # --- executed flag must be True ---
    if not record.executed:
        return CommitResult(
            permitted=False,
            denial_reason="Decision Record executed flag is False.",
            denial_code=DenialCode.NOT_EXECUTED,
        )

    # --- Failure 4: Hash binding — record must match the packet ---
    expected_hash = packet.canonical_hash()
    if record.packet_hash != expected_hash:
        return CommitResult(
            permitted=False,
            denial_reason=(
                f"packet_hash mismatch: record={record.packet_hash}, "
                f"packet={expected_hash}."
            ),
            denial_code=DenialCode.HASH_MISMATCH,
        )

    # --- Failure 6 (Gap 5): State hash verification via oracle ---
    if state_oracle is not None:
        actual_state = state_oracle.current_state_hash(packet.object_ref)
        if actual_state is None:
            return CommitResult(
                permitted=False,
                denial_reason=(
                    f"State oracle cannot determine current state for "
                    f"'{packet.object_ref}'. Fail-closed."
                ),
                denial_code=DenialCode.STATE_UNKNOWN,
            )
        if actual_state != state_before_hash:
            return CommitResult(
                permitted=False,
                denial_reason=(
                    f"state_before_hash mismatch: claimed={state_before_hash}, "
                    f"actual={actual_state}."
                ),
                denial_code=DenialCode.STATE_HASH_MISMATCH,
            )

    # --- Failure 5 (Gap 4): Boundary context validation ---
    if boundary is not None:
        boundary_result = validate_boundary(boundary)
        if not boundary_result.valid:
            return CommitResult(
                permitted=False,
                denial_reason=boundary_result.denial_reason,
                denial_code=DenialCode.BOUNDARY_MISMATCH,
            )

    # --- Failure 7 (Gap 1): Authority scope validation ---
    action = Action(action_type=packet.requested_action)
    if action.is_mutating():
        auth = packet.authority_claim or {}
        auth_type = auth.get("authority_type", "")

        # Freshness — double-check at commit boundary
        expires = auth.get("expires_at", 0)
        if expires and packet.timestamp > expires:
            return CommitResult(
                permitted=False,
                denial_reason=(
                    f"Authority expired: expires_at={expires}, "
                    f"timestamp={packet.timestamp}."
                ),
                denial_code=DenialCode.AUTHORITY_STALE,
            )

        # Scope — is this authority type allowed for this action?
        if not authority_sufficient(packet.requested_action, auth_type):
            return CommitResult(
                permitted=False,
                denial_reason=(
                    f"Authority type '{auth_type}' insufficient for "
                    f"action '{packet.requested_action}'."
                ),
                denial_code=DenialCode.AUTHORITY_SCOPE,
            )

    # --- All checks pass: produce CommittedRecord (no mutation) ---
    committed = CommittedRecord(
        decision_id=record.decision_id,
        packet_hash=record.packet_hash,
        state_before_hash=state_before_hash,
        state_after_hash=state_after_hash,
    )

    return CommitResult(
        permitted=True,
        committed=committed,
    )
