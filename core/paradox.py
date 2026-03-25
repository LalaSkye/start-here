"""PARADOX_VECTOR_v1 — Formal contradiction sink.

Upgraded from src/paradox.py to operate on canonical Packets
and use the formal algebra primitives.

PV(x) = sink(x) iff contradiction(x) = true

Where:
  contradiction(x) :=
    authority_incoherent(x)
    ∨ state_incoherent(x)
    ∨ execution_incoherent(x)
    ∨ structural_incoherent(x)
    ∨ temporal_incoherent(x)

Invariant:
  contradiction(x) ⇒ execute(x) = false

Output set is closed: {DENY, HOLD, HALT}
No output in this set may execute.
No output may mutate state.
No output may adapt to attacker pressure.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from core.algebra import Verdict, Action
from core.canonical import Packet


# ---------------------------------------------------------------------------
# Contradiction classes (bounded, finite)
# ---------------------------------------------------------------------------

class ContradictionClass(str, Enum):
    AUTHORITY_CONTRADICTION = "authority_contradiction"
    STATE_CONTRADICTION = "state_contradiction"
    EXECUTION_CONTRADICTION = "execution_contradiction"
    STRUCTURAL_CONTRADICTION = "structural_contradiction"
    TEMPORAL_CONTRADICTION = "temporal_contradiction"
    REPLAY_CONTRADICTION = "replay_contradiction"


ALL_CONTRADICTION_CLASSES = frozenset(ContradictionClass)


# ---------------------------------------------------------------------------
# Contradiction detection — operates on canonical Packets
# ---------------------------------------------------------------------------

def detect_contradiction(packet: Packet) -> Optional[ContradictionClass]:
    """Check a canonical packet for contradiction conditions.

    Evaluation order is fixed. First contradiction wins.
    Returns None if no contradiction found.
    """
    flags = packet.flags or {}
    auth = packet.authority_claim or {}
    action = Action(action_type=packet.requested_action)

    # --- A. Authority contradictions ---

    # Authority revoked but mutating action requested
    if flags.get("authority_revoked") and action.is_mutating():
        return ContradictionClass.AUTHORITY_CONTRADICTION

    # Inherited authority where fresh is required
    if flags.get("inherited_authority") and flags.get("fresh_authority_required"):
        return ContradictionClass.AUTHORITY_CONTRADICTION

    # Claims approval but authority claim is empty
    auth_type = auth.get("authority_type", "")
    if flags.get("claims_approval") and not auth_type:
        return ContradictionClass.AUTHORITY_CONTRADICTION

    # --- B. State contradictions ---

    if flags.get("references_nonexistent_state"):
        return ContradictionClass.STATE_CONTRADICTION

    if flags.get("impossible_prior_state"):
        return ContradictionClass.STATE_CONTRADICTION

    # State hash mismatch
    if flags.get("state_hash_mismatch"):
        return ContradictionClass.STATE_CONTRADICTION

    # --- C. Execution contradictions ---

    if flags.get("marked_non_exec") and flags.get("requests_execution"):
        return ContradictionClass.EXECUTION_CONTRADICTION

    if flags.get("execution_in_description"):
        return ContradictionClass.EXECUTION_CONTRADICTION

    # --- D. Structural contradictions ---

    if flags.get("missing_critical_fields") and action.is_high_risk():
        return ContradictionClass.STRUCTURAL_CONTRADICTION

    # --- E. Temporal contradictions ---

    if flags.get("stale_approval"):
        return ContradictionClass.TEMPORAL_CONTRADICTION

    if flags.get("future_authorisation"):
        return ContradictionClass.TEMPORAL_CONTRADICTION

    # Authority expiry check (if timestamps are present)
    issued = auth.get("issued_at", 0)
    expires = auth.get("expires_at", 0)
    current = packet.timestamp
    if issued and expires and current:
        if current > expires and action.is_mutating():
            return ContradictionClass.TEMPORAL_CONTRADICTION

    return None


# ---------------------------------------------------------------------------
# Contradiction sink — sealed, fixed, non-executing
# ---------------------------------------------------------------------------

def sink(contradiction: ContradictionClass) -> dict:
    """Emit a fixed non-executing result. The contradiction sink.

    Mandatory behaviour: stop, emit, log. No mutation. No adaptation.
    Forbidden: counterattack, taunting, recursive engagement,
               rich attacker feedback, adaptive counter-play.
    """
    return {
        "verdict": Verdict.DENY.value,
        "reason_code": contradiction.value,
        "execution": "BLOCKED",
        "state_change": "NONE",
        "executed": False,
    }
