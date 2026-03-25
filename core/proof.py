"""PROOF_CARRYING_PACKET_SPEC_v1 — Proof obligations for admissibility.

Do not merely submit an action. Submit the action with the minimal
proof obligations needed for admissibility.

A packet missing required proof fragments is incomplete, not "probably okay".

This is one of the strongest moat layers. Many can copy the policy.
Few will reproduce proof-carrying execution cleanly.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

from core.algebra import Action
from core.canonical import Packet


# ---------------------------------------------------------------------------
# Proof obligation types
# ---------------------------------------------------------------------------

class ObligationType(str, Enum):
    OBJECT_EXISTS = "object_exists"
    ACTOR_BOUND = "actor_bound"
    DEPENDENCY_SATISFIED = "dependency_satisfied"
    STATE_PRECONDITION = "state_precondition"
    ACTION_REGISTERED = "action_registered"
    POLICY_VERSION_MATCH = "policy_version_match"
    AUTHORITY_FRESH = "authority_fresh"
    AUTHORITY_SUFFICIENT = "authority_sufficient"


# ---------------------------------------------------------------------------
# Obligation schema — what proofs are required for which actions
# ---------------------------------------------------------------------------

# Base obligations required for ALL actions
BASE_OBLIGATIONS = frozenset({
    ObligationType.ACTOR_BOUND,
    ObligationType.ACTION_REGISTERED,
})

# Additional obligations for mutating actions
MUTATING_OBLIGATIONS = frozenset({
    ObligationType.OBJECT_EXISTS,
    ObligationType.AUTHORITY_FRESH,
    ObligationType.AUTHORITY_SUFFICIENT,
    ObligationType.STATE_PRECONDITION,
})

# Additional obligations for actions with dependencies
DEPENDENCY_OBLIGATIONS = frozenset({
    ObligationType.DEPENDENCY_SATISFIED,
})

# Policy-bound obligations
POLICY_OBLIGATIONS = frozenset({
    ObligationType.POLICY_VERSION_MATCH,
})


def required_obligations(packet: Packet) -> frozenset[ObligationType]:
    """Compute the set of proof obligations required for this packet."""
    action = Action(action_type=packet.requested_action)
    required = set(BASE_OBLIGATIONS)

    if action.is_mutating():
        required |= MUTATING_OBLIGATIONS

    if packet.dependencies:
        required |= DEPENDENCY_OBLIGATIONS

    # Policy version match is always good practice
    required |= POLICY_OBLIGATIONS

    return frozenset(required)


# ---------------------------------------------------------------------------
# Proof fragment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ProofFragment:
    """A single proof claim attached to a packet."""
    obligation_type: str
    claim: str          # e.g. "object_ref=/data/reports exists"
    evidence_hash: str  # hash of the evidence supporting the claim
    fresh: bool = True  # is this proof current?


# ---------------------------------------------------------------------------
# Proof checker
# ---------------------------------------------------------------------------

@dataclass
class ProofResult:
    """Result of checking proof obligations against a packet."""
    complete: bool
    missing: frozenset[ObligationType]
    stale: frozenset[ObligationType]
    satisfied: frozenset[ObligationType]

    @property
    def admissible(self) -> bool:
        """Proof is admissible only if complete and nothing is stale."""
        return self.complete and len(self.stale) == 0


def check_proof(packet: Packet) -> ProofResult:
    """Check whether a packet carries sufficient proof obligations.

    A packet missing required proof fragments is incomplete, not "probably okay".
    """
    required = required_obligations(packet)

    # Parse proof_obligations from packet
    provided = {}
    for po in (packet.proof_obligations or []):
        if isinstance(po, dict):
            ob_type = po.get("obligation_type", "")
            provided[ob_type] = ProofFragment(
                obligation_type=ob_type,
                claim=po.get("claim", ""),
                evidence_hash=po.get("evidence_hash", ""),
                fresh=po.get("fresh", True),
            )

    satisfied = set()
    missing = set()
    stale = set()

    for obligation in required:
        if obligation.value in provided:
            fragment = provided[obligation.value]
            if fragment.fresh:
                satisfied.add(obligation)
            else:
                stale.add(obligation)
        else:
            missing.add(obligation)

    return ProofResult(
        complete=len(missing) == 0,
        missing=frozenset(missing),
        stale=frozenset(stale),
        satisfied=frozenset(satisfied),
    )


# ---------------------------------------------------------------------------
# Proof denial reasons
# ---------------------------------------------------------------------------

def proof_denial_reason(result: ProofResult) -> Optional[str]:
    """Return a denial reason code if proof is insufficient, else None."""
    if result.admissible:
        return None

    if result.missing:
        missing_names = sorted(o.value for o in result.missing)
        return f"proof_incomplete:{','.join(missing_names)}"

    if result.stale:
        stale_names = sorted(o.value for o in result.stale)
        return f"proof_stale:{','.join(stale_names)}"

    return "proof_inadmissible"
