"""Paradox Vector — Non-executing contradiction sink.

Sits upstream of the normal admissibility gate.
Detects authority-incoherent, state-incoherent, execution-incoherent,
structural-incoherent, and temporal-incoherent inputs.

Contradiction paths do not execute.

PV(x) = sink(x) iff contradiction(x) = true

Output set is closed: {DENY, HOLD, HALT}
No output in this set may execute.
"""

# --- Contradiction reason codes (bounded, finite) ---

AUTHORITY_CONTRADICTION = "authority_contradiction"
STATE_CONTRADICTION = "state_contradiction"
EXECUTION_CONTRADICTION = "execution_contradiction"
STRUCTURAL_CONTRADICTION = "structural_contradiction"
TEMPORAL_CONTRADICTION = "temporal_contradiction"
REPLAY_CONTRADICTION = "replay_contradiction"

ALL_CONTRADICTION_CODES = frozenset({
    AUTHORITY_CONTRADICTION,
    STATE_CONTRADICTION,
    EXECUTION_CONTRADICTION,
    STRUCTURAL_CONTRADICTION,
    TEMPORAL_CONTRADICTION,
    REPLAY_CONTRADICTION,
})


def check_contradictions(scenario: dict) -> tuple[bool, str | None]:
    """Check for contradiction conditions. Returns (is_contradiction, reason_code).

    Evaluation order is fixed. First contradiction wins.
    """

    action = scenario.get("action", "")
    authority = scenario.get("authority", "")
    policy = scenario.get("policy", "")
    state = scenario.get("state", {})
    flags = scenario.get("flags", {})

    # --- A. Authority contradiction ---
    # Request demands execution but authority is explicitly absent or revoked
    if flags.get("authority_revoked") and action in _MUTATING_ACTIONS:
        return True, AUTHORITY_CONTRADICTION

    # Claims inherited authority where fresh is required
    if flags.get("inherited_authority") and flags.get("fresh_authority_required"):
        return True, AUTHORITY_CONTRADICTION

    # Asserts approval without evidence
    if flags.get("claims_approval") and not authority:
        return True, AUTHORITY_CONTRADICTION

    # --- B. State contradiction ---
    # References state that does not exist
    if flags.get("references_nonexistent_state"):
        return True, STATE_CONTRADICTION

    # Claims impossible state transition
    if flags.get("impossible_prior_state"):
        return True, STATE_CONTRADICTION

    # --- C. Execution contradiction ---
    # Marked NON_EXEC but contains execution request
    if flags.get("marked_non_exec") and flags.get("requests_execution"):
        return True, EXECUTION_CONTRADICTION

    # Smuggles execution inside descriptive language
    if flags.get("execution_in_description"):
        return True, EXECUTION_CONTRADICTION

    # --- D. Structural contradiction ---
    # Missing required fields paired with high-authority action
    if flags.get("missing_critical_fields") and action in _HIGH_RISK_ACTIONS:
        return True, STRUCTURAL_CONTRADICTION

    # --- E. Temporal contradiction ---
    # Stale approval used as present
    if flags.get("stale_approval"):
        return True, TEMPORAL_CONTRADICTION

    # Future authorisation referenced as active
    if flags.get("future_authorisation"):
        return True, TEMPORAL_CONTRADICTION

    # No contradiction found
    return False, None


def sink(scenario_name: str, reason_code: str) -> dict:
    """Emit a fixed non-executing result. The contradiction sink.

    Mandatory behaviour: stop, emit, log. No mutation. No adaptation.
    """
    return {
        "decision": "DENY",
        "reason_code": reason_code,
        "executed": False,
    }


# --- Internal constants ---

_MUTATING_ACTIONS = frozenset({"write", "delete", "deploy", "commit"})
_HIGH_RISK_ACTIONS = frozenset({"delete", "deploy", "commit"})
