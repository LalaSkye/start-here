"""Closed reason-code registry.

Single source of truth. All modules import from here.
No module may invent its own reason codes.

If a code is not in this enum, it is not a valid reason code.
"""

from enum import Enum


class ReasonCode(str, Enum):
    """Bounded, finite set of reason codes. Closed enum."""

    # --- ALLOW ---
    POLICY_ALLOW = "policy_allow"

    # --- DENY: structural ---
    MALFORMED_PACKET = "malformed_packet"
    UNKNOWN_FIELD = "unknown_field"
    SCHEMA_MISMATCH = "schema_mismatch"

    # --- DENY: closed-world ---
    ACTION_UNKNOWN = "action_unknown"

    # --- DENY: authority ---
    AUTHORITY_MISSING = "authority_missing"

    # --- DENY: policy ---
    POLICY_VIOLATION = "policy_violation"

    # --- DENY: replay ---
    REPLAY_DETECTED = "replay_detected"

    # --- DENY: proof ---
    PROOF_INCOMPLETE = "proof_incomplete"
    PROOF_STALE = "proof_stale"
    PROOF_INADMISSIBLE = "proof_inadmissible"

    # --- DENY: paradox (contradiction sink) ---
    AUTHORITY_CONTRADICTION = "authority_contradiction"
    STATE_CONTRADICTION = "state_contradiction"
    EXECUTION_CONTRADICTION = "execution_contradiction"
    STRUCTURAL_CONTRADICTION = "structural_contradiction"
    TEMPORAL_CONTRADICTION = "temporal_contradiction"
    REPLAY_CONTRADICTION = "replay_contradiction"

    # --- ESCALATE ---
    AUTHORITY_EXPIRED = "authority_expired"
    AUTHORITY_UNRECOGNISED = "authority_unrecognised"
    AUTHORITY_INSUFFICIENT = "authority_insufficient"
    STATE_AMBIGUOUS = "state_ambiguous"

    # --- FALLBACK ---
    DEFAULT_DENY = "default_deny"
