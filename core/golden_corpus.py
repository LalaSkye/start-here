"""Golden corpus — the canonical adversarial test surface.

Every implementation must produce identical verdicts for these cases.
If two systems disagree on any case, they are not equivalent.

Categories:
  VALID       — clean packets that should ALLOW
  POLICY      — policy violations that should DENY
  CLOSED      — unknown actions (closed-world DENY)
  MALFORMED   — structurally broken packets
  STALE       — expired authority
  PROOF       — missing or stale proof obligations
  PARADOX     — contradiction sink cases
  REPLAY      — duplicate request IDs
  NEAR_VALID  — almost correct but fatally flawed
"""

from core.conformance import ConformanceCase


def _base_packet(**overrides) -> dict:
    """Build a base valid packet, overriding specific fields."""
    base = {
        "packet_id": "PKT-TEST-001",
        "schema_version": "1.0.0",
        "actor_id": "actor-1",
        "requested_action": "read",
        "object_ref": "/data/report.csv",
        "state_claim": "abc123",
        "authority_claim": {
            "authority_type": "operator",
            "issued_at": 1000,
            "expires_at": 2000,
            "nonce": "n-001",
        },
        "dependencies": [],
        "timestamp": 1500,
        "nonce": "req-n-001",
        "provenance": "test-suite",
        "flags": {},
        "proof_obligations": [
            {"obligation_type": "actor_bound", "claim": "actor-1 bound", "evidence_hash": "e1", "fresh": True},
            {"obligation_type": "action_registered", "claim": "read in registry", "evidence_hash": "e2", "fresh": True},
            {"obligation_type": "policy_version_match", "claim": "v1.0.0", "evidence_hash": "e3", "fresh": True},
        ],
    }
    base.update(overrides)
    return base


def _mutating_packet(**overrides) -> dict:
    """Build a valid mutating packet with full proof obligations."""
    pkt = _base_packet(
        packet_id="PKT-MUT-001",
        requested_action="write",
        authority_claim={
            "authority_type": "admin",
            "issued_at": 1000,
            "expires_at": 2000,
            "nonce": "n-mut-001",
        },
        proof_obligations=[
            {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": True},
            {"obligation_type": "action_registered", "claim": "write in registry", "evidence_hash": "e2", "fresh": True},
            {"obligation_type": "policy_version_match", "claim": "v1.0.0", "evidence_hash": "e3", "fresh": True},
            {"obligation_type": "object_exists", "claim": "object exists", "evidence_hash": "e4", "fresh": True},
            {"obligation_type": "authority_fresh", "claim": "fresh", "evidence_hash": "e5", "fresh": True},
            {"obligation_type": "authority_sufficient", "claim": "admin", "evidence_hash": "e6", "fresh": True},
            {"obligation_type": "state_precondition", "claim": "state valid", "evidence_hash": "e7", "fresh": True},
        ],
    )
    pkt.update(overrides)
    return pkt


# ---------------------------------------------------------------------------
# THE GOLDEN CORPUS
# ---------------------------------------------------------------------------

GOLDEN_CORPUS: list[ConformanceCase] = [

    # === VALID ===
    ConformanceCase(
        case_id="VALID-001-read",
        category="VALID",
        description="Clean read with valid authority and proofs",
        packet_raw=_base_packet(),
        expected_verdict="ALLOW",
        expected_reason="policy_allow",
        expected_executed=True,
    ),
    ConformanceCase(
        case_id="VALID-002-mutating-write",
        category="VALID",
        description="Clean write with admin authority, full proofs",
        packet_raw=_mutating_packet(),
        expected_verdict="ALLOW",
        expected_reason="policy_allow",
        expected_executed=True,
    ),

    # === CLOSED-WORLD ===
    ConformanceCase(
        case_id="CLOSED-001-unknown-action",
        category="CLOSED",
        description="Unknown action type rejected by closed-world rule",
        packet_raw=_base_packet(
            packet_id="PKT-CLOSED-001",
            requested_action="format_disk",
        ),
        expected_verdict="DENY",
        expected_reason="action_unknown",
        expected_executed=False,
    ),

    # === MALFORMED ===
    ConformanceCase(
        case_id="MALFORMED-001-missing-actor",
        category="MALFORMED",
        description="Missing actor_id",
        packet_raw={
            "packet_id": "PKT-MAL-001",
            "requested_action": "read",
            "object_ref": "/data",
            "timestamp": 1500,
            "nonce": "n-1",
        },
        expected_verdict="DENY",
        expected_reason="malformed_packet",
        expected_executed=False,
    ),
    ConformanceCase(
        case_id="MALFORMED-002-empty-dict",
        category="MALFORMED",
        description="Empty dict",
        packet_raw={},
        expected_verdict="DENY",
        expected_reason="malformed_packet",
        expected_executed=False,
    ),
    ConformanceCase(
        case_id="MALFORMED-003-not-dict",
        category="MALFORMED",
        description="Input is a list, not a dict",
        packet_raw={"_wrapped": True},  # Will use [] in runner
        expected_verdict="DENY",
        expected_reason="malformed_packet",
        expected_executed=False,
    ),

    # === STALE AUTHORITY ===
    # Note: expired timestamp on a mutating action hits paradox temporal
    # check before reaching the main authority expiry gate. This is correct:
    # the paradox vector catches temporal contradiction first.
    ConformanceCase(
        case_id="STALE-001-expired-authority",
        category="STALE",
        description="Authority expired — caught by paradox temporal check (timestamp > expires_at)",
        packet_raw=_mutating_packet(
            packet_id="PKT-STALE-001",
            timestamp=3000,  # after expires_at=2000
        ),
        expected_verdict="DENY",
        expected_reason="temporal_contradiction",
        expected_executed=False,
    ),
    ConformanceCase(
        case_id="STALE-002-explicit-stale-flag",
        category="STALE",
        description="Explicit stale_approval flag",
        packet_raw=_base_packet(
            packet_id="PKT-STALE-002",
            flags={"stale_approval": True},
        ),
        expected_verdict="DENY",
        expected_reason="temporal_contradiction",
        expected_executed=False,
    ),

    # === PROOF INCOMPLETE ===
    ConformanceCase(
        case_id="PROOF-001-missing-obligations",
        category="PROOF",
        description="Mutating action with only base proofs (missing mutating proofs)",
        packet_raw=_mutating_packet(
            packet_id="PKT-PROOF-001",
            proof_obligations=[
                {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": True},
                {"obligation_type": "action_registered", "claim": "registered", "evidence_hash": "e2", "fresh": True},
                {"obligation_type": "policy_version_match", "claim": "v1", "evidence_hash": "e3", "fresh": True},
                # Missing: object_exists, authority_fresh, authority_sufficient, state_precondition
            ],
        ),
        expected_verdict="DENY",
        expected_reason="proof_incomplete:authority_fresh,authority_sufficient,object_exists,state_precondition",
        expected_executed=False,
    ),
    ConformanceCase(
        case_id="PROOF-002-stale-proof",
        category="PROOF",
        description="Proof fragment marked as not fresh",
        packet_raw=_base_packet(
            packet_id="PKT-PROOF-002",
            proof_obligations=[
                {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": False},
                {"obligation_type": "action_registered", "claim": "registered", "evidence_hash": "e2", "fresh": True},
                {"obligation_type": "policy_version_match", "claim": "v1", "evidence_hash": "e3", "fresh": True},
            ],
        ),
        expected_verdict="DENY",
        expected_reason="proof_stale:actor_bound",
        expected_executed=False,
    ),

    # === PARADOX (contradiction sink) ===
    ConformanceCase(
        case_id="PARADOX-001-authority-revoked",
        category="PARADOX",
        description="Authority revoked but mutating action requested",
        packet_raw=_mutating_packet(
            packet_id="PKT-PX-001",
            flags={"authority_revoked": True},
        ),
        expected_verdict="DENY",
        expected_reason="authority_contradiction",
        expected_executed=False,
    ),
    ConformanceCase(
        case_id="PARADOX-002-execution-in-nonexec",
        category="PARADOX",
        description="Marked non-exec but requests execution",
        packet_raw=_base_packet(
            packet_id="PKT-PX-002",
            flags={"marked_non_exec": True, "requests_execution": True},
        ),
        expected_verdict="DENY",
        expected_reason="execution_contradiction",
        expected_executed=False,
    ),
    ConformanceCase(
        case_id="PARADOX-003-stale-temporal",
        category="PARADOX",
        description="Stale approval used as current",
        packet_raw=_base_packet(
            packet_id="PKT-PX-003",
            flags={"stale_approval": True},
        ),
        expected_verdict="DENY",
        expected_reason="temporal_contradiction",
        expected_executed=False,
    ),

    # === REPLAY ===
    ConformanceCase(
        case_id="REPLAY-001-duplicate-id",
        category="REPLAY",
        description="Same packet_id as VALID-001 (replayed after first evaluation)",
        packet_raw=_base_packet(
            packet_id="PKT-TEST-001",  # Same as VALID-001
        ),
        expected_verdict="DENY",
        expected_reason="replay_detected",
        expected_executed=False,
    ),

    # === NEAR-VALID (the dangerous ones) ===
    ConformanceCase(
        case_id="NEAR-001-almost-valid-empty-nonce",
        category="NEAR_VALID",
        description="Everything correct except empty nonce",
        packet_raw=_base_packet(
            packet_id="PKT-NEAR-001",
            nonce="",
        ),
        expected_verdict="DENY",
        expected_reason="malformed_packet",
        expected_executed=False,
    ),
]
