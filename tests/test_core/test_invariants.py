"""Protected invariants — the bulkhead.

These are the non-negotiable properties of the system.
If any of these fail, the implementation is broken. Full stop.

Every assertion here is a structural guarantee, not a feature test.
"""

from core.evaluator import Evaluator
from core.algebra import Verdict


def _valid_read_packet(packet_id="PKT-INV-001"):
    return {
        "packet_id": packet_id,
        "schema_version": "1.0.0",
        "actor_id": "actor-1",
        "requested_action": "read",
        "object_ref": "/data/file",
        "state_claim": "abc",
        "authority_claim": {"authority_type": "operator", "issued_at": 100, "expires_at": 200, "nonce": "n1"},
        "dependencies": [],
        "timestamp": 150,
        "nonce": "n1",
        "provenance": "test",
        "proof_obligations": [
            {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": True},
            {"obligation_type": "action_registered", "claim": "registered", "evidence_hash": "e2", "fresh": True},
            {"obligation_type": "policy_version_match", "claim": "v1", "evidence_hash": "e3", "fresh": True},
        ],
    }


def _mutating_packet(packet_id="PKT-INV-MUT-001", action="write"):
    return {
        "packet_id": packet_id,
        "schema_version": "1.0.0",
        "actor_id": "actor-1",
        "requested_action": action,
        "object_ref": "/data/file",
        "state_claim": "abc",
        "authority_claim": {"authority_type": "admin", "issued_at": 100, "expires_at": 200, "nonce": "n1"},
        "dependencies": [],
        "timestamp": 150,
        "nonce": "n1",
        "provenance": "test",
        "proof_obligations": [
            {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": True},
            {"obligation_type": "action_registered", "claim": "registered", "evidence_hash": "e2", "fresh": True},
            {"obligation_type": "policy_version_match", "claim": "v1", "evidence_hash": "e3", "fresh": True},
            {"obligation_type": "object_exists", "claim": "exists", "evidence_hash": "e4", "fresh": True},
            {"obligation_type": "authority_fresh", "claim": "fresh", "evidence_hash": "e5", "fresh": True},
            {"obligation_type": "authority_sufficient", "claim": "admin", "evidence_hash": "e6", "fresh": True},
            {"obligation_type": "state_precondition", "claim": "valid", "evidence_hash": "e7", "fresh": True},
        ],
    }


# === INVARIANT 1: Contradiction never executes ===

def test_contradiction_never_executes():
    """No contradiction path may produce executed=True."""
    ev = Evaluator()
    for flag_set in [
        {"authority_revoked": True},
        {"inherited_authority": True, "fresh_authority_required": True},
        {"references_nonexistent_state": True},
        {"marked_non_exec": True, "requests_execution": True},
        {"stale_approval": True},
        {"future_authorisation": True},
    ]:
        pkt = _mutating_packet(packet_id=f"PKT-C-{hash(str(flag_set))}")
        pkt["flags"] = flag_set
        record = ev.evaluate(pkt)
        assert record.executed is False, f"Contradiction executed with flags: {flag_set}"
        assert record.state_change == "NONE", f"Contradiction mutated state with flags: {flag_set}"


# === INVARIANT 2: Malformed never mutates state ===

def test_malformed_never_mutates():
    """No malformed packet may cause state mutation."""
    ev = Evaluator()
    for raw in [{}, {"packet_id": ""}, {"garbage": True}, None]:
        if raw is None:
            raw = {}
        record = ev.evaluate(raw)
        assert record.executed is False
        assert record.state_change == "NONE"


# === INVARIANT 3: Stale authority never allows mutation ===

def test_stale_authority_never_allows_mutation():
    """Expired authority on mutating action must not ALLOW."""
    ev = Evaluator()
    pkt = _mutating_packet(packet_id="PKT-STALE-INV")
    pkt["timestamp"] = 9999  # way past expires_at=200
    record = ev.evaluate(pkt)
    assert record.verdict != Verdict.ALLOW.value
    assert record.executed is False


# === INVARIANT 4: Unknown action never executes ===

def test_unknown_action_never_executes():
    """Action not in the registry must never produce execution."""
    ev = Evaluator()
    pkt = _valid_read_packet(packet_id="PKT-UNK-INV")
    pkt["requested_action"] = "format_disk"
    record = ev.evaluate(pkt)
    assert record.verdict == Verdict.DENY.value
    assert record.executed is False


# === INVARIANT 5: Replay never executes ===

def test_replay_never_executes():
    """Replayed packet_id must be denied."""
    ev = Evaluator()
    pkt = _valid_read_packet(packet_id="PKT-REPLAY-INV")
    r1 = ev.evaluate(pkt)
    assert r1.verdict == Verdict.ALLOW.value  # first time is fine

    r2 = ev.evaluate(pkt)  # second time is replay
    assert r2.verdict == Verdict.DENY.value
    assert r2.executed is False


# === INVARIANT 6: Proof failure never falls through to ALLOW ===

def test_proof_failure_never_allows():
    """Missing proof obligations must block, not fall through."""
    ev = Evaluator()
    pkt = _mutating_packet(packet_id="PKT-PROOF-INV")
    pkt["proof_obligations"] = []  # no proofs at all
    record = ev.evaluate(pkt)
    assert record.verdict != Verdict.ALLOW.value
    assert record.executed is False


# === INVARIANT 7: Schema mismatch is denied ===

def test_schema_mismatch_denied():
    """Wrong schema version must be denied outright."""
    ev = Evaluator()
    pkt = _valid_read_packet(packet_id="PKT-SCHEMA-INV")
    pkt["schema_version"] = "99.0.0"
    record = ev.evaluate(pkt)
    assert record.verdict == Verdict.DENY.value
    assert record.executed is False


# === INVARIANT 8: Unknown fields rejected ===

def test_unknown_fields_rejected():
    """Packets with unknown top-level fields must be denied."""
    ev = Evaluator()
    pkt = _valid_read_packet(packet_id="PKT-FIELD-INV")
    pkt["secret_backdoor"] = "please_execute"
    record = ev.evaluate(pkt)
    assert record.verdict == Verdict.DENY.value
    assert record.executed is False


# === INVARIANT 9: Every record has a trace ===

def test_every_record_has_trace():
    """Every decision record must contain a non-empty trace."""
    ev = Evaluator()
    for pkt in [_valid_read_packet("PKT-T1"), {}, _mutating_packet("PKT-T2")]:
        record = ev.evaluate(pkt)
        assert len(record.trace) > 0, f"Empty trace for verdict {record.verdict}"


# === INVARIANT 10: ALLOW is the only executable verdict ===

def test_only_allow_executes():
    """Only ALLOW may have executed=True. All others must be False."""
    ev = Evaluator()
    pkt = _valid_read_packet("PKT-EXEC-INV")
    record = ev.evaluate(pkt)
    if record.verdict == Verdict.ALLOW.value:
        assert record.executed is True
    else:
        assert record.executed is False
