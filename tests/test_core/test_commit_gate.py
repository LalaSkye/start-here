"""Protected invariants — commit gate.

These are the structural guarantees of the commit boundary.
If any of these fail, the system permits ungoverned state mutation.

Every test here maps to the canonical freeze:
    "No valid Decision Record at commit time = no state mutation."

Test naming convention:
    test_CG{N}_{invariant_name}
    CG = Commit Gate
    N  = invariant number

v1.1 — Tests updated for immutable DecisionRecord + CommittedRecord.
        The gate never mutates the record. State binding lives on
        CommitResult.committed (a CommittedRecord).
"""

from core.evaluator import Evaluator
from core.canonical import Packet
from core.decision_record import DecisionRecord
from core.commit_gate import (
    commit_gate, CommitResult, CommittedRecord, DenialCode,
    authority_sufficient, AUTHORITY_SCOPE,
)
from core.algebra import Verdict
from core.version import SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _valid_mutating_packet(packet_id="PKT-CG-MUT-001", action="write"):
    """A packet that the evaluator will ALLOW."""
    return {
        "packet_id": packet_id,
        "schema_version": "1.0.0",
        "actor_id": "actor-1",
        "requested_action": action,
        "object_ref": "/data/file",
        "state_claim": "abc",
        "authority_claim": {
            "authority_type": "admin",
            "issued_at": 100,
            "expires_at": 200,
            "nonce": "n1",
        },
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


def _valid_read_packet(packet_id="PKT-CG-READ-001"):
    return {
        "packet_id": packet_id,
        "schema_version": "1.0.0",
        "actor_id": "actor-1",
        "requested_action": "read",
        "object_ref": "/data/file",
        "state_claim": "abc",
        "authority_claim": {
            "authority_type": "operator",
            "issued_at": 100,
            "expires_at": 200,
            "nonce": "n1",
        },
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


def _evaluate_and_get(raw_packet):
    """Run the evaluator and return (record, packet)."""
    ev = Evaluator()
    record = ev.evaluate(raw_packet)
    packet = Packet.from_dict(raw_packet)
    return record, packet


STATE_BEFORE = "state_hash_before_abc123"
STATE_AFTER = "state_hash_after_def456"


# =========================================================================
# CG1: No decision record → no commit
# =========================================================================

def test_CG1_no_record_no_commit():
    """Passing None as the record must deny the commit."""
    raw = _valid_mutating_packet()
    packet = Packet.from_dict(raw)
    result = commit_gate(None, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.NO_RECORD
    assert result.committed is None
    assert result.state_after_hash is None


# =========================================================================
# CG2: Verdict != ALLOW → no commit
# =========================================================================

def test_CG2_non_allow_verdict_no_commit():
    """A DENY record must not permit commit even if all other fields match."""
    ev = Evaluator()
    raw = _valid_mutating_packet(packet_id="PKT-CG2")
    raw["requested_action"] = "format_disk"  # unknown → DENY
    record = ev.evaluate(raw)
    assert record.verdict == Verdict.DENY.value

    valid_raw = _valid_mutating_packet(packet_id="PKT-CG2-VALID")
    valid_packet = Packet.from_dict(valid_raw)
    result = commit_gate(record, valid_packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.VERDICT_NOT_ALLOW


# =========================================================================
# CG3: Hash mismatch → no commit
# =========================================================================

def test_CG3_hash_mismatch_no_commit():
    """Record's packet_hash must match the packet being committed."""
    record_raw = _valid_mutating_packet(packet_id="PKT-CG3-A")
    record, _ = _evaluate_and_get(record_raw)
    assert record.verdict == Verdict.ALLOW.value

    different_raw = _valid_mutating_packet(packet_id="PKT-CG3-B")
    different_packet = Packet.from_dict(different_raw)

    result = commit_gate(record, different_packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.HASH_MISMATCH


# =========================================================================
# CG4: Valid ALLOW record + matching packet → commit permitted
# =========================================================================

def test_CG4_valid_allow_permits_commit():
    """The happy path: valid record + matching packet = commit allowed."""
    raw = _valid_mutating_packet(packet_id="PKT-CG4")
    record, packet = _evaluate_and_get(raw)
    assert record.verdict == Verdict.ALLOW.value

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is True
    assert result.decision_id == record.decision_id
    assert result.state_after_hash == STATE_AFTER
    assert result.committed is not None
    assert isinstance(result.committed, CommittedRecord)


# =========================================================================
# CG5: State is bound via CommittedRecord (record is NOT mutated)
# =========================================================================

def test_CG5_state_bound_via_committed_record():
    """After commit, state binding lives on CommittedRecord, not on the
    DecisionRecord.  The DecisionRecord must remain untouched."""
    raw = _valid_mutating_packet(packet_id="PKT-CG5")
    record, packet = _evaluate_and_get(raw)

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is True

    # State binding is on the CommittedRecord
    assert result.committed.state_after_hash == STATE_AFTER
    assert result.committed.state_before_hash == STATE_BEFORE
    assert result.committed.decision_id == record.decision_id

    # DecisionRecord was NOT mutated (it has no state_after_hash attribute
    # — that was removed in v1.2 to enforce immutability)
    assert not hasattr(record, "state_after_hash") or \
        getattr(record, "state_after_hash", None) is None


# =========================================================================
# CG6: decision_id is deterministic
# =========================================================================

def test_CG6_decision_id_deterministic():
    """Same inputs → same decision_id.  Replay produces identical id."""
    raw_a = _valid_mutating_packet(packet_id="PKT-CG6")
    raw_b = _valid_mutating_packet(packet_id="PKT-CG6")

    ev_a = Evaluator()
    ev_b = Evaluator()
    rec_a = ev_a.evaluate(raw_a)
    rec_b = ev_b.evaluate(raw_b)

    assert rec_a.decision_id == rec_b.decision_id
    assert rec_a.decision_id != ""


# =========================================================================
# CG7: decision_id changes when verdict changes
# =========================================================================

def test_CG7_decision_id_changes_with_verdict():
    """Different verdicts for different inputs → different decision_ids."""
    ev = Evaluator()
    allow_raw = _valid_mutating_packet(packet_id="PKT-CG7-A")
    deny_raw = _valid_mutating_packet(packet_id="PKT-CG7-B")
    deny_raw["requested_action"] = "format_disk"

    rec_allow = ev.evaluate(allow_raw)
    rec_deny = ev.evaluate(deny_raw)

    assert rec_allow.decision_id != rec_deny.decision_id


# =========================================================================
# CG8 (Gap 1): Operator cannot commit high-risk action
# =========================================================================

def test_CG8_operator_cannot_deploy():
    """An operator authority must be denied at the commit gate for deploy."""
    raw = _valid_mutating_packet(packet_id="PKT-CG8")
    raw["requested_action"] = "deploy"
    raw["authority_claim"]["authority_type"] = "operator"

    record, packet = _evaluate_and_get(raw)

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.AUTHORITY_SCOPE


# =========================================================================
# CG9 (Gap 1): Reviewer cannot write
# =========================================================================

def test_CG9_reviewer_cannot_write():
    """A reviewer authority must be denied at commit for write."""
    raw = _valid_mutating_packet(packet_id="PKT-CG9")
    raw["requested_action"] = "write"
    raw["authority_claim"]["authority_type"] = "reviewer"

    record, packet = _evaluate_and_get(raw)

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.AUTHORITY_SCOPE


# =========================================================================
# CG10 (Gap 1): Admin can do everything
# =========================================================================

def test_CG10_admin_can_deploy():
    """Admin authority is sufficient for high-risk actions."""
    raw = _valid_mutating_packet(packet_id="PKT-CG10")
    raw["requested_action"] = "deploy"
    raw["authority_claim"]["authority_type"] = "admin"

    record, packet = _evaluate_and_get(raw)
    assert record.verdict == Verdict.ALLOW.value

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is True


# =========================================================================
# CG11: Read actions bypass authority scope (no mutation)
# =========================================================================

def test_CG11_read_skips_authority_scope():
    """Read actions don't mutate state — reviewer is fine."""
    raw = _valid_read_packet(packet_id="PKT-CG11")
    record, packet = _evaluate_and_get(raw)
    assert record.verdict == Verdict.ALLOW.value

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is True


# =========================================================================
# CG12: Missing decision_id → no commit
# =========================================================================

def test_CG12_missing_decision_id_no_commit():
    """A record with empty decision_id must be denied."""
    raw = _valid_mutating_packet(packet_id="PKT-CG12")
    record, packet = _evaluate_and_get(raw)

    # Construct a record with empty decision_id
    # (We can't mutate the frozen record, so we build a broken one directly)
    broken = DecisionRecord(
        packet_hash=record.packet_hash,
        schema_version=record.schema_version,
        verdict=record.verdict,
        reason_code=record.reason_code,
        proof_status=record.proof_status,
        paradox_class=record.paradox_class,
        state_change=record.state_change,
        trace=record.trace,
        executed=record.executed,
        decision_id="",  # will be auto-computed — override after
    )
    # Force empty decision_id on frozen object
    object.__setattr__(broken, "decision_id", "")

    result = commit_gate(broken, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.MALFORMED_RECORD


# =========================================================================
# CG13: Schema mismatch → no commit
# =========================================================================

def test_CG13_schema_mismatch_no_commit():
    """Record with wrong schema version must be denied at gate."""
    raw = _valid_mutating_packet(packet_id="PKT-CG13")
    record, packet = _evaluate_and_get(raw)

    # Build a record with mismatched schema
    bad_schema = DecisionRecord(
        packet_hash=record.packet_hash,
        schema_version="99.0.0",
        verdict=record.verdict,
        reason_code=record.reason_code,
        proof_status=record.proof_status,
        paradox_class=record.paradox_class,
        state_change=record.state_change,
        trace=record.trace,
        executed=record.executed,
    )

    result = commit_gate(bad_schema, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.SCHEMA_MISMATCH


# =========================================================================
# CG14: executed=False → no commit (even if verdict is ALLOW)
# =========================================================================

def test_CG14_not_executed_no_commit():
    """A record with executed=False must not pass the gate."""
    raw = _valid_mutating_packet(packet_id="PKT-CG14")
    record, packet = _evaluate_and_get(raw)
    assert record.verdict == Verdict.ALLOW.value

    # Build a record with executed=False
    not_exec = DecisionRecord(
        packet_hash=record.packet_hash,
        schema_version=record.schema_version,
        verdict=record.verdict,
        reason_code=record.reason_code,
        proof_status=record.proof_status,
        paradox_class=record.paradox_class,
        state_change=record.state_change,
        trace=record.trace,
        executed=False,
    )

    result = commit_gate(not_exec, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.NOT_EXECUTED


# =========================================================================
# CG15: Authority freshness re-checked at gate (belt + suspenders)
# =========================================================================

def test_CG15_stale_authority_at_gate():
    """Even if someone forged an ALLOW record, stale authority at commit = denied."""
    raw_expired = _valid_mutating_packet(packet_id="PKT-CG15-EXP")
    raw_expired["timestamp"] = 9999  # way past expires_at=200

    packet_exp = Packet.from_dict(raw_expired)
    forged = DecisionRecord(
        packet_hash=packet_exp.canonical_hash(),
        schema_version=SCHEMA_VERSION,
        verdict=Verdict.ALLOW.value,
        reason_code="policy_allow",
        proof_status="PASSED",
        paradox_class=None,
        state_change="NONE",
        trace=("FORGED",),
        executed=True,
    )
    result = commit_gate(forged, packet_exp, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is False
    assert result.denial_code == DenialCode.AUTHORITY_STALE


# =========================================================================
# CG16: authority_sufficient function unit tests
# =========================================================================

def test_CG16_authority_scope_table():
    """Verify the authority scope mapping is correct."""
    for action in ("read", "write", "delete", "deploy", "commit"):
        assert authority_sufficient(action, "admin") is True

    assert authority_sufficient("read", "operator") is True
    assert authority_sufficient("write", "operator") is True
    assert authority_sufficient("delete", "operator") is False
    assert authority_sufficient("deploy", "operator") is False
    assert authority_sufficient("commit", "operator") is False

    assert authority_sufficient("read", "reviewer") is True
    assert authority_sufficient("write", "reviewer") is False
    assert authority_sufficient("delete", "reviewer") is False

    assert authority_sufficient("format_disk", "admin") is False
    assert authority_sufficient("read", "hacker") is False


# =========================================================================
# CG17: DecisionRecord is actually frozen (immutability invariant)
# =========================================================================

def test_CG17_decision_record_is_frozen():
    """DecisionRecord must reject attribute assignment after construction."""
    raw = _valid_mutating_packet(packet_id="PKT-CG17")
    record, _ = _evaluate_and_get(raw)

    try:
        record.verdict = "DENY"
        assert False, "DecisionRecord should be frozen but accepted mutation"
    except AttributeError:
        pass  # correct — frozen dataclass rejects mutation


# =========================================================================
# CG18: CommittedRecord is frozen
# =========================================================================

def test_CG18_committed_record_is_frozen():
    """CommittedRecord must reject attribute assignment after construction."""
    raw = _valid_mutating_packet(packet_id="PKT-CG18")
    record, packet = _evaluate_and_get(raw)
    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is True

    try:
        result.committed.state_after_hash = "tampered"
        assert False, "CommittedRecord should be frozen but accepted mutation"
    except AttributeError:
        pass  # correct


# =========================================================================
# CG19: Gate does not mutate the DecisionRecord
# =========================================================================

def test_CG19_gate_does_not_mutate_record():
    """The commit gate must not modify the DecisionRecord in any way."""
    raw = _valid_mutating_packet(packet_id="PKT-CG19")
    record, packet = _evaluate_and_get(raw)

    # Snapshot the record's dict before the gate call
    before = record.to_dict()

    result = commit_gate(record, packet, STATE_BEFORE, STATE_AFTER)
    assert result.permitted is True

    # Record must be identical after the gate call
    after = record.to_dict()
