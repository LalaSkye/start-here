"""Tests for proof-carrying packet obligations."""

from core.canonical import Packet
from core.proof import (
    check_proof, required_obligations, proof_denial_reason,
    ObligationType, BASE_OBLIGATIONS, MUTATING_OBLIGATIONS,
)


def _packet(action="read", proofs=None, deps=None):
    raw = {
        "packet_id": "PKT-P-001",
        "actor_id": "actor-1",
        "requested_action": action,
        "object_ref": "/data",
        "state_claim": "abc",
        "authority_claim": {"authority_type": "admin", "issued_at": 100, "expires_at": 200, "nonce": "n1"},
        "dependencies": deps or [],
        "timestamp": 150,
        "nonce": "n1",
        "provenance": "test",
        "proof_obligations": proofs or [],
    }
    return Packet.from_dict(raw)


def test_read_requires_base_obligations():
    required = required_obligations(_packet("read"))
    assert ObligationType.ACTOR_BOUND in required
    assert ObligationType.ACTION_REGISTERED in required


def test_write_requires_mutating_obligations():
    required = required_obligations(_packet("write"))
    assert ObligationType.OBJECT_EXISTS in required
    assert ObligationType.AUTHORITY_FRESH in required
    assert ObligationType.STATE_PRECONDITION in required


def test_complete_proof_for_read():
    p = _packet("read", proofs=[
        {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": True},
        {"obligation_type": "action_registered", "claim": "registered", "evidence_hash": "e2", "fresh": True},
        {"obligation_type": "policy_version_match", "claim": "v1", "evidence_hash": "e3", "fresh": True},
    ])
    result = check_proof(p)
    assert result.complete is True
    assert result.admissible is True
    assert proof_denial_reason(result) is None


def test_missing_proof_for_read():
    p = _packet("read", proofs=[])
    result = check_proof(p)
    assert result.complete is False
    assert len(result.missing) > 0
    reason = proof_denial_reason(result)
    assert reason is not None
    assert reason.startswith("proof_incomplete:")


def test_stale_proof_denied():
    p = _packet("read", proofs=[
        {"obligation_type": "actor_bound", "claim": "bound", "evidence_hash": "e1", "fresh": False},
        {"obligation_type": "action_registered", "claim": "registered", "evidence_hash": "e2", "fresh": True},
        {"obligation_type": "policy_version_match", "claim": "v1", "evidence_hash": "e3", "fresh": True},
    ])
    result = check_proof(p)
    assert result.admissible is False
    assert ObligationType.ACTOR_BOUND in result.stale


def test_dependency_obligations_added():
    p = _packet("read", deps=[{"dep_id": "d1", "satisfied": True}])
    required = required_obligations(p)
    assert ObligationType.DEPENDENCY_SATISFIED in required
