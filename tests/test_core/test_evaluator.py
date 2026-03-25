"""Tests for the strict evaluation pipeline."""

from core.evaluator import Evaluator
from core.algebra import Verdict
from core.reason_codes import ReasonCode


def _valid_read(packet_id="PKT-EV-001"):
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


def test_valid_packet_allows():
    ev = Evaluator()
    r = ev.evaluate(_valid_read())
    assert r.verdict == Verdict.ALLOW.value
    assert r.executed is True
    assert "PARSE_OK" in r.trace
    assert "SCHEMA_OK" in r.trace
    assert "PROOF_OK" in r.trace


def test_malformed_denies():
    ev = Evaluator()
    r = ev.evaluate({})
    assert r.verdict == Verdict.DENY.value
    assert r.reason_code == ReasonCode.MALFORMED_PACKET.value


def test_unknown_field_denies():
    ev = Evaluator()
    pkt = _valid_read(packet_id="PKT-UF-001")
    pkt["injected_field"] = "malicious"
    r = ev.evaluate(pkt)
    assert r.verdict == Verdict.DENY.value
    assert r.reason_code == ReasonCode.UNKNOWN_FIELD.value


def test_schema_mismatch_denies():
    ev = Evaluator()
    pkt = _valid_read(packet_id="PKT-SM-001")
    pkt["schema_version"] = "99.0.0"
    r = ev.evaluate(pkt)
    assert r.verdict == Verdict.DENY.value
    assert r.reason_code == ReasonCode.SCHEMA_MISMATCH.value


def test_replay_denies():
    ev = Evaluator()
    ev.evaluate(_valid_read("PKT-RP-001"))
    r = ev.evaluate(_valid_read("PKT-RP-001"))
    assert r.verdict == Verdict.DENY.value
    assert r.reason_code == ReasonCode.REPLAY_DETECTED.value


def test_trace_always_present():
    ev = Evaluator()
    r = ev.evaluate(_valid_read("PKT-TR-001"))
    assert len(r.trace) > 0
    assert any("VERDICT" in t for t in r.trace)


def test_records_accumulate():
    ev = Evaluator()
    ev.evaluate(_valid_read("PKT-R1"))
    ev.evaluate(_valid_read("PKT-R2"))
    ev.evaluate({})
    assert len(ev.get_records()) == 3


def test_decision_record_to_dict():
    ev = Evaluator()
    r = ev.evaluate(_valid_read("PKT-DICT-001"))
    d = r.to_dict()
    assert "packet_hash" in d
    assert "schema_version" in d
    assert "verdict" in d
    assert "trace" in d
    assert d["state_change"] == "NONE"
