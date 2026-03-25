from src.engine import GovernanceEngine


def _scenario(action="read", authority="valid", policy="allowed", request_id="REQ-TEST"):
    return {
        "name": "test",
        "actor": "user",
        "action": action,
        "target": "file",
        "authority": authority,
        "policy": policy,
        "request_id": request_id,
    }


def test_allow():
    engine = GovernanceEngine()
    r = engine.decide(_scenario())
    assert r["decision"] == "ALLOW"
    assert r["executed"] is True


def test_deny_policy_violation():
    engine = GovernanceEngine()
    r = engine.decide(_scenario(policy="forbidden"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "policy_violation"


def test_deny_unknown_action():
    engine = GovernanceEngine()
    r = engine.decide(_scenario(action="format_disk"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "unknown_action"


def test_escalate_authority_ambiguous():
    engine = GovernanceEngine()
    r = engine.decide(_scenario(authority="unknown"))
    assert r["decision"] == "ESCALATE"
    assert r["reason_code"] == "authority_ambiguous"
    assert r["executed"] is False


def test_malformed_empty_authority():
    engine = GovernanceEngine()
    r = engine.decide(_scenario(authority=""))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "malformed_input"


def test_malformed_missing_field():
    engine = GovernanceEngine()
    r = engine.decide({"actor": "user", "action": "read"})
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "malformed_input"


def test_replay_detected():
    engine = GovernanceEngine()
    engine.decide(_scenario(request_id="REQ-REPLAY"))
    r = engine.decide(_scenario(request_id="REQ-REPLAY"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "replay_detected"


def test_default_deny():
    engine = GovernanceEngine()
    r = engine.decide(_scenario(authority="valid", policy="maybe"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "default_deny"


def test_executed_only_on_allow():
    engine = GovernanceEngine()
    for action in ["read", "write", "delete", "format_disk"]:
        r = engine.decide(_scenario(action=action, request_id=f"REQ-{action}"))
        if r["decision"] == "ALLOW":
            assert r["executed"] is True
        else:
            assert r["executed"] is False


def test_event_log_grows():
    engine = GovernanceEngine()
    engine.decide(_scenario(request_id="REQ-A"))
    engine.decide(_scenario(request_id="REQ-B"))
    log = engine.export_event_log()
    assert len(log["events"]) == 2


def test_event_log_hash_chain():
    engine = GovernanceEngine()
    engine.decide(_scenario(request_id="REQ-C"))
    engine.decide(_scenario(request_id="REQ-D"))
    events = engine.export_event_log()["events"]
    assert events[0]["prev_hash"] == "GENESIS"
    assert events[1]["prev_hash"] == events[0]["event_hash"]


def test_deterministic():
    e1 = GovernanceEngine()
    e2 = GovernanceEngine()
    r1 = e1.decide(_scenario(request_id="REQ-DET"))
    r2 = e2.decide(_scenario(request_id="REQ-DET"))
    assert r1 == r2
