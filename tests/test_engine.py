"""Engine tests. One test per decision path."""

from src.engine import decide


def s(action="read", authority="valid", policy="allowed"):
    return {"actor": "test", "action": action, "target": "/t", "authority": authority, "policy": policy}


# --- ALLOW ---

def test_allow_valid():
    assert decide(s())["decision"] == "ALLOW"
    assert decide(s())["executed"] is True


def test_allow_read():
    assert decide(s("read"))["decision"] == "ALLOW"


def test_allow_write():
    assert decide(s("write"))["decision"] == "ALLOW"


# --- DENY ---

def test_deny_prohibited():
    r = decide(s("deploy_production"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "action_prohibited"


def test_deny_unknown_action():
    r = decide(s("escalate_privileges"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "action_unknown"


def test_deny_policy_forbidden():
    r = decide(s(policy="forbidden"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "policy_violation"


def test_deny_authority_missing():
    r = decide(s(authority=""))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "authority_missing"


# --- ESCALATE ---

def test_escalate_authority_ambiguous():
    r = decide(s(authority="unknown"))
    assert r["decision"] == "ESCALATE"
    assert r["reason_code"] == "authority_ambiguous"


# --- PROPERTIES ---

def test_executed_only_on_allow():
    for action in ["read", "write", "delete", "deploy_production", "xyz"]:
        r = decide(s(action, authority="valid"))
        if r["decision"] == "ALLOW":
            assert r["executed"] is True
        else:
            assert r["executed"] is False


def test_prohibited_before_policy():
    """Prohibited check runs before policy check."""
    r = decide(s("deploy_production", policy="allowed"))
    assert r["decision"] == "DENY"
    assert r["reason_code"] == "action_prohibited"


def test_deterministic():
    r1 = decide(s())
    r2 = decide(s())
    assert r1 == r2
