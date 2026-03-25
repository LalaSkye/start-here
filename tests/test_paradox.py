"""Paradox Vector tests. Each maps to a contradiction class from the spec."""

from src.paradox import (
    check_contradictions,
    sink,
    AUTHORITY_CONTRADICTION,
    STATE_CONTRADICTION,
    EXECUTION_CONTRADICTION,
    STRUCTURAL_CONTRADICTION,
    TEMPORAL_CONTRADICTION,
)


def _scenario(action="read", authority="valid", flags=None):
    return {
        "action": action,
        "authority": authority,
        "policy": "allowed",
        "state": {},
        "flags": flags or {},
    }


# --- Authority contradictions ---

def test_authority_revoked_on_mutating_action():
    is_c, code = check_contradictions(_scenario("write", flags={"authority_revoked": True}))
    assert is_c is True
    assert code == AUTHORITY_CONTRADICTION


def test_inherited_where_fresh_required():
    is_c, code = check_contradictions(_scenario(flags={
        "inherited_authority": True,
        "fresh_authority_required": True,
    }))
    assert is_c is True
    assert code == AUTHORITY_CONTRADICTION


def test_claims_approval_without_authority():
    is_c, code = check_contradictions(_scenario(authority="", flags={"claims_approval": True}))
    assert is_c is True
    assert code == AUTHORITY_CONTRADICTION


# --- State contradictions ---

def test_nonexistent_state():
    is_c, code = check_contradictions(_scenario(flags={"references_nonexistent_state": True}))
    assert is_c is True
    assert code == STATE_CONTRADICTION


def test_impossible_prior_state():
    is_c, code = check_contradictions(_scenario(flags={"impossible_prior_state": True}))
    assert is_c is True
    assert code == STATE_CONTRADICTION


# --- Execution contradictions ---

def test_non_exec_with_execution_request():
    is_c, code = check_contradictions(_scenario(flags={
        "marked_non_exec": True,
        "requests_execution": True,
    }))
    assert is_c is True
    assert code == EXECUTION_CONTRADICTION


def test_execution_smuggled_in_description():
    is_c, code = check_contradictions(_scenario(flags={"execution_in_description": True}))
    assert is_c is True
    assert code == EXECUTION_CONTRADICTION


# --- Structural contradictions ---

def test_missing_fields_on_high_risk():
    is_c, code = check_contradictions(_scenario("delete", flags={"missing_critical_fields": True}))
    assert is_c is True
    assert code == STRUCTURAL_CONTRADICTION


# --- Temporal contradictions ---

def test_stale_approval():
    is_c, code = check_contradictions(_scenario(flags={"stale_approval": True}))
    assert is_c is True
    assert code == TEMPORAL_CONTRADICTION


def test_future_authorisation():
    is_c, code = check_contradictions(_scenario(flags={"future_authorisation": True}))
    assert is_c is True
    assert code == TEMPORAL_CONTRADICTION


# --- Clean path (no contradiction) ---

def test_clean_input_no_contradiction():
    is_c, code = check_contradictions(_scenario())
    assert is_c is False
    assert code is None


# --- Sink output ---

def test_sink_output_shape():
    result = sink("test_scenario", AUTHORITY_CONTRADICTION)
    assert result["decision"] == "DENY"
    assert result["reason_code"] == AUTHORITY_CONTRADICTION
    assert result["executed"] is False


def test_sink_never_executes():
    """No contradiction code may produce executed=True."""
    from src.paradox import ALL_CONTRADICTION_CODES
    for code in ALL_CONTRADICTION_CODES:
        result = sink("test", code)
        assert result["executed"] is False, f"{code} produced executed=True"
