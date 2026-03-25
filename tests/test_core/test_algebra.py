"""Tests for the admissibility algebra."""

from core.algebra import (
    Verdict, Actor, Action, Object, Authority, StateSnapshot,
    Dependency, ForbiddenTransition, FORBIDDEN_TRANSITIONS,
    combine_verdicts, is_admissible, may_execute, VERDICT_ORDER,
)
import pytest


def test_verdict_only_allow_is_executable():
    assert Verdict.ALLOW in Verdict.executable()
    assert Verdict.DENY not in Verdict.executable()
    assert Verdict.HOLD not in Verdict.executable()
    assert Verdict.ESCALATE not in Verdict.executable()


def test_verdict_blocking_set():
    blocking = Verdict.blocking()
    assert Verdict.DENY in blocking
    assert Verdict.HOLD in blocking
    assert Verdict.ESCALATE in blocking
    assert Verdict.ALLOW not in blocking


def test_combine_verdicts_most_restrictive():
    assert combine_verdicts(Verdict.ALLOW, Verdict.DENY) == Verdict.DENY
    assert combine_verdicts(Verdict.ALLOW, Verdict.HOLD) == Verdict.HOLD
    assert combine_verdicts(Verdict.HOLD, Verdict.ESCALATE) == Verdict.ESCALATE
    assert combine_verdicts(Verdict.ALLOW, Verdict.ALLOW) == Verdict.ALLOW


def test_combine_empty_raises():
    with pytest.raises(ValueError):
        combine_verdicts()


def test_is_admissible():
    assert is_admissible(Verdict.ALLOW) is True
    assert is_admissible(Verdict.DENY) is False


def test_may_execute():
    assert may_execute(Verdict.ALLOW) is True
    assert may_execute(Verdict.DENY) is False
    assert may_execute(Verdict.HOLD) is False
    assert may_execute(Verdict.ESCALATE) is False


def test_actor_rejects_empty():
    with pytest.raises(ValueError):
        Actor(actor_id="")


def test_action_registry():
    assert Action("read").is_known()
    assert Action("format_disk").is_known() is False


def test_action_mutating():
    assert Action("write").is_mutating()
    assert Action("read").is_mutating() is False


def test_action_high_risk():
    assert Action("delete").is_high_risk()
    assert Action("read").is_high_risk() is False


def test_authority_freshness():
    auth = Authority("admin", issued_at=100, expires_at=200, nonce="n1")
    assert auth.is_fresh(150) is True
    assert auth.is_fresh(250) is False
    assert auth.is_expired(250) is True


def test_forbidden_transitions_exist():
    assert len(FORBIDDEN_TRANSITIONS) >= 8
