"""Protected invariants — Action Registry (Layer 1).

Test naming convention: test_AR{N}_{invariant_name}
"""

from core.action_registry import (
    ActionRegistry, ActionRegistryEntry, CommitBoundary,
    ReversibilityClass, DEFAULT_REGISTRY,
)
from core.algebra import Action, Verdict
from core.evaluator import Evaluator


def _valid_packet(packet_id="PKT-AR-001", action="read"):
    return {
        "packet_id": packet_id, "schema_version": "1.0.0",
        "actor_id": "actor-1", "requested_action": action,
        "object_ref": "/data/file", "state_claim": "abc",
        "authority_claim": {"authority_type": "admin", "issued_at": 100, "expires_at": 200, "nonce": "n1"},
        "dependencies": [], "timestamp": 150, "nonce": "n1", "provenance": "test",
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


def test_AR1_registry_contains_governed_actions():
    assert DEFAULT_REGISTRY.all_action_ids() == frozenset({"read", "write", "delete", "deploy", "commit"})

def test_AR2_registry_version():
    assert DEFAULT_REGISTRY.version == "1.0.0"

def test_AR3_unknown_action_not_in_registry():
    assert not DEFAULT_REGISTRY.is_known("format_disk")
    assert DEFAULT_REGISTRY.lookup("format_disk") is None

def test_AR4_all_entries_have_mandatory_fields():
    for entry in DEFAULT_REGISTRY.all_entries():
        assert entry.action_id
        assert isinstance(entry.commit_boundary, CommitBoundary)
        assert entry.authority_required
        assert isinstance(entry.reversibility_class, ReversibilityClass)
        assert len(entry.evidence_required) > 0
        assert entry.owner_of_record

def test_AR5_mutating_classification():
    assert not DEFAULT_REGISTRY.is_mutating("read")
    assert DEFAULT_REGISTRY.is_mutating("write")
    assert DEFAULT_REGISTRY.is_mutating("delete")
    assert DEFAULT_REGISTRY.is_mutating("deploy")
    assert DEFAULT_REGISTRY.is_mutating("commit")

def test_AR6_high_risk_classification():
    assert not DEFAULT_REGISTRY.is_high_risk("read")
    assert not DEFAULT_REGISTRY.is_high_risk("write")
    assert DEFAULT_REGISTRY.is_high_risk("delete")
    assert DEFAULT_REGISTRY.is_high_risk("deploy")
    assert DEFAULT_REGISTRY.is_high_risk("commit")

def test_AR7_action_delegates_to_registry():
    assert Action._registry is DEFAULT_REGISTRY
    assert Action(action_type="read").is_known()
    assert not Action(action_type="read").is_mutating()
    assert Action(action_type="deploy").is_high_risk()
    assert not Action(action_type="format_disk").is_known()

def test_AR8_registry_entry_lookup():
    entry = Action(action_type="write").registry_entry()
    assert entry is not None
    assert entry.action_id == "write"
    assert entry.commit_boundary == CommitBoundary.STANDARD
    assert entry.authority_required == "operator"
    assert "state_precondition" in entry.evidence_required

def test_AR9_unknown_returns_none():
    assert Action(action_type="hack_mainframe").registry_entry() is None

def test_AR10_duplicate_action_id_raises():
    e = ActionRegistryEntry(action_id="x", commit_boundary=CommitBoundary.NONE,
        authority_required="r", reversibility_class=ReversibilityClass.REVERSIBLE,
        evidence_required=("a",), owner_of_record="t")
    try:
        ActionRegistry(entries=[e, e])
        assert False, "Should raise"
    except ValueError:
        pass

def test_AR11_entry_is_frozen():
    try:
        DEFAULT_REGISTRY.lookup("read").action_id = "hacked"
        assert False
    except AttributeError:
        pass

def test_AR12_evaluator_denies_unknown_via_registry():
    ev = Evaluator()
    record = ev.evaluate(_valid_packet(packet_id="PKT-AR12", action="format_disk"))
    assert record.verdict == Verdict.DENY.value

def test_AR13_evaluator_allows_known_via_registry():
    ev = Evaluator()
    for a in ("read", "write", "delete", "deploy", "commit"):
        r = ev.evaluate(_valid_packet(packet_id=f"PKT-AR13-{a}", action=a))
        assert r.verdict == Verdict.ALLOW.value, f"{a} should ALLOW"

def test_AR14_backward_compat_frozensets():
    assert "read" in Action.REGISTRY
    assert "write" in Action.MUTATING
    assert "delete" in Action.HIGH_RISK

def test_AR15_evidence_requirements_consistent():
    read_e = DEFAULT_REGISTRY.lookup("read")
    write_e = DEFAULT_REGISTRY.lookup("write")
    assert len(read_e.evidence_required) < len(write_e.evidence_required)
    for a in ("write", "delete", "deploy", "commit"):
        e = DEFAULT_REGISTRY.lookup(a)
        assert "authority_fresh" in e.evidence_required
        assert "authority_sufficient" in e.evidence_required
    assert "authority_fresh" not in read_e.evidence_required

def test_AR16_authority_requirements_consistent():
    from core.commit_gate import AUTHORITY_SCOPE
    for entry in DEFAULT_REGISTRY.all_entries():
        scope = AUTHORITY_SCOPE.get(entry.action_id)
        assert scope is not None
        assert entry.authority_required in scope

def test_AR17_reversibility_classification():
    assert DEFAULT_REGISTRY.lookup("read").reversibility_class == ReversibilityClass.REVERSIBLE
    assert DEFAULT_REGISTRY.lookup("delete").reversibility_class == ReversibilityClass.IRREVERSIBLE
    assert DEFAULT_REGISTRY.lookup("commit").reversibility_class == ReversibilityClass.IRREVERSIBLE
    assert DEFAULT_REGISTRY.lookup("write").reversibility_class == ReversibilityClass.CONDITIONALLY_REVERSIBLE
