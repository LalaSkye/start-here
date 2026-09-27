"""Adversarial tests for the measured mutation fixture.

The claim is intentionally narrow: one exact InMemoryMeasuredResource is bound
to both the live-state check and the effect path, and its state is observed
before and after the attempted consequence using one fixed hash rule.
"""

from __future__ import annotations

import inspect

import pytest

from core.canonical import Packet
from core.evaluator import Evaluator
from core.measured_mutation import (
    MEASUREMENT_RULE,
    InMemoryMeasuredResource,
    MeasuredMutationBoundary,
    canonical_state_hash,
)


def _valid_mutating_packet(packet_id: str = "PKT-MEASURED-001") -> dict:
    return {
        "packet_id": packet_id,
        "schema_version": "1.0.0",
        "actor_id": "actor-1",
        "requested_action": "write",
        "object_ref": "/data/file",
        "state_claim": "fixture",
        "authority_claim": {
            "authority_type": "admin",
            "issued_at": 100,
            "expires_at": 200,
            "nonce": "n-measured",
        },
        "dependencies": [],
        "timestamp": 150,
        "nonce": "n-measured",
        "provenance": "measured-mutation-fixture",
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


def _record_and_packet(packet_id: str = "PKT-MEASURED-001"):
    raw = _valid_mutating_packet(packet_id)
    record = Evaluator().evaluate(raw)
    packet = Packet.from_dict(raw)
    assert record.verdict == "ALLOW"
    return record, packet


def _resource(**kwargs):
    return InMemoryMeasuredResource(
        {"/data/file": {"value": "before", "version": 1}},
        **kwargs,
    )


def _boundary(resource: InMemoryMeasuredResource):
    return MeasuredMutationBoundary(resource=resource)


def test_same_store_contract_is_constructor_enforced():
    sig = inspect.signature(MeasuredMutationBoundary)
    assert tuple(sig.parameters) == ("resource",)

    resource = _resource()
    boundary = _boundary(resource)

    assert boundary._resource is resource

    class MerelySimilarResource(InMemoryMeasuredResource):
        pass

    with pytest.raises(TypeError):
        MeasuredMutationBoundary(resource=MerelySimilarResource({
            "/data/file": {"value": "before", "version": 1}
        }))


def test_authorised_mutation_is_measured_from_same_concrete_resource():
    record, packet = _record_and_packet("PKT-MEASURED-ALLOW")
    resource = _resource()
    boundary = _boundary(resource)

    before_snapshot = resource.snapshot(packet.object_ref)
    before_hash = canonical_state_hash(before_snapshot)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    after_snapshot = resource.snapshot(packet.object_ref)
    after_hash = canonical_state_hash(after_snapshot)

    assert receipt.gate_permitted is True
    assert receipt.effect_attempted is True
    assert receipt.effect_completed is True
    assert receipt.measurement_complete is True
    assert receipt.state_changed is True
    assert receipt.code == "MEASURED:STATE_CHANGED"
    assert receipt.pre_state_hash == before_hash
    assert receipt.post_state_hash == after_hash
    assert before_snapshot != after_snapshot
    assert receipt.pre_state_hash != receipt.post_state_hash
    assert resource.effect_calls == 1
    assert resource.mutation_calls == 1
    assert receipt.measurement_rule == MEASUREMENT_RULE
    assert receipt.post_state_hash != MeasuredMutationBoundary._UNOBSERVED_POST_STATE


def test_refusal_control_never_calls_effect_and_same_resource_stays_unchanged():
    _, packet = _record_and_packet("PKT-MEASURED-REFUSE")
    resource = _resource()
    boundary = _boundary(resource)

    before = resource.snapshot(packet.object_ref)
    receipt = boundary.attempt(
        record=None,
        packet=packet,
        payload={"value": "after", "version": 2},
    )
    after = resource.snapshot(packet.object_ref)

    assert receipt.gate_permitted is False
    assert receipt.effect_attempted is False
    assert receipt.effect_completed is False
    assert receipt.measurement_complete is True
    assert receipt.state_changed is False
    assert receipt.pre_state_hash == receipt.post_state_hash
    assert resource.effect_calls == 0
    assert resource.mutation_calls == 0
    assert before == after


def test_caller_cannot_supply_post_state_hash_or_separate_witnesses():
    record, packet = _record_and_packet("PKT-MEASURED-NO-INJECT")
    resource = _resource()
    boundary = _boundary(resource)
    before = resource.snapshot(packet.object_ref)

    attempt_sig = inspect.signature(boundary.attempt)
    assert "state_after_hash" not in attempt_sig.parameters
    assert "observer" not in attempt_sig.parameters
    assert "effect" not in attempt_sig.parameters

    with pytest.raises(TypeError):
        boundary.attempt(
            record=record,
            packet=packet,
            payload={"value": "after", "version": 2},
            state_after_hash="forged-zero",  # type: ignore[call-arg]
        )

    assert resource.effect_calls == 0
    assert resource.snapshot(packet.object_ref) == before


def test_effect_return_is_discarded_even_when_it_equals_actual_post_hash():
    record, packet = _record_and_packet("PKT-MEASURED-RETURN")

    expected_after = {"value": "after", "version": 2}
    actual_hash = canonical_state_hash(expected_after)
    resource = _resource(effect_return=actual_hash)
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload=expected_after,
    )

    assert resource.effect_calls == 1
    assert resource.mutation_calls == 1
    assert receipt.measurement_complete is True
    assert receipt.state_changed is True
    assert receipt.post_state_hash == canonical_state_hash(
        resource.snapshot(packet.object_ref)
    )
    # Same bytes are deliberately used as the adapter's return value. The
    # source cannot be distinguished by equality, so the contract removes the
    # return channel from MeasuredMutationBoundary entirely.
    assert receipt.post_state_hash == actual_hash


def test_pre_state_drift_between_first_read_and_gate_read_refuses_before_effect():
    record, packet = _record_and_packet("PKT-MEASURED-DRIFT")
    resource = _resource(
        drift_on_observation=2,
        drift_payload={"value": "drifted", "version": 99},
    )
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert receipt.gate_permitted is False
    assert receipt.effect_attempted is False
    assert resource.effect_calls == 0
    assert resource.mutation_calls == 0
    assert resource.external_drift_calls == 1
    assert receipt.state_changed is True
    assert receipt.measurement_complete is True
    assert "state_hash_mismatch" in receipt.code
    assert resource.snapshot(packet.object_ref) == {"value": "drifted", "version": 99}


def test_pre_state_unobservable_fails_closed_without_gate_effect_or_measurement():
    record, packet = _record_and_packet("PKT-MEASURED-PRE-UNOBS")
    resource = _resource(unavailable_observations=frozenset({1}))
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert receipt.gate_permitted is False
    assert receipt.effect_attempted is False
    assert receipt.effect_completed is False
    assert receipt.measurement_complete is False
    assert receipt.state_changed is None
    assert receipt.pre_state_hash is None
    assert receipt.post_state_hash is None
    assert receipt.code == "DENY:PRE_STATE_UNOBSERVABLE"
    assert resource.effect_calls == 0
    assert resource.mutation_calls == 0


def test_post_state_unobservable_never_becomes_measured_success():
    record, packet = _record_and_packet("PKT-MEASURED-POST-UNOBS")
    # Authorised path reads three times: pre, gate live-state, post.
    resource = _resource(unavailable_observations=frozenset({3}))
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert resource.mutation_calls == 1
    assert resource.snapshot(packet.object_ref) == {"value": "after", "version": 2}
    assert receipt.gate_permitted is True
    assert receipt.effect_attempted is True
    assert receipt.effect_completed is True
    assert receipt.measurement_complete is False
    assert receipt.state_changed is None
    assert receipt.post_state_hash is None
    assert receipt.code == "ERROR:POST_STATE_UNOBSERVABLE"
    assert not receipt.code.startswith("MEASURED:")


def test_effect_failure_before_write_reports_no_observed_change():
    record, packet = _record_and_packet("PKT-MEASURED-FAIL-BEFORE")
    resource = _resource(effect_failure="before_write")
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert resource.effect_calls == 1
    assert resource.mutation_calls == 0
    assert receipt.gate_permitted is True
    assert receipt.effect_attempted is True
    assert receipt.effect_completed is False
    assert receipt.measurement_complete is True
    assert receipt.state_changed is False
    assert receipt.code == "ERROR:EFFECT_FAILED:RuntimeError"


def test_partial_write_then_raise_keeps_effect_failure_and_reports_observed_change():
    record, packet = _record_and_packet("PKT-MEASURED-PARTIAL")
    resource = _resource(effect_failure="after_write")
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert resource.effect_calls == 1
    assert resource.mutation_calls == 1
    assert resource.snapshot(packet.object_ref) == {"value": "after", "version": 2}
    assert receipt.gate_permitted is True
    assert receipt.effect_attempted is True
    assert receipt.effect_completed is False
    assert receipt.measurement_complete is True
    assert receipt.state_changed is True
    assert receipt.pre_state_hash != receipt.post_state_hash
    assert receipt.code == "ERROR:EFFECT_FAILED:RuntimeError"
    assert not receipt.code.startswith("MEASURED:")


def test_legacy_commit_gate_sentinel_never_enters_measurement_receipt():
    record, packet = _record_and_packet("PKT-MEASURED-SENTINEL")
    resource = _resource()
    boundary = _boundary(resource)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )
    exported = receipt.to_dict()

    assert MeasuredMutationBoundary._UNOBSERVED_POST_STATE not in exported.values()
    assert receipt.post_state_hash == canonical_state_hash(
        resource.snapshot(packet.object_ref)
    )
