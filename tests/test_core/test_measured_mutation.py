"""Measured mutation fixture tests.

These tests close one narrow evidence gap in start-here:
the stronger fixture measures a concrete in-memory object before and after the
effect instead of accepting a caller-supplied post-state hash.
"""

from __future__ import annotations

import inspect

import pytest

from core.canonical import Packet
from core.evaluator import Evaluator
from core.measured_mutation import (
    InMemoryMeasuredResource,
    InMemoryStateObserver,
    InMemoryWriteAdapter,
    MeasuredMutationBoundary,
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


def _fixture():
    resource = InMemoryMeasuredResource({
        "/data/file": {"value": "before", "version": 1},
    })
    observer = InMemoryStateObserver(resource)
    effect = InMemoryWriteAdapter(resource)
    boundary = MeasuredMutationBoundary(observer=observer, effect=effect)
    return resource, observer, effect, boundary


def test_authorised_mutation_is_measured_from_concrete_state():
    record, packet = _record_and_packet("PKT-MEASURED-ALLOW")
    resource, observer, effect, boundary = _fixture()

    expected_pre = observer.observe_state_hash(packet.object_ref)
    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )
    expected_post = observer.observe_state_hash(packet.object_ref)

    assert receipt.gate_permitted is True
    assert receipt.effect_attempted is True
    assert receipt.effect_completed is True
    assert receipt.measurement_complete is True
    assert receipt.state_changed is True
    assert receipt.code == "MEASURED:STATE_CHANGED"
    assert receipt.pre_state_hash == expected_pre
    assert receipt.post_state_hash == expected_post
    assert receipt.pre_state_hash != receipt.post_state_hash
    assert effect.mutation_calls == 1
    assert resource.snapshot(packet.object_ref) == {"value": "after", "version": 2}


def test_refusal_measures_unchanged_state_and_never_calls_effect():
    _, packet = _record_and_packet("PKT-MEASURED-REFUSE")
    resource, observer, effect, boundary = _fixture()

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
    assert effect.mutation_calls == 0
    assert before == after


def test_caller_cannot_supply_post_state_hash_to_the_measurement_boundary():
    record, packet = _record_and_packet("PKT-MEASURED-NO-INJECT")
    resource, observer, effect, boundary = _fixture()
    before = resource.snapshot(packet.object_ref)

    assert "state_after_hash" not in inspect.signature(boundary.attempt).parameters

    with pytest.raises(TypeError):
        boundary.attempt(
            record=record,
            packet=packet,
            payload={"value": "after", "version": 2},
            state_after_hash="forged-zero",  # type: ignore[call-arg]
        )

    assert effect.mutation_calls == 0
    assert resource.snapshot(packet.object_ref) == before


def test_post_state_is_observed_not_taken_from_effect_return_value():
    record, packet = _record_and_packet("PKT-MEASURED-RETURN")

    resource = InMemoryMeasuredResource({
        "/data/file": {"value": "before", "version": 1},
    })
    observer = InMemoryStateObserver(resource)

    class MisreportingEffect:
        def __init__(self) -> None:
            self.calls = 0

        def apply(self, *, object_ref, action, payload):
            self.calls += 1
            resource._write(object_ref, payload)
            return "sha256:caller-supplied-fiction"

    effect = MisreportingEffect()
    boundary = MeasuredMutationBoundary(observer=observer, effect=effect)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert effect.calls == 1
    assert receipt.measurement_complete is True
    assert receipt.state_changed is True
    assert receipt.post_state_hash == observer.observe_state_hash(packet.object_ref)
    assert receipt.post_state_hash != "sha256:caller-supplied-fiction"


def test_pre_state_drift_refuses_before_effect():
    record, packet = _record_and_packet("PKT-MEASURED-DRIFT")
    resource, observer, effect, boundary = _fixture()

    class DriftBetweenReads:
        def __init__(self) -> None:
            self.calls = 0

        def observe_state_hash(self, object_ref: str):
            self.calls += 1
            if self.calls == 2:
                resource._write(object_ref, {"value": "drifted", "version": 99})
            return observer.observe_state_hash(object_ref)

    drifting_observer = DriftBetweenReads()
    boundary = MeasuredMutationBoundary(observer=drifting_observer, effect=effect)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert receipt.gate_permitted is False
    assert receipt.effect_attempted is False
    assert effect.mutation_calls == 0
    assert "state_hash_mismatch" in receipt.code


def test_effect_failure_does_not_claim_successful_measurement():
    record, packet = _record_and_packet("PKT-MEASURED-FAIL")

    resource = InMemoryMeasuredResource({
        "/data/file": {"value": "before", "version": 1},
    })
    observer = InMemoryStateObserver(resource)

    class FailingEffect:
        def apply(self, *, object_ref, action, payload):
            raise RuntimeError("synthetic failure")

    boundary = MeasuredMutationBoundary(observer=observer, effect=FailingEffect())

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    assert receipt.gate_permitted is True
    assert receipt.effect_attempted is True
    assert receipt.effect_completed is False
    assert receipt.measurement_complete is True
    assert receipt.state_changed is False
    assert receipt.code == "ERROR:EFFECT_FAILED:RuntimeError"
