#!/usr/bin/env python3
"""Run the bounded measured-mutation fixture.

This is not a production executor. It demonstrates one concrete state object
being observed before and after an authorised in-memory write.
"""

from core.canonical import Packet
from core.evaluator import Evaluator
from core.measured_mutation import (
    InMemoryMeasuredResource,
    InMemoryStateObserver,
    InMemoryWriteAdapter,
    MeasuredMutationBoundary,
)


RAW = {
    "packet_id": "PKT-MEASURED-DEMO",
    "schema_version": "1.0.0",
    "actor_id": "actor-1",
    "requested_action": "write",
    "object_ref": "/data/file",
    "state_claim": "fixture",
    "authority_claim": {
        "authority_type": "admin",
        "issued_at": 100,
        "expires_at": 200,
        "nonce": "n-measured-demo",
    },
    "dependencies": [],
    "timestamp": 150,
    "nonce": "n-measured-demo",
    "provenance": "measured-mutation-demo",
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


def main() -> int:
    record = Evaluator().evaluate(RAW)
    packet = Packet.from_dict(RAW)

    resource = InMemoryMeasuredResource({
        packet.object_ref: {"value": "before", "version": 1},
    })
    observer = InMemoryStateObserver(resource)
    effect = InMemoryWriteAdapter(resource)
    boundary = MeasuredMutationBoundary(observer=observer, effect=effect)

    receipt = boundary.attempt(
        record=record,
        packet=packet,
        payload={"value": "after", "version": 2},
    )

    print("MEASURED MUTATION FIXTURE")
    print(f"gate permitted      : {receipt.gate_permitted}")
    print(f"effect completed    : {receipt.effect_completed}")
    print(f"measurement complete: {receipt.measurement_complete}")
    print(f"pre-state hash      : {receipt.pre_state_hash}")
    print(f"post-state hash     : {receipt.post_state_hash}")
    print(f"state changed       : {receipt.state_changed}")
    print(f"mutation calls      : {effect.mutation_calls}")
    print(f"result code         : {receipt.code}")
    print()
    print("Claim limit: one in-memory fixture, one governed write path.")
    print("No production, universal-path, or deployment claim.")

    return 0 if (
        receipt.gate_permitted
        and receipt.effect_completed
        and receipt.measurement_complete
        and receipt.state_changed is True
        and effect.mutation_calls == 1
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
