"""Measured mutation fixture for the public start-here inspection surface.

This module answers one bounded question:

    On this exact in-memory fixture, did the same bound resource object change,
    as measured from that resource before and after the attempted consequence?

The fixture deliberately binds observation and effect to ONE concrete resource
instance. Callers do not inject an observer, an effect adapter, a hash rule, or
a post-state hash into the measurement boundary.

The sequence is:

    bound resource
      -> first observation
      -> commit-gate live-state re-read
      -> effect attempt
      -> final observation of the same resource

The existing commit gate remains permission-only. Its legacy state_after_hash
parameter is not measurement evidence and is never copied into the
MeasurementReceipt.

This is an in-memory proof fixture only. It does not establish production
atomicity, path-universal enforcement, durable execution custody, or
independent third-party observation.
"""

from __future__ import annotations

import hashlib
import json
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator, Mapping, Optional

from core.canonical import Packet
from core.commit_gate import commit_gate
from core.decision_record import DecisionRecord
from core.state_oracle import StateOracle


MEASUREMENT_RULE = "canonical-json-sha256:v1"


def canonical_state_hash(value: Mapping[str, Any]) -> str:
    """Hash one observed state mapping using the fixture's fixed rule."""
    blob = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


@dataclass(frozen=True)
class MeasurementReceipt:
    """Record of what this exact fixture observed and attempted.

    `state_changed` is defined only by the two bound-resource observations.
    It is None if either observation is unavailable.

    `effect_completed=False` does NOT mean no effect occurred: an adapter can
    mutate and then raise. The observed post-state is therefore retained even
    on effect failure.

    `measurement_complete=True` means both observations were available. It
    does not upgrade the fixture into third-party attestation.
    """

    gate_permitted: bool
    effect_attempted: bool
    effect_completed: bool
    measurement_complete: bool
    state_changed: Optional[bool]
    code: str
    decision_id: Optional[str]
    object_ref: str
    action: str
    pre_state_hash: Optional[str]
    post_state_hash: Optional[str]
    measurement_rule: str = MEASUREMENT_RULE

    def to_dict(self) -> dict[str, Any]:
        return {
            "gate_permitted": self.gate_permitted,
            "effect_attempted": self.effect_attempted,
            "effect_completed": self.effect_completed,
            "measurement_complete": self.measurement_complete,
            "state_changed": self.state_changed,
            "code": self.code,
            "decision_id": self.decision_id,
            "object_ref": self.object_ref,
            "action": self.action,
            "pre_state_hash": self.pre_state_hash,
            "post_state_hash": self.post_state_hash,
            "measurement_rule": self.measurement_rule,
        }


class InMemoryMeasuredResource:
    """The one concrete state object used by the measurement fixture.

    Observation and effect both address this same instance and the same
    `object_ref`. The hash rule is fixed by `canonical_state_hash`.

    Fault controls exist only to exercise negative paths deterministically:
      - unavailable_observations: 1-based observation calls returning None
      - drift_on_observation: mutate just before that observation is returned
      - effect_failure: None, "before_write", or "after_write"
      - effect_return: arbitrary value returned after a successful write;
        the boundary deliberately ignores it
    """

    def __init__(
        self,
        initial: Mapping[str, Mapping[str, Any]],
        *,
        unavailable_observations: frozenset[int] = frozenset(),
        drift_on_observation: Optional[int] = None,
        drift_payload: Optional[Mapping[str, Any]] = None,
        effect_failure: Optional[str] = None,
        effect_return: Any = None,
    ) -> None:
        if effect_failure not in (None, "before_write", "after_write"):
            raise ValueError("effect_failure must be None, before_write, or after_write")
        if drift_on_observation is not None and drift_on_observation < 1:
            raise ValueError("drift_on_observation must be 1-based")

        self._objects = {
            key: dict(value)
            for key, value in initial.items()
        }
        self._unavailable_observations = frozenset(unavailable_observations)
        self._drift_on_observation = drift_on_observation
        self._drift_payload = None if drift_payload is None else dict(drift_payload)
        self._effect_failure = effect_failure
        self._effect_return = effect_return
        self._lock = threading.RLock()

        self.observation_calls = 0
        self.effect_calls = 0
        self.mutation_calls = 0
        self.external_drift_calls = 0

    @contextmanager
    def measurement_session(self) -> Iterator[None]:
        """Hold the fixture resource lock across check, effect, and observation.

        This closes interleaving through this resource's own read/write methods
        for the bounded in-memory fixture. It is not a production transaction.
        """
        with self._lock:
            yield

    def observe_state_hash(self, object_ref: str) -> Optional[str]:
        """Observe the current state of this resource using the fixed hash rule."""
        with self._lock:
            self.observation_calls += 1
            call = self.observation_calls

            if self._drift_on_observation == call:
                if object_ref not in self._objects:
                    raise KeyError(object_ref)
                if self._drift_payload is None:
                    raise RuntimeError("drift_payload required for configured drift")
                self._objects[object_ref] = dict(self._drift_payload)
                self.external_drift_calls += 1

            if call in self._unavailable_observations:
                return None

            state = self._objects.get(object_ref)
            if state is None:
                return None
            return canonical_state_hash(state)

    def apply_write(
        self,
        *,
        object_ref: str,
        action: str,
        payload: Mapping[str, Any],
    ) -> Any:
        """Apply the fixture's one effect path to this same bound resource."""
        with self._lock:
            self.effect_calls += 1

            if action != "write":
                raise ValueError("UNSUPPORTED_FIXTURE_ACTION")
            if self._effect_failure == "before_write":
                raise RuntimeError("synthetic failure before write")
            if object_ref not in self._objects:
                raise KeyError(object_ref)

            self._objects[object_ref] = dict(payload)
            self.mutation_calls += 1

            if self._effect_failure == "after_write":
                raise RuntimeError("synthetic failure after write")

            return self._effect_return

    def snapshot(self, object_ref: str) -> Optional[dict[str, Any]]:
        """Return a copy for test inspection; never exposes the live mapping."""
        with self._lock:
            state = self._objects.get(object_ref)
            return None if state is None else dict(state)


class _BoundResourceOracle(StateOracle):
    """Commit-gate adapter over the SAME resource used for the effect."""

    def __init__(self, resource: InMemoryMeasuredResource) -> None:
        self._resource = resource

    def current_state_hash(self, object_ref: str) -> Optional[str]:
        return self._resource.observe_state_hash(object_ref)


class MeasuredMutationBoundary:
    """Gate one effect and measure the same bound resource before/after.

    The constructor accepts exactly one resource. It does not accept arbitrary
    observer/effect implementations, so the public fixture cannot accidentally
    observe object A while writing object B.

    The legacy commit gate still requires a state_after_hash argument. A private
    sentinel is supplied only to satisfy that older result shape. The sentinel
    is never measurement evidence and never enters MeasurementReceipt.
    """

    _UNOBSERVED_POST_STATE = "UNOBSERVED:MEASUREMENT_BOUNDARY"

    def __init__(self, *, resource: InMemoryMeasuredResource) -> None:
        if type(resource) is not InMemoryMeasuredResource:
            raise TypeError("measurement fixture requires exact InMemoryMeasuredResource")
        self._resource = resource
        self._oracle = _BoundResourceOracle(resource)

    def attempt(
        self,
        *,
        record: Optional[DecisionRecord],
        packet: Packet,
        payload: Mapping[str, Any],
    ) -> MeasurementReceipt:
        with self._resource.measurement_session():
            pre_state_hash = self._resource.observe_state_hash(packet.object_ref)

            if pre_state_hash is None:
                return self._receipt(
                    gate_permitted=False,
                    effect_attempted=False,
                    effect_completed=False,
                    measurement_complete=False,
                    state_changed=None,
                    code="DENY:PRE_STATE_UNOBSERVABLE",
                    record=record,
                    packet=packet,
                    pre_state_hash=None,
                    post_state_hash=None,
                )

            gate_result = commit_gate(
                record,
                packet,
                pre_state_hash,
                self._UNOBSERVED_POST_STATE,
                state_oracle=self._oracle,
            )

            if not gate_result.permitted:
                post_state_hash = self._resource.observe_state_hash(packet.object_ref)
                complete = post_state_hash is not None
                changed = pre_state_hash != post_state_hash if complete else None
                return self._receipt(
                    gate_permitted=False,
                    effect_attempted=False,
                    effect_completed=False,
                    measurement_complete=complete,
                    state_changed=changed,
                    code=gate_result.denial_code or gate_result.denial_reason or "DENY",
                    record=record,
                    packet=packet,
                    pre_state_hash=pre_state_hash,
                    post_state_hash=post_state_hash,
                )

            try:
                # Deliberately discard any return value. The only post-state
                # evidence accepted by this fixture is the later resource read.
                self._resource.apply_write(
                    object_ref=packet.object_ref,
                    action=packet.requested_action,
                    payload=payload,
                )
            except Exception as exc:
                post_state_hash = self._resource.observe_state_hash(packet.object_ref)
                complete = post_state_hash is not None
                changed = pre_state_hash != post_state_hash if complete else None
                return self._receipt(
                    gate_permitted=True,
                    effect_attempted=True,
                    effect_completed=False,
                    measurement_complete=complete,
                    state_changed=changed,
                    code=f"ERROR:EFFECT_FAILED:{type(exc).__name__}",
                    record=record,
                    packet=packet,
                    pre_state_hash=pre_state_hash,
                    post_state_hash=post_state_hash,
                )

            post_state_hash = self._resource.observe_state_hash(packet.object_ref)
            if post_state_hash is None:
                return self._receipt(
                    gate_permitted=True,
                    effect_attempted=True,
                    effect_completed=True,
                    measurement_complete=False,
                    state_changed=None,
                    code="ERROR:POST_STATE_UNOBSERVABLE",
                    record=record,
                    packet=packet,
                    pre_state_hash=pre_state_hash,
                    post_state_hash=None,
                )

            changed = pre_state_hash != post_state_hash
            return self._receipt(
                gate_permitted=True,
                effect_attempted=True,
                effect_completed=True,
                measurement_complete=True,
                state_changed=changed,
                code="MEASURED:STATE_CHANGED" if changed else "MEASURED:NO_STATE_CHANGE",
                record=record,
                packet=packet,
                pre_state_hash=pre_state_hash,
                post_state_hash=post_state_hash,
            )

    @staticmethod
    def _receipt(
        *,
        gate_permitted: bool,
        effect_attempted: bool,
        effect_completed: bool,
        measurement_complete: bool,
        state_changed: Optional[bool],
        code: str,
        record: Optional[DecisionRecord],
        packet: Packet,
        pre_state_hash: Optional[str],
        post_state_hash: Optional[str],
    ) -> MeasurementReceipt:
        return MeasurementReceipt(
            gate_permitted=gate_permitted,
            effect_attempted=effect_attempted,
            effect_completed=effect_completed,
            measurement_complete=measurement_complete,
            state_changed=state_changed,
            code=code,
            decision_id=None if record is None else record.decision_id,
            object_ref=packet.object_ref,
            action=packet.requested_action,
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
        )
