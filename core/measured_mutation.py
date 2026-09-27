"""Measured mutation fixture for the public start-here inspection surface.

This module exists for one bounded question:

    Did a concrete state object actually change, as observed from the object
    before and after the attempted consequence?

It deliberately separates:
    - authority / commit permission (`commit_gate`)
    - the effect adapter that may change state
    - the observer that measures state before and after

The caller cannot supply a post-state hash. Post-state is observed from the
resource after the effect attempt.

This is an in-memory proof fixture only. It does not establish production
atomicity, path-universal enforcement, or independent third-party observation.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Protocol

from core.canonical import Packet
from core.commit_gate import commit_gate
from core.decision_record import DecisionRecord
from core.state_oracle import StateOracle


def canonical_state_hash(value: Mapping[str, Any]) -> str:
    """Hash a state mapping using deterministic JSON bytes."""
    blob = json.dumps(
        dict(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(blob).hexdigest()


class StateObserver(Protocol):
    """Read-only observation surface used by the measurement boundary."""

    def observe_state_hash(self, object_ref: str) -> Optional[str]:
        """Return the current state hash, or None if it cannot be observed."""
        ...


class EffectAdapter(Protocol):
    """Effect-capable adapter used only after the gate permits the action."""

    def apply(
        self,
        *,
        object_ref: str,
        action: str,
        payload: Mapping[str, Any],
    ) -> None:
        """Apply one bounded effect or raise."""
        ...


class _ObserverOracle(StateOracle):
    """Adapt StateObserver to the existing commit-gate StateOracle interface."""

    def __init__(self, observer: StateObserver) -> None:
        self._observer = observer

    def current_state_hash(self, object_ref: str) -> Optional[str]:
        return self._observer.observe_state_hash(object_ref)


@dataclass(frozen=True)
class MeasurementReceipt:
    """Record of what the boundary observed and attempted.

    `state_changed` is None when either observation is unavailable.
    `effect_completed` means the effect adapter returned successfully; it is
    not, by itself, evidence of state change. The before/after observations are
    the measurement.
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
        }


class MeasuredMutationBoundary:
    """Gate one effect, then observe the concrete state again."""

    _UNOBSERVED_POST_STATE = "UNOBSERVED:MEASUREMENT_BOUNDARY"

    def __init__(self, *, observer: StateObserver, effect: EffectAdapter) -> None:
        self._observer = observer
        self._effect = effect
        self._oracle = _ObserverOracle(observer)

    def attempt(
        self,
        *,
        record: Optional[DecisionRecord],
        packet: Packet,
        payload: Mapping[str, Any],
    ) -> MeasurementReceipt:
        pre_state_hash = self._observer.observe_state_hash(packet.object_ref)

        if pre_state_hash is None:
            return MeasurementReceipt(
                gate_permitted=False,
                effect_attempted=False,
                effect_completed=False,
                measurement_complete=False,
                state_changed=None,
                code="DENY:PRE_STATE_UNOBSERVABLE",
                decision_id=None if record is None else record.decision_id,
                object_ref=packet.object_ref,
                action=packet.requested_action,
                pre_state_hash=None,
                post_state_hash=None,
            )

        # Existing commit_gate validates the decision record and independently
        # re-reads the current state through the observer-backed oracle.
        #
        # Its state_after_hash parameter is legacy commit-record plumbing, not
        # measurement evidence. This wrapper therefore supplies a private
        # sentinel and never exposes that value as the observed post-state.
        gate_result = commit_gate(
            record,
            packet,
            pre_state_hash,
            self._UNOBSERVED_POST_STATE,
            state_oracle=self._oracle,
        )

        if not gate_result.permitted:
            post_state_hash = self._observer.observe_state_hash(packet.object_ref)
            complete = post_state_hash is not None
            changed = (
                pre_state_hash != post_state_hash
                if complete
                else None
            )
            return MeasurementReceipt(
                gate_permitted=False,
                effect_attempted=False,
                effect_completed=False,
                measurement_complete=complete,
                state_changed=changed,
                code=gate_result.denial_code or gate_result.denial_reason or "DENY",
                decision_id=None if record is None else record.decision_id,
                object_ref=packet.object_ref,
                action=packet.requested_action,
                pre_state_hash=pre_state_hash,
                post_state_hash=post_state_hash,
            )

        try:
            self._effect.apply(
                object_ref=packet.object_ref,
                action=packet.requested_action,
                payload=payload,
            )
        except Exception as exc:
            post_state_hash = self._observer.observe_state_hash(packet.object_ref)
            complete = post_state_hash is not None
            changed = (
                pre_state_hash != post_state_hash
                if complete
                else None
            )
            return MeasurementReceipt(
                gate_permitted=True,
                effect_attempted=True,
                effect_completed=False,
                measurement_complete=complete,
                state_changed=changed,
                code=f"ERROR:EFFECT_FAILED:{type(exc).__name__}",
                decision_id=record.decision_id if record is not None else None,
                object_ref=packet.object_ref,
                action=packet.requested_action,
                pre_state_hash=pre_state_hash,
                post_state_hash=post_state_hash,
            )

        post_state_hash = self._observer.observe_state_hash(packet.object_ref)
        if post_state_hash is None:
            return MeasurementReceipt(
                gate_permitted=True,
                effect_attempted=True,
                effect_completed=True,
                measurement_complete=False,
                state_changed=None,
                code="ERROR:POST_STATE_UNOBSERVABLE",
                decision_id=record.decision_id if record is not None else None,
                object_ref=packet.object_ref,
                action=packet.requested_action,
                pre_state_hash=pre_state_hash,
                post_state_hash=None,
            )

        changed = pre_state_hash != post_state_hash
        return MeasurementReceipt(
            gate_permitted=True,
            effect_attempted=True,
            effect_completed=True,
            measurement_complete=True,
            state_changed=changed,
            code="MEASURED:STATE_CHANGED" if changed else "MEASURED:NO_STATE_CHANGE",
            decision_id=record.decision_id if record is not None else None,
            object_ref=packet.object_ref,
            action=packet.requested_action,
            pre_state_hash=pre_state_hash,
            post_state_hash=post_state_hash,
        )


class InMemoryMeasuredResource:
    """Concrete mutable state object used only by the measurement fixture."""

    def __init__(self, initial: Mapping[str, Mapping[str, Any]]) -> None:
        self._objects = {
            key: dict(value)
            for key, value in initial.items()
        }

    def _observe(self, object_ref: str) -> Optional[str]:
        state = self._objects.get(object_ref)
        if state is None:
            return None
        return canonical_state_hash(state)

    def _write(self, object_ref: str, payload: Mapping[str, Any]) -> None:
        if object_ref not in self._objects:
            raise KeyError(object_ref)
        self._objects[object_ref] = dict(payload)

    def snapshot(self, object_ref: str) -> Optional[dict[str, Any]]:
        state = self._objects.get(object_ref)
        return None if state is None else dict(state)


class InMemoryStateObserver:
    """Read-only view over InMemoryMeasuredResource."""

    def __init__(self, resource: InMemoryMeasuredResource) -> None:
        self._resource = resource

    def observe_state_hash(self, object_ref: str) -> Optional[str]:
        return self._resource._observe(object_ref)


class InMemoryWriteAdapter:
    """Write-only fixture adapter with an observable call count."""

    def __init__(self, resource: InMemoryMeasuredResource) -> None:
        self._resource = resource
        self.mutation_calls = 0

    def apply(
        self,
        *,
        object_ref: str,
        action: str,
        payload: Mapping[str, Any],
    ) -> None:
        if action != "write":
            raise ValueError("UNSUPPORTED_FIXTURE_ACTION")
        self.mutation_calls += 1
        self._resource._write(object_ref, payload)
