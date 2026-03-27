"""ADMISSIBILITY_ALGEBRA_v1 — Formal primitives for execution-boundary governance.

Defines the minimal algebra over which all governance decisions are computed.

Primitives: Actor, Action, Object, State, Authority, Time, Dependency, Verdict
Verdicts:   {ALLOW, DENY, HOLD, ESCALATE}
Hard rule:   execute(action) iff verdict(action) == ALLOW

No derived execution. No implied authority. No inherited commit rights.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import FrozenSet


# ---------------------------------------------------------------------------
# Verdict algebra
# ---------------------------------------------------------------------------

class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    HOLD = "HOLD"
    ESCALATE = "ESCALATE"

    @staticmethod
    def executable() -> FrozenSet[Verdict]:
        """Only ALLOW may produce execution."""
        return frozenset({Verdict.ALLOW})

    @staticmethod
    def blocking() -> FrozenSet[Verdict]:
        """All verdicts that prevent execution."""
        return frozenset({Verdict.DENY, Verdict.HOLD, Verdict.ESCALATE})


# ---------------------------------------------------------------------------
# Primitives
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Actor:
    """An identified principal requesting an action."""
    actor_id: str
    roles: tuple[str, ...] = ()

    def __post_init__(self):
        if not self.actor_id or not self.actor_id.strip():
            raise ValueError("actor_id must be non-empty")


@dataclass(frozen=True)
class Action:
    """A named operation against a target object.

    Delegates classification to the ActionRegistry (Layer 1).
    The REGISTRY/MUTATING/HIGH_RISK frozensets are kept as backward-
    compatible class attributes derived from DEFAULT_REGISTRY.
    """
    action_type: str

    # Backward-compatible class attributes — derived from DEFAULT_REGISTRY.
    # Importing here would create a circular import, so we use a lazy
    # classmethod pattern: _registry is set after action_registry.py loads.
    _registry = None  # type: ignore[assignment]

    # Keep the frozensets as backward-compatible fallbacks.
    # These are overridden by the registry when available.
    REGISTRY: frozenset = frozenset({"read", "write", "delete", "deploy", "commit"})
    MUTATING: frozenset = frozenset({"write", "delete", "deploy", "commit"})
    HIGH_RISK: frozenset = frozenset({"delete", "deploy", "commit"})

    @classmethod
    def set_registry(cls, registry) -> None:
        """Bind the Action class to a governed ActionRegistry.

        Called once at import time by action_registry.py.
        After this, is_known/is_mutating/is_high_risk delegate to the registry.
        """
        cls._registry = registry

    def is_known(self) -> bool:
        if self._registry is not None:
            return self._registry.is_known(self.action_type)
        return self.action_type in self.REGISTRY

    def is_mutating(self) -> bool:
        if self._registry is not None:
            return self._registry.is_mutating(self.action_type)
        return self.action_type in self.MUTATING

    def is_high_risk(self) -> bool:
        if self._registry is not None:
            return self._registry.is_high_risk(self.action_type)
        return self.action_type in self.HIGH_RISK

    def registry_entry(self):
        """Return the full ActionRegistryEntry for this action, or None."""
        if self._registry is not None:
            return self._registry.lookup(self.action_type)
        return None


@dataclass(frozen=True)
class Object:
    """A target resource identified by reference."""
    object_ref: str

    def __post_init__(self):
        if not self.object_ref or not self.object_ref.strip():
            raise ValueError("object_ref must be non-empty")


@dataclass(frozen=True)
class StateSnapshot:
    """Deterministic snapshot of system state at evaluation time."""
    state_hash: str
    epoch: int = 0

    def __post_init__(self):
        if not self.state_hash:
            raise ValueError("state_hash must be non-empty")


@dataclass(frozen=True)
class Authority:
    """An authority claim bound to an actor at a point in time."""
    authority_type: str  # e.g. "admin", "operator", "reviewer"
    issued_at: int       # epoch timestamp
    expires_at: int      # epoch timestamp
    nonce: str           # unique per issuance

    VALID_TYPES: frozenset = frozenset({"admin", "operator", "reviewer"})

    def is_valid_type(self) -> bool:
        return self.authority_type in self.VALID_TYPES

    def is_fresh(self, current_time: int) -> bool:
        """Authority must not be stale. Time is load-bearing."""
        return self.issued_at <= current_time <= self.expires_at

    def is_expired(self, current_time: int) -> bool:
        return current_time > self.expires_at


@dataclass(frozen=True)
class Dependency:
    """A prerequisite that must be satisfied before evaluation."""
    dep_id: str
    satisfied: bool
    evidence_hash: str = ""


# ---------------------------------------------------------------------------
# Forbidden transitions (negative-space governance)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ForbiddenTransition:
    """An explicitly prohibited state transition."""
    from_condition: str
    to_condition: str
    reason: str


# The shape of the system is defined as much by what cannot happen.
FORBIDDEN_TRANSITIONS = frozenset({
    ForbiddenTransition("no_authority", "execute_mutating", "authority_required_for_mutation"),
    ForbiddenTransition("expired_authority", "execute_any", "stale_authority_rejected"),
    ForbiddenTransition("unknown_action", "execute_any", "closed_world_action_set"),
    ForbiddenTransition("unresolved_dependency", "execute_dependent", "dependency_must_resolve"),
    ForbiddenTransition("state_hash_mismatch", "execute_stateful", "state_must_be_current"),
    ForbiddenTransition("non_exec_scope", "execute_any", "scope_monotonicity"),
    ForbiddenTransition("inherited_authority", "execute_fresh_required", "fresh_authority_required"),
    ForbiddenTransition("absent_object", "mutate_object", "object_must_exist"),
})


# ---------------------------------------------------------------------------
# Decision lattice
# ---------------------------------------------------------------------------

# Verdict ordering: ALLOW < HOLD < ESCALATE < DENY
# When combining verdicts, the most restrictive wins.
VERDICT_ORDER = {
    Verdict.ALLOW: 0,
    Verdict.HOLD: 1,
    Verdict.ESCALATE: 2,
    Verdict.DENY: 3,
}


def combine_verdicts(*verdicts: Verdict) -> Verdict:
    """Combine multiple verdicts. Most restrictive wins."""
    if not verdicts:
        raise ValueError("Cannot combine zero verdicts")
    return max(verdicts, key=lambda v: VERDICT_ORDER[v])


# ---------------------------------------------------------------------------
# Admissibility predicate
# ---------------------------------------------------------------------------

def is_admissible(verdict: Verdict) -> bool:
    """Only ALLOW is admissible for execution."""
    return verdict == Verdict.ALLOW


def may_execute(verdict: Verdict) -> bool:
    """Alias. execute(action) iff verdict(action) == ALLOW."""
    return verdict == Verdict.ALLOW
