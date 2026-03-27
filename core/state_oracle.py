"""STATE_ORACLE_v1 — State verification at commit boundary.

The state oracle is the mechanism that makes the commit gate truthful
about the state it claims to change.

Without it:
    The gate accepts state_before_hash and state_after_hash as arguments
    but never verifies them against reality.

With it:
    The gate asks the oracle "what is the current state hash?" and
    compares that to state_before_hash.  If they don't match, the
    commit is denied.  You cannot mutate state you don't actually hold.

Design constraints:
    - StateOracle is a protocol (abstract interface).
    - Implementations are injected, not hard-coded.
    - The oracle is read-only.  It observes state.  It never mutates.
    - The oracle is deterministic for a given state.
    - Fail-closed: if the oracle cannot determine state, it returns None
      and the gate denies the commit.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional


class StateOracle(ABC):
    """Abstract interface for state verification."""

    @abstractmethod
    def current_state_hash(self, object_ref: str) -> Optional[str]:
        """Return the current state hash for the given object, or None."""
        ...


class InMemoryStateOracle(StateOracle):
    """Simple in-memory state oracle for testing."""

    def __init__(self, state: Optional[dict[str, str]] = None):
        self._state: dict[str, str] = dict(state) if state else {}

    def current_state_hash(self, object_ref: str) -> Optional[str]:
        return self._state.get(object_ref)

    def set_state(self, object_ref: str, state_hash: str) -> None:
        self._state[object_ref] = state_hash

    def remove_state(self, object_ref: str) -> None:
        self._state.pop(object_ref, None)


class NullStateOracle(StateOracle):
    """Oracle that always returns None (state unknown)."""

    def current_state_hash(self, object_ref: str) -> Optional[str]:
        return None
