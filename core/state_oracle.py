"""STATE_ORACLE_v1 — Pre-state verification at commit boundary.

The state oracle lets the pure commit gate compare a caller-presented
`state_before_hash` with the oracle's current view of that object.

Without it:
    the gate does not verify the caller-presented pre-state.

With it:
    the gate asks "what is the current state hash?" and compares that result
    with `state_before_hash`. A mismatch or unknown state denies commit
    permission.

The oracle does not observe post-state, apply mutation, prove custody of the
underlying world object, or turn `state_after_hash` into measurement evidence.

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
