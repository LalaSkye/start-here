"""ACTION_REGISTRY_v1 — Layer 1: Governed action surface.

The Action Registry is the single source of truth for what action classes
exist and what each class requires.  It is a governed artefact: frozen,
explicit, and bound at parse-time.

Canonical role (from the freeze):
    Layer 1 — Action Registry
    Defines which action classes exist and what each class requires.

Every action that reaches the evaluator must be present in the registry.
Unknown actions → DENY.  Incomplete registry entries → DENY.

Design constraints:
    - ActionRegistryEntry is frozen (immutable after construction).
    - The registry itself is frozen after construction.
    - All fields are mandatory.  No optional fields.  No defaults.
    - Unknown action_id → not in registry → DENY.
    - The registry is a governed artefact: changes require a version bump.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class ReversibilityClass(str, Enum):
    REVERSIBLE = "reversible"
    IRREVERSIBLE = "irreversible"
    CONDITIONALLY_REVERSIBLE = "conditionally_reversible"


class CommitBoundary(str, Enum):
    NONE = "none"
    STANDARD = "standard"
    ELEVATED = "elevated"
    CRITICAL = "critical"


@dataclass(frozen=True)
class ActionRegistryEntry:
    """A single entry in the Action Registry. All fields mandatory."""
    action_id: str
    commit_boundary: CommitBoundary
    authority_required: str
    reversibility_class: ReversibilityClass
    evidence_required: tuple[str, ...]
    owner_of_record: str

    @property
    def is_mutating(self) -> bool:
        return self.commit_boundary != CommitBoundary.NONE

    @property
    def is_high_risk(self) -> bool:
        return self.commit_boundary in (CommitBoundary.ELEVATED, CommitBoundary.CRITICAL)


class ActionRegistry:
    """Frozen, governed registry of action classes."""

    def __init__(self, entries: list[ActionRegistryEntry], version: str = "1.0.0"):
        self._version = version
        self._entries: dict[str, ActionRegistryEntry] = {}
        for entry in entries:
            if entry.action_id in self._entries:
                raise ValueError(f"Duplicate action_id in registry: '{entry.action_id}'")
            self._entries[entry.action_id] = entry
        self._frozen = True

    @property
    def version(self) -> str:
        return self._version

    def lookup(self, action_id: str) -> Optional[ActionRegistryEntry]:
        return self._entries.get(action_id)

    def is_known(self, action_id: str) -> bool:
        return action_id in self._entries

    def is_mutating(self, action_id: str) -> bool:
        entry = self._entries.get(action_id)
        return entry.is_mutating if entry else False

    def is_high_risk(self, action_id: str) -> bool:
        entry = self._entries.get(action_id)
        return entry.is_high_risk if entry else False

    def all_action_ids(self) -> frozenset[str]:
        return frozenset(self._entries.keys())

    def all_entries(self) -> tuple[ActionRegistryEntry, ...]:
        return tuple(self._entries.values())

    def __contains__(self, action_id: str) -> bool:
        return action_id in self._entries

    def __len__(self) -> int:
        return len(self._entries)


DEFAULT_REGISTRY = ActionRegistry(
    version="1.0.0",
    entries=[
        ActionRegistryEntry(
            action_id="read",
            commit_boundary=CommitBoundary.NONE,
            authority_required="reviewer",
            reversibility_class=ReversibilityClass.REVERSIBLE,
            evidence_required=("actor_bound", "action_registered", "policy_version_match"),
            owner_of_record="platform",
        ),
        ActionRegistryEntry(
            action_id="write",
            commit_boundary=CommitBoundary.STANDARD,
            authority_required="operator",
            reversibility_class=ReversibilityClass.CONDITIONALLY_REVERSIBLE,
            evidence_required=("actor_bound", "action_registered", "policy_version_match", "object_exists", "authority_fresh", "authority_sufficient", "state_precondition"),
            owner_of_record="platform",
        ),
        ActionRegistryEntry(
            action_id="delete",
            commit_boundary=CommitBoundary.ELEVATED,
            authority_required="admin",
            reversibility_class=ReversibilityClass.IRREVERSIBLE,
            evidence_required=("actor_bound", "action_registered", "policy_version_match", "object_exists", "authority_fresh", "authority_sufficient", "state_precondition"),
            owner_of_record="platform",
        ),
        ActionRegistryEntry(
            action_id="deploy",
            commit_boundary=CommitBoundary.CRITICAL,
            authority_required="admin",
            reversibility_class=ReversibilityClass.CONDITIONALLY_REVERSIBLE,
            evidence_required=("actor_bound", "action_registered", "policy_version_match", "object_exists", "authority_fresh", "authority_sufficient", "state_precondition"),
            owner_of_record="platform",
        ),
        ActionRegistryEntry(
            action_id="commit",
            commit_boundary=CommitBoundary.CRITICAL,
            authority_required="admin",
            reversibility_class=ReversibilityClass.IRREVERSIBLE,
            evidence_required=("actor_bound", "action_registered", "policy_version_match", "object_exists", "authority_fresh", "authority_sufficient", "state_precondition"),
            owner_of_record="platform",
        ),
    ],
)


# ---------------------------------------------------------------------------
# Bind the default registry to the Action class at import time.
# ---------------------------------------------------------------------------

from core.algebra import Action  # noqa: E402

Action.set_registry(DEFAULT_REGISTRY)
