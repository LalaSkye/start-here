"""BOUNDARY_CONTEXT_v1 — Commit boundary validation.

The boundary context ensures a valid-looking decision record cannot be
used at the wrong boundary.  A record authorised for staging must not
cross the production commit boundary.

Without it:
    A record can pass all checks and still be applied in the wrong
    environment.  That's a lateral movement vulnerability.

With it:
    The gate checks that the action is being committed at the correct
    boundary (environment + boundary class).  Wrong boundary = denied.

Design constraints:
    - BoundaryContext is a frozen dataclass (immutable).
    - Boundary validation is a pure function.
    - Fail-closed: missing context or unknown environment = denied.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


class Environment:
    """Known environments.  Closed set — unknown = denied."""
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"
    ALL = frozenset({"dev", "staging", "production"})

    @staticmethod
    def is_known(env: str) -> bool:
        return env in Environment.ALL


class BoundaryClass:
    """Known boundary classes.  Closed set — unknown = denied."""
    PRE_MERGE = "pre_merge"
    MERGE_TO_MAIN = "merge_to_main"
    DEPLOY = "deploy"
    RUNTIME = "runtime"
    ALL = frozenset({"pre_merge", "merge_to_main", "deploy", "runtime"})

    @staticmethod
    def is_known(bc: str) -> bool:
        return bc in BoundaryClass.ALL


ALLOWED_BOUNDARIES: dict[str, frozenset[str]] = {
    Environment.DEV: frozenset({
        BoundaryClass.PRE_MERGE,
        BoundaryClass.MERGE_TO_MAIN,
    }),
    Environment.STAGING: frozenset({
        BoundaryClass.PRE_MERGE,
        BoundaryClass.MERGE_TO_MAIN,
        BoundaryClass.DEPLOY,
    }),
    Environment.PRODUCTION: frozenset({
        BoundaryClass.DEPLOY,
        BoundaryClass.RUNTIME,
    }),
}


@dataclass(frozen=True)
class BoundaryContext:
    """Immutable description of where the commit is happening."""
    environment: str
    boundary_class: str


@dataclass(frozen=True)
class BoundaryResult:
    """Result of boundary validation."""
    valid: bool
    denial_reason: str = ""


def validate_boundary(context: Optional[BoundaryContext]) -> BoundaryResult:
    """Validate that the commit is happening at an allowed boundary.
    Pure function. Fail-closed."""
    if context is None:
        return BoundaryResult(valid=False, denial_reason="No boundary context provided.")

    if not Environment.is_known(context.environment):
        return BoundaryResult(valid=False, denial_reason=f"Unknown environment: '{context.environment}'.")

    if not BoundaryClass.is_known(context.boundary_class):
        return BoundaryResult(valid=False, denial_reason=f"Unknown boundary class: '{context.boundary_class}'.")

    allowed = ALLOWED_BOUNDARIES.get(context.environment, frozenset())
    if context.boundary_class not in allowed:
        return BoundaryResult(
            valid=False,
            denial_reason=f"Boundary class '{context.boundary_class}' is not permitted in environment '{context.environment}'.",
        )

    return BoundaryResult(valid=True)
