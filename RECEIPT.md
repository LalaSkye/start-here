# Repository Receipt

Date: 2026-05-11
Repository: `LalaSkye/start-here`
Evidence class: entry surface / runnable path-local demonstration / bounded artefact

## Object

`start-here` is the entry surface for the execution-boundary governance repo chain.

It provides a minimal runnable demonstration showing a system deciding whether an action may execute before any state mutation occurs.

## What this repository does

- Provides a quick runnable inspection route.
- Demonstrates runtime decisions before execution on the demonstrated path.
- Shows explicit authority handling, replay denial, malformed-input denial, and contradiction collapse.
- Routes readers to deeper repositories in the execution-boundary chain.
- Provides a small proof surface that can be inspected in one sitting.

## What this repository does not do

This repository does not claim:

- adoption
- certification
- compliance
- endorsement
- production readiness
- field validation
- standardisation
- path-universal coverage
- enterprise deployment
- cross-decision hash chaining
- that every downstream route to consequence is controlled

## Proof surface

Useful inspection questions:

1. Can the demo be run locally?
2. Are decisions produced before execution?
3. Are invalid, ambiguous, malformed, replayed, or contradictory inputs denied on the demonstrated path?
4. Does the commit gate require a valid decision record before state mutation?
5. Are current hardening gaps stated rather than hidden?

## Related evidence

- README: `README.md`
- Demo runner: `run_demo.py`
- Core gate: `core/commit_gate.py`
- Tests: `tests/`
- Deeper route map: `links.md`

## Claim boundary

Allowed claim:

> This repository is a minimal runnable entry surface for inspecting path-local execution-boundary behaviour before state mutation.

Not allowed:

> This repository proves adoption, compliance, certification, production readiness, field validation, or path-universal governance coverage.

## Receipt line

This is the front door. It shows the route; it is not the whole castle.
