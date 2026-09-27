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
- Measured mutation boundary: `core/measured_mutation.py`
- Measured fixture runner: `examples/measured_mutation.py`
- Measured fixture tests: `tests/test_core/test_measured_mutation.py`
- Tests: `tests/`
- Deeper route map: `links.md`

## Measured fixture receipt

The measured-mutation fixture is a separate bounded object inside this repository.

Its receipt records:

- whether the existing gate permitted the attempt
- whether the effect adapter was attempted and completed
- the state hash observed from the concrete in-memory resource before the attempt
- the state hash observed from that resource after the attempt
- whether the observations establish a state change

The boundary accepts no caller-supplied post-state hash. An effect adapter return
value is not treated as measurement evidence.

A denial control must show no effect-adapter call and equal observed pre/post
state. The authorised control must show one effect call and unequal observed
pre/post state. Failure to observe either side is not reported as a successful
measurement.

This is not a claim of production atomicity, independent third-party
observation, universal path elimination, deployment or certification.

## Claim boundary

Allowed claim:

> This repository is a minimal runnable inspection surface containing a bounded decision/commit demo and a separate measured in-memory mutation fixture.

Not allowed:

> This repository proves adoption, compliance, certification, production readiness, field validation, or path-universal governance coverage.

## Receipt line

This is the front door. It shows the route; it is not the whole castle.
