# start-here

> **Public routing status:** Under revalidation. No repository is currently designated as the public starting point. This repository remains available as a bounded inspection object.

A bounded inspection surface with two distinct proof objects: the original
decision/commit demo and a measured in-memory mutation fixture. Evidence does
not transfer between them.

## Public disclosure boundary

This repository is a public inspection surface, not full architecture disclosure.

It shows a bounded claim, a minimal evidence object, a public inspection path, and the claim limit.

See [`PUBLIC_DISCLOSURE_BOUNDARY.md`](PUBLIC_DISCLOSURE_BOUNDARY.md).

## Proof-surface boundary

This repository is a bounded, path-local proof surface.

It does not claim:

- production readiness
- compliance or certification
- enterprise deployment
- path-universal governance
- tamper-proofing
- non-bypassability

It demonstrates a narrow execution-control behaviour that can be inspected, tested, and challenged.

It should be read as a bounded proof object, not as a complete governance architecture.

## What this does not prove

This repository does not prove adoption, certification, standardisation, production readiness, or path-universal deployment coverage.

It demonstrates a bounded execution-control surface on the demonstrated path.

It is not `commit-gate-core`. That repo is an authorize-only kernel and does not apply payloads.

## Run It

```
git clone https://github.com/LalaSkye/start-here.git
cd start-here
python run_demo.py
```

No dependencies beyond Python 3.8+. No install step.

Run a single scenario:

```
python run_demo.py --scenario deny
```

## Inspection path

Run the demo and tests.

The original decision demo answers:

**Can the demonstrated decision/commit path permit a governed action without a valid decision record?**

Expected answer:

**No.**

The separate measured-mutation fixture answers:

**When that bounded fixture is denied, does the concrete state stay unchanged; and when its authorised control runs, is the resulting state change observed from the resource rather than supplied by the caller?**

Expected answer:

**Yes.**

## What you will see

Twelve scenarios producing three runtime decisions:

```text
ALLOW
DENY
ESCALATE
```

The demonstrated path includes allowed, denied, ambiguous, malformed, contradiction, replay, and unknown-action cases.

## What this proves

On the original decision/commit path:

- not every proposed action is allowed to run
- invalid authority or commit conditions are refused before permission is returned
- ambiguous inputs do not silently pass
- malformed inputs fail closed
- replay attempts are blocked
- contradiction cases do not proceed
- decision records are canonically hashed

On the separate measured-mutation fixture:

- the pre-state hash is read from a concrete in-memory resource
- the gate performs a second read from the same bound in-memory resource at the commit boundary
- the included denial control does not call the effect path and its two reads of that same resource are equal
- the authorised control writes that same resource and a later read produces a different post-state hash
- the measurement boundary accepts no caller-supplied post-state hash, observer or effect implementation
- the effect return channel is discarded; only a later bound-resource read can populate post-state evidence
- pre- and post-observation failure paths are explicit and cannot emit a MEASURED success code
- a write-then-raise specimen reports effect failure and the observed state change separately

## Current hardening gap

This repository demonstrates per-record canonical hashing, not cross-decision hash chaining.

## Canonical invariant

> **No valid decision record -> no commit permission on the demonstrated commit-gate path.**

The separate measured fixture then checks one concrete in-memory resource. In its included denial control, no effect call occurs and the two bound-resource observations are equal. Do not transfer either claim outside its demonstrated object.

## Tests

```
python -m pytest tests/ -v
```

## Scope note

Implementation files are present so the demonstrated path can be run and inspected.

This README does not publish an architecture map, component sequence, orchestration model, or protected system design.

## Measured mutation fixture

Run the bounded fixture:

```bash
python examples/measured_mutation.py
python -m pytest tests/test_core/test_measured_mutation.py -v
```

The fixture binds one exact `InMemoryMeasuredResource` into the measurement boundary. Observation and effect are not separately injectable. Both address the same resource instance and the same `object_ref`, and observations use the fixed `canonical-json-sha256:v1` rule.

The existing commit gate decides whether the effect may proceed and performs a second live-state read through an adapter over that same resource. The effect then writes that same resource. A final read of that resource supplies the post-state measurement.

The measurement boundary does **not** accept a `state_after_hash`, observer, effect adapter or hash rule from its caller. The legacy commit gate still receives a private sentinel for its older result shape, but that sentinel is never copied into the measurement receipt.

The tests include an authorised state-changing control; an unchanged denial control; same-resource constructor binding; pre-state drift between the first and gate reads; pre- and post-observation failure; rejection of a caller-supplied post-state hash; an effect return equal to the real post hash whose return channel is nevertheless discarded; failure before write; partial write followed by an exception; and explicit sentinel exclusion from the receipt.

**Claim limit:** this is one instrumented in-memory resource and one governed
write path. It is not production atomicity, independent third-party
observation, path-universal enforcement, deployment, certification or
compliance.

## Where next

This repo remains an inspection surface only.

Authorize-only kernel (binds payload bytes; does not apply them):

[https://github.com/LalaSkye/commit-gate-core](https://github.com/LalaSkye/commit-gate-core)

Standing versus admission lab:

[https://github.com/LalaSkye/obligation-bound-policy-admission-lab](https://github.com/LalaSkye/obligation-bound-policy-admission-lab)

Those are separate objects. This demo's mutation-path evidence does not
transfer to either one.

---

This repository demonstrates deterministic control using standard engineering techniques. No proprietary frameworks or external implementations are used.
