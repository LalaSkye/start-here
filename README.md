# start-here

A path-local demo for one question: can the demonstrated action reach state
mutation without a valid decision record?

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

The narrow question this repo answers is:

**Can an action reach state mutation without a valid decision record on the demonstrated path?**

Expected answer:

**No.**

## What you will see

Twelve scenarios producing three runtime decisions:

```text
ALLOW
DENY
ESCALATE
```

The demonstrated path includes allowed, denied, ambiguous, malformed, contradiction, replay, and unknown-action cases.

## What this proves

On the demonstrated path:

- not every proposed action is allowed to run
- the decision occurs before state mutation
- ambiguous inputs do not silently pass
- malformed inputs fail closed
- replay attempts are blocked
- contradiction cases do not proceed
- decision records are canonically hashed

## Current hardening gap

This repository demonstrates per-record canonical hashing, not cross-decision hash chaining.

## Canonical invariant

> **No valid decision record -> no state mutation on the demonstrated path.**

That invariant belongs to this demo. Do not read it as the claim of `commit-gate-core`.

## Tests

```
python -m pytest tests/ -v
```

## Scope note

Implementation files are present so the demonstrated path can be run and inspected.

This README does not publish an architecture map, component sequence, orchestration model, or protected system design.

## Where next

This repo is the entry surface only.

Authorize-only kernel (binds payload bytes; does not apply them):

[https://github.com/LalaSkye/commit-gate-core](https://github.com/LalaSkye/commit-gate-core)

Standing versus admission lab:

[https://github.com/LalaSkye/obligation-bound-policy-admission-lab](https://github.com/LalaSkye/obligation-bound-policy-admission-lab)

Those are separate objects. This demo's mutation-path evidence does not
transfer to either one.

---

This repository demonstrates deterministic control using standard engineering techniques. No proprietary frameworks or external implementations are used.
