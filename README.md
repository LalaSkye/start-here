# start-here

**Research Surface Map:** [lalaSkye.github.io/inspection-surface](https://lalaskye.github.io/inspection-surface/) — full index, provenance, and cross-links


**Ricky Jones / AlvianTech / TrinityOS — execution-boundary AI governance.**

Governance becomes real at the execution boundary: where an AI-supported system must either prove authority to act or fail closed with an inspectable refusal receipt.

## Public disclosure boundary

This repository is a public inspection surface, not full architecture disclosure.

It shows a bounded claim, a minimal evidence object, a public inspection path, and the claim limit.

See [`PUBLIC_DISCLOSURE_BOUNDARY.md`](PUBLIC_DISCLOSURE_BOUNDARY.md).

## Proof-surface boundary

This repository is a research-grade, path-local proof surface.

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

## Tests

```
python -m pytest tests/ -v
```

## Scope note

Implementation files are present so the demonstrated path can be run and inspected.

This README does not publish an architecture map, component sequence, orchestration model, or protected system design.

## Where next

This repo is the entry surface only.

Primary execution-boundary proof surface:

[https://github.com/LalaSkye/commit-gate-core](https://github.com/LalaSkye/commit-gate-core)

Author / identity surface:

[https://github.com/LalaSkye](https://github.com/LalaSkye)

LinkedIn public surface:

[https://www.linkedin.com/in/ricky-jones-trinityos](https://www.linkedin.com/in/ricky-jones-trinityos)

Deeper repo route:

See [`links.md`](links.md) for deeper repos.

---

This repository demonstrates deterministic control using standard engineering techniques. No proprietary frameworks or external implementations are used.
