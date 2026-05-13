# Public Disclosure Boundary

This repository is a public inspection surface.

It is intended to show enough for a reader to understand the claim, inspect the evidence, and see the claim limit.

It is not intended to disclose the full architecture, orchestration logic, runtime substrate, commercial implementation path, private evaluator logic, or protected system design.

## What this public surface may show

- The claim being made
- The evidence object attached to that claim
- The public inspection path
- The refusal, hold, or output behaviour being demonstrated
- The receipt or trace shape
- The claim boundary
- The status of the artefact
- What the artefact does not prove

## What this public surface does not disclose

- Full system architecture
- Private routing or orchestration logic
- Runtime substrate
- Commercial implementation path
- Integration strategy
- Private evaluator logic
- Deployment model
- Customer-specific corridors
- Protected governance machinery
- Internal sequencing between components

## Claim boundary

A public proof object proves only the claim attached to it.

It must not be treated as proof of the whole system unless the repository explicitly says so.

A local proof object may demonstrate one link in the chain, such as:

- a refusal event
- a HOLD state
- a replay trace
- a claim boundary
- an admissibility check
- a receipt shape
- an execution stop

That does not mean it proves the entire governance architecture.

## Inspection standard

The standard for this public surface is:

```text
claim -> evidence object -> inspection path -> claim limit
```

This allows claims to be inspected without requiring disclosure of protected machinery.

## Status

Public proof surface.

Not full architecture disclosure.

Not production deployment evidence unless explicitly stated.

Not a claim of adoption, certification, compliance, or standardisation unless explicitly stated.
