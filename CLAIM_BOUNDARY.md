# Claim Boundary

Date: 2026-05-11
Repository: `LalaSkye/start-here`

## Purpose

This file keeps the repository's claim surface bounded to its role as a runnable inspection surface.

## Allowed claims

This repository may be described as:

- a bounded artefact
- an inspection surface
- a runnable path-local demonstration
- a minimal inspection route
- a bounded inspection object

## Mechanism claims

Safe wording for the original decision/commit demo:

> `start-here` demonstrates a minimal path where invalid authority or commit conditions are refused before permission to proceed is returned.

Safe wording for the measured-mutation fixture:

> On one exact instrumented in-memory write path, the included denial control makes no effect call and produces equal first/final reads of the same bound resource; the authorised control writes that same resource and produces unequal first/final reads under the fixed `canonical-json-sha256:v1` rule.

These are separate bounded proof objects. Evidence from one must not be used to enlarge the claim of the other.

## Evidence claim

Safe wording:

> The repository provides a runnable demo, core files, tests, and route links for inspecting execution-boundary behaviour.

## Forbidden claims

Do not claim:

- adoption
- validation
- endorsement
- certification
- compliance
- production readiness
- field impact
- proven market demand
- path-universal coverage
- standardisation
- enterprise deployment
- cross-decision hash chaining
- control over all downstream consequence routes

## Known gap boundary

The repository currently demonstrates per-record canonical hashing, not cross-decision hash chaining.

The measured-mutation fixture binds one exact `InMemoryMeasuredResource` into the boundary. Observation and effect are not separately injectable: both address that same instance and `object_ref`, and the hash rule is fixed. The resource lock closes interleaving only through this fixture's own in-memory read/write methods during one attempt.

It does not establish production atomicity, independent third-party observation, durable execution custody, or elimination of every possible effect-capable path outside that fixture.

Do not claim cross-decision receipt-chain custody until the implementation and tests prove it.

## Public sentence

> This is a runnable object for inspecting a narrow decision/commit demo plus a separate measured in-memory mutation fixture. It does not designate a current public starting point.

## Stop line

If the evidence is not in the demo, code, tests, route map, receipt, or linked proof surface, do not claim it.
