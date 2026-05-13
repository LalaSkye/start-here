# Publication Lock

This file controls future public releases in this corpus.

No new public repository, README expansion, diagram, route list, adapter note, architecture section, or cross-repo index should be published unless it passes this lock.

## Hard rule

Public material may show a bounded claim, a local evidence object, an inspection path, and the claim limit.

Public material must not disclose, imply, or reconstruct protected architecture.

## Do not publish

Do not publish material that exposes:

- internal layering
- component sequencing
- orchestration logic
- repo-to-repo system composition
- runtime substrate
- deployment model
- commercial implementation path
- private evaluator logic
- adapter bridges from concept to runtime
- diagrams showing how proof objects connect
- file maps that identify protected component roles

## Required public shape

Every public artefact should reduce to:

```text
claim -> evidence object -> inspection path -> claim limit
```

If it cannot be reduced to that shape, hold it private.

## Required pre-publication checks

Before publishing, answer:

1. What exact claim does this artefact support?
2. What evidence object supports that claim?
3. What does this artefact explicitly not prove?
4. Could a skilled reader infer architecture, sequencing, or orchestration from it?
5. Does any diagram, file list, route list, or adapter note reveal connective tissue?
6. Would the artefact still make sense if all system-map language were removed?

If any answer creates architecture leakage, do not publish.

## Default decision

When uncertain:

```text
HOLD PRIVATE
```

Reputation should be built through bounded evidence, timestamps, restraint, and claim limits.

Not through architecture disclosure.
