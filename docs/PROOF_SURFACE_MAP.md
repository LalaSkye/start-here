# Proof Surface Map

**Claim boundary:** This is a public proof-surface collection, not a production platform, certification claim, adoption claim, or standard. Each entry describes a bounded inspection surface only.

This document maps the public repositories that together form a proof-surface collection. For each repo, it records:

1. **What it is for** — the artefact's scope.
2. **What question it helps inspect** — the reviewer-facing question it lets you examine.
3. **What it does not prove** — out-of-scope claims the repo does not establish.

---

## commit-gate-core

- **What it is for:** A minimal core surface for a commit-time gate concept.
- **What question it helps inspect:** Whether a decision can be resolved at commit boundary before state mutation occurs on the demonstrated path.
- **What it does not prove:** Production readiness, adoption, coverage of all commit paths, or universal applicability.

## runtime-commit-gate-demo

- **What it is for:** A runnable demonstration of a commit-gate path at runtime.
- **What question it helps inspect:** Whether the demonstrated runtime path routes through a gate before commit on inspected inputs.
- **What it does not prove:** Behaviour on unmodelled inputs, performance characteristics, or fitness for any deployed system.

## execution-gate-litmus

- **What it is for:** A litmus surface for execution-boundary behaviour.
- **What question it helps inspect:** Whether a specific input class is admitted or refused at the execution boundary on the demonstrated path.
- **What it does not prove:** Completeness of the litmus set or coverage of all execution paths.

## fail-closed-ai

- **What it is for:** A surface demonstrating a fail-closed default on an inspected path.
- **What question it helps inspect:** Whether the demonstrated path defaults to refusal when preconditions are not met.
- **What it does not prove:** Fail-closed behaviour across all paths, deployments, or model configurations.

## transition-admissibility-gate

- **What it is for:** A surface for inspecting whether a state transition is admissible before it is taken.
- **What question it helps inspect:** Whether an inadmissible transition is refused at the gate on inspected cases.
- **What it does not prove:** Admissibility rules are complete, correct in all domains, or suitable for any specific system.

## receipt-chain-core

- **What it is for:** A core surface for a per-decision receipt artefact concept.
- **What question it helps inspect:** Whether a decision produces an inspectable receipt on the demonstrated path.
- **What it does not prove:** Cross-decision chaining, tamper-evidence guarantees beyond the demonstrated path, or auditability at scale.

## refusal-receipt-chain

- **What it is for:** A surface demonstrating receipts emitted on refusal decisions.
- **What question it helps inspect:** Whether refusals on the demonstrated path emit an inspectable receipt artefact.
- **What it does not prove:** That all refusals in any system are receipted, or that the receipt format is canonical.

## inspection-surface

- **What it is for:** A reader-facing surface for inspecting the artefacts in this collection.
- **What question it helps inspect:** Where to look to examine the bounded claims of each artefact.
- **What it does not prove:** That the inspection surface is exhaustive or that all reviewer questions are answerable from it.

## deterministic-lexicon

- **What it is for:** A bounded lexicon for terms used across the collection.
- **What question it helps inspect:** Whether terms are used consistently within the demonstrated artefacts.
- **What it does not prove:** Lexical universality, standardisation, or applicability outside this collection.

## policy-lint

- **What it is for:** A lint surface for policy-shaped artefacts.
- **What question it helps inspect:** Whether a policy artefact passes the bounded lint checks defined in the repo.
- **What it does not prove:** That a passing artefact is correct, safe, or fit for any deployed policy use.

## invariant-lock

- **What it is for:** A surface demonstrating invariant locking on the inspected path.
- **What question it helps inspect:** Whether a stated invariant is held across the demonstrated path.
- **What it does not prove:** Invariant preservation under all inputs, environments, or unmodelled conditions.

---

## Boundary recap

- Each repo above is a bounded artefact and inspection surface.
- No entry asserts production readiness, certification, adoption, standardisation, or universal runtime-governance coverage.
- This map does not compare these artefacts to other systems.
