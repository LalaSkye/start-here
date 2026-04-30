# Reasoning Chessboard Adapter v1.0

**Status:** FROZEN  
**Class:** Governance adapter  
**Scope:** Maps the Reasoning Chessboard formation onto the GitHub runtime-governance corpus.

---

## Purpose

This adapter explains how the GitHub corpus implements the same structure as the Reasoning Chessboard.

The board language is human-readable.

The repositories are runtime-readable.

Both preserve the same invariant:

> Admissibility precedes movement.

---

## Boundary

This repository demonstrates one bounded control surface.

It does not claim to solve governance generally.

It shows where movement is allowed, where it is refused, and what evidence proves the refusal.

If the required condition is not present:

**HOLD / DENY / BLOCK.**

---

## Transition Rule

A proposed action may move only through this path:

```text
PROPOSED -> CHECKED -> AUTHORISED -> COMMITTED
```

No skipped stage is valid.

No upstream approval carries itself forward unless rechecked at the boundary.

---

## Behaviour Contract

The system must behave the same way under pressure.

Required behaviour:

- unclear input does not pass
- malformed input does not pass
- stale authority does not pass
- replay does not pass
- scope mismatch does not pass
- contradiction does not pass
- missing proof does not pass

First failure stops movement.

---

## Corpus Map

| Repo | Board Role | Purpose |
|---|---|---|
| `start-here` | Entry board | Shows the whole control path in one sitting |
| `runtime-commit-gate-demo` | Commit boundary | Proves no valid decision record means no mutation |
| `stop-machine` | Stop primitive | Proves terminal refusal |
| `invariant-lock` | Drift lock | Blocks silent version movement |
| `policy-lint` | Language gate | Rejects weak governance claims |
| `deterministic-lexicon` | Term boundary | Prevents vocabulary drift |
| `execution-boundary-lab` | Failure lab | Shows what breaks without enforced boundary |
| `interpretation-boundary-lab` | Upstream gate | Tests interpretive admissibility |

---

## Failure Map

Failure occurs when movement is attempted without admissibility.

| Chessboard Failure | GitHub Equivalent | Expected Result |
|---|---|---|
| Frame shift | action changes after decision | HOLD / DENY |
| Smuggled assumption | authority assumed but not present | HOLD / DENY |
| Constraint avoidance | scope or environment mismatch | HOLD / DENY |
| Burden shift | missing proof treated as acceptable | HOLD / DENY |
| Layer change | audit or log mistaken for control | HOLD / DENY |
| Hidden state | unresolved dependency or stale context | HOLD |
| Replay | old decision reused | DENY |
| Drift | version change without declared transition | DENY |

---

## Hidden-State Check

Before movement, the system asks:

> What is not visible yet?

The check surfaces:

- hidden assumptions
- missing constraints
- unknown dependencies
- stale authority
- unresolved state
- untested downstream consequence

This check does not promote anything.

If hidden state cannot be resolved:

**HOLD.**

---

## Consequence

If the required condition is missing, stale, contradictory, replayed, or out of scope:

**the action does not execute.**

The refusal is not advisory.

It is the behaviour of the system.

---

## Final Reduced Shape

Admissibility Filter checks the move.

Reasoning Chessboard maps the board.

Threat Detection sees illegal movement forming.

The GitHub corpus implements the same structure at runtime.

A proposed action may not move unless the required condition is present, explicit, current, scoped, and checked at the boundary.

If any condition fails:

**HOLD / DENY / BLOCK.**

No valid decision record means no state mutation.
