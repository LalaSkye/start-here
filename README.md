# start-here

A minimal runnable demonstration of execution-boundary governance.
This shows a system deciding whether an action may execute before any state mutation occurs.

It is intentionally small. The point is to run it, inspect it, and verify the behaviour in one sitting.

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

## What You Will See

Twelve scenarios producing three distinct runtime decisions:

```
========================================================
  EXECUTION BOUNDARY — Decision Demo (steel)
========================================================

  [+] allow              -> ALLOW       (policy_allow_with_valid_authority)
  [x] deny               -> DENY        (policy_violation)
  [?] escalate           -> ESCALATE    (authority_ambiguous)
  [x] malformed          -> DENY        (malformed_input)
  [x] paradox_authority  -> DENY        (authority_contradiction)
  [x] paradox_exec       -> DENY        (execution_contradiction)
  [x] paradox_inheritance-> DENY        (authority_contradiction)
  [x] paradox_state      -> DENY        (state_contradiction)
  [x] paradox_structural -> DENY        (structural_contradiction)
  [x] paradox_temporal   -> DENY        (temporal_contradiction)
  [x] replay             -> DENY        (replay_detected)
  [x] unknown            -> DENY        (unknown_action)

  ALL 12 SCENARIOS PASSED
```

## What This Proves

- Not every proposed action is allowed to run
- The decision happens before execution
- Authority is explicit, not assumed
- Ambiguous inputs do not silently pass
- Malformed inputs fail cleanly
- Replay attempts are detected and blocked
- Contradiction paths collapse before reaching the gate
- Every decision is hash-chained for tamper evidence

## Canonical Invariant

> **No valid Decision Record → no state mutation.**

## Architecture

**Layer 1 — Action Registry** (`core/action_registry.py`): Defines which action classes exist and what each class requires. Governed artefact with six mandatory fields per action. Bound at parse-time. Unknown actions → DENY.

**Layer 2 — Commit Gate** (`core/commit_gate.py`): The Decision Record is not an audit artefact — it is the transition licence. The commit gate converts the record from evaluation output into a required input for state mutation. Pure function. Fail-closed. Nine checks including authority scope, state verification, and boundary validation.

**Layer 3 — Paradox Vector** (`core/paradox.py`): Detects inputs that contain mutually incompatible conditions — authority claimed but absent, execution smuggled inside non-exec scope, stale approvals used as current. Contradiction paths collapse into a sealed sink.

**Layer 4 — Stress Harness** (`tests/test_core/test_invariants.py`): 10 bulkhead invariants. If any fail, the implementation is broken.

```
input → PARSE → CANONICALISE → VALIDATE → EVALUATE → DECISION RECORD
                                                          ↓
                                              COMMIT GATE (Layer 2)
                                                          ↓
                                              state_oracle verifies state
                                              boundary_context validates where
                                              authority_scope validates who
                                                          ↓
                                              CommittedRecord binds decision → state
```

## Files Worth Reading

| File | What it does |
|------|-------------|
| `core/action_registry.py` | Layer 1 — governed action surface |
| `core/commit_gate.py` | Layer 2 — execution-binding commit boundary |
| `core/decision_record.py` | Immutable decision record with decision_id |
| `core/evaluator.py` | 8-stage evaluation pipeline |
| `core/state_oracle.py` | State verification at commit boundary |
| `core/boundary_context.py` | Environment + boundary class validation |
| `core/paradox.py` | Contradiction detection + sealed sink |
| `core/proof.py` | Proof-carrying packet obligations |
| `core/algebra.py` | Admissibility algebra + action primitives |
| `run_demo.py` | Entry point |
| `expected/` | Canonical outputs |

## Run Tests

```
python -m pytest tests/ -v
```

134 tests. All passing.

## Canonical Failure Set (all enforced)

1. No decision record
2. Malformed decision record
3. Missing mandatory fields
4. Evidence / hash mismatch
5. Commit boundary mismatch
6. State hash mismatch
7. Authority stale or scope-invalid

Any of the above → invalid decision record → no commit.

## Where Next

See [links.md](links.md) for deeper repos. This repo is the entry surface only.
