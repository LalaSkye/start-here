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

## Two Layers

**Paradox Vector** (pre-gate): detects inputs that contain mutually incompatible conditions — authority claimed but absent, execution smuggled inside non-exec scope, stale approvals used as current. Contradiction paths collapse into a sealed sink. No execution. No adaptation.

**Admissibility Gate** (main gate): evaluates coherent requests against policy, authority, and action rules. Returns ALLOW, DENY, or ESCALATE.

```
input → PARADOX CHECK → if contradiction → SINK (blocked)
                      → if clean → ADMISSIBILITY GATE → ALLOW / DENY / ESCALATE
```

## Files Worth Reading

| File | What it does |
|------|-------------|
| `run_demo.py` | Entry point |
| `src/paradox.py` | Contradiction detection + sealed sink |
| `src/engine.py` | Decision logic (paradox → validation → policy) |
| `src/validation.py` | Input structure checks |
| `src/event_log.py` | Replay guard + hash-chained log |
| `expected/` | Canonical outputs |

## Run Tests

```
python -m pytest tests/ -v
```

28 tests. All passing.

## Where Next

See [links.md](links.md) for deeper repos. This repo is the entry surface only.
