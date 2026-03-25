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

Six scenarios producing three distinct runtime decisions:

```
========================================================
  EXECUTION BOUNDARY — Decision Demo (steel)
========================================================

  [+] allow        -> ALLOW       (policy_allow_with_valid_authority)
  [x] deny         -> DENY        (policy_violation)
  [?] escalate     -> ESCALATE    (authority_ambiguous)
  [x] malformed    -> DENY        (malformed_input)
  [x] replay       -> DENY        (replay_detected)
  [x] unknown      -> DENY        (unknown_action)

--------------------------------------------------------
  ALL 6 SCENARIOS PASSED
--------------------------------------------------------

  EVENT LOG (6 entries, hash-chained)
    REQ-ALLOW-001        ALLOW      hash:a1b2c3d4e5f6...
    REQ-DENY-001         DENY       hash:...
    ...
```

## What This Proves

- Not every proposed action is allowed to run
- The decision happens before execution
- Authority is explicit, not assumed
- Ambiguous inputs do not silently pass
- Malformed inputs fail cleanly
- Replay attempts are detected and blocked
- Every decision is hash-chained for tamper evidence

## Files Worth Reading

| File | What it does |
|------|-------------|
| `run_demo.py` | Entry point |
| `src/engine.py` | Decision logic |
| `src/validation.py` | Input checks |
| `src/event_log.py` | Replay guard + hash-chained log |
| `expected/` | Canonical outputs |

## Run Tests

```
python -m pytest tests/ -v
```

## Where Next

See [links.md](links.md) for deeper repos. This repo is the entry surface only.
