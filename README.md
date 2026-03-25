# start-here

A minimal runnable demonstration of execution-boundary governance.
This shows a system deciding whether an action may execute before any state mutation occurs.

## Run It

```
git clone https://github.com/LalaSkye/start-here.git
cd start-here
python run_demo.py
```

No dependencies beyond Python 3.8+. No install step.

## What You Will See

```
========================================================
  EXECUTION BOUNDARY — Decision Demo
========================================================

  [+] allow        -> ALLOW       (policy_allow)
  [x] deny         -> DENY        (policy_violation)
  [?] escalate     -> ESCALATE    (authority_ambiguous)
  [x] unknown      -> DENY        (action_unknown)

--------------------------------------------------------
  ALL 4 SCENARIOS PASSED
--------------------------------------------------------
```

## Expected Outcomes

| Scenario | Decision | Why |
|----------|----------|-----|
| allow | ALLOW | Valid action, valid authority, policy permits |
| deny | DENY | Policy is forbidden — action blocked |
| escalate | ESCALATE | Authority is ambiguous — system will not guess |
| unknown | DENY | Action not in known set — closed-world refusal |

## Run Tests

```
python -m pytest tests/ -v
```

## Where Next

See [links.md](links.md) for deeper repos.

This repo is intentionally small.
