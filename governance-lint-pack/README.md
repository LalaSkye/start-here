# Governance Lint Pack

**Artefact:** `GOVERNANCE_LINT_GITHUB_ACTIONS_IMPLEMENTATION_PACK_v1`
**Derived from:** NEGATION_KERNEL_v1.3
**Author:** Ricky Dean Jones
**Date:** 2026-03-26

---

## What this does

The governance lint layer scans pull requests for governance language — sentences
that name an authority, reviewer, controller, or approval process — and checks
whether that language is bound to explicit, executable structure.

It detects. It classifies. It labels. It comments. It does **not** rewrite
prose, infer missing structure, or invent mechanisms.

---

## How it works

### Pipeline

```
PR opened/updated
  → changed files filtered by extension (.md .txt .rst .yaml .yml .json)
  → each file parsed into sentences
  → each sentence checked for entity terms + trigger terms
  → if both present: 4-binding check (interface, mechanism, constraint, enforcement)
  → verdict: PASS (all bindings present) or AMBIGUOUS (one or more missing)
  → results written to JSON
  → enforcement step applies mode rules
```

### The 4-binding check

Every governance sentence must answer four questions:

| Binding | Question | Hint words |
|---------|----------|------------|
| **Interface** | Where is this recorded? | field, form, API, log, record, signature |
| **Mechanism** | What executes this step? | workflow, service, procedure, engine, gate check |
| **Constraint** | What criteria govern this? | threshold, checklist, invariant, policy, rule |
| **Enforcement** | What happens if this is absent? | block, gate, escalate, audit, log |

If any binding is missing, the sentence is marked **AMBIGUOUS** and the
missing questions are listed in the output.

---

## Operating modes

| Mode | Behaviour | When to use |
|------|-----------|-------------|
| **MODE_A** | Labels + PR comments only. Build never fails. | Initial rollout. Observe results. |
| **MODE_B** | Fails the build if a **protected surface** has an AMBIGUOUS sentence missing mechanism or enforcement. | Production default after review. |
| **MODE_C** | Fails the build on **any** AMBIGUOUS sentence, regardless of surface. | Maximum strictness. |

The mode is set in `.github/workflows/governance-lint.yml` via the
`GOVERNANCE_LINT_MODE` environment variable.

---

## Protected surfaces

Files matching these patterns are considered protected. In MODE_B, AMBIGUOUS
findings on protected surfaces with missing mechanism or enforcement will
fail the build.

```
docs/governance/**       specs/governance/**
docs/runtime/**          specs/runtime/**
docs/approval/**         specs/control/**
docs/deployment/**       specs/approval/**
docs/safety/**           architecture/**/governance*
policies/**              architecture/**/runtime*
contracts/**
```

The full list is in `.github/governance/protected_paths.txt`.

---

## Reading the lint output

### CI log

```
Governance Lint — mode=MODE_A
  Files scanned:              3
  Sentences analysed:         47
  AMBIGUOUS sentences:        2
  Protected + AMBIGUOUS:      1

  Flagged sentences:
    - docs/governance/policy.md:4 [PROTECTED]
      "The approver must verify the request before it is allowed to proceed."
        ? Where is this recorded (field, form, API, log)?
        ? What executes this step (workflow, service, procedure)?
        ? What criteria govern this (thresholds, checklist, invariants)?
        ? What changes if this is absent (block, route, escalate, log)?
```

### JSON output

Each flagged sentence includes:
- `verdict`: `PASS` or `AMBIGUOUS`
- `is_protected_surface`: whether the file is on a protected path
- `interface_present`, `mechanism_present`, `constraint_present`, `enforcement_present`: which bindings were found
- `mechanism_missing`, `enforcement_missing`: the two bindings that trigger MODE_B failure
- `questions`: the specific questions the author needs to answer
- `waived`: whether a waiver has been applied

---

## Labels

| Label | Colour | Purpose |
|-------|--------|---------|
| `governance-binding-gap` | Red | Primary — sentence has unbound governance language |
| `missing-interface` | Yellow | No interface binding found |
| `missing-mechanism` | Yellow | No mechanism binding found |
| `missing-constraint` | Yellow | No constraint binding found |
| `missing-enforcement` | Yellow | No enforcement binding found |
| `governance-lint-waived` | Blue | Finding explicitly waived by a human reviewer |
| `protected-surface` | Green | File is on a protected governance surface |
| `governance-doc` | Green | Governance documentation file |
| `runtime-control-surface` | Green | Runtime control surface document |

---

## How to fix a flagged sentence

See `.github/governance/rewrite_examples.md` for concrete before/after
examples. The short version:

1. Read the questions raised by the linter.
2. For each missing binding, either:
   - Point to the existing artefact that defines it, or
   - Create the artefact and reference it in the sentence.
3. Rewrite the sentence so the causal path is explicit.

**Never fabricate structure that does not exist.** If the binding genuinely
does not exist, build it first.

---

## How to request a waiver

See `.github/governance/waiver_policy.md` for full policy.

Short version:

1. Add a YAML block to the PR description:

```yaml
governance_lint_waiver:
  sentence_id: "<file>:<sentence_index>"
  reviewer: "<GitHub handle>"
  timestamp: "<ISO 8601>"
  justification: "<reason>"
  linked_artefact: "<issue URL or artefact ID>"
```

2. A human reviewer (not the author) applies the `governance-lint-waived` label.

**Waivers are never permitted on protected surfaces with missing mechanism
or enforcement bindings once MODE_B is active.**

---

## File layout

```
.github/
  workflows/
    governance-lint.yml          # GitHub Actions workflow
  scripts/
    governance_lint.py           # Python linter (293 lines)
  governance/
    protected_paths.txt          # Protected surface glob patterns
    label_map.json               # Label registry
    waiver_policy.md             # Waiver discipline
    rewrite_examples.md          # Before/after rewrite library
    comment_templates/
      ambiguous_comment.md       # PR comment for AMBIGUOUS findings
      fail_comment.md            # PR comment for build failure
      waiver_comment.md          # PR comment for waiver logging
governance-lint-pack/
  README.md                      # This file
```

---

## Rollout plan

1. ~~Add labels to repository~~
2. ~~Add files + enable MODE_A~~
3. Review results on real PRs
4. Promote to MODE_B (`GOVERNANCE_LINT_MODE: MODE_B` in workflow)
5. Add waiver discipline (done — see `waiver_policy.md`)
6. Train reviewers with rewrite library (done — see `rewrite_examples.md`)

---

## Design principle

The lint layer does not rewrite prose, infer missing structure, or invent
mechanisms. It only detects, classifies, labels, comments, and optionally
fails protected surfaces. This is a detection tool, not a correction tool.

Derived from NEGATION_KERNEL_v1.3 — 10 bulkhead invariants + steel bolt-ons A–H.
