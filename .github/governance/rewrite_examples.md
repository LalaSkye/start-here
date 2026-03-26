# Governance Lint — Rewrite Library

**Artefact:** GOVERNANCE_LINT_GITHUB_ACTIONS_IMPLEMENTATION_PACK_v1
**Date:** 2026-03-26
**Author:** Ricky Dean Jones

---

## Purpose

This document provides concrete before/after examples showing how to fix
each lint verdict. The lint layer does **not** rewrite prose — this library
is a human reference for reviewers and authors.

---

## Verdict: AMBIGUOUS (all four bindings missing)

### Before

> The approver must verify the request before it is allowed to proceed.

**Lint output:** AMBIGUOUS — missing interface, mechanism, constraint, enforcement.

**Questions raised:**
- Where is this recorded?
- What executes this step?
- What criteria govern this?
- What changes if this is absent?

### After

> The approver verifies the request by signing the `approval_record` field
> in the governance API. The approval workflow engine executes this step.
> The request must meet the risk-score threshold defined in the policy
> checklist. If the approval is absent, the gate blocks execution and
> escalates to the compliance team via the audit log.

**Why this passes:** All four bindings are present — `approval_record` field
(interface), `approval workflow engine` (mechanism), `risk-score threshold`
and `policy checklist` (constraint), `gate blocks execution` and `escalates`
(enforcement).

---

## Verdict: AMBIGUOUS (mechanism + enforcement missing)

### Before

> The reviewer ensures compliance before the release is authorized.

**Lint output:** AMBIGUOUS — missing mechanism, missing enforcement.

### After

> The reviewer ensures compliance by running the validation checklist
> in the review-step workflow. If the checklist fails, the gate blocks
> the release and logs the failure to the audit trail.

**Why this passes:** `validation checklist` (constraint already implicit),
`review-step workflow` (mechanism), `gate blocks` and `logs` (enforcement).

---

## Verdict: AMBIGUOUS (interface missing)

### Before

> The controller approved the deployment after verification was completed.

**Lint output:** AMBIGUOUS — missing interface.

### After

> The controller approved the deployment by signing the `deploy_signoff`
> field in the deployment log after the verification workflow completed
> against the defined conditions checklist. Unsigned deployments are
> blocked by the gate.

**Why this passes:** `deploy_signoff` field and `deployment log` (interface).

---

## Verdict: AMBIGUOUS (constraint missing)

### Before

> The operator is responsible for reviewing the output before it proceeds
> to production via the release workflow, and blocks it if validation fails.

**Lint output:** AMBIGUOUS — missing constraint.

### After

> The operator is responsible for reviewing the output against the
> production-readiness checklist and risk-score threshold before it
> proceeds to production via the release workflow. The gate blocks
> the release if validation fails, and logs the result.

**Why this passes:** `production-readiness checklist` and `risk-score
threshold` (constraint) added.

---

## Verdict: DECORATIVE (entity without trigger)

A sentence that names a governance entity but uses no trigger verb is not
flagged by the linter — it carries no governance claim. No rewrite needed.

### Example (not flagged)

> The compliance team is based in London.

This is informational. No authority, review, control, or approval is claimed.

---

## Verdict: PASS (fully bound)

No action required. Example of a clean sentence:

> The system logs every decision to the audit trail via the governance
> workflow engine when the risk-score threshold is exceeded, and blocks
> execution if validation fails.

**Bindings present:** `audit trail` (interface), `governance workflow engine`
(mechanism), `risk-score threshold` (constraint), `blocks execution`
(enforcement).

---

## Quick reference — binding hint words

| Binding | Hint words to include |
|---------|-----------------------|
| Interface | token, field, form, API, log, entry, record, signature, sign-off, input, selection |
| Mechanism | workflow, validator, service, procedure, engine, step, process, check, validation, review step, gate check |
| Constraint | threshold, criteria, checklist, invariant, conditions, policy, rule, risk score, valid |
| Enforcement | block, blocked, gate, escalate, escalation, audit, logged, log, proceeds only if, does not proceed, before execution |

---

## Principle

Never invent structure that does not exist. If the binding genuinely does not
exist yet, create the artefact that defines it — then reference it in the
sentence. The rewrite makes the existing (or newly created) causal path
explicit. It does not fabricate one.
