# Governance Lint — Waiver Policy

**Artefact:** GOVERNANCE_LINT_GITHUB_ACTIONS_IMPLEMENTATION_PACK_v1
**Date:** 2026-03-26
**Author:** Ricky Dean Jones

---

## Purpose

This document defines when applying the `governance-lint-waived` label is
acceptable and how waivers must be recorded.

A waiver does **not** resolve a binding gap. It records an explicit human
decision to proceed despite one.

---

## When a waiver is acceptable

| Condition | Waiver permitted | Notes |
|-----------|-----------------|-------|
| Exploratory / draft branch | Yes | Work-in-progress prose that has not reached review. |
| Non-protected surface | Yes | Files outside the protected-paths list carry lower risk. |
| Informational / educational doc | Yes | Descriptions of external systems where we hold no authority. |
| Temporary placeholder | Yes | Sentence will be tightened before merge to `main`. Must link a follow-up issue. |
| Protected surface, mechanism missing | **No** | A protected surface without a mechanism binding is a structural gap. Fix, don't waive. |
| Protected surface, enforcement missing | **No** | A protected surface without enforcement is an execution gap. Fix, don't waive. |
| Any sentence on `main` after MODE_B | **No** | Once MODE_B is active, waivers on protected surfaces are not accepted on the default branch. |

---

## How to request a waiver

1. The PR author adds a YAML block to the PR description or a comment:

```yaml
governance_lint_waiver:
  sentence_id: "<file>:<sentence_index>"
  reviewer: "<GitHub handle of human reviewer>"
  timestamp: "<ISO 8601>"
  justification: "<Why this waiver is acceptable>"
  linked_artefact: "<issue URL or artefact ID, if applicable>"
```

2. A human reviewer (not the author) applies the `governance-lint-waived` label.

3. The waiver is logged. It does not suppress future runs — the sentence will
   be flagged again on every subsequent PR that touches the file.

---

## Waiver expiry

- Waivers on exploratory branches expire when the branch is merged or deleted.
- Waivers with a `linked_artefact` expire when the linked issue is closed.
- Waivers without a linked artefact are reviewed every 30 days.

---

## Escalation

If a waiver is disputed:

1. The reviewer tags `governance-binding-gap` on the PR.
2. The dispute is logged in the PR thread.
3. The repository owner (Ricky Dean Jones) makes the final call.

No automated system may grant, extend, or remove a waiver. Only a human reviewer
can apply `governance-lint-waived`.
