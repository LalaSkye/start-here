## Governance Lint Warning

This pull request contains governance language that names authority, review, control, or approval without fully binding it to explicit structure.

### Required bindings

- **Interface** — Where is this recorded (field, form, API, log)?
- **Mechanism** — What executes this step (workflow, service, procedure)?
- **Constraint** — What criteria govern this (thresholds, checklist, invariants)?
- **Enforcement** — What changes if this is absent (block, route, escalate, log)?

### Important

This lint layer does **not** infer missing structure and does **not** rewrite prose. It only reports absence.

Please either:
- Point to the existing binding in the artefact, or
- Tighten the sentence so the causal path is explicit.
