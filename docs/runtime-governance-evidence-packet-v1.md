# Runtime Governance Evidence Packet v1

Status: v1.0 — documentation artifact  
Scope: path-local evidence wrapper  
Owner: LalaSkye  
Related issue: https://github.com/LalaSkye/start-here/issues/6

## Purpose

This packet links three current proof surfaces into one buyer-readable evidence view:

- `commit-gate-core`
- `receipt-chain-core`
- `semantic-ambiguity-gate`

It shows how a consequence-binding AI-assisted action can be inspected through:

1. the stop condition
2. the refusal / decision receipt
3. the replayable evidence path

Clean line:

> Show me the stop.  
> Show me the receipt.  
> Show me the replay.

## Proof triangle

### 1. `commit-gate-core`

Role: structural refusal at the commit boundary.

Question answered:

> Can an unauthorised or invalid action be stopped before mutation?

Evidence class:

- attempted action
- required authority
- commit verdict
- mutation state
- refusal condition

Claim limit:

`commit-gate-core` demonstrates path-local commit-boundary control. It does not prove production enforcement, enterprise readiness, compliance, certification, or universal non-bypassability.

### 2. `receipt-chain-core`

Role: evidence of refusal.

Question answered:

> Can a refusal or decision event leave structured, inspectable evidence?

Evidence class:

- receipt object
- receipt hash / chain reference
- verification path
- replay / tamper evidence

Claim limit:

`receipt-chain-core` demonstrates path-local receipt evidence. It does not prove legal admissibility, production audit readiness, universal tamper resistance, or organisational adoption.

### 3. `semantic-ambiguity-gate`

Role: refusal on unresolved meaning at the consequence boundary.

Question answered:

> Can a syntactically valid action be refused because unresolved meaning creates binding risk?

Evidence class:

- structurally valid input
- unresolved term
- ambiguity finding
- HOLD / REFUSE verdict
- downstream send blocked
- no mutation
- receipt written

Claim limit:

`semantic-ambiguity-gate` demonstrates a narrow path-local ambiguity gate. It does not prove ethics detection, intent parsing, general semantic understanding, production safety, compliance, or enterprise readiness.

## Combined narrow claim

The current proof triangle demonstrates three path-local control patterns:

1. no valid authority → no consequence
2. refusal can leave structured evidence
3. unresolved meaning → no consequence

This is not a claim of production governance.

It is an inspectable proof surface showing how stop, receipt, and replay can be represented.

## Evidence packet

### 1. Action attempted

An AI-assisted or software-mediated workflow attempts to perform a consequence-binding action.

Example action class:

    {
      "action": "grant_access",
      "subject": "contractor_1842",
      "resource": "customer_records",
      "purpose": "support_review",
      "duration": "temporary",
      "approval_status": "approved"
    }

The action appears structurally valid.

It contains an action, subject, resource, purpose, duration, and approval status.

The risk is not that the transaction is malformed.

The risk is that one field appears acceptable while leaving the consequence unbounded.

### 2. Consequence boundary

The consequence boundary is the point where a proposed action would become a real downstream change.

Examples:

- access granted
- record changed
- file released
- approval issued
- notification sent
- workflow escalated
- asset moved
- obligation created

The question is not only:

> Did the system generate a plausible action?

The question is:

> Was the action allowed to bind consequence?

If the action crosses this boundary without valid authority, bounded meaning, and receipt evidence, governance becomes descriptive rather than controlling.

### 3. Required authority

Before consequence, the system must know what authority is required.

Evidence should show:

- who or what authorised the action
- what scope was authorised
- whether the authority is current
- whether the authority is replayed, stale, expired, or missing
- whether the authority covers this action class

If authority is missing or invalid, the action must not mutate state.

Relevant proof surface:

- `commit-gate-core`

Minimum inspection fields:

    required_authority_present = true / false
    authority_scope_valid = true / false
    authority_current = true / false
    authority_replayed = true / false
    commit_verdict = ALLOW / HOLD / DENY / REFUSE
    mutation_occurred = true / false

### 4. Semantic ambiguity check

Before consequence, the system must check whether any term controlling authority, scope, expiry, recipient, revocation, or downstream effect remains unresolved.

Example unresolved term:

    temporary

Why it matters:

`temporary` does not define:

- start time
- end time
- time zone
- revocation condition
- permitted access duration
- downstream expiry behaviour

If this term controls access, the system cannot safely bound the consequence.

Relevant proof surface:

- `semantic-ambiguity-gate`

Minimum inspection fields:

    schema_valid = true
    unresolved_term = temporary
    ambiguity_class = duration / expiry / revocation
    ambiguity_verdict = HOLD / REFUSE
    downstream_send = false
    mutation_occurred = false

### 5. Commit verdict

The commit verdict must be explicit.

Allowed verdict classes:

- `ALLOW`
- `HOLD`
- `DENY`
- `REFUSE`
- `ESCALATE`

A useful verdict records:

- decision
- reason codes
- whether downstream send is allowed
- whether mutation occurred
- receipt reference

Example reason codes:

    AMBIGUOUS_DURATION
    MISSING_EXPIRY_TIMESTAMP
    UNBOUND_REVOCATION_CONDITION
    DOWNSTREAM_PERMISSION_RISK

A verdict is not useful if it only describes the issue after the fact.

It must determine whether the action crosses the consequence boundary.

### 6. Downstream send state

The packet must show whether the action was sent downstream.

Required field:

    downstream_send = false

If the action is refused or held, downstream systems must not receive the mutation request.

This prevents a governance decision from becoming advisory-only theatre.

A stop that still sends the action downstream is not a stop.

It is commentary with a clipboard.

### 7. Mutation state

The packet must show whether state changed.

Required field:

    mutation_occurred = false

If mutation occurred after refusal, the system did not stop.

It only described a stop.

The central inspection question is:

> Did anything change?

If the answer is yes, the refusal did not bind at the execution boundary.

### 8. Receipt reference

Every refusal or hold should leave structured evidence.

A receipt should include:

- receipt id
- timestamp
- transaction hash
- verdict
- reason codes
- downstream send state
- mutation state
- claim boundary
- replay reference where available

Relevant proof surface:

- `receipt-chain-core`

Minimum receipt shape:

    {
      "receipt_id": "rcpt_example",
      "transaction_hash": "hash_of_attempted_action",
      "verdict": "REFUSE",
      "reason_codes": [
        "AMBIGUOUS_DURATION",
        "MISSING_EXPIRY_TIMESTAMP",
        "UNBOUND_REVOCATION_CONDITION",
        "DOWNSTREAM_PERMISSION_RISK"
      ],
      "downstream_send": false,
      "mutation_occurred": false,
      "claim_boundary": "path-local synthetic proof only"
    }

The receipt is not a guarantee of full governance.

It is evidence that this boundary event happened on this demonstrated path.

### 9. Replay evidence

Replay evidence should show that the same attempted action produces the same refusal outcome and does not mutate state.

Minimum replay evidence:

- same transaction hash
- same verdict
- downstream send remains false
- mutation remains false
- receipt remains inspectable

Replay is important because a governance claim is weak if it cannot be inspected again.

Minimum replay statement:

    same_transaction_hash = true
    same_verdict = true
    downstream_send = false
    mutation_occurred = false
    receipt_inspectable = true

Replay does not prove all paths are covered.

It proves this demonstrated path can be inspected again.

### 10. What this proves

This packet proves only that the current proof surfaces can be read together as a path-local evidence chain.

It shows:

- an action can be checked before consequence
- invalid authority can stop mutation
- unresolved meaning can stop mutation
- refusal can leave structured evidence
- replay can support inspection

This is useful because it converts governance language into inspectable questions:

- What tried to happen?
- What authority was required?
- What meaning was unresolved?
- Where did it stop?
- Did anything change?
- What receipt proves the stop?
- Can the path be replayed?

### 11. What this does not prove

This packet does not prove:

- enterprise readiness
- production enforcement
- certification
- legal compliance
- universal safety
- general semantic understanding
- complete ambiguity resolution
- path-universal non-bypassability
- adoption
- standardisation
- that all downstream systems are covered
- that all bypass paths are closed
- that all possible ambiguous terms are detected
- that receipts are legally admissible
- that these repos are integrated into a production system

The packet is an evidence wrapper.

It is not a runtime control engine.

## Buyer-readable summary

Most AI governance reviews inspect policies, outputs, or logs.

This packet inspects the moment before consequence:

- what action was attempted
- what authority was required
- what meaning was unresolved
- where execution stopped
- whether mutation occurred
- what receipt was written
- what replay can show

The value is not a bigger claim.

The value is a smaller inspection surface.

## Inspection question

The practical inspection question is:

> Can you show where the action stopped before it changed anything?

If not, the system may have a governance statement, but not yet a proof-of-stop surface.

## Current status

This packet links existing public proof surfaces.

It should not be used to claim that the triangle is uniformly green until:

- `commit-gate-core` CI is repaired or verified green
- `receipt-chain-core` claim boundary and test state are verified
- the packet is reviewed against current repo state

Until then, public routing remains HOLD.

## Final line

Show me the stop.  
Show me the receipt.  
Show me the replay.
