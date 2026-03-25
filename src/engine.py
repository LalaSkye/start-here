"""Decision engine. One function. Deterministic.

Evaluation order (first decisive check wins):

  1. Action prohibited?        -> DENY
  2. Action unknown?           -> DENY  (closed-world)
  3. Policy forbidden?         -> DENY
  4. Authority missing?        -> DENY
  5. Authority ambiguous?      -> ESCALATE
  6. All checks pass           -> ALLOW
"""

KNOWN_ACTIONS = {"read", "write", "delete"}
PROHIBITED_ACTIONS = {"drop_table", "deploy_production"}


def decide(scenario):
    """Evaluate a scenario dict. Returns a result dict. Never raises."""

    action = scenario.get("action", "")
    authority = scenario.get("authority", "")
    policy = scenario.get("policy", "")

    # 1. Prohibited action
    if action in PROHIBITED_ACTIONS:
        return _result("DENY", "action_prohibited")

    # 2. Unknown action (closed-world)
    if action not in KNOWN_ACTIONS:
        return _result("DENY", "action_unknown")

    # 3. Policy violation
    if policy == "forbidden":
        return _result("DENY", "policy_violation")

    # 4. Authority missing
    if not authority:
        return _result("DENY", "authority_missing")

    # 5. Authority ambiguous
    if authority == "unknown":
        return _result("ESCALATE", "authority_ambiguous")

    # 6. All checks pass
    return _result("ALLOW", "policy_allow")


def _result(decision, reason_code):
    return {
        "decision": decision,
        "reason_code": reason_code,
        "executed": decision == "ALLOW",
    }
