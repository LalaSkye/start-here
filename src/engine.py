from src.event_log import EventLog
from src.reason_codes import (
    REASON_AUTHORITY_AMBIGUOUS,
    REASON_DEFAULT_DENY,
    REASON_MALFORMED_INPUT,
    REASON_POLICY_ALLOW,
    REASON_POLICY_VIOLATION,
    REASON_REPLAY_DETECTED,
    REASON_UNKNOWN_ACTION,
)
from src.validation import validate_scenario


KNOWN_ACTIONS = {"read", "write", "delete"}


class GovernanceEngine:
    def __init__(self) -> None:
        self.event_log = EventLog()

    def decide(self, scenario: dict) -> dict:
        valid, _error = validate_scenario(scenario)
        request_id = scenario.get("request_id", "UNKNOWN")
        scenario_name = scenario.get("name", "unnamed")

        if not valid:
            result = {
                "decision": "DENY",
                "reason_code": REASON_MALFORMED_INPUT,
                "executed": False,
            }
            self.event_log.append(request_id, scenario_name, **result)
            return result

        action = scenario["action"]
        authority = scenario["authority"]
        policy = scenario["policy"]

        if self.event_log.has_seen(request_id):
            result = {
                "decision": "DENY",
                "reason_code": REASON_REPLAY_DETECTED,
                "executed": False,
            }
            self.event_log.append(request_id, scenario_name, **result)
            return result

        if action not in KNOWN_ACTIONS:
            result = {
                "decision": "DENY",
                "reason_code": REASON_UNKNOWN_ACTION,
                "executed": False,
            }
            self.event_log.mark_seen(request_id)
            self.event_log.append(request_id, scenario_name, **result)
            return result

        if policy == "forbidden":
            result = {
                "decision": "DENY",
                "reason_code": REASON_POLICY_VIOLATION,
                "executed": False,
            }
            self.event_log.mark_seen(request_id)
            self.event_log.append(request_id, scenario_name, **result)
            return result

        if authority == "unknown":
            result = {
                "decision": "ESCALATE",
                "reason_code": REASON_AUTHORITY_AMBIGUOUS,
                "executed": False,
            }
            self.event_log.mark_seen(request_id)
            self.event_log.append(request_id, scenario_name, **result)
            return result

        if authority == "valid" and policy == "allowed":
            result = {
                "decision": "ALLOW",
                "reason_code": REASON_POLICY_ALLOW,
                "executed": True,
            }
            self.event_log.mark_seen(request_id)
            self.event_log.append(request_id, scenario_name, **result)
            return result

        result = {
            "decision": "DENY",
            "reason_code": REASON_DEFAULT_DENY,
            "executed": False,
        }
        self.event_log.mark_seen(request_id)
        self.event_log.append(request_id, scenario_name, **result)
        return result

    def export_event_log(self) -> dict:
        return self.event_log.export()
