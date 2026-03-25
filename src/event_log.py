import hashlib
from typing import Any


class EventLog:
    def __init__(self) -> None:
        self._events: list[dict[str, Any]] = []
        self._seen_request_ids: set[str] = set()
        self._last_hash = "GENESIS"

    def has_seen(self, request_id: str) -> bool:
        return request_id in self._seen_request_ids

    def mark_seen(self, request_id: str) -> None:
        self._seen_request_ids.add(request_id)

    def append(self, request_id: str, scenario_name: str, decision: str, reason_code: str, executed: bool) -> None:
        payload = f"{self._last_hash}|{request_id}|{scenario_name}|{decision}|{reason_code}|{executed}"
        event_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

        event = {
            "request_id": request_id,
            "scenario_name": scenario_name,
            "decision": decision,
            "reason_code": reason_code,
            "executed": executed,
            "prev_hash": self._last_hash,
            "event_hash": event_hash,
        }

        self._events.append(event)
        self._last_hash = event_hash

    def export(self) -> dict:
        return {"events": self._events}
