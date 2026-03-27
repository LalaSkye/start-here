"""Strict evaluation pipeline.

parse → canonicalise → validate → evaluate

Evaluation never touches messy raw input.
Each stage is isolated. Each stage can fail independently.
Every evaluation emits a DecisionRecord with a rule trace.
"""

from __future__ import annotations

from typing import Optional

from core.version import SCHEMA_VERSION
from core.canonical import Packet, validate_raw, canonical_hash, ALL_FIELDS
from core.paradox import detect_contradiction, ContradictionClass
from core.proof import check_proof, proof_denial_reason
from core.algebra import Verdict, Action, may_execute, combine_verdicts
from core.reason_codes import ReasonCode
from core.decision_record import DecisionRecord


# ---------------------------------------------------------------------------
# Unknown-field policy: core packets reject unknown fields
# ---------------------------------------------------------------------------

# Fields that are allowed at the top level of a raw packet
ALLOWED_TOP_FIELDS = set(ALL_FIELDS) | {"name"}  # 'name' used by demo scenarios


def check_unknown_fields(raw: dict) -> Optional[str]:
    """Return the first unknown field name, or None if clean."""
    if not isinstance(raw, dict):
        return None
    for key in raw:
        if key not in ALLOWED_TOP_FIELDS:
            return key
    return None


# ---------------------------------------------------------------------------
# Evaluation pipeline
# ---------------------------------------------------------------------------

class Evaluator:
    """Strict evaluation pipeline with rule trace and decision records."""

    def __init__(self):
        self._seen_ids: set[str] = set()
        self._records: list[DecisionRecord] = []

    def evaluate(self, raw: dict) -> DecisionRecord:
        """Full pipeline: parse → canonicalise → validate → evaluate.

        Returns a DecisionRecord. Always. Never raises on input.
        """
        trace = []

        # --- Stage 0: Unknown field check ---
        unknown = check_unknown_fields(raw)
        if unknown is not None:
            trace.append(f"UNKNOWN_FIELD:{unknown}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash="",
                verdict=Verdict.DENY,
                reason=ReasonCode.UNKNOWN_FIELD,
                proof_status="NOT_CHECKED",
                paradox_class=None,
                trace=trace,
            )

        # --- Stage 1: Parse + canonicalise ---
        try:
            errors = validate_raw(raw)
            if errors:
                trace.append(f"PARSE_FAIL:{';'.join(errors)}")
                trace.append(f"VERDICT:{Verdict.DENY.value}")
                return self._emit(
                    packet_hash="",
                    verdict=Verdict.DENY,
                    reason=ReasonCode.MALFORMED_PACKET,
                    proof_status="NOT_CHECKED",
                    paradox_class=None,
                    trace=trace,
                )
            packet = Packet.from_dict(raw)
            trace.append("PARSE_OK")
            trace.append("CANONICAL_OK")
        except (ValueError, TypeError, KeyError) as e:
            trace.append(f"PARSE_FAIL:{e}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash="",
                verdict=Verdict.DENY,
                reason=ReasonCode.MALFORMED_PACKET,
                proof_status="NOT_CHECKED",
                paradox_class=None,
                trace=trace,
            )

        pkt_hash = packet.canonical_hash()

        # --- Stage 2: Schema version check ---
        if packet.schema_version != SCHEMA_VERSION:
            trace.append(f"SCHEMA_MISMATCH:got={packet.schema_version},expected={SCHEMA_VERSION}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash=pkt_hash,
                verdict=Verdict.DENY,
                reason=ReasonCode.SCHEMA_MISMATCH,
                proof_status="NOT_CHECKED",
                paradox_class=None,
                trace=trace,
            )
        trace.append("SCHEMA_OK")

        # --- Stage 3: Paradox check (pre-gate contradiction sink) ---
        contradiction = detect_contradiction(packet)
        if contradiction is not None:
            trace.append(f"PARADOX_SINK:{contradiction.value}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash=pkt_hash,
                verdict=Verdict.DENY,
                reason=ReasonCode(contradiction.value),
                proof_status="NOT_CHECKED",
                paradox_class=contradiction.value,
                trace=trace,
            )
        trace.append("PARADOX_CLEAR")

        # --- Stage 4: Replay check ---
        if packet.packet_id in self._seen_ids:
            trace.append(f"REPLAY:{packet.packet_id}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash=pkt_hash,
                verdict=Verdict.DENY,
                reason=ReasonCode.REPLAY_DETECTED,
                proof_status="NOT_CHECKED",
                paradox_class=None,
                trace=trace,
            )
        self._seen_ids.add(packet.packet_id)
        trace.append("REPLAY_CLEAR")

        # --- Stage 5: Action registry (closed-world) ---
        action = Action(action_type=packet.requested_action)
        if not action.is_known():
            trace.append(f"ACTION_UNKNOWN:{packet.requested_action}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash=pkt_hash,
                verdict=Verdict.DENY,
                reason=ReasonCode.ACTION_UNKNOWN,
                proof_status="NOT_CHECKED",
                paradox_class=None,
                trace=trace,
            )
        trace.append("ACTION_KNOWN")

        # --- Stage 6: Proof check ---
        proof_result = check_proof(packet)
        denial = proof_denial_reason(proof_result)
        if denial:
            # Map the detailed denial to a ReasonCode
            if denial.startswith("proof_incomplete"):
                reason = ReasonCode.PROOF_INCOMPLETE
            elif denial.startswith("proof_stale"):
                reason = ReasonCode.PROOF_STALE
            else:
                reason = ReasonCode.PROOF_INADMISSIBLE
            trace.append(f"PROOF_FAIL:{denial}")
            trace.append(f"VERDICT:{Verdict.DENY.value}")
            return self._emit(
                packet_hash=pkt_hash,
                verdict=Verdict.DENY,
                reason=reason,
                proof_status="FAILED",
                paradox_class=None,
                trace=trace,
            )
        trace.append("PROOF_OK")

        # --- Stage 7: Authority freshness ---
        auth = packet.authority_claim or {}
        auth_type = auth.get("authority_type", "")
        expires = auth.get("expires_at", 0)
        current = packet.timestamp

        if action.is_mutating():
            if not auth_type:
                trace.append("AUTHORITY_MISSING")
                trace.append(f"VERDICT:{Verdict.DENY.value}")
                return self._emit(
                    packet_hash=pkt_hash,
                    verdict=Verdict.DENY,
                    reason=ReasonCode.AUTHORITY_MISSING,
                    proof_status="PASSED",
                    paradox_class=None,
                    trace=trace,
                )
            if expires and current > expires:
                trace.append(f"AUTHORITY_EXPIRED:expires={expires},current={current}")
                trace.append(f"VERDICT:{Verdict.ESCALATE.value}")
                return self._emit(
                    packet_hash=pkt_hash,
                    verdict=Verdict.ESCALATE,
                    reason=ReasonCode.AUTHORITY_EXPIRED,
                    proof_status="PASSED",
                    paradox_class=None,
                    trace=trace,
                )
        trace.append("AUTHORITY_OK")

        # --- Stage 8: All checks pass ---
        trace.append(f"VERDICT:{Verdict.ALLOW.value}")
        return self._emit(
            packet_hash=pkt_hash,
            verdict=Verdict.ALLOW,
            reason=ReasonCode.POLICY_ALLOW,
            proof_status="PASSED",
            paradox_class=None,
            trace=trace,
            executed=True,
        )

    def _emit(
        self,
        packet_hash: str,
        verdict: Verdict,
        reason: ReasonCode,
        proof_status: str,
        paradox_class: Optional[str],
        trace: list[str],
        executed: bool = False,
    ) -> DecisionRecord:
        record = DecisionRecord(
            packet_hash=packet_hash,
            schema_version=SCHEMA_VERSION,
            verdict=verdict.value if isinstance(verdict, Verdict) else str(verdict),
            reason_code=reason.value if isinstance(reason, ReasonCode) else str(reason),
            proof_status=proof_status,
            paradox_class=paradox_class,
            state_change="NONE",
            trace=tuple(trace),
            executed=executed,
        )
        self._records.append(record)
        return record

    def get_records(self) -> list[DecisionRecord]:
        return list(self._records)
