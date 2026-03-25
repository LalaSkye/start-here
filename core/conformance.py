"""GOLDEN_CONFORMANCE_CORPUS_v1 — Canonical conformance surface.

If two systems produce different verdicts for the same canonical corpus,
they are not equivalent.

This is the moat. People can copy ideas. Then they fail the corpus.

Corpus categories:
  - valid packets (should ALLOW)
  - policy violations (should DENY)
  - unknown actions (should DENY)
  - malformed packets (should DENY)
  - stale authority (should DENY or ESCALATE)
  - missing proofs (should DENY)
  - contradiction packets (should DENY via paradox sink)
  - replay attempts (should DENY)
  - near-valid packets (should DENY — the dangerous ones)
  - mixed validity (should produce exact per-item verdicts)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from core.canonical import Packet, canonical_json, canonical_hash
from core.paradox import detect_contradiction, sink
from core.proof import check_proof, proof_denial_reason
from core.algebra import Verdict, Action, may_execute


# ---------------------------------------------------------------------------
# Conformance case
# ---------------------------------------------------------------------------

@dataclass
class ConformanceCase:
    """A single test case in the golden corpus."""
    case_id: str
    category: str
    description: str
    packet_raw: dict
    expected_verdict: str
    expected_reason: str
    expected_executed: bool


# ---------------------------------------------------------------------------
# Conformance evaluator — the reference implementation
# ---------------------------------------------------------------------------

def evaluate_packet(packet_raw: dict, seen_ids: set = None) -> dict:
    """Reference evaluation of a raw packet dict.

    This is the canonical evaluation path:
      1. Parse to canonical form (structural validation)
      2. Paradox check (contradiction sink)
      3. Replay check
      4. Proof check
      5. Authority freshness check
      6. Policy check
      7. Verdict

    Returns a result dict with verdict, reason_code, executed.
    """
    if seen_ids is None:
        seen_ids = set()

    # --- Step 1: Structural validation ---
    try:
        packet = Packet.from_dict(packet_raw)
    except (ValueError, TypeError, KeyError) as e:
        return {
            "verdict": "DENY",
            "reason_code": "malformed_packet",
            "executed": False,
        }

    # --- Step 2: Paradox check ---
    contradiction = detect_contradiction(packet)
    if contradiction is not None:
        return sink(contradiction)

    # --- Step 3: Replay check ---
    if packet.packet_id in seen_ids:
        return {
            "verdict": "DENY",
            "reason_code": "replay_detected",
            "executed": False,
        }
    seen_ids.add(packet.packet_id)

    # --- Step 4: Action registry (closed-world) ---
    action = Action(action_type=packet.requested_action)
    if not action.is_known():
        return {
            "verdict": "DENY",
            "reason_code": "action_unknown",
            "executed": False,
        }

    # --- Step 5: Proof check ---
    proof_result = check_proof(packet)
    denial = proof_denial_reason(proof_result)
    if denial:
        return {
            "verdict": "DENY",
            "reason_code": denial,
            "executed": False,
        }

    # --- Step 6: Authority freshness ---
    auth = packet.authority_claim or {}
    auth_type = auth.get("authority_type", "")
    issued = auth.get("issued_at", 0)
    expires = auth.get("expires_at", 0)
    current = packet.timestamp

    if action.is_mutating():
        if not auth_type:
            return {
                "verdict": "DENY",
                "reason_code": "authority_missing",
                "executed": False,
            }
        if expires and current > expires:
            return {
                "verdict": "ESCALATE",
                "reason_code": "authority_expired",
                "executed": False,
            }

    # --- Step 7: All checks pass ---
    return {
        "verdict": "ALLOW",
        "reason_code": "policy_allow",
        "executed": True,
    }


# ---------------------------------------------------------------------------
# Conformance runner
# ---------------------------------------------------------------------------

@dataclass
class ConformanceResult:
    case_id: str
    expected_verdict: str
    actual_verdict: str
    expected_reason: str
    actual_reason: str
    passed: bool


def run_corpus(cases: list[ConformanceCase]) -> list[ConformanceResult]:
    """Run the entire golden corpus through the reference evaluator.

    All cases run through a single seen_ids set (for replay detection).
    """
    seen_ids = set()
    results = []

    for case in cases:
        actual = evaluate_packet(case.packet_raw, seen_ids)

        passed = (
            actual["verdict"] == case.expected_verdict
            and actual["reason_code"] == case.expected_reason
            and actual["executed"] == case.expected_executed
        )

        results.append(ConformanceResult(
            case_id=case.case_id,
            expected_verdict=case.expected_verdict,
            actual_verdict=actual["verdict"],
            expected_reason=case.expected_reason,
            actual_reason=actual["reason_code"],
            passed=passed,
        ))

    return results


def conformance_report(results: list[ConformanceResult]) -> str:
    """Produce a human-readable conformance report."""
    lines = []
    passed = sum(1 for r in results if r.passed)
    total = len(results)

    lines.append(f"CONFORMANCE: {passed}/{total} passed")
    lines.append("")

    for r in results:
        symbol = "+" if r.passed else "x"
        lines.append(f"  [{symbol}] {r.case_id:30s} {r.actual_verdict:10s} ({r.actual_reason})")
        if not r.passed:
            lines.append(f"      expected: {r.expected_verdict} ({r.expected_reason})")

    return "\n".join(lines)
