#!/usr/bin/env python3
"""Run all scenarios through the decision engine. Compare against expected outputs.

Usage:
    python run_demo.py                  Run all scenarios
    python run_demo.py --scenario deny  Run one scenario
"""

import argparse
import json
from pathlib import Path

from src.engine import GovernanceEngine
from src.output import format_output
from src.canonical import canonical_json


SCENARIO_DIR = Path(__file__).resolve().parent / "scenarios"
EXPECTED_DIR = Path(__file__).resolve().parent / "expected"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def scenario_names() -> list[str]:
    return sorted(p.stem for p in SCENARIO_DIR.glob("*.json"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Execution-boundary governance demo")
    parser.add_argument("--scenario", help="Run one scenario only")
    args = parser.parse_args()

    names = [args.scenario] if args.scenario else scenario_names()
    engine = GovernanceEngine()

    print()
    print("=" * 56)
    print("  EXECUTION BOUNDARY — Decision Demo (steel)")
    print("=" * 56)
    print()

    mismatches = 0

    for name in names:
        scenario_path = SCENARIO_DIR / f"{name}.json"
        expected_path = EXPECTED_DIR / f"{name}.json"

        if not scenario_path.exists():
            print(f"  [!] {name:12s} -> scenario file not found")
            mismatches += 1
            continue

        scenario = load_json(scenario_path)
        expected = load_json(expected_path) if expected_path.exists() else None

        result = engine.decide(scenario)
        output = format_output(name, result)

        symbols = {"ALLOW": "+", "DENY": "x", "ESCALATE": "?"}
        s = symbols.get(output["decision"], " ")
        print(f"  [{s}] {name:12s} -> {output['decision']:10s}  ({output['reason_code']})")

        if expected is None:
            print(f"      WARNING: no expected output for '{name}'")
            mismatches += 1
        elif output != expected:
            print(f"      MISMATCH")
            print(f"        got:      {json.dumps(output, sort_keys=True)}")
            print(f"        expected: {json.dumps(expected, sort_keys=True)}")
            mismatches += 1

    print()
    print("-" * 56)

    total = len(names)
    passed = total - mismatches

    if mismatches == 0:
        print(f"  ALL {total} SCENARIOS PASSED")
    else:
        print(f"  {passed}/{total} PASSED")

    print("-" * 56)

    # Print event log
    print()
    print("  EVENT LOG ({} entries, hash-chained)".format(
        len(engine.export_event_log()["events"])
    ))
    for event in engine.export_event_log()["events"]:
        print(f"    {event['request_id']:20s} {event['decision']:10s} hash:{event['event_hash'][:12]}...")

    print()

    return 1 if mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
