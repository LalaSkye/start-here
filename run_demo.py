#!/usr/bin/env python3
"""Run all scenarios through the decision engine. Compare against expected outputs.

Usage:
    python run_demo.py          Run all scenarios
    python run_demo.py deny     Run one scenario
"""

import json
import pathlib
import sys

from src.engine import decide
from src.output import format_result, print_result

ROOT = pathlib.Path(__file__).resolve().parent
SCENARIOS = ROOT / "scenarios"
EXPECTED = ROOT / "expected"


def load(path):
    with open(path) as f:
        return json.load(f)


def run_one(name):
    scenario = load(SCENARIOS / f"{name}.json")
    result = decide(scenario)
    output = format_result(name, result)

    print_result(output)

    expected_path = EXPECTED / f"{name}.json"
    if expected_path.exists():
        expected = load(expected_path)
        if output != expected:
            print(f"    MISMATCH: got {json.dumps(output, sort_keys=True)}")
            return False
    return True


def main():
    print()
    print("=" * 56)
    print("  EXECUTION BOUNDARY — Decision Demo")
    print("=" * 56)
    print()

    names = sys.argv[1:] if len(sys.argv) > 1 else sorted(
        p.stem for p in SCENARIOS.glob("*.json")
    )

    results = [(n, run_one(n)) for n in names]

    print()
    print("-" * 56)

    passed = sum(1 for _, p in results if p)
    total = len(results)

    if passed == total:
        print(f"  ALL {total} SCENARIOS PASSED")
    else:
        print(f"  {passed}/{total} PASSED")
        for n, p in results:
            if not p:
                print(f"    FAIL: {n}")

    print("-" * 56)
    print()
    sys.exit(0 if passed == total else 1)


if __name__ == "__main__":
    main()
