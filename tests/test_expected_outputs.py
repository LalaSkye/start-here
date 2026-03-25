"""Golden output tests. Scenarios run in alphabetical order through one engine instance."""

import json
from pathlib import Path

from src.engine import GovernanceEngine
from src.output import format_output


SCENARIO_DIR = Path(__file__).resolve().parent.parent / "scenarios"
EXPECTED_DIR = Path(__file__).resolve().parent.parent / "expected"


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def test_expected_outputs_match():
    """Run all scenarios in order through one engine. Each must match its expected output."""
    engine = GovernanceEngine()
    ordered_names = sorted(p.stem for p in SCENARIO_DIR.glob("*.json"))

    for name in ordered_names:
        scenario = load_json(SCENARIO_DIR / f"{name}.json")
        expected = load_json(EXPECTED_DIR / f"{name}.json")
        actual = format_output(name, engine.decide(scenario))
        assert actual == expected, (
            f"Mismatch for scenario: {name}\n"
            f"  got:      {json.dumps(actual, sort_keys=True)}\n"
            f"  expected: {json.dumps(expected, sort_keys=True)}"
        )
