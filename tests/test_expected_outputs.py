"""Golden output tests. Scenarios must match expected files exactly."""

import json
import pathlib
import pytest

from src.engine import decide
from src.output import format_result

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCENARIOS = ROOT / "scenarios"
EXPECTED = ROOT / "expected"


def scenario_names():
    return sorted(p.stem for p in SCENARIOS.glob("*.json"))


@pytest.mark.parametrize("name", scenario_names())
def test_scenario_matches_expected(name):
    with open(SCENARIOS / f"{name}.json") as f:
        scenario = json.load(f)
    with open(EXPECTED / f"{name}.json") as f:
        expected = json.load(f)

    result = decide(scenario)
    actual = format_result(name, result)

    assert actual == expected, (
        f"'{name}' mismatch.\n"
        f"  got:      {json.dumps(actual, sort_keys=True)}\n"
        f"  expected: {json.dumps(expected, sort_keys=True)}"
    )
