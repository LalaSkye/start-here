"""Output formatting."""

import json


def format_result(name, result):
    """Wrap engine result with scenario name."""
    return {
        "scenario": name,
        "decision": result["decision"],
        "reason_code": result["reason_code"],
        "executed": result["executed"],
    }


def print_result(output):
    """Print one result line."""
    symbols = {"ALLOW": "+", "DENY": "x", "ESCALATE": "?"}
    d = output["decision"]
    s = symbols.get(d, " ")
    print(f"  [{s}] {output['scenario']:12s} -> {d:10s}  ({output['reason_code']})")


def to_json(obj):
    return json.dumps(obj, sort_keys=True, indent=2)
