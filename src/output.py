def format_output(name: str, result: dict) -> dict:
    return {
        "scenario": name,
        "decision": result["decision"],
        "reason_code": result["reason_code"],
        "executed": result["executed"],
    }
