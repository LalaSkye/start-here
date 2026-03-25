REQUIRED_FIELDS = {"actor", "action", "target", "authority", "policy", "request_id"}


def validate_scenario(scenario: dict) -> tuple[bool, str | None]:
    if not isinstance(scenario, dict):
        return False, "scenario_not_object"

    missing = REQUIRED_FIELDS - set(scenario.keys())
    if missing:
        return False, f"missing_fields:{','.join(sorted(missing))}"

    for field in REQUIRED_FIELDS:
        if not isinstance(scenario[field], str) or not scenario[field].strip():
            return False, f"invalid_field:{field}"

    return True, None
