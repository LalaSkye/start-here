import json


def canonical_json(data: dict) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True)
