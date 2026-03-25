from src.canonical import canonical_json


def test_canonical_json_sorted_keys():
    data = {"b": 1, "a": 2}
    output = canonical_json(data)
    assert output.index('"a"') < output.index('"b"')


def test_canonical_json_deterministic():
    data = {"z": 1, "m": 2, "a": 3}
    assert canonical_json(data) == canonical_json(data)
