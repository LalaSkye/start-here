"""Tests for canonical packet normal form."""

import pytest
from core.canonical import (
    Packet, canonical_json, canonical_hash,
    validate_raw, packets_equivalent, SCHEMA_VERSION,
)


def _valid_raw(**overrides):
    base = {
        "packet_id": "PKT-001",
        "actor_id": "actor-1",
        "requested_action": "read",
        "object_ref": "/data/file",
        "state_claim": "abc",
        "authority_claim": {"authority_type": "admin", "issued_at": 100, "expires_at": 200, "nonce": "n1"},
        "dependencies": [],
        "timestamp": 150,
        "nonce": "req-n1",
        "provenance": "test",
    }
    base.update(overrides)
    return base


def test_valid_packet_parses():
    p = Packet.from_dict(_valid_raw())
    assert p.packet_id == "PKT-001"
    assert p.requested_action == "read"


def test_canonical_json_deterministic():
    p = Packet.from_dict(_valid_raw())
    assert p.to_canonical_json() == p.to_canonical_json()


def test_canonical_json_sorted():
    j = canonical_json({"z": 1, "a": 2})
    assert j.index('"a"') < j.index('"z"')


def test_canonical_hash_deterministic():
    p = Packet.from_dict(_valid_raw())
    assert p.canonical_hash() == p.canonical_hash()


def test_different_packets_different_hash():
    p1 = Packet.from_dict(_valid_raw(packet_id="PKT-001"))
    p2 = Packet.from_dict(_valid_raw(packet_id="PKT-002"))
    assert p1.canonical_hash() != p2.canonical_hash()


def test_action_normalised_to_lowercase():
    p = Packet.from_dict(_valid_raw(requested_action="READ"))
    assert p.requested_action == "read"


def test_missing_required_field_raises():
    raw = _valid_raw()
    del raw["actor_id"]
    with pytest.raises(ValueError, match="missing_required_field"):
        Packet.from_dict(raw)


def test_empty_required_field_raises():
    with pytest.raises(ValueError, match="empty_required_field"):
        Packet.from_dict(_valid_raw(packet_id=""))


def test_validate_raw_returns_errors():
    errors = validate_raw({})
    assert len(errors) > 0


def test_validate_raw_valid():
    errors = validate_raw(_valid_raw())
    assert errors == []


def test_packets_equivalent_same_input():
    assert packets_equivalent(_valid_raw(), _valid_raw()) is True


def test_packets_equivalent_different():
    assert packets_equivalent(
        _valid_raw(packet_id="A"),
        _valid_raw(packet_id="B"),
    ) is False


def test_dependencies_sorted_by_dep_id():
    raw = _valid_raw(dependencies=[
        {"dep_id": "z-dep", "satisfied": True},
        {"dep_id": "a-dep", "satisfied": True},
    ])
    p = Packet.from_dict(raw)
    assert p.dependencies[0]["dep_id"] == "a-dep"
    assert p.dependencies[1]["dep_id"] == "z-dep"


def test_schema_version_defaults():
    raw = _valid_raw()
    raw.pop("schema_version", None)
    p = Packet.from_dict(raw)
    assert p.schema_version == SCHEMA_VERSION
