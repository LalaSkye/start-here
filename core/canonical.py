"""CANONICAL_PACKET_NORMAL_FORM_v1 — Deterministic packet canonicalisation.

Every input packet must reduce to one and only one canonical representation
before evaluation. This destroys ambiguity, formatting-based bypass, and
"close enough" copies.

Core rule:
  Semantic equivalence must imply identical canonical form.

If two packets differ in canonical form, they are different packets.
If two systems produce different canonical forms for the same input, they
are not equivalent implementations.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------------------
# Schema version — all packets are bound to a schema epoch
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0.0"

# ---------------------------------------------------------------------------
# Required fields (ordered). This ordering is the canonical field order.
# ---------------------------------------------------------------------------

REQUIRED_FIELDS = (
    "packet_id",
    "schema_version",
    "actor_id",
    "requested_action",
    "object_ref",
    "state_claim",
    "authority_claim",
    "dependencies",
    "timestamp",
    "nonce",
    "provenance",
)

# Optional fields that may appear but are not required
OPTIONAL_FIELDS = (
    "flags",
    "proof_obligations",
    "payload_hash",
)

ALL_FIELDS = REQUIRED_FIELDS + OPTIONAL_FIELDS

# ---------------------------------------------------------------------------
# Canonical JSON serialisation
# ---------------------------------------------------------------------------

def canonical_json(data: dict) -> str:
    """Deterministic JSON. Sorted keys, no whitespace, ASCII-safe.

    Two semantically equivalent packets must produce identical strings.
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def canonical_hash(data: dict) -> str:
    """SHA-256 of canonical JSON form."""
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Packet normal form
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    """A governance packet in canonical normal form.

    Construction validates and normalises. The resulting object
    is the single canonical representation.
    """
    packet_id: str
    schema_version: str
    actor_id: str
    requested_action: str
    object_ref: str
    state_claim: str
    authority_claim: dict
    dependencies: list[dict]
    timestamp: int
    nonce: str
    provenance: str
    flags: dict = field(default_factory=dict)
    proof_obligations: list[dict] = field(default_factory=list)
    payload_hash: str = ""

    def to_dict(self) -> dict:
        """Canonical dict representation. Field order is deterministic."""
        d = {}
        for f in ALL_FIELDS:
            val = getattr(self, f, None)
            if val is not None and f in REQUIRED_FIELDS:
                d[f] = val
            elif val is not None and f in OPTIONAL_FIELDS and val:
                d[f] = val
        return d

    def to_canonical_json(self) -> str:
        return canonical_json(self.to_dict())

    def canonical_hash(self) -> str:
        return canonical_hash(self.to_dict())

    @classmethod
    def from_dict(cls, raw: dict) -> Packet:
        """Parse and normalise a raw dict into canonical form.

        Raises ValueError if required fields are missing or invalid.
        """
        errors = validate_raw(raw)
        if errors:
            raise ValueError(f"Packet validation failed: {'; '.join(errors)}")

        return cls(
            packet_id=str(raw["packet_id"]).strip(),
            schema_version=str(raw.get("schema_version", SCHEMA_VERSION)).strip(),
            actor_id=str(raw["actor_id"]).strip(),
            requested_action=str(raw["requested_action"]).strip().lower(),
            object_ref=str(raw["object_ref"]).strip(),
            state_claim=str(raw.get("state_claim", "")).strip(),
            authority_claim=_normalise_authority(raw.get("authority_claim", {})),
            dependencies=_normalise_dependencies(raw.get("dependencies", [])),
            timestamp=int(raw["timestamp"]),
            nonce=str(raw["nonce"]).strip(),
            provenance=str(raw.get("provenance", "")).strip(),
            flags=raw.get("flags", {}),
            proof_obligations=raw.get("proof_obligations", []),
            payload_hash=str(raw.get("payload_hash", "")).strip(),
        )


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_raw(raw: dict) -> list[str]:
    """Validate a raw packet dict. Returns list of error strings (empty = valid)."""
    errors = []

    if not isinstance(raw, dict):
        return ["packet_must_be_dict"]

    for field_name in REQUIRED_FIELDS:
        if field_name == "schema_version":
            continue  # defaults to current
        if field_name not in raw or raw[field_name] is None:
            errors.append(f"missing_required_field:{field_name}")
        elif isinstance(raw[field_name], str) and not raw[field_name].strip():
            if field_name not in ("state_claim", "provenance"):
                errors.append(f"empty_required_field:{field_name}")

    if "timestamp" in raw:
        try:
            int(raw["timestamp"])
        except (TypeError, ValueError):
            errors.append("invalid_timestamp")

    return errors


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------

def _normalise_authority(auth: Any) -> dict:
    if not isinstance(auth, dict):
        return {}
    return {
        "authority_type": str(auth.get("authority_type", "")).strip().lower(),
        "issued_at": int(auth.get("issued_at", 0)),
        "expires_at": int(auth.get("expires_at", 0)),
        "nonce": str(auth.get("nonce", "")).strip(),
    }


def _normalise_dependencies(deps: Any) -> list[dict]:
    if not isinstance(deps, list):
        return []
    normalised = []
    for dep in deps:
        if isinstance(dep, dict):
            normalised.append({
                "dep_id": str(dep.get("dep_id", "")).strip(),
                "satisfied": bool(dep.get("satisfied", False)),
                "evidence_hash": str(dep.get("evidence_hash", "")).strip(),
            })
    return sorted(normalised, key=lambda d: d["dep_id"])


# ---------------------------------------------------------------------------
# Equivalence
# ---------------------------------------------------------------------------

def packets_equivalent(a: dict, b: dict) -> bool:
    """Two packets are equivalent iff their canonical forms are identical."""
    try:
        pa = Packet.from_dict(a)
        pb = Packet.from_dict(b)
        return pa.to_canonical_json() == pb.to_canonical_json()
    except ValueError:
        return False
