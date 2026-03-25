"""Corpus lock — CI-enforceable hash of the golden corpus.

If the corpus changes without updating this hash, CI fails.
This protects the moat from accidental semantic rot.
"""

import hashlib
import json

from core.golden_corpus import GOLDEN_CORPUS
from core.canonical import canonical_json


def compute_corpus_hash() -> str:
    """Compute a deterministic hash of the entire golden corpus."""
    corpus_data = []
    for case in GOLDEN_CORPUS:
        corpus_data.append({
            "case_id": case.case_id,
            "category": case.category,
            "expected_verdict": case.expected_verdict,
            "expected_reason": case.expected_reason,
            "expected_executed": case.expected_executed,
            "packet_raw": case.packet_raw,
        })
    serialised = canonical_json(corpus_data)
    return hashlib.sha256(serialised.encode("utf-8")).hexdigest()


# Frozen corpus hash — regenerate with: python -c "from core.corpus_lock import compute_corpus_hash; print(compute_corpus_hash())"
FROZEN_CORPUS_HASH = "86ea803fe9c9279d4c0c371caf91b9e0814fc032586482b85b83f1d94d273983"
