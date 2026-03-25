"""Corpus lock test — CI must fail if the golden corpus changes silently."""

from core.corpus_lock import compute_corpus_hash, FROZEN_CORPUS_HASH


def test_corpus_hash_matches_frozen():
    """If this fails, the golden corpus was changed without updating the frozen hash.

    To update after intentional changes:
        python -c "from core.corpus_lock import compute_corpus_hash; print(compute_corpus_hash())"
    Then paste the new hash into core/corpus_lock.py.
    """
    current = compute_corpus_hash()
    assert current == FROZEN_CORPUS_HASH, (
        f"Corpus hash drift detected.\n"
        f"  frozen:  {FROZEN_CORPUS_HASH}\n"
        f"  current: {current}\n"
        f"  If this change was intentional, update FROZEN_CORPUS_HASH in core/corpus_lock.py"
    )
