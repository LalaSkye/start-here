"""Golden conformance corpus tests.

If any case fails, the implementation is non-conformant.
"""

from core.golden_corpus import GOLDEN_CORPUS
from core.conformance import run_corpus, conformance_report


def test_golden_corpus_all_pass():
    """Every case in the golden corpus must produce the expected verdict."""
    results = run_corpus(GOLDEN_CORPUS)
    report = conformance_report(results)

    failures = [r for r in results if not r.passed]
    if failures:
        lines = [f"CONFORMANCE FAILURES ({len(failures)}/{len(results)}):"]
        for f in failures:
            lines.append(
                f"  {f.case_id}: expected {f.expected_verdict}({f.expected_reason}) "
                f"got {f.actual_verdict}({f.actual_reason})"
            )
        raise AssertionError("\n".join(lines))


def test_corpus_has_minimum_coverage():
    """Corpus must cover all major categories."""
    categories = {c.category for c in GOLDEN_CORPUS}
    assert "VALID" in categories
    assert "CLOSED" in categories
    assert "MALFORMED" in categories
    assert "PARADOX" in categories
    assert "REPLAY" in categories
    assert "PROOF" in categories
    assert "NEAR_VALID" in categories


def test_corpus_has_at_least_15_cases():
    assert len(GOLDEN_CORPUS) >= 15


def test_no_duplicate_case_ids():
    ids = [c.case_id for c in GOLDEN_CORPUS]
    assert len(ids) == len(set(ids))
