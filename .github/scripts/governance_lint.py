#!/usr/bin/env python3
"""
Governance Lint — NEGATION_KERNEL_v1.3 derived lint layer.

ARTEFACT: GOVERNANCE_LINT_GITHUB_ACTIONS_IMPLEMENTATION_PACK_v1
CLASS:    CI_INTEGRATION / NON_EXEC
AUTHOR:   Ricky Dean Jones
DATE:     2026-03-26

DESIGN PRINCIPLE:
    The lint layer does not rewrite prose, infer missing structure,
    or invent mechanisms. It only detects, classifies, labels,
    comments, and optionally fails protected surfaces.

Pipeline: parse files -> sentence split -> detect triggers
          -> check bindings -> classify AMBIGUOUS/PASS -> output JSON
"""

import argparse
import fnmatch
import json
import os
import re
import sys
from pathlib import Path

# ── Term registries ──────────────────────────────────────────────────────────

ENTITY_TERMS = [
    "user", "agent", "owner", "controller", "approver", "overseer",
    "authority", "actor", "decision-maker", "human", "reviewer",
    "operator", "system", "responsible person", "trusted reviewer",
    "compliance", "security", "legal",
]

TRIGGER_TERMS = [
    "approved", "decided", "allowed", "verified", "reviewed", "ensured",
    "responsible", "oversight", "controlled", "intended", "determined",
    "required", "validated", "authorised", "authorized", "proceed",
    "proceeds", "blocked", "released", "release",
]

INTERFACE_HINTS = [
    "token", "field", "form", "api", "log", "entry", "record",
    "signature", "sign-off", "signoff", "input", "selection",
]

MECHANISM_HINTS = [
    "workflow", "validator", "service", "procedure", "engine", "step",
    "process", "check", "validation", "review step", "gate check",
]

CONSTRAINT_HINTS = [
    "threshold", "criteria", "checklist", "invariant", "conditions",
    "defined conditions", "policy", "rule", "risk score", "valid",
]

ENFORCEMENT_HINTS = [
    "block", "blocked", "gate", "escalate", "escalation", "audit",
    "logged", "log", "proceeds only if", "doesn't proceed",
    "does not proceed", "before execution", "required before execution",
]

QUESTION_TEMPLATES = {
    "interface": "Where is this recorded (field, form, API, log)?",
    "mechanism": "What executes this step (workflow, service, procedure)?",
    "constraint": "What criteria govern this (thresholds, checklist, invariants)?",
    "enforcement": "What changes if this is absent (block, route, escalate, log)?",
}

# ── Scanned extensions ───────────────────────────────────────────────────────

SCANNED_EXTENSIONS = {".md", ".txt", ".rst", ".yaml", ".yml", ".json"}


# ── Helpers ──────────────────────────────────────────────────────────────────

def load_protected_paths(path: str) -> list[str]:
    """Load glob patterns from the protected-paths file."""
    patterns = []
    if not os.path.exists(path):
        return patterns
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                patterns.append(line)
    return patterns


def is_protected(filepath: str, patterns: list[str]) -> bool:
    """Check whether a file path matches any protected-surface pattern."""
    # Normalise to forward-slash posix style
    filepath = filepath.replace("\\", "/")
    for pattern in patterns:
        if fnmatch.fnmatch(filepath, pattern):
            return True
    return False


def split_sentences(text: str) -> list[str]:
    """Naive sentence splitter on period / exclamation / question mark
    followed by whitespace or end-of-string."""
    raw = re.split(r'(?<=[.!?])\s+', text)
    return [s.strip() for s in raw if s.strip()]


def _has_any(sentence_lower: str, terms: list[str]) -> bool:
    """Return True if any term appears in the lowered sentence."""
    for term in terms:
        if term in sentence_lower:
            return True
    return False


def analyse_sentence(sentence: str) -> dict:
    """Run the binding check on a single sentence.

    Returns a result dict with verdict and binding details.
    """
    lower = sentence.lower()

    has_entity = _has_any(lower, ENTITY_TERMS)
    has_trigger = _has_any(lower, TRIGGER_TERMS)

    # Only flag sentences that contain both an entity and a trigger
    if not (has_entity and has_trigger):
        return {
            "sentence": sentence,
            "verdict": "PASS",
            "has_entity": has_entity,
            "has_trigger": has_trigger,
            "interface_present": False,
            "mechanism_present": False,
            "constraint_present": False,
            "enforcement_present": False,
            "mechanism_missing": False,
            "enforcement_missing": False,
            "questions": [],
        }

    interface_present = _has_any(lower, INTERFACE_HINTS)
    mechanism_present = _has_any(lower, MECHANISM_HINTS)
    constraint_present = _has_any(lower, CONSTRAINT_HINTS)
    enforcement_present = _has_any(lower, ENFORCEMENT_HINTS)

    questions: list[str] = []
    if not interface_present:
        questions.append(QUESTION_TEMPLATES["interface"])
    if not mechanism_present:
        questions.append(QUESTION_TEMPLATES["mechanism"])
    if not constraint_present:
        questions.append(QUESTION_TEMPLATES["constraint"])
    if not enforcement_present:
        questions.append(QUESTION_TEMPLATES["enforcement"])

    # A sentence is AMBIGUOUS when it has entity+trigger but lacks
    # at least one binding category.
    all_bound = interface_present and mechanism_present and constraint_present and enforcement_present
    verdict = "PASS" if all_bound else "AMBIGUOUS"

    return {
        "sentence": sentence,
        "verdict": verdict,
        "has_entity": has_entity,
        "has_trigger": has_trigger,
        "interface_present": interface_present,
        "mechanism_present": mechanism_present,
        "constraint_present": constraint_present,
        "enforcement_present": enforcement_present,
        "mechanism_missing": not mechanism_present,
        "enforcement_missing": not enforcement_present,
        "questions": questions,
    }


def lint_file(filepath: str, protected_patterns: list[str]) -> list[dict]:
    """Lint every sentence in a single file. Returns per-sentence results."""
    results = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except Exception as exc:
        return [{
            "file": filepath,
            "error": str(exc),
            "verdict": "ERROR",
        }]

    protected = is_protected(filepath, protected_patterns)
    sentences = split_sentences(text)

    for idx, sentence in enumerate(sentences):
        result = analyse_sentence(sentence)
        result["file"] = filepath
        result["sentence_index"] = idx
        result["is_protected_surface"] = protected
        result["waived"] = False  # waiver injection point
        results.append(result)

    return results


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Governance lint — detects unbound governance language."
    )
    parser.add_argument(
        "--files",
        required=True,
        help="Space-separated list of changed file paths.",
    )
    parser.add_argument(
        "--protected-paths",
        required=True,
        help="Path to the protected_paths.txt file.",
    )
    parser.add_argument(
        "--mode",
        choices=["MODE_A", "MODE_B", "MODE_C"],
        default="MODE_A",
        help="Operating mode (default: MODE_A = warn only).",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Path to write the JSON results file.",
    )

    args = parser.parse_args()

    protected_patterns = load_protected_paths(args.protected_paths)
    file_list = args.files.split()

    all_results: list[dict] = []
    files_scanned = 0
    ambiguous_count = 0
    protected_ambiguous_count = 0

    for filepath in file_list:
        ext = Path(filepath).suffix.lower()
        if ext not in SCANNED_EXTENSIONS:
            continue
        if not os.path.exists(filepath):
            continue

        files_scanned += 1
        file_results = lint_file(filepath, protected_patterns)
        for r in file_results:
            if r.get("verdict") == "AMBIGUOUS":
                ambiguous_count += 1
                if r.get("is_protected_surface"):
                    protected_ambiguous_count += 1
        all_results.extend(file_results)

    output = {
        "artefact": "GOVERNANCE_LINT_GITHUB_ACTIONS_IMPLEMENTATION_PACK_v1",
        "mode": args.mode,
        "summary": {
            "files_scanned": files_scanned,
            "sentences_analysed": len(all_results),
            "ambiguous_count": ambiguous_count,
            "protected_ambiguous_count": protected_ambiguous_count,
        },
        "results": all_results,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    # Print summary to stdout for CI log readability
    print(f"Governance Lint — mode={args.mode}")
    print(f"  Files scanned:              {files_scanned}")
    print(f"  Sentences analysed:         {len(all_results)}")
    print(f"  AMBIGUOUS sentences:        {ambiguous_count}")
    print(f"  Protected + AMBIGUOUS:      {protected_ambiguous_count}")

    if ambiguous_count > 0:
        print("\n  Flagged sentences:")
        for r in all_results:
            if r.get("verdict") == "AMBIGUOUS":
                prot_tag = " [PROTECTED]" if r.get("is_protected_surface") else ""
                print(f"    - {r['file']}:{r['sentence_index']}{prot_tag}")
                print(f"      \"{r['sentence'][:120]}...\"" if len(r["sentence"]) > 120 else f"      \"{r['sentence']}\"")
                for q in r.get("questions", []):
                    print(f"        ? {q}")


if __name__ == "__main__":
    main()
