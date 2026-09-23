#!/usr/bin/env python3
# ======================================================================
# verify_read_only_audit.py — версия 1.0
# Независимая проверка evidence read-only audit wrapper.
# ======================================================================

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from run_read_only_audit import READ_ONLY_PROMPT_IDS, capture_state, compare_states  # noqa: E402


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_evidence(data: dict[str, Any], root: Path | None = None) -> list[str]:
    findings: list[str] = []
    prompt_id = data.get("prompt_id")
    if prompt_id not in READ_ONLY_PROMPT_IDS:
        findings.append("READ_ONLY_AUDIT_PROMPT_ID_UNKNOWN")
    before, after = data.get("before"), data.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        findings.append("READ_ONLY_AUDIT_EVIDENCE_INVALID")
        return findings
    recomputed = compare_states(before, after, str(prompt_id))
    recorded = data.get("findings", [])
    recorded_codes = sorted(item.get("code") for item in recorded if isinstance(item, dict))
    recomputed_codes = sorted(item.code for item in recomputed)
    if recorded_codes != recomputed_codes:
        findings.append("READ_ONLY_AUDIT_EVIDENCE_FINDINGS_MISMATCH")
    expected_status = "PASS" if not recomputed and data.get("command_exit_code") == 0 else ("MUTATION_DETECTED" if recomputed else "COMMAND_FAILED")
    if data.get("status") != expected_status:
        findings.append("READ_ONLY_AUDIT_EVIDENCE_STATUS_MISMATCH")
    for record in after.get("inputs", []):
        if not isinstance(record, dict) or not record.get("exists"):
            continue
        path = Path(str(record.get("path", "")))
        if not path.is_file() or _sha256(path) != record.get("sha256"):
            findings.append("READ_ONLY_AUDIT_INPUT_MUTATED")
    if root is not None:
        current = capture_state(root, [Path(item["path"]) for item in after.get("inputs", []) if isinstance(item, dict) and item.get("path")])
        if current != after:
            findings.append("READ_ONLY_AUDIT_CURRENT_STATE_MISMATCH")
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--root")
    args = parser.parse_args()
    try:
        data = json.loads(Path(args.evidence).read_text(encoding="utf-8-sig"))
        findings = verify_evidence(data, Path(args.root).resolve() if args.root else None)
    except (OSError, json.JSONDecodeError, RuntimeError, KeyError, TypeError) as exc:
        findings = ["READ_ONLY_AUDIT_EVIDENCE_INVALID"]
        print(f"READ_ONLY_AUDIT_EVIDENCE_INVALID: {type(exc).__name__}", file=sys.stderr)
    for code in findings:
        print(code)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
