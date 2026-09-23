#!/usr/bin/env python3
# ======================================================================
# run_read_only_audit.py — версия 1.0
# Fail-closed wrapper: фиксирует Git/input state до и после audit command.
# ======================================================================

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule  # noqa: E402

READ_ONLY_PROMPT_IDS = {
    "APS-PROMPT-AUDIT-STANDARD-001",
    "APS-PROMPT-AUDIT-TZ-001",
    "APS-PROMPT-AUDIT-GIT-001",
    "APS-PROMPT-AUDIT-MATCHING-001",
    "APS-PROMPT-AUDIT-DOCUMENTS-001",
    "APS-PROMPT-AUDIT-REACHABLE-NEVER-EXECUTED-001",
    "APS-PROMPT-AUDIT-TZ-LIFECYCLE-001",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git(root: Path, *args: str, binary: bool = False) -> bytes | str:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=False,
        text=not binary,
    )
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", "replace") if binary else proc.stderr
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr.strip()}")
    return proc.stdout


def _nul_items(payload: bytes) -> list[bytes]:
    return [item for item in payload.split(b"\0") if item]


def _tracked_records(root: Path) -> list[dict[str, Any]]:
    paths = [item.decode("utf-8", "surrogateescape") for item in _nul_items(_git(root, "ls-files", "-z", binary=True))]
    records: list[dict[str, Any]] = []
    for rel in sorted(paths):
        path = root / rel
        records.append({
            "path": rel,
            "kind": "file" if path.is_file() else ("symlink" if path.is_symlink() else "missing"),
            "sha256": _sha256(path) if path.is_file() else None,
        })
    return records


def _untracked_records(root: Path) -> list[dict[str, Any]]:
    raw = _git(root, "ls-files", "--others", "--exclude-standard", "-z", binary=True)
    paths = [item.decode("utf-8", "surrogateescape") for item in _nul_items(raw)]
    records: list[dict[str, Any]] = []
    for rel in sorted(paths):
        path = root / rel
        records.append({"path": rel, "sha256": _sha256(path) if path.is_file() else None})
    return records


def _text_digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def capture_state(root: Path, inputs: list[Path] | None = None) -> dict[str, Any]:
    branch_proc = subprocess.run(
        ["git", "-C", str(root), "symbolic-ref", "--quiet", "--short", "HEAD"],
        capture_output=True, text=True, check=False,
    )
    branch = branch_proc.stdout.strip() if branch_proc.returncode == 0 else "(detached)"
    head = str(_git(root, "rev-parse", "HEAD")).strip()
    git_dir_raw = str(_git(root, "rev-parse", "--git-dir")).strip()
    git_dir = Path(git_dir_raw)
    if not git_dir.is_absolute():
        git_dir = (root / git_dir).resolve()
    index_payload = _git(root, "ls-files", "--stage", "-z", binary=True)
    refs = str(_git(root, "for-each-ref", "--format=%(refname)%00%(objectname)"))
    stash = str(_git(root, "stash", "list", "--format=%gd%x00%H%x00%gs"))
    worktrees = str(_git(root, "worktree", "list", "--porcelain"))
    operation_markers = {
        name: (git_dir / name).exists()
        for name in ("MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG", "rebase-merge", "rebase-apply")
    }
    input_records = []
    for item in inputs or []:
        resolved = item.resolve()
        input_records.append({
            "path": str(resolved),
            "exists": resolved.is_file(),
            "sha256": _sha256(resolved) if resolved.is_file() else None,
        })
    return {
        "branch": branch,
        "head": head,
        "index_tree_sha256": hashlib.sha256(index_payload).hexdigest(),
        "tracked": _tracked_records(root),
        "untracked": _untracked_records(root),
        "refs_sha256": _text_digest(refs),
        "refs": refs.splitlines(),
        "stash_sha256": _text_digest(stash),
        "stash": stash.splitlines(),
        "worktree_list_sha256": _text_digest(worktrees),
        "worktree_list": worktrees.splitlines(),
        "operation_markers": operation_markers,
        "inputs": input_records,
    }


def _finding(code: str, rule_id: str, message: str, **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, "ERROR", evidence)


@enforces_rule("APS-PROMPT-AUDIT-STANDARD-001")
@enforces_rule("APS-PROMPT-AUDIT-TZ-001")
@enforces_rule("APS-PROMPT-AUDIT-GIT-001")
@enforces_rule("APS-PROMPT-AUDIT-MATCHING-001")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "READ_ONLY_AUDIT_MUTATION_DETECTED")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "READ_ONLY_AUDIT_INPUT_MUTATED")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "READ_ONLY_AUDIT_MUTATION_DETECTED")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "READ_ONLY_AUDIT_INPUT_MUTATED")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "READ_ONLY_AUDIT_MUTATION_DETECTED")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "READ_ONLY_AUDIT_BRANCH_CHANGED")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "READ_ONLY_AUDIT_INDEX_CHANGED")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "READ_ONLY_AUDIT_REF_CHANGED")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "READ_ONLY_AUDIT_INPUT_MUTATED")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "READ_ONLY_AUDIT_MUTATION_DETECTED")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "READ_ONLY_AUDIT_INPUT_MUTATED")
def compare_states(before: dict[str, Any], after: dict[str, Any], prompt_id: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    if before.get("branch") != after.get("branch") or before.get("head") != after.get("head"):
        findings.append(_finding(
            "READ_ONLY_AUDIT_BRANCH_CHANGED", prompt_id,
            "Audit command changed branch or HEAD.",
            before_branch=before.get("branch"), after_branch=after.get("branch"),
            before_head=before.get("head"), after_head=after.get("head"),
        ))
    if before.get("index_tree_sha256") != after.get("index_tree_sha256"):
        findings.append(_finding("READ_ONLY_AUDIT_INDEX_CHANGED", prompt_id, "Audit command changed the Git index."))
    if before.get("refs_sha256") != after.get("refs_sha256") or before.get("stash_sha256") != after.get("stash_sha256"):
        findings.append(_finding("READ_ONLY_AUDIT_REF_CHANGED", prompt_id, "Audit command changed refs or stash state."))
    if before.get("tracked") != after.get("tracked") or before.get("untracked") != after.get("untracked"):
        findings.append(_finding("READ_ONLY_AUDIT_MUTATION_DETECTED", prompt_id, "Audit command changed tracked or untracked repository contents."))
    if before.get("worktree_list_sha256") != after.get("worktree_list_sha256") or before.get("operation_markers") != after.get("operation_markers"):
        findings.append(_finding("READ_ONLY_AUDIT_MUTATION_DETECTED", prompt_id, "Audit command changed worktree or in-progress Git operation state."))
    if before.get("inputs") != after.get("inputs"):
        findings.append(_finding("READ_ONLY_AUDIT_INPUT_MUTATED", prompt_id, "Audit command changed an input artifact."))
    return findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Execute an audit command with fail-closed read-only state enforcement.")
    parser.add_argument("--root", required=True)
    parser.add_argument("--prompt-id", required=True, choices=sorted(READ_ONLY_PROMPT_IDS))
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--input", action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    evidence_path = Path(args.evidence).resolve()
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        print("audit command is required", file=sys.stderr)
        return 2
    inputs = [Path(value).resolve() for value in args.input]
    try:
        before = capture_state(root, inputs)
    except (OSError, RuntimeError) as exc:
        print(f"READ_ONLY_AUDIT_PREFLIGHT_FAILED: {exc}", file=sys.stderr)
        return 2
    env = dict(os.environ)
    env.update({"APS_AUDIT_PROMPT_ID": args.prompt_id, "PYTHONDONTWRITEBYTECODE": "1"})
    proc = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, check=False)
    try:
        after = capture_state(root, inputs)
    except (OSError, RuntimeError) as exc:
        after = {"capture_error": str(exc)}
    findings = compare_states(before, after, args.prompt_id) if "capture_error" not in after else [
        _finding("READ_ONLY_AUDIT_MUTATION_DETECTED", args.prompt_id, "Post-audit repository state could not be captured.", error=after["capture_error"])
    ]
    payload = {
        "schema_version": "1.0.0",
        "prompt_id": args.prompt_id,
        "root": str(root),
        "command": command,
        "command_exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "before": before,
        "after": after,
        "findings": [item.as_dict() for item in findings],
        "status": "PASS" if not findings and proc.returncode == 0 else ("MUTATION_DETECTED" if findings else "COMMAND_FAILED"),
    }
    evidence_path.parent.mkdir(parents=True, exist_ok=True)
    evidence_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for item in findings:
        print("APS_AUDIT_DIAGNOSTIC:" + json.dumps(item.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    if findings:
        return 3
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
