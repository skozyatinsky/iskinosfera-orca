#!/usr/bin/env python3
# ======================================================================
# project_health_release.py — версия 1.0
# Изолированный project-health evidence на exact Git candidate.
# ======================================================================
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from release_integrity import compare_records
from release_source_identity import identify_release_source
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

RULE_ID = "APS-RELEASE-PROJECT-HEALTH-ISOLATION-001"


def _git(root: Path, *args: str) -> str:
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"PROJECT_HEALTH_GIT_FAILED:{' '.join(args)}:{(proc.stderr or proc.stdout).strip()}")
    return proc.stdout.strip()


def resolve_repository_root(source_root: Path) -> tuple[Path, Path]:
    """Return the enclosing Git repository and the package path inside it."""
    source_root = source_root.resolve()
    repository = Path(_git(source_root, "rev-parse", "--show-toplevel")).resolve()
    try:
        relative = source_root.relative_to(repository)
    except ValueError as exc:
        raise RuntimeError("PROJECT_HEALTH_SOURCE_OUTSIDE_REPOSITORY") from exc
    return repository, relative


def clone_exact_candidate(source_root: Path, destination: Path, expected_commit: str) -> Path:
    """Clone the enclosing repository and materialize only the package subtree."""
    repository, relative = resolve_repository_root(source_root)
    proc = subprocess.run(
        ["git", "clone", "--no-hardlinks", "--quiet", "--no-checkout", str(repository), str(destination)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"PROJECT_HEALTH_CLONE_FAILED:{proc.stderr.strip()}")
    if relative != Path("."):
        _git(destination, "sparse-checkout", "init", "--cone")
        _git(destination, "sparse-checkout", "set", relative.as_posix())
    _git(destination, "checkout", "--quiet", expected_commit)
    candidate_root = destination / relative
    if not candidate_root.is_dir():
        raise RuntimeError(f"PROJECT_HEALTH_PACKAGE_ROOT_MISSING:{relative.as_posix()}")
    return candidate_root


@enforces_rule("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "PROJECT_HEALTH_PASS_FINDINGS_CONSISTENT")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "PROJECT_HEALTH_PASS_WITH_UNRESOLVED_HIGH")
def validate_health_pass_consistency(health: dict[str, Any]) -> list[RuleFinding]:
    severe = [
        item for item in health.get("findings", [])
        if isinstance(item, dict) and item.get("severity") in {"HIGH", "BLOCKING"}
    ]
    if health.get("status") == "PASS" and severe:
        return [RuleFinding(
            "PROJECT_HEALTH_PASS_WITH_UNRESOLVED_HIGH", RULE_ID,
            "Project-health PASS contains unresolved HIGH/BLOCKING findings.", "ERROR",
            {"finding_codes": [item.get("finding_code") for item in severe]},
        )]
    return []


@enforces_rule("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "PROJECT_HEALTH_ISOLATED_CANDIDATE_VALID")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "PROJECT_HEALTH_ISOLATED_CANDIDATE_IDENTITY_MISMATCH")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "PROJECT_HEALTH_ISOLATED_CANDIDATE_MUTATED")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "EXPECTED_DETACHED_CANDIDATE")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "ORPHAN_WORKTREE")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "PROJECT_HEALTH_ISOLATED_CANDIDATE_FAILED")
def run_isolated_project_health(
    source_repo: Path,
    *,
    expected_commit: str,
    expected_tree: str,
    expected_records: list[dict[str, Any]],
    output: Path,
) -> tuple[dict[str, Any], list[RuleFinding]]:
    findings: list[RuleFinding] = []
    with tempfile.TemporaryDirectory(prefix="aps_project_health_candidate_") as raw:
        repository_candidate = Path(raw) / "candidate"
        try:
            candidate = clone_exact_candidate(source_repo, repository_candidate, expected_commit)
        except RuntimeError as exc:
            findings.append(RuleFinding("PROJECT_HEALTH_ISOLATED_CANDIDATE_IDENTITY_MISMATCH", RULE_ID, "Candidate clone failed", "ERROR", {"stderr": str(exc)}))
            report = {"status": "FAIL", "findings": [item.as_dict() for item in findings]}
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            return report, findings
        before = identify_release_source(candidate)
        if before.commit_sha != expected_commit or before.tree_sha != expected_tree or compare_records(expected_records, before.records):
            findings.append(RuleFinding(
                "PROJECT_HEALTH_ISOLATED_CANDIDATE_IDENTITY_MISMATCH", RULE_ID,
                "Isolated project-health candidate does not match expected commit/tree/manifest.", "ERROR",
                {"expected_commit": expected_commit, "actual_commit": before.commit_sha, "expected_tree": expected_tree, "actual_tree": before.tree_sha},
            ))
        health_path = candidate / ".aps_project_health_report.json"
        env = dict(os.environ)
        env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider"})
        command = [
            sys.executable, "tools/project_health_audit.py", "--root", ".", "--profile", "release",
            "--mode", "full", "--audit-type", "MANUAL", "--protected-ref", "HEAD",
            "--candidate-context", "EXPECTED_DETACHED_CANDIDATE",
            "--output", str(health_path),
        ]
        proc = subprocess.run(command, cwd=candidate, env=env, capture_output=True, text=True)
        health = json.loads(health_path.read_text(encoding="utf-8-sig")) if health_path.is_file() else {"status": "FAIL", "findings": ["PROJECT_HEALTH_REPORT_MISSING"]}
        findings.extend(validate_health_pass_consistency(health))
        health_path.unlink(missing_ok=True)
        after_records = identify_release_source(candidate).records
        dirty = _git(repository_candidate, "status", "--porcelain", "--untracked-files=all")
        if compare_records(expected_records, after_records) or dirty:
            findings.append(RuleFinding(
                "PROJECT_HEALTH_ISOLATED_CANDIDATE_MUTATED", RULE_ID,
                "Project-health execution changed the isolated candidate.", "ERROR", {"git_status": dirty},
            ))
        if proc.returncode != 0 or health.get("status") != "PASS":
            findings.append(RuleFinding(
                "PROJECT_HEALTH_ISOLATED_CANDIDATE_FAILED", RULE_ID,
                "Project-health audit failed inside the isolated candidate.", "ERROR",
                {"exit_code": proc.returncode, "health_status": health.get("status"), "stderr": proc.stderr.strip()},
            ))
        if not findings:
            findings.append(RuleFinding(
                "PROJECT_HEALTH_ISOLATED_CANDIDATE_VALID", RULE_ID,
                "Project-health audit passed on an immutable exact-candidate clone.", "INFO",
                {"commit": expected_commit, "tree": expected_tree, "file_count": len(expected_records)},
            ))
        report = {
            "status": "PASS" if all(item.severity != "ERROR" for item in findings) else "FAIL",
            "candidate": {"commit": expected_commit, "tree": expected_tree, "file_count": len(expected_records)},
            "health_report": health,
            "findings": [item.as_dict() for item in findings],
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return report, findings


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-repo", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--source-records", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    records = json.loads(Path(args.source_records).read_text(encoding="utf-8-sig"))
    report, _ = run_isolated_project_health(
        Path(args.source_repo).resolve(), expected_commit=args.expected_commit, expected_tree=args.expected_tree,
        expected_records=records, output=Path(args.output).resolve(),
    )
    print(json.dumps({"status": report["status"]}, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
