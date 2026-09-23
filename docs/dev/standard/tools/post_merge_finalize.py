#!/usr/bin/env python3
# ======================================================================
# post_merge_finalize.py — версия 2.0
# Protected-branch-bound post-merge saga with deterministic recovery.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TRUSTED_GIT_EXECUTABLE = str(Path("/usr/bin/git").resolve()) if Path("/usr/bin/git").exists() else "git"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import (ATTESTATION_KEY_ENV, ATTESTATION_KEY_ID_ENV, REVOKED_KEY_IDS_ENV, SIGNER_IDENTITY_ENV, ControlPlaneError, OrchestratorDB, TRUST_ENV)  # noqa: E402
from trusted_execution import candidate_worktree, resolve_commit, run_command  # noqa: E402
from v128_validation import all_function_findings  # noqa: E402
from verify_agent_result import run_architecture_graph  # noqa: E402




@contextmanager
def candidate_check_context():
    keys = (TRUST_ENV, ATTESTATION_KEY_ENV, ATTESTATION_KEY_ID_ENV, REVOKED_KEY_IDS_ENV, SIGNER_IDENTITY_ENV)
    captured: dict[str, str] = {}
    for key in keys:
        value = os.environ.pop(key, None)
        if value is not None:
            captured[key] = value
    try:
        yield captured
    finally:
        os.environ.update(captured)

def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(root: Path, *args: str) -> str:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"GIT_COMMAND_FAILED:{' '.join(args)}:{proc.stderr.strip()}")
    return proc.stdout.strip()


def git_try(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True, text=True)


def load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def append_event(path: Path, event: dict[str, Any]) -> None:
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


def is_ancestor(root: Path, ancestor: str, descendant: str) -> bool:
    return subprocess.run([TRUSTED_GIT_EXECUTABLE, "merge-base", "--is-ancestor", ancestor, descendant], cwd=root).returncode == 0


def protected_policy(root: Path) -> dict[str, Any]:
    path = root / "reference/protected_branch_policy.json"
    data = load(path)
    if not isinstance(data, dict) or not isinstance(data.get("canonical_protected_ref"), str):
        raise RuntimeError("PROTECTED_BRANCH_POLICY_INVALID")
    canonical = data["canonical_protected_ref"]
    if canonical not in data.get("allowed_protected_refs", []):
        raise RuntimeError("PROTECTED_BRANCH_POLICY_CANONICAL_NOT_ALLOWED")
    return data


def current_symbolic_ref(root: Path) -> str:
    proc = git_try(root, "symbolic-ref", "-q", "HEAD")
    return proc.stdout.strip() if proc.returncode == 0 else ""


def verify_attestation(db: OrchestratorDB, root: Path, args: argparse.Namespace,
                       protected_ref: str, protected_sha: str) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    findings: list[str] = []
    attestation = db.get_trusted_attestation(args.attestation_id)
    if attestation.get("task_id") != args.task_id:
        findings.append("POST_MERGE_ATTESTATION_TASK_MISMATCH")
    if attestation.get("approved_target_ref") != protected_ref:
        findings.append("POST_MERGE_TARGET_BRANCH_MISMATCH")
    if not is_ancestor(root, attestation["head_commit_sha"], protected_sha):
        findings.append("FUNCTION_NOT_IN_PROTECTED_MAIN")
    if attestation.get("readiness_status") != "READY_TO_MERGE":
        findings.append("POST_MERGE_ATTESTATION_NOT_READY")
    lease = db.verify_active(
        args.task_id, int(attestation["fencing_token"]),
        branch=attestation.get("leased_branch"), base_sha=attestation["base_commit_sha"],
    )
    if f"refs/heads/{lease['branch']}" == protected_ref or lease["branch"] == protected_ref:
        findings.append("PROTECTED_REF_EQUALS_LEASED_BRANCH")
    if attestation.get("candidate_branch") != lease.get("branch"):
        findings.append("POST_MERGE_LEASE_BRANCH_MISMATCH")
    trusted_ids = attestation.get("trusted_test_evidence_ids", {})
    for role in ("targeted_tests", "affected_tests", "full_regression"):
        evidence_id = trusted_ids.get(role) if isinstance(trusted_ids, dict) else None
        if not isinstance(evidence_id, str):
            findings.append(f"POST_MERGE_TEST_EVIDENCE_MISSING:{role}")
            continue
        try:
            evidence = db.get_test_evidence(evidence_id)
        except ControlPlaneError as exc:
            findings.append(f"POST_MERGE_TEST_EVIDENCE_INVALID:{role}:{exc}")
            continue
        if evidence.get("head_sha") != attestation.get("head_commit_sha") or evidence.get("test_role") != role:
            findings.append(f"POST_MERGE_TEST_EVIDENCE_STALE:{role}")
        if evidence.get("run_id") != attestation.get("run_id"):
            findings.append(f"POST_MERGE_TEST_EVIDENCE_RUN_MISMATCH:{role}")
    return attestation, lease, findings


def run_post_merge_checks(root: Path, protected_sha: str, base_sha: str, db_path: str) -> tuple[list[dict[str, Any]], list[str]]:
    evidence: list[dict[str, Any]] = []
    findings: list[str] = []
    with candidate_worktree(root, protected_sha) as worktree:
        denied = [db_path, db_path + "-wal", db_path + "-shm"]
        architecture, architecture_findings = run_architecture_graph(worktree, root, base_sha, protected_sha, denied, True)
        evidence.extend(architecture); findings.extend(architecture_findings)
        full = run_command(
            worktree, [sys.executable, "-m", "pytest", "-q"],
            check_id="post_merge_full_regression", head_sha=protected_sha,
            timeout_seconds=1200, test_role="post_merge_validation",
            deny_paths=denied, require_sandbox=True,
            minimum_test_count=1,
            check_registry_digest=hashlib.sha256(b"post-merge-full-regression-v1").hexdigest(),
            check_registry_version="post-merge-v1",
        )
        evidence.append(full)
        if full["status"] != "PASS":
            findings.append("POST_MERGE_VALIDATION_FAILED")
    return evidence, findings


def store_post_merge_evidence(db: OrchestratorDB, task_id: str, protected_sha: str,
                              evidence: list[dict[str, Any]], operation_id: str) -> str:
    post_item = next(item for item in evidence if item.get("test_role") == "post_merge_validation")
    post_id = f"ev-{task_id}-{protected_sha[:10]}-{operation_id[-10:]}-post_merge_validation"
    summary = post_item.get("test_summary", {})
    db.store_test_evidence({
        "evidence_id": post_id, "run_id": operation_id, "task_id": task_id,
        "head_sha": protected_sha, "tree_sha": post_item.get("working_tree_tree_sha"),
        "check_id": post_item.get("check_id"), "test_role": "post_merge_validation",
        "command": post_item.get("command", []), "status": post_item.get("status"),
        "exit_code": post_item.get("exit_code"), "collected": summary.get("collected"),
        "completed": summary.get("completed"), "accounted": summary.get("accounted"),
        "passed": summary.get("passed"), "failed": summary.get("failed"),
        "errors": summary.get("errors"), "skipped": summary.get("skipped"),
        "xpassed": summary.get("xpassed", 0), "unexpected_skipped": summary.get("unexpected_skipped", 0),
        "node_ids": summary.get("node_ids", []), "expected_node_ids": [],
        "selection_digest": summary.get("selection_digest"), "minimum_test_count": 1,
        "command_digest": post_item.get("command_digest"),
        "check_registry_digest": post_item.get("check_registry_digest"),
        "check_registry_version": post_item.get("check_registry_version"),
        "sandbox_conformance_passed": post_item.get("sandbox_conformance_passed") is True,
        "sandbox_reference_only": post_item.get("sandbox_reference_only") is True,
        "sandbox_profile_id": post_item.get("sandbox_profile_id"),
        "sandbox_profile_digest": post_item.get("sandbox_profile_digest"),
        "sandbox_production_certified": post_item.get("sandbox_production_certified") is True,
        "sandbox_certification_id": post_item.get("sandbox_certification_id"),
        "sandbox_certification_issuer": post_item.get("sandbox_certification_issuer"),
        "sandbox_certification_expires_at": post_item.get("sandbox_certification_expires_at"),
        "sandbox_certified": post_item.get("sandbox_production_certified") is True,
        "report_sha256": post_item.get("report_sha256"), "report_content_base64": post_item.get("report_content_base64"),
        "stdout_sha256": post_item.get("stdout_sha256"), "stdout": post_item.get("stdout", ""),
        "stderr_sha256": post_item.get("stderr_sha256"), "stderr": post_item.get("stderr", ""),
        "duration_seconds": post_item.get("duration_seconds"),
        "issuer": "trusted-post-merge-runner", "issued_at": now(),
    })
    return post_id


def update_managed_state(root: Path, args: argparse.Namespace, attestation: dict[str, Any],
                         protected_sha: str, post_id: str, operation_id: str) -> tuple[tuple[Path, Path, Path], list[str]]:
    users_path = root / "docs/registry/user_functions.json"
    graph_path = root / "docs/registry/work_package_graph.json"
    journal_path = root / "docs/registry/change_journal.jsonl"
    users = load(users_path); graph = load(graph_path)
    findings: list[str] = []; changed_users = 0
    for item in users:
        if not isinstance(item, dict) or (item.get("task_id") or item.get("introduced_by_task")) != args.task_id:
            continue
        state = item.get("lifecycle_state"); identity = item.get("function_id") or item.get("id")
        if state not in {"IMPLEMENTED", "READY_FOR_REVIEW", "READY_FOR_MERGE", "MERGED"}:
            findings.append(f"POST_MERGE_LIFECYCLE_NOT_READY:{identity}:{state}"); continue
        evidence_ids = dict(attestation.get("trusted_test_evidence_ids", {})); evidence_ids["post_merge_validation"] = post_id
        item.update({
            "previous_lifecycle_state": "MERGED", "lifecycle_state": "DONE", "status": "DONE",
            "merged_commit": attestation["head_commit_sha"], "protected_main_verified_sha": protected_sha,
            "verified_attestation": args.attestation_id, "post_merge_operation_id": operation_id,
            "post_merge_validation": "PASS", "trusted_test_evidence_ids": evidence_ids,
        })
        append_event(journal_path, {
            "event_id": f"evt-{args.task_id}-{identity}-merged-{protected_sha[:8]}", "timestamp": now(),
            "task_id": args.task_id, "agent_id": "trusted-post-merge", "entity_type": "user_function",
            "entity_id": identity, "action": "MERGED", "from_state": state, "to_state": "MERGED",
            "commit_sha": attestation["head_commit_sha"], "attestation_id": args.attestation_id,
        })
        append_event(journal_path, {
            "event_id": f"evt-{args.task_id}-{identity}-done-{protected_sha[:8]}", "timestamp": now(),
            "task_id": args.task_id, "agent_id": "trusted-post-merge", "entity_type": "user_function",
            "entity_id": identity, "action": "DONE", "from_state": "MERGED", "to_state": "DONE",
            "commit_sha": protected_sha, "attestation_id": args.attestation_id,
        })
        changed_users += 1
    entries = graph.get("work_packages", graph.get("tasks", [])); changed_tasks = 0
    for item in entries:
        if isinstance(item, dict) and (item.get("id") or item.get("task_id")) == args.task_id:
            item.update({"status": "DONE", "merged_commit": protected_sha,
                         "attestation_id": args.attestation_id, "post_merge_operation_id": operation_id})
            changed_tasks += 1
    if changed_users == 0: findings.append("POST_MERGE_USER_FUNCTION_NOT_FOUND")
    if changed_tasks == 0: findings.append("POST_MERGE_TASK_NOT_FOUND")
    if not findings:
        dump(users_path, users); dump(graph_path, graph)
    return (users_path, graph_path, journal_path), findings


def validate_pending_registry(root: Path, db_path: str, protected_ref: str) -> list[str]:
    previous_db = os.environ.get("APS_ORCHESTRATOR_DB")
    os.environ["APS_ORCHESTRATOR_DB"] = db_path
    try:
        return all_function_findings(root, protected_ref=protected_ref)
    finally:
        if previous_db is None: os.environ.pop("APS_ORCHESTRATOR_DB", None)
        else: os.environ["APS_ORCHESTRATOR_DB"] = previous_db


def _patch_digest(root: Path) -> str:
    return hashlib.sha256(subprocess.run([TRUSTED_GIT_EXECUTABLE, "diff", "--binary"], cwd=root, capture_output=True).stdout).hexdigest()


def recover_operation(root: Path, db: OrchestratorDB, operation_id: str, protected_ref: str) -> tuple[dict[str, Any], list[str]]:
    operation = db.get_post_merge_operation(operation_id)
    if operation["protected_ref"] != protected_ref:
        return operation, ["POST_MERGE_RECOVERY_PROTECTED_REF_MISMATCH"]
    if operation["state"] == "COMPLETED":
        return {**operation, "status": "DONE"}, []
    if operation["state"] != "GIT_COMMITTED" or not operation.get("git_commit_sha"):
        return operation, ["POST_MERGE_RECOVERY_NOT_READY"]
    if resolve_commit(root, protected_ref) != operation["git_commit_sha"]:
        return operation, ["POST_MERGE_RECOVERY_COMMIT_NOT_PROTECTED_TIP"]
    completed = db.complete_post_merge_operation(operation_id)
    return {**completed, "status": "DONE"}, []


def finalize(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    root = Path(args.root).resolve()
    if os.environ.get(TRUST_ENV) != "1":
        return {}, ["POST_MERGE_TRUSTED_WRITER_REQUIRED"]
    findings: list[str] = []
    db = OrchestratorDB(args.orchestrator_db)
    try:
        db.validate_external_path(str(root))
        policy = db.get_repository_policy()
        protected_ref = policy["canonical_protected_ref"]
        if current_symbolic_ref(root) != protected_ref:
            findings.append("POST_MERGE_NOT_ON_CANONICAL_PROTECTED_REF")
        protected_sha = resolve_commit(root, protected_ref)
        if resolve_commit(root, "HEAD") != protected_sha:
            findings.append("POST_MERGE_NOT_ON_PROTECTED_REF")
        if git(root, "status", "--porcelain"):
            findings.append("POST_MERGE_WORKTREE_DIRTY")
        # Protected-branch identity is a trusted precondition. Never execute
        # candidate-derived validators when it fails.
        if findings:
            return {"status": "BLOCKED", "protected_ref": protected_ref}, sorted(set(findings))
        if getattr(args, "recover_operation", None):
            return recover_operation(root, db, args.recover_operation, protected_ref)
        attestation, lease, attestation_findings = verify_attestation(db, root, args, protected_ref, protected_sha)
        findings.extend(attestation_findings)
        completed_existing = db.connection.execute(
            "SELECT operation_id FROM post_merge_operations WHERE task_id=? AND attestation_id=? AND state='COMPLETED'",
            (args.task_id, args.attestation_id),
        ).fetchone()
        if completed_existing is not None:
            findings.append("POST_MERGE_ALREADY_COMPLETED")
        with candidate_check_context():
            evidence, check_findings = run_post_merge_checks(root, protected_sha, attestation["base_commit_sha"], args.orchestrator_db)
        findings.extend(check_findings)
        summary = {"task_id": args.task_id, "protected_ref": protected_ref, "protected_sha": protected_sha,
                   "attestation_id": args.attestation_id, "evidence": evidence}
        if findings or not args.apply:
            summary["status"] = "BLOCKED" if findings else "VALIDATED"
            return summary, sorted(set(findings))
        if not args.commit:
            return {"status": "BLOCKED"}, ["POST_MERGE_COMMIT_REQUIRED"]
        if policy.get("platform_protection_required") and not policy.get("platform_protection_verified") \
                and not policy.get("human_supervised_post_merge_allowed"):
            return {"status": "BLOCKED"}, ["PLATFORM_BRANCH_PROTECTION_NOT_VERIFIED"]

        operation_id = f"pm-{args.task_id}-{args.attestation_id[-10:]}-{uuid.uuid4().hex[:12]}"
        post_id = store_post_merge_evidence(db, args.task_id, protected_sha, evidence, operation_id)
        paths = (root / "docs/registry/user_functions.json", root / "docs/registry/work_package_graph.json",
                 root / "docs/registry/change_journal.jsonl")
        originals = {path: path.read_text(encoding="utf-8") for path in paths}
        updated_paths, update_findings = update_managed_state(root, args, attestation, protected_sha, post_id, operation_id)
        findings.extend(update_findings)
        findings.extend(f"POST_MERGE_REGISTRY_VALIDATION_FAILED:{item}"
                        for item in validate_pending_registry(root, args.orchestrator_db, protected_ref))
        if findings:
            for path, content in originals.items(): path.write_text(content, encoding="utf-8")
            return {"status": "BLOCKED", "findings": sorted(set(findings))}, sorted(set(findings))
        patch_sha = _patch_digest(root)
        db.begin_post_merge_operation({
            "operation_id": operation_id, "task_id": args.task_id, "attestation_id": args.attestation_id,
            "protected_ref": protected_ref, "protected_sha": protected_sha, "patch_sha256": patch_sha,
            "lease_id": lease["lease_id"], "fencing_token": int(attestation["fencing_token"]),
        })
        git(root, "add", *(str(path.relative_to(root)) for path in updated_paths))
        commit_proc = git_try(root, "commit", "-m", f"Post-merge finalize {args.task_id}")
        if commit_proc.returncode != 0:
            git_try(root, "reset", "--hard", protected_sha)
            db.compensate_post_merge_operation(operation_id, "GIT_COMMIT_FAILED")
            return {"status": "BLOCKED", "operation_id": operation_id}, ["GIT_COMMAND_FAILED:commit"]
        post_commit = resolve_commit(root, "HEAD")
        db.mark_post_merge_git_committed(operation_id, post_commit)
        try:
            completed = db.complete_post_merge_operation(operation_id)
        except ControlPlaneError as exc:
            return {"status": "RECOVERY_REQUIRED", "operation_id": operation_id,
                    "post_merge_commit_sha": post_commit}, [f"POST_MERGE_DB_COMPLETION_FAILED:{exc}"]
        return {
            "task_id": args.task_id, "attestation_id": args.attestation_id,
            "merged_candidate_sha": protected_sha, "post_merge_commit_sha": post_commit,
            "lease_id": lease["lease_id"], "operation_id": operation_id,
            "operation_state": completed["state"], "status": "DONE", "evidence": evidence,
        }, []
    except (ControlPlaneError, RuntimeError) as exc:
        return {}, [str(exc)]
    finally:
        db.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--task-id")
    parser.add_argument("--attestation-id")
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--recover-operation")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--commit", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    if not args.recover_operation and (not args.task_id or not args.attestation_id):
        parser.error("--task-id and --attestation-id are required unless --recover-operation is used")
    return args


def main() -> int:
    args = parse_args()
    try:
        result, findings = finalize(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr); return 2
    if args.output:
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    for finding in findings: print(finding, file=sys.stderr)
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
