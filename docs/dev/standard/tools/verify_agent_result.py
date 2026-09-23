#!/usr/bin/env python3
# ======================================================================
# verify_agent_result.py — версия 2.0
# Trusted candidate execution, evidence recomputation and DB attestation.
# ======================================================================
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TRUSTED_GIT_EXECUTABLE = str(Path("/usr/bin/git").resolve()) if Path("/usr/bin/git").exists() else "git"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB  # noqa: E402
from trusted_execution import candidate_worktree, evidence_digest, git as git_text, resolve_commit, resolve_tree, run_command  # noqa: E402
from v128_validation import load_json  # noqa: E402


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git_bytes(root: Path, *args: str) -> bytes:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"GIT_COMMAND_FAILED:{' '.join(args)}:{proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def changed_files(root: Path, base_sha: str, head_sha: str) -> list[str]:
    output = git_text(root, "diff", "--name-only", "--diff-filter=ACDMRTUXB", base_sha, head_sha)
    return sorted(line for line in output.splitlines() if line)


def file_modes(root: Path, head_sha: str, files: list[str]) -> dict[str, str]:
    modes: dict[str, str] = {}
    for rel in files:
        proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, "ls-tree", head_sha, "--", rel], cwd=root, capture_output=True, text=True)
        modes[rel] = proc.stdout.split()[0] if proc.returncode == 0 and proc.stdout.strip() else "deleted"
    return modes


def path_in_scope(path: str, scopes: list[str]) -> bool:
    normalized = path.replace("\\", "/")
    for raw in scopes:
        scope = raw.replace("\\", "/").rstrip("/")
        if normalized == scope or normalized.startswith(scope + "/"):
            return True
        if fnmatch.fnmatchcase(normalized, scope) or fnmatch.fnmatchcase(normalized, scope + "/**"):
            return True
    return False


def _json_at_ref(root: Path, ref: str, path: str) -> Any:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, "show", f"{ref}:{path}"], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"TRUSTED_INPUT_NOT_FOUND:{ref}:{path}")
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"TRUSTED_INPUT_INVALID:{ref}:{path}:{exc}") from exc


def find_task(root: Path, task_id: str, base_ref: str | None = None) -> dict[str, Any]:
    if base_ref:
        base_sha = resolve_commit(root, base_ref)
        names = git_text(root, "ls-tree", "-r", "--name-only", base_sha).splitlines()
        candidates = [name for name in names if name.startswith("docs/registry/agent_tasks") and name.endswith(".json")]
        matches = []
        for name in candidates:
            data = _json_at_ref(root, base_sha, name)
            if isinstance(data, dict) and (data.get("task_id") == task_id or data.get("id") == task_id):
                matches.append(data)
    else:
        matches = []
        for directory in ("agent_tasks", "agent_tasks.example"):
            folder = root / "docs" / "registry" / directory
            for path in folder.glob("*.json") if folder.exists() else []:
                data, error = load_json(path)
                if not error and isinstance(data, dict) and (data.get("task_id") == task_id or data.get("id") == task_id):
                    matches.append(data)
    if not matches:
        raise RuntimeError(f"TASK_NOT_FOUND:{task_id}")
    if len(matches) != 1:
        raise RuntimeError(f"TASK_AMBIGUOUS:{task_id}:{len(matches)}")
    return matches[0]


def dependency_state(root: Path, task: dict[str, Any], base_ref: str | None = None) -> tuple[str, list[str]]:
    try:
        graph = _json_at_ref(root, resolve_commit(root, base_ref), "docs/registry/work_package_graph.json") if base_ref else load_json(root / "docs/registry/work_package_graph.json")[0]
    except RuntimeError as exc:
        return "UNKNOWN", [str(exc)]
    if not isinstance(graph, dict):
        return "UNKNOWN", ["WORK_PACKAGE_GRAPH_INVALID"]
    entries = graph.get("work_packages", graph.get("tasks", []))
    by_id = {item.get("id") or item.get("task_id"): item for item in entries if isinstance(item, dict)}
    task_id = task.get("task_id") or task.get("id")
    findings: list[str] = []
    if task_id not in by_id:
        findings.append(f"TASK_NOT_IN_WORK_PACKAGE_GRAPH:{task_id}")
    for dependency in task.get("depends_on", []) or (by_id.get(task_id) or {}).get("depends_on", []):
        state = (by_id.get(dependency) or {}).get("status")
        if state not in {"DONE", "MERGED"}:
            findings.append(f"DEPENDENCY_NOT_READY:{dependency}:{state}")
    return ("READY" if not findings else "BLOCKED"), findings


def load_check_registry(root: Path, base_sha: str) -> tuple[dict[str, dict[str, Any]], str, str]:
    data = _json_at_ref(root, base_sha, "docs/registry/check_registry.json")
    if not isinstance(data, dict):
        raise RuntimeError("CHECK_REGISTRY_INVALID")
    canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(canonical).hexdigest()
    version = str(data.get("version", "1.0.0"))
    checks = {item["id"]: item for item in data.get("checks", []) if isinstance(item, dict) and isinstance(item.get("id"), str)}
    return checks, digest, version



def ownership_scopes(root: Path, base_sha: str, task: dict[str, Any]) -> tuple[list[str], list[str]]:
    data = _json_at_ref(root, base_sha, "docs/registry/code_ownership.json")
    entries = data.get("ownership", []) if isinstance(data, dict) else []
    task_owner = task.get("owner") or task.get("owner_module")
    scopes: list[str] = []
    findings: list[str] = []
    known_owners = {item.get("owner") for item in entries if isinstance(item, dict) and item.get("owner")}
    if task_owner and task_owner not in known_owners:
        return [], [f"TASK_OWNER_NOT_REGISTERED:{task_owner}", "OWNERSHIP_SCOPE_UNRESOLVED"]
    for item in entries:
        if not isinstance(item, dict) or item.get("access") != "read_write":
            continue
        if task_owner and item.get("owner") not in {task_owner, task.get("task_id"), task.get("id")}:
            continue
        if isinstance(item.get("path"), str):
            scopes.append(item["path"])
    if not scopes and not task_owner:
        scopes = [item["path"] for item in entries if isinstance(item, dict) and item.get("access") == "read_write" and isinstance(item.get("path"), str)]
    if not scopes:
        findings.append("OWNERSHIP_SCOPE_UNRESOLVED")
    return sorted(set(scopes)), findings


def run_required_checks(candidate: Path, trusted_root: Path, task: dict[str, Any], base_sha: str, head_sha: str,
                        deny_paths: list[str]) -> tuple[list[dict[str, Any]], list[str]]:
    registry, registry_digest, registry_version = load_check_registry(trusted_root, base_sha)
    results: list[dict[str, Any]] = []
    findings: list[str] = []
    for requirement in task.get("required_checks", []) or []:
        if not isinstance(requirement, dict):
            findings.append("REQUIRED_CHECK_INVALID")
            continue
        check_ref = requirement.get("check_ref")
        check = registry.get(check_ref)
        if check is None:
            findings.append(f"REQUIRED_CHECK_NOT_APPROVED:{check_ref}")
            continue
        argv = check.get("argv")
        if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
            findings.append(f"REQUIRED_CHECK_INVALID:{check_ref}")
            continue
        cwd = candidate / str(check.get("cwd", "."))
        evidence = run_command(
            cwd,
            list(argv),
            check_id=f"required:{check_ref}",
            head_sha=head_sha,
            timeout_seconds=int(check.get("timeout_seconds", 300)),
            test_role=check.get("test_role") if check.get("evidence_kind") == "test" else None,
            deny_paths=deny_paths, require_sandbox=True,
            expected_node_ids=check.get("expected_node_ids"),
            minimum_test_count=check.get("minimum_test_count"),
            check_registry_digest=registry_digest,
            check_registry_version=registry_version,
            skip_allowlist=check.get("skip_allowlist", []),
        )
        expected = check.get("expected_exit_codes", [0])
        if evidence["exit_code"] not in expected or evidence["status"] != "PASS":
            evidence["status"] = "FAIL"
            findings.append(f"REQUIRED_CHECK_FAILED:{check_ref}:{evidence['exit_code']}")
        results.append(evidence)
    return results, findings


def run_architecture_graph(candidate: Path, trusted_root: Path, base_ref: str, head_sha: str,
                           deny_paths: list[str] | None = None, require_sandbox: bool = True) -> tuple[list[dict[str, Any]], list[str]]:
    groups = [
        ("control_plane", ["--check-control-plane-integrity"]),
        ("module_boundaries", ["--check-module-registry", "--check-module-boundaries"]),
        ("code_ownership", ["--check-code-ownership"]),
        ("agent_workflow_integrity", ["--check-agent-task-contracts", "--check-work-package-graph"]),
        ("function_registries", ["--check-user-function-registry", "--check-function-registry", "--check-function-duplication", "--check-registry-task-linkage", "--check-function-lifecycle", "--check-change-journal", "--check-function-test-evidence"]),
    ]
    evidence: list[dict[str, Any]] = []
    findings: list[str] = []
    validator = trusted_root / "tools" / "validate_structure.py"
    for check_id, flags in groups:
        command = [sys.executable, str(validator), "--root", str(candidate), "--profile", "target-project", "--schemas-root", str(trusted_root / "schemas"), *flags, "--base-ref", base_ref, "--warnings-as-errors"]
        item = run_command(candidate, command, check_id=check_id, head_sha=head_sha,
                           deny_paths=deny_paths or [], require_sandbox=require_sandbox,
                           readonly_paths=[str(trusted_root)])
        evidence.append(item)
        if item["status"] != "PASS":
            findings.append(f"MANDATORY_VALIDATOR_FAILED:{check_id}:{item['exit_code']}")
            combined = item.get("stdout", "") + "\n" + item.get("stderr", "")
            for line in combined.splitlines():
                stripped = line.strip(" -")
                if any(code in stripped for code in ("CONTROL_PLANE", "GOVERNANCE_", "module-boundaries", "code-ownership", "FUNCTION_", "PUBLIC_SYMBOL", "AGENT_")):
                    findings.append(stripped)
    return evidence, findings


def _resolve_branch_tip(root: Path, branch: str) -> str:
    candidates = [branch]
    if not branch.startswith("refs/"):
        candidates.extend([f"refs/heads/{branch}", f"refs/remotes/origin/{branch}"])
    for ref in candidates:
        proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, "rev-parse", f"{ref}^{{commit}}"], cwd=root, capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout.strip()
    raise RuntimeError(f"LEASE_BRANCH_REF_NOT_FOUND:{branch}")


def _load_claim_and_lease(
    root: Path,
    claimed_path: Path,
    db: OrchestratorDB,
    task_id: str,
    task: dict[str, Any],
    fencing_token: int,
    base_sha: str,
    head_sha: str,
    agent_identity: str,
    actual: list[str],
) -> tuple[dict[str, Any], dict[str, Any], list[str], str]:
    findings: list[str] = []
    claim, error = load_json(claimed_path)
    if error or not isinstance(claim, dict):
        claim = {}; findings.append(f"AGENT_RESULT_INVALID:{error}")
    if claim.get("status") in {"VERIFIED", "READY_TO_MERGE", "MERGED", "DONE"}:
        findings.append(f"AGENT_SELF_VERIFICATION_FORBIDDEN:{claim.get('status')}")
    claimed_files = sorted(value for value in claim.get("changed_files", []) if isinstance(value, str))
    if claimed_files != actual:
        findings.append(f"AGENT_RESULT_DIFF_MISMATCH:missing={sorted(set(actual)-set(claimed_files))}:phantom={sorted(set(claimed_files)-set(actual))}")
    expected_branch = task.get("branch") or f"agent/{task_id}"
    try:
        lease = db.verify_active(task_id, fencing_token, branch=expected_branch, base_sha=base_sha)
    except ControlPlaneError as exc:
        findings.append(str(exc))
        lease = {"lease_id": "unknown", "fencing_token": fencing_token, "agent_id": agent_identity,
                 "allowed_paths": [], "branch": expected_branch}
    if lease.get("branch") != expected_branch:
        findings.append("TASK_LEASE_BRANCH_MISMATCH")
    try:
        branch_tip = _resolve_branch_tip(root, str(lease.get("branch", expected_branch)))
    except RuntimeError as exc:
        findings.append(str(exc)); branch_tip = ""
    if branch_tip and head_sha != branch_tip:
        findings.append(f"CANDIDATE_NOT_LEASED_BRANCH_TIP:expected={branch_tip}:actual={head_sha}")
    if claim.get("fencing_token") not in {None, fencing_token}:
        findings.append("AGENT_RESULT_FENCING_TOKEN_MISMATCH")
    if claim.get("lease_id") not in {None, lease.get("lease_id")}:
        findings.append("AGENT_RESULT_LEASE_MISMATCH")
    return claim, lease, findings, branch_tip


def _scope_findings(
    actual: list[str],
    task_scope: list[str],
    lease_scope: list[str],
    owner_scope: list[str],
) -> list[str]:
    findings: list[str] = []
    for path in actual:
        if not path_in_scope(path, task_scope):
            findings.append(f"TASK_SCOPE_VIOLATION:{path}")
        if not path_in_scope(path, lease_scope):
            findings.append(f"LEASE_SCOPE_VIOLATION:{path}")
        if not owner_scope:
            findings.append("OWNERSHIP_SCOPE_UNRESOLVED")
        elif not path_in_scope(path, owner_scope):
            findings.append(f"OWNERSHIP_SCOPE_VIOLATION:{path}")
    return findings


def _execute_candidate_graph(
    root: Path,
    trusted_root: Path,
    task: dict[str, Any],
    base_sha: str,
    head_sha: str,
    db_path: str,
) -> tuple[list[dict[str, Any]], list[str]]:
    evidence: list[dict[str, Any]] = []
    findings: list[str] = []
    with candidate_worktree(root, head_sha) as candidate:
        if resolve_commit(candidate, "HEAD") != head_sha:
            findings.append("CHECKOUT_DOES_NOT_MATCH_CANDIDATE")
        denied = [db_path, db_path + "-wal", db_path + "-shm"]
        architecture, architecture_findings = run_architecture_graph(candidate, trusted_root, base_sha, head_sha, denied, True)
        evidence.extend(architecture)
        findings.extend(architecture_findings)
        checks, check_findings = run_required_checks(candidate, trusted_root, task, base_sha, head_sha, denied)
        evidence.extend(checks)
        findings.extend(check_findings)
        observed_test_roles = {item.get("test_role") for item in checks if item.get("status") == "PASS"}
        for required_role in ("targeted_tests", "affected_tests", "full_regression"):
            if required_role not in observed_test_roles:
                findings.append(f"TRUSTED_TEST_ROLE_MISSING:{required_role}")
        if git_text(candidate, "status", "--porcelain"):
            findings.append("CANDIDATE_WORKTREE_MUTATED_DURING_CHECK")
        if resolve_commit(candidate, "HEAD") != head_sha:
            findings.append("CANDIDATE_SHA_CHANGED_DURING_CHECK")
    return evidence, findings



def _compose_attestation(*, task_id: str, base_sha: str, head_sha: str, head_tree_sha: str,
                         diff_sha: str, actual: list[str], modes: dict[str, str], task_scope: list[str],
                         lease_scope: list[str], owner_scope: list[str], evidence: list[dict[str, Any]],
                         caveats: list[str], dep_state: str, lease: dict[str, Any], fencing_token: int,
                         agent_identity: str, findings: list[str], branch_tip: str,
                         approved_target_ref: str, request_id: str) -> dict[str, Any]:
    run_id = uuid.uuid4().hex
    status = "VERIFIED_UNSIGNED" if not findings and evidence and all(
        item["status"] == "PASS" and item["working_tree_commit_sha"] == head_sha for item in evidence
    ) else "REJECTED"
    portable_evidence = [{key: value for key, value in item.items()
                          if key not in {"stdout", "stderr", "report_content_base64", "executed_command"}}
                         for item in evidence]
    test_ids = {item["test_role"]: f"ev-{task_id}-{head_sha[:10]}-{run_id[:12]}-{item['test_role']}"
                for item in evidence if item.get("test_role")}
    leased_branch = str(lease.get("branch", ""))
    return {
        "schema_version": "3.0.0",
        "run_id": run_id,
        "request_id": request_id,
        "candidate_identity_id": f"candidate-{task_id}-{head_sha[:12]}-{fencing_token}",
        "task_id": task_id,
        "base_commit_sha": base_sha,
        "head_commit_sha": head_sha,
        "head_tree_sha": head_tree_sha,
        "diff_sha256": diff_sha,
        "candidate_branch": leased_branch,
        "leased_branch": leased_branch,
        "candidate_ref_tip_sha": branch_tip,
        "approved_target_ref": approved_target_ref,
        "actual_changed_files": actual,
        "file_modes": modes,
        "task_allowed_paths": task_scope,
        "lease_allowed_paths": lease_scope,
        "ownership_allowed_paths": owner_scope,
        "scope_compliance": not any("SCOPE_VIOLATION" in finding for finding in findings),
        "ownership_compliance": not any("OWNERSHIP" in finding or "OWNER_" in finding for finding in findings),
        "module_boundary_compliance": not any("module-boundaries" in finding.lower() or "MODULE" in finding for finding in findings),
        "mandatory_check_evidence": portable_evidence,
        "trusted_test_evidence_ids": test_ids,
        "evidence_digest": evidence_digest(evidence),
        "blocking_caveats": caveats,
        "dependency_state": dep_state,
        "lease_id": str(lease.get("lease_id", "unknown")),
        "fencing_token": int(lease.get("fencing_token", fencing_token)),
        "agent_identity": str(lease.get("agent_id", agent_identity)),
        "issuer": "trusted-candidate-runner",
        "execution_completed_at": utc_now(),
        "readiness_status": status,
        "findings": findings,
    }


def _test_evidence_payloads(body: dict[str, Any], raw_evidence: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    portable_by_key = {(item.get("check_id"), item.get("test_role")): item for item in body["mandatory_check_evidence"]}
    for raw_item in raw_evidence:
        role = raw_item.get("test_role")
        item = portable_by_key.get((raw_item.get("check_id"), role), raw_item)
        if not role:
            continue
        summary = item.get("test_summary", {})
        records.append({
            "evidence_id": body["trusted_test_evidence_ids"][role], "run_id": body["run_id"],
            "task_id": body["task_id"], "head_sha": body["head_commit_sha"],
            "tree_sha": body["head_tree_sha"], "check_id": item["check_id"], "test_role": role,
            "command": item.get("command", []), "status": item.get("status"), "exit_code": item.get("exit_code"),
            "collected": summary.get("collected"), "completed": summary.get("completed"),
            "accounted": summary.get("accounted"), "passed": summary.get("passed"),
            "failed": summary.get("failed"), "errors": summary.get("errors"), "skipped": summary.get("skipped"),
            "xpassed": summary.get("xpassed", 0), "unexpected_skipped": summary.get("unexpected_skipped", 0),
            "node_ids": summary.get("node_ids", []), "expected_node_ids": item.get("expected_node_ids", []),
            "selection_digest": summary.get("selection_digest"),
            "minimum_test_count": item.get("minimum_test_count", summary.get("collected")),
            "command_digest": item.get("command_digest"),
            "check_registry_digest": item.get("check_registry_digest"),
            "check_registry_version": item.get("check_registry_version"),
            "sandbox_certified": item.get("sandbox_production_certified") is True,
            "sandbox_adapter_available": item.get("sandbox_adapter_available") is True,
            "sandbox_conformance_passed": item.get("sandbox_conformance_passed") is True,
            "sandbox_reference_only": item.get("sandbox_reference_only") is True,
            "sandbox_profile_id": item.get("sandbox_profile_id"),
            "sandbox_profile_digest": item.get("sandbox_profile_digest"),
            "sandbox_certification_id": item.get("sandbox_certification_id"),
            "sandbox_certification_issuer": item.get("sandbox_certification_issuer"),
            "sandbox_certification_expires_at": item.get("sandbox_certification_expires_at"),
            "sandbox_certification_profile_id": item.get("sandbox_certification_profile_id"),
            "sandbox_production_certified": item.get("sandbox_production_certified") is True,
            "executor_image_digest": item.get("executor_image_digest"),
            "executor_identity": item.get("executor_identity"),
            "deployment_identity": item.get("deployment_identity"),
            "report_sha256": item.get("report_sha256"), "report_content_base64": raw_item.get("report_content_base64"),
            "stdout_sha256": item.get("stdout_sha256"), "stdout": raw_item.get("stdout", ""),
            "stderr_sha256": item.get("stderr_sha256"), "stderr": raw_item.get("stderr", ""),
            "duration_seconds": item.get("duration_seconds"),
            "issuer": "trusted-candidate-runner", "issued_at": body["execution_completed_at"],
        })
    return records


def build_attestation(root: Path, task_id: str, base_ref: str, head_ref: str, claimed_path: Path,
                      db_path: str, fencing_token: int, agent_identity: str,
                      request_id: str | None = None) -> tuple[dict[str, Any], list[str]]:
    root = root.resolve(); base_sha = resolve_commit(root, base_ref); head_sha = resolve_commit(root, head_ref)
    head_tree_sha = resolve_tree(root, head_sha); task = find_task(root, task_id, base_sha)
    actual = changed_files(root, base_sha, head_sha)
    diff_sha = hashlib.sha256(git_bytes(root, "diff", "--binary", base_sha, head_sha)).hexdigest()
    modes = file_modes(root, head_sha, actual)
    db = OrchestratorDB(db_path)
    try:
        db.validate_external_path(str(root))
        claim, lease, findings, branch_tip = _load_claim_and_lease(
            root, claimed_path, db, task_id, task, fencing_token, base_sha, head_sha, agent_identity, actual
        )
        task_scope = [value for value in task.get("allowed_paths", []) if isinstance(value, str)]
        lease_scope = [value for value in lease.get("allowed_paths", []) if isinstance(value, str)]
        owner_scope, owner_findings = ownership_scopes(root, base_sha, task)
        findings.extend(owner_findings); findings.extend(_scope_findings(actual, task_scope, lease_scope, owner_scope))
        dep_state, dep_findings = dependency_state(root, task, base_sha); findings.extend(dep_findings)
        # Branch, lease, scope, ownership and dependency failures are trusted
        # preflight failures. Do not execute untrusted candidate code when the
        # candidate is already ineligible for verification.
        if findings:
            evidence = []
        else:
            with candidate_worktree(root, base_sha) as trusted_base:
                evidence, execution_findings = _execute_candidate_graph(root, trusted_base, task, base_sha, head_sha, db_path)
            findings.extend(execution_findings)
        caveats = [value for field in ("blocking_caveats", "unverified_claims") for value in claim.get(field, []) if isinstance(value, str)]
        if caveats: findings.append(f"BLOCKING_CAVEAT_PRESENT:{caveats}")
        policy = db.get_repository_policy()
        approved_target_ref = policy["canonical_protected_ref"]
        if approved_target_ref == f"refs/heads/{lease.get('branch')}":
            findings.append("PROTECTED_REF_EQUALS_LEASED_BRANCH")
        findings = sorted(set(findings))
        body = _compose_attestation(
            task_id=task_id, base_sha=base_sha, head_sha=head_sha, head_tree_sha=head_tree_sha,
            diff_sha=diff_sha, actual=actual, modes=modes, task_scope=task_scope, lease_scope=lease_scope,
            owner_scope=owner_scope, evidence=evidence, caveats=caveats, dep_state=dep_state, lease=lease,
            fencing_token=fencing_token, agent_identity=agent_identity, findings=findings, branch_tip=branch_tip,
            approved_target_ref=approved_target_ref, request_id=request_id or uuid.uuid4().hex,
        )
        return {"attestation": body, "test_evidence": _test_evidence_payloads(body, evidence)}, findings
    finally:
        db.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument("--claimed-result", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--fencing-token", type=int, required=True)
    parser.add_argument("--agent-identity", default="implementation-agent")
    parser.add_argument("--request-id")
    return parser.parse_args()


def main() -> int:
    args = parse_args(); root = Path(args.root).resolve(); output = Path(args.output).resolve()
    try:
        bundle, findings = build_attestation(root, args.task_id, args.base_ref, args.head_ref, Path(args.claimed_result), args.orchestrator_db, args.fencing_token, args.agent_identity, args.request_id)
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr); return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True))
    if findings:
        for finding in findings: print(finding, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
