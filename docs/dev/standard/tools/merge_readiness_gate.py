#!/usr/bin/env python3
# ======================================================================
# merge_readiness_gate.py — версия 4.0
# Independent revalidation of signed attestation and all mutable prerequisites.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

TRUSTED_GIT_EXECUTABLE = str(Path("/usr/bin/git").resolve()) if Path("/usr/bin/git").exists() else "git"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB, parse_iso  # noqa: E402
from trusted_execution import resolve_commit, resolve_tree  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402
from verify_agent_result import load_check_registry  # noqa: E402

REQUIRED_ROLES = ("targeted_tests", "affected_tests", "full_regression")


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def git_bytes(root: Path, *args: str) -> bytes:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True)
    if proc.returncode != 0:
        raise RuntimeError(f"GIT_COMMAND_FAILED:{proc.stderr.decode(errors='replace').strip()}")
    return proc.stdout


def branch_tip(root: Path, branch: str) -> str:
    refs = [branch] if branch.startswith("refs/") else [f"refs/heads/{branch}", f"refs/remotes/origin/{branch}", branch]
    for ref in refs:
        proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, "rev-parse", f"{ref}^{{commit}}"], cwd=root, capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout.strip()
    raise RuntimeError(f"LEASE_BRANCH_REF_NOT_FOUND:{branch}")


def _canonical_command(argv: list[str]) -> list[str]:
    command = list(argv)
    if command and command[0] in {"python", "python3"}:
        command[0] = sys.executable
    return command


def _command_digest(argv: list[str]) -> str:
    return hashlib.sha256(json.dumps(_canonical_command(argv), ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _revalidate_test_records(db: OrchestratorDB, root: Path, data: dict[str, Any], base: str, head: str, tree: str) -> list[str]:
    findings: list[str] = []
    ids = data.get("trusted_test_evidence_ids")
    if not isinstance(ids, dict) or set(ids) != set(REQUIRED_ROLES):
        return ["MERGE_TEST_EVIDENCE_GRAPH_INCOMPLETE"]
    checks, registry_digest, registry_version = load_check_registry(root, base)
    records: list[dict[str, Any]] = []
    for role in REQUIRED_ROLES:
        try:
            evidence = db.get_test_evidence(ids[role])
        except ControlPlaneError as exc:
            findings.append(f"MERGE_TEST_EVIDENCE_INVALID:{role}:{exc}")
            continue
        records.append(evidence)
        if evidence.get("test_role") != role:
            findings.append(f"MERGE_TEST_ROLE_MISMATCH:{role}")
        if evidence.get("task_id") != data.get("task_id"):
            findings.append(f"MERGE_TEST_TASK_MISMATCH:{role}")
        if evidence.get("run_id") != data.get("run_id"):
            findings.append(f"MERGE_TEST_RUN_MISMATCH:{role}")
        if evidence.get("head_sha") != head or evidence.get("tree_sha") != tree:
            findings.append(f"MERGE_TEST_CANDIDATE_MISMATCH:{role}")
        if evidence.get("check_registry_digest") != registry_digest or evidence.get("check_registry_version") != registry_version:
            findings.append(f"MERGE_TEST_REGISTRY_DRIFT:{role}")
        check_id = str(evidence.get("check_id", ""))
        registry_id = check_id.split(":", 1)[1] if check_id.startswith("required:") else ""
        check = checks.get(registry_id)
        if not check or check.get("test_role") != role:
            findings.append(f"MERGE_TEST_CHECK_NOT_REGISTERED:{role}")
        elif evidence.get("command_digest") != _command_digest(check.get("argv", [])):
            findings.append(f"MERGE_TEST_COMMAND_DRIFT:{role}")
    if records:
        digest = hashlib.sha256(
            json.dumps([{k: v for k, v in item.items() if k != "signature"} for item in records], sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        if digest != data.get("trusted_test_evidence_digest"):
            findings.append("MERGE_TEST_EVIDENCE_DIGEST_MISMATCH")
    return findings


def _validate_provider_attestation(db: OrchestratorDB, policy: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    provider_id = policy.get("provider_attestation_id")
    if not isinstance(provider_id, str) or not provider_id:
        return ["PROVIDER_ATTESTATION_REQUIRED"]
    try:
        provider = db.get_provider_attestation(provider_id)
    except ControlPlaneError as exc:
        return [str(exc)]
    if provider.get("repository_id") != policy.get("repository_id"):
        findings.append("PROVIDER_ATTESTATION_REPOSITORY_MISMATCH")
    if provider.get("canonical_protected_ref") != policy.get("canonical_protected_ref"):
        findings.append("PROVIDER_ATTESTATION_BRANCH_MISMATCH")
    if parse_iso(provider["expires_at"]) <= now_dt():
        findings.append("PROVIDER_ATTESTATION_EXPIRED")
    if provider.get("live_connector_verified") is not True:
        findings.append("LIVE_PROVIDER_CONNECTOR_PROOF_REQUIRED")
    if not provider.get("repository_provider_id") or not provider.get("account_id"):
        findings.append("PROVIDER_BINDING_INCOMPLETE")
    controls = provider.get("controls") if isinstance(provider.get("controls"), dict) else {}
    required = {
        "protected_branch", "required_checks", "required_reviews", "force_push_disabled",
        "branch_deletion_disabled", "workflow_changes_protected",
    }
    if not all(controls.get(key) is True for key in required):
        findings.append("PROVIDER_PROTECTION_CONTROLS_INCOMPLETE")
    return findings


def evaluate(args: argparse.Namespace) -> list[str]:
    root = Path(args.root).resolve()
    findings: list[str] = []
    current_tools = verify_trusted_tools([
        "tools/merge_readiness_gate.py", "tools/trusted_tool_identity.py",
        "tools/orchestrator_control_plane.py", "tools/orchestrator_trust_store.py",
        "tools/orchestrator_assurance_store.py",
    ])
    base = resolve_commit(root, args.base_ref)
    head = resolve_commit(root, args.head_ref)
    tree = resolve_tree(root, head)
    diff_sha = hashlib.sha256(git_bytes(root, "diff", "--binary", base, head)).hexdigest()
    db = OrchestratorDB(args.orchestrator_db)
    try:
        db.validate_external_path(str(root))
        policy = db.get_repository_policy()
        canonical_target = policy.get("canonical_protected_ref")
        data = db.get_trusted_attestation(args.attestation_id)
        if data.get("base_commit_sha") != base:
            findings.append("BASE_ADVANCED_AFTER_ATTESTATION")
        if data.get("head_commit_sha") != head:
            findings.append("MERGE_CANDIDATE_SHA_CHANGED")
        if data.get("head_tree_sha") != tree:
            findings.append("MERGE_CANDIDATE_TREE_CHANGED")
        if data.get("diff_sha256") != diff_sha:
            findings.append("MERGE_CANDIDATE_DIFF_CHANGED")
        if data.get("readiness_status") != "READY_TO_MERGE":
            findings.append("ATTESTATION_NOT_READY")
        if parse_iso(data.get("expires_at", "1970-01-01T00:00:00Z")) <= now_dt():
            findings.append("ATTESTATION_EXPIRED")
        if data.get("repository_policy_version") != policy.get("policy_version"):
            findings.append("ATTESTATION_POLICY_VERSION_STALE")
        tool_identity = data.get("trusted_tool_identity") if isinstance(data.get("trusted_tool_identity"), dict) else {}
        if tool_identity.get("manifest_sha256") != current_tools.get("manifest_sha256"):
            findings.append("ATTESTATION_TRUSTED_TOOL_IDENTITY_STALE")

        lease = db.verify_active(
            data["task_id"], int(data["fencing_token"]),
            branch=data.get("leased_branch"), base_sha=base,
        )
        if data.get("lease_id") != lease.get("lease_id"):
            findings.append("ATTESTATION_LEASE_MISMATCH")
        if data.get("candidate_branch") != lease.get("branch") or data.get("leased_branch") != lease.get("branch"):
            findings.append("ATTESTATION_BRANCH_BINDING_MISMATCH")
        tip = branch_tip(root, lease["branch"])
        if tip != head or data.get("candidate_ref_tip_sha") != tip:
            findings.append("CANDIDATE_NOT_LEASED_BRANCH_TIP")
        if sorted(data.get("lease_allowed_paths", [])) != sorted(lease.get("allowed_paths", [])):
            findings.append("ATTESTATION_LEASE_SCOPE_MISMATCH")
        if data.get("approved_target_ref") != canonical_target:
            findings.append("ATTESTATION_TARGET_BRANCH_MISMATCH")
        if canonical_target == f"refs/heads/{lease['branch']}":
            findings.append("PROTECTED_REF_EQUALS_LEASED_BRANCH")

        try:
            verification = db.get_verification_record(data.get("verification_record_id", ""))
            if verification.get("record_sha256") != data.get("verification_record_sha256"):
                findings.append("ATTESTATION_VERIFICATION_RECORD_MISMATCH")
            if verification.get("status") != "VERIFIED" or verification.get("findings"):
                findings.append("ATTESTATION_VERIFICATION_RECORD_NOT_PASSING")
            if parse_iso(verification["expires_at"]) <= now_dt():
                findings.append("ATTESTATION_VERIFICATION_RECORD_EXPIRED")
        except ControlPlaneError as exc:
            findings.append(str(exc))

        findings.extend(_revalidate_test_records(db, root, data, base, head, tree))
        if args.enqueue:
            if not policy.get("automatic_merge_enabled"):
                findings.append("AUTOMATIC_MERGE_DISABLED")
            if policy.get("platform_protection_required"):
                findings.extend(_validate_provider_attestation(db, policy))
            if not findings:
                db.enqueue_merge(data["task_id"], head, data["attestation_sha256"])
    finally:
        db.close()
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--attestation-id", required=True)
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument("--enqueue", action="store_true")
    args = parser.parse_args()
    try:
        findings = evaluate(args)
    except (ControlPlaneError, RuntimeError, json.JSONDecodeError, TrustedToolIdentityError, KeyError, ValueError) as exc:
        findings = [str(exc)]
    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        return 1
    print("READY_TO_MERGE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
