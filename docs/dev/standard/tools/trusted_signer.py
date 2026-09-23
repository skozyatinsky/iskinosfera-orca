#!/usr/bin/env python3
# ======================================================================
# trusted_signer.py — версия 2.0
# Canonical attestation builder over trusted verification records only.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

TRUSTED_GIT_EXECUTABLE = str(Path("/usr/bin/git").resolve()) if Path("/usr/bin/git").exists() else "git"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB, TRUST_ENV, parse_iso  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402
from verify_agent_result import find_task, load_check_registry, ownership_scopes, path_in_scope  # noqa: E402

REQUEST_FIELDS = {
    "request_id", "candidate_identity_id", "repository_id", "task_id", "expected_candidate_sha"
}
REQUIRED_TEST_ROLES = ("targeted_tests", "affected_tests", "full_regression")
REQUIRED_VALIDATOR_STEPS = {
    "control_plane", "module_boundaries", "code_ownership", "agent_workflow_integrity", "function_registries"
}


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def git(root: Path, *args: str) -> str:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise ControlPlaneError(f"GIT_COMMAND_FAILED:{' '.join(args)}:{proc.stderr.strip()}")
    return proc.stdout.strip()


def git_bytes(root: Path, *args: str) -> bytes:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True)
    if proc.returncode != 0:
        raise ControlPlaneError(f"GIT_COMMAND_FAILED:{' '.join(args)}")
    return proc.stdout


def load_request(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlPlaneError(f"SIGNING_REQUEST_INVALID:{exc}") from exc
    if not isinstance(data, dict):
        raise ControlPlaneError("SIGNING_REQUEST_INVALID:shape")
    extras = sorted(set(data) - REQUEST_FIELDS)
    missing = sorted(REQUEST_FIELDS - set(data))
    if extras:
        raise ControlPlaneError(f"CALLER_ATTESTATION_FIELDS_FORBIDDEN:{extras}")
    if missing:
        raise ControlPlaneError(f"SIGNING_REQUEST_INVALID:missing={missing}")
    for key in REQUEST_FIELDS:
        if not isinstance(data.get(key), str) or not data[key]:
            raise ControlPlaneError(f"SIGNING_REQUEST_INVALID:{key}")
    return data  # type: ignore[return-value]


def _branch_tip(root: Path, branch: str) -> str:
    candidates = [branch, f"refs/heads/{branch}", f"refs/remotes/origin/{branch}"]
    for ref in candidates:
        proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, "rev-parse", f"{ref}^{{commit}}"], cwd=root, capture_output=True, text=True)
        if proc.returncode == 0:
            return proc.stdout.strip()
    raise ControlPlaneError(f"LEASE_BRANCH_REF_NOT_FOUND:{branch}")


def _changed_files(root: Path, base_sha: str, head_sha: str) -> list[str]:
    output = git(root, "diff", "--name-only", "--diff-filter=ACDMRTUXB", base_sha, head_sha)
    return sorted(line for line in output.splitlines() if line)


def _canonical_command(argv: list[str]) -> list[str]:
    result = list(argv)
    if result and result[0] in {"python", "python3"}:
        result[0] = sys.executable
    return result


def _command_digest(argv: list[str]) -> str:
    return hashlib.sha256(json.dumps(_canonical_command(argv), ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()


def _validate_scope(root: Path, base_sha: str, head_sha: str, task_id: str, lease: dict[str, Any]) -> tuple[list[str], list[str], list[str], list[str]]:
    task = find_task(root, task_id, base_sha)
    actual = _changed_files(root, base_sha, head_sha)
    task_scope = [value for value in task.get("allowed_paths", []) if isinstance(value, str)]
    lease_scope = [value for value in lease.get("allowed_paths", []) if isinstance(value, str)]
    owner_scope, owner_findings = ownership_scopes(root, base_sha, task)
    findings = list(owner_findings)
    for path in actual:
        if not path_in_scope(path, task_scope):
            findings.append(f"TASK_SCOPE_VIOLATION:{path}")
        if not path_in_scope(path, lease_scope):
            findings.append(f"LEASE_SCOPE_VIOLATION:{path}")
        if not owner_scope or not path_in_scope(path, owner_scope):
            findings.append(f"OWNERSHIP_SCOPE_VIOLATION:{path}")
    return actual, task_scope, owner_scope, findings


def _validate_test_graph(
    db: OrchestratorDB,
    record: dict[str, Any],
    root: Path,
    base_sha: str,
    head_sha: str,
    tree_sha: str,
) -> tuple[dict[str, str], list[dict[str, Any]]]:
    ids = record.get("trusted_test_evidence_ids")
    if not isinstance(ids, dict) or set(ids) != set(REQUIRED_TEST_ROLES):
        raise ControlPlaneError("TRUSTED_TEST_EVIDENCE_GRAPH_INCOMPLETE")
    checks, registry_digest, registry_version = load_check_registry(root, base_sha)
    evidence_records: list[dict[str, Any]] = []
    for role in REQUIRED_TEST_ROLES:
        evidence = db.get_test_evidence(ids[role])
        if evidence.get("test_role") != role:
            raise ControlPlaneError(f"TRUSTED_TEST_ROLE_MISMATCH:{role}")
        if evidence.get("run_id") != record.get("run_id"):
            raise ControlPlaneError(f"TRUSTED_TEST_RUN_MISMATCH:{role}")
        if evidence.get("task_id") != record.get("task_id"):
            raise ControlPlaneError(f"TRUSTED_TEST_TASK_MISMATCH:{role}")
        if evidence.get("head_sha") != head_sha or evidence.get("tree_sha") != tree_sha:
            raise ControlPlaneError(f"TRUSTED_TEST_CANDIDATE_MISMATCH:{role}")
        if evidence.get("check_registry_digest") != registry_digest or evidence.get("check_registry_version") != registry_version:
            raise ControlPlaneError(f"TRUSTED_TEST_REGISTRY_DRIFT:{role}")
        check_id = str(evidence.get("check_id", ""))
        if not check_id.startswith("required:"):
            raise ControlPlaneError(f"TRUSTED_TEST_CHECK_NOT_REGISTERED:{role}")
        registry_id = check_id.split(":", 1)[1]
        check = checks.get(registry_id)
        if not check or check.get("test_role") != role:
            raise ControlPlaneError(f"TRUSTED_TEST_CHECK_NOT_REGISTERED:{role}")
        if evidence.get("command_digest") != _command_digest(check.get("argv", [])):
            raise ControlPlaneError(f"TRUSTED_TEST_COMMAND_DRIFT:{role}")
        evidence_records.append(evidence)
    return {role: ids[role] for role in REQUIRED_TEST_ROLES}, evidence_records


def _validate_validator_graph(record: dict[str, Any], head_sha: str) -> list[dict[str, Any]]:
    evidence = record.get("validator_evidence")
    if not isinstance(evidence, list) or not evidence:
        raise ControlPlaneError("TRUSTED_VALIDATOR_GRAPH_MISSING")
    observed: set[str] = set()
    portable: list[dict[str, Any]] = []
    for item in evidence:
        if not isinstance(item, dict) or item.get("status") != "PASS":
            raise ControlPlaneError("TRUSTED_VALIDATOR_GRAPH_FAILED")
        if item.get("working_tree_commit_sha") != head_sha:
            raise ControlPlaneError("TRUSTED_VALIDATOR_CANDIDATE_MISMATCH")
        check_id = item.get("check_id")
        if isinstance(check_id, str):
            observed.add(check_id.split(":", 1)[0] if check_id.startswith("required:") else check_id)
        portable.append({key: value for key, value in item.items() if key not in {"stdout", "stderr", "report_content_base64", "executed_command"}})
    if not REQUIRED_VALIDATOR_STEPS.issubset(observed):
        raise ControlPlaneError(f"TRUSTED_VALIDATOR_GRAPH_INCOMPLETE:{sorted(REQUIRED_VALIDATOR_STEPS-observed)}")
    digest = hashlib.sha256(json.dumps(portable, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()
    if digest != record.get("validator_graph_digest"):
        raise ControlPlaneError("TRUSTED_VALIDATOR_GRAPH_DIGEST_MISMATCH")
    return portable


def sign_request(request: dict[str, str], db_path: str, repository_root: str) -> dict[str, Any]:
    if os.environ.get(TRUST_ENV) != "1":
        raise ControlPlaneError("TRUSTED_SIGNER_CONTEXT_REQUIRED")
    root = Path(repository_root).resolve()
    current_tool_identity = verify_trusted_tools()
    db = OrchestratorDB(db_path)
    try:
        db.validate_external_path(str(root))
        record = db.get_verification_record(request["request_id"])
        for key in ("repository_id", "task_id", "candidate_identity_id", "expected_candidate_sha"):
            if record.get(key) != request.get(key):
                raise ControlPlaneError(f"SIGNING_REQUEST_RECORD_MISMATCH:{key}")
        if record.get("status") != "VERIFIED" or record.get("findings"):
            raise ControlPlaneError("TRUSTED_VERIFICATION_NOT_PASSING")
        if parse_iso(record["expires_at"]) <= now_dt():
            raise ControlPlaneError("TRUSTED_VERIFICATION_RECORD_EXPIRED")
        recorded_tools = record.get("tool_identity", {})
        if recorded_tools.get("manifest_sha256") != current_tool_identity.get("manifest_sha256"):
            raise ControlPlaneError("TRUSTED_TOOL_IDENTITY_CHANGED_AFTER_VERIFICATION")

        inputs = record.get("attestation_inputs")
        if not isinstance(inputs, dict):
            raise ControlPlaneError("TRUSTED_VERIFICATION_INPUTS_INVALID")
        base_sha = git(root, "rev-parse", f"{inputs['base_commit_sha']}^{{commit}}")
        head_sha = git(root, "rev-parse", f"{request['expected_candidate_sha']}^{{commit}}")
        tree_sha = git(root, "rev-parse", f"{head_sha}^{{tree}}")
        diff_sha = hashlib.sha256(git_bytes(root, "diff", "--binary", base_sha, head_sha)).hexdigest()
        if inputs.get("head_tree_sha") != tree_sha:
            raise ControlPlaneError("SIGNER_CANDIDATE_TREE_MISMATCH")
        if inputs.get("diff_sha256") != diff_sha:
            raise ControlPlaneError("SIGNER_CANDIDATE_DIFF_MISMATCH")

        lease = db.verify_active(
            request["task_id"],
            int(record["fencing_token"]),
            branch=inputs.get("leased_branch"),
            base_sha=base_sha,
        )
        tip = _branch_tip(root, lease["branch"])
        if tip != head_sha or inputs.get("candidate_ref_tip_sha") != tip:
            raise ControlPlaneError("CANDIDATE_NOT_LEASED_BRANCH_TIP")
        if record.get("lease_id") != lease.get("lease_id"):
            raise ControlPlaneError("SIGNER_LEASE_MISMATCH")

        policy = db.get_repository_policy()
        snapshot = record.get("repository_policy_snapshot", {})
        if snapshot.get("policy_version") != policy.get("policy_version"):
            raise ControlPlaneError("REPOSITORY_POLICY_CHANGED_AFTER_VERIFICATION")
        if inputs.get("approved_target_ref") != policy.get("canonical_protected_ref"):
            raise ControlPlaneError("SIGNER_TARGET_POLICY_MISMATCH")

        actual, task_scope, owner_scope, scope_findings = _validate_scope(root, base_sha, head_sha, request["task_id"], lease)
        if scope_findings:
            raise ControlPlaneError(scope_findings[0])
        validator_evidence = _validate_validator_graph(record, head_sha)
        test_ids, test_evidence = _validate_test_graph(db, record, root, base_sha, head_sha, tree_sha)

        # Idempotent delivery is allowed only after every mutable prerequisite
        # above has been revalidated.
        existing = db.connection.execute(
            "SELECT attestation_id,candidate_identity_id FROM trusted_attestations WHERE request_id=?",
            (request["request_id"],),
        ).fetchone()
        if existing is not None:
            if existing["candidate_identity_id"] != request["candidate_identity_id"]:
                raise ControlPlaneError("ATTESTATION_REQUEST_ID_REUSE_MISMATCH")
            return db.get_trusted_attestation(existing["attestation_id"])

        issued = now_dt()
        run_id = record["run_id"]
        body = {
            "schema_version": "4.0.0",
            "attestation_id": f"att-{request['task_id']}-{head_sha[:12]}-{record['fencing_token']}-{run_id[:12]}",
            "run_id": run_id,
            "request_id": request["request_id"],
            "repository_id": request["repository_id"],
            "candidate_identity_id": request["candidate_identity_id"],
            "task_id": request["task_id"],
            "base_commit_sha": base_sha,
            "head_commit_sha": head_sha,
            "head_tree_sha": tree_sha,
            "diff_sha256": diff_sha,
            "candidate_branch": lease["branch"],
            "leased_branch": lease["branch"],
            "candidate_ref_tip_sha": tip,
            "approved_target_ref": policy["canonical_protected_ref"],
            "actual_changed_files": actual,
            "task_allowed_paths": task_scope,
            "lease_allowed_paths": lease["allowed_paths"],
            "ownership_allowed_paths": owner_scope,
            "scope_compliance": True,
            "ownership_compliance": True,
            "module_boundary_compliance": True,
            "mandatory_check_evidence": validator_evidence,
            "trusted_test_evidence_ids": test_ids,
            "trusted_test_evidence_digest": hashlib.sha256(
                json.dumps([{k: v for k, v in item.items() if k != "signature"} for item in test_evidence], sort_keys=True, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "verification_record_id": request["request_id"],
            "verification_record_sha256": record["record_sha256"],
            "trusted_tool_identity": current_tool_identity,
            "repository_policy_version": policy["policy_version"],
            "provider_attestation_id": policy.get("provider_attestation_id"),
            "lease_id": lease["lease_id"],
            "fencing_token": int(lease["fencing_token"]),
            "issuer": "trusted-signer",
            "issued_at": iso(issued),
            "expires_at": iso(issued + timedelta(minutes=20)),
            "readiness_status": "READY_TO_MERGE",
            "findings": [],
        }
        stored = db.store_attestation(body)
        db._event("TRUSTED_SIGNER_COMPLETED", body["task_id"], body["lease_id"], {
            "attestation_id": stored["attestation_id"], "run_id": run_id,
            "request_id": request["request_id"], "verification_record_sha256": record["record_sha256"],
        })
        return stored
    finally:
        db.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request")
    parser.add_argument("--unsigned-bundle")
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--repository-root", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.unsigned_bundle:
            raise ControlPlaneError("CALLER_SUPPLIED_ATTESTATION_BODY_REJECTED")
        if not args.request:
            raise ControlPlaneError("SIGNING_REQUEST_REQUIRED")
        result = sign_request(load_request(Path(args.request)), args.orchestrator_db, args.repository_root)
    except (ControlPlaneError, TrustedToolIdentityError, OSError, ValueError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
