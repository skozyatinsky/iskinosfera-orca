#!/usr/bin/env python3
# ======================================================================
# automatic_merge_gate.py — версия 1.0
# Fail-closed pre-provider gate for controlled automatic merge.
# ======================================================================
from __future__ import annotations

import argparse
import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from external_trust import ExternalTrustError, parse_utc, verify_ed25519_record  # noqa: E402
from merge_readiness_gate import evaluate as evaluate_merge_readiness  # noqa: E402
from merge_transaction_store import MergeTransactionError, MergeTransactionStore  # noqa: E402
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB  # noqa: E402
from sandbox_certification import SandboxCertificationError, verify_external_certification  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402

POLICY_PATH_ENV = "APS_AUTOMATIC_MERGE_DEPLOYMENT_POLICY"
POLICY_KEYS_ENV = "APS_AUTOMATIC_MERGE_POLICY_KEYS_JSON"
POLICY_REVOKED_ENV = "APS_AUTOMATIC_MERGE_POLICY_REVOKED_KEY_IDS"
ORCHESTRATOR_KEYS_ENV = "APS_AUTOMATIC_MERGE_ORCHESTRATOR_KEYS_JSON"
ORCHESTRATOR_REVOKED_ENV = "APS_AUTOMATIC_MERGE_ORCHESTRATOR_REVOKED_KEY_IDS"
ENABLE_ENV = "AUTOMATIC_MERGE_ENABLED"
TRUST_ENV = "APS_TRUSTED_ORCHESTRATOR"

REQUIRED_CONTROLS = (
    "authenticated_provider_adapter", "provider_repository_binding", "protected_branch",
    "required_status_checks", "required_reviews", "force_push_disabled", "branch_deletion_disabled",
    "workflow_files_protected", "production_certified_executor", "orchestrator_service_identity",
    "signer_service_identity", "hsm_or_secrets_manager", "external_trusted_tool_root",
    "external_transactional_store", "audit_log_retention", "human_emergency_stop",
)
REQUEST_FIELDS = (
    "merge_request_id", "repository_id", "repository_provider_id", "account_id", "provider", "provider_pr_mr_id",
    "task_id", "lease_id", "fencing_token", "base_commit_sha", "candidate_commit_sha", "candidate_tree_sha",
    "candidate_diff_sha256", "candidate_branch", "target_protected_ref", "trusted_attestation_id",
    "provider_protection_attestation_id", "sandbox_certification_id", "trusted_toolchain_identity",
    "policy_version", "created_at", "expires_at", "request_nonce", "orchestrator_service_identity",
    "orchestrator_deployment_identity", "key_id", "signature",
)


class AutomaticMergeError(RuntimeError):
    """Fail-closed automatic merge validation error."""


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def _load_json(path: Path, finding: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AutomaticMergeError(f"{finding}:{exc}") from exc
    if not isinstance(value, dict):
        raise AutomaticMergeError(f"{finding}:INVALID_SHAPE")
    return value


def _outside_repository(path: Path, root: Path, finding: str) -> None:
    # Reject a repository-controlled symlink even when its target resolves
    # outside the repository. The link itself remains caller-controlled.
    if path.is_symlink():
        raise AutomaticMergeError(finding)
    resolved = path.resolve(strict=True)
    try:
        if os.path.commonpath([str(resolved), str(root.resolve())]) == str(root.resolve()):
            raise AutomaticMergeError(finding)
    except ValueError:
        return


def kill_switch_check() -> None:
    if os.environ.get(ENABLE_ENV, "false").strip().lower() != "true":
        raise AutomaticMergeError("AUTOMATIC_MERGE_KILL_SWITCH_ACTIVE")


def load_deployment_policy(root: Path) -> dict[str, Any]:
    path_value = os.environ.get(POLICY_PATH_ENV, "").strip()
    if not path_value:
        raise AutomaticMergeError("AUTOMATIC_MERGE_EXTERNAL_CONTROL_MISSING:DEPLOYMENT_POLICY")
    path = Path(path_value)
    _outside_repository(path, root, "AUTOMATIC_MERGE_POLICY_INSIDE_REPOSITORY")
    policy = _load_json(path, "AUTOMATIC_MERGE_POLICY_INVALID")
    try:
        verify_ed25519_record(
            policy, registry_env=POLICY_KEYS_ENV, revoked_env=POLICY_REVOKED_ENV,
            missing_registry_finding="AUTOMATIC_MERGE_POLICY_KEY_REGISTRY_REQUIRED",
            unknown_key_finding="AUTOMATIC_MERGE_POLICY_KEY_UNTRUSTED",
            revoked_key_finding="AUTOMATIC_MERGE_POLICY_KEY_REVOKED",
            signature_finding="AUTOMATIC_MERGE_POLICY_SIGNATURE_INVALID",
            expected_service_identity=str(policy.get("policy_issuer", "")),
            expected_deployment_identity=str(policy.get("deployment_identity", "")),
        )
    except ExternalTrustError as exc:
        raise AutomaticMergeError(str(exc)) from exc
    if policy.get("profile_id") != "controlled_automatic_merge":
        raise AutomaticMergeError("AUTOMATIC_MERGE_POLICY_PROFILE_MISMATCH")
    if policy.get("enabled") is not True:
        raise AutomaticMergeError("AUTOMATIC_MERGE_EXTERNAL_CONTROL_MISSING:PROFILE_DISABLED")
    if policy.get("failure_mode") != "fail_closed":
        raise AutomaticMergeError("AUTOMATIC_MERGE_POLICY_NOT_FAIL_CLOSED")
    controls = policy.get("controls") if isinstance(policy.get("controls"), dict) else {}
    missing = [name for name in REQUIRED_CONTROLS if controls.get(name) is not True]
    if missing:
        raise AutomaticMergeError("AUTOMATIC_MERGE_EXTERNAL_CONTROL_MISSING:" + ",".join(missing))
    issued = parse_utc(str(policy.get("issued_at", "")), "AUTOMATIC_MERGE_POLICY_TIMESTAMP_INVALID")
    expires = parse_utc(str(policy.get("expires_at", "")), "AUTOMATIC_MERGE_POLICY_TIMESTAMP_INVALID")
    if issued > now_dt() or expires <= now_dt():
        raise AutomaticMergeError("AUTOMATIC_MERGE_POLICY_EXPIRED")
    kill_switch_check()
    return policy


def load_merge_request(path: Path) -> dict[str, Any]:
    request = _load_json(path, "AUTOMATIC_MERGE_REQUEST_INVALID")
    missing = [field for field in REQUEST_FIELDS if field not in request]
    if missing:
        raise AutomaticMergeError("AUTOMATIC_MERGE_REQUEST_INVALID:MISSING=" + ",".join(missing))
    try:
        verify_ed25519_record(
            request, registry_env=ORCHESTRATOR_KEYS_ENV, revoked_env=ORCHESTRATOR_REVOKED_ENV,
            missing_registry_finding="AUTOMATIC_MERGE_ORCHESTRATOR_IDENTITY_REQUIRED",
            unknown_key_finding="AUTOMATIC_MERGE_ORCHESTRATOR_KEY_UNTRUSTED",
            revoked_key_finding="AUTOMATIC_MERGE_ORCHESTRATOR_KEY_REVOKED",
            signature_finding="AUTOMATIC_MERGE_REQUEST_SIGNATURE_INVALID",
            expected_service_identity=str(request["orchestrator_service_identity"]),
            expected_deployment_identity=str(request["orchestrator_deployment_identity"]),
        )
    except ExternalTrustError as exc:
        raise AutomaticMergeError(str(exc)) from exc
    created = parse_utc(str(request["created_at"]), "AUTOMATIC_MERGE_REQUEST_TIMESTAMP_INVALID")
    expires = parse_utc(str(request["expires_at"]), "AUTOMATIC_MERGE_REQUEST_TIMESTAMP_INVALID")
    if created > now_dt() or expires <= now_dt():
        raise AutomaticMergeError("AUTOMATIC_MERGE_REQUEST_EXPIRED")
    if len(str(request["request_nonce"])) < 16:
        raise AutomaticMergeError("AUTOMATIC_MERGE_REQUEST_NONCE_REQUIRED")
    return request




READINESS_FINDING_MAP = {
    "BASE_ADVANCED_AFTER_ATTESTATION": "BASE_ADVANCED_BEFORE_AUTOMATIC_MERGE",
    "CANDIDATE_NOT_LEASED_BRANCH_TIP": "CANDIDATE_BRANCH_TIP_CHANGED",
    "ATTESTATION_EXPIRED": "AUTOMATIC_MERGE_ATTESTATION_EXPIRED",
}


def enforce_readiness_findings(findings: list[str]) -> None:
    """Convert the deep merge-readiness verifier result into a hard gate."""
    if findings:
        raise AutomaticMergeError(READINESS_FINDING_MAP.get(findings[0], findings[0]))


def validate_request_bindings(request: dict[str, Any], policy: dict[str, Any]) -> None:
    pairs = (
        ("repository_id", "repository_id", "AUTOMATIC_MERGE_REPOSITORY_MISMATCH"),
        ("repository_provider_id", "repository_provider_id", "AUTOMATIC_MERGE_PROVIDER_REPOSITORY_MISMATCH"),
        ("account_id", "account_id", "AUTOMATIC_MERGE_ACCOUNT_MISMATCH"),
        ("provider", "provider", "AUTOMATIC_MERGE_PROVIDER_MISMATCH"),
        ("target_protected_ref", "target_protected_ref", "AUTOMATIC_MERGE_TARGET_BRANCH_MISMATCH"),
        ("policy_version", "policy_version", "AUTOMATIC_MERGE_POLICY_VERSION_STALE"),
    )
    for request_key, policy_key, finding in pairs:
        if request.get(request_key) != policy.get(policy_key):
            raise AutomaticMergeError(finding)


def evaluate_gate(*, root: Path, request_path: Path, orchestrator_db: str, transaction_db: str,
                  base_ref: str, head_ref: str, delivery_id: str, execution_id: str) -> dict[str, Any]:
    if os.environ.get(TRUST_ENV) != "1":
        raise AutomaticMergeError("TRUSTED_ORCHESTRATOR_REQUIRED")
    policy = load_deployment_policy(root)
    request = load_merge_request(request_path)
    validate_request_bindings(request, policy)
    tools = verify_trusted_tools([
        "tools/automatic_merge_gate.py", "tools/provider_merge_adapter.py", "tools/merge_transaction_store.py",
        "tools/verify_merge_result.py", "tools/recover_merge_operation.py", "tools/merge_readiness_gate.py",
    ], root=root, require_external_pin=True)
    toolchain = request.get("trusted_toolchain_identity")
    if not isinstance(toolchain, dict) or toolchain.get("manifest_sha256") != tools.get("manifest_sha256"):
        raise AutomaticMergeError("AUTOMATIC_MERGE_TRUSTED_TOOLCHAIN_CHANGED")
    certification = verify_external_certification(root=root, production_profile_id="controlled_automatic_merge")
    if certification["sandbox_certification_id"] != request["sandbox_certification_id"]:
        raise AutomaticMergeError("AUTOMATIC_MERGE_SANDBOX_CERTIFICATION_CHANGED")
    readiness_args = SimpleNamespace(
        root=str(root), orchestrator_db=orchestrator_db, attestation_id=request["trusted_attestation_id"],
        base_ref=base_ref, head_ref=head_ref,
    )
    findings = evaluate_merge_readiness(readiness_args)
    enforce_readiness_findings(findings)
    db = OrchestratorDB(orchestrator_db)
    try:
        db.validate_external_path(str(root))
        attestation = db.get_trusted_attestation(request["trusted_attestation_id"])
        provider = db.get_provider_attestation(request["provider_protection_attestation_id"])
        lease = db.verify_active(request["task_id"], int(request["fencing_token"]),
                                 branch=request["candidate_branch"], base_sha=request["base_commit_sha"])
        if lease["lease_id"] != request["lease_id"]:
            raise AutomaticMergeError("AUTOMATIC_MERGE_LEASE_MISMATCH")
        if attestation["head_commit_sha"] != request["candidate_commit_sha"]:
            raise AutomaticMergeError("AUTOMATIC_MERGE_CANDIDATE_SHA_CHANGED")
        if attestation["head_tree_sha"] != request["candidate_tree_sha"]:
            raise AutomaticMergeError("AUTOMATIC_MERGE_CANDIDATE_TREE_CHANGED")
        if attestation["diff_sha256"] != request["candidate_diff_sha256"]:
            raise AutomaticMergeError("AUTOMATIC_MERGE_CANDIDATE_DIFF_CHANGED")
        if provider.get("live_connector_verified") is not True:
            raise AutomaticMergeError("AUTOMATIC_MERGE_LIVE_PROVIDER_PROOF_REQUIRED")
        if provider.get("repository_provider_id") != request["repository_provider_id"]:
            raise AutomaticMergeError("AUTOMATIC_MERGE_PROVIDER_REPOSITORY_MISMATCH")
        if provider.get("account_id") != request["account_id"]:
            raise AutomaticMergeError("AUTOMATIC_MERGE_ACCOUNT_MISMATCH")
    finally:
        db.close()
    store = MergeTransactionStore(transaction_db)
    try:
        store.validate_external_path(str(root))
        operation = store.create(request, delivery_id=delivery_id, execution_id=execution_id)
        if operation.get("idempotent_replay"):
            return operation
        operation = store.transition(operation["operation_id"], "VALIDATING", expected={"CREATED"})
        operation = store.transition(operation["operation_id"], "READY_FOR_QUEUE", expected={"VALIDATING"})
        return operation
    finally:
        store.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--merge-request", required=True)
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--transaction-db", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--delivery-id", required=True)
    parser.add_argument("--execution-id")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    execution_id = args.execution_id or uuid.uuid4().hex
    try:
        result = evaluate_gate(
            root=Path(args.root).resolve(), request_path=Path(args.merge_request),
            orchestrator_db=args.orchestrator_db, transaction_db=args.transaction_db,
            base_ref=args.base_ref, head_ref=args.head_ref, delivery_id=args.delivery_id,
            execution_id=execution_id,
        )
    except (AutomaticMergeError, ControlPlaneError, ExternalTrustError, MergeTransactionError,
            SandboxCertificationError, TrustedToolIdentityError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
