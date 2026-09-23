#!/usr/bin/env python3
# ======================================================================
# verify_merge_result.py — версия 1.0
# Independent provider merge and signed post-merge evidence verifier.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from automatic_merge_gate import AutomaticMergeError, kill_switch_check, load_deployment_policy  # noqa: E402
from external_trust import ExternalTrustError, canonical_bytes, parse_utc, verify_ed25519_record  # noqa: E402
from merge_transaction_store import MergeTransactionError, MergeTransactionStore  # noqa: E402
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB  # noqa: E402
from provider_merge_adapter import ProviderAPI, ProviderMergeError, _validate_preflight  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402

POST_KEYS_ENV = "APS_POST_MERGE_VALIDATOR_KEYS_JSON"
POST_REVOKED_ENV = "APS_POST_MERGE_VALIDATOR_REVOKED_KEY_IDS"
TRUST_ENV = "APS_TRUSTED_POST_MERGE_VALIDATOR"
REQUIRED_CHECKS = (
    "protected_branch_identity", "candidate_inclusion", "governance_validation", "registry_validation",
    "module_boundaries", "function_lifecycle", "duplicate_detection", "affected_regression",
    "full_regression", "change_journal_update", "work_package_update",
)


class MergeResultError(RuntimeError):
    """Provider result or post-merge evidence validation error."""


def _load_evidence(path: Path, operation: dict[str, Any], request: dict[str, Any]) -> dict[str, Any]:
    try:
        evidence = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MergeResultError(f"POST_MERGE_EVIDENCE_INVALID:{exc}") from exc
    if not isinstance(evidence, dict):
        raise MergeResultError("POST_MERGE_EVIDENCE_INVALID:SHAPE")
    try:
        verify_ed25519_record(
            evidence, registry_env=POST_KEYS_ENV, revoked_env=POST_REVOKED_ENV,
            missing_registry_finding="POST_MERGE_VALIDATOR_IDENTITY_REQUIRED",
            unknown_key_finding="POST_MERGE_VALIDATOR_KEY_UNTRUSTED",
            revoked_key_finding="POST_MERGE_VALIDATOR_KEY_REVOKED",
            signature_finding="POST_MERGE_EVIDENCE_SIGNATURE_INVALID",
            expected_service_identity=str(evidence.get("validator_service_identity", "")),
            expected_deployment_identity=str(evidence.get("validator_deployment_identity", "")),
        )
    except ExternalTrustError as exc:
        raise MergeResultError(str(exc)) from exc
    expires = parse_utc(str(evidence.get("expires_at", "")), "POST_MERGE_EVIDENCE_TIMESTAMP_INVALID")
    if expires <= datetime.now(timezone.utc):
        raise MergeResultError("POST_MERGE_EVIDENCE_EXPIRED")
    bindings = {
        "operation_id": operation["operation_id"], "merge_request_id": operation["merge_request_id"],
        "repository_id": operation["repository_id"], "task_id": operation["task_id"],
        "candidate_commit_sha": operation["candidate_sha"], "merge_commit_sha": operation["merge_commit_sha"],
        "target_protected_ref": operation["target_ref"],
    }
    for key, expected in bindings.items():
        if evidence.get(key) != expected:
            raise MergeResultError(f"POST_MERGE_EVIDENCE_BINDING_MISMATCH:{key}")
    checks = evidence.get("checks") if isinstance(evidence.get("checks"), dict) else {}
    missing = [name for name in REQUIRED_CHECKS if checks.get(name) is not True]
    if missing:
        raise MergeResultError("MERGED_POST_VALIDATION_FAILED:" + ",".join(missing))
    if evidence.get("registry_commit_sha") != operation["merge_commit_sha"]:
        raise MergeResultError("POST_MERGE_REGISTRY_COMMIT_MISMATCH")
    return evidence


def verify_and_complete(*, root: Path, operation_id: str, transaction_db: str, orchestrator_db: str,
                        post_merge_evidence: Path, api: ProviderAPI | None = None) -> dict[str, Any]:
    if os.environ.get(TRUST_ENV) != "1":
        raise MergeResultError("TRUSTED_POST_MERGE_VALIDATOR_REQUIRED")
    load_deployment_policy(root)
    kill_switch_check()
    verify_trusted_tools([
        "tools/verify_merge_result.py", "tools/provider_merge_adapter.py", "tools/merge_transaction_store.py",
    ], root=root, require_external_pin=True)
    store = MergeTransactionStore(transaction_db)
    try:
        store.validate_external_path(str(root))
        operation = store.get(operation_id)
        request = json.loads(operation["request_json"])
        if operation["state"] == "COMPLETED":
            return {**operation, "idempotent_replay": True}
        if operation["state"] not in {"MERGE_CONFIRMED", "RECOVERY_REQUIRED", "POST_MERGE_VALIDATING"}:
            raise MergeResultError(f"AUTOMATIC_MERGE_STATE_CONFLICT:{operation['state']}")
        api = api or ProviderAPI(request["provider"], request["repository_provider_id"], request["account_id"])
        status = api.pull_status(request)
        _validate_preflight(status, request)
        if status.get("merged") is not True or not status.get("merge_commit_sha"):
            raise MergeResultError("PROVIDER_MERGE_NOT_CONFIRMED")
        if operation.get("merge_commit_sha") and operation["merge_commit_sha"] != status["merge_commit_sha"]:
            raise MergeResultError("PROVIDER_MERGE_COMMIT_MISMATCH")
        if operation["state"] != "POST_MERGE_VALIDATING":
            operation = store.transition(
                operation_id, "POST_MERGE_VALIDATING",
                expected={"MERGE_CONFIRMED", "RECOVERY_REQUIRED"}, event_type="POST_MERGE_VALIDATION_STARTED",
                updates={"merge_commit_sha": status["merge_commit_sha"],
                         "protected_branch_sha": status["merge_commit_sha"]},
            )
        try:
            evidence = _load_evidence(post_merge_evidence, operation, request)
        except MergeResultError as exc:
            return store.transition(
                operation_id, "RECOVERY_REQUIRED", expected={"POST_MERGE_VALIDATING"},
                event_type="POST_MERGE_VALIDATION_FAILED", updates={"finding_code": str(exc)},
            )
        digest = hashlib.sha256(canonical_bytes({key: value for key, value in evidence.items() if key != "signature"})).hexdigest()
        store.record_task_done(operation_id, digest)
        database = OrchestratorDB(orchestrator_db)
        try:
            database.validate_external_path(str(root))
            database.verify_active(operation["task_id"], int(operation["fencing_token"]))
            database.release(operation["lease_id"], int(operation["fencing_token"]), state="MERGED")
        finally:
            database.close()
        store.record_lease_closed(operation_id)
        return store.transition(
            operation_id, "COMPLETED", expected={"POST_MERGE_VALIDATING"}, event_type="AUTOMATIC_MERGE_COMPLETED"
        )
    finally:
        store.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--transaction-db", required=True)
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--post-merge-evidence", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify_and_complete(
            root=Path(args.root).resolve(), operation_id=args.operation_id,
            transaction_db=args.transaction_db, orchestrator_db=args.orchestrator_db,
            post_merge_evidence=Path(args.post_merge_evidence),
        )
    except (AutomaticMergeError, ControlPlaneError, ExternalTrustError, MergeResultError,
            MergeTransactionError, ProviderMergeError, TrustedToolIdentityError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("state") == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
