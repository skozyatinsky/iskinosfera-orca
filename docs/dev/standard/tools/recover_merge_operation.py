#!/usr/bin/env python3
# ======================================================================
# recover_merge_operation.py — версия 1.0
# Idempotent recovery after provider timeout or lost merge response.
# ======================================================================
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from automatic_merge_gate import AutomaticMergeError, kill_switch_check, load_deployment_policy  # noqa: E402
from merge_transaction_store import MergeTransactionError, MergeTransactionStore  # noqa: E402
from provider_merge_adapter import ProviderAPI, ProviderMergeError, _validate_preflight, execute_merge  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402
from verify_merge_result import MergeResultError, verify_and_complete  # noqa: E402


class MergeRecoveryError(RuntimeError):
    """Fail-closed merge recovery error."""


def recover(*, root: Path, operation_id: str, transaction_db: str, orchestrator_db: str,
            post_merge_evidence: Path | None = None, api: ProviderAPI | None = None) -> dict[str, Any]:
    load_deployment_policy(root)
    kill_switch_check()
    verify_trusted_tools([
        "tools/recover_merge_operation.py", "tools/provider_merge_adapter.py", "tools/verify_merge_result.py",
        "tools/merge_transaction_store.py",
    ], root=root, require_external_pin=True)
    store = MergeTransactionStore(transaction_db)
    try:
        operation = store.get(operation_id)
        request = json.loads(operation["request_json"])
    finally:
        store.close()
    if operation["state"] == "COMPLETED":
        return {**operation, "idempotent_replay": True}
    api = api or ProviderAPI(request["provider"], request["repository_provider_id"], request["account_id"])
    if operation["state"] == "RECOVERY_REQUIRED":
        status = api.pull_status(request)
        _validate_preflight(status, request)
        if status.get("merged") is True and status.get("merge_commit_sha"):
            store = MergeTransactionStore(transaction_db)
            try:
                operation = store.transition(
                    operation_id, "MERGE_CONFIRMED", expected={"RECOVERY_REQUIRED"},
                    event_type="LOST_PROVIDER_RESPONSE_RECOVERED",
                    updates={"merge_commit_sha": status["merge_commit_sha"],
                             "provider_request_id": status.get("provider_request_id")},
                )
            finally:
                store.close()
        elif operation.get("merge_commit_sha"):
            raise MergeRecoveryError("PROVIDER_MERGE_STATE_CONFLICT")
        else:
            return execute_merge(root=root, operation_id=operation_id, transaction_db=transaction_db, api=api)
    if post_merge_evidence is None:
        store = MergeTransactionStore(transaction_db)
        try:
            return store.get(operation_id)
        finally:
            store.close()
    return verify_and_complete(
        root=root, operation_id=operation_id, transaction_db=transaction_db,
        orchestrator_db=orchestrator_db, post_merge_evidence=post_merge_evidence, api=api,
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--transaction-db", required=True)
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--post-merge-evidence")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = recover(
            root=Path(args.root).resolve(), operation_id=args.operation_id,
            transaction_db=args.transaction_db, orchestrator_db=args.orchestrator_db,
            post_merge_evidence=Path(args.post_merge_evidence) if args.post_merge_evidence else None,
        )
    except (AutomaticMergeError, MergeRecoveryError, MergeResultError, MergeTransactionError,
            ProviderMergeError, TrustedToolIdentityError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("state") == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
