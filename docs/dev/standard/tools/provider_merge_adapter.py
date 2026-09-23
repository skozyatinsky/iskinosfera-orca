#!/usr/bin/env python3
# ======================================================================
# provider_merge_adapter.py — версия 1.0
# Authenticated GitHub/GitLab merge API adapter; local JSON is never evidence.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from automatic_merge_gate import (  # noqa: E402
    AutomaticMergeError, kill_switch_check, load_deployment_policy, validate_request_bindings,
)
from merge_transaction_store import MergeTransactionError, MergeTransactionStore, canonical_bytes  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402

TRUST_ENV = "APS_TRUSTED_PROVIDER_MERGE_ADAPTER"
GITHUB_TOKEN_ENV = "APS_GITHUB_PROVIDER_TOKEN"
GITLAB_TOKEN_ENV = "APS_GITLAB_PROVIDER_TOKEN"
GITHUB_API_BASE_ENV = "APS_GITHUB_API_BASE_URL"
GITLAB_API_BASE_ENV = "APS_GITLAB_API_BASE_URL"


class ProviderMergeError(RuntimeError):
    """Provider API or provider-state validation error."""


class ProviderTimeout(ProviderMergeError):
    def __init__(self, finding: str, *, request_sent: bool) -> None:
        super().__init__(finding)
        self.request_sent = request_sent


class ProviderAPI:
    """Small live-only HTTP adapter. Tests replace call(), not input authority."""

    def __init__(self, provider: str, repository_provider_id: str, account_id: str) -> None:
        self.provider = provider
        self.repository_provider_id = repository_provider_id
        self.account_id = account_id
        if provider == "github":
            self.token = os.environ.get(GITHUB_TOKEN_ENV, "").strip()
            self.base_url = os.environ.get(GITHUB_API_BASE_ENV, "").strip().rstrip("/")
        elif provider == "gitlab":
            self.token = os.environ.get(GITLAB_TOKEN_ENV, "").strip()
            self.base_url = os.environ.get(GITLAB_API_BASE_ENV, "").strip().rstrip("/")
        else:
            raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_UNSUPPORTED")
        if not self.token:
            raise ProviderMergeError("AUTOMATIC_MERGE_LIVE_PROVIDER_CREDENTIAL_REQUIRED")
        if not self.base_url or not self.base_url.startswith("https://"):
            raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_ENDPOINT_REQUIRED")

    def call(self, method: str, path: str, *, payload: dict[str, Any] | None = None,
             request_id: str | None = None) -> tuple[Any, dict[str, str]]:
        if not path.startswith("/") or ".." in path:
            raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_PATH_INVALID")
        body = canonical_bytes(payload) if payload is not None else None
        headers = {"Accept": "application/json", "User-Agent": "agent-project-standard/2.9.134"}
        if self.provider == "github":
            headers["Authorization"] = f"Bearer {self.token}"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
        else:
            headers["PRIVATE-TOKEN"] = self.token
        if body is not None:
            headers["Content-Type"] = "application/json"
        if request_id:
            headers["Idempotency-Key"] = request_id
        request = urllib.request.Request(self.base_url + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30, context=ssl.create_default_context()) as response:
                raw = response.read()
                data = json.loads(raw or b"{}")
                if not isinstance(data, (dict, list)):
                    raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_RESPONSE_INVALID")
                return data, {key.lower(): value for key, value in response.headers.items()}
        except (socket.timeout, TimeoutError) as exc:
            raise ProviderTimeout("AUTOMATIC_MERGE_PROVIDER_TIMEOUT", request_sent=method != "GET") from exc
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode("utf-8", errors="replace")
            raise ProviderMergeError(f"AUTOMATIC_MERGE_PROVIDER_HTTP_ERROR:{exc.code}:{raw[:200]}") from exc
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            raise ProviderMergeError(f"AUTOMATIC_MERGE_PROVIDER_TRANSPORT_ERROR:{exc}") from exc

    def pull_status(self, request: dict[str, Any]) -> dict[str, Any]:
        identifier = str(request["provider_pr_mr_id"])
        if self.provider == "github":
            data, headers = self.call("GET", f"/repositories/{self.repository_provider_id}/pulls/{identifier}")
            if not isinstance(data, dict):
                raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_RESPONSE_INVALID")
            reviews, _ = self.call("GET", f"/repositories/{self.repository_provider_id}/pulls/{identifier}/reviews")
            status, _ = self.call("GET", f"/repositories/{self.repository_provider_id}/commits/{request['candidate_commit_sha']}/status")
            checks, _ = self.call("GET", f"/repositories/{self.repository_provider_id}/commits/{request['candidate_commit_sha']}/check-runs")
            review_states: dict[str, str] = {}
            for review in reviews if isinstance(reviews, list) else []:
                if not isinstance(review, dict):
                    continue
                user_id = str(review.get("user", {}).get("id", ""))
                state = str(review.get("state", "")).upper()
                if user_id and state in {"APPROVED", "CHANGES_REQUESTED", "DISMISSED"}:
                    review_states[user_id] = state
            status_items = status.get("statuses", []) if isinstance(status, dict) else []
            check_items = checks.get("check_runs", []) if isinstance(checks, dict) else []
            checks_present = bool(status_items or check_items)
            checks_passed = (
                checks_present
                and (not status_items or status.get("state") == "success")
                and all(
                    isinstance(item, dict) and item.get("status") == "completed"
                    and item.get("conclusion") in {"success", "neutral"}
                    for item in check_items
                )
            )
            base_repo = data.get("base", {}).get("repo", {})
            owner = base_repo.get("owner", {}) if isinstance(base_repo, dict) else {}
            return {
                "provider": "github", "provider_pr_mr_id": identifier,
                "repository_provider_id": str(base_repo.get("id", "")),
                "account_id": str(owner.get("id", "")),
                "base_ref": "refs/heads/" + str(data.get("base", {}).get("ref", "")),
                "base_sha": str(data.get("base", {}).get("sha", "")),
                "head_sha": str(data.get("head", {}).get("sha", "")),
                "merged": bool(data.get("merged")), "merge_commit_sha": data.get("merge_commit_sha"),
                "mergeable": data.get("mergeable") is True,
                "reviews_approved": bool(review_states) and all(state == "APPROVED" for state in review_states.values()),
                "checks_passed": checks_passed,
                "provider_request_id": headers.get("x-github-request-id", ""),
                "raw_response": {"pull": data, "reviews": reviews, "status": status, "checks": checks},
            }
        encoded = urllib.parse.quote(self.repository_provider_id, safe="")
        data, headers = self.call("GET", f"/projects/{encoded}/merge_requests/{identifier}")
        project, _ = self.call("GET", f"/projects/{encoded}")
        approvals, _ = self.call("GET", f"/projects/{encoded}/merge_requests/{identifier}/approvals")
        pipelines, _ = self.call("GET", f"/projects/{encoded}/merge_requests/{identifier}/pipelines")
        if not isinstance(data, dict) or not isinstance(project, dict):
            raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_RESPONSE_INVALID")
        pipeline_items = pipelines if isinstance(pipelines, list) else []
        latest_pipeline = pipeline_items[0] if pipeline_items and isinstance(pipeline_items[0], dict) else {}
        namespace = project.get("namespace", {}) if isinstance(project.get("namespace"), dict) else {}
        return {
            "provider": "gitlab", "provider_pr_mr_id": identifier,
            "repository_provider_id": str(project.get("id", "")),
            "account_id": str(namespace.get("id", "")),
            "base_ref": "refs/heads/" + str(data.get("target_branch", "")),
            "base_sha": str(data.get("diff_refs", {}).get("base_sha", "")),
            "head_sha": str(data.get("sha", "")), "merged": data.get("state") == "merged",
            "merge_commit_sha": data.get("merge_commit_sha"),
            "mergeable": data.get("merge_status") == "can_be_merged",
            "reviews_approved": isinstance(approvals, dict) and approvals.get("approved") is True,
            "checks_passed": bool(latest_pipeline) and latest_pipeline.get("status") == "success",
            "provider_request_id": headers.get("x-request-id", ""),
            "raw_response": {"merge_request": data, "project": project, "approvals": approvals, "pipelines": pipelines},
        }

    def merge(self, request: dict[str, Any], provider_request_id: str) -> dict[str, Any]:
        identifier = str(request["provider_pr_mr_id"])
        if self.provider == "github":
            data, headers = self.call(
                "PUT", f"/repositories/{self.repository_provider_id}/pulls/{identifier}/merge",
                payload={"sha": request["candidate_commit_sha"], "merge_method": "merge"},
                request_id=provider_request_id,
            )
            return {
                "merged": bool(data.get("merged")), "merge_commit_sha": data.get("sha"),
                "message": data.get("message"),
                "provider_request_id": headers.get("x-github-request-id") or provider_request_id,
                "raw_response": data,
            }
        encoded = urllib.parse.quote(self.repository_provider_id, safe="")
        data, headers = self.call(
            "PUT", f"/projects/{encoded}/merge_requests/{identifier}/merge",
            payload={"sha": request["candidate_commit_sha"], "should_remove_source_branch": False},
            request_id=provider_request_id,
        )
        return {
            "merged": data.get("state") == "merged", "merge_commit_sha": data.get("merge_commit_sha"),
            "message": data.get("message"), "provider_request_id": headers.get("x-request-id") or provider_request_id,
            "raw_response": data,
        }


def _validate_preflight(status: dict[str, Any], request: dict[str, Any]) -> None:
    if status.get("repository_provider_id") != request["repository_provider_id"]:
        raise ProviderMergeError("PROVIDER_RESPONSE_OTHER_REPOSITORY")
    if status.get("account_id") != request["account_id"]:
        raise ProviderMergeError("PROVIDER_RESPONSE_OTHER_ACCOUNT")
    if status.get("base_ref") != request["target_protected_ref"]:
        raise ProviderMergeError("PROVIDER_RESPONSE_OTHER_BRANCH")
    if status.get("head_sha") != request["candidate_commit_sha"]:
        raise ProviderMergeError("CANDIDATE_BRANCH_TIP_CHANGED")
    if status.get("base_sha") != request["base_commit_sha"]:
        raise ProviderMergeError("BASE_ADVANCED_BEFORE_AUTOMATIC_MERGE")
    if status.get("merged"):
        return
    if status.get("mergeable") is not True or status.get("checks_passed") is not True:
        raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_CHECKS_NOT_READY")
    if status.get("reviews_approved") is not True:
        raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_REVIEWS_NOT_READY")


def execute_merge(*, root: Path, operation_id: str, transaction_db: str,
                  api: ProviderAPI | None = None) -> dict[str, Any]:
    if os.environ.get(TRUST_ENV) != "1":
        raise ProviderMergeError("TRUSTED_PROVIDER_MERGE_ADAPTER_REQUIRED")
    policy = load_deployment_policy(root)
    kill_switch_check()
    verify_trusted_tools([
        "tools/provider_merge_adapter.py", "tools/automatic_merge_gate.py", "tools/merge_transaction_store.py",
    ], root=root, require_external_pin=True)
    store = MergeTransactionStore(transaction_db)
    try:
        store.validate_external_path(str(root))
        operation = store.get(operation_id)
        request = json.loads(operation["request_json"])
        validate_request_bindings(request, policy)
        if operation["state"] in {"MERGE_CONFIRMED", "POST_MERGE_VALIDATING", "COMPLETED"}:
            return {**operation, "idempotent_replay": True}
        if operation["state"] not in {"READY_FOR_QUEUE", "QUEUED", "RECOVERY_REQUIRED"}:
            raise ProviderMergeError(f"AUTOMATIC_MERGE_STATE_CONFLICT:{operation['state']}")
        api = api or ProviderAPI(request["provider"], request["repository_provider_id"], request["account_id"])
        kill_switch_check()
        status = api.pull_status(request)
        _validate_preflight(status, request)
        if status.get("merged"):
            digest = hashlib.sha256(canonical_bytes(status["raw_response"])).hexdigest()
            return store.transition(
                operation_id, "MERGE_CONFIRMED", expected={operation["state"]}, event_type="MERGE_RECOVERED",
                updates={"provider_request_id": status.get("provider_request_id"),
                         "provider_response_json": json.dumps(status, sort_keys=True),
                         "provider_response_sha256": digest, "merge_commit_sha": status.get("merge_commit_sha")},
            )
        if operation["state"] == "READY_FOR_QUEUE":
            operation = store.transition(operation_id, "QUEUED", expected={"READY_FOR_QUEUE"}, event_type="PROVIDER_QUEUE_ENTERED")
        kill_switch_check()
        provider_request_id = operation.get("provider_request_id") or "provider-request-" + uuid.uuid4().hex
        operation = store.transition(
            operation_id, "MERGE_REQUESTED", expected={"QUEUED", "RECOVERY_REQUIRED"},
            event_type="PROVIDER_MERGE_REQUESTED", updates={"provider_request_id": provider_request_id},
        )
        try:
            response = api.merge(request, provider_request_id)
        except ProviderTimeout as exc:
            target = "RECOVERY_REQUIRED" if exc.request_sent else "READY_FOR_QUEUE"
            return store.transition(
                operation_id, target, expected={"MERGE_REQUESTED"}, event_type="PROVIDER_TIMEOUT",
                updates={"finding_code": "PROVIDER_TIMEOUT_AFTER_SEND" if exc.request_sent else "PROVIDER_TIMEOUT_BEFORE_SEND"},
            )
        if response.get("merged") is not True or not response.get("merge_commit_sha"):
            raise ProviderMergeError("AUTOMATIC_MERGE_PROVIDER_DID_NOT_CONFIRM_MERGE")
        digest = hashlib.sha256(canonical_bytes(response["raw_response"])).hexdigest()
        return store.transition(
            operation_id, "MERGE_CONFIRMED", expected={"MERGE_REQUESTED"}, event_type="PROVIDER_MERGE_CONFIRMED",
            updates={"provider_request_id": response.get("provider_request_id") or provider_request_id,
                     "provider_response_json": json.dumps(response, ensure_ascii=False, sort_keys=True),
                     "provider_response_sha256": digest, "merge_commit_sha": response["merge_commit_sha"]},
        )
    except (AutomaticMergeError, MergeTransactionError, ProviderMergeError):
        raise
    finally:
        store.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--operation-id", required=True)
    parser.add_argument("--transaction-db", required=True)
    parser.add_argument("--local-provider-json", help="Rejected legacy/non-authority input")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.local_provider_json:
        print("LOCAL_PROVIDER_JSON_IS_NOT_MERGE_EVIDENCE", file=sys.stderr)
        return 1
    try:
        result = execute_merge(root=Path(args.root).resolve(), operation_id=args.operation_id,
                               transaction_db=args.transaction_db)
    except (AutomaticMergeError, MergeTransactionError, ProviderMergeError, TrustedToolIdentityError,
            OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
