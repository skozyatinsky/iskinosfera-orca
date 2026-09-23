#!/usr/bin/env python3
# ======================================================================
# provider_protection_adapter.py — версия 2.0
# Trusted provider adapter: only signed external connector envelopes are authority.
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
from external_trust import (  # noqa: E402
    ExternalTrustError,
    canonical_bytes,
    parse_utc,
    verify_ed25519_record,
)
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB, TRUST_ENV  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402

ADAPTER_ENV = "APS_TRUSTED_PROVIDER_ADAPTER"
ADAPTER_IDENTITY_ENV = "APS_TRUSTED_PROVIDER_ADAPTER_IDENTITY"
CONNECTOR_KEYS_ENV = "APS_PROVIDER_CONNECTOR_PUBLIC_KEYS_JSON"
CONNECTOR_REVOKED_KEYS_ENV = "APS_PROVIDER_CONNECTOR_REVOKED_KEY_IDS"
RUNTIME_DIGEST_ENV = "APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST"
MAX_FRESHNESS_SECONDS = 900

REQUIRED_CONTROLS = (
    "protected_branch",
    "required_checks",
    "required_reviews",
    "force_push_disabled",
    "branch_deletion_disabled",
    "workflow_changes_protected",
)


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_json(value: Any) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _github_controls(raw: dict[str, Any]) -> dict[str, bool]:
    status_checks = raw.get("required_status_checks") if isinstance(raw.get("required_status_checks"), dict) else {}
    reviews = raw.get("required_pull_request_reviews") if isinstance(raw.get("required_pull_request_reviews"), dict) else {}
    force_pushes = raw.get("allow_force_pushes") if isinstance(raw.get("allow_force_pushes"), dict) else {}
    deletions = raw.get("allow_deletions") if isinstance(raw.get("allow_deletions"), dict) else {}
    admins = raw.get("enforce_admins") if isinstance(raw.get("enforce_admins"), dict) else {}
    checks = status_checks.get("checks") if isinstance(status_checks.get("checks"), list) else []
    contexts = status_checks.get("contexts") if isinstance(status_checks.get("contexts"), list) else []
    return {
        "protected_branch": raw.get("protected") is True,
        "required_checks": bool(checks or contexts),
        "required_reviews": isinstance(reviews.get("required_approving_review_count"), int)
        and reviews["required_approving_review_count"] > 0,
        "force_push_disabled": force_pushes.get("enabled") is False,
        "branch_deletion_disabled": deletions.get("enabled") is False,
        "workflow_changes_protected": admins.get("enabled") is True
        and reviews.get("dismiss_stale_reviews") is True,
    }


def _gitlab_controls(raw: dict[str, Any]) -> dict[str, bool]:
    merge_levels = raw.get("merge_access_levels") if isinstance(raw.get("merge_access_levels"), list) else []
    push_levels = raw.get("push_access_levels") if isinstance(raw.get("push_access_levels"), list) else []
    approval_rules = raw.get("approval_rules") if isinstance(raw.get("approval_rules"), list) else []
    required_checks = raw.get("required_status_checks") if isinstance(raw.get("required_status_checks"), list) else []
    return {
        "protected_branch": raw.get("protected") is True,
        "required_checks": bool(required_checks),
        "required_reviews": any(
            isinstance(item, dict) and int(item.get("approvals_required", 0)) > 0 for item in approval_rules
        ),
        "force_push_disabled": raw.get("allow_force_push") is False,
        "branch_deletion_disabled": raw.get("allow_deletion") is False,
        "workflow_changes_protected": bool(merge_levels) and bool(push_levels)
        and raw.get("code_owner_approval_required") is True,
    }


def recompute_controls(provider: str, raw_response: dict[str, Any]) -> dict[str, bool]:
    if provider == "github":
        controls = _github_controls(raw_response)
    elif provider == "gitlab":
        controls = _gitlab_controls(raw_response)
    else:
        raise ControlPlaneError("PROVIDER_UNSUPPORTED")
    if not all(controls.get(key) is True for key in REQUIRED_CONTROLS):
        raise ControlPlaneError("PROVIDER_PROTECTION_CONTROLS_INCOMPLETE")
    return controls


def load_authenticated_response(path: Path) -> tuple[dict[str, Any], bytes]:
    del path
    raise ControlPlaneError("LOCAL_PROVIDER_RESPONSE_NOT_AUTHORITY")


def load_connector_envelope(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ControlPlaneError(f"PROVIDER_CONNECTOR_ENVELOPE_INVALID:{exc}") from exc
    if not isinstance(envelope, dict):
        raise ControlPlaneError("PROVIDER_CONNECTOR_ENVELOPE_INVALID:shape")
    required = (
        "schema_version", "connector_envelope_id", "provider", "account_id", "repository_provider_id",
        "repository_id", "canonical_protected_ref", "request_id", "nonce", "requested_endpoint",
        "http_method", "response_status", "response_headers_sha256", "raw_response", "raw_response_sha256",
        "fetched_at", "expires_at", "connector_service_identity", "connector_deployment_identity",
        "key_id", "signature",
    )
    missing = [key for key in required if key not in envelope]
    if missing:
        raise ControlPlaneError(f"PROVIDER_CONNECTOR_ENVELOPE_INVALID:missing={missing}")
    if envelope.get("schema_version") != "1.0.0":
        raise ControlPlaneError("PROVIDER_CONNECTOR_ENVELOPE_INVALID:schema_version")
    if envelope.get("http_method") != "GET" or envelope.get("response_status") != 200:
        raise ControlPlaneError("PROVIDER_CONNECTOR_HTTP_RESULT_INVALID")
    if not isinstance(envelope.get("raw_response"), dict):
        raise ControlPlaneError("PROVIDER_CONNECTOR_ENVELOPE_INVALID:raw_response")
    if envelope.get("raw_response_sha256") != _sha256_json(envelope["raw_response"]):
        raise ControlPlaneError("PROVIDER_CONNECTOR_RAW_RESPONSE_DIGEST_MISMATCH")
    if not isinstance(envelope.get("nonce"), str) or len(envelope["nonce"]) < 16:
        raise ControlPlaneError("PROVIDER_CONNECTOR_NONCE_REQUIRED")
    if not isinstance(envelope.get("repository_provider_id"), str) or not envelope["repository_provider_id"]:
        raise ControlPlaneError("PROVIDER_REPOSITORY_PROVIDER_ID_REQUIRED")
    if not isinstance(envelope.get("account_id"), str) or not envelope["account_id"]:
        raise ControlPlaneError("PROVIDER_ACCOUNT_BINDING_REQUIRED")
    fetched = parse_utc(str(envelope["fetched_at"]), "PROVIDER_CONNECTOR_TIMESTAMP_INVALID")
    expires = parse_utc(str(envelope["expires_at"]), "PROVIDER_CONNECTOR_TIMESTAMP_INVALID")
    current = now_dt()
    if expires <= current or fetched > current or (current - fetched).total_seconds() > MAX_FRESHNESS_SECONDS:
        raise ControlPlaneError("PROVIDER_CONNECTOR_RESPONSE_EXPIRED")
    if expires <= fetched or (expires - fetched).total_seconds() > MAX_FRESHNESS_SECONDS:
        raise ControlPlaneError("PROVIDER_CONNECTOR_RESPONSE_FRESHNESS_INVALID")
    try:
        verify_ed25519_record(
            envelope,
            registry_env=CONNECTOR_KEYS_ENV,
            revoked_env=CONNECTOR_REVOKED_KEYS_ENV,
            missing_registry_finding="PROVIDER_LIVE_CONNECTOR_IDENTITY_REQUIRED",
            unknown_key_finding="PROVIDER_CONNECTOR_KEY_UNTRUSTED",
            revoked_key_finding="PROVIDER_CONNECTOR_KEY_REVOKED",
            signature_finding="PROVIDER_CONNECTOR_SIGNATURE_INVALID",
            expected_service_identity=str(envelope["connector_service_identity"]),
            expected_deployment_identity=str(envelope["connector_deployment_identity"]),
        )
    except ExternalTrustError as exc:
        raise ControlPlaneError(str(exc)) from exc
    return envelope, raw


def create_attestation(envelope_path: Path, db_path: str, repository_root: Path, *, apply: bool) -> dict[str, Any]:
    if os.environ.get(TRUST_ENV) != "1" or os.environ.get(ADAPTER_ENV) != "1":
        raise ControlPlaneError("TRUSTED_PROVIDER_ADAPTER_REQUIRED")
    adapter_identity = os.environ.get(ADAPTER_IDENTITY_ENV, "").strip()
    if not adapter_identity:
        raise ControlPlaneError("TRUSTED_PROVIDER_ADAPTER_IDENTITY_REQUIRED")
    tool_identity = verify_trusted_tools(
        ["tools/provider_protection_adapter.py", "tools/external_trust.py", "tools/trusted_tool_identity.py"],
        require_external_pin=True,
    )
    envelope, raw = load_connector_envelope(envelope_path)
    controls = recompute_controls(str(envelope["provider"]), envelope["raw_response"])
    provider_id = "provider-" + hashlib.sha256(
        f"{envelope['connector_envelope_id']}:{envelope['nonce']}:{envelope['raw_response_sha256']}".encode("utf-8")
    ).hexdigest()[:32]
    body = {
        "schema_version": "3.0.0",
        "provider_attestation_id": provider_id,
        "provider": envelope["provider"],
        "account_id": envelope["account_id"],
        "repository_provider_id": envelope["repository_provider_id"],
        "repository_id": envelope["repository_id"],
        "canonical_protected_ref": envelope["canonical_protected_ref"],
        "request_id": envelope["request_id"],
        "nonce": envelope["nonce"],
        "fetched_at": envelope["fetched_at"],
        "expires_at": envelope["expires_at"],
        "requested_endpoint": envelope["requested_endpoint"],
        "http_method": envelope["http_method"],
        "response_status": envelope["response_status"],
        "response_headers_sha256": envelope["response_headers_sha256"],
        "source_api": envelope["requested_endpoint"],
        "provider_response_sha256": envelope["raw_response_sha256"],
        "connector_envelope_sha256": hashlib.sha256(raw).hexdigest(),
        "connector_envelope_id": envelope["connector_envelope_id"],
        "connector_service_identity": envelope["connector_service_identity"],
        "connector_deployment_identity": envelope["connector_deployment_identity"],
        "connector_key_id": envelope["key_id"],
        "live_connector_verified": True,
        "controls": controls,
        "issuer": "trusted-provider-adapter-v2",
        "adapter_identity": adapter_identity,
        "tool_identity": tool_identity,
        "runtime_artifact_digest": os.environ.get(RUNTIME_DIGEST_ENV, ""),
    }
    db = OrchestratorDB(db_path)
    try:
        db.validate_external_path(str(repository_root.resolve()))
        policy = db.get_repository_policy() if apply else None
        if policy is not None:
            if policy["repository_id"] != envelope["repository_id"]:
                raise ControlPlaneError("PROVIDER_ATTESTATION_REPOSITORY_MISMATCH")
            if policy["canonical_protected_ref"] != envelope["canonical_protected_ref"]:
                raise ControlPlaneError("PROVIDER_ATTESTATION_BRANCH_MISMATCH")
        stored = db.store_provider_attestation(body)
        if policy is not None:
            policy.update({
                "platform_protection_verified": True,
                "automatic_merge_enabled": True,
                "provider_attestation_id": stored["provider_attestation_id"],
            })
            db.configure_repository_policy(policy)
        return stored
    finally:
        db.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--connector-envelope")
    group.add_argument("--authenticated-response", help="Rejected legacy local-file path")
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--repository-root", default=".")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.authenticated_response:
        print("LOCAL_PROVIDER_RESPONSE_NOT_AUTHORITY", file=sys.stderr)
        return 1
    try:
        result = create_attestation(
            Path(args.connector_envelope), args.orchestrator_db, Path(args.repository_root), apply=args.apply
        )
    except (ControlPlaneError, ExternalTrustError, TrustedToolIdentityError, OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.output:
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
