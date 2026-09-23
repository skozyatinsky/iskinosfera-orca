#!/usr/bin/env python3
# ======================================================================
# sandbox_certification.py — версия 1.0
# Проверка внешней signed production certification sandbox executor.
# ======================================================================
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from external_trust import ExternalTrustError, canonical_bytes, parse_utc, verify_ed25519_record

CERT_PATH_ENV = "APS_SANDBOX_CERTIFICATION_PATH"
CERT_KEYS_ENV = "APS_SANDBOX_CERTIFICATION_PUBLIC_KEYS_JSON"
CERT_REVOKED_KEYS_ENV = "APS_SANDBOX_CERTIFICATION_REVOKED_KEY_IDS"
EXECUTOR_IMAGE_DIGEST_ENV = "APS_SANDBOX_EXECUTOR_IMAGE_DIGEST"
EXECUTOR_IDENTITY_ENV = "APS_SANDBOX_EXECUTOR_IDENTITY"
DEPLOYMENT_IDENTITY_ENV = "APS_SANDBOX_DEPLOYMENT_IDENTITY"


class SandboxCertificationError(RuntimeError):
    """Fail-closed sandbox certification error."""


def profile_digest(root: Path, profile_id: str) -> tuple[str, dict[str, Any]]:
    path = root / "reference" / "sandbox_profiles.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SandboxCertificationError(f"SANDBOX_PROFILE_INVALID:{exc}") from exc
    profiles = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(profiles, list):
        raise SandboxCertificationError("SANDBOX_PROFILE_INVALID:shape")
    profile = next((item for item in profiles if isinstance(item, dict) and item.get("profile_id") == profile_id), None)
    if not isinstance(profile, dict):
        raise SandboxCertificationError(f"SANDBOX_PROFILE_UNKNOWN:{profile_id}")
    digest = hashlib.sha256(canonical_bytes(profile)).hexdigest()
    return digest, profile


def _load_record(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise SandboxCertificationError(f"SANDBOX_CERTIFICATION_INVALID:{exc}") from exc
    if not isinstance(data, dict):
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_INVALID:shape")
    required = (
        "schema_version", "certification_id", "issuer", "profile_id", "sandbox_profile_id",
        "sandbox_profile_digest", "executor_image_digest", "executor_identity", "deployment_identity",
        "kernel_runtime_profile", "conformance_suite_digest", "issued_at", "expires_at", "key_id", "signature",
    )
    missing = [key for key in required if key not in data]
    if missing:
        raise SandboxCertificationError(f"SANDBOX_CERTIFICATION_INVALID:missing={missing}")
    if data.get("schema_version") != "1.0.0":
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_INVALID:schema_version")
    return data


def verify_external_certification(
    *,
    root: Path,
    production_profile_id: str,
    sandbox_profile_id: str = "linux-reference-v3",
) -> dict[str, Any]:
    path_value = os.environ.get(CERT_PATH_ENV, "").strip()
    if not path_value:
        raise SandboxCertificationError("CERTIFIED_SANDBOX_REQUIRED")
    record = _load_record(Path(path_value))
    try:
        verify_ed25519_record(
            record,
            registry_env=CERT_KEYS_ENV,
            revoked_env=CERT_REVOKED_KEYS_ENV,
            missing_registry_finding="SANDBOX_CERTIFICATION_ISSUER_REQUIRED",
            unknown_key_finding="SANDBOX_CERTIFICATION_ISSUER_UNTRUSTED",
            revoked_key_finding="SANDBOX_CERTIFICATION_REVOKED",
            signature_finding="SANDBOX_CERTIFICATION_SIGNATURE_INVALID",
            expected_service_identity=str(record["issuer"]),
            expected_deployment_identity=str(record["deployment_identity"]),
        )
    except ExternalTrustError as exc:
        raise SandboxCertificationError(str(exc)) from exc
    now = datetime.now(timezone.utc)
    issued = parse_utc(str(record["issued_at"]), "SANDBOX_CERTIFICATION_TIMESTAMP_INVALID")
    expires = parse_utc(str(record["expires_at"]), "SANDBOX_CERTIFICATION_TIMESTAMP_INVALID")
    if issued > now or expires <= now:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_EXPIRED")
    if record.get("profile_id") != production_profile_id:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_PROFILE_MISMATCH")
    if record.get("sandbox_profile_id") != sandbox_profile_id:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_SANDBOX_PROFILE_MISMATCH")
    expected_digest, profile = profile_digest(root, sandbox_profile_id)
    if record.get("sandbox_profile_digest") != expected_digest:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_PROFILE_DIGEST_MISMATCH")
    if profile.get("production_certified") is True:
        raise SandboxCertificationError("REFERENCE_PROFILE_SELF_CERTIFICATION_FORBIDDEN")
    image_digest = os.environ.get(EXECUTOR_IMAGE_DIGEST_ENV, "").strip()
    executor_identity = os.environ.get(EXECUTOR_IDENTITY_ENV, "").strip()
    deployment_identity = os.environ.get(DEPLOYMENT_IDENTITY_ENV, "").strip()
    if not image_digest or record.get("executor_image_digest") != image_digest:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_IMAGE_DIGEST_MISMATCH")
    if not executor_identity or record.get("executor_identity") != executor_identity:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_EXECUTOR_IDENTITY_MISMATCH")
    if not deployment_identity or record.get("deployment_identity") != deployment_identity:
        raise SandboxCertificationError("SANDBOX_CERTIFICATION_DEPLOYMENT_IDENTITY_MISMATCH")
    return {
        "sandbox_certification_id": record["certification_id"],
        "sandbox_certification_issuer": record["issuer"],
        "sandbox_certification_expires_at": record["expires_at"],
        "sandbox_certification_profile_id": record["profile_id"],
        "sandbox_production_certified": True,
        "executor_image_digest": record["executor_image_digest"],
        "executor_identity": record["executor_identity"],
        "deployment_identity": record["deployment_identity"],
        "kernel_runtime_profile": record["kernel_runtime_profile"],
        "conformance_suite_digest": record["conformance_suite_digest"],
    }


def certification_state(root: Path, *, production_profile_id: str | None = None) -> dict[str, Any]:
    state: dict[str, Any] = {
        "sandbox_adapter_available": False,
        "sandbox_conformance_passed": False,
        "sandbox_profile_id": "linux-reference-v3",
        "sandbox_profile_digest": None,
        "sandbox_reference_only": True,
        "sandbox_certification_id": None,
        "sandbox_certification_issuer": None,
        "sandbox_certification_expires_at": None,
        "sandbox_certification_profile_id": None,
        "sandbox_production_certified": False,
    }
    try:
        digest, _ = profile_digest(root, "linux-reference-v3")
        state["sandbox_profile_digest"] = digest
    except SandboxCertificationError:
        pass
    if production_profile_id:
        try:
            state.update(verify_external_certification(
                root=root,
                production_profile_id=production_profile_id,
                sandbox_profile_id="linux-reference-v3",
            ))
        except SandboxCertificationError as exc:
            state["sandbox_certification_finding"] = str(exc)
    return state
