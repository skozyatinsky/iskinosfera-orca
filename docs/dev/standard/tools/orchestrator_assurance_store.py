#!/usr/bin/env python3
# ======================================================================
# orchestrator_assurance_store.py — версия 1.0
# Content-addressed assurance records, verifier requests and provider attestations.
# ======================================================================
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any

from orchestrator_types import TRUST_ENV, ControlPlaneError


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class AssuranceStoreMixin:
    """Trusted assurance records mixed into ``OrchestratorDB``."""

    def store_artifact(self, payload: bytes, *, media_type: str) -> str:
        if os.environ.get(TRUST_ENV) != "1":
            raise ControlPlaneError("TRUSTED_ARTIFACT_WRITER_REQUIRED")
        digest = hashlib.sha256(payload).hexdigest()
        with self.transaction():
            row = self.connection.execute(
                "SELECT size,content FROM trusted_artifacts WHERE sha256=?", (digest,)
            ).fetchone()
            if row is not None:
                if int(row["size"]) != len(payload) or bytes(row["content"]) != payload:
                    raise ControlPlaneError("TRUSTED_ARTIFACT_DIGEST_COLLISION")
                return digest
            self.connection.execute(
                "INSERT INTO trusted_artifacts(sha256,media_type,size,content,created_at) VALUES(?,?,?,?,?)",
                (digest, media_type, len(payload), payload, iso(utc_now())),
            )
        return digest

    def get_artifact(self, digest: str) -> bytes:
        row = self.connection.execute(
            "SELECT size,content FROM trusted_artifacts WHERE sha256=?", (digest,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError(f"TRUSTED_ARTIFACT_NOT_FOUND:{digest}")
        payload = bytes(row["content"])
        if len(payload) != int(row["size"]) or hashlib.sha256(payload).hexdigest() != digest:
            raise ControlPlaneError(f"TRUSTED_ARTIFACT_DIGEST_MISMATCH:{digest}")
        return payload

    def store_verification_record(self, record: dict[str, Any]) -> dict[str, Any]:
        if os.environ.get(TRUST_ENV) != "1":
            raise ControlPlaneError("TRUSTED_VERIFICATION_WRITER_REQUIRED")
        required = (
            "request_id", "run_id", "repository_id", "task_id", "candidate_identity_id",
            "expected_candidate_sha", "status", "recorded_at", "expires_at",
            "attestation_inputs", "trusted_test_evidence_ids", "tool_identity",
        )
        missing = [key for key in required if key not in record]
        if missing:
            raise ControlPlaneError(f"TRUSTED_VERIFICATION_RECORD_INVALID:missing={missing}")
        if record["status"] not in {"VERIFIED", "BLOCKED"}:
            raise ControlPlaneError("TRUSTED_VERIFICATION_RECORD_INVALID:status")
        portable = dict(record)
        portable["key_id"] = self._trusted_key_id()
        portable["signer_identity"] = self._signer_identity()
        payload = canonical_bytes(portable)
        digest = hashlib.sha256(payload).hexdigest()
        signature = self._sign(payload)
        with self.transaction():
            existing = self.connection.execute(
                "SELECT record_sha256,signature FROM trusted_verification_records WHERE request_id=?",
                (portable["request_id"],),
            ).fetchone()
            if existing is not None:
                if existing["record_sha256"] != digest or existing["signature"] != signature:
                    raise ControlPlaneError("VERIFICATION_REQUEST_ID_COLLISION")
                return self.get_verification_record(portable["request_id"])
            self.connection.execute(
                """INSERT INTO trusted_verification_records(
                    request_id,run_id,repository_id,task_id,candidate_identity_id,expected_candidate_sha,
                    status,record_json,record_sha256,signature,key_id,signer_identity,created_at,expires_at,revoked
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (
                    portable["request_id"], portable["run_id"], portable["repository_id"],
                    portable["task_id"], portable["candidate_identity_id"], portable["expected_candidate_sha"],
                    portable["status"], json.dumps(portable, ensure_ascii=False, sort_keys=True),
                    digest, signature, portable["key_id"], portable["signer_identity"],
                    portable["recorded_at"], portable["expires_at"],
                ),
            )
            self._event("TRUSTED_VERIFICATION_RECORDED", portable["task_id"], portable.get("lease_id"), {
                "request_id": portable["request_id"], "run_id": portable["run_id"],
                "status": portable["status"], "head_sha": portable["expected_candidate_sha"],
            })
        return {**portable, "record_sha256": digest, "signature": signature}

    def get_verification_record(self, request_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM trusted_verification_records WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError("TRUSTED_VERIFICATION_RECORD_NOT_FOUND")
        if int(row["revoked"]):
            raise ControlPlaneError("TRUSTED_VERIFICATION_RECORD_REVOKED")
        body = json.loads(row["record_json"])
        payload = canonical_bytes(body)
        if hashlib.sha256(payload).hexdigest() != row["record_sha256"]:
            raise ControlPlaneError("TRUSTED_VERIFICATION_RECORD_DIGEST_MISMATCH")
        if not self._verify_signature(payload, row["signature"], row["key_id"]):
            raise ControlPlaneError("TRUSTED_VERIFICATION_RECORD_SIGNATURE_INVALID")
        return {**body, "record_sha256": row["record_sha256"], "signature": row["signature"]}

    def store_provider_attestation(self, body: dict[str, Any]) -> dict[str, Any]:
        if os.environ.get(TRUST_ENV) != "1":
            raise ControlPlaneError("TRUSTED_PROVIDER_ADAPTER_REQUIRED")
        required = (
            "provider_attestation_id", "provider", "repository_id", "repository_provider_id", "account_id",
            "canonical_protected_ref", "request_id", "nonce", "fetched_at", "expires_at",
            "provider_response_sha256", "connector_envelope_id", "connector_envelope_sha256",
            "connector_service_identity", "connector_deployment_identity", "connector_key_id",
            "live_connector_verified", "controls", "issuer", "adapter_identity",
        )
        missing = [key for key in required if key not in body]
        if missing:
            raise ControlPlaneError(f"PROVIDER_ATTESTATION_INVALID:missing={missing}")
        portable = dict(body)
        if portable.get("live_connector_verified") is not True:
            raise ControlPlaneError("LIVE_PROVIDER_CONNECTOR_PROOF_REQUIRED")
        if portable.get("issuer") != "trusted-provider-adapter-v2":
            raise ControlPlaneError("PROVIDER_ATTESTATION_ISSUER_INVALID")
        portable["key_id"] = self._trusted_key_id()
        portable["signer_identity"] = self._signer_identity()
        payload = canonical_bytes(portable)
        digest = hashlib.sha256(payload).hexdigest()
        signature = self._sign(payload)
        with self.transaction():
            nonce_row = self.connection.execute(
                "SELECT provider_attestation_id FROM trusted_provider_attestations WHERE nonce=?", (portable["nonce"],)
            ).fetchone()
            if nonce_row is not None and nonce_row["provider_attestation_id"] != portable["provider_attestation_id"]:
                raise ControlPlaneError("PROVIDER_ATTESTATION_REPLAY")
            existing = self.connection.execute(
                "SELECT body_sha256,signature FROM trusted_provider_attestations WHERE provider_attestation_id=?",
                (portable["provider_attestation_id"],),
            ).fetchone()
            if existing is not None:
                if existing["body_sha256"] != digest or existing["signature"] != signature:
                    raise ControlPlaneError("PROVIDER_ATTESTATION_ID_COLLISION")
                return self.get_provider_attestation(portable["provider_attestation_id"])
            self.connection.execute(
                """INSERT INTO trusted_provider_attestations(
                    provider_attestation_id,provider,repository_id,account_id,canonical_protected_ref,nonce,
                    fetched_at,expires_at,body_json,body_sha256,signature,key_id,signer_identity,revoked
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (
                    portable["provider_attestation_id"], portable["provider"], portable["repository_id"],
                    portable["account_id"], portable["canonical_protected_ref"], portable["nonce"],
                    portable["fetched_at"], portable["expires_at"],
                    json.dumps(portable, ensure_ascii=False, sort_keys=True), digest, signature,
                    portable["key_id"], portable["signer_identity"],
                ),
            )
        return {**portable, "body_sha256": digest, "signature": signature}

    def get_provider_attestation(self, provider_attestation_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM trusted_provider_attestations WHERE provider_attestation_id=?",
            (provider_attestation_id,),
        ).fetchone()
        if row is None:
            raise ControlPlaneError("PROVIDER_ATTESTATION_NOT_FOUND")
        if int(row["revoked"]):
            raise ControlPlaneError("PROVIDER_ATTESTATION_REVOKED")
        body = json.loads(row["body_json"])
        payload = canonical_bytes(body)
        if hashlib.sha256(payload).hexdigest() != row["body_sha256"]:
            raise ControlPlaneError("PROVIDER_ATTESTATION_DIGEST_MISMATCH")
        if not self._verify_signature(payload, row["signature"], row["key_id"]):
            raise ControlPlaneError("PROVIDER_ATTESTATION_SIGNATURE_INVALID")
        return {**body, "body_sha256": row["body_sha256"], "signature": row["signature"]}
