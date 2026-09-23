#!/usr/bin/env python3
# ======================================================================
# orchestrator_trust_store.py — версия 1.0
# Trusted attestation, test evidence, post-merge saga and merge queue mixin.
# ======================================================================

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any

from orchestrator_types import (
    ATTESTATION_KEY_ENV,
    ATTESTATION_KEY_ID_ENV,
    REVOKED_KEY_IDS_ENV,
    SIGNER_IDENTITY_ENV,
    TRUST_ENV,
    ControlPlaneError,
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


class TrustedEvidenceStoreMixin:
    """Trusted-store methods mixed into OrchestratorDB.

    The host class provides ``connection``, ``transaction()``, ``_event()``,
    ``_require_active()``, ``get_lease()`` and ``get_repository_policy()``.
    """

    @staticmethod
    def _trusted_key() -> bytes:
        value = os.environ.get(ATTESTATION_KEY_ENV)
        if not value or len(value.encode()) < 32:
            raise ControlPlaneError("TRUSTED_ATTESTATION_KEY_REQUIRED")
        return value.encode()

    @staticmethod
    def _trusted_key_id() -> str:
        value = os.environ.get(ATTESTATION_KEY_ID_ENV, "aps-hmac-v1").strip()
        if not value:
            raise ControlPlaneError("TRUSTED_ATTESTATION_KEY_ID_REQUIRED")
        return value

    @staticmethod
    def _signer_identity() -> str:
        value = os.environ.get(SIGNER_IDENTITY_ENV, "trusted-signer-reference").strip()
        if not value:
            raise ControlPlaneError("TRUSTED_SIGNER_IDENTITY_REQUIRED")
        return value

    @staticmethod
    def _revoked_key_ids() -> set[str]:
        return {item.strip() for item in os.environ.get(REVOKED_KEY_IDS_ENV, "").split(",") if item.strip()}

    @classmethod
    def _sign(cls, payload: bytes) -> str:
        return hmac.new(cls._trusted_key(), payload, hashlib.sha256).hexdigest()

    @classmethod
    def _verify_signature(cls, payload: bytes, signature: str, key_id: str) -> bool:
        if key_id in cls._revoked_key_ids():
            raise ControlPlaneError(f"ATTESTATION_KEY_REVOKED:{key_id}")
        if key_id != cls._trusted_key_id():
            raise ControlPlaneError(f"ATTESTATION_KEY_UNAVAILABLE:{key_id}")
        return hmac.compare_digest(cls._sign(payload), signature)

    def store_attestation(self, body: dict[str, Any]) -> dict[str, Any]:
        if os.environ.get(TRUST_ENV) != "1":
            raise ControlPlaneError("TRUSTED_ATTESTATION_WRITER_REQUIRED")
        required = (
            "attestation_id", "run_id", "request_id", "candidate_identity_id", "task_id",
            "base_commit_sha", "head_commit_sha", "head_tree_sha", "diff_sha256", "fencing_token",
            "candidate_branch", "leased_branch", "candidate_ref_tip_sha", "approved_target_ref",
            "issuer", "issued_at", "readiness_status",
        )
        missing = [key for key in required if key not in body]
        if missing:
            raise ControlPlaneError(f"ATTESTATION_INVALID:missing={missing}")
        portable = dict(body)
        portable.pop("signature", None)
        portable.pop("attestation_sha256", None)
        portable["key_id"] = self._trusted_key_id()
        portable["signer_identity"] = self._signer_identity()
        payload = json.dumps(portable, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(payload).hexdigest()
        signature = self._sign(payload)
        with self.transaction():
            by_request = self.connection.execute(
                "SELECT * FROM trusted_attestations WHERE request_id=?", (portable["request_id"],)
            ).fetchone()
            if by_request is not None:
                if by_request["candidate_identity_id"] != portable["candidate_identity_id"]:
                    raise ControlPlaneError("ATTESTATION_REQUEST_ID_REUSE_MISMATCH")
                return self.get_trusted_attestation(by_request["attestation_id"])
            existing = self.connection.execute(
                "SELECT body_sha256,signature FROM trusted_attestations WHERE attestation_id=?",
                (portable["attestation_id"],),
            ).fetchone()
            if existing is not None:
                if existing["body_sha256"] != digest or existing["signature"] != signature:
                    raise ControlPlaneError("ATTESTATION_ID_COLLISION")
                return {**portable, "attestation_sha256": digest, "signature": signature}
            self.connection.execute(
                """INSERT INTO trusted_attestations(
                    attestation_id,run_id,request_id,candidate_identity_id,task_id,base_sha,head_sha,tree_sha,
                    diff_sha256,fencing_token,candidate_branch,leased_branch,candidate_ref_tip_sha,
                    approved_target_ref,issuer,signer_identity,key_id,issued_at,readiness_status,
                    body_json,body_sha256,signature,revoked
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)""",
                (
                    portable["attestation_id"], portable["run_id"], portable["request_id"],
                    portable["candidate_identity_id"], portable["task_id"], portable["base_commit_sha"],
                    portable["head_commit_sha"], portable["head_tree_sha"], portable["diff_sha256"],
                    int(portable["fencing_token"]), portable["candidate_branch"], portable["leased_branch"],
                    portable["candidate_ref_tip_sha"], portable["approved_target_ref"], portable["issuer"],
                    portable["signer_identity"], portable["key_id"], portable["issued_at"],
                    portable["readiness_status"], json.dumps(portable, sort_keys=True), digest, signature,
                ),
            )
            self._event(
                "TRUSTED_ATTESTATION_STORED", portable["task_id"], None,
                {"attestation_id": portable["attestation_id"], "run_id": portable["run_id"],
                 "request_id": portable["request_id"], "head_sha": portable["head_commit_sha"],
                 "signer_identity": portable["signer_identity"], "key_id": portable["key_id"]},
            )
        return {**portable, "attestation_sha256": digest, "signature": signature}

    def get_trusted_attestation(self, attestation_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM trusted_attestations WHERE attestation_id=?", (attestation_id,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError("ATTESTATION_NOT_TRUSTED")
        if int(row["revoked"]):
            raise ControlPlaneError("ATTESTATION_REVOKED")
        body = json.loads(row["body_json"])
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(payload).hexdigest() != row["body_sha256"]:
            raise ControlPlaneError("ATTESTATION_DB_DIGEST_MISMATCH")
        if not self._verify_signature(payload, row["signature"], row["key_id"]):
            raise ControlPlaneError("ATTESTATION_SIGNATURE_INVALID")
        return {**body, "attestation_sha256": row["body_sha256"], "signature": row["signature"]}

    def latest_valid_attestation(self, task_id: str, head_sha: str, fencing_token: int) -> dict[str, Any]:
        rows = self.connection.execute(
            "SELECT attestation_id FROM trusted_attestations WHERE task_id=? AND head_sha=? AND fencing_token=? AND revoked=0 ORDER BY issued_at DESC, attestation_id DESC",
            (task_id, head_sha, fencing_token),
        ).fetchall()
        for row in rows:
            try:
                item = self.get_trusted_attestation(row["attestation_id"])
            except ControlPlaneError:
                continue
            if item.get("readiness_status") == "READY_TO_MERGE":
                return item
        raise ControlPlaneError("ATTESTATION_NOT_TRUSTED")

    def _strict_test_evidence_findings(self, evidence: dict[str, Any]) -> list[str]:
        findings: list[str] = []
        for key in ("collected", "completed", "accounted", "passed", "failed", "errors", "skipped", "xpassed", "unexpected_skipped"):
            if not isinstance(evidence.get(key), int) or evidence[key] < 0:
                findings.append(f"TEST_EVIDENCE_INVALID:{key}")
        if findings:
            return findings
        if evidence["collected"] <= 0:
            findings.append("TRUSTED_TEST_ZERO_COLLECTED")
        if evidence["completed"] != evidence["collected"] or evidence["accounted"] != evidence["collected"]:
            findings.append("TEST_EVIDENCE_ACCOUNTING_MISMATCH")
        if evidence["passed"] <= 0:
            findings.append("TRUSTED_TEST_ZERO_PASSED")
        if evidence["failed"] or evidence["errors"]:
            findings.append("TEST_EVIDENCE_FAILURES_PRESENT")
        if evidence["xpassed"]:
            findings.append("TRUSTED_TEST_XPASS_PRESENT")
        if evidence["unexpected_skipped"]:
            findings.append("TRUSTED_TEST_UNEXPECTED_SKIP")
        minimum = evidence.get("minimum_test_count")
        if isinstance(minimum, int) and evidence["collected"] < minimum:
            findings.append("TRUSTED_TEST_COUNT_REDUCTION")
        node_ids = evidence.get("node_ids")
        expected_node_ids = evidence.get("expected_node_ids")
        if not isinstance(node_ids, list) or not all(isinstance(value, str) and value for value in node_ids):
            findings.append("TEST_EVIDENCE_INVALID:node_ids")
        elif isinstance(expected_node_ids, list) and expected_node_ids and sorted(node_ids) != sorted(expected_node_ids):
            findings.append("TRUSTED_TEST_NODE_SELECTION_DRIFT")
        if isinstance(node_ids, list):
            actual_selection = hashlib.sha256("\n".join(sorted(node_ids)).encode("utf-8")).hexdigest()
            if evidence.get("selection_digest") != actual_selection:
                findings.append("TRUSTED_TEST_SELECTION_DIGEST_MISMATCH")
        command = evidence.get("command")
        if not isinstance(command, list) or not command or not all(isinstance(value, str) for value in command):
            findings.append("TEST_EVIDENCE_INVALID:command")
        else:
            command_digest = hashlib.sha256(json.dumps(command, ensure_ascii=False, separators=(",", ":")).encode("utf-8")).hexdigest()
            if evidence.get("command_digest") != command_digest:
                findings.append("TRUSTED_TEST_COMMAND_DIGEST_MISMATCH")
        if evidence.get("sandbox_conformance_passed") is not True:
            findings.append("SANDBOX_CONFORMANCE_REQUIRED")
        return findings

    def store_test_evidence(self, evidence: dict[str, Any]) -> dict[str, Any]:
        if os.environ.get(TRUST_ENV) != "1":
            raise ControlPlaneError("TRUSTED_TEST_EVIDENCE_WRITER_REQUIRED")
        string_fields = (
            "evidence_id", "run_id", "task_id", "head_sha", "tree_sha", "check_id", "test_role",
            "status", "report_sha256", "stdout_sha256", "stderr_sha256", "issuer", "issued_at",
            "command_digest", "selection_digest", "check_registry_digest", "check_registry_version",
        )
        for key in string_fields:
            if not isinstance(evidence.get(key), str) or not evidence[key]:
                raise ControlPlaneError(f"TEST_EVIDENCE_INVALID:{key}")
        if evidence.get("test_role") not in {"targeted_tests", "affected_tests", "full_regression", "post_merge_validation"}:
            raise ControlPlaneError("TEST_EVIDENCE_INVALID:test_role")
        if evidence.get("status") != "PASS" or evidence.get("exit_code") != 0:
            raise ControlPlaneError("TEST_EVIDENCE_NOT_PASSING")
        strict_findings = self._strict_test_evidence_findings(evidence)
        if strict_findings:
            raise ControlPlaneError(strict_findings[0])

        portable = dict(evidence)
        report_b64 = portable.pop("report_content_base64", None)
        stdout_text = portable.pop("stdout", "")
        stderr_text = portable.pop("stderr", "")
        try:
            report_bytes = base64.b64decode(report_b64, validate=True) if isinstance(report_b64, str) else None
        except ValueError as exc:
            raise ControlPlaneError("TRUSTED_TEST_REPORT_ENCODING_INVALID") from exc
        if report_bytes is None:
            # Re-validation of already persisted records does not need raw bytes.
            self.get_artifact(portable["report_sha256"])
        else:
            if hashlib.sha256(report_bytes).hexdigest() != portable["report_sha256"]:
                raise ControlPlaneError("TRUSTED_TEST_REPORT_DIGEST_MISMATCH")
            self.store_artifact(report_bytes, media_type="application/junit+xml")
        stdout_bytes = str(stdout_text).encode("utf-8", errors="replace")
        stderr_bytes = str(stderr_text).encode("utf-8", errors="replace")
        if stdout_text:
            if hashlib.sha256(stdout_bytes).hexdigest() != portable["stdout_sha256"]:
                raise ControlPlaneError("TRUSTED_TEST_STDOUT_DIGEST_MISMATCH")
            self.store_artifact(stdout_bytes, media_type="text/plain; stream=stdout")
        if stderr_text:
            if hashlib.sha256(stderr_bytes).hexdigest() != portable["stderr_sha256"]:
                raise ControlPlaneError("TRUSTED_TEST_STDERR_DIGEST_MISMATCH")
            self.store_artifact(stderr_bytes, media_type="text/plain; stream=stderr")

        portable["key_id"] = self._trusted_key_id()
        portable["signer_identity"] = self._signer_identity()
        payload = json.dumps(portable, sort_keys=True, separators=(",", ":")).encode()
        digest = hashlib.sha256(payload).hexdigest()
        signature = self._sign(payload)
        with self.transaction():
            existing = self.connection.execute(
                "SELECT evidence_sha256,signature FROM trusted_test_evidence WHERE evidence_id=?",
                (portable["evidence_id"],),
            ).fetchone()
            if existing is not None:
                if existing["evidence_sha256"] != digest or existing["signature"] != signature:
                    raise ControlPlaneError("TEST_EVIDENCE_ID_COLLISION")
                return {**portable, "evidence_sha256": digest, "signature": signature}
            self.connection.execute(
                "INSERT INTO trusted_test_evidence(evidence_id,run_id,task_id,head_sha,check_id,evidence_json,evidence_sha256,signature,key_id,signer_identity,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (portable["evidence_id"], portable["run_id"], portable["task_id"], portable["head_sha"],
                 portable["check_id"], json.dumps(portable, sort_keys=True), digest, signature,
                 portable["key_id"], portable["signer_identity"], iso(utc_now())),
            )
        return {**portable, "evidence_sha256": digest, "signature": signature}

    def get_test_evidence(self, evidence_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM trusted_test_evidence WHERE evidence_id=?", (evidence_id,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError("TRUSTED_TEST_EVIDENCE_NOT_FOUND")
        body = json.loads(row["evidence_json"])
        payload = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
        if hashlib.sha256(payload).hexdigest() != row["evidence_sha256"]:
            raise ControlPlaneError("TRUSTED_TEST_EVIDENCE_INVALID")
        if not self._verify_signature(payload, row["signature"], row["key_id"]):
            raise ControlPlaneError("TRUSTED_TEST_EVIDENCE_INVALID")
        strict_findings = self._strict_test_evidence_findings(body)
        if strict_findings:
            raise ControlPlaneError(strict_findings[0])
        report = self.get_artifact(body["report_sha256"])
        if hashlib.sha256(report).hexdigest() != body["report_sha256"]:
            raise ControlPlaneError("TRUSTED_TEST_REPORT_DIGEST_MISMATCH")
        return {**body, "evidence_sha256": row["evidence_sha256"], "signature": row["signature"]}

    def begin_post_merge_operation(self, operation: dict[str, Any]) -> dict[str, Any]:
        required = ("operation_id", "task_id", "attestation_id", "protected_ref", "protected_sha", "patch_sha256", "lease_id", "fencing_token")
        missing = [key for key in required if not operation.get(key)]
        if missing:
            raise ControlPlaneError(f"POST_MERGE_OPERATION_INVALID:{missing}")
        timestamp = iso(utc_now())
        with self.transaction():
            existing = self.connection.execute(
                "SELECT * FROM post_merge_operations WHERE operation_id=?", (operation["operation_id"],)
            ).fetchone()
            if existing is not None:
                return dict(existing)
            self.connection.execute(
                "INSERT INTO post_merge_operations(operation_id,task_id,attestation_id,protected_ref,protected_sha,state,patch_sha256,lease_id,fencing_token,created_at,updated_at) VALUES(?,?,?,?,?,'PREPARED',?,?,?,?,?)",
                (operation["operation_id"], operation["task_id"], operation["attestation_id"],
                 operation["protected_ref"], operation["protected_sha"], operation["patch_sha256"],
                 operation["lease_id"], int(operation["fencing_token"]), timestamp, timestamp),
            )
            self._event("POST_MERGE_PREPARED", operation["task_id"], operation["lease_id"], {"operation_id": operation["operation_id"]})
        return self.get_post_merge_operation(operation["operation_id"])

    def get_post_merge_operation(self, operation_id: str) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM post_merge_operations WHERE operation_id=?", (operation_id,)
        ).fetchone()
        if row is None:
            raise ControlPlaneError("POST_MERGE_OPERATION_NOT_FOUND")
        return dict(row)

    def mark_post_merge_git_committed(self, operation_id: str, commit_sha: str) -> dict[str, Any]:
        with self.transaction():
            row = self.connection.execute("SELECT * FROM post_merge_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row["state"] not in {"PREPARED", "GIT_COMMITTED"}:
                raise ControlPlaneError("POST_MERGE_OPERATION_STATE_INVALID")
            self.connection.execute(
                "UPDATE post_merge_operations SET state='GIT_COMMITTED',git_commit_sha=?,updated_at=? WHERE operation_id=?",
                (commit_sha, iso(utc_now()), operation_id),
            )
            self._event("POST_MERGE_GIT_COMMITTED", row["task_id"], row["lease_id"], {"operation_id": operation_id, "commit_sha": commit_sha})
        return self.get_post_merge_operation(operation_id)

    def complete_post_merge_operation(self, operation_id: str) -> dict[str, Any]:
        with self.transaction():
            row = self.connection.execute("SELECT * FROM post_merge_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None or row["state"] != "GIT_COMMITTED" or not row["git_commit_sha"]:
                raise ControlPlaneError("POST_MERGE_OPERATION_NOT_COMMIT_CONFIRMED")
            lease = self.connection.execute("SELECT * FROM leases WHERE lease_id=?", (row["lease_id"],)).fetchone()
            self._require_active(lease, int(row["fencing_token"]), utc_now())
            self.connection.execute("UPDATE leases SET state='MERGED' WHERE lease_id=?", (row["lease_id"],))
            self.connection.execute(
                "UPDATE post_merge_operations SET state='COMPLETED',updated_at=? WHERE operation_id=?",
                (iso(utc_now()), operation_id),
            )
            self._event("POST_MERGE_COMPLETED", row["task_id"], row["lease_id"], {"operation_id": operation_id, "commit_sha": row["git_commit_sha"]})
        return self.get_post_merge_operation(operation_id)

    def compensate_post_merge_operation(self, operation_id: str, error_code: str) -> dict[str, Any]:
        with self.transaction():
            row = self.connection.execute("SELECT * FROM post_merge_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                raise ControlPlaneError("POST_MERGE_OPERATION_NOT_FOUND")
            if row["state"] == "COMPLETED":
                raise ControlPlaneError("POST_MERGE_OPERATION_ALREADY_COMPLETED")
            self.connection.execute(
                "UPDATE post_merge_operations SET state='COMPENSATED',error_code=?,updated_at=? WHERE operation_id=?",
                (error_code, iso(utc_now()), operation_id),
            )
            self._event("POST_MERGE_COMPENSATED", row["task_id"], row["lease_id"], {"operation_id": operation_id, "error": error_code})
        return self.get_post_merge_operation(operation_id)

    def enqueue_merge(self, task_id: str, head_sha: str, attestation_sha256: str) -> dict[str, Any]:
        with self.transaction():
            self.connection.execute(
                "INSERT INTO merge_queue(task_id,head_sha,attestation_sha256,enqueued_at,state) VALUES(?,?,?,?, 'QUEUED')",
                (task_id, head_sha, attestation_sha256, iso(utc_now())),
            )
            self._event("MERGE_ENQUEUED", task_id, None, {"head_sha": head_sha, "attestation_sha256": attestation_sha256})
        row = self.connection.execute("SELECT * FROM merge_queue WHERE task_id=?", (task_id,)).fetchone()
        return dict(row)

