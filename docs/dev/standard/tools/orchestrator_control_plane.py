#!/usr/bin/env python3
# ======================================================================
# orchestrator_control_plane.py — версия 1.0
# Reference SQLite control plane: transactional leases, fencing tokens,
# conflict classification, heartbeat, merge queue and append-only events.
# ======================================================================

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sqlite3
import sys
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator

# The control plane is also loaded through importlib.spec_from_file_location in
# isolated release/test workspaces. Ensure sibling modules resolve without
# relying on caller-controlled PYTHONPATH or the current working directory.
_TOOL_DIR = Path(__file__).resolve().parent
if str(_TOOL_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOL_DIR))

from orchestrator_assurance_store import AssuranceStoreMixin
from orchestrator_trust_store import TrustedEvidenceStoreMixin
from orchestrator_types import (
    ATTESTATION_KEY_ENV,
    ATTESTATION_KEY_ID_ENV,
    REVOKED_KEY_IDS_ENV,
    SIGNER_IDENTITY_ENV,
    TRUST_ENV,
    ControlPlaneError,
)

BLOCKING_CONFLICTS = {"WRITE_WRITE", "SCHEMA_CONFLICT", "MIGRATION_CONFLICT", "CONTROL_PLANE_CONFLICT"}


# ======================================================================
# 1. ВРЕМЯ, ПУТИ И КОНФЛИКТЫ
# ======================================================================


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_iso(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_scope(scope: str) -> str:
    normalized = scope.replace("\\", "/").lstrip("./")
    if not normalized or PurePosixPath(normalized).is_absolute() or ".." in PurePosixPath(normalized).parts:
        raise ValueError(f"unsafe scope: {scope!r}")
    return normalized


def _literal_prefix(pattern: str) -> str:
    parts: list[str] = []
    for part in pattern.split("/"):
        if any(char in part for char in "*?["):
            break
        parts.append(part)
    return "/".join(parts)


def scopes_overlap(left: str, right: str) -> bool:
    left = _normalize_scope(left)
    right = _normalize_scope(right)
    if fnmatch.fnmatchcase(left, right) or fnmatch.fnmatchcase(right, left):
        return True
    lp = _literal_prefix(left)
    rp = _literal_prefix(right)
    if not lp or not rp:
        return True
    return lp == rp or lp.startswith(rp + "/") or rp.startswith(lp + "/")


def classify_conflict(
    left_paths: list[str],
    right_paths: list[str],
    *,
    left_access: str = "write",
    right_access: str = "write",
) -> str:
    if not any(scopes_overlap(left, right) for left in left_paths for right in right_paths):
        return "NO_CONFLICT"
    if left_access == "read" and right_access == "read":
        return "READ_READ"
    if "read" in {left_access, right_access}:
        return "READ_WRITE"
    joined = "\n".join([*left_paths, *right_paths]).lower()
    if "docs/registry" in joined or "control_plane" in joined or ".github/workflows" in joined:
        return "CONTROL_PLANE_CONFLICT"
    if "migration" in joined or "/migrations/" in joined:
        return "MIGRATION_CONFLICT"
    if "schema" in joined or joined.endswith(".sql"):
        return "SCHEMA_CONFLICT"
    return "WRITE_WRITE"


# ======================================================================
# 2. SQLITE CONTROL PLANE
# ======================================================================



# ======================================================================
# TRUSTED CONTROL-PLANE SCHEMA
# SQL lives at module scope so schema definition does not inflate the
# operational initialize() method and remains reviewable as one unit.
# ======================================================================
_CONTROL_PLANE_SCHEMA_SQL = """
            CREATE TABLE IF NOT EXISTS task_tokens(
                task_id TEXT PRIMARY KEY,
                last_token INTEGER NOT NULL CHECK(last_token >= 0)
            );
            CREATE TABLE IF NOT EXISTS leases(
                lease_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                branch TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                fencing_token INTEGER NOT NULL CHECK(fencing_token > 0),
                issued_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                heartbeat_at TEXT NOT NULL,
                allowed_paths_json TEXT NOT NULL,
                access_mode TEXT NOT NULL CHECK(access_mode IN ('read', 'write')),
                state TEXT NOT NULL CHECK(state IN ('ACTIVE', 'EXPIRED', 'RELEASED', 'MERGED')),
                UNIQUE(task_id, fencing_token)
            );
            CREATE UNIQUE INDEX IF NOT EXISTS one_active_lease_per_task
                ON leases(task_id) WHERE state='ACTIVE';
            CREATE TABLE IF NOT EXISTS merge_queue(
                queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL UNIQUE,
                head_sha TEXT NOT NULL,
                attestation_sha256 TEXT NOT NULL,
                enqueued_at TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('QUEUED', 'BLOCKED', 'MERGED', 'CANCELLED'))
            );
            CREATE TABLE IF NOT EXISTS trusted_attestations(
                attestation_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                request_id TEXT NOT NULL UNIQUE,
                candidate_identity_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                tree_sha TEXT NOT NULL,
                diff_sha256 TEXT NOT NULL,
                fencing_token INTEGER NOT NULL,
                candidate_branch TEXT NOT NULL,
                leased_branch TEXT NOT NULL,
                candidate_ref_tip_sha TEXT NOT NULL,
                approved_target_ref TEXT NOT NULL,
                issuer TEXT NOT NULL,
                signer_identity TEXT NOT NULL,
                key_id TEXT NOT NULL,
                issued_at TEXT NOT NULL,
                readiness_status TEXT NOT NULL CHECK(readiness_status IN ('READY_TO_MERGE','REJECTED')),
                body_json TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
            );
            CREATE INDEX IF NOT EXISTS attestations_candidate_idx
                ON trusted_attestations(task_id,head_sha,fencing_token,issued_at);
            CREATE TABLE IF NOT EXISTS trusted_test_evidence(
                evidence_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                head_sha TEXT NOT NULL,
                check_id TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                evidence_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                signer_identity TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trusted_artifacts(
                sha256 TEXT PRIMARY KEY,
                media_type TEXT NOT NULL,
                size INTEGER NOT NULL CHECK(size >= 0),
                content BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS trusted_verification_records(
                request_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                candidate_identity_id TEXT NOT NULL,
                expected_candidate_sha TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('VERIFIED','BLOCKED')),
                record_json TEXT NOT NULL,
                record_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                signer_identity TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
            );
            CREATE TABLE IF NOT EXISTS trusted_provider_attestations(
                provider_attestation_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                repository_id TEXT NOT NULL,
                account_id TEXT NOT NULL,
                canonical_protected_ref TEXT NOT NULL,
                nonce TEXT NOT NULL UNIQUE,
                fetched_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                body_json TEXT NOT NULL,
                body_sha256 TEXT NOT NULL,
                signature TEXT NOT NULL,
                key_id TEXT NOT NULL,
                signer_identity TEXT NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
            );
            CREATE TABLE IF NOT EXISTS repository_policy(
                repository_id TEXT PRIMARY KEY,
                policy_version TEXT NOT NULL,
                canonical_protected_ref TEXT NOT NULL,
                allowed_protected_refs_json TEXT NOT NULL,
                automatic_merge_enabled INTEGER NOT NULL CHECK(automatic_merge_enabled IN (0,1)),
                platform_protection_required INTEGER NOT NULL CHECK(platform_protection_required IN (0,1)),
                platform_protection_verified INTEGER NOT NULL CHECK(platform_protection_verified IN (0,1)),
                human_supervised_post_merge_allowed INTEGER NOT NULL CHECK(human_supervised_post_merge_allowed IN (0,1)),
                provider_attestation_id TEXT,
                configured_by TEXT NOT NULL,
                configured_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS post_merge_operations(
                operation_id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                attestation_id TEXT NOT NULL,
                protected_ref TEXT NOT NULL,
                protected_sha TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('PREPARED','GIT_COMMITTED','COMPLETED','COMPENSATED','FAILED')),
                patch_sha256 TEXT NOT NULL,
                git_commit_sha TEXT,
                lease_id TEXT NOT NULL,
                fencing_token INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                error_code TEXT
            );
            CREATE TABLE IF NOT EXISTS events(
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                task_id TEXT,
                lease_id TEXT,
                payload_json TEXT NOT NULL
            );
            """
_REPOSITORY_POLICY_BOOTSTRAP_SQL = """INSERT OR IGNORE INTO repository_policy(
                repository_id,policy_version,canonical_protected_ref,allowed_protected_refs_json,
                automatic_merge_enabled,platform_protection_required,platform_protection_verified,
                human_supervised_post_merge_allowed,provider_attestation_id,configured_by,configured_at
            ) VALUES('default','2.0.0','refs/heads/main','["refs/heads/main"]',0,1,0,1,NULL,'reference-bootstrap',?)"""

class OrchestratorDB(TrustedEvidenceStoreMixin, AssuranceStoreMixin):
    def __init__(self, path: str) -> None:
        self.path = path
        self.connection = sqlite3.connect(path, isolation_level=None, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.initialize()
        self._secure_database_files()

    def close(self) -> None:
        self.connection.close()

    def _secure_database_files(self) -> None:
        if self.path == ":memory:":
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = self.path + suffix
            if os.path.exists(candidate) and os.name != "nt":
                os.chmod(candidate, 0o600)

    def validate_external_path(self, repository_root: str | None = None) -> None:
        if self.path == ":memory:":
            raise ControlPlaneError("TRUSTED_DB_IN_MEMORY_FORBIDDEN")
        db_path = os.path.realpath(os.path.abspath(self.path))
        if repository_root:
            repo = os.path.realpath(os.path.abspath(repository_root))
            try:
                common = os.path.commonpath([db_path, repo])
            except ValueError:
                common = ""
            if common == repo:
                raise ControlPlaneError("TRUSTED_DB_INSIDE_REPOSITORY")
        if os.name != "nt":
            mode = os.stat(db_path).st_mode & 0o777
            if mode & 0o077:
                raise ControlPlaneError(f"TRUSTED_DB_PERMISSIONS_TOO_OPEN:{mode:03o}")

    def initialize(self) -> None:
        self.connection.executescript(_CONTROL_PLANE_SCHEMA_SQL)
        self.connection.execute(
            _REPOSITORY_POLICY_BOOTSTRAP_SQL,
            (iso(utc_now()),),
        )
        self.connection.commit()

    def get_repository_policy(self) -> dict[str, Any]:
        row = self.connection.execute(
            "SELECT * FROM repository_policy WHERE repository_id='default'"
        ).fetchone()
        if row is None:
            raise ControlPlaneError("TRUSTED_REPOSITORY_POLICY_MISSING")
        result = dict(row)
        result["allowed_protected_refs"] = json.loads(result.pop("allowed_protected_refs_json"))
        for key in (
            "automatic_merge_enabled", "platform_protection_required",
            "platform_protection_verified", "human_supervised_post_merge_allowed",
        ):
            result[key] = bool(result[key])
        canonical = result.get("canonical_protected_ref")
        if not isinstance(canonical, str) or not canonical.startswith("refs/heads/"):
            raise ControlPlaneError("TRUSTED_REPOSITORY_POLICY_INVALID")
        if canonical not in result["allowed_protected_refs"]:
            raise ControlPlaneError("TRUSTED_REPOSITORY_POLICY_INVALID")
        return result

    def configure_repository_policy(self, policy: dict[str, Any]) -> dict[str, Any]:
        if os.environ.get(TRUST_ENV) != "1":
            raise ControlPlaneError("TRUSTED_REPOSITORY_POLICY_WRITER_REQUIRED")
        canonical = policy.get("canonical_protected_ref")
        allowed = policy.get("allowed_protected_refs")
        if not isinstance(canonical, str) or not canonical.startswith("refs/heads/") \
                or not isinstance(allowed, list) or canonical not in allowed:
            raise ControlPlaneError("TRUSTED_REPOSITORY_POLICY_INVALID")
        if policy.get("platform_protection_verified") or policy.get("automatic_merge_enabled"):
            provider_id = policy.get("provider_attestation_id")
            if not isinstance(provider_id, str) or not provider_id:
                raise ControlPlaneError("PROVIDER_ATTESTATION_REQUIRED")
            provider = self.get_provider_attestation(provider_id)
            if provider.get("repository_id") != "default":
                raise ControlPlaneError("PROVIDER_ATTESTATION_REPOSITORY_MISMATCH")
            if provider.get("canonical_protected_ref") != canonical:
                raise ControlPlaneError("PROVIDER_ATTESTATION_BRANCH_MISMATCH")
            if parse_iso(provider["expires_at"]) <= utc_now():
                raise ControlPlaneError("PROVIDER_ATTESTATION_EXPIRED")
            if provider.get("live_connector_verified") is not True:
                raise ControlPlaneError("LIVE_PROVIDER_CONNECTOR_PROOF_REQUIRED")
            if not provider.get("repository_provider_id") or not provider.get("account_id"):
                raise ControlPlaneError("PROVIDER_BINDING_INCOMPLETE")
            controls = provider.get("controls", {})
            required_controls = (
                "protected_branch", "required_checks", "required_reviews", "force_push_disabled",
                "branch_deletion_disabled", "workflow_changes_protected",
            )
            if not all(controls.get(key) is True for key in required_controls):
                raise ControlPlaneError("PROVIDER_PROTECTION_CONTROLS_INCOMPLETE")
        timestamp = iso(utc_now())
        with self.transaction():
            self.connection.execute(
                """INSERT OR REPLACE INTO repository_policy(
                    repository_id,policy_version,canonical_protected_ref,allowed_protected_refs_json,
                    automatic_merge_enabled,platform_protection_required,platform_protection_verified,
                    human_supervised_post_merge_allowed,provider_attestation_id,configured_by,configured_at
                ) VALUES('default',?,?,?,?,?,?,?,?,?,?)""",
                (
                    str(policy.get("policy_version", "2.0.0")), canonical,
                    json.dumps(allowed, sort_keys=True), int(bool(policy.get("automatic_merge_enabled"))),
                    int(bool(policy.get("platform_protection_required", True))),
                    int(bool(policy.get("platform_protection_verified"))),
                    int(bool(policy.get("human_supervised_post_merge_allowed", True))),
                    policy.get("provider_attestation_id"), self._signer_identity(), timestamp,
                ),
            )
            self._event("TRUSTED_REPOSITORY_POLICY_CONFIGURED", None, None, {
                "canonical_protected_ref": canonical, "configured_by": self._signer_identity(),
            })
        return self.get_repository_policy()

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield self.connection
        except Exception:
            self.connection.execute("ROLLBACK")
            raise
        else:
            self.connection.execute("COMMIT")

    def _event(self, event_type: str, task_id: str | None, lease_id: str | None, payload: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO events(event_id,timestamp,event_type,task_id,lease_id,payload_json) VALUES(?,?,?,?,?,?)",
            (f"evt-{uuid.uuid4().hex}", iso(utc_now()), event_type, task_id, lease_id, json.dumps(payload, sort_keys=True)),
        )

    def _expire_due_locked(self, now: datetime) -> list[str]:
        rows = self.connection.execute("SELECT * FROM leases WHERE state='ACTIVE'").fetchall()
        expired: list[str] = []
        for row in rows:
            if parse_iso(row["expires_at"]) <= now:
                self.connection.execute("UPDATE leases SET state='EXPIRED' WHERE lease_id=? AND state='ACTIVE'", (row["lease_id"],))
                if self.connection.total_changes:
                    expired.append(row["lease_id"])
                    self._event("LEASE_EXPIRED", row["task_id"], row["lease_id"], {"fencing_token": row["fencing_token"]})
        return expired

    def acquire(
        self,
        *,
        task_id: str,
        agent_id: str,
        branch: str,
        base_sha: str,
        allowed_paths: list[str],
        ttl_seconds: int,
        access_mode: str = "write",
        now: datetime | None = None,
    ) -> dict[str, Any]:
        if ttl_seconds <= 0:
            raise ControlPlaneError("LEASE_TTL_INVALID")
        if access_mode not in {"read", "write"}:
            raise ControlPlaneError("LEASE_ACCESS_MODE_INVALID")
        scopes = sorted({_normalize_scope(path) for path in allowed_paths})
        if not scopes:
            raise ControlPlaneError("LEASE_SCOPE_EMPTY")
        now = now or utc_now()
        with self.transaction():
            self._expire_due_locked(now)
            active = self.connection.execute("SELECT * FROM leases WHERE state='ACTIVE'").fetchall()
            for row in active:
                other_paths = json.loads(row["allowed_paths_json"])
                conflict = classify_conflict(scopes, other_paths, left_access=access_mode, right_access=row["access_mode"])
                if conflict in BLOCKING_CONFLICTS:
                    raise ControlPlaneError(f"{conflict}:task={row['task_id']}:lease={row['lease_id']}")
            existing = self.connection.execute("SELECT last_token FROM task_tokens WHERE task_id=?", (task_id,)).fetchone()
            token = int(existing["last_token"]) + 1 if existing else 1
            self.connection.execute(
                "INSERT INTO task_tokens(task_id,last_token) VALUES(?,?) ON CONFLICT(task_id) DO UPDATE SET last_token=excluded.last_token",
                (task_id, token),
            )
            lease_id = f"lease-{task_id}-{token:04d}"
            expires = now + timedelta(seconds=ttl_seconds)
            self.connection.execute(
                """INSERT INTO leases(
                    lease_id,task_id,agent_id,branch,base_sha,fencing_token,issued_at,expires_at,
                    heartbeat_at,allowed_paths_json,access_mode,state
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,'ACTIVE')""",
                (lease_id, task_id, agent_id, branch, base_sha, token, iso(now), iso(expires), iso(now), json.dumps(scopes), access_mode),
            )
            self._event("LEASE_ACQUIRED", task_id, lease_id, {"fencing_token": token, "allowed_paths": scopes, "branch": branch})
        return self.get_lease(lease_id)

    def renew(self, lease_id: str, ttl_seconds: int, allowed_paths: list[str] | None = None, now: datetime | None = None) -> dict[str, Any]:
        now = now or utc_now()
        if ttl_seconds <= 0:
            raise ControlPlaneError("LEASE_TTL_INVALID")
        with self.transaction():
            row = self.connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            if row is None:
                raise ControlPlaneError("LEASE_NOT_FOUND")
            if row["state"] != "ACTIVE" or parse_iso(row["expires_at"]) <= now:
                self.connection.execute("UPDATE leases SET state='EXPIRED' WHERE lease_id=? AND state='ACTIVE'", (lease_id,))
                raise ControlPlaneError("LEASE_EXPIRED")
            current_paths = json.loads(row["allowed_paths_json"])
            if allowed_paths is not None and sorted({_normalize_scope(path) for path in allowed_paths}) != current_paths:
                raise ControlPlaneError("LEASE_RENEWAL_SCOPE_CHANGE_FORBIDDEN")
            expires = now + timedelta(seconds=ttl_seconds)
            self.connection.execute("UPDATE leases SET expires_at=?,heartbeat_at=? WHERE lease_id=?", (iso(expires), iso(now), lease_id))
            self._event("LEASE_RENEWED", row["task_id"], lease_id, {"expires_at": iso(expires)})
        return self.get_lease(lease_id)

    def heartbeat(self, lease_id: str, fencing_token: int, now: datetime | None = None) -> dict[str, Any]:
        now = now or utc_now()
        with self.transaction():
            row = self.connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            self._require_active(row, fencing_token, now)
            self.connection.execute("UPDATE leases SET heartbeat_at=? WHERE lease_id=?", (iso(now), lease_id))
            self._event("LEASE_HEARTBEAT", row["task_id"], lease_id, {"fencing_token": fencing_token})
        return self.get_lease(lease_id)

    def release(self, lease_id: str, fencing_token: int, state: str = "RELEASED", now: datetime | None = None) -> dict[str, Any]:
        if state not in {"RELEASED", "MERGED"}:
            raise ControlPlaneError("LEASE_RELEASE_STATE_INVALID")
        now = now or utc_now()
        with self.transaction():
            row = self.connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
            self._require_active(row, fencing_token, now)
            self.connection.execute("UPDATE leases SET state=? WHERE lease_id=?", (state, lease_id))
            self._event(f"LEASE_{state}", row["task_id"], lease_id, {"fencing_token": fencing_token})
        return self.get_lease(lease_id)

    def _require_active(self, row: sqlite3.Row | None, token: int, now: datetime) -> None:
        if row is None:
            raise ControlPlaneError("LEASE_NOT_FOUND")
        if int(row["fencing_token"]) != token:
            raise ControlPlaneError("FENCING_TOKEN_STALE")
        if row["state"] != "ACTIVE":
            raise ControlPlaneError(f"LEASE_NOT_ACTIVE:{row['state']}")
        if parse_iso(row["expires_at"]) <= now:
            self.connection.execute("UPDATE leases SET state='EXPIRED' WHERE lease_id=?", (row["lease_id"],))
            raise ControlPlaneError("LEASE_EXPIRED")

    def verify_active(self, task_id: str, fencing_token: int, branch: str | None = None, base_sha: str | None = None, now: datetime | None = None) -> dict[str, Any]:
        now = now or utc_now()
        row = self.connection.execute("SELECT * FROM leases WHERE task_id=? AND state='ACTIVE'", (task_id,)).fetchone()
        self._require_active(row, fencing_token, now)
        if branch is not None and row["branch"] != branch:
            raise ControlPlaneError("LEASE_BRANCH_MISMATCH")
        if base_sha is not None and row["base_sha"] != base_sha:
            raise ControlPlaneError("LEASE_BASE_SHA_STALE")
        return self._row_to_lease(row)

    def expire_due(self, now: datetime | None = None) -> list[str]:
        now = now or utc_now()
        with self.transaction():
            return self._expire_due_locked(now)

    def get_lease(self, lease_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM leases WHERE lease_id=?", (lease_id,)).fetchone()
        if row is None:
            raise ControlPlaneError("LEASE_NOT_FOUND")
        return self._row_to_lease(row)

    def active_leases(self) -> list[dict[str, Any]]:
        return [self._row_to_lease(row) for row in self.connection.execute("SELECT * FROM leases WHERE state='ACTIVE' ORDER BY task_id")]

    def _row_to_lease(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "lease_id": row["lease_id"], "task_id": row["task_id"], "agent_id": row["agent_id"],
            "branch": row["branch"], "base_sha": row["base_sha"], "fencing_token": row["fencing_token"],
            "issued_at": row["issued_at"], "expires_at": row["expires_at"], "heartbeat_at": row["heartbeat_at"],
            "allowed_paths": json.loads(row["allowed_paths_json"]), "access_mode": row["access_mode"], "state": row["state"],
        }


    @staticmethod
    def events(self) -> list[dict[str, Any]]:
        return [dict(row) for row in self.connection.execute("SELECT * FROM events ORDER BY timestamp,event_id")]


# ======================================================================
# 3. CLI
# ======================================================================


def require_trusted_writer() -> None:
    if os.environ.get(TRUST_ENV) != "1":
        raise ControlPlaneError("ORCHESTRATOR_TRUSTED_WRITER_REQUIRED")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("init")
    acquire = sub.add_parser("acquire")
    acquire.add_argument("--task-id", required=True); acquire.add_argument("--agent-id", required=True)
    acquire.add_argument("--branch", required=True); acquire.add_argument("--base-sha", required=True)
    acquire.add_argument("--allowed-path", action="append", required=True); acquire.add_argument("--ttl-seconds", type=int, default=3600)
    acquire.add_argument("--access-mode", choices=["read", "write"], default="write")
    renew = sub.add_parser("renew"); renew.add_argument("--lease-id", required=True); renew.add_argument("--ttl-seconds", type=int, default=3600)
    heartbeat = sub.add_parser("heartbeat"); heartbeat.add_argument("--lease-id", required=True); heartbeat.add_argument("--fencing-token", type=int, required=True)
    release = sub.add_parser("release"); release.add_argument("--lease-id", required=True); release.add_argument("--fencing-token", type=int, required=True); release.add_argument("--state", choices=["RELEASED", "MERGED"], default="RELEASED")
    sub.add_parser("list"); sub.add_parser("expire"); sub.add_parser("events")
    verify = sub.add_parser("verify"); verify.add_argument("--task-id", required=True); verify.add_argument("--fencing-token", type=int, required=True); verify.add_argument("--branch"); verify.add_argument("--base-sha")
    queue = sub.add_parser("enqueue-merge"); queue.add_argument("--task-id", required=True); queue.add_argument("--head-sha", required=True); queue.add_argument("--attestation-sha256", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    db = OrchestratorDB(args.db)
    try:
        if args.command in {"acquire", "renew", "heartbeat", "release", "expire", "enqueue-merge"}:
            require_trusted_writer()
        if args.command == "init": result: Any = {"status": "INITIALIZED", "db": args.db}
        elif args.command == "acquire": result = db.acquire(task_id=args.task_id, agent_id=args.agent_id, branch=args.branch, base_sha=args.base_sha, allowed_paths=args.allowed_path, ttl_seconds=args.ttl_seconds, access_mode=args.access_mode)
        elif args.command == "renew": result = db.renew(args.lease_id, args.ttl_seconds)
        elif args.command == "heartbeat": result = db.heartbeat(args.lease_id, args.fencing_token)
        elif args.command == "release": result = db.release(args.lease_id, args.fencing_token, args.state)
        elif args.command == "list": result = {"leases": db.active_leases()}
        elif args.command == "expire": result = {"expired": db.expire_due()}
        elif args.command == "events": result = {"events": db.events()}
        elif args.command == "verify": result = db.verify_active(args.task_id, args.fencing_token, args.branch, args.base_sha)
        elif args.command == "enqueue-merge": result = db.enqueue_merge(args.task_id, args.head_sha, args.attestation_sha256)
        else: raise ControlPlaneError("UNKNOWN_COMMAND")
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    except (ControlPlaneError, sqlite3.Error, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
