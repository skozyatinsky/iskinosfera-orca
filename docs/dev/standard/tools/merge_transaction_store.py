#!/usr/bin/env python3
# ======================================================================
# merge_transaction_store.py — версия 1.0
# Immutable transactional state store for controlled automatic merge.
# ======================================================================
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

TRUST_ENV = "APS_TRUSTED_MERGE_SERVICE"

STATES = (
    "CREATED", "VALIDATING", "READY_FOR_QUEUE", "QUEUED", "MERGE_REQUESTED",
    "MERGE_CONFIRMED", "POST_MERGE_VALIDATING", "COMPLETED", "BLOCKED",
    "EXPIRED", "CANCELLED", "RECOVERY_REQUIRED", "COMPENSATED",
)
TERMINAL_STATES = {"COMPLETED", "BLOCKED", "EXPIRED", "CANCELLED", "COMPENSATED"}
TRANSITIONS: dict[str, set[str]] = {
    "CREATED": {"VALIDATING", "BLOCKED", "EXPIRED", "CANCELLED"},
    "VALIDATING": {"READY_FOR_QUEUE", "BLOCKED", "EXPIRED", "CANCELLED"},
    "READY_FOR_QUEUE": {"QUEUED", "BLOCKED", "EXPIRED", "CANCELLED", "RECOVERY_REQUIRED"},
    "QUEUED": {"MERGE_REQUESTED", "BLOCKED", "EXPIRED", "CANCELLED", "RECOVERY_REQUIRED"},
    "MERGE_REQUESTED": {"MERGE_CONFIRMED", "RECOVERY_REQUIRED", "BLOCKED", "EXPIRED"},
    "MERGE_CONFIRMED": {"POST_MERGE_VALIDATING", "RECOVERY_REQUIRED", "BLOCKED"},
    "POST_MERGE_VALIDATING": {"COMPLETED", "RECOVERY_REQUIRED", "BLOCKED", "COMPENSATED"},
    "RECOVERY_REQUIRED": {"READY_FOR_QUEUE", "MERGE_CONFIRMED", "POST_MERGE_VALIDATING", "COMPLETED", "BLOCKED", "COMPENSATED"},
    "BLOCKED": set(), "EXPIRED": set(), "CANCELLED": set(), "COMPENSATED": set(), "COMPLETED": set(),
}


class MergeTransactionError(RuntimeError):
    """Fail-closed automatic-merge transaction error."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


class MergeTransactionStore:
    """External immutable state store with validated transitions and event order."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.connection = sqlite3.connect(path, isolation_level=None, timeout=30)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self._initialize()
        self._secure_files()

    def close(self) -> None:
        self.connection.close()

    def _secure_files(self) -> None:
        if self.path == ":memory:" or os.name == "nt":
            return
        for suffix in ("", "-wal", "-shm"):
            candidate = self.path + suffix
            if os.path.exists(candidate):
                os.chmod(candidate, 0o600)

    def validate_external_path(self, repository_root: str) -> None:
        if self.path == ":memory:":
            raise MergeTransactionError("AUTOMATIC_MERGE_EXTERNAL_STORE_REQUIRED")
        database = os.path.realpath(os.path.abspath(self.path))
        repository = os.path.realpath(os.path.abspath(repository_root))
        if os.path.commonpath([database, repository]) == repository:
            raise MergeTransactionError("AUTOMATIC_MERGE_STORE_INSIDE_REPOSITORY")
        if os.name != "nt" and os.stat(database).st_mode & 0o077:
            raise MergeTransactionError("AUTOMATIC_MERGE_STORE_PERMISSIONS_TOO_OPEN")

    def _initialize(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS merge_operations(
                operation_id TEXT PRIMARY KEY,
                merge_request_id TEXT NOT NULL UNIQUE,
                delivery_id TEXT NOT NULL UNIQUE,
                execution_id TEXT NOT NULL UNIQUE,
                request_nonce TEXT NOT NULL UNIQUE,
                repository_id TEXT NOT NULL,
                task_id TEXT NOT NULL,
                lease_id TEXT NOT NULL,
                fencing_token INTEGER NOT NULL,
                provider TEXT NOT NULL,
                provider_request_id TEXT,
                provider_pr_mr_id TEXT NOT NULL,
                target_ref TEXT NOT NULL,
                base_sha TEXT NOT NULL,
                candidate_sha TEXT NOT NULL,
                candidate_tree_sha TEXT NOT NULL,
                state TEXT NOT NULL,
                request_json TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                provider_response_json TEXT,
                provider_response_sha256 TEXT,
                merge_commit_sha TEXT,
                protected_branch_sha TEXT,
                post_merge_evidence_sha256 TEXT,
                task_state TEXT NOT NULL DEFAULT 'MERGE_PENDING',
                lease_closed INTEGER NOT NULL DEFAULT 0,
                finding_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS merge_events(
                event_id TEXT PRIMARY KEY,
                operation_id TEXT NOT NULL,
                sequence INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                state TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE(operation_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS merge_operations_candidate_idx
                ON merge_operations(repository_id, candidate_sha, target_ref);
            """
        )

    def _require_trusted(self) -> None:
        if os.environ.get(TRUST_ENV) != "1":
            raise MergeTransactionError("TRUSTED_MERGE_SERVICE_REQUIRED")

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

    def _event(self, connection: sqlite3.Connection, operation_id: str, event_type: str, state: str, payload: dict[str, Any]) -> None:
        row = connection.execute(
            "SELECT COALESCE(MAX(sequence),0)+1 AS next_sequence FROM merge_events WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        connection.execute(
            "INSERT INTO merge_events(event_id,operation_id,sequence,event_type,state,payload_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (str(uuid.uuid4()), operation_id, int(row["next_sequence"]), event_type, state,
             json.dumps(payload, ensure_ascii=False, sort_keys=True), utc_now()),
        )

    def create(self, request: dict[str, Any], *, delivery_id: str, execution_id: str) -> dict[str, Any]:
        self._require_trusted()
        existing = self.get_by_delivery(delivery_id, required=False)
        if existing is not None:
            if existing["request_sha256"] != hashlib.sha256(canonical_bytes(request)).hexdigest():
                raise MergeTransactionError("AUTOMATIC_MERGE_DELIVERY_COLLISION")
            return {**existing, "idempotent_replay": True}
        now = utc_now()
        operation_id = "merge-op-" + uuid.uuid4().hex
        digest = hashlib.sha256(canonical_bytes(request)).hexdigest()
        with self.transaction() as connection:
            nonce_replay = connection.execute(
                "SELECT operation_id FROM merge_operations WHERE request_nonce=?",
                (request["request_nonce"],),
            ).fetchone()
            if nonce_replay is not None:
                raise MergeTransactionError("AUTOMATIC_MERGE_NONCE_REPLAYED")
            duplicate = connection.execute(
                "SELECT operation_id,state FROM merge_operations WHERE repository_id=? AND candidate_sha=? AND target_ref=?",
                (request["repository_id"], request["candidate_commit_sha"], request["target_protected_ref"]),
            ).fetchone()
            if duplicate and duplicate["state"] not in {"BLOCKED", "EXPIRED", "CANCELLED", "COMPENSATED"}:
                raise MergeTransactionError("DUPLICATE_PROVIDER_MERGE_PREVENTED")
            connection.execute(
                """INSERT INTO merge_operations(
                    operation_id,merge_request_id,delivery_id,execution_id,request_nonce,repository_id,task_id,lease_id,
                    fencing_token,provider,provider_pr_mr_id,target_ref,base_sha,candidate_sha,candidate_tree_sha,
                    state,request_json,request_sha256,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (operation_id, request["merge_request_id"], delivery_id, execution_id, request["request_nonce"], request["repository_id"],
                 request["task_id"], request["lease_id"], int(request["fencing_token"]), request["provider"],
                 str(request["provider_pr_mr_id"]), request["target_protected_ref"], request["base_commit_sha"],
                 request["candidate_commit_sha"], request["candidate_tree_sha"], "CREATED",
                 json.dumps(request, ensure_ascii=False, sort_keys=True), digest, now, now),
            )
            self._event(connection, operation_id, "OPERATION_CREATED", "CREATED", {"delivery_id": delivery_id})
        return self.get(operation_id)

    def get(self, operation_id: str) -> dict[str, Any]:
        row = self.connection.execute("SELECT * FROM merge_operations WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise MergeTransactionError("AUTOMATIC_MERGE_OPERATION_NOT_FOUND")
        return dict(row)

    def get_by_delivery(self, delivery_id: str, *, required: bool = True) -> dict[str, Any] | None:
        row = self.connection.execute("SELECT * FROM merge_operations WHERE delivery_id=?", (delivery_id,)).fetchone()
        if row is None and required:
            raise MergeTransactionError("AUTOMATIC_MERGE_DELIVERY_NOT_FOUND")
        return dict(row) if row is not None else None

    def transition(self, operation_id: str, target: str, *, expected: set[str] | None = None,
                   event_type: str | None = None, updates: dict[str, Any] | None = None) -> dict[str, Any]:
        self._require_trusted()
        if target not in STATES:
            raise MergeTransactionError("AUTOMATIC_MERGE_STATE_INVALID")
        updates = dict(updates or {})
        allowed_columns = {
            "provider_request_id", "provider_response_json", "provider_response_sha256", "merge_commit_sha",
            "protected_branch_sha", "post_merge_evidence_sha256", "task_state", "lease_closed", "finding_code",
        }
        if set(updates) - allowed_columns:
            raise MergeTransactionError("AUTOMATIC_MERGE_UPDATE_FIELD_FORBIDDEN")
        with self.transaction() as connection:
            row = connection.execute("SELECT state FROM merge_operations WHERE operation_id=?", (operation_id,)).fetchone()
            if row is None:
                raise MergeTransactionError("AUTOMATIC_MERGE_OPERATION_NOT_FOUND")
            current = str(row["state"])
            if expected is not None and current not in expected:
                raise MergeTransactionError(f"AUTOMATIC_MERGE_STATE_CONFLICT:{current}")
            if target != current and target not in TRANSITIONS[current]:
                raise MergeTransactionError(f"AUTOMATIC_MERGE_TRANSITION_FORBIDDEN:{current}->{target}")
            assignments = ["state=?", "updated_at=?"]
            values: list[Any] = [target, utc_now()]
            for key, value in updates.items():
                assignments.append(f"{key}=?")
                values.append(value)
            values.append(operation_id)
            connection.execute(f"UPDATE merge_operations SET {','.join(assignments)} WHERE operation_id=?", values)
            self._event(connection, operation_id, event_type or f"STATE_{target}", target, updates)
        return self.get(operation_id)

    def record_task_done(self, operation_id: str, evidence_sha256: str) -> dict[str, Any]:
        return self.transition(
            operation_id, "POST_MERGE_VALIDATING", expected={"POST_MERGE_VALIDATING"},
            event_type="TASK_LIFECYCLE_DONE",
            updates={"task_state": "DONE", "post_merge_evidence_sha256": evidence_sha256},
        )

    def record_lease_closed(self, operation_id: str) -> dict[str, Any]:
        return self.transition(
            operation_id, "POST_MERGE_VALIDATING", expected={"POST_MERGE_VALIDATING"},
            event_type="LEASE_CLOSED_LAST", updates={"lease_closed": 1},
        )

    def events(self, operation_id: str) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM merge_events WHERE operation_id=? ORDER BY sequence", (operation_id,)
        ).fetchall()
        return [dict(row) for row in rows]
