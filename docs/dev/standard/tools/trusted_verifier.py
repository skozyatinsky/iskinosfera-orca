#!/usr/bin/env python3
# ======================================================================
# trusted_verifier.py — версия 1.0
# Trusted verifier: executes the validator graph and records assurance data.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import ControlPlaneError, OrchestratorDB, TRUST_ENV  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402
from verify_agent_result import build_attestation, resolve_commit  # noqa: E402

REQUEST_FIELDS = {
    "request_id",
    "candidate_identity_id",
    "repository_id",
    "task_id",
    "expected_candidate_sha",
}


def now_dt() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def load_request(path: Path) -> dict[str, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ControlPlaneError(f"VERIFICATION_REQUEST_INVALID:{exc}") from exc
    if not isinstance(data, dict):
        raise ControlPlaneError("VERIFICATION_REQUEST_INVALID:shape")
    extras = sorted(set(data) - REQUEST_FIELDS)
    missing = sorted(REQUEST_FIELDS - set(data))
    if extras:
        raise ControlPlaneError(f"CALLER_ATTESTATION_FIELDS_FORBIDDEN:{extras}")
    if missing:
        raise ControlPlaneError(f"VERIFICATION_REQUEST_INVALID:missing={missing}")
    for key in REQUEST_FIELDS:
        if not isinstance(data.get(key), str) or not data[key]:
            raise ControlPlaneError(f"VERIFICATION_REQUEST_INVALID:{key}")
    return data  # type: ignore[return-value]



# ======================================================================
# 2. CANONICAL TRUSTED RECORD CONSTRUCTION
# Caller-provided readiness/compliance fields are never copied.
# ======================================================================
def _build_attestation_inputs(body: dict[str, Any], findings: list[str]) -> dict[str, Any]:
    forbidden = {
        "readiness_status", "findings", "scope_compliance",
        "ownership_compliance", "module_boundary_compliance",
        "mandatory_check_evidence", "trusted_test_evidence_ids", "issuer",
    }
    inputs = {key: value for key, value in body.items() if key not in forbidden}
    validator_evidence = body.get("mandatory_check_evidence", [])
    inputs.update({
        "scope_compliance": not any("SCOPE_VIOLATION" in item for item in findings),
        "ownership_compliance": not any(
            "OWNERSHIP" in item or "OWNER_" in item for item in findings
        ),
        "module_boundary_compliance": not any(
            "MODULE" in item or "module-boundaries" in item.lower() for item in findings
        ),
        "validator_graph_digest": hashlib.sha256(
            json.dumps(validator_evidence, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest(),
    })
    return inputs


def _build_verification_record(
    request: dict[str, str],
    body: dict[str, Any],
    findings: list[str],
    stored_ids: dict[str, str],
    lease: dict[str, Any],
    policy: dict[str, Any],
    fencing_token: int,
    tool_identity: dict[str, Any],
) -> dict[str, Any]:
    timestamp = now_dt()
    inputs = _build_attestation_inputs(body, findings)
    return {
        "request_id": request["request_id"],
        "run_id": body["run_id"],
        "repository_id": request["repository_id"],
        "task_id": request["task_id"],
        "candidate_identity_id": request["candidate_identity_id"],
        "expected_candidate_sha": request["expected_candidate_sha"],
        "status": "VERIFIED" if not findings else "BLOCKED",
        "recorded_at": iso(timestamp),
        "expires_at": iso(timestamp + timedelta(minutes=30)),
        "lease_id": lease["lease_id"],
        "fencing_token": fencing_token,
        "lease_snapshot": {
            "lease_id": lease["lease_id"],
            "branch": lease["branch"],
            "base_sha": lease["base_sha"],
            "fencing_token": lease["fencing_token"],
            "expires_at": lease["expires_at"],
            "allowed_paths": lease["allowed_paths"],
        },
        "repository_policy_snapshot": {
            "policy_version": policy["policy_version"],
            "canonical_protected_ref": policy["canonical_protected_ref"],
            "provider_attestation_id": policy.get("provider_attestation_id"),
        },
        "attestation_inputs": inputs,
        "validator_evidence": body.get("mandatory_check_evidence", []),
        "validator_graph_digest": inputs["validator_graph_digest"],
        "trusted_test_evidence_ids": stored_ids,
        "findings": sorted(set(findings)),
        "tool_identity": tool_identity,
    }

def verify_request(
    request: dict[str, str],
    *,
    root: Path,
    db_path: str,
    base_ref: str,
    head_ref: str,
    fencing_token: int,
    claimed_result: Path,
) -> dict[str, Any]:
    if os.environ.get(TRUST_ENV) != "1":
        raise ControlPlaneError("TRUSTED_VERIFIER_CONTEXT_REQUIRED")
    root = root.resolve()
    tool_identity = verify_trusted_tools(
        [
            "tools/trusted_verifier.py",
            "tools/trusted_signer.py",
            "tools/trusted_tool_identity.py",
            "tools/trusted_execution.py",
            "tools/candidate_sandbox.py",
            "tools/merge_readiness_gate.py",
            "tools/orchestrator_control_plane.py",
            "tools/orchestrator_trust_store.py",
            "tools/orchestrator_assurance_store.py",
        ]
    )
    head_sha = resolve_commit(root, head_ref)
    if request["expected_candidate_sha"] != head_sha:
        raise ControlPlaneError("VERIFICATION_REQUEST_CANDIDATE_SHA_MISMATCH")
    expected_identity = f"candidate-{request['task_id']}-{head_sha[:12]}-{fencing_token}"
    if request["candidate_identity_id"] != expected_identity:
        raise ControlPlaneError("VERIFICATION_REQUEST_CANDIDATE_IDENTITY_MISMATCH")

    bundle, findings = build_attestation(
        root,
        request["task_id"],
        base_ref,
        head_ref,
        claimed_result,
        db_path,
        fencing_token,
        "trusted-verifier",
        request["request_id"],
    )
    body = bundle["attestation"]
    db = OrchestratorDB(db_path)
    try:
        db.validate_external_path(str(root))
        stored_ids: dict[str, str] = {}
        if not findings:
            for evidence in bundle["test_evidence"]:
                stored = db.store_test_evidence(evidence)
                stored_ids[stored["test_role"]] = stored["evidence_id"]
        required_roles = {"targeted_tests", "affected_tests", "full_regression"}
        if not findings and set(stored_ids) != required_roles:
            findings.append("TRUSTED_TEST_EVIDENCE_GRAPH_INCOMPLETE")
        lease = db.verify_active(
            request["task_id"],
            fencing_token,
            branch=body.get("leased_branch"),
            base_sha=body.get("base_commit_sha"),
        )
        policy = db.get_repository_policy()
        record = _build_verification_record(
            request, body, findings, stored_ids, lease, policy, fencing_token, tool_identity
        )
        return db.store_verification_record(record)
    finally:
        db.close()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", required=True)
    parser.add_argument("--fencing-token", type=int, required=True)
    parser.add_argument("--claimed-result", required=True)
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        result = verify_request(
            load_request(Path(args.request)),
            root=Path(args.root),
            db_path=args.orchestrator_db,
            base_ref=args.base_ref,
            head_ref=args.head_ref,
            fencing_token=args.fencing_token,
            claimed_result=Path(args.claimed_result),
        )
    except (ControlPlaneError, TrustedToolIdentityError, OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if result.get("status") == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
