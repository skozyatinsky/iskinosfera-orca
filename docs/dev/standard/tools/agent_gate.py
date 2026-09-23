#!/usr/bin/env python3
# ======================================================================
# agent_gate.py — версия 4.0
# Fail-closed candidate gate using trusted verifier records and canonical signer.
# ======================================================================
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

TRUSTED_GIT_EXECUTABLE = str(Path("/usr/bin/git").resolve()) if Path("/usr/bin/git").exists() else "git"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import (  # noqa: E402
    ATTESTATION_KEY_ENV,
    ATTESTATION_KEY_ID_ENV,
    REVOKED_KEY_IDS_ENV,
    SIGNER_IDENTITY_ENV,
    TRUST_ENV,
    ControlPlaneError,
    OrchestratorDB,
)
from trusted_execution import SAFE_ENV_KEYS  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402
from v128_validation import load_json  # noqa: E402
from verify_agent_result import find_task, resolve_commit  # noqa: E402

SIGNING_KEYS = (TRUST_ENV, ATTESTATION_KEY_ENV, ATTESTATION_KEY_ID_ENV, REVOKED_KEY_IDS_ENV, SIGNER_IDENTITY_ENV)
TRUSTED_RUNTIME_ENV = (
    "APS_TRUSTED_TOOL_MANIFEST_SHA256",
    "APS_TRUSTED_TOOL_MANIFEST_PUBLIC_KEYS_JSON",
    "APS_TRUSTED_TOOL_MANIFEST_REVOKED_KEY_IDS",
    "APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST",
    "APS_SANDBOX_CERTIFICATION_PATH",
    "APS_SANDBOX_CERTIFICATION_PUBLIC_KEYS_JSON",
    "APS_SANDBOX_CERTIFICATION_REVOKED_KEY_IDS",
    "APS_SANDBOX_EXECUTOR_IMAGE_DIGEST",
    "APS_SANDBOX_EXECUTOR_IDENTITY",
    "APS_SANDBOX_DEPLOYMENT_IDENTITY",
)


def load_profiles(root: Path) -> dict[str, Any]:
    data, error = load_json(root / "reference" / "release_profiles.json")
    if error or not isinstance(data, dict):
        raise RuntimeError(f"EXECUTION_PROFILES_INVALID:{error}")
    return data.get("profiles", {})


def git(root: Path, *args: str) -> str:
    proc = subprocess.run([TRUSTED_GIT_EXECUTABLE, *args], cwd=root, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(f"GIT_COMMAND_FAILED:{' '.join(args)}:{proc.stderr.strip()}")
    return proc.stdout.strip()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", required=True)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--base-ref", required=True)
    parser.add_argument("--head-ref", default="HEAD")
    parser.add_argument("--orchestrator-db", required=True)
    parser.add_argument("--fencing-token", type=int, required=True)
    parser.add_argument("--claimed-result", required=True)
    parser.add_argument("--request-id")
    parser.add_argument("--attestation-output")
    parser.add_argument("--output")
    return parser.parse_args()


@contextmanager
def _candidate_execution_context() -> Iterator[dict[str, str]]:
    captured: dict[str, str] = {}
    for key in SIGNING_KEYS:
        value = os.environ.pop(key, None)
        if value is not None:
            captured[key] = value
    try:
        yield captured
    finally:
        os.environ.update(captured)


def _trusted_process_env(captured: dict[str, str]) -> dict[str, str]:
    env = {key: value for key, value in os.environ.items() if key in SAFE_ENV_KEYS}
    env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    env.update(captured)
    for key in TRUSTED_RUNTIME_ENV:
        value = os.environ.get(key)
        if value is not None:
            env[key] = value
    env.pop("PYTHONPATH", None)
    return env


def _request(task_id: str, head_sha: str, fencing_token: int, request_id: str) -> dict[str, str]:
    return {
        "request_id": request_id,
        "candidate_identity_id": f"candidate-{task_id}-{head_sha[:12]}-{fencing_token}",
        "repository_id": "default",
        "task_id": task_id,
        "expected_candidate_sha": head_sha,
    }


def _run_trusted_tool(argv: list[str], env: dict[str, str]) -> tuple[int, str, str]:
    proc = subprocess.run(argv, capture_output=True, text=True, env=env)
    return proc.returncode, proc.stdout, proc.stderr


def _verify_and_sign(root: Path, args: argparse.Namespace, request: dict[str, str], captured: dict[str, str], *, verify: bool) -> tuple[dict[str, Any] | None, list[str]]:
    if TRUST_ENV not in captured or ATTESTATION_KEY_ENV not in captured:
        return None, ["TRUSTED_SIGNER_UNAVAILABLE"]
    env = _trusted_process_env(captured)
    env["APS_EXECUTION_PROFILE_ID"] = args.profile
    tool_dir = Path(__file__).resolve().parent
    with tempfile.TemporaryDirectory(prefix="aps_trusted_request_") as raw:
        temp = Path(raw)
        request_path = temp / "request.json"
        verifier_output = temp / "verification.json"
        signed_output = temp / "signed.json"
        request_path.write_text(json.dumps(request, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        if verify:
            rc, stdout, stderr = _run_trusted_tool([
                sys.executable, str(tool_dir / "trusted_verifier.py"),
                "--request", str(request_path), "--root", str(root),
                "--orchestrator-db", args.orchestrator_db,
                "--base-ref", args.base_ref, "--head-ref", args.head_ref,
                "--fencing-token", str(args.fencing_token),
                "--claimed-result", str(Path(args.claimed_result).resolve()),
                "--output", str(verifier_output),
            ], env)
            if rc != 0:
                # A BLOCKED verifier result is still a trusted, signed record.
                # Surface its machine-readable findings instead of hiding them
                # behind a generic subprocess failure wrapper.
                if verifier_output.exists():
                    try:
                        record = json.loads(verifier_output.read_text(encoding="utf-8"))
                    except (OSError, json.JSONDecodeError):
                        record = {}
                    record_findings = record.get("findings") if isinstance(record, dict) else None
                    if isinstance(record_findings, list) and record_findings:
                        return None, [str(item) for item in record_findings]
                detail = (stderr or stdout).strip()
                return None, [f"TRUSTED_VERIFIER_FAILED:{detail}"]
        rc, stdout, stderr = _run_trusted_tool([
            sys.executable, str(tool_dir / "trusted_signer.py"),
            "--request", str(request_path),
            "--orchestrator-db", args.orchestrator_db,
            "--repository-root", str(root),
            "--output", str(signed_output),
        ], env)
        if rc != 0 or not signed_output.exists():
            detail = (stderr or stdout).strip()
            return None, [f"TRUSTED_SIGNER_FAILED:{detail}"]
        return json.loads(signed_output.read_text(encoding="utf-8")), []


def _observed_steps(attestation: dict[str, Any], lease_ok: bool, profile_id: str) -> set[str]:
    observed = {"candidate_checkout", "task_graph", "effective_scope"}
    evidence = attestation.get("mandatory_check_evidence", [])
    if evidence and all(item.get("environment_policy") == "candidate-allowlist-v2" for item in evidence):
        observed.add("candidate_environment_isolation")
    if evidence and all(item.get("sandbox_conformance_passed") is True for item in evidence):
        observed.add("sandbox_attestation")
    if evidence and all(
        item.get("sandbox_production_certified") is True
        and item.get("sandbox_certification_profile_id") == profile_id
        for item in evidence
    ):
        observed.add("certified_sandbox")
    if evidence and all(not any("CANDIDATE_PROCESS_CLEANUP_FAILED" in finding for finding in item.get("findings", [])) for item in evidence):
        observed.add("process_cleanup")
    if attestation.get("approved_target_ref", "").startswith("refs/heads/"):
        observed.add("trusted_repository_policy")
    if lease_ok:
        observed.add("active_lease")
    for item in evidence:
        check_id = item.get("check_id")
        if isinstance(check_id, str) and item.get("status") == "PASS":
            observed.add(check_id.split(":", 1)[0] if check_id.startswith("required:") else check_id)
            if check_id.startswith("required:"):
                observed.add("required_checks")
    if attestation.get("scope_compliance"):
        observed.add("effective_scope")
    if attestation.get("ownership_compliance"):
        observed.add("code_ownership")
    if attestation.get("module_boundary_compliance"):
        observed.add("module_boundaries")
    if attestation.get("readiness_status") == "READY_TO_MERGE" and attestation.get("signature"):
        observed.update({"trusted_attestation", "merge_readiness", "signer_separation"})
    if attestation.get("trusted_tool_identity"):
        observed.add("trusted_executable_identity")
    trusted_ids = attestation.get("trusted_test_evidence_ids")
    if isinstance(trusted_ids, dict) and set(trusted_ids) == {"targeted_tests", "affected_tests", "full_regression"}:
        observed.add("trusted_test_evidence")
    return observed


def run_gate(args: argparse.Namespace) -> tuple[dict[str, Any], list[str]]:
    root = Path(args.root).resolve()
    findings: list[str] = []
    try:
        verify_trusted_tools(["tools/agent_gate.py", "tools/trusted_verifier.py", "tools/trusted_signer.py"])
    except TrustedToolIdentityError as exc:
        return {}, [str(exc)]
    profile = load_profiles(root).get(args.profile)
    if not isinstance(profile, dict):
        return {}, [f"EXECUTION_PROFILE_UNKNOWN:{args.profile}"]
    if profile.get("enabled") is False or profile.get("executable") is not True:
        return {}, [f"EXECUTION_PROFILE_DISABLED:{args.profile}"]
    if profile.get("entrypoint") != "tools/agent_gate.py" or profile.get("failure_mode") != "fail_closed":
        return {}, [f"EXECUTION_PROFILE_ENTRYPOINT_MISMATCH:{args.profile}"]

    task = find_task(root, args.task_id, args.base_ref)
    base_sha = resolve_commit(root, args.base_ref)
    head_sha = resolve_commit(root, args.head_ref)
    branch = git(root, "branch", "--show-current")
    expected_branch = task.get("branch") or f"agent/{args.task_id}"
    # The caller's current checkout is not authoritative. The verifier resolves
    # and checks the exact candidate SHA against the leased branch tip in the
    # trusted store, so a clean administrative checkout may remain on another
    # branch without changing what code is executed.
    if git(root, "status", "--porcelain"):
        findings.append("WORKTREE_DIRTY")

    lease_ok = False
    db = OrchestratorDB(args.orchestrator_db)
    try:
        db.validate_external_path(str(root))
        db.verify_active(args.task_id, args.fencing_token, branch=expected_branch, base_sha=base_sha)
        lease_ok = True
    except ControlPlaneError as exc:
        findings.append(str(exc))
    finally:
        db.close()

    request_id = getattr(args, "request_id", None) or uuid.uuid4().hex
    request = _request(args.task_id, head_sha, args.fencing_token, request_id)
    db = OrchestratorDB(args.orchestrator_db)
    try:
        existing_record = db.connection.execute(
            "SELECT request_id FROM trusted_verification_records WHERE request_id=?", (request_id,)
        ).fetchone() is not None
    finally:
        db.close()

    signed: dict[str, Any] | None = None
    if not findings:
        with _candidate_execution_context() as captured:
            signed, trusted_findings = _verify_and_sign(root, args, request, captured, verify=not existing_record)
            findings.extend(trusted_findings)
    attestation = signed or {}
    observed = _observed_steps(attestation, lease_ok, args.profile)
    mandatory = list(profile.get("agent_mandatory_steps") or profile.get("mandatory_steps") or [])
    missing = sorted(set(mandatory) - observed)
    if missing:
        findings.append(f"PROFILE_MANDATORY_STEPS_MISSING:{missing}")
        if "certified_sandbox" in missing:
            certification_findings = sorted({
                str(item.get("sandbox_certification_finding"))
                for item in attestation.get("mandatory_check_evidence", [])
                if item.get("sandbox_certification_finding")
            })
            findings.extend(certification_findings or ["CERTIFIED_SANDBOX_REQUIRED"])
    if args.profile == "autonomous_ai":
        findings.append("AUTONOMOUS_AI_EXTERNAL_CONTROLS_NOT_CERTIFIED")
    findings = sorted(set(findings))

    if getattr(args, "attestation_output", None):
        output = Path(args.attestation_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(attestation, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result = {
        "profile": args.profile,
        "task_id": args.task_id,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "branch": branch,
        "request_id": request_id,
        "mandatory_steps": mandatory,
        "observed_steps": sorted(observed),
        "missing_steps": missing,
        "attestation_id": attestation.get("attestation_id"),
        "attestation": attestation,
        "status": "READY_TO_MERGE" if not findings and attestation.get("readiness_status") == "READY_TO_MERGE" else "BLOCKED",
        "findings": findings,
        "idempotent_replay": existing_record,
    }
    return result, findings


def main() -> int:
    args = parse_args()
    try:
        result, findings = run_gate(args)
    except (OSError, RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if args.output:
        Path(args.output).write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
