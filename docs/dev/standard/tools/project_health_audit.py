#!/usr/bin/env python3
# ======================================================================
# project_health_audit.py — версия 1.0
# Unified manual/scheduled health audit. The same mode/profile resolves to
# the same check graph; scheduled execution is never weaker than manual.
# ======================================================================

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from orchestrator_control_plane import OrchestratorDB  # noqa: E402
from rule_traceability_types import emits_diagnostic, enforces_rule  # noqa: E402


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def git(root: Path, *args: str) -> tuple[str | None, str | None]:
    try:
        proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout).strip()
    return proc.stdout.strip(), None


def finding(code: str, *, severity: str = "BLOCKING", message: str | None = None, **context: Any) -> dict[str, Any]:
    return {"finding_code": code, "severity": severity, "message": message or code, **context}


def run_command_check(check_id: str, command: list[str], root: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    started = datetime.now(timezone.utc)
    proc = subprocess.run(command, cwd=root, capture_output=True, text=True, env={**os.environ, "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"})
    output = (proc.stdout + "\n" + proc.stderr).strip()
    codes = []
    for line in output.splitlines():
        match = __import__("re").search(r"\b([A-Z][A-Z0-9_]{3,})\b", line)
        if match and ("_" in match.group(1) or match.group(1) in {"FAIL", "ERROR"}):
            codes.append(match.group(1))
    item = {
        "check_id": check_id,
        "validator_version": "2.9.134",
        "command": command,
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "exit_code": proc.returncode,
        "duration_seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 3),
        "finding_codes": sorted(set(codes)),
        "evidence_digest": hashlib.sha256(output.encode()).hexdigest(),
        "checked_entities": max(1, len(output.splitlines())),
    }
    findings = [finding(code or f"{check_id.upper()}_FAILED", message=output[-1000:]) for code in (item["finding_codes"] or ([f"{check_id.upper()}_FAILED"] if proc.returncode else []))]
    return item, findings


@enforces_rule("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "EXPECTED_DETACHED_CANDIDATE")
@emits_diagnostic("APS-RELEASE-PROJECT-HEALTH-ISOLATION-001", "ORPHAN_WORKTREE")
def git_hygiene(root: Path, protected_ref: str, candidate_context: str = "WORKSPACE") -> tuple[dict[str, Any], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    status, error = git(root, "status", "--porcelain")
    branch, _ = git(root, "branch", "--show-current")
    head, _ = git(root, "rev-parse", "HEAD")
    protected, protected_error = git(root, "rev-parse", protected_ref)
    if error:
        findings.append(finding("GIT_STATE_UNAVAILABLE", message=error))
    if status:
        findings.append(finding("MAIN_WORKTREE_DIRTY" if branch in {"main", "master"} else "WORKTREE_DIRTY", branch=branch))
    if branch in {"main", "master"} and head and protected and head != protected:
        findings.append(finding("DIRECT_WORK_ON_MAIN", branch=branch))
    worktrees, _ = git(root, "worktree", "list", "--porcelain")
    branches, _ = git(root, "for-each-ref", "--format=%(refname:short)|%(upstream:short)|%(objectname)", "refs/heads")
    repository_root_text, _ = git(root, "rev-parse", "--show-toplevel")
    repository_root = Path(repository_root_text).resolve() if repository_root_text else root
    if worktrees:
        blocks = worktrees.split("\n\n")
        for block in blocks:
            if "detached" not in block or "worktree " not in block:
                continue
            worktree_line = next((line for line in block.splitlines() if line.startswith("worktree ")), "")
            worktree_path = Path(worktree_line.removeprefix("worktree ")).resolve() if worktree_line else None
            if candidate_context == "EXPECTED_DETACHED_CANDIDATE" and worktree_path == repository_root:
                findings.append(finding(
                    "EXPECTED_DETACHED_CANDIDATE", severity="INFO",
                    message="Detached HEAD is the explicitly declared immutable release candidate.",
                    worktree=str(worktree_path),
                ))
            else:
                findings.append(finding("ORPHAN_WORKTREE", severity="HIGH", message=block.replace("\n", " ")))
    if branches:
        for line in branches.splitlines():
            name, upstream, commit = (line.split("|", 2) + ["", ""])[:3]
            if name not in {"main", "master", branch} and not upstream:
                findings.append(finding("ORPHAN_BRANCH", severity="HIGH", branch=name, commit=commit))
    check = {
        "check_id": "git-hygiene", "validator_version": "2.9.134", "command": ["internal", "git-hygiene"],
        "status": "PASS" if not any(item["severity"] in {"HIGH", "BLOCKING"} for item in findings) else "FAIL", "exit_code": 0 if not any(item["severity"] in {"HIGH", "BLOCKING"} for item in findings) else 1,
        "duration_seconds": 0.0, "finding_codes": sorted({item["finding_code"] for item in findings}),
        "evidence_digest": hashlib.sha256(json.dumps({"status": status, "branch": branch, "head": head, "protected": protected, "worktrees": worktrees, "branches": branches, "candidate_context": candidate_context}, sort_keys=True).encode()).hexdigest(),
        "checked_entities": len((branches or "").splitlines()) + len((worktrees or "").split("\n\n")),
    }
    if protected_error:
        findings.append(finding("PROTECTED_MAIN_NOT_RESOLVED", message=protected_error))
        check["status"] = "FAIL"; check["exit_code"] = 1
    return check, findings


def lease_audit(db_path: str | None, apply_safe_actions: bool) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    if not db_path:
        return ({"check_id": "leases", "validator_version": "2.9.134", "command": ["internal", "leases"], "status": "INCOMPLETE", "exit_code": 2, "duration_seconds": 0.0, "finding_codes": ["ORCHESTRATOR_UNAVAILABLE"], "evidence_digest": hashlib.sha256(b"missing").hexdigest(), "checked_entities": 0}, [finding("ORCHESTRATOR_UNAVAILABLE")], [])
    db = OrchestratorDB(db_path); actions: list[dict[str, Any]] = []
    try:
        expired = db.expire_due() if apply_safe_actions else []
        if expired: actions.append({"action": "CLOSE_EXPIRED_LEASES", "lease_ids": expired, "status": "APPLIED"})
        leases = db.active_leases(); findings: list[dict[str, Any]] = []
        for lease in leases:
            heartbeat = datetime.fromisoformat(lease["heartbeat_at"].replace("Z", "+00:00"))
            age = (datetime.now(timezone.utc) - heartbeat).total_seconds()
            if age > 7200: findings.append(finding("TASK_STALE", task_id=lease["task_id"], lease_id=lease["lease_id"]))
        digest = hashlib.sha256(json.dumps(leases, sort_keys=True).encode()).hexdigest()
        check={"check_id":"leases","validator_version":"2.9.134","command":["internal","leases"],"status":"PASS" if not findings else "FAIL","exit_code":0 if not findings else 1,"duration_seconds":0.0,"finding_codes":sorted({f["finding_code"] for f in findings}),"evidence_digest":digest,"checked_entities":len(leases)}
        return check, findings, actions
    finally: db.close()


def mode_commands(root: Path, profile: str, mode: str, base_ref: str | None, protected_ref: str) -> list[tuple[str, list[str]]]:
    validator = [sys.executable, "tools/validate_structure.py", "--root", "."]
    commands: list[tuple[str, list[str]]] = []
    if (root / "manifest.json").exists() and not (root / "docs" / "registry").exists():
        commands.append(("standard-static", validator + ["--profile", "standard-package", "--check-manifest", "--check-version-sync", "--check-release-hygiene", "--check-standard-capabilities", "--check-capability-evidence", "--check-ci-security", "--warnings-as-errors"]))
        return commands
    flags = ["--profile", "target-project", "--check-user-function-registry", "--check-function-registry", "--check-function-duplication", "--check-registry-task-linkage", "--check-function-lifecycle", "--check-change-journal", "--check-function-test-evidence", "--check-function-merge-status", "--check-control-plane-integrity", "--check-ci-security", "--warnings-as-errors", "--protected-ref", protected_ref]
    if base_ref: flags += ["--base-ref", base_ref]
    commands.append(("registries-and-governance", validator + flags))
    if mode in {"tests", "merge-readiness", "post-merge", "full"}:
        commands.append(("full-regression", [sys.executable, "tools/run_test_suite.py", "--", "-q"]))
    return commands


def parse_args() -> argparse.Namespace:
    p=argparse.ArgumentParser(); p.add_argument("--root",default="."); p.add_argument("--profile",default="human_supervised"); p.add_argument("--mode",choices=["quick","task","registries","leases","git","tests","merge-readiness","post-merge","full"],default="full"); p.add_argument("--audit-type",choices=["MANUAL","SCHEDULED"],default="MANUAL"); p.add_argument("--output",required=True); p.add_argument("--history-dir"); p.add_argument("--orchestrator-db"); p.add_argument("--base-ref"); p.add_argument("--protected-ref",default="HEAD"); p.add_argument("--apply-safe-actions",action="store_true"); p.add_argument("--task-id"); p.add_argument("--candidate-context", choices=["WORKSPACE", "EXPECTED_DETACHED_CANDIDATE"], default="WORKSPACE")
    return p.parse_args()


def main() -> int:
    a=parse_args(); root=Path(a.root).resolve(); started=now(); checks=[]; findings=[]; actions=[]
    head,_=git(root,"rev-parse","HEAD"); protected,_=git(root,"rev-parse",a.protected_ref)
    if a.mode in {"git","quick","full","merge-readiness","post-merge"}:
        check,items=git_hygiene(root,a.protected_ref,a.candidate_context); checks.append(check); findings.extend(items)
    if a.mode in {"leases","quick","task","full","merge-readiness","post-merge"} and a.profile in {"parallel_ai","autonomous_ai"}:
        check,items,acts=lease_audit(a.orchestrator_db,a.apply_safe_actions); checks.append(check); findings.extend(items); actions.extend(acts)
    if a.mode in {"registries","quick","task","tests","merge-readiness","post-merge","full"}:
        for cid,cmd in mode_commands(root,a.profile,a.mode,a.base_ref,a.protected_ref):
            check,items=run_command_check(cid,cmd,root); checks.append(check); findings.extend(items)
    if not checks: findings.append(finding("AUDIT_MANDATORY_CHECK_MISSING"))
    blocking=[item for item in findings if item.get("severity") in {"HIGH", "BLOCKING"}]
    status="PASS" if checks and not blocking and all(c["status"]=="PASS" for c in checks) else "FAIL"
    report={"audit_id":f"audit-{uuid.uuid4().hex}","audit_type":a.audit_type,"profile":a.profile,"mode":a.mode,"candidate_context":a.candidate_context,"root_commit":head,"protected_main_commit":protected,"started_at":started,"completed_at":now(),"status":status,"checks":checks,"findings":findings,"actions":actions,"evidence":{"source_commit":head,"report_sha256":"0"*64}}
    encoded=json.dumps({**report,"evidence":{**report["evidence"],"report_sha256":None}},sort_keys=True,separators=(",",":")).encode(); report["evidence"]["report_sha256"]=hashlib.sha256(encoded).hexdigest()
    out=Path(a.output); out.parent.mkdir(parents=True,exist_ok=True); out.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if a.history_dir:
        hist=Path(a.history_dir); (hist/"history").mkdir(parents=True,exist_ok=True); target=hist/"history"/f"{report['audit_id']}.json"; target.write_text(out.read_text(encoding="utf-8"),encoding="utf-8"); (hist/"latest.json").write_text(out.read_text(encoding="utf-8"),encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)); return 0 if status=="PASS" else 1
if __name__=="__main__": raise SystemExit(main())
