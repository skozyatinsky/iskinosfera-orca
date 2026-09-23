#!/usr/bin/env python3
# ======================================================================
# architect_readiness.py — версия 1.0
# Aggregate executable profile for the Architector standards library.
# ======================================================================
from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import asdict
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from architect_readiness_common import (  # noqa: E402
    ALLOWED_LICENSE_STATUSES,
    ArchitectReport,
    _diag_line,
    _finding,
    _load_json,
    _profile,
    _relative_path,
    _sha256,
)
from architect_readiness_governance import (  # noqa: E402
    _git,
    assess_tz03_adoption,
    validate_git_state,
    validate_index_and_session,
    validate_tz_registry,
    validate_v123_immutability,
)
from architect_readiness_profiles import (  # noqa: E402
    _skill_entries,
    validate_canonical_command,
    validate_path_classification,
    validate_skill_licenses,
    validate_skills,
)
from rule_traceability_types import RuleFinding  # noqa: E402
# 11. АГРЕГИРУЮЩИЙ GATE И INSTALLER
# ======================================================================


def validate_architect_library(root: Path) -> list[RuleFinding]:
    profile, findings = _profile(root)
    if profile is None:
        return findings
    findings.extend(validate_canonical_command(root, profile))
    findings.extend(validate_skills(root, profile))
    findings.extend(validate_skill_licenses(root, profile))
    findings.extend(validate_path_classification(root, profile))
    findings.extend(validate_tz_registry(root, profile))
    findings.extend(validate_index_and_session(root, profile))
    findings.extend(validate_git_state(root, profile))
    findings.extend(validate_v123_immutability(root, profile))
    findings.extend(assess_tz03_adoption(root, profile))
    return findings


def install_skills(root: Path, target: Path, *, force: bool = False) -> dict[str, Any]:
    profile, findings = _profile(root)
    if profile is None:
        return {"status": "FAIL", "installed": [], "skipped": [], "findings": [item.as_dict() for item in findings]}
    entries, findings = _skill_entries(root, profile)
    installed: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    target.mkdir(parents=True, exist_ok=True)
    for entry in entries:
        skill_id = str(entry.get("skill_id", ""))
        license_status = entry.get("license_status")
        if entry.get("installable") is not True or license_status not in ALLOWED_LICENSE_STATUSES:
            skipped.append({"skill_id": skill_id, "reason": "NOT_INSTALLABLE_OR_LICENSE_BLOCKED"})
            continue
        canonical_rel = _relative_path(entry.get("canonical_path"))
        if canonical_rel is None:
            findings.append(_finding("ARCHITECTOR_SKILL_LINK_NOT_PORTABLE", "APS-ARCH-SKILL-001", "Canonical skill path is non-portable", skill_id=skill_id))
            continue
        source = root / canonical_rel
        if not source.is_file() or _sha256(source) != entry.get("sha256"):
            findings.append(_finding("ARCHITECTOR_SKILL_MANIFEST_DRIFT", "APS-ARCH-SKILL-001", "Skill source is missing or hash-mismatched", skill_id=skill_id))
            continue
        destination_dir = target / skill_id
        destination = destination_dir / "SKILL.md"
        metadata = destination_dir / ".aps-managed-copy.json"
        if destination.exists() and not force:
            managed = False
            if metadata.is_file():
                try:
                    current = _load_json(metadata)
                    managed = current.get("sha256") == _sha256(destination)
                except (OSError, UnicodeError, json.JSONDecodeError):
                    managed = False
            if not managed:
                findings.append(_finding(
                    "ARCHITECTOR_SKILL_USER_MODIFICATION_PROTECTED",
                    "APS-ARCH-SKILL-001",
                    "Installer refused to overwrite an unmanaged or user-modified skill",
                    skill_id=skill_id,
                ))
                continue
        destination_dir.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
        metadata.write_text(json.dumps({
            "skill_id": skill_id,
            "canonical_path": canonical_rel.as_posix(),
            "sha256": _sha256(source),
            "managed_by": "agent_project_standard/architect_library",
        }, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        installed.append({"skill_id": skill_id, "path": destination.as_posix(), "sha256": _sha256(destination)})
    errors = [item for item in findings if item.severity == "ERROR"]
    return {
        "schema_version": 1,
        "status": "PASS" if not errors else "FAIL",
        "installed": installed,
        "skipped": skipped,
        "findings": [item.as_dict() for item in findings],
    }


def verify_git_archive(root: Path) -> dict[str, Any]:
    profile, findings = _profile(root)
    if profile is None:
        return {"status": "FAIL", "findings": [item.as_dict() for item in findings]}
    if _git(root, "rev-parse", "--is-inside-work-tree").returncode != 0:
        finding = _finding("ARCHITECTOR_GIT_REPOSITORY_REQUIRED", "APS-ARCH-GIT-001", "git archive verification requires a Git repository")
        return {"status": "FAIL", "findings": [finding.as_dict()]}
    with tempfile.TemporaryDirectory(prefix="aps-architect-archive-") as tmp:
        tmp_path = Path(tmp)
        archive = tmp_path / "head.tar"
        extracted = tmp_path / "tree"
        extracted.mkdir()
        proc = _git(root, "archive", "--format=tar", f"--output={archive}", "HEAD")
        if proc.returncode != 0:
            finding = _finding("ARCHITECTOR_CLEAN_ARCHIVE_FAILED", "APS-ARCH-GIT-001", "git archive HEAD failed", stderr=proc.stderr)
            return {"status": "FAIL", "findings": [finding.as_dict()]}
        with tarfile.open(archive, "r") as bundle:
            bundle.extractall(extracted, filter="data")
        cmd = shlex.split(str(profile.get("canonical_command")))
        run = subprocess.run(cmd, cwd=extracted, text=True, capture_output=True, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        status = "PASS" if run.returncode == 0 else "FAIL"
        return {
            "status": status,
            "exit_code": run.returncode,
            "command": cmd,
            "stdout": run.stdout,
            "stderr": run.stderr,
            "findings": [] if status == "PASS" else [_finding(
                "ARCHITECTOR_CANONICAL_COMMAND_FAILED",
                "APS-ARCH-RUN-001",
                "Canonical command failed in git archive HEAD",
                exit_code=run.returncode,
            ).as_dict()],
        }


def _report(findings: list[RuleFinding]) -> ArchitectReport:
    errors = [item for item in findings if item.severity == "ERROR"]
    return ArchitectReport(
        profile="architect_library",
        status="PASS" if not errors else "FAIL",
        findings=[item.as_dict() for item in findings],
        counts={
            "total": len(findings),
            "errors": len(errors),
            "info": len(findings) - len(errors),
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--report")
    parser.add_argument("--install-skills-to")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--verify-git-archive", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if args.install_skills_to:
        result = install_skills(root, Path(args.install_skills_to).resolve(), force=args.force)
        text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.report:
            Path(args.report).write_text(text, encoding="utf-8")
        print(text, end="")
        return 0 if result["status"] == "PASS" else 1
    if args.verify_git_archive:
        result = verify_git_archive(root)
        text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.report:
            Path(args.report).write_text(text, encoding="utf-8")
        print(text, end="")
        return 0 if result["status"] == "PASS" else 1
    findings = validate_architect_library(root)
    report = _report(findings)
    for finding in findings:
        print(_diag_line(finding))
    text = json.dumps(asdict(report), ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.report:
        Path(args.report).write_text(text, encoding="utf-8")
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
