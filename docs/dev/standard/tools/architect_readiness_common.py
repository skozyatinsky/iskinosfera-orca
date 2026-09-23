#!/usr/bin/env python3
# ======================================================================
# architect_readiness.py — версия 1.0
# Исполняемый профиль Architector как библиотеки стандартов и мастерской
# AI-агентов. Все проверки работают без сети и возвращают diagnostics с ID.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_traceability_types import RuleFinding  # noqa: E402

CANONICAL_COMMAND = (
    "python3 tools/validate_structure.py --root . "
    "--profile architect_library --warnings-as-errors"
)
PROFILE_PATH = Path("docs/registry/architect_library_profile.json")
VALID_CLASSIFICATIONS = {
    "active_project",
    "reference_example",
    "fixture",
    "template",
    "archived_material",
    "external_project",
}
TZ_STATUSES = {
    "TODO",
    "IN_PROGRESS",
    "BLOCKED",
    "DONE",
    "ARCHIVED",
    "REFERENCE",
    "OTHER_PROJECT",
}
WORK_CLASSIFICATIONS = {
    "released",
    "open_tz",
    "reference_material",
    "audit_archive",
    "other_project",
}
ACTIVE_TZ_STATUSES = {"TODO", "IN_PROGRESS", "BLOCKED"}
ALLOWED_LICENSE_STATUSES = {"APPROVED", "KNOWN", "INTERNAL"}
HISTORICAL_MARKERS = {"DEPRECATED", "ARCHIVED", "HISTORICAL"}


# ======================================================================
# 1. ОБЩИЕ ТИПЫ И IO
# ======================================================================

@dataclass(frozen=True)
class ArchitectReport:
    profile: str
    status: str
    findings: list[dict[str, Any]]
    counts: dict[str, int]


def _finding(
    code: str,
    rule_id: str,
    message: str,
    *,
    severity: str = "ERROR",
    **evidence: Any,
) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative_path(value: Any) -> Path | None:
    if not isinstance(value, str) or not value.strip():
        return None
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return None
    return path


def _profile(root: Path) -> tuple[dict[str, Any] | None, list[RuleFinding]]:
    path = root / PROFILE_PATH
    if not path.is_file():
        return None, [_finding(
            "ARCHITECTOR_PROFILE_MISSING",
            "APS-ARCH-RUN-001",
            f"Profile is missing: {PROFILE_PATH.as_posix()}",
            path=PROFILE_PATH.as_posix(),
        )]
    try:
        data = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, [_finding(
            "ARCHITECTOR_PROFILE_INVALID",
            "APS-ARCH-RUN-001",
            "Profile JSON is invalid",
            path=PROFILE_PATH.as_posix(),
            error=str(exc),
        )]
    if not isinstance(data, dict) or data.get("profile_id") != "architect_library":
        return None, [_finding(
            "ARCHITECTOR_PROFILE_INVALID",
            "APS-ARCH-RUN-001",
            "profile_id must be architect_library",
            path=PROFILE_PATH.as_posix(),
        )]
    return data, []


def _configured_path(root: Path, profile: dict[str, Any], key: str) -> tuple[Path | None, list[RuleFinding]]:
    rel = _relative_path(profile.get(key))
    if rel is None:
        return None, [_finding(
            "ARCHITECTOR_PROFILE_PATH_INVALID",
            "APS-ARCH-RUN-001",
            f"Profile path is missing or non-portable: {key}",
            field=key,
        )]
    return root / rel, []


def _diag_line(finding: RuleFinding) -> str:
    return "APS_ARCH_DIAGNOSTIC:" + json.dumps(
        finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


# ======================================================================
