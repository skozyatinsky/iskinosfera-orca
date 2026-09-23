#!/usr/bin/env python3
# ======================================================================
# architect_readiness_profiles.py — версия 1.0
# Canonical run, skills, license quarantine and path classification.
# ======================================================================
from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any

from architect_readiness_common import (
    ALLOWED_LICENSE_STATUSES,
    CANONICAL_COMMAND,
    VALID_CLASSIFICATIONS,
    _configured_path,
    _finding,
    _load_json,
    _relative_path,
    _sha256,
)
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule
# 2. APS-ARCH-RUN-001 — ПРОФИЛЬ И КАНОНИЧЕСКАЯ КОМАНДА
# ======================================================================

@enforces_rule("APS-ARCH-RUN-001")
@emits_diagnostic("APS-ARCH-RUN-001", "ARCHITECTOR_CANONICAL_COMMAND_VALID")
@emits_diagnostic("APS-ARCH-RUN-001", "ARCHITECTOR_CANONICAL_COMMAND_MISSING")
@emits_diagnostic("APS-ARCH-RUN-001", "ARCHITECTOR_CANONICAL_COMMAND_DRIFT")
@emits_diagnostic("APS-ARCH-RUN-001", "ARCHITECTOR_CANONICAL_COMMAND_FAILED")
@emits_diagnostic("APS-ARCH-RUN-001", "ARCHITECTOR_CANONICAL_COMMAND_NOT_PORTABLE")
def validate_canonical_command(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    command = profile.get("canonical_command")
    findings: list[RuleFinding] = []
    if command != CANONICAL_COMMAND:
        findings.append(_finding(
            "ARCHITECTOR_CANONICAL_COMMAND_DRIFT",
            "APS-ARCH-RUN-001",
            "Profile command differs from the stable architect_library command",
            expected=CANONICAL_COMMAND,
            actual=command,
        ))
        return findings
    try:
        argv = shlex.split(command, posix=True)
    except ValueError as exc:
        return [_finding(
            "ARCHITECTOR_CANONICAL_COMMAND_NOT_PORTABLE",
            "APS-ARCH-RUN-001",
            "Canonical command cannot be parsed portably",
            error=str(exc),
        )]
    if (
        not argv
        or argv[0] not in {"python3", "python"}
        or any(Path(token).is_absolute() for token in argv[1:] if token and not token.startswith("-"))
        or "--root" not in argv
        or argv[argv.index("--root") + 1] != "."
        or "--profile" not in argv
        or argv[argv.index("--profile") + 1] != "architect_library"
        or "--warnings-as-errors" not in argv
    ):
        return [_finding(
            "ARCHITECTOR_CANONICAL_COMMAND_NOT_PORTABLE",
            "APS-ARCH-RUN-001",
            "Canonical command contains a non-portable or incomplete invocation",
            command=command,
        )]
    script = root / argv[1]
    if len(argv) < 2 or not script.is_file():
        return [_finding(
            "ARCHITECTOR_CANONICAL_COMMAND_MISSING",
            "APS-ARCH-RUN-001",
            "Documented command points to a missing entrypoint",
            script=argv[1] if len(argv) > 1 else None,
        )]
    doc_paths = profile.get("canonical_command_documents", [])
    if not isinstance(doc_paths, list) or sorted(doc_paths) != sorted([
        "README.md", "docs/PROJECT_SNAPSHOT.md", "structure.txt"
    ]):
        findings.append(_finding(
            "ARCHITECTOR_CANONICAL_COMMAND_DRIFT",
            "APS-ARCH-RUN-001",
            "Canonical command document set is incomplete",
            documents=doc_paths,
        ))
        return findings
    observed: dict[str, int] = {}
    for raw in doc_paths:
        rel = _relative_path(raw)
        if rel is None or not (root / rel).is_file():
            findings.append(_finding(
                "ARCHITECTOR_CANONICAL_COMMAND_MISSING",
                "APS-ARCH-RUN-001",
                "Canonical command document is missing",
                path=raw,
            ))
            continue
        text = (root / rel).read_text(encoding="utf-8", errors="strict")
        observed[raw] = text.count(command)
        if observed[raw] != 1:
            findings.append(_finding(
                "ARCHITECTOR_CANONICAL_COMMAND_DRIFT",
                "APS-ARCH-RUN-001",
                "Canonical command must occur exactly once in each required document",
                path=raw,
                occurrences=observed[raw],
            ))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_CANONICAL_COMMAND_VALID",
            "APS-ARCH-RUN-001",
            "Canonical command is present, synchronized and portable",
            severity="INFO",
            command=command,
        ))
    return findings


# ======================================================================
# 3. APS-ARCH-SKILL-001 — SKILLS MANIFEST И ROOT EXPOSURE
# ======================================================================


def _skill_entries(root: Path, profile: dict[str, Any]) -> tuple[list[dict[str, Any]], list[RuleFinding]]:
    path, problems = _configured_path(root, profile, "skills_manifest")
    if problems or path is None:
        return [], problems
    if not path.is_file():
        return [], [_finding(
            "ARCHITECTOR_SKILL_MANIFEST_DRIFT",
            "APS-ARCH-SKILL-001",
            "Skills manifest is missing",
            path=str(path.relative_to(root)),
        )]
    try:
        data = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [_finding(
            "ARCHITECTOR_SKILL_MANIFEST_DRIFT",
            "APS-ARCH-SKILL-001",
            "Skills manifest is invalid JSON",
            error=str(exc),
        )]
    entries = data.get("skills") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return [], [_finding(
            "ARCHITECTOR_SKILL_MANIFEST_DRIFT",
            "APS-ARCH-SKILL-001",
            "Skills manifest must contain a skills array",
        )]
    return [item for item in entries if isinstance(item, dict)], []


def _managed_exposure_matches(root: Path, canonical: Path, exposure: Path) -> bool:
    """Выставление скила — ссылка на канонический источник либо управляемая копия.

    Ссылка засчитывается и тогда, когда симлинком объявлен КАТАЛОГ выше по
    пути, а не сам файл. Прежняя проверка смотрела только на
    `exposure.is_symlink()`, поэтому раскладка `.claude/skills ->
    ../_architect/.claude/skills` — та самая, что описана в README, — читалась
    как неуправляемая копия. Пока устанавливаемых скилов в каноническом дереве
    не было, это молчало.

    Копия по-прежнему обязана предъявить metadata и совпадение хешей:
    у настоящей копии путь разрешается в другое место, и до сравнения хешей
    дело доходит только через неё.
    """
    try:
        if exposure.exists() and exposure.resolve(strict=True) == canonical.resolve(strict=True):
            return True
    except OSError:
        return False
    metadata = exposure.parent / ".aps-managed-copy.json"
    if not exposure.is_file() or not metadata.is_file():
        return False
    try:
        data = _load_json(metadata)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return False
    canonical_rel = canonical.relative_to(root).as_posix()
    return (
        data.get("canonical_path") == canonical_rel
        and data.get("sha256") == _sha256(canonical)
        and _sha256(exposure) == _sha256(canonical)
    )


@enforces_rule("APS-ARCH-SKILL-001")
@emits_diagnostic("APS-ARCH-SKILL-001", "ARCHITECTOR_SKILLS_VALID")
@emits_diagnostic("APS-ARCH-SKILL-001", "ARCHITECTOR_SKILL_SOURCE_DUPLICATED")
@emits_diagnostic("APS-ARCH-SKILL-001", "ARCHITECTOR_SKILL_TARGET_MISSING")
@emits_diagnostic("APS-ARCH-SKILL-001", "ARCHITECTOR_SKILL_LINK_NOT_PORTABLE")
@emits_diagnostic("APS-ARCH-SKILL-001", "ARCHITECTOR_SKILL_MANIFEST_DRIFT")
def validate_skills(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    entries, findings = _skill_entries(root, profile)
    if findings:
        return findings
    expected_count = profile.get("expected_skill_count")
    if not isinstance(expected_count, int) or len(entries) != expected_count:
        findings.append(_finding(
            "ARCHITECTOR_SKILL_MANIFEST_DRIFT",
            "APS-ARCH-SKILL-001",
            "Declared and manifest skill counts differ",
            expected=expected_count,
            actual=len(entries),
        ))
    ids: set[str] = set()
    canonical_paths: set[str] = set()
    exposure_paths: set[str] = set()
    for entry in entries:
        skill_id = entry.get("skill_id")
        canonical_rel = _relative_path(entry.get("canonical_path"))
        exposure_rel = _relative_path(entry.get("root_exposure_path"))
        if not isinstance(skill_id, str) or not skill_id or skill_id in ids:
            findings.append(_finding(
                "ARCHITECTOR_SKILL_MANIFEST_DRIFT",
                "APS-ARCH-SKILL-001",
                "Skill ID is empty or duplicated",
                skill_id=skill_id,
            ))
            continue
        ids.add(skill_id)
        if canonical_rel is None or exposure_rel is None:
            findings.append(_finding(
                "ARCHITECTOR_SKILL_LINK_NOT_PORTABLE",
                "APS-ARCH-SKILL-001",
                "Skill paths must be repository-relative and cannot escape root",
                skill_id=skill_id,
            ))
            continue
        canonical_key = canonical_rel.as_posix()
        exposure_key = exposure_rel.as_posix()
        if canonical_key in canonical_paths or exposure_key in exposure_paths:
            findings.append(_finding(
                "ARCHITECTOR_SKILL_SOURCE_DUPLICATED",
                "APS-ARCH-SKILL-001",
                "Two skills share a canonical or root exposure path",
                skill_id=skill_id,
                canonical_path=canonical_key,
                root_exposure_path=exposure_key,
            ))
        canonical_paths.add(canonical_key)
        exposure_paths.add(exposure_key)
        canonical = root / canonical_rel
        exposure = root / exposure_rel
        if not canonical.is_file():
            findings.append(_finding(
                "ARCHITECTOR_SKILL_TARGET_MISSING",
                "APS-ARCH-SKILL-001",
                "Canonical SKILL.md is missing",
                skill_id=skill_id,
                path=canonical_key,
            ))
            continue
        actual_hash = _sha256(canonical)
        if entry.get("sha256") != actual_hash:
            findings.append(_finding(
                "ARCHITECTOR_SKILL_MANIFEST_DRIFT",
                "APS-ARCH-SKILL-001",
                "Canonical skill hash differs from manifest",
                skill_id=skill_id,
                expected=entry.get("sha256"),
                actual=actual_hash,
            ))
        if entry.get("installable") is True and not _managed_exposure_matches(root, canonical, exposure):
            code = "ARCHITECTOR_SKILL_SOURCE_DUPLICATED" if exposure.exists() else "ARCHITECTOR_SKILL_TARGET_MISSING"
            findings.append(_finding(
                code,
                "APS-ARCH-SKILL-001",
                "Root skill exposure is missing or is an unmanaged divergent copy",
                skill_id=skill_id,
                canonical_path=canonical_key,
                root_exposure_path=exposure_key,
            ))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_SKILLS_VALID",
            "APS-ARCH-SKILL-001",
            "Skills have one canonical source and managed root exposure",
            severity="INFO",
            count=len(entries),
        ))
    return findings


# ======================================================================
# 4. APS-ARCH-LICENSE-001 — QUARANTINE
# ======================================================================

@enforces_rule("APS-ARCH-LICENSE-001")
@emits_diagnostic("APS-ARCH-LICENSE-001", "ARCHITECTOR_SKILL_QUARANTINE_VALID")
@emits_diagnostic("APS-ARCH-LICENSE-001", "ARCHITECTOR_SKILL_LICENSE_UNKNOWN")
@emits_diagnostic("APS-ARCH-LICENSE-001", "ARCHITECTOR_SKILL_QUARANTINED")
def validate_skill_licenses(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    entries, findings = _skill_entries(root, profile)
    if findings:
        return findings
    ledger_path, ledger_problems = _configured_path(root, profile, "license_ledger")
    if ledger_problems or ledger_path is None or not ledger_path.is_file():
        return [*ledger_problems, _finding(
            "ARCHITECTOR_SKILL_LICENSE_UNKNOWN",
            "APS-ARCH-LICENSE-001",
            "Machine-readable skill license ledger is missing",
        )]
    try:
        ledger_data = _load_json(ledger_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [_finding(
            "ARCHITECTOR_SKILL_LICENSE_UNKNOWN",
            "APS-ARCH-LICENSE-001",
            "Machine-readable skill license ledger is invalid",
            error=str(exc),
        )]
    ledger_entries = ledger_data.get("skills", []) if isinstance(ledger_data, dict) else []
    if not isinstance(ledger_entries, list):
        ledger_entries = []
    ledger_by_id = {item.get("skill_id"): item for item in ledger_entries if isinstance(item, dict)}
    quarantined_ids = set(profile.get("quarantined_skill_ids", []))
    by_id = {item.get("skill_id"): item for item in entries}
    for skill_id in sorted(quarantined_ids):
        entry = by_id.get(skill_id)
        ledger_entry = ledger_by_id.get(skill_id)
        if not isinstance(entry, dict) or not isinstance(ledger_entry, dict):
            findings.append(_finding(
                "ARCHITECTOR_SKILL_LICENSE_UNKNOWN",
                "APS-ARCH-LICENSE-001",
                "Quarantined skill is missing from the manifest or license ledger",
                skill_id=skill_id,
            ))
            continue
        if (
            ledger_entry.get("license_status") != "QUARANTINED"
            or ledger_entry.get("installable") is not False
            or ledger_entry.get("client_distribution_allowed") is not False
            or not str(ledger_entry.get("source", "")).strip()
        ):
            findings.append(_finding(
                "ARCHITECTOR_SKILL_LICENSE_UNKNOWN",
                "APS-ARCH-LICENSE-001",
                "License ledger does not preserve the quarantine boundary",
                skill_id=skill_id,
            ))
        exposure = _relative_path(entry.get("root_exposure_path"))
        if (
            entry.get("license_status") != "QUARANTINED"
            or entry.get("installable") is not False
            or entry.get("client_distribution_allowed") is not False
            or (exposure is not None and (root / exposure).exists())
        ):
            findings.append(_finding(
                "ARCHITECTOR_SKILL_QUARANTINED",
                "APS-ARCH-LICENSE-001",
                "Quarantined skill is active, installable, distributable or exposed",
                skill_id=skill_id,
            ))
    for entry in entries:
        license_status = entry.get("license_status")
        if license_status not in ALLOWED_LICENSE_STATUSES | {"QUARANTINED"}:
            if entry.get("installable") is True or entry.get("client_distribution_allowed") is True:
                findings.append(_finding(
                    "ARCHITECTOR_SKILL_LICENSE_UNKNOWN",
                    "APS-ARCH-LICENSE-001",
                    "Unknown license cannot be installed or distributed",
                    skill_id=entry.get("skill_id"),
                    license_status=license_status,
                ))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_SKILL_QUARANTINE_VALID",
            "APS-ARCH-LICENSE-001",
            "Quarantined and unknown-license skills are excluded from activation",
            severity="INFO",
        ))
    return findings


# ======================================================================
# 5. APS-ARCH-STRUCT-001 — PROFILE-AWARE PATH CLASSIFICATION
# ======================================================================


def _path_classifications(root: Path, profile: dict[str, Any]) -> tuple[list[tuple[Path, str]], list[RuleFinding]]:
    path, problems = _configured_path(root, profile, "path_classification_manifest")
    if problems or path is None:
        return [], problems
    if not path.is_file():
        return [], [_finding(
            "ARCHITECTOR_PATH_CLASSIFICATION_MISSING",
            "APS-ARCH-STRUCT-001",
            "Path classification manifest is missing",
            path=str(path.relative_to(root)),
        )]
    try:
        data = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [_finding(
            "ARCHITECTOR_PATH_CLASSIFICATION_INVALID",
            "APS-ARCH-STRUCT-001",
            "Path classification manifest is invalid",
            error=str(exc),
        )]
    result: list[tuple[Path, str]] = []
    invalid: list[RuleFinding] = []
    entries = data.get("paths", []) if isinstance(data, dict) else []
    if not isinstance(entries, list):
        entries = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rel = _relative_path(entry.get("path"))
        classification = entry.get("classification")
        if rel is None or classification not in VALID_CLASSIFICATIONS:
            # Молчаливый пропуск оставлял оператора наедине со следствием:
            # запись отброшена, файлы снова «нерасклассифицированы», и ничто
            # не связывает одно с другим. Опечатка в значении перечисления
            # выглядела как отсутствие записи (v2.9.161).
            invalid.append(_finding(
                "ARCHITECTOR_PATH_CLASSIFICATION_INVALID",
                "APS-ARCH-STRUCT-001",
                "Path classification entry is unusable and was ignored",
                path=entry.get("path"),
                classification=classification,
                allowed=sorted(VALID_CLASSIFICATIONS),
            ))
            continue
        result.append((rel, classification))
    result.sort(key=lambda item: len(item[0].parts), reverse=True)
    return result, invalid


def _classification_for(rel: Path, classifications: list[tuple[Path, str]]) -> str | None:
    for base, classification in classifications:
        if rel == base or base in rel.parents:
            return classification
    return None


@enforces_rule("APS-ARCH-STRUCT-001")
@emits_diagnostic("APS-ARCH-STRUCT-001", "ARCHITECTOR_STRUCTURE_CLASSIFICATION_VALID")
@emits_diagnostic("APS-ARCH-STRUCT-001", "ARCHITECTOR_REFERENCE_EXAMPLE_FALSE_POSITIVE")
@emits_diagnostic("APS-ARCH-STRUCT-001", "ARCHITECTOR_REAL_NESTED_AGENTS_HIDDEN")
@emits_diagnostic("APS-ARCH-STRUCT-001", "ARCHITECTOR_UNCLASSIFIED_NESTED_AGENTS")
@emits_diagnostic("APS-ARCH-STRUCT-001", "ARCHITECTOR_PATH_CLASSIFICATION_INVALID")
def validate_path_classification(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    classifications, findings = _path_classifications(root, profile)
    if findings:
        return findings
    required_reference = Path("_library/agent_configs/examples")
    if (required_reference, "reference_example") not in classifications:
        findings.append(_finding(
            "ARCHITECTOR_REFERENCE_EXAMPLE_FALSE_POSITIVE",
            "APS-ARCH-STRUCT-001",
            "Illustrative agent configs are not structurally classified as reference_example",
            path=required_reference.as_posix(),
        ))
    for agents_file in sorted(root.rglob("AGENTS.md")):
        rel = agents_file.relative_to(root)
        if rel == Path("AGENTS.md") or any(part in {".git", ".venv", "venv", "__pycache__"} for part in rel.parts):
            continue
        classification = _classification_for(rel.parent, classifications)
        if classification is None:
            findings.append(_finding(
                "ARCHITECTOR_UNCLASSIFIED_NESTED_AGENTS",
                "APS-ARCH-STRUCT-001",
                "Nested AGENTS.md is not classified",
                path=rel.as_posix(),
            ))
            continue
        if classification == "active_project":
            text = agents_file.read_text(encoding="utf-8", errors="ignore")
            if "AGENTS.md" not in text or "root" not in text.lower():
                findings.append(_finding(
                    "ARCHITECTOR_REAL_NESTED_AGENTS_HIDDEN",
                    "APS-ARCH-STRUCT-001",
                    "Active nested AGENTS.md does not preserve linkage to root instructions",
                    path=rel.as_posix(),
                ))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_STRUCTURE_CLASSIFICATION_VALID",
            "APS-ARCH-STRUCT-001",
            "Reference examples are excluded structurally while active nested configs remain checked",
            severity="INFO",
        ))
    return findings


# ======================================================================
