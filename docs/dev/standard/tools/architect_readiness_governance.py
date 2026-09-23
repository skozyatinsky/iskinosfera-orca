#!/usr/bin/env python3
# ======================================================================
# architect_readiness_governance.py — версия 1.0
# TZ/evidence, index/session state, Git reproducibility, immutability and
# the honest TZ-03 adoption boundary.
# ======================================================================
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import hashlib
import zipfile
from pathlib import Path
from typing import Any, Iterable

from architect_readiness_common import (
    ACTIVE_TZ_STATUSES,
    HISTORICAL_MARKERS,
    TZ_STATUSES,
    WORK_CLASSIFICATIONS,
    _configured_path,
    _finding,
    _load_json,
    _relative_path,
    _sha256,
)
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule
# 6. APS-ARCH-TZ-001 — TZ REGISTRY, DONE EVIDENCE, TZ-02 И WORK MATERIALS
# ======================================================================


def _registry_array(root: Path, profile: dict[str, Any], key: str, field: str, rule_id: str, code: str) -> tuple[list[dict[str, Any]], list[RuleFinding]]:
    path, problems = _configured_path(root, profile, key)
    if problems or path is None:
        return [], problems
    if not path.is_file():
        return [], [_finding(code, rule_id, f"Registry is missing: {path.relative_to(root)}")]
    try:
        data = _load_json(path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [], [_finding(code, rule_id, "Registry JSON is invalid", error=str(exc))]
    values = data.get(field) if isinstance(data, dict) else None
    if not isinstance(values, list):
        return [], [_finding(code, rule_id, f"Registry field {field} must be an array")]
    return [item for item in values if isinstance(item, dict)], []


def _executable_tz_evidence(root: Path, item: dict[str, Any], tz_id: str) -> bool:
    node_id = item.get("test_node_id")
    command = item.get("command")
    if not isinstance(node_id, str) or "::" not in node_id or not isinstance(command, list):
        return False
    expected = ["python3", "-m", "pytest", "-q", node_id]
    alternate = ["python", "-m", "pytest", "-q", node_id]
    test_path = _relative_path(node_id.split("::", 1)[0])
    return (
        command in (expected, alternate)
        and test_path is not None
        and (root / test_path).is_file()
        and item.get("tz_id") == tz_id
        and item.get("verified_result") == "PASS"
        and item.get("expected_exit_code") == 0
    )


def _validate_tz02(root: Path, profile: dict[str, Any], evidence_by_id: dict[str, dict[str, Any]]) -> list[RuleFinding]:
    path, problems = _configured_path(root, profile, "tz02_contract")
    if problems or path is None:
        return problems
    if not path.is_file():
        return [_finding("TZ02_CONTRACT_MISSING", "APS-ARCH-TZ-001", "TZ-02 contract is missing")]
    data = _load_json(path)
    findings: list[RuleFinding] = []
    for raw in data.get("archive_paths", []):
        rel = _relative_path(raw)
        if rel is None or not (root / rel).exists():
            findings.append(_finding(
                "TZ02_ARCHIVE_FILE_MISSING",
                "APS-ARCH-TZ-001",
                "TZ-02 archive evidence path is missing",
                path=raw,
            ))
    for raw in data.get("forbidden_active_paths", []):
        rel = _relative_path(raw)
        if rel is None or (root / rel).exists():
            findings.append(_finding(
                "TZ02_OLD_SOURCE_STILL_ACTIVE",
                "APS-ARCH-TZ-001",
                "TZ-02 old source remains in active TZ directory",
                path=raw,
            ))
    evidence_id = data.get("evidence_id")
    evidence = evidence_by_id.get(evidence_id)
    if not evidence or not _executable_tz_evidence(root, evidence, "TZ-02"):
        findings.append(_finding(
            "TZ02_EVIDENCE_MISMATCH",
            "APS-ARCH-TZ-001",
            "TZ-02 evidence is missing, not PASS or linked to another TZ ID",
            evidence_id=evidence_id,
        ))
    return findings


@enforces_rule("APS-ARCH-TZ-001")
@emits_diagnostic("APS-ARCH-TZ-001", "ARCHITECTOR_TZ_REGISTRY_VALID")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ_DONE_WITHOUT_EVIDENCE")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ_REGISTRY_DOCUMENT_DRIFT")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ_WORK_MATERIAL_UNCLASSIFIED")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ02_ARCHIVE_FILE_MISSING")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ02_OLD_SOURCE_STILL_ACTIVE")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ02_EVIDENCE_MISMATCH")
def validate_tz_registry(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    tz_entries, findings = _registry_array(
        root, profile, "tz_registry", "technical_specs", "APS-ARCH-TZ-001", "TZ_REGISTRY_DOCUMENT_DRIFT"
    )
    evidence_entries, local = _registry_array(
        root, profile, "tz_evidence_registry", "evidence", "APS-ARCH-TZ-001", "TZ_DONE_WITHOUT_EVIDENCE"
    )
    findings.extend(local)
    work_entries, local = _registry_array(
        root, profile, "work_materials_registry", "materials", "APS-ARCH-TZ-001", "TZ_WORK_MATERIAL_UNCLASSIFIED"
    )
    findings.extend(local)
    if findings:
        return findings
    evidence_by_id = {item.get("evidence_id"): item for item in evidence_entries if item.get("evidence_id")}
    tz_by_path: dict[str, dict[str, Any]] = {}
    tz_ids: set[str] = set()
    for entry in tz_entries:
        tz_id = entry.get("tz_id")
        path_raw = entry.get("path")
        rel = _relative_path(path_raw)
        if not isinstance(tz_id, str) or not tz_id or tz_id in tz_ids or rel is None or entry.get("status") not in TZ_STATUSES:
            findings.append(_finding(
                "TZ_REGISTRY_DOCUMENT_DRIFT",
                "APS-ARCH-TZ-001",
                "TZ registry entry is invalid or duplicated",
                tz_id=tz_id,
                path=path_raw,
            ))
            continue
        tz_ids.add(tz_id)
        tz_by_path[rel.as_posix()] = entry
        if not (root / rel).is_file():
            findings.append(_finding(
                "TZ_REGISTRY_DOCUMENT_DRIFT",
                "APS-ARCH-TZ-001",
                "Registered TZ document is missing",
                tz_id=tz_id,
                path=rel.as_posix(),
            ))
        if entry.get("status") == "DONE":
            refs = entry.get("evidence_refs")
            linked = [evidence_by_id.get(ref) for ref in refs] if isinstance(refs, list) else []
            if not linked or any(
                not item or not _executable_tz_evidence(root, item, tz_id)
                for item in linked
            ):
                findings.append(_finding(
                    "TZ_DONE_WITHOUT_EVIDENCE",
                    "APS-ARCH-TZ-001",
                    "DONE TZ lacks exact executable PASS evidence",
                    tz_id=tz_id,
                ))
    active_dir = root / "docs/ТЗ"
    if active_dir.is_dir():
        for document in sorted(active_dir.glob("*.md")):
            if document.name == "README.md":
                # Индекс каталога не является техническим заданием
                # (APS-TZ-INDEX-EXEMPTION-001, v2.9.157). Исключение было
                # подключено только к --check-tz-governance; собственная
                # проверка профиля Архитектора о нём не знала и требовала
                # от навигационного индекса статуса в имени файла и записи
                # в реестре ТЗ — того, чего индекс дать не может по смыслу.
                continue
            rel = document.relative_to(root).as_posix()
            if rel not in tz_by_path:
                findings.append(_finding(
                    "TZ_REGISTRY_DOCUMENT_DRIFT",
                    "APS-ARCH-TZ-001",
                    "Active TZ document is absent from registry",
                    path=rel,
                ))
            if not re.search(r"__(?:TODO|IN_PROGRESS|BLOCKED|DONE|ARCHIVED|REFERENCE|OTHER_PROJECT)\.md$", document.name):
                findings.append(_finding(
                    "TZ_REGISTRY_DOCUMENT_DRIFT",
                    "APS-ARCH-TZ-001",
                    "Active TZ filename has no explicit status suffix",
                    path=rel,
                ))
    work_root = root / "docs/docs_standard_package/work"
    classified: set[str] = set()
    for entry in work_entries:
        rel = _relative_path(entry.get("path"))
        classification = entry.get("classification")
        if rel is None or classification not in WORK_CLASSIFICATIONS:
            findings.append(_finding(
                "TZ_WORK_MATERIAL_UNCLASSIFIED",
                "APS-ARCH-TZ-001",
                "Work material classification is invalid",
                path=entry.get("path"),
                classification=classification,
            ))
            continue
        classified.add(rel.as_posix())
    if work_root.is_dir():
        for path in sorted(work_root.rglob("*")):
            if path.is_file():
                rel = path.relative_to(root).as_posix()
                if not _covered_by_classification(rel, classified):
                    findings.append(_finding(
                        "TZ_WORK_MATERIAL_UNCLASSIFIED",
                        "APS-ARCH-TZ-001",
                        "Work material is absent from classification registry",
                        path=rel,
                    ))
    findings.extend(_validate_tz02(root, profile, evidence_by_id))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_TZ_REGISTRY_VALID",
            "APS-ARCH-TZ-001",
            "TZ registry, DONE evidence, TZ-02 and work classification are consistent",
            severity="INFO",
            technical_specs=len(tz_entries),
        ))
    return findings


# ======================================================================
# 7. APS-ARCH-INDEX-001 — INDEX И SESSION STATE
# ======================================================================


def _markdown_local_links(text: str) -> Iterable[tuple[str, int]]:
    pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
    for line_number, line in enumerate(text.splitlines(), 1):
        for match in pattern.finditer(line):
            yield match.group(1).strip(), line_number


def _session_metadata(text: str) -> dict[str, str]:
    match = re.search(r"<!--\s*aps-session-state\s*\n(.*?)\n\s*-->", text, re.DOTALL | re.IGNORECASE)
    if not match:
        return {}
    result: dict[str, str] = {}
    for raw in match.group(1).splitlines():
        if ":" in raw:
            key, value = raw.split(":", 1)
            result[key.strip()] = value.strip()
    return result


@enforces_rule("APS-ARCH-INDEX-001")
@emits_diagnostic("APS-ARCH-INDEX-001", "ARCHITECTOR_INDEX_SESSION_VALID")
@emits_diagnostic("APS-ARCH-INDEX-001", "ARCHITECTOR_INDEX_BROKEN_LINK")
@emits_diagnostic("APS-ARCH-INDEX-001", "ARCHITECTOR_INDEX_DEPRECATED_ENTRY_UNMARKED")
@emits_diagnostic("APS-ARCH-INDEX-001", "ARCHITECTOR_SESSION_STATE_STALE")
@emits_diagnostic("APS-ARCH-INDEX-001", "ARCHITECTOR_SESSION_STATE_REGISTRY_DRIFT")
def validate_index_and_session(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    index_path, local = _configured_path(root, profile, "library_index")
    findings.extend(local)
    session_path, local = _configured_path(root, profile, "session_state")
    findings.extend(local)
    if findings or index_path is None or session_path is None:
        return findings
    if not index_path.is_file():
        findings.append(_finding("ARCHITECTOR_INDEX_BROKEN_LINK", "APS-ARCH-INDEX-001", "Library index is missing"))
    else:
        text = index_path.read_text(encoding="utf-8", errors="strict")
        base = index_path.parent
        for target, line_number in _markdown_local_links(text):
            if target.startswith(("http://", "https://", "mailto:", "#")):
                continue
            clean = target.split("#", 1)[0]
            if not clean:
                continue
            candidate = (base / clean).resolve()
            try:
                candidate.relative_to(root.resolve())
            except ValueError:
                findings.append(_finding(
                    "ARCHITECTOR_INDEX_BROKEN_LINK",
                    "APS-ARCH-INDEX-001",
                    "Index link escapes repository root",
                    target=target,
                    line=line_number,
                ))
                continue
            if not candidate.exists():
                findings.append(_finding(
                    "ARCHITECTOR_INDEX_BROKEN_LINK",
                    "APS-ARCH-INDEX-001",
                    "Index contains a broken active local link",
                    target=target,
                    line=line_number,
                ))
        for line_number, line in enumerate(text.splitlines(), 1):
            if "architect_library_search" in line and not any(marker in line.upper() for marker in HISTORICAL_MARKERS):
                findings.append(_finding(
                    "ARCHITECTOR_INDEX_DEPRECATED_ENTRY_UNMARKED",
                    "APS-ARCH-INDEX-001",
                    "Deprecated architect_library_search reference is not marked",
                    line=line_number,
                ))
    if not session_path.is_file():
        findings.append(_finding("ARCHITECTOR_SESSION_STATE_STALE", "APS-ARCH-INDEX-001", "Session state is missing"))
    else:
        metadata = _session_metadata(session_path.read_text(encoding="utf-8", errors="strict"))
        try:
            updated = dt.date.fromisoformat(metadata.get("updated_at", ""))
            max_age = int(profile.get("session_state_max_age_days", 31))
            if (dt.date.today() - updated).days > max_age or updated > dt.date.today():
                raise ValueError("stale")
        except (ValueError, TypeError):
            findings.append(_finding(
                "ARCHITECTOR_SESSION_STATE_STALE",
                "APS-ARCH-INDEX-001",
                "Session state date is missing, future-dated or stale",
                updated_at=metadata.get("updated_at"),
            ))
        if metadata.get("standard_version") != profile.get("standard_version"):
            findings.append(_finding(
                "ARCHITECTOR_SESSION_STATE_REGISTRY_DRIFT",
                "APS-ARCH-INDEX-001",
                "Session state claims another standard version",
                expected=profile.get("standard_version"),
                actual=metadata.get("standard_version"),
            ))
        tz_entries, local = _registry_array(
            root, profile, "tz_registry", "technical_specs", "APS-ARCH-INDEX-001", "ARCHITECTOR_SESSION_STATE_REGISTRY_DRIFT"
        )
        findings.extend(local)
        expected_open = sorted(
            str(item.get("tz_id")) for item in tz_entries if item.get("status") in ACTIVE_TZ_STATUSES
        )
        actual_open = sorted(filter(None, (part.strip() for part in metadata.get("open_tz_ids", "").split(","))))
        if expected_open != actual_open:
            findings.append(_finding(
                "ARCHITECTOR_SESSION_STATE_REGISTRY_DRIFT",
                "APS-ARCH-INDEX-001",
                "Session state open TZ list differs from registry",
                expected=expected_open,
                actual=actual_open,
            ))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_INDEX_SESSION_VALID",
            "APS-ARCH-INDEX-001",
            "Index links and session state are current and registry-consistent",
            severity="INFO",
        ))
    return findings


# ======================================================================
# 8. APS-ARCH-GIT-001 — CRITICAL FILES, TRACKING И PROTECTED LOCAL STATE
# ======================================================================


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True,
        env={**os.environ, "LC_ALL": "C", "LANG": "C"},
    )


@enforces_rule("APS-ARCH-GIT-001")
@emits_diagnostic("APS-ARCH-GIT-001", "ARCHITECTOR_GIT_STATE_VALID")
@emits_diagnostic("APS-ARCH-GIT-001", "ARCHITECTOR_REQUIRED_FILE_NOT_TRACKED")
@emits_diagnostic("APS-ARCH-GIT-001", "ARCHITECTOR_REQUIRED_FILE_MISSING")
@emits_diagnostic("APS-ARCH-GIT-001", "ARCHITECTOR_SETTINGS_LOCAL_MODIFIED")
def validate_git_state(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    entries, findings = _registry_array(
        root, profile, "critical_files_manifest", "files", "APS-ARCH-GIT-001", "ARCHITECTOR_REQUIRED_FILE_MISSING"
    )
    if findings:
        return findings
    is_git = _git(root, "rev-parse", "--is-inside-work-tree").returncode == 0
    for entry in entries:
        rel = _relative_path(entry.get("path"))
        if rel is None or not (root / rel).exists():
            findings.append(_finding(
                "ARCHITECTOR_REQUIRED_FILE_MISSING",
                "APS-ARCH-GIT-001",
                "Critical startup file is missing",
                path=entry.get("path"),
            ))
            continue
        if is_git and entry.get("must_be_tracked", True):
            if _git(root, "ls-files", "--error-unmatch", "--", rel.as_posix()).returncode != 0:
                findings.append(_finding(
                    "ARCHITECTOR_REQUIRED_FILE_NOT_TRACKED",
                    "APS-ARCH-GIT-001",
                    "Critical startup file is not tracked in HEAD",
                    path=rel.as_posix(),
                ))
    if is_git:
        diff = _git(root, "diff", "--name-only", "--", ".claude/settings.local.json")
        cached = _git(root, "diff", "--cached", "--name-only", "--", ".claude/settings.local.json")
        if diff.stdout.strip() or cached.stdout.strip():
            findings.append(_finding(
                "ARCHITECTOR_SETTINGS_LOCAL_MODIFIED",
                "APS-ARCH-GIT-001",
                "Owner-local Claude settings were modified",
                path=".claude/settings.local.json",
            ))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_GIT_STATE_VALID",
            "APS-ARCH-GIT-001",
            "Critical startup files exist and tracked state is reproducible",
            severity="INFO",
            git_repository=is_git,
        ))
    return findings


# ======================================================================
# 9. APS-ARCH-IMMUTABLE-002 — ИСТОРИЧЕСКИЙ RELEASE v2.9.123
# ======================================================================


@enforces_rule("APS-ARCH-TZ-001")
@emits_diagnostic("APS-ARCH-TZ-001", "TZ_WORK_MATERIAL_UNCLASSIFIED")
def _covered_by_classification(relative: str, classified: set[str]) -> bool:
    """Классифицирован ли путь сам или каталогом, в котором лежит.

    До v2.9.161 совпадение было только точным, а каталог рабочих материалов
    жёстко задан в коде. Для Архитектора это означало 7451 запись реестра,
    растущую примерно на 700 с каждым выпуском стандарта: каждое дерево
    выпуска — сотни файлов, и каждый требовал собственной строки.

    Запись на каталог при этом не просто не помогала, а удваивала находки —
    она сама не резолвилась в файл и давала вторую ошибку.

    Соседний реестр `architect_path_classification.json` покрытие каталогом
    поддерживал с самого начала. Требование к двум реестрам одного профиля
    расходилось без причины.
    """
    if relative in classified:
        return True
    return any(
        relative.startswith(prefix + "/")
        for prefix in classified
    )


@enforces_rule("APS-ARCH-IMMUTABLE-002")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_SOURCE_DIFFERS_FROM_ARCHIVE")
def _compare_archive_to_source(archive_path: Path, source: Path) -> list[RuleFinding]:
    """Сверяет содержимое архива с распакованным деревом по каждой записи.

    До v2.9.161 требовалась побайтовая пересборка. Это оказалось
    невыполнимо по построению, и проверено обоими способами: собственная
    пересборка проверки переписывала алгоритм заново (не обрабатывала
    симлинки, иначе задавала режим файла и compresslevel), а штатный
    `build_release_zip.py` тоже не воспроизводил архив — он собран
    сборщиком своей эпохи, а тот с тех пор изменился.

    Требование «побайтово» не переживает развитие сборщика, если версия
    сборщика не закреплена вместе с артефактом. Но охраняемый инвариант
    другой: **содержимое не изменилось**. Целостность самого контейнера
    уже подтверждена его SHA-256 и CRC выше.

    Поэтому сверяется то, что действительно важно: состав записей и
    содержимое каждой из них. Расхождение называется поимённо — какой
    файл добавлен, исчез или изменился.
    """
    findings: list[RuleFinding] = []
    with zipfile.ZipFile(archive_path) as archive:
        in_archive = {
            info.filename: hashlib.sha256(archive.read(info.filename)).hexdigest()
            for info in archive.infolist() if not info.is_dir()
        }
    on_disk = {
        path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(source.rglob("*")) if path.is_file()
    }
    for name in sorted(set(in_archive) | set(on_disk)):
        expected, actual = in_archive.get(name), on_disk.get(name)
        if expected == actual:
            continue
        findings.append(_finding(
            "ARCHITECTOR_V123_SOURCE_DIFFERS_FROM_ARCHIVE",
            "APS-ARCH-IMMUTABLE-002",
            "Extracted copy no longer matches the immutable archive",
            entry=name,
            state="absent_on_disk" if actual is None
            else "absent_in_archive" if expected is None else "content_differs",
        ))
    return findings


@enforces_rule("APS-ARCH-IMMUTABLE-002")
def _source_check_required(release: dict[str, Any]) -> bool:
    """Сверка распакованной копии с архивом обязательна.

    До v2.9.161 ключ назывался ``require_byte_identical_rebuild``. Старое имя
    принимается, чтобы конфиг прежнего образца не отключил проверку молча.
    """
    if "require_source_matches_archive" in release:
        return release["require_source_matches_archive"] is True
    return release.get("require_byte_identical_rebuild") is True

@enforces_rule("APS-ARCH-IMMUTABLE-002")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_IMMUTABILITY_VALID")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_SOURCE_DIFFERS_FROM_ARCHIVE")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_ARCHIVE_HASH_CHANGED")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_ARCHIVE_ENTRY_COUNT_CHANGED")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_ARCHIVE_CRC_FAILED")
@emits_diagnostic("APS-ARCH-IMMUTABLE-002", "ARCHITECTOR_V123_EVIDENCE_INVARIANT_DRIFT")
def validate_v123_immutability(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    path, problems = _configured_path(root, profile, "immutable_releases_registry")
    if problems or path is None:
        return problems
    if not path.is_file():
        return [_finding(
            "ARCHITECTOR_V123_ARCHIVE_HASH_CHANGED",
            "APS-ARCH-IMMUTABLE-002",
            "Immutable releases registry is missing",
        )]
    data = _load_json(path)
    release = next((item for item in data.get("releases", []) if item.get("version") == "2.9.123"), None)
    if not isinstance(release, dict):
        return [_finding(
            "ARCHITECTOR_V123_ARCHIVE_HASH_CHANGED",
            "APS-ARCH-IMMUTABLE-002",
            "v2.9.123 is absent from immutable releases registry",
        )]
    archive_rel = _relative_path(release.get("zip_path"))
    source_rel = _relative_path(release.get("source_directory"))
    if archive_rel is None or not (root / archive_rel).is_file():
        return [_finding(
            "ARCHITECTOR_V123_ARCHIVE_HASH_CHANGED",
            "APS-ARCH-IMMUTABLE-002",
            "v2.9.123 archive is missing",
            path=release.get("zip_path"),
        )]
    archive_path = root / archive_rel
    findings: list[RuleFinding] = []
    if release.get("expected_tests") != 1020 or release.get("strict_gate_status") != "PASS":
        findings.append(_finding(
            "ARCHITECTOR_V123_EVIDENCE_INVARIANT_DRIFT",
            "APS-ARCH-IMMUTABLE-002",
            "v2.9.123 evidence must retain 1020 passed and strict gate PASS",
            expected_tests=release.get("expected_tests"),
            strict_gate_status=release.get("strict_gate_status"),
        ))
    actual_hash = _sha256(archive_path)
    if actual_hash != release.get("sha256"):
        findings.append(_finding(
            "ARCHITECTOR_V123_ARCHIVE_HASH_CHANGED",
            "APS-ARCH-IMMUTABLE-002",
            "v2.9.123 archive SHA-256 changed",
            expected=release.get("sha256"),
            actual=actual_hash,
        ))
    try:
        with zipfile.ZipFile(archive_path) as archive:
            if len(archive.infolist()) != release.get("zip_entries"):
                findings.append(_finding(
                    "ARCHITECTOR_V123_ARCHIVE_ENTRY_COUNT_CHANGED",
                    "APS-ARCH-IMMUTABLE-002",
                    "v2.9.123 ZIP entry count changed",
                    expected=release.get("zip_entries"),
                    actual=len(archive.infolist()),
                ))
            bad = archive.testzip()
            if bad is not None:
                findings.append(_finding(
                    "ARCHITECTOR_V123_ARCHIVE_CRC_FAILED",
                    "APS-ARCH-IMMUTABLE-002",
                    "v2.9.123 ZIP CRC failed",
                    entry=bad,
                ))
    except zipfile.BadZipFile as exc:
        findings.append(_finding(
            "ARCHITECTOR_V123_ARCHIVE_CRC_FAILED",
            "APS-ARCH-IMMUTABLE-002",
            "v2.9.123 is not a valid ZIP",
            error=str(exc),
        ))
    if source_rel is not None and (root / source_rel).is_dir() and _source_check_required(release):
        findings.extend(_compare_archive_to_source(archive_path, root / source_rel))
    if not findings:
        findings.append(_finding(
            "ARCHITECTOR_V123_IMMUTABILITY_VALID",
            "APS-ARCH-IMMUTABLE-002",
            "Historical v2.9.123 archive remains immutable and reproducible",
            severity="INFO",
            sha256=actual_hash,
        ))
    return findings


# ======================================================================
# 10. APS-ARCH-ADOPTION-001 — ЧЕСТНЫЙ СТАТУС ПРИМЕНЕНИЯ TZ-03
# ======================================================================

@enforces_rule("APS-ARCH-ADOPTION-001")
@emits_diagnostic("APS-ARCH-ADOPTION-001", "ARCHITECTOR_ADOPTION_PENDING")
@emits_diagnostic("APS-ARCH-ADOPTION-001", "ARCHITECTOR_ADOPTION_DONE")
@emits_diagnostic("APS-ARCH-ADOPTION-001", "ARCHITECTOR_ADOPTION_EVIDENCE_INCOMPLETE")
def assess_tz03_adoption(root: Path, profile: dict[str, Any]) -> list[RuleFinding]:
    evidence_path = root / "ARCHITECTOR_TZ_03_EVIDENCE.json"
    if not evidence_path.is_file():
        return [_finding(
            "ARCHITECTOR_ADOPTION_PENDING",
            "APS-ARCH-ADOPTION-001",
            "Standard support exists, but Architector repository remediation was not evidenced",
            severity="INFO",
            status="PENDING_EXTERNAL_APPLICATION",
        )]
    try:
        data = _load_json(evidence_path)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return [_finding(
            "ARCHITECTOR_ADOPTION_EVIDENCE_INCOMPLETE",
            "APS-ARCH-ADOPTION-001",
            "TZ-03 evidence JSON is invalid",
            error=str(exc),
        )]
    criteria = data.get("acceptance_criteria") if isinstance(data, dict) else None
    if (
        not isinstance(criteria, list)
        or len(criteria) != 18
        or any(item.get("status") != "PASS" for item in criteria if isinstance(item, dict))
        or len([item for item in criteria if isinstance(item, dict)]) != 18
        or data.get("clean_head_verified") is not True
        or data.get("git_archive_verified") is not True
    ):
        return [_finding(
            "ARCHITECTOR_ADOPTION_EVIDENCE_INCOMPLETE",
            "APS-ARCH-ADOPTION-001",
            "TZ-03 cannot be DONE without all 18 PASS criteria and clean-HEAD/archive proof",
        )]
    return [_finding(
        "ARCHITECTOR_ADOPTION_DONE",
        "APS-ARCH-ADOPTION-001",
        "All 18 TZ-03 acceptance criteria are evidenced on the Architector repository",
        severity="INFO",
        status="DONE",
    )]


# ======================================================================
