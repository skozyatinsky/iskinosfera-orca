#!/usr/bin/env python3
# ======================================================================
# validate_structure.py — версия 2.9.129
# Валидатор структуры документации, машинного registry и навыков
# Роль: tool. Намеренно ЕДИНЫЙ файл без внешних зависимостей (проект кладёт его
# одним файлом), поэтому осознанно превышает лимит SOURCE_FILE_STANDARD (800
# строк) — задокументированное исключение, см. SOURCE_FILE_STANDARD §1.
# ======================================================================

"""Проверяет пакет стандартов или проект, к которому стандарт применён.

Примеры:
  # проверка самого пакета
  python tools/validate_structure.py --profile standard-package --root . --check-skills --check-manifest --check-skills-manifest --check-prompt-catalog --check-standard-overview --check-release-hygiene --check-version-sync
  # только реестр целевого проекта
  python tools/validate_structure.py --root /path/to/project --profile target-project --language-profile ru_internal --check-registry --check-schemas --check-paths --check-symbols
  # basic validation целевого проекта
  python tools/validate_structure.py --root /path/to/project --profile target-project --language-profile ru_internal --check-registry --check-schemas --check-paths --check-symbols --check-agent-config --check-reference-data --check-spec-sync --check-user-functions --check-project-snapshot
  # strict validation (basic + runtime, hardcode, skills-manifest, layout & source discipline, pattern memory, markdown links)
  python tools/validate_structure.py --root /path/to/project --profile target-project --language-profile ru_internal --check-registry --check-schemas --check-paths --check-symbols --check-agent-config --check-reference-data --check-spec-sync --check-user-functions --check-project-snapshot --check-test-runner --check-hardcode --check-skills-manifest --check-project-layout --check-entrypoints --check-file-size --check-code-language --check-pattern-memory --check-markdown-links --check-data-in-code --check-test-coverage
  # проверка инженерного стиля (агрегатор layout/entrypoints/file-size/code-language/hardcode/user-functions/project-snapshot)
  python tools/validate_structure.py --root /path/to/project --profile target-project --language-profile ru_internal --check-best-style

Модель серьёзности:
  ошибки — печатаются под «Нарушения» и дают exit 1;
  предупреждения (префикс "[warning] ") — печатаются под «Предупреждения» и НЕ
  влияют на exit code, если не передан --warnings-as-errors.

Серьёзность → exit code:
  нарушение (ошибка)                     -> 1
  предупреждение                         -> 0
  предупреждение + --warnings-as-errors  -> 1
  ошибка аргументов argparse             -> 2
  всё чисто                              -> 0
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import ast
import hashlib
import json
import re
import shlex
import subprocess
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

# v2.9.128 semantic validators live in a separate module so the copyable
# core validator remains reviewable while retaining a single CLI entrypoint.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule  # noqa: E402
except ModuleNotFoundError:
    # ``validate_structure.py`` is a deliberately portable entrypoint. Legacy
    # target projects may copy only this file plus ``v128_validation.py`` and
    # ``governance_validation.py``. Preserve that deployment contract while
    # keeping the same runtime metadata used by the full standard package.
    from dataclasses import dataclass, field
    from typing import Callable, TypeVar

    _RuleCallable = TypeVar("_RuleCallable", bound=Callable[..., Any])

    @dataclass(frozen=True, order=True)
    class RuleFinding:  # type: ignore[no-redef]
        code: str
        rule_id: str
        message: str
        severity: str = "ERROR"
        evidence: dict[str, Any] = field(default_factory=dict, compare=False)

    def enforces_rule(rule_id: str):  # type: ignore[no-redef]
        def decorator(func: _RuleCallable) -> _RuleCallable:
            current = tuple(getattr(func, "__aps_enforces_rules__", ()))
            setattr(func, "__aps_enforces_rules__", (*current, rule_id))
            return func
        return decorator

    def emits_diagnostic(rule_id: str, diagnostic_code: str):  # type: ignore[no-redef]
        def decorator(func: _RuleCallable) -> _RuleCallable:
            current = tuple(getattr(func, "__aps_emits_diagnostics__", ()))
            setattr(func, "__aps_emits_diagnostics__", (*current, (rule_id, diagnostic_code)))
            return func
        return decorator

from v128_validation import (  # noqa: E402
    check_capability_evidence_contract,
    check_change_journal_v128,
    check_function_duplication as check_function_duplication_v128,
    check_function_lifecycle as check_function_lifecycle_v128,
    check_function_merge_status as check_function_merge_status_v128,
    check_function_registry as check_function_registry_v128,
    check_function_test_evidence as check_function_test_evidence_v128,
    check_registry_task_linkage as check_registry_task_linkage_v128,
    check_user_function_registry as check_user_function_registry_v128,
    semantic_control_plane_findings,
)

# Предупреждения помечаются этим префиксом: они печатаются отдельно и НЕ влияют
# на exit code, если не передан --warnings-as-errors. Ошибки — всё остальное.
WARN_PREFIX = "[warning] "

# --- единая скан-граница (v2.9.22) ---
# Что сканирующие проверки (file-size, hardcode, markdown-links) НЕ смотрят в
# реальном репозитории: инфраструктура, кэши, git-воркри, венвы, генерённые данные.
# Плюс уважаются паттерны из .gitignore / .agentignore. Заменяет разрозненные
# per-check скип-листы (урок полевого прогона BestPrice — VALIDATION_FAILURES).
from fnmatch import fnmatch  # noqa: E402

BASE_SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache",
    ".ruff_cache", ".pytest_cache", ".claude", ".codex", ".opencode",
    ".playwright-mcp", ".benchmarks", ".qoder", "_archive", "generated",
}
IGNORE_FILES = (".gitignore", ".agentignore")


def _load_ignore_patterns(root: Path) -> list[str]:
    pats: list[str] = []
    for name in IGNORE_FILES:
        f = root / name
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("!"):
                continue
            pats.append(line.rstrip("/").lstrip("/"))
    return pats


def _is_ignored(rel: Path, patterns: list[str], extra: frozenset[str] = frozenset()) -> bool:
    parts = rel.parts
    if any(p in BASE_SKIP_DIRS or p in extra for p in parts):
        return True
    s = str(rel)
    for pat in patterns:
        if not pat:
            continue
        if "/" in pat:
            if s == pat or s.startswith(pat + "/") or fnmatch(s, pat) or fnmatch(s, pat + "/*"):
                return True
        elif any(fnmatch(part, pat) for part in parts):
            return True
    return False


@enforces_rule("APS-SCAN-SCOPE-UNIFORM-001")
@emits_diagnostic("APS-SCAN-SCOPE-UNIFORM-001", "SCAN_SCOPE_UNIFORM_APPLIED")
@emits_diagnostic("APS-SCAN-SCOPE-UNIFORM-001", "SCAN_SCOPE_UNIFORM_NOT_APPLIED")
def _declared_scope_exclusions(root: Path) -> tuple[str, ...]:
    """Объявленная проектом область — одна на все сканирующие проверки.

    До v2.9.157 реестр области обслуживал только аудит мёртвого кода, а
    проверка хардкода своей области не имела и сканировала каталоги, которые
    проект уже объявил вне контура: архив, мастерскую, поставленные артефакты
    (находка 20-02). Два ответа на один вопрос «что здесь не наш код» —
    это два источника правды, ровно то, что стандарт запрещает.

    Сужение не молчаливое: каждая запись реестра несёт причину и владельца.
    """
    cached = getattr(_declared_scope_exclusions, "_cache", {})
    key = str(root)
    if key not in cached:
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parent))
            from dead_code_registry import load_scan_scope
            paths = tuple(
                str(entry["path"]).strip("/")
                for entry in load_scan_scope(root)
                if isinstance(entry.get("path"), str) and entry["path"].strip("/")
            )
        except Exception:
            paths = ()
        cached[key] = paths
        setattr(_declared_scope_exclusions, "_cache", cached)
    return cached[key]


def _iter_files(root: Path, suffix: str, extra: frozenset[str] = frozenset()):
    """Файлы *suffix под root в пределах единой скан-границы (rel-путь тоже)."""
    patterns = _load_ignore_patterns(root)
    declared = _declared_scope_exclusions(root)
    for f in root.rglob(f"*{suffix}"):
        rel = f.relative_to(root)
        if _is_ignored(rel, patterns, extra):
            continue
        posix = rel.as_posix()
        if any(posix == d or posix.startswith(d + "/") for d in declared):
            continue
        yield f, rel


@enforces_rule("APS-SCAN-SCOPE-UNIFORM-001")
@emits_diagnostic("APS-SCAN-SCOPE-UNIFORM-001", "SCAN_SCOPE_UNIFORM_APPLIED")
def _iter_tree(root: Path, pattern: str = "*"):
    """Обход всего дерева в пределах объявленной области.

    `_iter_files` покрывает проверки, ищущие файлы по расширению. Три
    проверки обходят дерево от корня целиком — гигиена поставки, поиск
    каталогов `ref`, поиск `__main__.py`, — и до v2.9.160 делали это в
    обход объявленной области.

    Следствие видно на числах: на Архитекторе гигиена поставки давала 57
    находок, из них 51 — в каталоге, который проект объявил вне контура.
    Правило `APS-SCAN-SCOPE-UNIFORM-001` (v2.9.157) обещало единую область
    для всех сканирующих проверок, но дошло только до тех, что ходят через
    `_iter_files`.
    """
    declared = _declared_scope_exclusions(root)
    for path in root.rglob(pattern):
        posix = path.relative_to(root).as_posix()
        if any(posix == d or posix.startswith(d + "/") for d in declared):
            continue
        yield path


BASE_REQUIRED = ["README.md", "docs/README.md"]
PROFILE_DOCS = {
    "ru_internal": [["docs/ТЕРМИНЫ.md"], ["docs/ОГРАНИЧЕНИЯ.md"]],
    "en_public": [["docs/TERMS.md"], ["docs/LIMITATIONS.md"]],
    "mixed": [["docs/ТЕРМИНЫ.md", "docs/TERMS.md"], ["docs/ОГРАНИЧЕНИЯ.md", "docs/LIMITATIONS.md"]],
}
SPEC_DIRS = {"ru_internal": ["ТЗ"], "en_public": ["specs"], "mixed": ["ТЗ", "specs"]}


def project_doc_problems(root: Path, profile: str) -> list[str]:
    out = [f"нет обязательного файла: {p}" for p in BASE_REQUIRED if not (root / p).exists()]
    for group in PROFILE_DOCS.get(profile, PROFILE_DOCS["ru_internal"]):
        if not any((root / p).exists() for p in group):
            out.append("нет обязательного файла: " + " или ".join(group))
    return out

PACKAGE_REQUIRED = [
    "AGENTS.md", "README.md", "manifest.json", "CHANGELOG.md",
    "core/CRAFT_STANDARD.md", "core/DOCUMENTATION_STANDARD.md",
    "core/FILE_AND_FOLDER_STANDARD.md", "core/PROJECT_PROFILES.md",
    "core/STRUCTURE_TXT_STANDARD.md", "core/REGISTRY_CONTRACT.md",
    "core/COMPATIBILITY_POLICY.md", "core/DEPRECATION_POLICY.md",
    "core/RELEASE_CHECKLIST.md", "core/TERMINOLOGY_DICTIONARY.md",
    "core/VERIFICATION_GAUNTLET_AND_TOOL_DISCOVERY_STANDARD.md",
    "core/VERIFICATION_GAUNTLET_MACHINE_CONTRACTS.md",
    "core/VERIFICATION_GAUNTLET_OPERATIONAL_APPENDICES.md",
    "core/PROMPT_CATALOG_AND_EXECUTION_STANDARD.md",
    "core/AGENT_ORCHESTRATION_RUNTIME_STANDARD.md",
    "profiles/README.md",
    "profiles/iskinosphere/ISKINOSPHERE_ORCA_FORK_RUNTIME_PROFILE.md",
    "profiles/architect_library/ARCHITECT_LIBRARY_PROFILE.md",
    "tools/architect_readiness.py", "tools/architect_readiness_common.py",
    "tools/architect_readiness_profiles.py", "tools/architect_readiness_governance.py",
    "tools/build_architect_skills_manifest.py",
    "schemas/architect_library_profile.schema.json",
    "schemas/architect_license_ledger.schema.json",
    "schemas/architect_skills_manifest.schema.json",
    "schemas/architect_tz_registry.schema.json",
    "tests/test_v2_9_136_architect_readiness.py",
    "prompts/README.md", "prompts/registry.json",
    "schemas/prompt_registry.schema.json",
    "tools/generate_standard_overview.py", "STANDARD_OVERVIEW.html",
    "schemas/release_profiles.schema.json", "reference/release_profiles.json",
    "tools/release_integrity.py", "tools/validate_release_receipt.py",
    "tests/test_v2_9_124_integrations.py", "tests/test_v2_9_127_regressions.py",
    "tests/test_v2_9_128_regressions.py",
    "reference/governance_class_registry.json", "schemas/governance_class_registry.schema.json",
    "reference/orchestrator_protocol.json", "schemas/orchestrator_protocol.schema.json",
    "reference/function_lifecycle.json", "reference/capability_evidence.json",
    "schemas/capability_evidence.schema.json", "schemas/trusted_agent_result.schema.json",
    "schemas/project_health_audit.schema.json", "schemas/tz_implementation_audit.schema.json",
    "schemas/release_evidence_bundle.schema.json",
    "tools/v128_validation.py", "tools/orchestrator_control_plane.py",
    "tools/agent_gate.py", "tools/verify_agent_result.py",
    "tools/merge_readiness_gate.py", "tools/function_registry.py",
    "tools/project_health_audit.py", "tools/audit_tz_implementation.py",
    "templates/README_TEMPLATE.md", "templates/RFC_TEMPLATE.md",
    "checklists/docs_review.md", "prompts/apply_docs_standard.md",
    "core/AGENT_INSTRUCTIONS_STANDARD.md", "core/REFERENCE_DATA_STANDARD.md",
    "core/SPEC_SYNC_STANDARD.md",
    "core/NO_HARDCODE_POLICY.md",
    "core/USER_FUNCTION_REGISTRY_CONTRACT.md", "core/PROJECT_SNAPSHOT_STANDARD.md",
    "core/STANDARD_UPDATE_POLICY.md", "core/TEST_RUNNER_CONTRACT.md",
    "core/PROJECT_LAYOUT_STANDARD.md", "core/ENTRYPOINTS_STANDARD.md",
    "core/SOURCE_FILE_STANDARD.md", "core/CODE_LANGUAGE_POLICY.md",
    "core/BEST_ENGINEERING_STYLE_STANDARD.md", "core/AI_AGENT_QUALITY_GATES.md",
    "core/GOLDEN_PATH_STANDARD.md", "core/LEARNING_LOOP_STANDARD.md",
    "reference/SUCCESS_PATTERNS.md", "reference/ANTI_PATTERNS.md",
    "reference/VALIDATION_FAILURES.md", "reference/AGENT_BEHAVIOR_NOTES.md",
    "templates/PATTERN_CARD_TEMPLATE.md", "templates/POST_TASK_LESSONS_TEMPLATE.md",
    "prompts/extract_lessons_from_completed_task.md",
    "skills/maintenance/harvest-lessons/SKILL.md",
    "schemas/engineering_patterns.schema.json",
    "tests/test_validate_structure.py",
    "checklists/best_engineering_review.md", "checklists/ai_agent_code_review.md",
    "prompts/enforce_best_engineering_style.md",
    "prompts/review_ai_agent_output_like_senior_maintainer.md",
    "templates/PYTHON_MODULE_TEMPLATE.py", "templates/CLI_ENTRYPOINT_TEMPLATE.py",
    "templates/BIN_LAUNCHER_TEMPLATE.sh", "templates/BIN_LAUNCHER_TEMPLATE.cmd",
    "templates/BIN_LAUNCHER_TEMPLATE.ps1",
    "templates/BEST_ENGINEERING_CHANGE_REPORT_TEMPLATE.md",
    "templates/AI_AGENT_FINAL_REPORT_TEMPLATE.md",
    "reference/INFLUENCE_MAP.md", "reference/document_types_RU_EN.md",
    "schemas/functions.schema.json", "schemas/skill.schema.json",
    "schemas/skills_manifest.schema.json",
    "schemas/user_functions.schema.json", "schemas/project_snapshot.schema.json",
    "schemas/test_runner.schema.json", "schemas/project_layout.schema.json",
    "schemas/test_coverage.schema.json", "core/TEST_COVERAGE_CONTRACT.md",
    "core/BUILD_AND_PROTECT_STANDARD.md", "core/KNOWLEDGE_INDEX_STANDARD.md",
    "schemas/constants.schema.json", "reference/PEER_STANDARD_RECONCILIATION.md",
    "schemas/entitlements.schema.json", "core/ENTITLEMENTS_STANDARD.md",
    "templates/entitlements.json",
    "schemas/dependency_policy.schema.json", "core/DEPENDENCY_MANAGEMENT_STANDARD.md",
    "templates/dependency_policy.json",
    "schemas/dependency_decisions.schema.json", "templates/dependency_decisions.json",
    "core/TOOLING_SECURITY_REVIEW_STANDARD.md",
    "schemas/tooling_security_reviews.schema.json", "templates/tooling_security_reviews.json",
    "schemas/tool_candidates.schema.json", "templates/tool_candidates.json",
    "schemas/approved_tools.schema.json", "templates/approved_tools.json",
    "schemas/verification_evidence.schema.json", "templates/verification_evidence.json",
    "core/SYNC_AND_BACKUP_STANDARD.md", "core/ENCRYPTED_ENV_STANDARD.md",
    "core/AUTOMATION_SERVER_SYNC_STANDARD.md",
    "schemas/sync_jobs.schema.json", "schemas/encrypted_env_policy.schema.json",
    "schemas/automation_jobs.schema.json",
    "templates/sync_jobs.json", "templates/encrypted_env_policy.json",
    "templates/automation_jobs.json", "templates/automation_sync_jobs.yaml",
    "templates/encrypt_env.py", "templates/rsync_job.sh", "templates/restic_backup_job.sh",
    "prompts/setup_laptop_server_sync.md", "prompts/review_sync_backup_secrets_setup.md",
    "adapters/park/ECOSYSTEM_SERVICES.md",
    "core/GIT_AGENT_WORKFLOW_STANDARD.md", "core/AUTOMATED_CODE_AUDIT_STANDARD.md",
    "schemas/git_agent_policy.schema.json", "schemas/code_audit_jobs.schema.json",
    "templates/git_agent_policy.json", "templates/code_audit_jobs.json",
    "core/LICENSE_SERVER_INTEGRATION_STANDARD.md",
    "schemas/license_integration_policy.schema.json",
    "templates/license_integration_policy.json",
    "core/QAI_FABRIC_ADAPTER_STANDARD.md",
    "schemas/qai_fabric_policy.schema.json",
    "templates/qai_fabric_policy.json",
]

REGISTRY_FILES = {
    "functions.json": "functions.schema.json",
    "cli_commands.json": "cli_commands.schema.json",
    "config_fields.json": "config_fields.schema.json",
    "env_vars.json": "env_vars.schema.json",
    "endpoints.json": "endpoints.schema.json",
    "constants.json": "constants.schema.json",
}

# реестры, которых может не быть (проверяются только если присутствуют)
OPTIONAL_REGISTRY_FILES = {"constants.json"}

# Единственный объявленный словарь статусов управляемого документа.
# Нормативный источник — core/TZ_LIFECYCLE_AND_AUDIT_SEQUENCE_STANDARD.md,
# правило APS-TZ-STATUS-AUTHORITY-001. Совпадение кода с этим документом
# проверяется тестом test_v2_9_171_status_vocabulary.py: до v2.9.171 набор
# здесь был короче на REVIEW и CONFLICT, из-за чего предписанная стандартом
# передача работы проверяющему (`__REVIEW`) давала нарушение.
SPEC_DOC_STATUSES = (
    "DRAFT",
    "TODO",
    "WIP",
    "REVIEW",
    "BLOCKED",
    "DONE",
    "ARCHIVE",
    "CONFLICT",
)

STATUS_RE = re.compile(r"__(" + "|".join(SPEC_DOC_STATUSES) + r")\.md$")
WORKDOC_RE = re.compile(r"^\d{2}[a-z]?_.+")


def missing(root: Path, files: list[str]) -> list[str]:
    return [f"нет обязательного файла: {p}" for p in files if not (root / p).exists()]


def check_statuses(root: Path, profile: str = "ru_internal") -> list[str]:
    out: list[str] = []
    for section in ["БТ", "Дизайн"] + SPEC_DIRS.get(profile, ["ТЗ"]):
        directory = root / "docs" / section
        if not directory.is_dir():
            continue
        for file in directory.rglob("*.md"):
            if file.name == "README.md":
                continue
            if WORKDOC_RE.match(file.name) and not STATUS_RE.search(file.name):
                out.append(f"нет статуса в имени: {file.relative_to(root)}")
    return out


# --- минимальная JSON Schema (подмножество draft-07, без внешних зависимостей) ---
def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "number"
    if value is None:
        return "null"
    return type(value).__name__


def _matches_type(value: Any, expected: str | list[str]) -> bool:
    if isinstance(expected, list):
        return any(_matches_type(value, item) for item in expected)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    return _type_name(value) == expected


def validate_schema(data: Any, schema: dict[str, Any], where: str) -> list[str]:
    errors: list[str] = []

    def walk(value: Any, sch: dict[str, Any], path: str) -> None:
        expected = sch.get("type")
        if expected and not _matches_type(value, expected):
            errors.append(f"{where}{path}: ожидался тип {expected}, получен {_type_name(value)}")
            return
        if "enum" in sch and value not in sch["enum"]:
            errors.append(f"{where}{path}: значение {value!r} не входит в enum {sch['enum']!r}")
        if "const" in sch and value != sch["const"]:
            errors.append(f"{where}{path}: значение {value!r} не равно const={sch['const']!r}")
        expected_name = _type_name(value) if isinstance(expected, list) else expected
        if expected_name == "string":
            min_len = sch.get("minLength")
            if min_len is not None and len(value) < min_len:
                errors.append(f"{where}{path}: строка короче minLength={min_len}")
            pattern = sch.get("pattern")
            if pattern and not re.search(pattern, value):
                errors.append(f"{where}{path}: строка не соответствует pattern={pattern!r}")
        if expected_name == "number" and not isinstance(value, bool):
            # minimum/exclusiveMinimum/maximum/exclusiveMaximum поддержаны с
            # v2.9.118 (тот же класс декоративного контракта, что был у
            # minItems/uniqueItems до этого — draft-07 их допускает, walk() их
            # молча игнорировал бы, не будь этой ветки).
            for key, op, label in (
                ("minimum", lambda v, b: v < b, "меньше minimum"),
                ("exclusiveMinimum", lambda v, b: v <= b, "не больше exclusiveMinimum"),
                ("maximum", lambda v, b: v > b, "больше maximum"),
                ("exclusiveMaximum", lambda v, b: v >= b, "не меньше exclusiveMaximum"),
            ):
                bound = sch.get(key)
                if bound is not None and op(value, bound):
                    errors.append(f"{where}{path}: значение {value!r} {label}={bound!r}")
        if expected_name == "array":
            # minItems поддержан с v2.9.59 (P2 ревью v2.9.58): три схемы уже
            # декларировали его, но walk() молча игнорировал — декоративный контракт
            min_items = sch.get("minItems")
            if min_items is not None and len(value) < min_items:
                errors.append(f"{where}{path}: массив короче minItems={min_items}")
            # uniqueItems поддержан с v2.9.118 (P2 внешнего аудита v2.9.117):
            # тот же класс декоративного контракта, что был у minItems до
            # v2.9.59 — схема объявляла бы поле, walk() молча бы его игнорировал.
            # Элементы могут быть нехэшируемыми (dict/list) — сравниваем через
            # json.dumps(sort_keys=True) как ключ дедупликации, не set() напрямую.
            if sch.get("uniqueItems") is True:
                seen_keys: set[str] = set()
                for i, item in enumerate(value):
                    try:
                        dedup_key = json.dumps(item, sort_keys=True, ensure_ascii=False)
                    except TypeError:
                        dedup_key = repr(item)
                    if dedup_key in seen_keys:
                        errors.append(f"{where}{path}[{i}]: дублирует более ранний элемент "
                                      f"массива (uniqueItems)")
                    seen_keys.add(dedup_key)
            item_schema = sch.get("items")
            if item_schema:
                for i, item in enumerate(value):
                    walk(item, item_schema, f"{path}[{i}]")
        if expected_name == "object":
            min_properties = sch.get("minProperties")
            if min_properties is not None and len(value) < min_properties:
                errors.append(f"{where}{path}: объект содержит меньше minProperties={min_properties}")
            for key in sch.get("required", []):
                if key not in value:
                    errors.append(f"{where}{path}: нет обязательного поля {key!r}")
            allowed = set(sch.get("properties", {}).keys())
            addl = sch.get("additionalProperties")
            if addl is False:
                for key in value.keys():
                    if key not in allowed:
                        errors.append(f"{where}{path}: лишнее поле {key!r}")
            elif isinstance(addl, dict) and addl:
                for key in value.keys():
                    if key not in allowed:
                        walk(value[key], addl, f"{path}.{key}")
            for key, sub_schema in sch.get("properties", {}).items():
                if key in value and isinstance(sub_schema, dict) and sub_schema:
                    walk(value[key], sub_schema, f"{path}.{key}")

    walk(data, schema, "")
    return errors


@enforces_rule("APS-CHECK-MISSING-INPUT-001")
@emits_diagnostic("APS-CHECK-MISSING-INPUT-001", "CHECK_INPUT_UNREADABLE")
def load_json(path: Path) -> tuple[Any | None, str | None]:
    """Читает JSON, возвращая ошибку вместо исключения.

    Функция объявлена как защищённое чтение: возвращает `(данные, ошибка)`,
    и все 79 её вызовов трактуют непустую ошибку как «прочитать не удалось».
    Но перехватывался только `JSONDecodeError` — самый частый случай,
    отсутствие файла, ронял весь валидатор трассировкой.

    Следствие было тяжелее, чем кажется: восемь флагов падали при запуске на
    проекте, у которого нет файлов самого пакета стандарта. Падение — не
    отказ: оно не даёт ни диагностического кода, ни рекомендации, а вызывающий
    не может отличить «нечего проверять» от «проверка сломана».
    """
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except json.JSONDecodeError as exc:
        return None, str(exc)
    except OSError as exc:
        return None, f"{path}: {exc.strerror or exc}"


def _as_list(value: Any) -> list:
    """v2.9.123 (P2 внешнего аудита v2.9.122, A-4, репродуцировано:
    `blocking_caveats: true` роняет check_agent_workflow_integrity()
    traceback'ом `TypeError: 'bool' object is not iterable`). `data.get(field)
    or []` крашится на truthy не-списке — `True or []` возвращает `True`, не
    `[]`; схема отдельно ловит это как находку («ожидался тип array»), но сам
    процесс продолжает работать с уже загруженным сырым JSON и падает
    раньше, чем список находок будет возвращён вызывающему. Используется
    везде, где поле схемой объявлено как array, но код читает его из уже
    загруженного (не прошедшего валидацию типов) JSON."""
    return value if isinstance(value, list) else []


# --- пути и символы ---
def _path_values(registry_name: str, item: dict[str, Any]) -> list[str]:
    if registry_name in ("functions.json", "constants.json") and isinstance(item.get("path"), str):
        return [item["path"]]
    if registry_name == "cli_commands.json" and isinstance(item.get("implementation"), str):
        return [item["implementation"]]
    if registry_name == "env_vars.json" and isinstance(item.get("used_in"), list):
        return [p for p in item["used_in"] if isinstance(p, str)]
    return []


def check_registry_paths(root: Path, registry_name: str, data: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(data, list):
        return out
    for idx, item in enumerate(data):
        if not isinstance(item, dict):
            continue
        for rel_path in _path_values(registry_name, item):
            if not rel_path or rel_path.startswith(("http://", "https://")):
                continue
            if not (root / rel_path).exists():
                out.append(f"docs/registry/{registry_name}[{idx}]: path не существует: {rel_path}")
    return out


def parse_python(path: Path) -> ast.Module | None:
    if path.suffix != ".py" or not path.exists():
        return None
    try:
        return ast.parse(path.read_text(encoding="utf-8-sig"))
    except SyntaxError:
        return None


def module_has_symbol(tree: ast.Module, symbol: str, kind: str) -> bool:
    if kind == "method":
        if "." in symbol:
            class_name, method_name = symbol.split(".", 1)
            for node in tree.body:
                if isinstance(node, ast.ClassDef) and node.name == class_name:
                    return any(isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)) and c.name == method_name for c in node.body)
            return False
        return any(
            isinstance(node, ast.ClassDef)
            and any(isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef)) and c.name == symbol for c in node.body)
            for node in tree.body
        )
    if kind == "function":
        return any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == symbol for n in tree.body)
    if kind == "class":
        return any(isinstance(n, ast.ClassDef) and n.name == symbol for n in tree.body)
    if kind == "constant":
        for node in tree.body:
            targets: list[ast.expr] = []
            if isinstance(node, ast.Assign):
                targets = list(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets = [node.target]
            for target in targets:
                if isinstance(target, ast.Name) and target.id == symbol:
                    return True
        return False
    return False


def check_python_symbols(root: Path, functions_data: Any) -> list[str]:
    out: list[str] = []
    if not isinstance(functions_data, list):
        return out
    for idx, item in enumerate(functions_data):
        if not isinstance(item, dict) or item.get("public") is not True or item.get("status") == "REMOVED":
            continue
        symbol, kind, rel_path = item.get("symbol"), item.get("kind"), item.get("path")
        if not all(isinstance(v, str) for v in (symbol, kind, rel_path)):
            continue
        tree = parse_python(root / rel_path)
        if tree is None:
            continue
        if not module_has_symbol(tree, symbol, kind):
            out.append(f"docs/registry/functions.json[{idx}]: символ {symbol!r} ({kind}) не найден в {rel_path}")
    return out


def _source_roots(root: Path) -> list[Path]:
    """Корни исходников для сканирования публичной поверхности (v2.9.91):
    src/<pkg>, modules/<pkg>, packages/<pkg> — канон и монорепо-альтернативы
    (см. _packages/check_project_layout); если ни одного нет — плоский
    top-level пакет (папка с __init__.py прямо в корне, урок раскатки
    automation_server)."""
    roots: list[Path] = []
    for base_name in ("src", "modules", "packages"):
        base = root / base_name
        if base.is_dir():
            roots.extend(d for d in sorted(base.iterdir())
                         if d.is_dir() and (d / "__init__.py").exists())
    if not roots:
        roots.extend(
            p for p in sorted(root.iterdir())
            if p.is_dir() and not p.name.startswith(".") and (p / "__init__.py").exists()
        )
    return roots


def _public_symbols_in_module(tree: ast.Module) -> list[tuple[str, str]]:
    """[(kind, name)] для module-level function/class без ведущего "_". Если
    модуль объявляет __all__ (список строковых литералов) — поверхность
    сужается до пересечения с __all__. Честная граница: re-export через
    __init__.py (from x import y), методы классов, CLI-роутеры, декораторы —
    не отслеживаются в этой версии (см. GIT_WORKSPACE_HYGIENE_STANDARD.md §5
    — тот же приём "честная граница вместо тихого недо-покрытия")."""
    all_names: set[str] | None = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            if isinstance(node.value, (ast.List, ast.Tuple)):
                all_names = {e.value for e in node.value.elts
                             if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    symbols: list[tuple[str, str]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_"):
            symbols.append(("function", node.name))
        elif isinstance(node, ast.ClassDef) and not node.name.startswith("_"):
            symbols.append(("class", node.name))
    if all_names is not None:
        symbols = [(k, n) for k, n in symbols if n in all_names]
    return symbols


def check_registry_completeness(root: Path) -> list[str]:
    """--check-registry-completeness (v2.9.91, P1 внешнего ревью v2.9.90):
    check_python_symbols проверяет только направление registry -> код (что
    заявленный символ существует); ОБРАТНОЕ направление — что каждый
    публичный символ кода заявлен в registry — не проверялось вообще.
    Подтверждено репродукцией перед правкой: новая публичная функция без
    единой registry-записи проходила весь strict-набор с exit 0. Публичная
    поверхность — module-level function/class без ведущего "_" (см.
    _public_symbols_in_module); опциональный waiver-файл
    docs/registry/registry_completeness_waivers.json снимает конкретные
    находки при непустом reason (тот же waiver-идиома, что везде в пакете)."""
    out: list[str] = []
    functions_path = root / "docs" / "registry" / "functions.json"
    if not functions_path.exists():
        return out  # нет реестра функций — нечего сверять (др. проверка требует его наличия)
    fdata, ferr = load_json(functions_path)
    if ferr:
        return [f"registry-completeness: битый functions.json: {ferr}"]
    registered: set[tuple[str, str]] = set()
    if isinstance(fdata, list):
        for item in fdata:
            if (isinstance(item, dict) and isinstance(item.get("path"), str)
                    and isinstance(item.get("symbol"), str)):
                registered.add((item["path"], item["symbol"]))
    waivers: set[tuple[str, str]] = set()
    waivers_path = root / "docs" / "registry" / "registry_completeness_waivers.json"
    if waivers_path.exists():
        wdata, werr = load_json(waivers_path)
        if werr:
            out.append(f"registry-completeness: битый registry_completeness_waivers.json: {werr}")
        elif isinstance(wdata, list):
            for w in wdata:
                if not isinstance(w, dict):
                    continue
                if not (isinstance(w.get("reason"), str) and w["reason"].strip()):
                    out.append(f"registry-completeness: waiver без непустого reason: {w!r}")
                    continue
                if isinstance(w.get("path"), str) and isinstance(w.get("symbol"), str):
                    waivers.add((w["path"], w["symbol"]))
    src_reldirs = [str(sr.relative_to(root)) for sr in _source_roots(root)]
    if not src_reldirs:
        return out  # нет распознанного корня исходников — нечего сканировать
    for f, rel in _iter_files(root, ".py"):
        rel_s = str(rel)
        if not any(rel_s == sr or rel_s.startswith(sr + "/") for sr in src_reldirs):
            continue
        if "tests" in rel.parts or f.name.startswith("test_") or f.name.endswith("_test.py"):
            continue
        if f.name.startswith("_") and f.name != "__init__.py":
            continue
        tree = parse_python(f)
        if tree is None:
            continue
        for kind, name in _public_symbols_in_module(tree):
            key = (rel_s, name)
            if key in registered or key in waivers:
                continue
            out.append(f"registry-completeness: публичный {kind} {name!r} в {rel_s} не "
                       f"зарегистрирован в functions.json (или добавьте waiver с reason "
                       f"в registry_completeness_waivers.json)")
    return out


def resolve_schemas_root(project_root: Path, explicit: str | None) -> Path | None:
    candidates: list[Path] = []
    if explicit:
        candidates.append(Path(explicit))
    candidates.append(project_root / "schemas")
    candidates.append(Path(__file__).resolve().parent.parent / "schemas")
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def check_change_journal(registry_dir: Path, schemas_root: Path | None, check_schemas: bool) -> list[str]:
    journal = registry_dir / "change_journal.jsonl"
    if not journal.exists():
        return []
    out: list[str] = []
    schema: dict[str, Any] | None = None
    schema_path = schemas_root / "change_journal.schema.json" if schemas_root else None
    if check_schemas and schema_path and schema_path.exists():
        loaded, error = load_json(schema_path)
        if error:
            out.append(f"битая схема change_journal.schema.json: {error}")
        elif isinstance(loaded, dict):
            schema = loaded
    for line_no, line in enumerate(journal.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            out.append(f"change_journal.jsonl:{line_no}: битый JSONL: {exc}")
            continue
        if not isinstance(obj, dict):
            out.append(f"change_journal.jsonl:{line_no}: ожидался JSON object")
            continue
        # два диалекта журнала (v2.9.36): наш (date+action) или парный
        # qai-fabric/RAG (timestamp+change_type); anyOf не в schema-subset — код
        ours = "date" in obj and "action" in obj
        peer = "timestamp" in obj and "change_type" in obj
        managed_v128 = "event_id" in obj and "timestamp" in obj and "action" in obj
        if not (ours or peer or managed_v128):
            out.append(f"change_journal.jsonl:{line_no}: нужен один из диалектов: "
                       f"date+action, timestamp+change_type или event_id+timestamp+action")
        if schema:
            out.extend(validate_schema(obj, schema, f"change_journal.jsonl:{line_no}"))
    return out


def check_registry(root: Path, check_schemas: bool, check_paths: bool, check_symbols: bool, schemas_root_arg: str | None) -> list[str]:
    registry_dir = root / "docs" / "registry"
    if not registry_dir.is_dir():
        return ["нет папки docs/registry/"]
    out: list[str] = []
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    parsed: dict[str, Any] = {}
    if check_schemas and schemas_root is None:
        out.append("не найдена папка schemas/ для проверки JSON Schema")
    for registry_name, schema_name in REGISTRY_FILES.items():
        registry_file = registry_dir / registry_name
        if not registry_file.exists():
            if registry_name not in OPTIONAL_REGISTRY_FILES:
                out.append(f"нет docs/registry/{registry_name} (для неприменимого слоя используйте [] )")
            continue
        data, error = load_json(registry_file)
        if error:
            out.append(f"битый JSON {registry_name}: {error}")
            continue
        parsed[registry_name] = data
        if not isinstance(data, list):
            out.append(f"{registry_name}: ожидался массив")
            continue
        if check_schemas and schemas_root:
            schema_path = schemas_root / schema_name
            if not schema_path.exists():
                out.append(f"нет схемы: {schema_path}")
            else:
                schema, schema_error = load_json(schema_path)
                if schema_error:
                    out.append(f"битая схема {schema_name}: {schema_error}")
                elif isinstance(schema, dict):
                    out.extend(validate_schema(data, schema, registry_name))
        if check_paths:
            out.extend(check_registry_paths(root, registry_name, data))
    if check_symbols and "functions.json" in parsed:
        out.extend(check_python_symbols(root, parsed["functions.json"]))
    out.extend(check_change_journal(registry_dir, schemas_root, check_schemas))
    return out


# --- навыки: проверка YAML front-matter по skill.schema.json ---
FRONT_MATTER_KEY_RE = re.compile(r"^(?P<key>[A-Za-z_][\w-]*)\s*:\s*(?P<value>.*)$")


def parse_front_matter(text: str) -> dict[str, str] | None:
    """YAML front-matter: ключи верхнего уровня, включая блочные скаляры.

    До v2.9.157 разбор шёл построчно и не знал о блочных скалярах (`|`, `>`)
    и о продолжении значения с отступом. Из-за этого каждая строка описания,
    содержащая двоеточие, становилась отдельным «лишним полем», а сам
    `description` оказывался пустым — валидный файл отклонялся дважды.

    Полный YAML сюда не тянется намеренно: валидатор остаётся без внешних
    зависимостей. Разбирается ровно то, что встречается во front-matter, —
    ключ верхнего уровня без отступа и его значение.
    """
    if not text.startswith("---"):
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        return None
    result: dict[str, str] = {}
    key: str | None = None
    block: list[str] = []
    for raw in parts[1].splitlines():
        if not raw.strip():
            if key is not None and block:
                block.append("")
            continue
        indented = raw[:1].isspace()
        match = None if indented else FRONT_MATTER_KEY_RE.match(raw)
        if match is None:
            # Продолжение значения: отступ либо строка, не похожая на ключ.
            if key is not None:
                block.append(raw.strip())
            continue
        if key is not None:
            result[key] = " ".join(item for item in block if item).strip()
        key = match.group("key")
        value = match.group("value").strip()
        block = [] if value in {"|", "|-", "|+", ">", ">-", ">+"} else [value.strip('"').strip("'")]
    if key is not None:
        result[key] = " ".join(item for item in block if item).strip()
    return result


def check_skills(root: Path, schemas_root_arg: str | None) -> list[str]:
    skills_dir = root / "skills"
    if not skills_dir.is_dir():
        return []
    out: list[str] = []
    schema: dict[str, Any] | None = None
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "skill.schema.json").exists():
        loaded, error = load_json(schemas_root / "skill.schema.json")
        if isinstance(loaded, dict):
            schema = loaded
    for skill_file in sorted(skills_dir.rglob("SKILL.md")):
        rel = skill_file.relative_to(root)
        front = parse_front_matter(skill_file.read_text(encoding="utf-8"))
        if front is None:
            out.append(f"{rel}: нет YAML front-matter")
            continue
        if schema:
            out.extend(validate_schema(front, schema, str(rel)))
        out.extend(_skill_invocation_conflicts(front, str(rel)))
    return out


@enforces_rule("APS-SKILL-INVOCATION-COHERENCE-001")
@emits_diagnostic("APS-SKILL-INVOCATION-COHERENCE-001", "SKILL_INVOCATION_COHERENT")
@emits_diagnostic("APS-SKILL-INVOCATION-COHERENCE-001", "SKILL_INVOCATION_CONFLICT")
def _skill_invocation_conflicts(front: dict[str, Any], rel: str) -> list[str]:
    """Намерение стандарта не должно противоречить механике среды.

    `invocation` объявляет, кем скил задуман к вызову; поля Claude Code
    управляют тем, кто может вызвать его на самом деле. Схема проверяет
    поля поодиночке и такого расхождения не видит — нужна кросс-полевая
    проверка (v2.9.157).

    Ось намерения и ось механики независимы там, где они не спорят:
    `invocation: model` + `user-invocable: false` осмысленно, как и
    `invocation: user` + `disable-model-invocation: true`. Ошибкой считается
    только прямое противоречие.
    """
    invocation = str(front.get("invocation", "")).strip().casefold()
    out: list[str] = []
    if invocation == "model" and front.get("disable-model-invocation") is True:
        out.append(f"{rel}: invocation: model противоречит disable-model-invocation: true — "
                   "скил объявлен вызываемым моделью, но модели вызывать его запрещено")
    if invocation == "user" and front.get("user-invocable") is False:
        out.append(f"{rel}: invocation: user противоречит user-invocable: false — "
                   "скил объявлен вызываемым человеком, но скрыт из меню команд")
    return out


# --- инструкции агентов: единый контракт + один конфиг на инструмент ---
def check_agent_config(root: Path) -> list[str]:
    out: list[str] = []
    if not (root / "AGENTS.md").exists():
        out.append("нет корневого AGENTS.md (единый контракт правил)")
    pairs = [
        ("opencode.json", ".opencode/opencode.json"),
        ("CLAUDE.md", ".claude/CLAUDE.md"),
        ("codex.toml", ".codex/config.toml"),
    ]
    for a, b in pairs:
        if (root / a).exists() and (root / b).exists():
            out.append(f"два конфига одного инструмента: {a} и {b} — расхождение")
    # проверка «устаревший путь docs/architecture/» удалена (урок пилота qai,
    # v2.9.36): это была конвенция одного проекта, протёкшая в универсальный
    # валидатор — у других проектов docs/architecture/ живой канонический каталог.
    for name in ("AGENTS.md", "CLAUDE.md"):
        f = root / name
        if f.exists():
            lines = len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
            if lines > 200:
                out.append(f"{name}: {lines} строк > 200 — вынеси детали в docs/ (тонкий контракт)")
    root_agents = root / "AGENTS.md"
    # v2.9.37 (урок пилота RAG): уважаем скан-границу — иначе ловим AGENTS.md
    # в .claude/worktrees/, project_data/ (пользовательские данные) и т.п.
    for nested, rel in _iter_files(root, "AGENTS.md"):
        if nested == root_agents or "_archive" in rel.parts:
            continue
        if "AGENTS.md" not in nested.read_text(encoding="utf-8", errors="ignore"):
            out.append(f"{rel}: вложенный AGENTS.md не ссылается на корневой AGENTS.md")
    return out


# --- справочные данные: помеченное зеркало, без хардкода ---
def check_reference_data(root: Path) -> list[str]:
    out: list[str] = []
    external_status = root / "reference" / "external_control_status.json"
    if external_status.is_file():
        try:
            from external_control_status import validate_external_control_status
            status_data = json.loads(external_status.read_text(encoding="utf-8-sig"))
        except (ImportError, OSError, json.JSONDecodeError) as exc:
            out.append(f"reference/external_control_status.json: unreadable: {type(exc).__name__}")
        else:
            out.extend(
                f"reference/external_control_status.json: {item.code}: {item.message}"
                for item in validate_external_control_status(status_data)
                if item.severity == "ERROR"
            )
    for ref_dir in _iter_tree(root, "ref"):
        if not ref_dir.is_dir():
            continue
        jsons = list(ref_dir.glob("*.json"))
        if not jsons:
            continue
        # Каталог с именем `ref` не обязан быть зеркалом: пакет вправе везти
        # встроенные данные, которые сам и является источником. Требовать от
        # такого каталога пометки «зеркало» — требовать записать неправду
        # (v2.9.163, находка онбординга BestPrice: два из трёх ref/ оказались
        # источниками, их читает код самого пакета).
        if (ref_dir / "_SOURCE.md").exists():
            continue
        marked = (ref_dir / "_MIRROR.md").exists()
        if not marked:
            for j in jsons:
                try:
                    data = json.loads(j.read_text(encoding="utf-8-sig"))
                except (json.JSONDecodeError, OSError):
                    continue
                if isinstance(data, dict) and "_mirror_of" in data:
                    marked = True
                    break
        if not marked:
            out.append(f"{ref_dir.relative_to(root)}/: не объявлено, зеркало это или источник "
                       f"(нужен _MIRROR.md с указанием источника, ключ _mirror_of или _SOURCE.md)")
    return out


def check_spec_sync(root: Path, profile: str = "ru_internal") -> list[str]:
    out: list[str] = []
    # захватываем ПОЛНЫЙ путь до tests/ (например modules/cli/tests/x.py) —
    # раньше regex без левой границы вырезал хвост «tests/x.py» и не находил
    # файл (урок пилота qai, v2.9.36)
    test_re = re.compile(r"[A-Za-z0-9._/-]*tests?/[A-Za-z0-9._/-]+")
    for section in SPEC_DIRS.get(profile, ["ТЗ"]):
        spec_dir = root / "docs" / section
        if not spec_dir.is_dir():
            continue
        for f in sorted(spec_dir.rglob("*__DONE.md")):
            text = f.read_text(encoding="utf-8", errors="ignore")
            refs = [r.lstrip("/") for r in test_re.findall(text)]
            if not refs:
                out.append(f"{f.relative_to(root)}: DONE спека без ссылки на тесты (spec-sync)")
                continue
            seen_missing: set[str] = set()
            for ref in refs:
                if ref not in seen_missing and not (root / ref).exists():
                    seen_missing.add(ref)
                    out.append(f"{f.relative_to(root)}: тест не найден: {ref}")
    return out


def check_manifest(root: Path) -> list[str]:
    mf = root / "manifest.json"
    if not mf.exists():
        return ["нет manifest.json"]
    data, err = load_json(mf)
    if err or not isinstance(data, dict):
        return [f"битый manifest.json: {err}"]
    out: list[str] = []
    contents = data.get("contents", {})
    for section, items in contents.items():
        if not isinstance(items, list):
            continue
        base = "" if section == "root" else section + "/"
        for rel in (base + it for it in items):
            if not (root / rel).exists():
                out.append(f"manifest: файла нет на диске: {rel}")
    flat_sections = ("core", "templates", "checklists", "examples",
                     "reference", "schemas", "tools", "decisions")
    for section in flat_sections:
        d = root / section
        if not d.is_dir():
            continue
        listed = set(contents.get(section, []) if isinstance(contents.get(section), list) else [])
        for extra in {f.name for f in d.iterdir() if f.is_file()} - listed:
            out.append(f"manifest: {section}/{extra} есть на диске, но не в manifest.contents.{section}")
    # Вложенные разделы проверяются рекурсивно: иначе незарегистрированный
    # файл может попасть в ZIP, оставаясь невидимым для manifest gate.
    # С v3.0.0 это относится и к pilots/fixtures/.
    for section in ("prompts", "profiles", "tests", "pilots"):
        d = root / section
        if not d.is_dir():
            continue
        listed = set(contents.get(section, []) if isinstance(contents.get(section), list) else [])
        actual = {str(f.relative_to(d)) for f in d.rglob("*") if f.is_file()}
        for extra in sorted(actual - listed):
            out.append(f"manifest: {section}/{extra} есть на диске, но не в manifest.contents.{section}")
    sk = root / "skills"
    if sk.is_dir():
        listed = set(contents.get("skills", []) if isinstance(contents.get("skills"), list) else [])
        for p in sk.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(sk))
                if rel not in listed:
                    out.append(f"manifest: skills/{rel} есть на диске, но не в manifest.contents.skills")
    listed_root = set(contents.get("root", []) if isinstance(contents.get("root"), list) else [])
    for f in root.iterdir():
        if f.is_file() and f.name not in listed_root:
            out.append(f"manifest: {f.name} есть в корне, но не в manifest.contents.root")
    ad = root / "adapters"
    if ad.is_dir():
        listed_ad = set(contents.get("adapters", []) if isinstance(contents.get("adapters"), list) else [])
        for p in ad.rglob("*"):
            if p.is_file():
                rel = str(p.relative_to(ad))
                if rel not in listed_ad:
                    out.append(f"manifest: adapters/{rel} есть на диске, но не в manifest.contents.adapters")
    version = str(data.get("version", ""))
    for fname in ("README.md", "CHANGELOG.md"):
        f = root / fname
        if f.exists() and version and version not in f.read_text(encoding="utf-8", errors="ignore"):
            out.append(f"manifest.version={version} не найдена в {fname}")
    has_archive = (root / "_archive").exists()
    if has_archive and "archive" not in data:
        out.append("_archive присутствует, но manifest не разрешает архивный донор")
    if not has_archive and "archive" in data:
        out.append("manifest заявляет archive, но _archive отсутствует")
    return out


def check_skills_manifest(root: Path, schemas_root_arg: str | None) -> list[str]:
    mf = root / "skills.manifest.json"
    if not mf.exists():
        return []
    data, err = load_json(mf)
    if err:
        return [f"битый skills.manifest.json: {err}"]
    out: list[str] = []
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "skills_manifest.schema.json").exists():
        schema, _ = load_json(schemas_root / "skills_manifest.schema.json")
        if isinstance(schema, dict):
            out.extend(validate_schema(data, schema, "skills.manifest.json"))
    skills_dir = root / "skills"
    present = {p.parent.name for p in skills_dir.rglob("SKILL.md")} if skills_dir.is_dir() else set()
    entries = data.get("skills", []) if isinstance(data, dict) else []
    for entry in entries:
        name = entry.get("name") if isinstance(entry, dict) else None
        if name and name not in present:
            out.append(f"skills.manifest.json: выбранный скил {name!r} не найден в skills/")
    return out


def _doc_string_lines(text: str) -> set[int]:
    """Номера строк, занятых документацией, а не значениями: docstring'и,
    отдельные строковые выражения и любые многострочные строки (шаблоны/доки).

    НЕ включает однострочные строки-значения вида `URL = "http://..."` — их
    как раз и должен ловить no-hardcode. Калибровка по 18 эталонам (v2.9.23):
    без этого исключения ~99% находок были URL внутри docstring'ов лучших репо.
    """
    out: set[int] = set()
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return out
    for node in ast.walk(tree):
        # отдельное строковое выражение (docstring/inline-doc)
        if isinstance(node, ast.Expr) and isinstance(getattr(node, "value", None), ast.Constant) \
                and isinstance(node.value.value, str):
            end = getattr(node.value, "end_lineno", node.lineno)
            out.update(range(node.lineno, end + 1))
        # любая многострочная строка — документация/шаблон, не значение-константа
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            end = getattr(node, "end_lineno", node.lineno)
            if end > node.lineno:
                out.update(range(node.lineno, end + 1))
    return out


@enforces_rule("APS-HARDCODE-WAIVER-001")
@emits_diagnostic("APS-HARDCODE-WAIVER-001", "HARDCODE_WAIVER_APPLIED")
@emits_diagnostic("APS-HARDCODE-WAIVER-001", "HARDCODE_WAIVER_STALE")
@emits_diagnostic("APS-HARDCODE-WAIVER-001", "HARDCODE_WAIVER_REJECTED")
def load_hardcode_waivers(root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    """Объявленные проектом исключения хардкода.

    Часть находок закрывается решением владельца, а не правкой: URL площадки
    внутри её же парсера — предмет парсера, не конфигурация. До v2.9.163 такое
    решение жило прозой, проверка его не читала и повторяла находку каждый
    прогон, пряча за ней настоящие.
    """
    path = root / "docs" / "registry" / "hardcode_waivers.json"
    if not path.is_file():
        return [], []
    data, err = load_json(path)
    if err:
        return [], [f"hardcode: битый hardcode_waivers.json: {err}"]
    if not isinstance(data, dict) or not isinstance(data.get("waivers"), list):
        return [], ["hardcode: hardcode_waivers.json: ожидается объект с массивом waivers"]
    waivers: list[dict[str, Any]] = []
    problems: list[str] = []
    for item in data["waivers"]:
        if not isinstance(item, dict):
            problems.append("hardcode: запись исключения не является объектом")
            continue
        if not str(item.get("reason", "")).strip():
            problems.append(f"hardcode: исключение {item.get('waiver_id')!r} без причины")
            continue
        if not str(item.get("path", "")).strip():
            problems.append(f"hardcode: исключение {item.get('waiver_id')!r} без пути")
            continue
        waivers.append(item)
    return waivers, problems


@enforces_rule("APS-HARDCODE-WAIVER-001")
def _waiver_for(waivers: list[dict[str, Any]], rel: str, line: str) -> dict[str, Any] | None:
    """Первое исключение, покрывающее находку в этом файле.

    Путь совпадает целиком либо как каталог-префикс. Если объявлен `literal`,
    исключение действует только на строки, где он встречается: точечное
    решение не должно молча накрывать весь файл.
    """
    for waiver in waivers:
        declared = str(waiver["path"]).rstrip("/")
        if rel != declared and not rel.startswith(declared + "/"):
            continue
        literal = waiver.get("literal")
        if literal and str(literal) not in line:
            continue
        return waiver
    return None


def check_hardcode(root: Path) -> list[str]:
    """Эвристики захардкоженных URL и абсолютных home-путей в .py.

    URL ловятся в двух формах: внешний хост с точкой в домене; и внутренний
    стенд вида scheme + host + двоеточие + порт без точки (иначе адреса стендов
    проскакивают мимо no-hardcode). Пропускаются: docstring'и/многострочные
    строки (документация, не значения) и doc-конфиги (`conf.py`, `docs/`).
    Примеры и объяснение — в NO_HARDCODE_POLICY (таксономия НСИ/конфиг/константа).
    """
    out: list[str] = []
    waivers, waiver_problems = load_hardcode_waivers(root)
    out.extend(waiver_problems)
    used: set[str] = set()
    waived = 0
    url_re = re.compile(r"https?://[\w.\-]+\.[a-z]")
    url_port_re = re.compile(r"https?://[\w\-]+:\d+")
    abs_re = re.compile(r"(/Users/|/home/)\w")
    # XML/RDF namespace URI — идентификатор, а не сетевой endpoint: код его не
    # запрашивает, вынести в config нельзя (урок раскатки automation_server, v2.9.39)
    ns_re = re.compile(r"https?://(www\.)?(w3\.org|purl\.org|xmlns\.com|"
                       r"schemas\.(xmlsoap|openxmlformats)\.org|docbook\.org|ns\.adobe\.com)/")
    # Значение по умолчанию у ИМЕНОВАННОГО ключа конфигурации — это и есть
    # конфиг-поверхность, а не её отсутствие: вызывающий вправе передать своё,
    # окружение — переопределить. Правило требует «вынести в config/env»;
    # значение, которое УЖЕ там, требованию удовлетворяет.
    #
    # До v2.9.164 освобождался только localhost (v2.9.36), поэтому боевой адрес
    # в словаре умолчаний окружения читался как захардкоженный. Находка
    # онбординга BestPrice: 7 из 20 остатков были такими.
    #
    # Форма узкая намеренно: ключ рядом со значением. Голая константа модуля и
    # умолчание безымянного параметра остаются находками — у них нет точки
    # переопределения, названной по имени.
    keyed_default_re = re.compile(
        r"""(?:get|getenv)\s*\(\s*["'][A-Za-z_][\w.]*["']\s*,\s*["']https?://"""
        r"""|["'][A-Z][A-Z0-9_]{2,}["']\s*:\s*["']https?://""")
    # семантические скипы hardcode поверх общей скан-границы: фикстуры и схемы
    extra = frozenset({"tests", "test", "examples", "schemas"})
    for f, rel in _iter_files(root, ".py", extra):
        # doc-конфиг (Sphinx conf.py, файлы под docs/) — не бизнес-код
        if f.name == "conf.py" or "docs" in rel.parts:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        lines = text.splitlines()
        doc_lines = _doc_string_lines(text)
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("#") or n in doc_lines:
                continue
            # отрезаем inline-комментарий: URL в комментарии — документация,
            # не значение (урок пилота RAG, v2.9.37); '#' внутри строки-литерала
            # определяем по чётности кавычек слева
            hash_pos = line.find("#")
            if hash_pos > 0:
                left = line[:hash_pos]
                if left.count('"') % 2 == 0 and left.count("'") % 2 == 0:
                    line = left
            m = url_re.search(line) or url_port_re.search(line)
            # localhost/127.0.0.1 — легитимный dev-дефолт конфиг-поверхности
            # (os.getenv("X", "http://localhost:8765") и т.п.) — урок пилота qai, v2.9.36;
            # namespace-URI — идентификатор, не endpoint (v2.9.39)
            if (m and not re.search(r"https?://(localhost|127\.0\.0\.1)", line)
                    and not ns_re.search(line) and not keyed_default_re.search(line)):
                waiver = _waiver_for(waivers, rel.as_posix(), line)
                if waiver is None:
                    out.append(f"{rel}:{n}: захардкоженный URL — вынести в config/env (эвристика)")
                else:
                    waived += 1
                    used.add(str(waiver["waiver_id"]))
            if abs_re.search(line):
                waiver = _waiver_for(waivers, rel.as_posix(), line)
                if waiver is None:
                    out.append(f"{rel}:{n}: абсолютный путь — вынести в config (эвристика)")
                else:
                    waived += 1
                    used.add(str(waiver["waiver_id"]))
    # Сужение не бывает молчаливым. Счёт закрытого — сообщение, а не нарушение:
    # объявленное исключение работает, и падать на нём незачем. Исключение,
    # не совпавшее ни с чем, — предупреждение: оно либо описывает уже
    # исправленное, либо содержит ошибку в пути, и оба случая — гниль.
    if waived:
        print(f"APS_HARDCODE_WAIVERS_APPLIED: закрыто находок {waived}, "
              f"задействовано записей {len(used)} из {len(waivers)}")
    for waiver in waivers:
        if str(waiver["waiver_id"]) not in used:
            out.append(f"{WARN_PREFIX}hardcode: исключение {waiver['waiver_id']} не совпало "
                       f"ни с одной находкой — устарело либо ошибка в пути {waiver['path']!r}")
    return out


def _path_escapes_root(root: Path, rel_path: str) -> bool:
    """True, если `rel_path` абсолютен или (после resolve()) выходит за пределы `root`.

    P1 внешнего ревью v2.9.101, репродуцировано: check_test_runner/
    check_test_coverage/check_user_functions резолвили путь через
    `root / rel_path` и проверяли `.exists()` — но у `pathlib.Path.__truediv__`
    абсолютный правый операнд ПОЛНОСТЬЮ отбрасывает левый (`Path("/a") /
    "/b/c" == Path("/b/c")`), так что абсолютный путь в registry тихо
    проверялся сам по себе, а не относительно `root`. Раннеры
    (run_user_function_tests.py/verify_test_coverage.py) уже отклоняют такие
    пути fail-closed (`PathEscapesProjectError`/`UnsafeTestRefError`) — до
    этой правки строгая статическая проверка могла PASS конфигурацию,
    которую рантайм-инструмент тут же REJECT, создавая ложное чувство
    безопасности от "strict validation passed". Та же логика, что и в
    рантайм-инструментах: пустой/NUL/абсолютный путь или `..`-эскейп
    (включая через symlink) — эскейп."""
    if not rel_path or "\x00" in rel_path:
        return True
    candidate = Path(rel_path.replace("\\", "/"))
    if candidate.is_absolute():
        return True
    resolved_root = root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        return True
    return False


# v2.9.121 (P1 внешнего аудита v2.9.120, репродуцировано напрямую):
# work_package_graph.json[].id / active_work_packages.json.active[].task_id /
# agent_task_contract.task_id были ограничены только type:string,
# minLength:1 в схемах — ЛЮБАЯ строка проходила, включая "../../outside".
# graph.status=DONE строит путь `agent_results/<id>.json` напрямую из id
# (f-строкой) — id="../../outside" + существующий docs/outside.json с
# {"status": "COMPLETED"} на диске резолвился ВНЕ agent_results/ и
# check_agent_workflow_integrity() не находил ни одной проблемы (DONE
# считался подтверждённым чужим/произвольным файлом). Единый безопасный
# паттерн для всех трёх ID — без "/" в теле паттерна traversal/абсолютные
# пути невозможны в принципе, не только там, где резолвится реальный путь
# на диске (то же верно для git-show rel_path в check_active_task_diff -
# без "/" нельзя выйти за пределы предполагаемого поддерева и там).
_SAFE_REGISTRY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _registry_ids(root: Path, name: str):
    f = root / "docs" / "registry" / name
    if not f.exists():
        return None
    data, _ = load_json(f)
    if not isinstance(data, list):
        return set()
    ids: set = set()
    for it in data:
        if not isinstance(it, dict):
            continue
        for key in ("symbol", "command", "field", "variable"):
            if isinstance(it.get(key), str):
                ids.add(it[key])
        # уникальные формы для однозначной ссылки из user_functions
        if isinstance(it.get("id"), str):
            ids.add(it["id"])
        if isinstance(it.get("symbol"), str) and isinstance(it.get("path"), str):
            ids.add(f"{it['path']}::{it['symbol']}")
        if isinstance(it.get("method"), str) and isinstance(it.get("path"), str):
            ids.add(f"{it['method']} {it['path']}")
    return ids


COMMAND_CATALOG_PATH = Path("docs/registry/command_catalog.json")


def _command_catalog_names(root: Path) -> set[str] | None:
    """Имена команд продукта, или None — если каталога нет.

    None и пустое множество различаются намеренно. Отсутствие каталога значит
    «продукт свой командный слой не объявил», и ссылку проверить не по чему;
    пустой каталог значит «команд нет», и любая ссылка на команду неверна.
    Свести их в одно означало бы молча пропускать первый случай — ровно тот
    класс, что уже ловили как «зелёная проверка ≠ нарушений нет».
    """
    path = root / COMMAND_CATALOG_PATH
    if not path.is_file():
        return None
    data, err = load_json(path)
    if err or not isinstance(data, dict):
        return set()
    commands = data.get("commands")
    if not isinstance(commands, list):
        return set()
    return {
        item["name"]
        for item in commands
        if isinstance(item, dict) and isinstance(item.get("name"), str) and item["name"]
    }


def _check_assistant_entry_points(root: Path, uf: dict, tag: str) -> list[str]:
    """Ссылка kind=assistant обязана называть команду из каталога продукта.

    Без этой сверки `entry_points` остаётся обещанием: поле объявлено, форма
    задана, а указывать оно может куда угодно. Помощник, читающий реестр,
    узнает об опечатке только в момент вызова.
    """
    entry_points = uf.get("entry_points")
    if not isinstance(entry_points, list):
        return []
    refs = [
        item.get("ref")
        for item in entry_points
        if isinstance(item, dict) and item.get("kind") == "assistant"
    ]
    refs = [ref for ref in refs if isinstance(ref, str) and ref]
    if not refs:
        return []
    names = _command_catalog_names(root)
    if names is None:
        return [
            f"{tag}: entry_points ссылается на команды помощника "
            f"({', '.join(sorted(refs))}), но нет {COMMAND_CATALOG_PATH}"
        ]
    return [
        f"{tag}: команды {ref!r} нет в {COMMAND_CATALOG_PATH}"
        for ref in sorted(refs)
        if ref not in names
    ]


def check_user_function_interfaces(root: Path) -> list[str]:
    """Обе двери у ACTIVE-функции: визуальная и через помощника.

    Проверка отключена по умолчанию и включается флагом. Правило «две двери»
    верно для решений этой экосистемы, но пакет уезжает и в библиотеки, и в
    инструменты командной строки, у которых визуального интерфейса нет
    законно. Делать его всеобщим значило бы объявить нарушением нормальный
    проект — см. урок о строгой проверке, сломавшей собственный эталон.
    """
    path = root / "docs" / "registry" / "user_functions.json"
    if not path.is_file():
        return [f"нет {path.relative_to(root)}"]
    data, err = load_json(path)
    if err:
        return [f"битый user_functions.json: {err}"]
    if not isinstance(data, list):
        return ["user_functions.json: ожидался массив"]
    out: list[str] = []
    for index, uf in enumerate(data):
        if not isinstance(uf, dict) or uf.get("status") != "ACTIVE":
            continue
        tag = f"user_functions.json[{index}]" + (f" ({uf['id']})" if isinstance(uf.get("id"), str) else "")
        kinds = {
            item.get("kind")
            for item in (uf.get("entry_points") or [])
            if isinstance(item, dict)
        }
        for required, human in (("ui", "визуальная"), ("assistant", "через помощника")):
            if required not in kinds:
                out.append(f"{tag}: ACTIVE без двери «{human}» (entry_points kind={required})")
    return out


def check_user_functions(root: Path, schemas_root_arg: str | None) -> list[str]:
    f = root / "docs" / "registry" / "user_functions.json"
    if not f.exists():
        return ["нет docs/registry/user_functions.json"]
    data, err = load_json(f)
    if err:
        return [f"битый user_functions.json: {err}"]
    out: list[str] = []
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "user_functions.schema.json").exists():
        sch, _ = load_json(schemas_root / "user_functions.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "user_functions.json"))
    if not isinstance(data, list):
        return out + ["user_functions.json: ожидался массив"]
    reg_map = {"functions": "functions.json", "endpoints": "endpoints.json",
               "cli_commands": "cli_commands.json", "config_fields": "config_fields.json",
               "env_vars": "env_vars.json"}
    reg_ids = {k: _registry_ids(root, v) for k, v in reg_map.items()}
    seen: set = set()
    for i, uf in enumerate(data):
        if not isinstance(uf, dict):
            continue
        uid = uf.get("id")
        tag = f"user_functions.json[{i}]" + (f" ({uid})" if uid else "")
        # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано): нестроковый
        # id (list/dict) ронял TypeError на seen.add() — unhashable type.
        # Схема уже флагует неверный тип отдельной находкой; здесь только
        # предотвращаем краш, не дублируем сообщение.
        if isinstance(uid, str) and uid:
            if uid in seen:
                out.append(f"{tag}: дублирующийся id")
            seen.add(uid)
        if uf.get("status") == "ACTIVE":
            if not (uf.get("manual_steps") or uf.get("automation")):
                out.append(f"{tag}: ACTIVE без manual_steps/automation")
            for req in ("expected_result", "related_code", "regression_policy"):
                if not uf.get(req):
                    out.append(f"{tag}: ACTIVE без {req}")
        if uf.get("priority") == "critical":
            if not ({"smoke", "regression"} & set(uf.get("tags") or [])):
                out.append(f"{tag}: critical без tag smoke/regression")
        out.extend(_check_assistant_entry_points(root, uf, tag))
        # v2.9.103 (P1 внешнего ревью v2.9.102, репродуцировано): `related_code`
        # строкой (не списком) итерировался посимвольно — каждый символ строки
        # тоже строка, `isinstance(p, str)` его пропускал дальше как валидный
        # путь (ложные "related_code не найден" на каждую букву). `automation`
        # нестроковым/нестроковым типом (например строкой "bad") ронял
        # `AttributeError: 'str' object has no attribute 'get'` на
        # `.get("test_refs")` — строгий статический валидатор обязан вернуть
        # список нарушений, а не упасть с traceback на пользовательском JSON.
        # Type guard ПЕРЕД обходом, не после. То же для related_registry.
        related_code = uf.get("related_code")
        if related_code is not None and not isinstance(related_code, list):
            out.append(f"{tag}: related_code должен быть списком строк, получено "
                       f"{type(related_code).__name__}")
        else:
            for p in (related_code or []):
                if not isinstance(p, str):
                    continue
                if _path_escapes_root(root, p):
                    out.append(f"{tag}: related_code выходит за пределы проекта: {p}")
                elif not (root / p).exists():
                    out.append(f"{tag}: related_code не найден: {p}")
        automation = uf.get("automation")
        if automation is not None and not isinstance(automation, dict):
            out.append(f"{tag}: automation должен быть объектом, получено "
                       f"{type(automation).__name__}")
        else:
            for p in ((automation or {}).get("test_refs") or []):
                if not isinstance(p, str):
                    continue
                # pytest node id (path::test_x) обрезается до пути файла — та же
                # нормализация, что и check_test_coverage (p.split("::")[0]);
                # раньше буквальный exists() на "path::test_x" отклонял валидный
                # node id, который run_user_function_tests.py и без того умеет
                # запускать (P1 внешнего ревью v2.9.98, репродуцировано —
                # runtime-инструмент PASS, статический валидатор FAIL)
                file_part = p.split("::", 1)[0]
                # v2.9.102 (P1 внешнего ревью v2.9.101): та же граница --root,
                # что run_user_function_tests.py уже применяет к test_ref
                # (см. _path_escapes_root) — иначе абсолютный/эскейпящий путь
                # тихо проходил статическую строгую проверку.
                if _path_escapes_root(root, file_part):
                    out.append(f"{tag}: test_ref выходит за пределы проекта: {p}")
                elif not (root / file_part).exists():
                    out.append(f"{tag}: test_ref не найден: {p}")
        related_registry = uf.get("related_registry")
        if related_registry is not None and not isinstance(related_registry, dict):
            out.append(f"{tag}: related_registry должен быть объектом, получено "
                       f"{type(related_registry).__name__}")
        else:
            rr = related_registry or {}
            for k, name in reg_map.items():
                ids = reg_ids.get(k)
                if ids is None:
                    continue
                for ref in (rr.get(k) or []):
                    if isinstance(ref, str) and ref not in ids:
                        out.append(f"{tag}: {k} ref не найден в {name}: {ref}")
    return out


def check_project_snapshot(root: Path, schemas_root_arg: str | None, profile: str) -> list[str]:
    out: list[str] = []
    if not (root / "docs" / "PROJECT_SNAPSHOT.md").exists():
        out.append("нет docs/PROJECT_SNAPSHOT.md")
    js = root / "docs" / "registry" / "project_snapshot.json"
    if not js.exists():
        return out + ["нет docs/registry/project_snapshot.json"]
    data, err = load_json(js)
    if err:
        return out + [f"битый project_snapshot.json: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "project_snapshot.schema.json").exists():
        sch, _ = load_json(schemas_root / "project_snapshot.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "project_snapshot.json"))
    if not isinstance(data, dict):
        return out
    uf_ids: set = set()
    uff = root / "docs" / "registry" / "user_functions.json"
    if uff.exists():
        ufd, _ = load_json(uff)
        if isinstance(ufd, list):
            uf_ids = {u.get("id") for u in ufd if isinstance(u, dict)}
    for key in ("critical_user_functions", "must_not_break"):
        for ref in (data.get(key) or []):
            if uf_ids and ref not in uf_ids:
                out.append(f"project_snapshot.json: {key} '{ref}' нет в user_functions.json")
    expected = {"ru_internal": "ТЗ", "en_public": "specs"}
    lp = data.get("language_profile", profile)
    sd = data.get("spec_dir", "")
    if lp in expected and sd and not sd.rstrip("/").endswith(expected[lp]):
        out.append(f"project_snapshot.json: spec_dir '{sd}' не соответствует профилю {lp}")
    return out


def check_test_runner(root: Path, schemas_root_arg: str | None) -> list[str]:
    f = root / "docs" / "registry" / "test_runner.json"
    if not f.exists():
        return ["нет docs/registry/test_runner.json (рантайм-контракт для внешнего контролёра)"]
    data, err = load_json(f)
    if err:
        return [f"битый test_runner.json: {err}"]
    out: list[str] = []
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "test_runner.schema.json").exists():
        sch, _ = load_json(schemas_root / "test_runner.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "test_runner.json"))
    if not isinstance(data, dict):
        return out
    reg = data.get("registry")
    if isinstance(reg, str):
        # v2.9.102 (P1 внешнего ревью v2.9.101): та же граница --root, что
        # run_user_function_tests.py уже применяет к registry — иначе
        # абсолютный/эскейпящий путь тихо проходил статическую строгую
        # проверку, хотя рантайм-инструмент его бы отклонил (см. _path_escapes_root).
        if _path_escapes_root(root, reg):
            out.append(f"test_runner.json: registry выходит за пределы проекта: {reg}")
        elif not (root / reg).exists():
            out.append(f"test_runner.json: registry не найден: {reg}")
    env_list = set(data.get("env") or [])
    ph = re.compile(r"\$\{([A-Z0-9_]+)\}")
    base = data.get("base") or {}
    if isinstance(base, dict):
        for k, v in base.items():
            if not isinstance(v, str):
                continue
            if re.search(r"https?://", v):
                out.append(f"test_runner.json: base.{k} содержит захардкоженный URL — используй ${{ENV}}")
            for var in ph.findall(v):
                if var not in env_list:
                    out.append(f"test_runner.json: base.{k} ссылается на ${{{var}}}, которого нет в env[]")
    return out


# --- раскладка проекта, точки входа, размер файлов, язык кода (v2.9.14) ---
def _packages(root: Path) -> list[Path]:
    src = root / "src"
    if not src.is_dir():
        return []
    return [d for d in sorted(src.iterdir()) if d.is_dir() and (d / "__init__.py").exists()]


def _mentions(root: Path, needle: str, files: tuple[str, ...]) -> bool:
    for name in files:
        f = root / name
        if f.exists() and needle in f.read_text(encoding="utf-8", errors="ignore"):
            return True
    return False


def _is_python_package_project(root: Path) -> bool:
    """Проект — Python-пакет, если есть манифест пакета или корень исходников.
    Промпт/док-пак с парой утилитных скриптов (scripts/, tools/) пакетом НЕ считается
    (урок раскатки Network_AI, v2.9.39): к нему не применяются pyproject/src."""
    if any((root / m).exists() for m in ("pyproject.toml", "setup.py", "setup.cfg")):
        return True
    if any((root / d).is_dir() for d in ("src", "modules", "packages")):
        return True
    return False


def check_project_layout(root: Path) -> list[str]:
    out: list[str] = []
    for name in ("README.md", "AGENTS.md"):
        if not (root / name).exists():
            out.append(f"project-layout: нет {name} (PROJECT_LAYOUT_STANDARD)")
    for d in ("docs", "docs/registry"):
        if not (root / d).is_dir():
            out.append(f"project-layout: нет директории {d}/ (PROJECT_LAYOUT_STANDARD)")
    if not _is_python_package_project(root):
        return out  # промпт/док-пак — pyproject/src/tests-как-пакет не требуются
    if not (root / "pyproject.toml").exists():
        out.append("project-layout: нет pyproject.toml (PROJECT_LAYOUT_STANDARD)")
    if not (root / "tests").is_dir():
        out.append("project-layout: нет директории tests/ (PROJECT_LAYOUT_STANDARD)")
    # корень исходников: src/ — канон; modules/ и packages/ — монорепо-альтернативы
    # (урок qai); плоская раскладка — top-level каталог с __init__.py (пакет прямо
    # в корне: app/, core/, … — урок раскатки automation_server, v2.9.39)
    has_src = any((root / d).is_dir() for d in ("src", "modules", "packages"))
    has_flat_pkg = any(
        p.is_dir() and not p.name.startswith(".") and (p / "__init__.py").exists()
        for p in root.iterdir()
    )
    if not has_src and not has_flat_pkg:
        out.append("project-layout: нет корня исходников src/ (modules/, packages/ или top-level пакета) (PROJECT_LAYOUT_STANDARD)")
    if not (root / "configs").is_dir() and not _mentions(root, "configs", ("README.md", "docs/PROJECT_SNAPSHOT.md")):
        out.append("project-layout: нет configs/ и нет объяснения в README.md/PROJECT_SNAPSHOT.md")
    return out


LAUNCH_SECTION_VERBS = {
    "ru_internal": frozenset({"запуск", "тесты", "проверка", "сборка"}),
    "en_public": frozenset({"run", "test", "check", "build"}),
}
CANONICAL_RUN_WRAPPERS = frozenset({"run.sh", "run.cmd", "run.ps1"})
RUN_WRAPPER_RE = re.compile(
    r"(?i)([A-Za-z0-9_.-]+\.(?:sh|cmd|ps1|bat))(?=$|[\s`\"'<>])"
)
SINGLE_DASH_LONG_OPTION_RE = re.compile(
    r"(?<!\S)(-[A-Za-z][A-Za-z0-9_-]{2,})(?=$|[\s=])"
)
SLASH_OPTION_RE = re.compile(
    r"(?<!\S)(/[A-Za-z][A-Za-z0-9_-]{1,})(?=$|[\s:=])"
)


def _launch_command_contract(command: str) -> list[str]:
    """Проверить единое имя OS-обёртки и форму параметров запуска.

    Внутренние команды стека (`python -m`, `npm run`) остаются допустимыми.
    Но если основной запуск уже ссылается на shell/cmd/PowerShell-файл, его
    базовое имя одинаково во всём парке: run. Длинный параметр начинается с
    двух дефисов; один дефис оставлен однобуквенному псевдониму.
    """
    contract_part = re.split(r"(?<!\S)--(?=$|\s)", command, maxsplit=1)[0]
    out: list[str] = []
    for wrapper in RUN_WRAPPER_RE.findall(contract_part):
        if wrapper.lower() not in CANONICAL_RUN_WRAPPERS:
            out.append(
                f"раздел «Запуск»: файл запуска `{wrapper}` имеет неканоническое "
                "имя; используйте `run.sh`, `run.cmd` или `run.ps1`"
            )
    for option in SINGLE_DASH_LONG_OPTION_RE.findall(contract_part):
        out.append(
            f"раздел «Запуск»: длинный параметр `{option}` должен начинаться "
            "с `--`; короткий параметр содержит одну букву"
        )
    for option in SLASH_OPTION_RE.findall(contract_part):
        out.append(
            f"раздел «Запуск»: параметр `{option}` использует форму `/name`; "
            "используйте `--name value`"
        )
    return out


@enforces_rule("APS-CORE-ENTRYPOINTS-RUN-001")
@emits_diagnostic("APS-CORE-ENTRYPOINTS-RUN-001", "LAUNCH_COMMAND_CONTRACT_VALID")
@emits_diagnostic("APS-CORE-ENTRYPOINTS-RUN-001", "LAUNCH_WRAPPER_NAME_NONCANONICAL")
@emits_diagnostic("APS-CORE-ENTRYPOINTS-RUN-001", "LAUNCH_LONG_OPTION_NONCANONICAL")
def check_launch_section(root: Path, language_profile: str) -> list[str]:
    readme = root / "README.md"
    if not readme.exists():
        return ["раздел «Запуск»: в корне проекта нет README.md"]
    try:
        lines = readme.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError):
        return ["раздел «Запуск»: README.md должен читаться как UTF-8"]

    launch_index = next(
        (index for index, line in enumerate(lines) if line.strip() == "## Запуск"),
        None,
    )
    if launch_index is None:
        return ["раздел «Запуск»: в README.md нет раздела `## Запуск`"]

    section: list[str] = []
    for line in lines[launch_index + 1:]:
        if re.match(r"^#{1,2}(?:\s|$)", line):
            break
        section.append(line)

    main_index = next(
        (index for index, line in enumerate(section) if line.strip() == "Основной запуск:"),
        None,
    )
    if main_index is None:
        return ["раздел «Запуск»: нет строки `Основной запуск:`"]

    command = ""
    in_comment = False
    for line in section[main_index + 1:]:
        stripped = line.strip()
        if stripped.startswith("<!--"):
            in_comment = "-->" not in stripped
            continue
        if in_comment:
            if "-->" in stripped:
                in_comment = False
            continue
        if not stripped or stripped.startswith("```"):
            continue
        if stripped == "Дополнительно:" or stripped.startswith("- "):
            break
        command = stripped
        break
    if not command or command == "<command>":
        return ["раздел «Запуск»: после `Основной запуск:` нужна непустая команда"]

    if language_profile == "mixed":
        allowed_verbs = set().union(*LAUNCH_SECTION_VERBS.values())
    else:
        allowed_verbs = LAUNCH_SECTION_VERBS[language_profile]

    out: list[str] = _launch_command_contract(command)
    in_comment = False
    in_fence = False
    in_additional = False
    label_re = re.compile(r"^([^:`]+?)(?:\s+\([^)]+\))?:\s*.*$")
    for raw_line in section:
        stripped = raw_line.strip()
        if stripped.startswith("<!--"):
            in_comment = "-->" not in stripped
            continue
        if in_comment:
            if "-->" in stripped:
                in_comment = False
            continue
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or not stripped:
            continue
        if stripped == "Дополнительно:":
            in_additional = True
            continue
        is_list_item = stripped.startswith("- ")
        candidate = stripped[2:].strip() if is_list_item else stripped
        match = label_re.fullmatch(candidate)
        if not match or candidate == "Основной запуск:":
            continue
        verb = match.group(1).strip()
        if verb in allowed_verbs:
            continue
        if in_additional and is_list_item:
            continue
        out.append(
            f"раздел «Запуск»: глагол `{verb}` не разрешён для профиля "
            f"`{language_profile}`; используйте табличный глагол или пункт списка "
            "после `Дополнительно:`"
        )
    return out


BIN_FORBIDDEN = re.compile(r"https?://|\.env\b|os\.environ|load_config|api_key|token|secret|passwd|password", re.I)


#: Разделы `docs/`, известные стандарту: обязательный минимум обоих профилей
#: плюс необязательные из DOCUMENTATION_STANDARD §2.1. Список открытый по
#: замыслу — раздел вне его не запрещён, он обязан быть объявлен в
#: `docs/README.md`.
KNOWN_DOCS_SECTIONS = frozenset({
    # ru_internal
    "БТ", "ТЗ", "Дизайн", "Инструкции_пользователя", "Инструкции_разработчика",
    "Отчеты", "Архив", "Презентации",
    # en_public
    "business_requirements", "specs", "design", "user", "dev", "reports",
    "archive", "presentation",
    # машинные слои, латиница в обоих профилях
    "registry", "audits", "memory",
})


def check_docs_sections_declared(root: Path) -> list[str]:
    """Каталог `docs/` вне известного списка объявлен в `docs/README.md`.

    Список разделов — минимальный скелет, а не белый список
    (DOCUMENTATION_STANDARD §2.1), поэтому проверка не запрещает новые
    разделы. Она закрывает другое: раздел, заведённый молча. Одна и та же
    потребность в презентационных материалах успела получить пять имён в
    четырёх проектах — `маркетинг/`, `marketing/`, `presentation/`, `demo/`,
    `demo_builder/`, — и ни одно не было названо в `docs/README.md`.

    Проверяется упоминание имени каталога в тексте `docs/README.md`, а не
    его форма: требовать таблицу значило бы диктовать вёрстку README, чего
    стандарт не делает нигде.
    """
    out: list[str] = []
    docs = root / "docs"
    if not docs.is_dir():
        return out
    readme = docs / "README.md"
    text = readme.read_text(encoding="utf-8", errors="ignore") if readme.is_file() else ""
    for entry in sorted(docs.iterdir()):
        if not entry.is_dir() or entry.name.startswith((".", "_")):
            continue
        if entry.name in KNOWN_DOCS_SECTIONS:
            continue
        if entry.name in text:
            continue
        if not readme.is_file():
            out.append(
                f"docs-sections: раздел docs/{entry.name}/ вне известного списка, "
                "а docs/README.md нет — объявить раздел там (DOCUMENTATION_STANDARD §2.1)"
            )
            continue
        out.append(
            f"docs-sections: раздел docs/{entry.name}/ не объявлен в docs/README.md "
            "— либо назвать его по таблице §2.1, либо объявить строкой о том, "
            "что в нём лежит и почему он заведён"
        )
    return out


def check_entrypoints(root: Path) -> list[str]:
    out: list[str] = []
    pkgs = _packages(root)
    pyproject = root / "pyproject.toml"
    has_scripts = pyproject.exists() and "[project.scripts]" in pyproject.read_text(encoding="utf-8", errors="ignore")
    has_main = any((p / "__main__.py").exists() for p in pkgs) or bool(list(_iter_tree(root, "__main__.py")))
    bin_dir = root / "bin"
    bin_launchers = bin_dir.is_dir() and any(p.is_file() for p in bin_dir.iterdir())
    # Библиотека (нет [project.scripts], нет __main__, нет bin/-launchers) не
    # обязана иметь CLI entrypoint — её импортируют, а не запускают. Калибровка
    # по 18 эталонам (v2.9.23): 12/13 «нет entrypoint» приходились на библиотеки.
    if not has_main and not has_scripts:
        if bin_launchers:
            out.append("entrypoints: есть bin/-launchers, но нет canonical entrypoint (python -m / [project.scripts])")
        # иначе — библиотека, entrypoint не требуется
    if bin_dir.is_dir():
        for f in sorted(bin_dir.iterdir()):
            if not f.is_file():
                continue
            text = f.read_text(encoding="utf-8", errors="ignore")
            body = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith(("#", "@echo", "rem", "::"))]
            rel = f.relative_to(root)
            if "-m " not in text and "python" not in text.lower():
                out.append(f"entrypoints: {rel} не вызывает canonical entrypoint (python -m ...)")
            if BIN_FORBIDDEN.search(text):
                out.append(f"entrypoints: {rel} содержит URL/секрет/config-loading — bin/ только thin wrapper")
            if any(re.match(r"\s*(def |class |for |while |import )", ln) for ln in body):
                out.append(f"entrypoints: {rel} содержит бизнес-логику — bin/ только thin wrapper")
            # POSIX-launcher (без расширения или .sh) с shebang должен быть исполняемым
            if f.suffix in ("", ".sh") and text.startswith("#!") and (f.stat().st_mode & 0o111) == 0:
                out.append(f"entrypoints: {rel} — POSIX launcher без executable bit (chmod +x)")
    return out


# SOURCE_FILE_STANDARD §1 «документированное исключение»: единый файл может
# осознанно превышать лимит, если разбиение противоречит его назначению
# (дистрибутивный tool без внешних зависимостей / файл с неразрывной
# построчной историей). v2.9.114 (P2 внешнего ревью v2.9.113): --check-
# file-size наконец подключается к release-gate (queued с v2.9.108) — оба
# исключения ниже задокументированы здесь И в собственной шапке файла (там,
# где применимо) И в README, как того требует стандарт — не тихая лазейка.
_FILE_SIZE_EXEMPT_PY = frozenset({
    "tools/validate_structure.py",     # единый бездепенденсный валидатор
    "tools/run_user_function_tests.py",  # единый бездепенденсный раннер, тот же класс
})
_FILE_SIZE_EXEMPT_MD = frozenset({
    "CHANGELOG.md",  # накопительная построчная история с v2.5 — не документация текущих правил, дробление стирало бы аудит-трейл
    "STANDARD_GUIDE_FOR_HUMANS.md",  # единый non-normative human navigator; splitting defeats the requested one-document entrypoint
})
_RELEASE_NOTES_FILE_RE = re.compile(r"^RELEASE_NOTES_v\d+_\d+\.md$")


def check_file_size(root: Path) -> list[str]:
    # семантический скип поверх общей скан-границы: тесты меряются по своему
    # лимиту в другом месте, здесь не шумим на них
    extra = frozenset({"tests", "test", "examples"})
    out: list[str] = []
    for f, rel in _iter_files(root, ".py", extra):
        if rel.as_posix() in _FILE_SIZE_EXEMPT_PY:
            continue
        try:
            src = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        n = len(src.splitlines())
        if n > 800:
            out.append(f"file-size: {rel}: {n} строк > hard limit 800 — предложи разбиение (SOURCE_FILE_STANDARD)")
        tree = parse_python(f)
        if tree is None:
            continue
        for node in ast.walk(tree):
            end = getattr(node, "end_lineno", None)
            if end is None:
                continue
            span = end - node.lineno + 1
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and span > 120:
                out.append(f"file-size: {rel}:{node.lineno}: функция {node.name}() {span} строк > 120")
            elif isinstance(node, ast.ClassDef) and span > 500:
                out.append(f"file-size: {rel}:{node.lineno}: класс {node.name} {span} строк > 500")
    for f, rel in _iter_files(root, ".md", extra):
        if rel.as_posix() in _FILE_SIZE_EXEMPT_MD or _RELEASE_NOTES_FILE_RE.fullmatch(rel.as_posix()):
            continue
        try:
            n = len(f.read_text(encoding="utf-8", errors="ignore").splitlines())
        except OSError:
            continue
        if n > 900:
            out.append(f"{WARN_PREFIX}file-size: {rel}: {n} строк > 900 — вынеси раздел")
    return out


ENV_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")
KEY_RE = re.compile(r"^[a-z][a-z0-9_]*$")
UID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
SECTION_BANNER = re.compile(r"^\s*#\s*=")
CYRILLIC = re.compile(r"[А-Яа-яЁё]")


def check_code_language(root: Path, profile: str) -> list[str]:
    out: list[str] = []
    src = root / "src"
    if src.is_dir():
        for f in src.rglob("*.py"):
            if not f.name.isascii():
                out.append(f"code-language: имя Python-файла не ASCII: {f.relative_to(root)}")
        for d in src.rglob("*"):
            if d.is_dir() and (d / "__init__.py").exists() and not d.name.isascii():
                out.append(f"code-language: имя пакета не ASCII: {d.relative_to(root)}")
        if profile == "ru_internal":
            for f in src.rglob("*.py"):
                tree = parse_python(f)
                if tree is None:
                    continue
                for node in ast.walk(tree):
                    name = getattr(node, "name", None)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and name and not name.isascii():
                        out.append(f"code-language: идентификатор не ASCII: {name!r} в {f.relative_to(root)}")
        if profile == "en_public":
            # русский текст в комментариях/секционных заголовках src — soft warning;
            # один сигнал на файл (первая строка-комментарий с кириллицей)
            for f in src.rglob("*.py"):
                for i, line in enumerate(f.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                    if line.lstrip().startswith("#") and CYRILLIC.search(line):
                        out.append(f"{WARN_PREFIX}code-language: русский комментарий/заголовок в en_public: {f.relative_to(root)}:{i}")
                        break
    env_data, _ = load_json(root / "docs" / "registry" / "env_vars.json") if (root / "docs" / "registry" / "env_vars.json").exists() else (None, None)
    if isinstance(env_data, list):
        for it in env_data:
            v = it.get("variable") if isinstance(it, dict) else None
            if isinstance(v, str) and not ENV_RE.match(v):
                out.append(f"code-language: env var не UPPER_SNAKE: {v}")
    cfg_data, _ = load_json(root / "docs" / "registry" / "config_fields.json") if (root / "docs" / "registry" / "config_fields.json").exists() else (None, None)
    if isinstance(cfg_data, list):
        for it in cfg_data:
            v = it.get("field") if isinstance(it, dict) else None
            if isinstance(v, str) and not KEY_RE.match(v.split(".")[-1]):
                out.append(f"code-language: config key не snake_case: {v}")
    uf_data, _ = load_json(root / "docs" / "registry" / "user_functions.json") if (root / "docs" / "registry" / "user_functions.json").exists() else (None, None)
    if isinstance(uf_data, list):
        for it in uf_data:
            v = it.get("id") if isinstance(it, dict) else None
            if isinstance(v, str) and not UID_RE.match(v):
                out.append(f"code-language: user_function id не ASCII dot/kebab/snake: {v}")
    return out


def check_best_style(root: Path, profile: str, schemas_root_arg: str | None) -> list[str]:
    """Агрегатор инженерного стиля: layout + entrypoints + file-size +
    code-language + hardcode + user-functions + project-snapshot + test-runner
    (без дублей). Runtime-контракт контролёра (`test_runner.json`) входит в набор:
    без него human-like regression неполна (BEST_ENGINEERING_STYLE/QUALITY_GATES)."""
    out: list[str] = []
    out += check_project_layout(root)
    out += check_entrypoints(root)
    out += check_file_size(root)
    out += check_code_language(root, profile)
    out += check_hardcode(root)
    out += check_user_functions(root, schemas_root_arg)
    out += check_project_snapshot(root, schemas_root_arg, profile)
    out += check_test_runner(root, schemas_root_arg)
    # public CLI есть в коде, но cli_commands.json пуст/отсутствует
    cli_f = root / "docs" / "registry" / "cli_commands.json"
    cli_data, _ = load_json(cli_f) if cli_f.exists() else (None, None)
    cli_empty = not isinstance(cli_data, list) or len(cli_data) == 0
    src = root / "src"
    uses_cli = src.is_dir() and any(
        re.search(r"argparse|import click|import typer|add_argument", f.read_text(encoding="utf-8", errors="ignore"))
        for f in src.rglob("*.py")
    )
    if uses_cli and cli_empty:
        out.append("best-style: код использует CLI (argparse/click/typer), но cli_commands.json пуст/отсутствует")
    seen: set[str] = set()
    deduped: list[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


# --- память паттернов: repository-based learning loop (v2.9.18) ---
def _first_existing(root: Path, rels: tuple[str, ...]) -> Path | None:
    for rel in rels:
        if (root / rel).exists():
            return root / rel
    return None


def _pattern_card_names(path: Path, heading_prefix: str) -> list[str]:
    """Имена карточек (`# Pattern: <имя>` / `# Anti-pattern: <имя>`) в файле.
    Пустой список — файл существует, но не содержит ни одной карточки (v2.9.91,
    P1 внешнего ревью v2.9.90: полностью очищенные SUCCESS_PATTERNS.md/
    ANTI_PATTERNS.md проходили --check-pattern-memory молча)."""
    names: list[str] = []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return names
    for line in text.splitlines():
        if line.startswith(heading_prefix):
            names.append(line[len(heading_prefix):].strip())
    return names


def check_pattern_memory(root: Path, schemas_root_arg: str | None) -> list[str]:
    out: list[str] = []
    success_names: list[str] = []
    anti_names: list[str] = []
    success_path = _first_existing(root, ("reference/SUCCESS_PATTERNS.md", "docs/SUCCESS_PATTERNS.md"))
    if success_path is None:
        out.append("pattern-memory: нет reference/SUCCESS_PATTERNS.md (LEARNING_LOOP_STANDARD)")
    else:
        success_names = _pattern_card_names(success_path, "# Pattern:")
        if not success_names:
            # warning, не error (v2.9.91): свежий проект легитимно начинает с
            # пустого файла-заготовки ("пока пусто: накапливается...") —
            # см. golden-эталон. Полностью очищенный ранее заполненный файл
            # (реальный репро-кейс внешнего ревью) всё равно виден под
            # --warnings-as-errors (release/CI-режим), просто не валит
            # обычный прогон на bootstrap-стадии проекта.
            out.append(f"{WARN_PREFIX}pattern-memory: {success_path.name} есть, но не "
                       f"содержит ни одной карточки (# Pattern: ...)")
    anti_path = _first_existing(root, ("reference/ANTI_PATTERNS.md", "docs/ANTI_PATTERNS.md"))
    if anti_path is None:
        out.append("pattern-memory: нет reference/ANTI_PATTERNS.md (LEARNING_LOOP_STANDARD)")
    else:
        anti_names = _pattern_card_names(anti_path, "# Anti-pattern:")
        if not anti_names:
            out.append(f"{WARN_PREFIX}pattern-memory: {anti_path.name} есть, но не "
                       f"содержит ни одной карточки (# Anti-pattern: ...)")
    reg = root / "docs" / "registry" / "engineering_patterns.json"
    if not reg.exists():
        return out  # машинный реестр опционален
    data, err = load_json(reg)
    if err:
        return out + [f"битый engineering_patterns.json: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "engineering_patterns.schema.json").exists():
        sch, _ = load_json(schemas_root / "engineering_patterns.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "engineering_patterns.json"))
    if not isinstance(data, list):
        return out + ["engineering_patterns.json: ожидался массив"]
    seen: set = set()
    for i, p in enumerate(data):
        if not isinstance(p, dict):
            continue
        pid = p.get("id")
        tag = f"engineering_patterns.json[{i}]" + (f" ({pid})" if pid else "")
        # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано): нестроковый
        # id (list/dict) ронял TypeError на seen.add() — unhashable type.
        if isinstance(pid, str) and pid:
            if pid in seen:
                out.append(f"{tag}: дублирующийся id")
            seen.add(pid)
        if p.get("status") in ("APPROVED", "RECOMMENDED"):
            for req in ("id", "problem", "solution", "good_example", "applies_to", "enforcement_refs"):
                if not p.get(req):
                    out.append(f"{tag}: {p.get('status')} без {req}")
            if not (p.get("bad_example") or p.get("forbidden_example")):
                out.append(f"{tag}: {p.get('status')} без bad_example/forbidden_example")
        for ref in (p.get("enforcement_refs") or []):
            if isinstance(ref, str) and not (root / ref).exists():
                out.append(f"{tag}: enforcement_ref не найден: {ref}")
        # v2.9.91 (P2 внешнего ревью v2.9.90): расхождение Markdown <-> JSON —
        # APPROVED/RECOMMENDED/FORBIDDEN запись обязана иметь свою карточку
        # (# Pattern: <id> / # Anti-pattern: <id>) в соответствующем .md
        if isinstance(pid, str) and p.get("status") in ("APPROVED", "RECOMMENDED", "FORBIDDEN"):
            if p.get("kind") == "success" and success_path is not None and pid not in success_names:
                out.append(f"{tag}: нет карточки '# Pattern: {pid}' в {success_path.name} "
                           f"(engineering_patterns.json и Markdown разошлись)")
            elif p.get("kind") == "anti" and anti_path is not None and pid not in anti_names:
                out.append(f"{tag}: нет карточки '# Anti-pattern: {pid}' в {anti_path.name} "
                           f"(engineering_patterns.json и Markdown разошлись)")
    return out


# --- локальные markdown-ссылки (v2.9.21; v2.9.22 — path:line, скан-граница) ---
MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
MD_LINE_SUFFIX_RE = re.compile(r":\d+$")


def check_markdown_links(root: Path) -> list[str]:
    """Проверяет, что локальные относительные markdown-ссылки резолвятся.

    Внешние (`http(s)://`, `mailto:` и т.п.), якоря (`#...`) и ссылки внутри
    fenced-блоков (```) пропускаются. Суффикс `:line` (кликабельный формат
    `файл:строка`) отбрасывается перед проверкой существования. Скан-граница —
    общая (`_iter_files`). Битая локальная ссылка — ошибка.
    """
    out: list[str] = []
    for f, rel in _iter_files(root, ".md"):
        try:
            lines = f.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        in_fence = False
        for n, line in enumerate(lines, 1):
            if line.lstrip().startswith("```"):
                in_fence = not in_fence
                continue
            if in_fence:
                continue
            for target in MD_LINK_RE.findall(line):
                # первый токен, снять markdown-автолинк-скобки <...> с любого края
                target = target.strip().split(" ")[0].strip("<>")
                if not target or target.startswith("#") or "://" in target or target.startswith("mailto:"):
                    continue
                if target.startswith("~") or target.startswith("/"):
                    continue  # home/absolute вне зоны проверки
                path_part = target.split("#", 1)[0].split("?", 1)[0]
                path_part = MD_LINE_SUFFIX_RE.sub("", path_part)  # снять :line
                if not path_part:
                    continue
                # ссылка валидна, если резолвится относительно md-файла ИЛИ
                # относительно корня репозитория (обе конвенции встречаются)
                if not (f.parent / path_part).exists() and not (root / path_part.lstrip("/")).exists():
                    out.append(f"{rel}:{n}: битая локальная ссылка: {target}")
    return out


# --- НСИ в коде: крупные литеральные справочники/прайсы вне reference/ (v2.9.23) ---
DATA_NAME_RE = re.compile(
    r"(?i)(price|прайс|цен[аы]|catalog|catalogue|каталог|synonym|синоним|"
    r"dictionary|словар|nomenclat|номенклат|tariff|тариф|товар|product_data|"
    r"reference_data|_data\b|_table\b|_catalog\b|_prices\b)"
)


def _data_shape(value: ast.AST) -> tuple[int, int]:
    """(число элементов, сколько из них record-like: dict/list/tuple/число)."""
    if isinstance(value, ast.Dict):
        vals = value.values
        rec = sum(1 for v in vals if isinstance(v, (ast.Dict, ast.List, ast.Tuple))
                  or (isinstance(v, ast.Constant) and isinstance(v.value, (int, float)) and not isinstance(v.value, bool)))
        return len(value.keys), rec
    if isinstance(value, ast.List):
        rec = sum(1 for e in value.elts if isinstance(e, (ast.Dict, ast.List, ast.Tuple)))
        return len(value.elts), rec
    return 0, 0


LOOP_MUTATING_METHODS = frozenset({
    "append", "extend", "insert", "remove", "pop", "clear",
    "add", "discard", "update", "popitem", "setdefault",
})


def _loop_mutations(loop: ast.For, name: str) -> list[tuple[int, str]]:
    """Мутации коллекции `name` внутри тела цикла, идущего прямо по ней."""
    found: list[tuple[int, str]] = []
    for node in ast.walk(loop):
        if node is loop.iter:
            continue
        # coll.append(...) и другие изменяющие методы
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            target = node.func.value
            if isinstance(target, ast.Name) and target.id == name \
                    and node.func.attr in LOOP_MUTATING_METHODS:
                found.append((node.lineno, f"{name}.{node.func.attr}()"))
        # del coll[...]
        elif isinstance(node, ast.Delete):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) \
                        and t.value.id == name:
                    found.append((node.lineno, f"del {name}[...]"))
        # coll[...] = ... — только присваивание в элемент, не чтение
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if isinstance(t, ast.Subscript) and isinstance(t.value, ast.Name) \
                        and t.value.id == name:
                    found.append((node.lineno, f"{name}[...] = ..."))
    return found


@enforces_rule("APS-LOOP-SAFE-MUTATION-001")
@emits_diagnostic("APS-LOOP-SAFE-MUTATION-001", "LOOP_MUTATION_DURING_ITERATION")
def check_loop_safe_mutation(root: Path) -> list[str]:
    """Коллекция не изменяется во время обхода её же самой.

    `CC-LOOP-SAFE-MUTATION` (Макконнелл, «Совершенный код»): изменение
    коллекции во время обхода требует явного безопасного контракта. Для
    list это молча пропускает элементы, для dict и set — `RuntimeError`
    прямо во время выполнения.

    Ловятся только достоверные случаи: цикл идёт по голому имени
    (`for x in items:`) и в теле то же имя изменяется. Явный безопасный
    контракт — копия (`list(items)`, `items.copy()`), обход по индексам
    (`range(len(items))`) или сбор нового списка — под проверку не
    попадает: там `iter` не голое имя, а вызов.
    """
    out: list[str] = []
    for f, rel in _iter_files(root, ".py"):
        tree = parse_python(f)
        if tree is None:
            continue
        for loop in ast.walk(tree):
            if not isinstance(loop, ast.For) or not isinstance(loop.iter, ast.Name):
                continue
            for lineno, what in _loop_mutations(loop, loop.iter.id):
                out.append(
                    f"loop-safe-mutation: {rel}:{lineno}: {what} изменяет коллекцию "
                    f"`{loop.iter.id}` во время обхода её же самой (цикл в строке "
                    f"{loop.lineno}) — нужен явный безопасный контракт: копия "
                    f"`list({loop.iter.id})`, обход по индексам или сбор нового "
                    f"списка (CC-LOOP-SAFE-MUTATION)"
                )
    return out


def check_data_in_code(root: Path) -> list[str]:
    """Эвристика: крупная литеральная структура данных в .py вне reference/.

    Справочники, прайс-листы, каталоги, словари синонимов — доменные данные (НСИ),
    их правит человек, не программист; они не должны быть зашиты в код (даже в
    constants.py). См. NO_HARDCODE_POLICY, REFERENCE_DATA_STANDARD. Warning:
    эвристика неполная (плоские str→str словари без говорящего имени не ловятся).
    """
    out: list[str] = []
    extra = frozenset({"tests", "test", "examples", "schemas", "reference"})
    for f, rel in _iter_files(root, ".py", extra):
        tree = parse_python(f)
        if tree is None:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            name = " ".join(t.id for t in targets if isinstance(t, ast.Name))
            n_elems, recordish = _data_shape(node.value)
            if n_elems < 20:
                continue
            looks_data = recordish >= n_elems * 0.5 or bool(DATA_NAME_RE.search(name)) or bool(DATA_NAME_RE.search(f.name))
            if looks_data:
                label = name or "литерал"
                out.append(f"{WARN_PREFIX}data-in-code: {rel}:{node.lineno}: {label} — крупная структура данных "
                           f"({n_elems} элем.), похоже на справочник/прайс/каталог → reference/ (REFERENCE_DATA_STANDARD)")
    return out


# --- гигиена поставки: артефакты сборки/кэши не должны попадать в архив (v2.9.25) ---
# v2.9.66, P1.1 ревью v2.9.65: +виртуальные окружения (.venv/venv/.nox/.eggs);
# имя-независимо venv ловится по маркеру pyvenv.cfg (см. _venv_roots).
HYGIENE_DIRS = {
    ".pytest_cache", "__pycache__", ".mypy_cache", ".ruff_cache", ".benchmarks",
    "htmlcov", "dist", "build", ".tox", ".nox", ".eggs", ".cache",
    ".venv", "venv", "node_modules",
}
HYGIENE_FILES = {".DS_Store", ".coverage", ".env", ".env.local"}
# plaintext-секреты в поставке (v2.9.49): ключи/сертификаты и локальные env
HYGIENE_SECRET_SUFFIXES = {".pem", ".key", ".p12", ".pfx"}
# генерённые packaging-каталоги: *.egg-info (build), *.dist-info (installed dist)
HYGIENE_META_DIR_SUFFIXES = (".egg-info", ".dist-info")


def _hygiene_dir_flag(name: str) -> bool:
    return name in HYGIENE_DIRS or name.endswith(HYGIENE_META_DIR_SUFFIXES)


def _hygiene_file_flag(name: str, suffix: str) -> bool:
    return (name in HYGIENE_FILES or suffix == ".pyc"
            or suffix in HYGIENE_SECRET_SUFFIXES
            # .env.*.local — любое окружение, не только буквально ".env.local"
            or (name.startswith(".env.") and name.endswith(".local")))


def _venv_roots(root: Path) -> list[Path]:
    """Каталоги-виртуальные окружения по маркеру pyvenv.cfg — имя-независимо
    (.venv/venv/env/ENV/любое). v2.9.66, P1.1: `.venv`, созданный `uv run`, утёк
    в архив, а release-hygiene ловил только по списку имён."""
    return [cfg.parent.relative_to(root) for cfg in root.rglob("pyvenv.cfg")]


def check_release_hygiene(root: Path) -> list[str]:
    """Артефакты сборки/кэши/мусор в поставке — release hygiene.

    Не использует скан-границу: специально ищет то, что не должно попасть в
    архив (`--check-manifest` это не ловит). Каталог-артефакт репортится один раз.
    """
    out: list[str] = []
    venv_roots = _venv_roots(root)
    reported_venv: set[Path] = set()
    for p in sorted(_iter_tree(root)):
        rel = p.relative_to(root)
        # виртуальное окружение (по pyvenv.cfg) — репортим корень один раз, содержимое пропускаем
        vroot = next((vr for vr in venv_roots if rel == vr or vr in rel.parents), None)
        if vroot is not None:
            if vroot not in reported_venv:
                reported_venv.add(vroot)
                out.append(f"release-hygiene: виртуальное окружение в поставке: {vroot}/ "
                           f"(не должно быть в архиве)")
            continue
        if any(part in HYGIENE_DIRS for part in rel.parts[:-1]):
            continue  # уже под отмеченным артефакт-каталогом
        # .egg-info/.dist-info — генерённые packaging-каталоги (v2.9.50 P1: раньше
        # проверка стояла только в файловой ветке и не ловила директории)
        if p.is_dir() and _hygiene_dir_flag(p.name):
            out.append(f"release-hygiene: артефакт-каталог в поставке: {rel}/ (не должен быть в архиве)")
        elif p.is_file() and _hygiene_file_flag(p.name, p.suffix):
            out.append(f"release-hygiene: артефакт-файл в поставке: {rel}")
    return out


def check_release_artifact(zip_path: Path) -> list[str]:
    """Проверить СОБРАННЫЙ ZIP по listing (zipinfo-уровень), не распаковывая.
    v2.9.66, P1.1/P2.3 ревью v2.9.65: `.venv`, созданный `uv run` уже ПОСЛЕ
    clean-прогона hygiene по дереву, утёк в архив — дерево на момент проверки
    было чистым, а артефакт нет. Финальный гейт по самим байтам поставки:
    ловит venv (pyvenv.cfg-маркер), кэши/build-каталоги, *.egg-info/*.dist-info,
    *.pyc, .env/.env.*.local, секреты, .DS_Store."""
    import zipfile
    try:
        with zipfile.ZipFile(zip_path) as z:
            names = z.namelist()
    except (OSError, zipfile.BadZipFile) as exc:
        return [f"release-artifact: не читается {zip_path}: {exc}"]
    out: list[str] = []
    reported_dirs: set[str] = set()
    # venv-корни по маркеру pyvenv.cfg (имя-независимо)
    venv_roots = ["/".join(n.split("/")[:-1]) for n in names if n.split("/")[-1] == "pyvenv.cfg"]
    for name in names:
        parts = name.split("/")
        vroot = next((vr for vr in venv_roots if name == vr or name.startswith(vr + "/")), None)
        if vroot is not None:
            if vroot not in reported_dirs:
                reported_dirs.add(vroot)
                out.append(f"release-artifact: виртуальное окружение в ZIP: {vroot}/")
            continue
        flagged_dir = None
        for i, part in enumerate(parts[:-1]):
            if _hygiene_dir_flag(part):
                flagged_dir = "/".join(parts[:i + 1])
                break
        if flagged_dir is not None:
            if flagged_dir not in reported_dirs:
                reported_dirs.add(flagged_dir)
                out.append(f"release-artifact: артефакт-каталог в ZIP: {flagged_dir}/")
            continue
        base = parts[-1]
        if base and _hygiene_file_flag(base, Path(base).suffix):
            out.append(f"release-artifact: артефакт-файл в ZIP: {name}")
    return out


def _looks_like_test_file(file_part: str) -> bool:
    """kind=pytest test_refs[].path обязан выглядеть как тест (v2.9.91, P1
    внешнего ревью v2.9.90 — подтверждено репродукцией: path=README.md
    проходил check_test_coverage молча). Не заменяет реальный сбор pytest
    (--collect-only) — честная граница статической проверки, см.
    tools/verify_test_coverage.py для runtime-подтверждения."""
    p = Path(file_part)
    if p.suffix != ".py":
        return False
    return "tests" in p.parts[:-1] or p.name.startswith("test_") or p.name.endswith("_test.py")


# --- покрытие тестами: regression-guard символ->тест (v2.9.28, перенято из qai-fabric/RAG) ---
def check_test_coverage(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Каждый ACTIVE public символ functions.json должен иметь защищающий тест
    в test_coverage.json (coverage_status active) — иначе поверхность не защищена
    от регрессии. См. TEST_COVERAGE_CONTRACT.md."""
    out: list[str] = []
    functions_f = root / "docs" / "registry" / "functions.json"
    if not functions_f.exists():
        return out  # нет публичной поверхности — нечего защищать
    fdata, _ = load_json(functions_f)
    active: list[str] = []
    if isinstance(fdata, list):
        for it in fdata:
            if not isinstance(it, dict) or it.get("public") is not True:
                continue
            if it.get("status") == "REMOVED":
                continue
            sym = it.get("id") or (
                f"{it['path']}::{it['symbol']}" if isinstance(it.get("path"), str) and isinstance(it.get("symbol"), str)
                else it.get("symbol"))
            if isinstance(sym, str):
                active.append(sym)
    cov_f = root / "docs" / "registry" / "test_coverage.json"
    if not cov_f.exists():
        if active:
            out.append("нет docs/registry/test_coverage.json, а есть активные публичные символы (regression-guard)")
        return out
    data, err = load_json(cov_f)
    if err:
        return [f"битый test_coverage.json: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "test_coverage.schema.json").exists():
        sch, _ = load_json(schemas_root / "test_coverage.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "test_coverage.json"))
    if not isinstance(data, list):
        return out + ["test_coverage.json: ожидался массив"]
    func_ids = _registry_ids(root, "functions.json") or set()
    covered: set = set()
    for i, e in enumerate(data):
        if not isinstance(e, dict):
            continue
        sid = e.get("symbol_id")
        if isinstance(sid, str):
            if func_ids and sid not in func_ids:
                out.append(f"test_coverage.json[{i}]: symbol_id не найден в functions.json: {sid}")
            status = e.get("coverage_status")
            if status == "active":
                covered.add(sid)
            elif status == "waived":
                # осознанный отказ от теста с причиной снимает regression-guard
                # (v2.9.39): это документированное исключение, не «дыра»
                if isinstance(e.get("waiver_reason"), str) and e["waiver_reason"].strip():
                    covered.add(sid)
                else:
                    out.append(f"test_coverage.json[{i}]: coverage_status=waived требует waiver_reason: {sid}")
        for ref in (e.get("test_refs") or []):
            if not isinstance(ref, dict):
                continue
            p = ref.get("path")
            if not isinstance(p, str):
                continue
            file_part = p.split("::")[0]
            # v2.9.102 (P1 внешнего ревью v2.9.101): та же граница --root,
            # что verify_test_coverage.py уже применяет к test_ref (см.
            # _path_escapes_root) — иначе абсолютный/эскейпящий путь тихо
            # проходил статическую строгую проверку.
            if _path_escapes_root(root, file_part):
                out.append(f"test_coverage.json[{i}]: test_ref выходит за пределы проекта: {p}")
            elif not (root / file_part).exists():
                out.append(f"test_coverage.json[{i}]: test_ref не найден: {p}")
            elif ref.get("kind") == "pytest" and not _looks_like_test_file(file_part):
                out.append(f"test_coverage.json[{i}]: test_ref kind=pytest указывает на "
                           f"файл, не похожий на тест ({p}) — ожидается .py под tests/ "
                           f"или имя test_*.py/*_test.py (v2.9.91, P1 внешнего ревью "
                           f"v2.9.90: путь на README.md раньше проходил)")
    for sym in active:
        if sym not in covered:
            out.append(f"regression-guard: ACTIVE public символ без покрытия в test_coverage.json: {sym}")
    return out


# --- knowledge-index: enforcement дизайн-контракта эскалации знаний (v2.9.32) ---
# P1 внешнего ревью v2.9.107, репродуцировано: knowledge_access.mode="rag"
# без vector, fallback вверх/вбок по лестнице, source_of_truth="rag" и
# placeholder-значения (TODO, "<collection_id>", "YYYY-MM-DD", пустая/
# пробельная строка) — всё проходило schema-валидацию, т.к. схема видит
# только синтаксис поля-за-полем, не связь между полями. Denylist source_
# of_truth и ladder fallback — из явного текста KNOWLEDGE_ACCESS_MODE_
# STANDARD.md §12/§16, не изобретены. freshness_sla_hours>0 и return_
# sources=true-для-rag — сознательно добавлены сверх буквы стандарта,
# владелец подтвердил явно (не решено молча, см. feedback_p2_design_forks).
_KNOWLEDGE_ACCESS_LADDER = {"direct": 0, "indexed_search": 1, "rag": 2}
_KNOWLEDGE_ACCESS_SOT_DENYLIST = {"rag", "vector", "index", "embeddings", "vector_db", "vectordb"}
_PLACEHOLDER_TOKENS = {"todo", "tbd", "unknown", "n/a", "na", "later", "?", "-", "—", ""}
# v2.9.118 (P0 внешнего аудита v2.9.117): required_checks[].argv — литеральные
# аргументы (subprocess shell=False), не shell-строка целиком. Отдельный токен
# со спрятанным ';'/'&&'/pipe/redirect/command-substitution — сигнал, что
# кто-то пытается пронести полноценную shell-команду внутрь одного элемента
# argv, обходя саму защиту argv-формы. `\$\(` — command substitution
# ($(...)); голый `\$` НЕ запрещён (переменные окружения — легитимный
# аргумент, интерпретируются самим subprocess, не отдельным shell).
_SHELL_METACHAR_RE = re.compile(r";|&&|\|\||\||`|\$\(|<|>")

# v2.9.119 (P1 внешнего аудита v2.9.118): _SHELL_METACHAR_RE ловит спрятанную
# ВТОРУЮ команду внутри одного токена, но НЕ ловит argv[0]=интерпретатор +
# inline-code флаг — ["bash", "-c", "rm -rf /tmp/x"] не содержит ни одного
# shell-метасимвола (ни в "bash", ни в "-c", ни в "rm -rf /tmp/x" самом по
# себе), но исполняет произвольный код, если что-то когда-то станет
# исполнять этот argv автоматически (сегодня НЕ исполняет — см. описание
# поля в схеме). Различие с легитимным ["bash", "script.sh"] (запуск ФАЙЛА
# скрипта, обычный паттерн) — именно во FLAG'е, не в самом факте вызова
# интерпретатора: поэтому проверяется КОМБИНАЦИЯ (интерпретатор как argv[0]
# И inline-флаг где-либо в argv), не запрет интерпретатора самого по себе.
_ARGV_INTERPRETERS = {
    "bash", "sh", "zsh", "dash", "ksh", "cmd", "cmd.exe",
    "powershell", "powershell.exe", "pwsh", "pwsh.exe",
    "python", "python3", "python2", "node", "nodejs", "ruby", "perl", "php",
}
_ARGV_INLINE_CODE_FLAGS = {
    "-c", "-e", "--eval", "/c", "/C",
    "-command", "-encodedcommand",
}
# v2.9.120 (P1 внешнего аудита v2.9.119, репродуцировано): проверка v2.9.119
# смотрела только на argv[0] — ["env", "bash", "-c", "id"]/["timeout", "5",
# "bash", "-c", "id"]/["/usr/bin/env", "python", "-c", "..."] проходили без
# находок, хотя интерпретатор с inline-флагом всё равно исполняется, просто
# на одну позицию правее. Best-effort разворачивание ведущих wrapper-команд
# — не полный парсер аргументов каждой из них (это декларативное поле,
# сегодня никто не исполняет автоматически, см. схему), а bounded defense-
# in-depth: пропускаем имя wrapper'а, его dash-флаги, и (для wrapper'ов с
# обязательным позиционным аргументом до самой команды, напр. `timeout
# <секунды> cmd...`) фиксированное число позиционных токенов из
# _ARGV_WRAPPER_ARITY.
_ARGV_WRAPPER_COMMANDS = {
    "env", "timeout", "nice", "nohup", "setsid", "stdbuf", "sudo", "doas",
    "chrt", "ionice",
    # v2.9.122 (P1 внешнего аудита v2.9.121 §9, репродуцировано: ["xargs",
    # "sh", "-c", "id"] проходил без находок): xargs без аргументов от
    # stdin по умолчанию всё равно запускает команду ОДИН раз (POSIX,
    # если не передан -r/--no-run-if-empty) — эффективно эквивалентно
    # прямому запуску команды-шаблона, тот же класс, что и остальные
    # wrapper'ы. Не моделирует xargs полностью (шаблон/{}-подстановку из
    # stdin) — только эту демонстрационно найденную форму.
    "xargs",
    # v2.9.123 (P2 внешнего аудита v2.9.122, A-9, репродуцировано:
    # ["flock","/tmp/l","bash","-c","id"]/["unbuffer","bash","-c","id"]
    # проходили без находок): flock/unbuffer — тот же класс wrapper'ов,
    # что и остальные (запускают ОДНУ реальную команду без интерпретации
    # своих аргументов). Не расширено дальше в этом цикле — script -c
    # (комбинированный короткий флаг `-qc`), awk BEGIN{system()}, make -f,
    # git --exec-path, docker run, голые деструктивные команды (rm -rf /,
    # curl, ssh) не вписываются в модель «wrapper, затем реальная команда
    # позицией правее» вообще (это не wrapper, а сам по себе опасный/
    # self-interpreting бинарь) — продолжать патчить denylist по одному
    # новому бинарю за раз и есть та самая «гонка вооружений», ради
    # прекращения которой введён check_registry.json (v2.9.122); классы,
    # не вписывающиеся в существующую модель, — аргумент ЗА миграцией на
    # check_ref, не повод расширять денилист up to infinitum.
    "flock", "unbuffer",
}
# v2.9.122 (P1 внешнего аудита v2.9.121 §9, репродуцировано: ["chrt", "-r",
# "1", "bash", "-c", "id"] проходил без находок): chrt — тот же паттерн,
# что и timeout — ОБЯЗАТЕЛЬНЫЙ позиционный priority ПОСЛЕ dash-флагов и
# ПЕРЕД самой командой (chrt [-flags] priority command...).
_ARGV_WRAPPER_ARITY = {"timeout": 1, "chrt": 1, "flock": 1}
# v2.9.121 (P1 внешнего аудита v2.9.120, репродуцировано напрямую — все 6
# случаев ниже проходили без находок до этой правки): фиксированная arity
# ("N позиционных токенов после всех dash-флагов") не покрывает wrapper'ы,
# чьи ФЛАГИ сами потребляют значение следующим токеном — "10" в
# `nice -n 10 bash -c id` раньше ошибочно принимался за интерпретатор
# (Path("10").stem == "10", не в _ARGV_INTERPRETERS, сканирование
# останавливалось, не доходя до bash -c). Не претендует на исчерпывающий
# список флагов каждого wrapper'а — эвристика defense-in-depth (см.
# докстринг ниже), не полноценный парсер аргументов.
_ARGV_WRAPPER_VALUE_FLAGS = {
    "nice": {"-n", "--adjustment"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "sudo": {"-u", "-g", "--user", "--group"},
    # v2.9.122 (P1 внешнего аудита v2.9.121 §9, репродуцировано, все 4 ниже
    # проходили без находок): timeout --signal СИГНАЛ и env -u ИМЯ/--unset
    # ИМЯ — value-флаги, не boolean; doas -u ПОЛЬЗОВАТЕЛЬ — тот же паттерн,
    # что уже закрыт для sudo; ionice -c/-n/--class/--classdata — value-флаги
    # I/O scheduling class/classdata.
    "timeout": {"--signal"},
    "env": {"-u", "--unset"},
    "doas": {"-u"},
    "ionice": {"-c", "-n", "--class", "--classdata"},
}
# v2.9.121: env поддерживает НОЛЬ-ИЛИ-БОЛЬШЕ ведущих NAME=VALUE-присваиваний
# перед самой командой (`env FOO=bar BAZ=qux bash -c id`) — раньше "foo=bar"
# ошибочно принимался за интерпретатор (тот же класс бага, что и с
# value-флагами выше, другая грамматика).
_ARGV_WRAPPER_ENV_ASSIGNMENT = {"env"}
_ARGV_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# v2.9.121: `env -S/--split-string STRING` разбивает STRING по shell-подобным
# правилам (кавычки/пробелы) и запускает результат НАПРЯМУЮ, без отдельного
# shell, — `env -S "bash -c id"` по факту эквивалентно `env bash -c id`,
# только команда упакована в одну строку. shlex.split — тот же принцип
# разбора, что и у GNU env для -S (whitespace + POSIX-кавычки).
_ARGV_ENV_SPLIT_STRING_FLAGS = {"-S", "--split-string"}
# python -m <module> — модуль исполняется как __main__, все аргументы ПОСЛЕ
# имени модуля принадлежат ЕМУ (своя грамматика, напр. pytest -c ЭТО НЕ
# то же самое, что python -c) — не interpreter'у, поэтому сканирование
# inline-code флагов интерпретатора обязано остановиться здесь, иначе
# ["python", "-m", "pytest", "-c", "custom.ini"] (легитимно — pytest.ini
# путь) ложно флагуется как ["python", "-c", ...] (исполнение inline-кода).
_ARGV_MODULE_INVOCATION_FLAGS = {"-m", "--module"}
# v2.9.121 (репродуцировано: ["cmd.exe", "/d", "/c", "whoami"] проходил без
# находок): "/d" не распознавался как флаг для пропуска (только "-"-префикс
# считался флагом), поэтому сканирование останавливалось на нём раньше, чем
# доходило до реального "/c". Ограничено Windows-стиль интерпретаторами —
# для POSIX-интерпретаторов ведущий "/" в позиционном токене означает
# абсолютный путь (`bash /opt/script.sh`), а не флаг, который можно
# пропускать.
_ARGV_SLASH_FLAG_INTERPRETERS = {
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}


def _argv_interpreter_inline_flags(argv: list, _depth: int = 0) -> tuple[str | None, list[str]]:
    """Возвращает (эффективный_интерпретатор, найденные_inline_code_флаги)
    после разворачивания ведущих wrapper-команд. Останавливает сканирование
    на первом non-flag токене после интерпретатора (это цель — файл/модуль,
    дальнейшие токены принадлежат ЕЙ) или на флаге модульного вызова.
    Эвристика best-effort defense-in-depth (см. комментарий у
    _ARGV_WRAPPER_COMMANDS) — не претендует на полноценный парсер аргументов
    каждого wrapper'а, только на демонстрационно найденные обходы. _depth
    ограничивает рекурсию через `env -S` (защита от вырожденного/
    зациклленного ввода — на практике команда не вложена глубже одного
    уровня)."""
    if _depth > 4:
        return None, []
    i, n = 0, len(argv)
    while i < n:
        tok = argv[i]
        if not isinstance(tok, str):
            return None, []
        stem = Path(tok.replace("\\", "/")).stem.lower()
        if stem not in _ARGV_WRAPPER_COMMANDS:
            break
        i += 1
        if stem in _ARGV_WRAPPER_ENV_ASSIGNMENT:
            while i < n and isinstance(argv[i], str) and _ARGV_ENV_ASSIGNMENT_RE.match(argv[i]):
                i += 1
        while i < n and isinstance(argv[i], str) and argv[i].startswith("-"):
            flag = argv[i]
            if stem in _ARGV_WRAPPER_ENV_ASSIGNMENT and flag in _ARGV_ENV_SPLIT_STRING_FLAGS:
                if i + 1 < n and isinstance(argv[i + 1], str):
                    return _argv_interpreter_inline_flags(shlex.split(argv[i + 1]), _depth + 1)
                return None, []
            i += 1
            if flag in _ARGV_WRAPPER_VALUE_FLAGS.get(stem, ()):
                i += 1
        i += _ARGV_WRAPPER_ARITY.get(stem, 0)
    if i >= n or not isinstance(argv[i], str):
        return None, []
    interp = Path(argv[i].replace("\\", "/")).stem.lower()
    if interp not in _ARGV_INTERPRETERS:
        return interp, []
    flag_prefixes = ("-", "/") if interp in _ARGV_SLASH_FLAG_INTERPRETERS else ("-",)
    inline_flags: list[str] = []
    for tok in argv[i + 1:]:
        if not isinstance(tok, str):
            continue
        low = tok.lower()
        if low in _ARGV_MODULE_INVOCATION_FLAGS:
            break
        if low in _ARGV_INLINE_CODE_FLAGS:
            inline_flags.append(tok)
            break
        if not tok.startswith(flag_prefixes):
            break
    return interp, inline_flags


def _check_argv_safety(argv, cwd, root: Path, label: str, out: list[str]) -> None:
    """v2.9.122: общая проверка безопасности argv/cwd — переиспользуется
    check_agent_task_contracts() (required_checks[].argv, legacy-путь) и
    check_check_registry() (checks[].argv в trusted check registry, см.
    schemas/check_registry.schema.json) — один и тот же класс риска
    (shell-метасимволы, известный интерпретатор+inline-code-флаг после
    разворачивания wrapper-команд, cwd, выходящий за --root), раньше
    продублированный только внутри check_agent_task_contracts().

    label — префикс сообщения БЕЗ поля (напр. "docs/registry/agent_tasks/
    T1.json: required_checks[0]" или "docs/registry/check_registry.json:
    checks[0]") — функция сама добавляет .argv[j]/.argv/.cwd."""
    for j, token in enumerate(argv or []):
        if not isinstance(token, str):
            continue
        if _is_placeholder_value(token):
            out.append(f"{label}.argv[{j}] — плейсхолдер или пусто")
            continue
        bad = _SHELL_METACHAR_RE.search(token)
        if bad:
            out.append(f"{label}.argv[{j}] содержит shell-метасимвол {bad.group()!r} "
                       f"({token!r}) — argv обязан быть массивом литеральных аргументов "
                       f"(subprocess shell=False), не спрятанной shell-командой; разбей "
                       f"на несколько чётких проверок или вызови скрипт-обёртку файлом")
    if isinstance(argv, list) and argv:
        interp, inline_flags = _argv_interpreter_inline_flags(argv)
        if interp in _ARGV_INTERPRETERS and inline_flags:
            out.append(f"{label}.argv — интерпретатор {interp!r} с inline-code флагом "
                       f"{inline_flags!r} исполняет произвольный код без единого "
                       f"shell-метасимвола ({argv!r}); чтобы запустить готовый скрипт "
                       f"легитимно, вызови его ФАЙЛОМ (напр. ['bash', 'script.sh'], без "
                       f"-c/-e/--eval/-Command/...)")
    if isinstance(cwd, str) and cwd and _path_escapes_root(root, cwd):
        out.append(f"{label}.cwd выходит за пределы --root: {cwd!r}")


def _is_placeholder_value(value: Any) -> bool:
    """Тот же placeholder-принцип, что уже применён (промт-уровнем) в
    create_technical_spec_from_business_requirements.md — здесь машинно."""
    if not isinstance(value, str):
        return False
    s = value.strip()
    return s.lower() in _PLACEHOLDER_TOKENS or s.lower() == "yyyy-mm-dd" or bool(re.match(r"^<.*>$", s))


def check_knowledge_index(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/knowledge_index.json: схема, реальность summary_first/digests
    путей (в пределах root, не за его пределами), адрес вектор-базы только через
    env (не хардкод URL), согласованность knowledge_access с механизмом (vector
    обязателен для mode=rag, fallback только вниз по лестнице, source_of_truth не
    сам RAG-слой, значения не placeholder). Файл опционален — слой дизайнерский;
    проверяем лишь если он есть. См. KNOWLEDGE_INDEX_STANDARD.md/
    KNOWLEDGE_ACCESS_MODE_STANDARD.md."""
    out: list[str] = []
    f = root / "docs" / "registry" / "knowledge_index.json"
    if not f.exists():
        return out  # слой не заведён — нечего проверять
    data, err = load_json(f)
    if err:
        return [f"битый knowledge_index.json: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "knowledge_index.schema.json").exists():
        sch, _ = load_json(schemas_root / "knowledge_index.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "knowledge_index.json"))
    if not isinstance(data, dict):
        return out + ["knowledge_index.json: ожидался объект"]
    for key in ("summary_first", "digests"):
        for p in data.get(key, []) or []:
            if not isinstance(p, str):
                continue
            # P1 внешнего ревью v2.9.107: `(root / p).exists()` тихо проверял
            # абсолютный путь САМ ПО СЕБЕ — pathlib отбрасывает root при
            # абсолютном правом операнде (`Path("/a") / "/b" == Path("/b")`).
            # Та же уязвимость уже закрыта для test_runner/test_coverage/
            # user_functions в v2.9.101 через _path_escapes_root — здесь не
            # была подключена.
            if _path_escapes_root(root, p):
                out.append(f"knowledge_index.json: {key}-путь выходит за пределы проекта: {p}")
            elif not (root / p).exists():
                out.append(f"knowledge_index.json: {key}-путь не найден: {p}")
    vec = data.get("vector")
    if isinstance(vec, dict):
        if "url" in vec:
            out.append("knowledge_index.json: адрес вектор-базы должен быть в env (vector.url_env), не литеральный vector.url")
        ue = vec.get("url_env")
        if isinstance(ue, str):
            if "://" in ue:
                out.append(f"knowledge_index.json: vector.url_env — имя env-переменной, не URL: {ue}")
            elif not re.match(r"^[A-Z][A-Z0-9_]*$", ue):
                out.append(f"knowledge_index.json: vector.url_env не в UPPER_SNAKE: {ue}")
        if _is_placeholder_value(vec.get("collection")):
            out.append("knowledge_index.json: vector.collection — плейсхолдер, не заполнено (например, \"<collection_id>\")")
        fsh = vec.get("freshness_sla_hours")
        if isinstance(fsh, (int, float)) and not isinstance(fsh, bool) and fsh <= 0:
            out.append(f"knowledge_index.json: vector.freshness_sla_hours должен быть положительным: {fsh}")
    ka = data.get("knowledge_access")
    if isinstance(ka, dict):
        mode = ka.get("mode")
        if _is_placeholder_value(ka.get("reason")):
            out.append("knowledge_index.json: knowledge_access.reason — не заполнено по существу (плейсхолдер или пусто)")
        reviewed_by = ka.get("reviewed_by")
        if reviewed_by is not None and _is_placeholder_value(reviewed_by):
            out.append("knowledge_index.json: knowledge_access.reviewed_by — плейсхолдер, не заполнено")
        reviewed_at = ka.get("reviewed_at")
        if reviewed_at is not None:
            if (_is_placeholder_value(reviewed_at) or not isinstance(reviewed_at, str)
                    or not re.match(r"^\d{4}-\d{2}-\d{2}$", reviewed_at.strip())):
                out.append(f"knowledge_index.json: knowledge_access.reviewed_at не похоже на дату YYYY-MM-DD: {reviewed_at!r}")
        sot = ka.get("source_of_truth")
        if isinstance(sot, str) and sot.strip().lower() in _KNOWLEDGE_ACCESS_SOT_DENYLIST:
            out.append(f"knowledge_index.json: knowledge_access.source_of_truth не может быть самим RAG-слоем ({sot!r}) — RAG не источник истины (KNOWLEDGE_ACCESS_MODE_STANDARD.md §12)")
        fallback = ka.get("fallback")
        if mode in _KNOWLEDGE_ACCESS_LADDER and fallback is not None:
            if fallback not in _KNOWLEDGE_ACCESS_LADDER or _KNOWLEDGE_ACCESS_LADDER[fallback] >= _KNOWLEDGE_ACCESS_LADDER[mode]:
                out.append(f"knowledge_index.json: knowledge_access.fallback={fallback!r} должен быть строго ниже mode={mode!r} по лестнице rag→indexed_search→direct (KNOWLEDGE_ACCESS_MODE_STANDARD.md §16)")
        if mode == "rag":
            if not isinstance(vec, dict) or not vec.get("provider") or not vec.get("collection"):
                out.append('knowledge_index.json: knowledge_access.mode="rag" требует заполненного vector (provider+collection) (KNOWLEDGE_ACCESS_MODE_STANDARD.md §4)')
            elif vec.get("return_sources") is not True:
                out.append('knowledge_index.json: knowledge_access.mode="rag" требует vector.return_sources=true (KNOWLEDGE_ACCESS_MODE_STANDARD.md §15)')
    return out


# --- entitlements: отображающий манифест лицензионных прав (v2.9.40) ---
def check_entitlements(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/entitlements.json: схема; адрес License Hub только через env
    (не литеральный URL); covers ссылается на существующие user_functions;
    module_code уникальны. Файл ОПЦИОНАЛЕН (только лицензируемые проекты).
    Отображение, не управление — валидатор офлайн, Hub не дёргает.
    Источник правды — БД Hub, манифест — помеченное зеркало. См. ENTITLEMENTS_STANDARD.md."""
    out: list[str] = []
    f = root / "docs" / "registry" / "entitlements.json"
    if not f.exists():
        return out  # проект не лицензируется через Hub — нечего проверять
    data, err = load_json(f)
    if err:
        return [f"битый entitlements.json: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "entitlements.schema.json").exists():
        sch, _ = load_json(schemas_root / "entitlements.schema.json")
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "entitlements.json"))
    if not isinstance(data, dict):
        return out + ["entitlements.json: ожидался объект"]
    if "hub_url" in data:
        out.append("entitlements.json: адрес Hub должен быть в env (hub_url_env), не литеральный hub_url")
    # зеркало ОБЯЗАНО быть помеченным (v2.9.41): без source_of_truth/mirror_of
    # манифест начинает читаться как второй источник правды рядом с Hub
    for field, why in (("source_of_truth", "помеченного зеркала"),
                       ("mirror_of", "помеченного зеркала"),
                       ("hub_url_env", "адреса Hub из env")):
        val = data.get(field)
        if not (isinstance(val, str) and val.strip()):
            out.append(f"entitlements.json: {field} обязателен для {why}")
    ue = data.get("hub_url_env")
    if isinstance(ue, str):
        if "://" in ue:
            out.append(f"entitlements.json: hub_url_env — имя env-переменной, не URL: {ue}")
        elif not re.match(r"^[A-Z][A-Z0-9_]*$", ue):
            out.append(f"entitlements.json: hub_url_env не в UPPER_SNAKE: {ue}")
    uf_ids = _registry_ids(root, "user_functions.json")
    seen: set = set()
    for m in data.get("modules", []) or []:
        if not isinstance(m, dict):
            continue
        code = m.get("module_code")
        if isinstance(code, str):
            if code in seen:
                out.append(f"entitlements.json: дубликат module_code: {code}")
            seen.add(code)
        for c in m.get("covers", []) or []:
            if isinstance(c, str) and uf_ids is not None and c not in uf_ids:
                out.append(f"entitlements.json: covers ссылается на несуществующую user-function: {c}")
    return out


_LOCKFILES = {"uv.lock": "uv", "poetry.lock": "poetry", "pdm.lock": "pdm"}


def check_dependency_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Политика управления зависимостями: uv — рекомендуемый default,
    pip/venv — fallback, pyproject.toml — source of truth (не проверяется здесь,
    это PROJECT_LAYOUT). docs/registry/dependency_policy.json ОПЦИОНАЛЕН — часть
    проверок идёт по факту дерева (lock-конфликты, requirements.txt-роль) даже
    без файла. См. DEPENDENCY_MANAGEMENT_STANDARD.md."""
    out: list[str] = []
    present_locks = [name for name in _LOCKFILES if (root / name).exists()]
    policy_f = root / "docs" / "registry" / "dependency_policy.json"
    policy: dict[str, Any] | None = None
    if policy_f.exists():
        data, err = load_json(policy_f)
        if err:
            return [f"битый dependency_policy.json: {err}"]
        schemas_root = resolve_schemas_root(root, schemas_root_arg)
        if schemas_root and (schemas_root / "dependency_policy.schema.json").exists():
            sch, _ = load_json(schemas_root / "dependency_policy.schema.json")
            if isinstance(sch, dict):
                out.extend(validate_schema(data, sch, "dependency_policy.json"))
        if isinstance(data, dict):
            policy = data
    manager = policy.get("manager") if policy else None
    if manager in ("uv", "poetry", "pdm"):
        expected = {"uv": "uv.lock", "poetry": "poetry.lock", "pdm": "pdm.lock"}[manager]
        if not (root / expected).exists():
            out.append(f"dependency_policy.json: manager={manager}, но нет {expected} в корне")
    if len(present_locks) > 1 and policy is None:
        out.append(f"{WARN_PREFIX}несколько lock-файлов ({', '.join(present_locks)}) без "
                   f"dependency_policy.json — неясно, какой канонический")
    has_requirements = (root / "requirements.txt").exists()
    has_pyproject = (root / "pyproject.toml").exists()
    if has_requirements and has_pyproject:
        rtp = policy.get("requirements_txt_policy") if policy else None
        if not isinstance(rtp, str) or not rtp.strip():
            out.append(f"{WARN_PREFIX}requirements.txt рядом с pyproject.toml без "
                       f"requirements_txt_policy в dependency_policy.json — роль файла не названа")
    ci_cmd = policy.get("ci_install_command") if policy else None
    if isinstance(ci_cmd, str) and ci_cmd.strip():
        workflows_dir = root / ".github" / "workflows"
        if workflows_dir.is_dir():
            found = any(ci_cmd in f.read_text(encoding="utf-8", errors="ignore")
                       for f in workflows_dir.glob("*.yml"))
            if not found:
                out.append(f"{WARN_PREFIX}ci_install_command '{ci_cmd}' не встречается в "
                           f".github/workflows/*.yml (эвристика — другой CI-провайдер пропускается)")
    return out


_RISKY_MAINTENANCE_STATUS = {"archived", "deprecated", "unmaintained"}
# принятое решение (accepted/accepted_with_waiver) обязано опираться на реально
# проверенные факты, не на "maintenance_status: maintained" из памяти агента
# без доказательств (v2.9.71, P1.3 ревью v2.9.70). source_reference добавлен
# в v2.9.72 (P2.3 ревью v2.9.71): source_checked_at фиксирует КОГДА проверяли,
# но не ГДЕ — без ссылки на источник "проверено" тоже можно написать по памяти.
_DECISION_EVIDENCE_STRING_FIELDS = (
    "selected_version", "source_checked_at", "last_release_date", "license",
    "rationale", "source_reference",
)
_DECISION_DATE_FIELDS = ("source_checked_at", "last_release_date")
# floating-ссылки вместо зафиксированной версии — то же самое "по памяти", но
# для номера версии, не для maintenance status (v2.9.72, P2.4 ревью v2.9.71).
# v2.9.73 (P1.2 ревью v2.9.72): точный список токенов ловил latest/master/
# main/head/*, но пропускал semver/PEP 440 floating ranges (>=1.0.0, ^1.2.3,
# ~1.2.3, 1.*, 1.x) — реальная форма плавающей версии в Python/npm-экосистемах.
# Регекс ловит: VCS/тег-слова, любой сравнительный/caret/tilde/wildcard символ,
# x/X как отдельный версионный сегмент (1.x, x.x.x). НЕ ловит легитимные точные
# версии: pre-release суффиксы (1.0.0rc1, 1.0.0-alpha), PEP 440 epoch (1!2.3.4),
# префикс v (v1.2.3) — те не содержат ни один из перечисленных wildcard-символов.
_FLOATING_VERSION_RE = re.compile(
    r"(^|\s)(latest|master|main|head)(\s|$)|"
    r"[<>=~^*]|"
    r"(^|[.\-])x([.\-]|$)",
    re.IGNORECASE,
)
# source_reference должен называть ГДЕ проверяли, а не быть общей фразой типа
# "checked online" — soft-проверка по ключевым словам/URL (v2.9.73, P2.1 ревью
# v2.9.72); warning, не error — это эвристика, не гарантия воспроизводимости
_SOURCE_REFERENCE_HINTS = (
    "pypi", "npm", "github", "gitlab", "crates.io", "rubygems", "nuget",
    "official", "documentation", "docs", "registry", "releases", "changelog",
)


def check_dependency_selection_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/dependency_decisions.json (опционален): decision-запись
    на каждую новую внешнюю зависимость. Идиома waiver (7-й слой с этим
    паттерном): risky maintenance_status (archived/deprecated/unmaintained)
    допускает только decision=accepted_with_waiver + непустой waiver_reason,
    не тихий accepted. accepted/accepted_with_waiver без evidence-полей
    (selected_version/source_checked_at/last_release_date/license/rationale/
    source_reference/alternatives_considered≥1 непустой строки) — ошибка
    (v2.9.71, P1.3 ревью v2.9.70: без evidence решение неотличимо от "по
    памяти", что слой призван исключить). v2.9.72 (P2 ревью v2.9.71):
    source_checked_at/last_release_date проверяются как реальные календарные
    даты (date.fromisoformat, не только regex-форма); selected_version не
    может быть floating-ссылкой (latest/master/main/head/*). v2.9.73 (ревью
    v2.9.72): P1.2 — расширено до semver/PEP 440 floating ranges (>=1.0.0,
    ^1.2.3, ~1.2.3, 1.*, 1.x); P2.1 — source_reference слишком расплывчатый
    ("checked online") даёт warning (эвристика по ключевым словам/URL);
    P2.2 — опциональный top-level freshness_policy (max_age_months +
    checked_against_date — ФИКСИРОВАННАЯ дата в самой записи, не "сейчас")
    флагует decision=accepted с last_release_date старше порога. Валидатор
    офлайн — не ходит в PyPI/npm/advisories сам, проверяет только структурную
    дисциплину записи. См. DEPENDENCY_MANAGEMENT_STANDARD §6."""
    out: list[str] = []
    data = _load_registry_json(root, "dependency_decisions.json",
                               "dependency_decisions.schema.json", schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    # freshness_policy (опционален): staleness-порог с ФИКСИРОВАННОЙ датой
    # сравнения в самой записи, не "сейчас" — детерминированно, не зависит от
    # системных часов (v2.9.73, P2.2 ревью v2.9.72)
    policy_max_months: int | None = None
    policy_checked: date | None = None
    fp = data.get("freshness_policy")
    if isinstance(fp, dict):
        mam = fp.get("max_age_months")
        cad = fp.get("checked_against_date")
        if isinstance(mam, int) and not isinstance(mam, bool) and mam > 0:
            policy_max_months = mam
        if isinstance(cad, str) and cad.strip():
            try:
                policy_checked = date.fromisoformat(cad.strip())
            except ValueError:
                out.append(f"dependency_decisions.json: freshness_policy."
                           f"checked_against_date={cad!r} — не существующая календарная дата")
    seen: set[tuple] = set()
    for i, d in enumerate(data.get("decisions", []) or []):
        if not isinstance(d, dict):
            continue
        name = d.get("name", f"[{i}]")
        eco = d.get("ecosystem")
        # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано): нестроковый
        # name/ecosystem (list/dict) ронял TypeError на seen.add(key) —
        # unhashable type в tuple-ключе. Остальные проверки записи (ниже)
        # используют name только в f-строках — им guard не нужен.
        if isinstance(name, str) and (eco is None or isinstance(eco, str)):
            key = (name, eco)
            if key in seen:
                out.append(f"{WARN_PREFIX}dependency_decisions.json: дубликат записи "
                           f"{name} ({eco})")
            seen.add(key)
        status = d.get("maintenance_status")
        decision = d.get("decision")
        waiver = d.get("waiver_reason")
        if status in _RISKY_MAINTENANCE_STATUS and decision == "accepted":
            out.append(f"dependency_decisions.json: {name}: maintenance_status="
                       f"{status} требует decision=accepted_with_waiver + "
                       f"waiver_reason, а не тихого accepted")
        if decision == "accepted_with_waiver" and not (isinstance(waiver, str) and waiver.strip()):
            out.append(f"dependency_decisions.json: {name}: decision="
                       f"accepted_with_waiver без waiver_reason")
        # календарная валидность дат — регекс в схеме проверяет ТОЛЬКО форму
        # (YYYY-MM-DD), не что дата реально существует; "2026-99-99" проходил
        # (v2.9.72, P2.2 ревью v2.9.71). Не зависит от текущего времени —
        # только парсинг фиксированной строки, детерминированно.
        for field in _DECISION_DATE_FIELDS:
            val = d.get(field)
            if isinstance(val, str) and val.strip():
                try:
                    date.fromisoformat(val.strip())
                except ValueError:
                    out.append(f"dependency_decisions.json: {name}: {field}="
                               f"{val!r} — не существующая календарная дата")
        # floating-версия ("latest"/"master"/...) — то же самое "по памяти",
        # но для номера версии: агент не зафиксировал, что реально проверял
        # (v2.9.72, P2.4 ревью v2.9.71)
        sv = d.get("selected_version")
        if isinstance(sv, str) and _FLOATING_VERSION_RE.search(sv.strip()):
            out.append(f"dependency_decisions.json: {name}: selected_version="
                       f"{sv!r} — floating-ссылка/range, укажи зафиксированную версию")
        # freshness_policy: last_release_date старше порога — принятое БЕЗ
        # waiver'а решение считается устаревшим. accepted_with_waiver не
        # флагуется — явный waiver уже покрывает исключения из любого правила
        # (v2.9.73, P2.2 ревью v2.9.72)
        if policy_checked is not None and policy_max_months is not None and decision == "accepted":
            lrd = d.get("last_release_date")
            if isinstance(lrd, str) and lrd.strip():
                try:
                    released = date.fromisoformat(lrd.strip())
                    age_months = ((policy_checked.year - released.year) * 12
                                 + (policy_checked.month - released.month))
                    if age_months > policy_max_months:
                        out.append(f"dependency_decisions.json: {name}: last_release_date "
                                   f"старше freshness_policy.max_age_months ({age_months} мес. "
                                   f"> {policy_max_months}) — нужен decision=accepted_with_waiver "
                                   f"+ waiver_reason, либо обнови selected_version/last_release_date")
                except ValueError:
                    pass  # уже поймано общей проверкой календарной валидности выше
        # accepted/accepted_with_waiver без evidence — агент мог написать
        # maintenance_status "по памяти", не проверив реальный источник
        # (v2.9.71, P1.3 ревью v2.9.70)
        if decision in ("accepted", "accepted_with_waiver"):
            missing = [f for f in _DECISION_EVIDENCE_STRING_FIELDS
                      if not (isinstance(d.get(f), str) and d.get(f).strip())]
            alts = d.get("alternatives_considered")
            # каждая альтернатива обязана быть непустой строкой — иначе
            # ["", " "] формально "непустой список" длиной ≥1, но фактически
            # альтернатив не названо (v2.9.72, P2.1 ревью v2.9.71)
            if not (isinstance(alts, list) and len(alts) >= 1
                    and all(isinstance(a, str) and a.strip() for a in alts)):
                missing.append("alternatives_considered (непустой список непустых строк)")
            if missing:
                out.append(f"dependency_decisions.json: {name}: decision={decision} "
                           f"без evidence-полей: {', '.join(missing)} — без них решение "
                           f"выглядит как 'по памяти', а не проверенным")
            # source_reference слишком расплывчатый ("checked online") — soft
            # эвристика по ключевым словам/URL, только если поле само по себе
            # непустое (пусто уже поймано выше как missing evidence)
            sr = d.get("source_reference")
            if isinstance(sr, str) and sr.strip():
                low = sr.lower()
                if "://" not in low and not any(h in low for h in _SOURCE_REFERENCE_HINTS):
                    out.append(f"{WARN_PREFIX}dependency_decisions.json: {name}: "
                               f"source_reference={sr!r} — слишком расплывчато, укажи "
                               f"конкретно где проверяли (PyPI/npm/GitHub/официальная "
                               f"документация/URL)")
    return out


# --- ИБ-ревью внешнего agent-tooling: Skills/MCP/плагины (v2.9.74) ---
_RISKY_TOOLING_SOURCE = {"external", "unknown"}
_TOOLING_EVIDENCE_STRING_FIELDS = ("reviewed_at", "reviewed_by", "source_reference", "rationale")
_TOOLING_RED_FLAGS = frozenset({
    "shell_pipe_to_interpreter", "eval_or_dynamic_code", "obfuscated_content",
    "outbound_network_calls", "requests_broad_permissions", "unclear_authorship",
    "embedded_secrets",
})
# reviewed_by слишком расплывчатый — не называет конкретного человека/роль.
# "me"/"я"/"owner"/"admin"/"reviewer" тоже не идентифицируют РЕАЛЬНОГО
# человека для audit trail (кто именно "owner"? через год не восстановить) —
# нужна конкретика (имя, ник, роль в IskInoSfera) (v2.9.75 P2 + v2.9.76 P2.4
# ревью v2.9.75)
_VAGUE_REVIEWED_BY = {
    "кто-то", "someone", "agent", "ai", "bot", "???", "-", "n/a", "unknown", "?",
    "me", "я", "owner", "admin", "reviewer",
}
# эвристический скан SKILL.md на грубые red-flag паттерны — не статический
# анализатор, ловит только явные грубые случаи (v2.9.74)
_SUSPICIOUS_TOOLING_PATTERNS = (
    (re.compile(r"curl\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"), "shell_pipe_to_interpreter"),
    (re.compile(r"wget\s+[^\n|]*\|\s*(sudo\s+)?(sh|bash|zsh)\b"), "shell_pipe_to_interpreter"),
    (re.compile(r"base64\s+(-d|--decode)\b[^\n]*\|\s*(sh|bash)\b"), "obfuscated_content"),
    (re.compile(r"\beval\s*\("), "eval_or_dynamic_code"),
    (re.compile(r"\biex\s*\(", re.IGNORECASE), "eval_or_dynamic_code"),
)


def check_tooling_security_review(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/tooling_security_reviews.json (опционален): ИБ-ревью
    Skills/MCP-серверов/плагинов перед установкой. Идиома waiver (8-й слой с
    этим паттерном): непустой `red_flags_found` (реальная находка ревью)
    допускает только decision=approved_with_waiver + waiver_reason, не тихий
    approved — ошибка. source∈{external,unknown} — это ПРОВЕНАНС, не сам по
    себе вердикт риска (в отличие от risky maintenance_status в dependency-
    selection, который описывает состояние пакета): чистый обзор без находок
    даёт только мягкую подсказку (warning), не требует waiver-обёртки.
    approved/approved_with_waiver без evidence — ошибка (та же логика, что в
    DEPENDENCY_MANAGEMENT_STANDARD §6 — без evidence запись неотличима от
    «одобрено не глядя»): reviewed_at/reviewed_by/source_reference/rationale
    непустые, И red_flags_checked покрывает ВЕСЬ фиксированный чек-лист (все
    7 флагов, не выборочно — v2.9.75, P4 ревью v2.9.74: частичный чек-лист
    тоже "не глядя", просто по части списка). red_flags_found ⊆
    red_flags_checked — нельзя найти то, что не проверяли (v2.9.75, P5).
    source_reference/reviewed_by слишком расплывчатые ("checked online",
    "someone") — soft warning (v2.9.75, P2). Опциональное структурное поле
    source_url (отдельно от свободного source_reference) проверяется как URL
    по схеме (http(s)://, git+ssh://), не эвристикой по словам — warning,
    если не похоже на URL (v2.9.77, P2.2 ревью v2.9.76). Плюс эвристический
    скан текста skills/**/SKILL.md на грубые red-flag паттерны (curl|sh, eval, iex,
    base64-в-shell) — warning, если для такого skill'а нет записи в
    реестре. Валидатор офлайн: не анализирует код MCP-серверов (обычно
    внешний бинарник, не в репозитории), не заменяет реальный security
    review. См. TOOLING_SECURITY_REVIEW_STANDARD.md."""
    out: list[str] = []
    data = _load_registry_json(root, "tooling_security_reviews.json",
                               "tooling_security_reviews.schema.json", schemas_root_arg, out)
    reviewed_names: set[str] = set()
    if isinstance(data, dict):
        seen: set[tuple] = set()
        for i, r in enumerate(data.get("reviews", []) or []):
            if not isinstance(r, dict):
                continue
            name = r.get("name", f"[{i}]")
            kind = r.get("kind")
            # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано):
            # нестроковый name (list/dict) ронял TypeError на
            # reviewed_names.add(name) — unhashable type. Остальные проверки
            # записи (ниже) используют name только в f-строках — guard не
            # нужен.
            if isinstance(name, str):
                reviewed_names.add(name)
                if kind is None or isinstance(kind, str):
                    key = (name, kind)
                    if key in seen:
                        out.append(f"{WARN_PREFIX}tooling_security_reviews.json: дубликат "
                                   f"записи {name} ({kind})")
                    seen.add(key)
            source = r.get("source")
            decision = r.get("decision")
            waiver = r.get("waiver_reason")
            red_flags_found = r.get("red_flags_found") or []
            # source=external/unknown — это ПРОВЕНАНС, не сам по себе вердикт
            # риска (в отличие от maintenance_status в dependency-selection,
            # который описывает состояние пакета) — чистый обзор без
            # находок не обязан притворяться "принятым риском"; только
            # мягкая подсказка (v2.9.74, урок из собственных golden-примеров,
            # которые падали при error-варианте этого правила)
            if source in _RISKY_TOOLING_SOURCE and decision == "approved":
                out.append(f"{WARN_PREFIX}tooling_security_reviews.json: {name}: "
                           f"source={source} — рассмотри decision=approved_with_waiver, "
                           f"чтобы явно отметить непроверенное происхождение")
            # red_flags_found — это РЕАЛЬНАЯ находка ревью, а не провенанс;
            # тихий approved с найденным красным флагом — это и есть та самая
            # непоследовательность, которую идиома waiver призвана исключить
            if red_flags_found and decision == "approved":
                out.append(f"tooling_security_reviews.json: {name}: red_flags_found="
                           f"{red_flags_found} требует decision=approved_with_waiver + "
                           f"waiver_reason, а не тихого approved")
            if decision == "approved_with_waiver" and not (isinstance(waiver, str) and waiver.strip()):
                out.append(f"tooling_security_reviews.json: {name}: decision="
                           f"approved_with_waiver без waiver_reason")
            reviewed_at = r.get("reviewed_at")
            if isinstance(reviewed_at, str) and reviewed_at.strip():
                try:
                    date.fromisoformat(reviewed_at.strip())
                except ValueError:
                    out.append(f"tooling_security_reviews.json: {name}: reviewed_at="
                               f"{reviewed_at!r} — не существующая календарная дата")
            # source_url — опциональное СТРУКТУРНОЕ поле, отдельное от
            # свободного source_reference; проверяется как URL по схеме, не
            # эвристикой по ключевым словам (v2.9.77, P2.2 ревью v2.9.76)
            source_url = r.get("source_url")
            if isinstance(source_url, str) and source_url.strip():
                if not re.match(r"^(https?|git\+ssh)://", source_url.strip(), re.IGNORECASE):
                    out.append(f"{WARN_PREFIX}tooling_security_reviews.json: {name}: "
                               f"source_url={source_url!r} — не похож на URL (ожидается "
                               f"схема http(s):// или git+ssh://)")
            # red_flags_found не может содержать флаг, которого не было в
            # red_flags_checked — нельзя найти то, что не проверяли; это
            # внутренняя непоследовательность записи (v2.9.75, P4/P5 ревью
            # v2.9.74)
            checked_raw = r.get("red_flags_checked")
            checked_set = set(checked_raw) if isinstance(checked_raw, list) else set()
            not_checked = [f for f in red_flags_found if f not in checked_set]
            if not_checked:
                out.append(f"tooling_security_reviews.json: {name}: red_flags_found "
                           f"содержит {not_checked}, чего нет в red_flags_checked — "
                           f"нельзя найти то, что не проверяли")
            if decision in ("approved", "approved_with_waiver"):
                missing = [f for f in _TOOLING_EVIDENCE_STRING_FIELDS
                          if not (isinstance(r.get(f), str) and r.get(f).strip())]
                # чек-лист красных флагов ФИКСИРОВАННЫЙ и короткий (7 пунктов)
                # именно для того, чтобы можно было проверить, что ревью
                # прошло ВСЕ пункты, а не выборочно; частичный чек-лист —
                # тот же "одобрено не глядя", просто по части списка
                # (v2.9.75, P4 ревью v2.9.74)
                missing_flags = _TOOLING_RED_FLAGS - checked_set
                if missing_flags:
                    missing.append(f"red_flags_checked не покрывает весь чек-лист "
                                   f"(не хватает: {sorted(missing_flags)})")
                if missing:
                    out.append(f"tooling_security_reviews.json: {name}: decision="
                               f"{decision} без evidence-полей: {', '.join(missing)} — "
                               f"без них ревью выглядит как «одобрено не глядя»")
                # source_reference/reviewed_by слишком расплывчатые — soft
                # эвристика, не гарантия воспроизводимости (v2.9.75, P2)
                sr = r.get("source_reference")
                if isinstance(sr, str) and sr.strip():
                    low = sr.lower()
                    if "://" not in low and not any(h in low for h in _SOURCE_REFERENCE_HINTS):
                        out.append(f"{WARN_PREFIX}tooling_security_reviews.json: {name}: "
                                   f"source_reference={sr!r} — слишком расплывчато, укажи "
                                   f"конкретно откуда взят инструмент (репозиторий/"
                                   f"маркетплейс/официальная страница/URL)")
                rb = r.get("reviewed_by")
                if isinstance(rb, str) and rb.strip().lower() in _VAGUE_REVIEWED_BY:
                    out.append(f"{WARN_PREFIX}tooling_security_reviews.json: {name}: "
                               f"reviewed_by={rb!r} — слишком расплывчато, укажи "
                               f"конкретного человека/роль")
    # эвристический скан skills/**/SKILL.md — независимо от наличия реестра
    skills_dir = root / "skills"
    if skills_dir.is_dir():
        for skill_file in sorted(skills_dir.rglob("SKILL.md")):
            text = skill_file.read_text(encoding="utf-8", errors="ignore")
            front = parse_front_matter(text)
            skill_name = front.get("name") if isinstance(front, dict) else None
            if skill_name in reviewed_names:
                continue  # уже есть запись ревью — не дублируем предупреждение
            for pattern, flag in _SUSPICIOUS_TOOLING_PATTERNS:
                if pattern.search(text):
                    rel = skill_file.relative_to(root)
                    out.append(f"{WARN_PREFIX}{rel}: похоже на red-flag паттерн "
                               f"({flag}), но нет записи в tooling_security_reviews.json — "
                               f"возможно ложное срабатывание (документация, не код), "
                               f"проверь вручную")
                    break
    return out


# --- sync/backup/secrets: три опциональных контракта (v2.9.47, ТЗ владельца) ---
def _load_registry_json(root: Path, name: str, schema_name: str,
                        schemas_root_arg: str | None, out: list[str]):
    """Общий приём: опциональный docs/registry/<name>; если есть — схема."""
    f = root / "docs" / "registry" / name
    if not f.exists():
        return None
    data, err = load_json(f)
    if err:
        out.append(f"битый {name}: {err}")
        return None
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / schema_name).exists():
        sch, _ = load_json(schemas_root / schema_name)
        if isinstance(sch, dict):
            out.extend(validate_schema(data, sch, name))
    return data


# --- независимые модули (v2.9.113, MODULE_BOUNDARIES_STANDARD.md) ---
_SCOPE_WILDCARD_CHARS = frozenset("*?[]")


def _is_simple_scope_pattern(pattern: str) -> bool:
    """v2.9.115 (P1 внешнего ревью v2.9.114, репродуцировано: src/app/*.py
    против src/app/main.py ложно НЕ пересекались — компонентная эвристика
    ниже сравнивает "*.py" с "main.py" как две РАЗНЫЕ литеральные строки,
    не разворачивая wildcard). Вместо полноценного glob-движка (риск тонких
    ошибок в намеренно упрощённом коде без внешних зависимостей) —
    ограничение грамматики: allowed_paths/path/related_paths поддерживают
    ТОЛЬКО точный путь (без wildcard-символов вообще) или путь-дерево вида
    "dir/**" (без wildcard-символов до суффикса). Любая другая glob-форма
    (*.py, ?, [abc], **/tests/**, src/*/api/**) — явная ошибка валидации,
    не тихо неверно обрабатываемый паттерн."""
    body = pattern[:-3] if pattern.endswith("/**") else pattern
    return not any(c in _SCOPE_WILDCARD_CHARS for c in body)


def _glob_base_components(path: str) -> list[str]:
    """Компоненты пути без завершающего '/**'. Компонентно, не по строке —
    иначе src/cat ложно "пересекался" бы с src/catalog. Вызывается только
    после _is_simple_scope_pattern() — вход уже ограничен простой формой."""
    stripped = path.rstrip("/")
    if stripped.endswith("/**"):
        stripped = stripped[:-3]
    elif stripped == "**":
        stripped = ""
    return [p for p in stripped.split("/") if p]


def _globs_overlap(a: str, b: str) -> bool:
    """a и b — уже проверенные _is_simple_scope_pattern() простые формы
    (точный путь или dir/**). Пересекаются, если один — компонентный
    префикс другого."""
    pa, pb = _glob_base_components(a), _glob_base_components(b)
    if not pa or not pb:
        return False
    shorter, longer = (pa, pb) if len(pa) <= len(pb) else (pb, pa)
    return longer[:len(shorter)] == shorter


def _pattern_within(inner: str, outer: str) -> bool:
    """inner (напр. allowed_paths задачи) содержится в outer (напр. module
    root/related_paths) — outer компонентный префикс inner. Направленная
    версия _globs_overlap (containment, не просто intersection)."""
    pi, po = _glob_base_components(inner), _glob_base_components(outer)
    if not pi or not po:
        return False
    return pi[:len(po)] == po


def _path_within_scope(file_path: str, patterns: list[str]) -> bool:
    """Реальный файловый путь (не паттерн) попадает хотя бы в один из
    patterns (уже проверенных _is_simple_scope_pattern())."""
    for pattern in patterns:
        if pattern.endswith("/**"):
            prefix = pattern[:-3]
            if file_path == prefix or file_path.startswith(prefix + "/"):
                return True
        elif file_path == pattern:
            return True
    return False


def check_module_registry(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/module_registry.json (опционален): границы независимых
    модулей — id/root/public_api/owned_data/may_import/must_not_import/
    composition_owner.

    v2.9.114 (P1×6 внешнего ревью v2.9.113, все репродуцированы): (1) пустой
    modules[] — warning, не hard error (реестр существует, но легитимно
    описывает bootstrap-состояние — тот же принцип, что у SUCCESS_PATTERNS.md/
    ANTI_PATTERNS.md, v2.9.91); (2) root теперь обязан существовать и быть
    каталогом, public_api — существовать файлом (раньше проверялся только
    path-эскейп, не реальность); (3) may_import ∩ must_not_import — явное
    противоречие (одно и то же одновременно разрешено и запрещено) теперь
    ошибка; (4) пересекающиеся module root (компонентно через
    _globs_overlap, не по строке) теперь ошибка; (5) пробельные
    root/composition_owner/элементы public_api/owned_data/may_import/
    must_not_import — через _is_placeholder_value() (тот же принцип, что уже
    применён в v2.9.108/111 к другим полям), раньше проходили как непустые
    строки; (6) self-reference в must_not_import раньше сравнивал id с ЦЕЛОЙ
    строкой (mid in must_not) — реалистичная dotted-запись
    ("project.modules.catalog.internal") не совпадала с "catalog" и не
    ловилась; теперь id ищется как компонент dotted-пути.

    AST-проверка, что реальный код модуля действительно соблюдает
    may_import/must_not_import — --check-module-boundaries
    (MODULE_BOUNDARIES_STANDARD.md §11)."""
    out: list[str] = []
    data = _load_registry_json(root, "module_registry.json", "module_registry.schema.json",
                               schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    modules = data.get("modules")
    if not isinstance(modules, list):
        return out
    if not modules:
        out.append(f"{WARN_PREFIX}module_registry.json: modules пуст — реестр существует, "
                   f"но не описывает ни одного модуля")
        return out
    seen: set[str] = set()
    roots: list[tuple[str, str]] = []
    for i, m in enumerate(modules):
        if not isinstance(m, dict):
            continue
        mid = m.get("id")
        tag = f"module_registry.json[{i}]" + (f" ({mid})" if isinstance(mid, str) and mid else "")
        if isinstance(mid, str) and mid:
            if mid in seen:
                out.append(f"{tag}: дублирующийся id")
            seen.add(mid)
        root_path = m.get("root")
        if _is_placeholder_value(root_path):
            out.append(f"{tag}: root пуст или похож на плейсхолдер")
        elif isinstance(root_path, str) and root_path:
            if _path_escapes_root(root, root_path):
                out.append(f"{tag}: root выходит за пределы --root: {root_path}")
            elif not (root / root_path).is_dir():
                out.append(f"{tag}: root не существует или не каталог: {root_path}")
            else:
                roots.append((tag, root_path))
        composition_owner = m.get("composition_owner")
        if composition_owner is not None and _is_placeholder_value(composition_owner):
            out.append(f"{tag}: composition_owner пуст или похож на плейсхолдер")
        for field in ("public_api", "owned_data", "may_import", "must_not_import", "related_paths", "layers"):
            for rel in m.get(field) or []:
                if _is_placeholder_value(rel):
                    out.append(f"{tag}: {field} содержит пустое/плейсхолдер-значение")
        layers_val = m.get("layers")
        if isinstance(layers_val, list) and layers_val:
            layer_names = [x for x in layers_val if isinstance(x, str) and x]
            if len(set(layer_names)) != len(layer_names):
                out.append(f"{tag}: layers содержит дубли — порядок слоёв должен быть однозначным")
            if not isinstance(m.get("package"), str) or not m.get("package"):
                out.append(f"{tag}: layers задан без package — Dependency Rule не будет "
                           f"проверяться (--check-module-boundaries не может сопоставить dotted-путь "
                           f"импорта со слоем без package), см. MODULE_BOUNDARIES_STANDARD.md §9")
            elif isinstance(root_path, str) and root_path and not _path_escapes_root(root, root_path) \
                    and (root / root_path).is_dir():
                for layer in layer_names:
                    if not (root / root_path / layer).is_dir():
                        out.append(f"{tag}: layers[{layer!r}] — поддиректория {root_path}/{layer} "
                                   f"не существует")
        else:
            layer_names = []
        lei = m.get("layer_external_imports")
        if isinstance(lei, dict) and lei:
            if not layer_names:
                out.append(f"{tag}: layer_external_imports задан без layers — ключи не могут "
                           f"сослаться ни на один слой, проверка не сработает ни для одного файла")
            for layer_key, policy in lei.items():
                if layer_names and layer_key not in layer_names:
                    out.append(f"{tag}: layer_external_imports[{layer_key!r}] — слой не объявлен "
                               f"в layers ({layer_names!r}), опечатка?")
                if not isinstance(policy, dict):
                    continue
                for field in ("forbidden_external_imports", "allowed_external_imports"):
                    for item in policy.get(field) or []:
                        if _is_placeholder_value(item):
                            out.append(f"{tag}: layer_external_imports[{layer_key!r}].{field} "
                                       f"содержит пустое/плейсхолдер-значение")
        for rel in m.get("public_api", []) or []:
            if not isinstance(rel, str) or not rel:
                continue
            if _path_escapes_root(root, rel):
                out.append(f"{tag}: public_api выходит за пределы --root: {rel}")
            elif not (root / rel).is_file():
                out.append(f"{tag}: public_api не существует: {rel}")
        for rel in m.get("related_paths", []) or []:
            if not isinstance(rel, str) or not rel:
                continue
            if _path_escapes_root(root, rel):
                out.append(f"{tag}: related_paths выходит за пределы --root: {rel}")
            elif not _is_simple_scope_pattern(rel):
                out.append(f"{tag}: related_paths использует неподдерживаемый glob-синтаксис "
                           f"{rel!r} — поддерживаются только точный путь или dir/**")
        may_import = m.get("may_import")
        must_not = m.get("must_not_import")
        if isinstance(may_import, list) and isinstance(must_not, list):
            may_set = {x for x in may_import if isinstance(x, str)}
            must_set = {x for x in must_not if isinstance(x, str)}
            for clash in sorted(may_set & must_set):
                out.append(f"{tag}: {clash!r} одновременно в may_import и must_not_import")
        if isinstance(mid, str) and mid and isinstance(must_not, list):
            for entry in must_not:
                if isinstance(entry, str) and mid in entry.split("."):
                    out.append(f"{tag}: собственный id {mid!r} перечислен в must_not_import "
                               f"({entry!r}) — модуль не может запрещать импорт самого себя")
                    break
    for j, (tag_a, root_a) in enumerate(roots):
        for tag_b, root_b in roots[j + 1:]:
            if _globs_overlap(root_a, root_b):
                out.append(f"{tag_a} и {tag_b}: пересекающиеся root ({root_a} / {root_b})")
    return out


def check_code_ownership(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/code_ownership.json (опционален): сопоставление path ->
    owner/access.

    v2.9.114 (P1×3 внешнего ревью v2.9.113, все репродуцированы): (1) пустой
    ownership[] — warning, не hard error (тот же bootstrap-принцип, что у
    module_registry.json выше); (2) пробельные path/owner — через
    _is_placeholder_value(), раньше проходили; (3) пересечение РАЗНЫХ путей у
    РАЗНЫХ владельцев внутри самого реестра (компонентная эвристика
    _globs_overlap — src/** и src/catalog/** пересекаются, src/catalog/** и
    src/matching/** нет) — раньше ловились только точные дубликаты одной и
    той же строки path, не пересечение разных.

    v2.9.115 (P1 внешнего ревью v2.9.114, репродуцировано): path теперь
    обязан быть простой формы (_is_simple_scope_pattern — точный путь или
    dir/**) — раньше src/app/*.py тихо принимался, но _globs_overlap
    сравнивал "*.py" с реальным именем файла как две разные литеральные
    строки и не находил очевидного пересечения.

    Это проверка СТАТИЧЕСКОГО реестра. Проверка пересечения между АКТИВНЫМИ
    (сейчас выполняемыми) work package — отдельный механизм с отдельным
    источником данных, т.к. code_ownership.json описывает постоянное
    review-владение, а не временную аренду scope на время задачи — см.
    --check-work-package-overlap (docs/registry/active_work_packages.json,
    MODULE_BOUNDARIES_STANDARD.md §11)."""
    out: list[str] = []
    data = _load_registry_json(root, "code_ownership.json", "code_ownership.schema.json",
                               schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    ownership = data.get("ownership")
    if not isinstance(ownership, list):
        return out
    if not ownership:
        out.append(f"{WARN_PREFIX}code_ownership.json: ownership пуст — реестр существует, "
                   f"но не описывает ни одной зоны владения")
        return out
    seen_paths: set[str] = set()
    entries: list[tuple[str, str, str]] = []
    for i, entry in enumerate(ownership):
        if not isinstance(entry, dict):
            continue
        path = entry.get("path")
        owner = entry.get("owner")
        tag = f"code_ownership.json[{i}]" + (f" ({path})" if isinstance(path, str) and path else "")
        if _is_placeholder_value(path):
            out.append(f"{tag}: path пуст или похож на плейсхолдер")
        if _is_placeholder_value(owner):
            out.append(f"{tag}: owner пуст или похож на плейсхолдер")
        if isinstance(path, str) and path:
            if _path_escapes_root(root, path):
                out.append(f"{tag}: path выходит за пределы --root: {path}")
            elif not _is_simple_scope_pattern(path):
                out.append(f"{tag}: path использует неподдерживаемый glob-синтаксис "
                           f"{path!r} — поддерживаются только точный путь или dir/**")
            if path in seen_paths:
                out.append(f"{tag}: дублирующийся path")
            seen_paths.add(path)
            if isinstance(owner, str) and owner:
                entries.append((tag, path, owner))
    for j, (tag_a, path_a, owner_a) in enumerate(entries):
        for tag_b, path_b, owner_b in entries[j + 1:]:
            if owner_a != owner_b and _globs_overlap(path_a, path_b):
                out.append(f"{tag_a} и {tag_b}: пересекающиеся path у разных владельцев "
                           f"({owner_a} / {owner_b})")
    return out


def _import_matches_forbidden(imported: str, forbidden: str) -> bool:
    """imported нарушает forbidden, если это тот же dotted-путь целиком, или
    путь СТРОГО ГЛУБЖЕ него (imported импортирует конкретный символ/подпакет
    ИЗ forbidden). НЕ наоборот: import project.modules.catalog (родитель) не
    обязательно достаёт .internal — это дало бы ложные срабатывания."""
    return imported == forbidden or imported.startswith(forbidden + ".")


def _resolve_relative_import(file_path: Path, module_dir: Path, module_package: str,
                              node: "ast.ImportFrom") -> list[str]:
    """v2.9.115: резолвит относительный импорт (node.level > 0) в dotted-
    путь(и) — кандидаты для сверки с must_not_import. Использует dotted
    package-префикс модуля (module_registry.json[].package) + позицию файла
    внутри root модуля. "." в "from .x import y" всегда означает СОБСТВЕННЫЙ
    пакет файла (директорию, содержащую файл — одинаково для __init__.py и
    обычных модулей), каждая следующая точка поднимается на уровень выше —
    тот же алгоритм, что использует сам Python. Возвращает [], если level
    уходит выше того, что известно из package-префикса модуля (не гадаем
    про структуру выше него).

    v2.9.117 (P1 внешнего ревью v2.9.116, репродуцировано): при непустом
    node.module возвращался только резолвленный модуль (project.modules.
    matching), без кандидата resolved_module.alias — "from ...matching
    import adapters" не ловился как импорт .adapters, хотя абсолютная форма
    "from package import forbidden_child" эту же дыру уже закрыла (см.
    candidates ниже по коду). Теперь оба случая строят кандидатов
    одинаково: сам модуль + модуль.имя для каждого импортированного alias."""
    try:
        dir_parts = list(file_path.parent.relative_to(module_dir).parts)
    except ValueError:
        return []
    base_parts = module_package.split(".") + dir_parts
    strip = node.level - 1
    if strip >= len(base_parts):
        return []
    if strip:
        base_parts = base_parts[:-strip]
    if node.module:
        resolved_module = ".".join(base_parts + node.module.split("."))
        return [resolved_module] + [f"{resolved_module}.{a.name}" for a in node.names]
    return [".".join(base_parts + [a.name]) for a in node.names]


_DYNAMIC_IMPORT_CALLS = frozenset({"import_module", "__import__"})


def _layer_of_file(file_path: Path, module_dir: Path, layers: list[str]) -> str | None:
    """v2.9.116: первый компонент пути файла относительно module_dir, если
    совпадает с одним из объявленных layers. None — файл живёт вне
    объявленных слоёв (прямо в root или в неучтённой поддиректории) — не
    участвует в Dependency Rule проверке."""
    try:
        rel_parts = file_path.relative_to(module_dir).parts
    except ValueError:
        return None
    return rel_parts[0] if rel_parts and rel_parts[0] in layers else None


def _layer_of_dotted_import(imported: str, module_package: str, layers: list[str]) -> str | None:
    """v2.9.116: если imported — dotted-путь ВНУТРИ этого же модуля (module_
    package-префикс) и следующий компонент — объявленный слой, возвращает
    его. None — импорт вне модуля или вне объявленных слоёв (не Dependency
    Rule забота — может быть must_not_import находкой отдельно)."""
    prefix = module_package + "."
    if not imported.startswith(prefix):
        return None
    first = imported[len(prefix):].split(".", 1)[0]
    return first if first in layers else None


def _emit_layer_violations(candidates: list[str], source_layer: str | None, module_package: str | None,
                           layers: list[str], mid: str, rel: Path, lineno: int, out: list[str],
                           via: str = "импорт") -> None:
    """v2.9.116: Dependency Rule — layers[] упорядочен от самого стабильного
    (индекс 0, напр. domain) к самому нестабильному (напр. adapters);
    зависимости разрешены только к РАВНОМУ или БОЛЕЕ раннему индексу
    (наружу → внутрь), никогда наоборот. Требует одновременно заданных
    module.layers И module.package (без package не можем сопоставить
    dotted-путь импорта с директорией слоя — тот же принцип, что у резолва
    относительных импортов v2.9.115: не гадаем)."""
    if not source_layer or not module_package or not layers:
        return
    src_idx = layers.index(source_layer)
    for candidate in candidates:
        target_layer = _layer_of_dotted_import(candidate, module_package, layers)
        if target_layer is None or target_layer == source_layer:
            continue
        if src_idx < layers.index(target_layer):
            out.append(f"module-boundaries: {mid}: {rel}:{lineno}: {via} {candidate!r} — слой "
                       f"{source_layer!r} зависит от менее стабильного слоя {target_layer!r} "
                       f"(layers: {layers!r}) — нарушение Dependency Rule")


def _forbidden_external_imports_for_layer(layer_external_imports: dict, layer: str | None) -> list[str]:
    """v2.9.117: forbidden_external_imports объявленного слоя — [] если слой
    не задан или у него нет собственной политики (opt-in для каждого слоя
    по отдельности, не только для модуля в целом)."""
    if not layer:
        return []
    policy = layer_external_imports.get(layer)
    if not isinstance(policy, dict):
        return []
    return [x for x in (policy.get("forbidden_external_imports") or []) if isinstance(x, str) and x]


def _emit_external_import_violations(candidates: list[str], source_layer: str | None,
                                     layer_external_imports: dict, mid: str, rel: Path, lineno: int,
                                     out: list[str], via: str = "импорт") -> None:
    """v2.9.117 (P1 внешнего ревью v2.9.116, репродуцировано: 'external
    framework imports into domain not caught') — Dependency Rule (B) в
    _emit_layer_violations проверяет только импорты МЕЖДУ слоями ВНУТРИ
    модуля; domain, импортирующий flask/sqlalchemy напрямую, никогда не
    матчился ни одним candidate из другого слоя, потому что flask вообще
    не является поддиректорией модуля. Здесь — отдельная, дополняющая
    проверка: forbidden_external_imports слоя сравнивается с dotted-путём
    импорта тем же _import_matches_forbidden, что уже используется для
    must_not_import (denylist — см. _emit_external_import_allowlist_
    violations() для дополняющего opt-in allowlist-режима, v2.9.118)."""
    forbidden_ext = _forbidden_external_imports_for_layer(layer_external_imports, source_layer)
    if not forbidden_ext:
        return
    for candidate in candidates:
        for fx in forbidden_ext:
            if _import_matches_forbidden(candidate, fx):
                out.append(f"module-boundaries: {mid}: {rel}:{lineno}: слой {source_layer!r} "
                           f"— {via} {candidate!r} запрещён внешний импорт для этого слоя "
                           f"(layer_external_imports[{source_layer!r}].forbidden_external_imports: "
                           f"{fx!r})")


def _allowed_external_imports_for_layer(layer_external_imports: dict, layer: str | None) -> list[str]:
    """v2.9.118 (§10.1 внешнего аудита v2.9.117): allowed_external_imports
    объявленного слоя — [] если слой не задан или allowlist для него не
    включён (opt-in для каждого слоя по отдельности, симметрично
    _forbidden_external_imports_for_layer)."""
    if not layer:
        return []
    policy = layer_external_imports.get(layer)
    if not isinstance(policy, dict):
        return []
    return [x for x in (policy.get("allowed_external_imports") or []) if isinstance(x, str) and x]


def _is_self_import(candidate: str, module_package: str | None) -> bool:
    """Импорт своего же пакета модуля — не «внешний» по определению, вне
    зависимости от allowlist/denylist. Единственное исключение allowlist-
    режима, не требующее классификации stdlib/third-party (module_package —
    явное поле реестра, не эвристика)."""
    if not module_package:
        return False
    return candidate == module_package or candidate.startswith(module_package + ".")


def _emit_external_import_allowlist_violations(candidates: list[str], source_layer: str | None,
                                               layer_external_imports: dict, module_package: str | None,
                                               mid: str, rel: Path, lineno: int,
                                               out: list[str], via: str = "импорт") -> None:
    """v2.9.118 (§10.1 внешнего аудита v2.9.117: «Предпочтительно
    поддержать: allowlist для строгого domain, denylist как дополнительную
    защиту» — allowed_external_imports был ТОЛЬКО документационным с
    v2.9.117, см. CHANGELOG). Opt-in per-слой: если allowed_external_imports
    непустой, КАЖДЫЙ внешний импорт этого слоя обязан совпадать (точно или
    как более глубокий подпуть, та же _import_matches_forbidden, что и для
    denylist — направление сравнения общее для обеих ролей) хотя бы с одной
    записью списка, иначе — находка. Единственное исключение без явного
    перечисления — импорт СОБСТВЕННОГО пакета модуля (_is_self_import):
    это не решает общую задачу классификации stdlib/third-party/чужой код
    (аудит explicitly требует перечислять даже stdlib — 'dataclasses,
    typing, decimal, enum' для строгого domain), только устраняет один
    источник гарантированных ложных срабатываний. Аддитивно с denylist —
    оба режима могут быть заданы для одного слоя одновременно."""
    allowed_ext = _allowed_external_imports_for_layer(layer_external_imports, source_layer)
    if not allowed_ext:
        return
    for candidate in candidates:
        if _is_self_import(candidate, module_package):
            continue
        if not any(_import_matches_forbidden(candidate, ax) for ax in allowed_ext):
            out.append(f"module-boundaries: {mid}: {rel}:{lineno}: слой {source_layer!r} "
                       f"— {via} {candidate!r} не входит в allowed_external_imports слоя "
                       f"(layer_external_imports[{source_layer!r}].allowed_external_imports: "
                       f"{allowed_ext!r}) — при заданном allowlist разрешены только "
                       f"перечисленные внешние импорты (v2.9.118, §10.1 внешнего аудита v2.9.117)")


def _check_import_candidates(candidates: list[str], forbidden: list[str], source_layer: str | None,
                             module_package: str | None, layers: list[str], layer_external_imports: dict,
                             mid: str, rel: Path, lineno: int, out: list[str], via: str = "импорт") -> None:
    """v2.9.123 (P1 внешнего аудита v2.9.122, A-1, репродуцировано: `from
    ...matching import adapters` проходил с 0 находок, хотя абсолютная форма
    того же импорта блокировалась). Единственное место, вызывающее ВСЕ
    четыре проверки импорта — must_not_import denylist, layer Dependency
    Rule, forbidden_external_imports слоя, allowed_external_imports слоя —
    вместо того, чтобы каждая ветка AST-обхода (ast.ImportFrom level==0,
    ast.ImportFrom level>0, ast.Import) вызывала подмножество эмиттеров
    по отдельности. Корневая причина была структурной: ветка относительных
    импортов (level>0) вызывала только 2 из 4 — новая ветка (или пятый
    эмиттер) больше не может так же незаметно разойтись с остальными,
    потому что расходиться просто негде."""
    for candidate in candidates:
        for fb in forbidden:
            if _import_matches_forbidden(candidate, fb):
                out.append(f"module-boundaries: {mid}: {rel}:{lineno}: {via} {candidate!r} "
                           f"запрещён (must_not_import: {fb!r})")
    _emit_layer_violations(candidates, source_layer, module_package, layers, mid, rel, lineno, out, via=via)
    _emit_external_import_violations(candidates, source_layer, layer_external_imports, mid, rel, lineno,
                                     out, via=via)
    _emit_external_import_allowlist_violations(candidates, source_layer, layer_external_imports, module_package,
                                               mid, rel, lineno, out, via=via)


def check_module_boundaries(root: Path, schemas_root_arg: str | None) -> list[str]:
    """--check-module-boundaries (v2.9.114, реализует ранее отложенный
    AST-сканер — MODULE_BOUNDARIES_STANDARD.md §11). Требует docs/registry/
    module_registry.json; без него no-op (тот же opt-in принцип, что у
    остальных модульных проверок).

    Для каждого модуля с непустым must_not_import И/ИЛИ заданными layers
    обходит .py-файлы под его root, разбирает import/from-import через AST.

    Три независимых, но использующих один AST-обход правила:
    (A) must_not_import (v2.9.114): сравнивает импортированный dotted-путь с
        каждой записью денилиста (_import_matches_forbidden) — МЕЖДУ
        модулями;
    (B) layers (v2.9.116, Dependency Rule из Clean Architecture): при
        одновременно заданных module.layers И module.package проверяет
        направление зависимостей ВНУТРИ модуля — слой не может импортировать
        менее стабильный слой (_emit_layer_violations). Опционально, как и
        must_not_import — модули без layers не затронуты (MODULE_BOUNDARIES_
        STANDARD.md §4 профиль "minimal" остаётся ничем не ограничен).
    (C) layer_external_imports (v2.9.117, P1 внешнего ревью v2.9.116:
        "external framework imports into domain not caught" — (B) ловит
        только импорты МЕЖДУ слоями внутри модуля, но domain, напрямую
        импортирующий flask/sqlalchemy, ни под одно из существующих
        правил не подпадал, т.к. эти пакеты — не поддиректория модуля).
        При заданном module.layer_external_imports[layer].
        forbidden_external_imports сравнивает импорт файлов этого слоя с
        денилистом тем же _import_matches_forbidden, что и (A)
        (_emit_external_import_violations). v2.9.118 (§10.1 внешнего
        аудита v2.9.117): allowed_external_imports теперь ТОЖЕ enforced —
        opt-in allowlist-режим, аддитивный к denylist (см. (2) ниже)
        (_emit_external_import_allowlist_violations).

    Явные, не тихие ограничения scope (см. MODULE_BOUNDARIES_STANDARD.md
    §11):
    (1) относительные импорты (from . import x, from ..sibling import y)
        резолвятся ТОЛЬКО если у модуля задан опциональный package (v2.9.115
        — dotted-префикс, соответствующий root); без package — не
        проверяются (не гадаем) — это же ограничение автоматически
        распространяется на (B), т.к. layers требует package. (C) на
        относительные импорты не распространяется вовсе (ни denylist, ни
        allowlist) — относительный импорт по определению внутренний,
        никогда не внешний пакет;
    (2) may_import (межмодульный уровень) остаётся ТОЛЬКО документационным
        — enforcement потребовал бы классифицировать "это импорт другого
        МОДУЛЯ или stdlib/third-party/своего кода" для ЧУЖИХ модулей, а не
        просто "внешний ли это пакет вообще" (module_registry.json не
        перечисляет все свои модули с precision, достаточной для этого).
        layer_external_imports[layer].allowed_external_imports (v2.9.118,
        внутримодульный уровень) — enforced: единственное исключение без
        явного перечисления — импорт СОБСТВЕННОГО пакета модуля
        (_is_self_import, module.package — явное поле, не эвристика),
        stdlib/third-party классифицировать не нужно, т.к. allowlist
        требует перечислить ИХ ВСЕ явно (см. пример в MODULE_BOUNDARIES_
        STANDARD.md §11 — 'dataclasses, typing, decimal, enum' для
        строгого domain);
    (3) динамические импорты (importlib.import_module(...)/__import__(...))
        с буквальной строкой-аргументом — warning, не error, для (A) и (C)
        (обе роли — denylist и allowlist); для (B) Dependency Rule для
        динамических импортов не проверяется вовсе (редкий случай внутри
        одного модуля, риск ложных срабатываний перевешивает пользу)."""
    out: list[str] = []
    mr_data = _load_registry_json(root, "module_registry.json", "module_registry.schema.json",
                                  schemas_root_arg, [])
    if not isinstance(mr_data, dict):
        return out
    modules = mr_data.get("modules")
    if not isinstance(modules, list):
        return out
    packages_by_id: dict[str, str] = {
        m["id"]: m["package"] for m in modules
        if isinstance(m, dict) and isinstance(m.get("id"), str)
        and isinstance(m.get("package"), str) and m["package"]
    }
    for m in modules:
        if not isinstance(m, dict):
            continue
        mid = m.get("id")
        root_path = m.get("root")
        forbidden = [x for x in (m.get("must_not_import") or []) if isinstance(x, str) and x]
        layers = [x for x in (m.get("layers") or []) if isinstance(x, str) and x]
        layer_external_imports = m.get("layer_external_imports")
        if not isinstance(layer_external_imports, dict):
            layer_external_imports = {}
        if (not forbidden and not layers) or not isinstance(root_path, str) or not root_path:
            continue
        if _path_escapes_root(root, root_path):
            continue  # уже отдельная находка в check_module_registry, не дублируем
        module_dir = root / root_path
        if not module_dir.is_dir():
            continue
        module_package = packages_by_id.get(mid) if isinstance(mid, str) else None
        for f in sorted(module_dir.rglob("*.py")):
            rel = f.relative_to(root)
            tree = parse_python(f)
            if tree is None:
                out.append(f"module-boundaries: {mid}: {rel}: не удалось разобрать через AST "
                           f"(SyntaxError) — файл не проверен, требуется ручная проверка")
                continue
            source_layer = _layer_of_file(f, module_dir, layers) if layers else None
            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    candidates = [node.module] + [f"{node.module}.{a.name}" for a in node.names]
                    _check_import_candidates(candidates, forbidden, source_layer, module_package, layers,
                                             layer_external_imports, mid, rel, node.lineno, out)
                elif isinstance(node, ast.ImportFrom) and node.level > 0 and module_package:
                    resolved = _resolve_relative_import(f, module_dir, module_package, node)
                    _check_import_candidates(resolved, forbidden, source_layer, module_package, layers,
                                             layer_external_imports, mid, rel, node.lineno, out,
                                             via="относительный импорт")
                elif isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                    _check_import_candidates(names, forbidden, source_layer, module_package, layers,
                                             layer_external_imports, mid, rel, node.lineno, out)
                elif isinstance(node, ast.Call):
                    func = node.func
                    name = (func.attr if isinstance(func, ast.Attribute)
                            else func.id if isinstance(func, ast.Name) else None)
                    if name in _DYNAMIC_IMPORT_CALLS and node.args \
                            and isinstance(node.args[0], ast.Constant) \
                            and isinstance(node.args[0].value, str):
                        target = node.args[0].value
                        for fb in forbidden:
                            if _import_matches_forbidden(target, fb):
                                out.append(f"{WARN_PREFIX}module-boundaries: {mid}: {rel}:{node.lineno}: "
                                           f"динамический импорт {target!r} похож на запрещённый "
                                           f"(must_not_import: {fb!r}) — проверь вручную")
                        for fx in _forbidden_external_imports_for_layer(layer_external_imports, source_layer):
                            if _import_matches_forbidden(target, fx):
                                out.append(f"{WARN_PREFIX}module-boundaries: {mid}: {rel}:{node.lineno}: "
                                           f"динамический импорт {target!r} похож на запрещённый внешний "
                                           f"импорт слоя {source_layer!r} (forbidden_external_imports: "
                                           f"{fx!r}) — проверь вручную")
                        allowed_ext = _allowed_external_imports_for_layer(layer_external_imports, source_layer)
                        if allowed_ext and not _is_self_import(target, module_package) \
                                and not any(_import_matches_forbidden(target, ax) for ax in allowed_ext):
                            out.append(f"{WARN_PREFIX}module-boundaries: {mid}: {rel}:{node.lineno}: "
                                       f"динамический импорт {target!r} не входит в allowed_external_imports "
                                       f"слоя {source_layer!r} — проверь вручную (v2.9.118)")
    return out


def _find_cycle(graph: dict[str, list[str]]) -> list[str] | None:
    """Первый найденный цикл (список id по кругу) через DFS с
    белый/серый/чёрный маркерами узлов. Неизвестные id в depends_on здесь
    игнорируются — они отдельная находка (check_work_package_graph)."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color = {node: WHITE for node in graph}

    def visit(node: str, path: list[str]) -> list[str] | None:
        color[node] = GRAY
        for neighbor in graph.get(node, []):
            if neighbor not in color:
                continue
            if color[neighbor] == GRAY:
                idx = path.index(neighbor)
                return path[idx:] + [neighbor]
            if color[neighbor] == WHITE:
                found = visit(neighbor, path + [neighbor])
                if found:
                    return found
        color[node] = BLACK
        return None

    for node in graph:
        if color[node] == WHITE:
            found = visit(node, [node])
            if found:
                return found
    return None


def check_work_package_graph(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/work_package_graph.json (опционален, v2.9.114, реализует
    ранее отложенный --check-work-package-graph — MODULE_BOUNDARIES_
    STANDARD.md §11): id/status/depends_on. Статусный словарь — TODO/WIP/
    BLOCKED/DONE/FAILED (переиспользует SOFTWARE_DEVELOPMENT_LIFECYCLE_
    STANDARD.md §9.1 TODO/WIP/BLOCKED/DONE + FAILED, не изобретает
    отдельный).

    Проверяется: уникальность id; depends_on ссылается только на известные
    id (не опечатка); self-dependency (id в собственном depends_on);
    циклы графа (не только прямые, любой длины); зависимость от FAILED
    work package (тупиковая ветка, продолжать нельзя); WIP/DONE work
    package, у которого хотя бы один depends_on ещё не DONE (начал/закончил
    работу до готовности предпосылки — нарушение заявленного порядка)."""
    out: list[str] = []
    data = _load_registry_json(root, "work_package_graph.json", "work_package_graph.schema.json",
                               schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    wps = data.get("work_packages")
    if not isinstance(wps, list):
        return out
    if not wps:
        out.append(f"{WARN_PREFIX}work_package_graph.json: work_packages пуст — реестр существует, "
                   f"но не описывает ни одного work package")
        return out
    seen: set[str] = set()
    status_by_id: dict[str, str] = {}
    deps_by_id: dict[str, list[str]] = {}
    for i, wp in enumerate(wps):
        if not isinstance(wp, dict):
            continue
        wid = wp.get("id")
        tag = f"work_package_graph.json[{i}]" + (f" ({wid})" if isinstance(wid, str) and wid else "")
        if isinstance(wid, str) and wid:
            if not _SAFE_REGISTRY_ID_RE.match(wid):
                out.append(f"{tag}: id {wid!r} использует небезопасные символы — разрешены только "
                          f"буквы/цифры/./_/- (не '/', не '..', не пробел); id участвует в "
                          f"построении пути agent_results/<id>.json при DONE (v2.9.121, P1 "
                          f"внешнего аудита v2.9.120: path traversal через id)")
                continue
            if wid in seen:
                out.append(f"{tag}: дублирующийся id")
            seen.add(wid)
            status = wp.get("status")
            if isinstance(status, str):
                status_by_id[wid] = status
            deps = [d for d in (wp.get("depends_on") or []) if isinstance(d, str)]
            deps_by_id[wid] = deps
    for i, wp in enumerate(wps):
        if not isinstance(wp, dict):
            continue
        wid = wp.get("id")
        if not isinstance(wid, str) or not wid:
            continue
        tag = f"work_package_graph.json[{i}] ({wid})"
        deps = deps_by_id.get(wid, [])
        if wid in deps:
            out.append(f"{tag}: зависит от самого себя")
        for dep in deps:
            if dep not in seen:
                out.append(f"{tag}: depends_on ссылается на неизвестный id: {dep!r}")
                continue
            if status_by_id.get(dep) == "FAILED":
                out.append(f"{tag}: зависит от FAILED work package {dep!r}")
        my_status = status_by_id.get(wid)
        if my_status in ("WIP", "DONE"):
            not_done = [d for d in deps if d in seen and status_by_id.get(d) != "DONE"]
            if not_done:
                out.append(f"{tag}: status={my_status}, но depends_on {sorted(not_done)!r} "
                           f"ещё не DONE — начато/закончено до готовности предпосылки")
    cycle = _find_cycle(deps_by_id)
    if cycle:
        out.append(f"work_package_graph.json: циклическая зависимость: {' -> '.join(cycle)}")
    return out


def _agent_tasks_index(root: Path) -> dict[str, list[str]] | None:
    """task_id -> allowed_paths по всем docs/registry/agent_tasks/*.json.
    None означает "директория отсутствует — не проверяем", не "пусто"
    (тот же принцип differentiации, что у остальных cross-check helper'ов
    этого файла)."""
    tasks_dir = root / "docs" / "registry" / "agent_tasks"
    if not tasks_dir.is_dir():
        return None
    index: dict[str, list[str]] = {}
    for f in sorted(tasks_dir.glob("*.json")):
        data, err = load_json(f)
        if err or not isinstance(data, dict):
            continue
        tid = data.get("task_id")
        if not isinstance(tid, str) or not tid:
            continue
        index[tid] = [p for p in (data.get("allowed_paths") or []) if isinstance(p, str) and p]
    return index


def _work_package_graph_ids(root: Path) -> set[str] | None:
    """Известные id из work_package_graph.json. None — реестр отсутствует."""
    graph_path = root / "docs" / "registry" / "work_package_graph.json"
    if not graph_path.exists():
        return None
    data, err = load_json(graph_path)
    if err or not isinstance(data, dict) or not isinstance(data.get("work_packages"), list):
        return set()
    return {wp.get("id") for wp in data["work_packages"]
            if isinstance(wp, dict) and isinstance(wp.get("id"), str)}


def _work_package_graph_status_by_id(root: Path) -> dict[str, str] | None:
    """v2.9.118 (P0 внешнего аудита v2.9.117): id -> status из
    work_package_graph.json — используется check_work_package_overlap()
    для сверки graph.status с наличием/статусом active lease. Реальный
    словарь статусов — TODO/WIP/BLOCKED/DONE/FAILED (work_package_graph.
    schema.json), не более богатая модель из аудита (READY/CANCELLED там
    не существуют — не изобретаем поверх реального словаря)."""
    graph_path = root / "docs" / "registry" / "work_package_graph.json"
    if not graph_path.exists():
        return None
    data, err = load_json(graph_path)
    if err or not isinstance(data, dict) or not isinstance(data.get("work_packages"), list):
        return {}
    return {wp["id"]: wp["status"] for wp in data["work_packages"]
            if isinstance(wp, dict) and isinstance(wp.get("id"), str)
            and isinstance(wp.get("status"), str)}


def _work_package_graph_depends_on_by_id(root: Path) -> dict[str, list[str]] | None:
    """v2.9.118 (P0 внешнего аудита v2.9.117): id -> depends_on из
    work_package_graph.json — используется check_agent_task_contracts()
    для сверки с task.depends_on (единственный источник истины
    зависимостей — граф, task.depends_on обязан быть согласованным
    snapshot). None — реестр отсутствует (не 'нет зависимостей', а 'нечего
    сверять')."""
    graph_path = root / "docs" / "registry" / "work_package_graph.json"
    if not graph_path.exists():
        return None
    data, err = load_json(graph_path)
    if err or not isinstance(data, dict) or not isinstance(data.get("work_packages"), list):
        return {}
    result: dict[str, list[str]] = {}
    for wp in data["work_packages"]:
        if isinstance(wp, dict) and isinstance(wp.get("id"), str):
            result[wp["id"]] = [d for d in (wp.get("depends_on") or []) if isinstance(d, str)]
    return result


def _active_lease_task_ids(root: Path) -> set[str] | None:
    """v2.9.119 (P1 внешнего аудита v2.9.118): task_id из docs/registry/
    active_work_packages.json.active[] — используется check_agent_workflow_
    integrity() для обратного направления графа: «WIP требует активную
    аренду», не только «аренда требует существующий task/graph node»
    (последнее уже проверял check_work_package_overlap() до этого цикла).
    None — реестр отсутствует (не 'аренд нет', а 'нечего сверять')."""
    path = root / "docs" / "registry" / "active_work_packages.json"
    if not path.exists():
        return None
    data, err = load_json(path)
    if err or not isinstance(data, dict) or not isinstance(data.get("active"), list):
        return set()
    return {e["task_id"] for e in data["active"]
            if isinstance(e, dict) and isinstance(e.get("task_id"), str) and e["task_id"]}


def check_work_package_overlap(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/active_work_packages.json (опционален, v2.9.114,
    реализует ранее отложенный --check-work-package-overlap черновика —
    MODULE_BOUNDARIES_STANDARD.md §11): task_id/status/branch/worktree/
    allowed_paths — ВРЕМЕННАЯ аренда write-scope на время выполнения задачи.
    Отдельная сущность от code_ownership.json (постоянное review-владение):
    один агент может ПОСТОЯННО отвечать за модуль (code_ownership.json), но
    активно писать в него ПРЯМО СЕЙЧАС только в рамках конкретной задачи с
    конкретным allowed_paths (этот реестр) — путаница этих двух понятий и
    была прямой находкой ревью v2.9.113.

    Проверяется: уникальность task_id, allowed_paths не выходят за --root и
    используют только простую glob-форму (_is_simple_scope_pattern),
    пересечение allowed_paths МЕЖДУ РАЗНЫМИ активными записями (active task
    A allowed_paths ∩ active task B allowed_paths = ∅ — тот самый механизм,
    которого не хватало для реального предотвращения конфликтов нескольких
    одновременно работающих AI-помощников).

    v2.9.115 (P2 внешнего ревью v2.9.114, репродуцировано — собственное
    упущение: тот же _is_placeholder_value()-принцип, что уже применён к
    module_registry.json/code_ownership.json в этом же цикле, не был
    превентивно применён к СВОЕМУ ЖЕ новому реестру): пробельные
    task_id/branch/worktree теперь ловятся, worktree проверяется на
    path-эскейп (раньше проверялся только allowed_paths).

    Кросс-проверка task_id против agent_tasks/*.json и work_package_graph.
    json, и allowed_paths аренды ⊆ allowed_paths задачи — см.
    check_agent_task_contracts() (module_id-подобная ссылка в обратную
    сторону) и test_validate_structure.py.

    v2.9.118 (P0 внешнего аудита v2.9.117 — «Реестры и проверки существуют
    отдельно, но между ними остаются разрывы ссылочной и поведенческой
    целостности», реестр задач → граф → аренда): (1) graph.status vs
    lease — состояние-машина по РЕАЛЬНОМУ словарю work_package_graph.
    schema.json (TODO/WIP/BLOCKED/DONE/FAILED, не более богатая
    ACTIVE/PAUSED/STALE/RELEASED-модель из аудита, которой у графа не
    существует): TODO/DONE/FAILED несовместимы с активной арендой, WIP
    требует IN_PROGRESS/PAUSED/STALE, BLOCKED допускает только PAUSED;
    (2) branch/worktree уникальны МЕЖДУ активными арендами (не только
    allowed_paths); (3) status=STALE — громкий warning каждый прогон, не
    тихое молчание (не снимается автоматически, см. схему); (4) branch/
    worktree, если объявлены, сверяются с РЕАЛЬНЫМ git-состоянием — вторая
    git-читающая проверка в этом файле после check_active_task_diff() (см.
    _git_worktree_branch_map()/_git_branch_exists()), строго opt-in:
    ноль subprocess-вызовов, если ни одна запись не объявила worktree/
    branch, и молчаливый skip (не hard fail) вне git-репозитория. Branch
    naming policy (аудит §6.2) сознательно НЕ реализована этим циклом —
    нет существующей конвенции имени ветки в пакете, изобретать её с нуля
    без владельца — не эта задача (см. CHANGELOG v2.9.118)."""
    out: list[str] = []
    data = _load_registry_json(root, "active_work_packages.json", "active_work_packages.schema.json",
                               schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    active = data.get("active")
    if not isinstance(active, list):
        return out
    if not active:
        # v2.9.126: normal idle state; golden strict CI must be truly green.
        return out
    task_allowed_paths = _agent_tasks_index(root)
    task_ids = set(task_allowed_paths) if task_allowed_paths is not None else None
    graph_ids = _work_package_graph_ids(root)
    graph_status = _work_package_graph_status_by_id(root)
    # v2.9.119 (P1 внешнего аудита v2.9.118): GIT_WORKSPACE_HYGIENE_STANDARD.md
    # уже заявляет «parallel work = branch + worktree + PR», git_agent_policy.
    # json уже объявляет parallel_agent_work_requires_worktree=true — но ни
    # одна проверка не сверяла это с РЕАЛЬНЫМИ активными арендами: branch/
    # worktree оставались опциональными даже при parallel_ai_development.
    # enabled=true. Тот же parallel_enabled-паттерн, что уже используется в
    # check_agent_results()/check_agent_task_contracts()/
    # check_agent_workflow_integrity().
    parallel_enabled = False
    profile_path = root / "docs" / "registry" / "project_profile.json"
    if profile_path.exists():
        pdata, perr = load_json(profile_path)
        if not perr and isinstance(pdata, dict):
            pad = pdata.get("parallel_ai_development")
            if isinstance(pad, dict) and pad.get("enabled") is True:
                parallel_enabled = True
    # v2.9.118 (P0 внешнего аудита v2.9.117: «Проверить Git» — worktree
    # существует, branch существует, branch действительно checkout в
    # указанном worktree). Второй git-читающий блок в этом файле после
    # --check-active-task-diff (см. обновлённые docstring/доки) — строго
    # opt-in: ни один subprocess не запускается, если ни одна запись не
    # объявила worktree/branch, и молча пропускается вне git-репозитория
    # (opt-in принцип этого поля целиком, не hard-фейл на неполном окружении).
    wants_git_check = any(isinstance(e, dict) and (e.get("worktree") or e.get("branch"))
                          for e in active)
    worktree_map: dict[str, str | None] = {}
    git_available = False
    if wants_git_check and (root / ".git").exists():
        worktree_map, wt_err = _git_worktree_branch_map(root)
        if wt_err:
            out.append(f"{WARN_PREFIX}active_work_packages.json: не удалось получить реальное "
                       f"состояние git worktree ({wt_err}) — branch/worktree не сверены с git")
        else:
            git_available = True
    branch_exists_cache: dict[str, bool] = {}
    seen: set[str] = set()
    seen_branches: dict[str, str] = {}
    seen_worktrees: dict[str, str] = {}
    entries: list[tuple[str, str, list[str]]] = []
    for i, entry in enumerate(active):
        if not isinstance(entry, dict):
            continue
        tid = entry.get("task_id")
        branch = entry.get("branch")
        worktree = entry.get("worktree")
        tag = f"active_work_packages.json[{i}]" + (f" ({tid})" if isinstance(tid, str) and tid else "")
        if _is_placeholder_value(tid):
            out.append(f"{tag}: task_id пуст или похож на плейсхолдер")
        if parallel_enabled:
            if not isinstance(branch, str) or not branch:
                out.append(f"{tag}: parallel_ai_development.enabled=true требует branch у "
                           f"каждой активной аренды — GIT_WORKSPACE_HYGIENE_STANDARD.md уже "
                           f"заявляет 'parallel work = branch + worktree + PR', git_agent_policy."
                           f"json уже объявляет parallel_agent_work_requires_worktree=true; эта "
                           f"аренда их не соблюдает (v2.9.119, P1 внешнего аудита v2.9.118)")
            if not isinstance(worktree, str) or not worktree:
                out.append(f"{tag}: parallel_ai_development.enabled=true требует worktree у "
                           f"каждой активной аренды (см. branch выше — тот же принцип, "
                           f"v2.9.119, P1 внешнего аудита v2.9.118)")
        if branch is not None and _is_placeholder_value(branch):
            out.append(f"{tag}: branch пуст или похож на плейсхолдер")
        if worktree is not None and _is_placeholder_value(worktree):
            out.append(f"{tag}: worktree пуст или похож на плейсхолдер")
        elif isinstance(worktree, str) and worktree and _path_escapes_root(root, worktree):
            out.append(f"{tag}: worktree выходит за пределы --root: {worktree}")
        if entry.get("status") == "STALE":
            # v2.9.118: STALE не снимается автоматически — громкий warning
            # при каждом прогоне, пока человек/оркестратор не разберётся
            # (уберёт запись или обновит heartbeat_at), не тихая недоделка.
            out.append(f"{WARN_PREFIX}{tag}: status=STALE — аренда не обновляла heartbeat "
                       f"дольше stale_after_seconds; требует решения человека/оркестратора "
                       f"(снять аренду или подтвердить, что задача жива), не снимается "
                       f"автоматически")
        if isinstance(tid, str) and tid:
            if tid in seen:
                out.append(f"{tag}: дублирующийся task_id")
            seen.add(tid)
            if task_ids is not None and tid not in task_ids:
                out.append(f"{tag}: task_id {tid!r} не найден в docs/registry/agent_tasks/*.json")
            if graph_ids is not None and tid not in graph_ids:
                out.append(f"{tag}: task_id {tid!r} не найден в work_package_graph.json")
            # v2.9.118 (P0 внешнего аудита v2.9.117: «graph: DONE, lease:
            # IN_PROGRESS» или «graph: WIP, lease отсутствует» — реальный
            # словарь статусов графа TODO/WIP/BLOCKED/DONE/FAILED (work_
            # package_graph.schema.json), не более богатая модель из
            # аудита). status этой lease уже провалидирован схемой
            # (IN_PROGRESS/PAUSED/STALE).
            if graph_status is not None and tid in graph_status:
                g_status = graph_status[tid]
                l_status = entry.get("status")
                if g_status in ("TODO", "DONE", "FAILED"):
                    out.append(f"{tag}: work_package_graph.json узел {tid!r} имеет "
                               f"status={g_status!r}, но существует активная аренда "
                               f"(status={l_status!r}) — {g_status} несовместим с активной "
                               f"работой над задачей")
                elif g_status == "WIP" and l_status not in ("IN_PROGRESS", "PAUSED", "STALE"):
                    out.append(f"{tag}: work_package_graph.json узел {tid!r} имеет status=WIP, "
                               f"но аренда не в IN_PROGRESS/PAUSED/STALE (status={l_status!r})")
                elif g_status == "BLOCKED" and l_status == "IN_PROGRESS":
                    out.append(f"{tag}: work_package_graph.json узел {tid!r} имеет "
                               f"status=BLOCKED — активная аренда допустима только в PAUSED, "
                               f"не IN_PROGRESS (status={l_status!r})")
        if isinstance(branch, str) and branch:
            if branch in seen_branches and seen_branches[branch] != tid:
                out.append(f"{tag}: branch {branch!r} уже используется активной арендой "
                           f"{seen_branches[branch]!r} — одна ветка не может быть закреплена "
                           f"за двумя одновременно активными задачами (v2.9.118)")
            else:
                seen_branches[branch] = tid if isinstance(tid, str) else tag
        if isinstance(worktree, str) and worktree:
            if worktree in seen_worktrees and seen_worktrees[worktree] != tid:
                out.append(f"{tag}: worktree {worktree!r} уже используется активной арендой "
                           f"{seen_worktrees[worktree]!r} — один worktree не может "
                           f"обслуживать две одновременно активные задачи (v2.9.118)")
            else:
                seen_worktrees[worktree] = tid if isinstance(tid, str) else tag
        # v2.9.118: сверка с РЕАЛЬНЫМ состоянием git — только если у записи
        # объявлен worktree/branch И живое состояние удалось получить
        # (git_available); при недоступности git не гадаем, не превращаем
        # неполное окружение (напр. --root не git-репозиторий) в hard fail.
        worktree_branch: str | None = None
        worktree_found = False
        if git_available and isinstance(worktree, str) and worktree:
            resolved = str((root / worktree).resolve()) if not _path_escapes_root(root, worktree) else None
            if resolved is not None and resolved in worktree_map:
                worktree_found = True
                worktree_branch = worktree_map[resolved]
            else:
                out.append(f"{tag}: worktree {worktree!r} не найден среди реальных "
                           f"`git worktree list` — задача заявляет worktree, которого нет "
                           f"(v2.9.118)")
        if git_available and isinstance(branch, str) and branch:
            if worktree_found:
                if worktree_branch is None:
                    out.append(f"{tag}: worktree {worktree!r} в состоянии detached HEAD — "
                               f"заявлен branch {branch!r}, но в этом worktree ветка не "
                               f"checkout (v2.9.118)")
                elif worktree_branch != branch:
                    out.append(f"{tag}: worktree {worktree!r} реально на ветке "
                               f"{worktree_branch!r}, не заявленной {branch!r} (v2.9.118)")
            else:
                if branch not in branch_exists_cache:
                    exists, br_err = _git_branch_exists(root, branch)
                    if br_err:
                        out.append(f"{WARN_PREFIX}{tag}: не удалось проверить существование "
                                   f"ветки {branch!r} ({br_err})")
                        branch_exists_cache[branch] = True  # не гадаем при ошибке git
                    else:
                        branch_exists_cache[branch] = bool(exists)
                if not branch_exists_cache[branch]:
                    out.append(f"{tag}: branch {branch!r} не найден среди реальных локальных "
                               f"веток (`git branch --list`) — v2.9.118")
        paths = [p for p in (entry.get("allowed_paths") or []) if isinstance(p, str) and p]
        for p in paths:
            if _path_escapes_root(root, p):
                out.append(f"{tag}: allowed_paths выходит за пределы --root: {p}")
            elif not _is_simple_scope_pattern(p):
                out.append(f"{tag}: allowed_paths использует неподдерживаемый glob-синтаксис "
                           f"{p!r} — поддерживаются только точный путь или dir/**")
        if isinstance(tid, str) and tid and paths and task_allowed_paths is not None \
                and tid in task_allowed_paths:
            task_paths = task_allowed_paths[tid]
            for p in paths:
                if not any(_pattern_within(p, tp) or p == tp for tp in task_paths):
                    out.append(f"{tag}: allowed_paths {p!r} шире, чем allowed_paths задачи "
                               f"{tid!r} в agent_tasks — аренда должна быть ⊆ scope задачи")
        if isinstance(tid, str) and tid and paths:
            entries.append((tag, tid, paths))
    for j, (tag_a, tid_a, paths_a) in enumerate(entries):
        for tag_b, tid_b, paths_b in entries[j + 1:]:
            if tid_a == tid_b:
                continue
            for pa in paths_a:
                for pb in paths_b:
                    if _globs_overlap(pa, pb):
                        out.append(f"{tag_a} и {tag_b}: пересекающиеся allowed_paths "
                                   f"({pa} / {pb}) — active task A allowed_paths ∩ "
                                   f"active task B allowed_paths должно быть ∅")
    return out


def check_lease_expiry(root: Path, now_str: str | None) -> list[str]:
    """--check-lease-expiry [--now <ISO-8601>] (v2.9.119, §15 внешнего аудита
    v2.9.118): ЕДИНСТВЕННАЯ проверка в этом файле, что реально сравнивает
    heartbeat_at/lease_expires_at с текущим (или явно инжектированным
    --now) временем — намеренно НЕ часть --check-work-package-overlap
    (тот статический release-gate детерминирован на любом коммите вне
    зависимости от момента запуска; эта проверка ПО ОПРЕДЕЛЕНИЮ зависит от
    wall-clock) и намеренно НЕ входит в «полный набор осей» strict-команды
    — opt-in отдельный шаг (как --check-active-task-diff), для проектов,
    что реально ведут heartbeat/lease_expires_at автоматизацией (см.
    active_work_packages.schema.json.heartbeat_at/lease_expires_at:
    раньше единственной альтернативой было НИКАК не проверять их
    исполнение, теперь есть opt-in runtime-проверка).

    --now не задан — используется datetime.now(timezone.utc): недетерминировано
    (подходит periodic CI job, не release-gate одного коммита). --now
    задан — сравнение полностью детерминировано, инжектируемо в тестах."""
    out: list[str] = []
    data = _load_registry_json(root, "active_work_packages.json", "active_work_packages.schema.json",
                               None, out)
    if not isinstance(data, dict):
        return out
    active = data.get("active")
    if not isinstance(active, list) or not active:
        return out
    if now_str:
        try:
            now = datetime.fromisoformat(now_str.replace("Z", "+00:00"))
        except ValueError:
            return [f"--check-lease-expiry: --now {now_str!r} — не ISO-8601 datetime"]
        if now.tzinfo is None:
            return [f"--check-lease-expiry: --now {now_str!r} обязан содержать timezone "
                   f"(Z или ±HH:MM)"]
    else:
        now = datetime.now(timezone.utc)
    for i, entry in enumerate(active):
        if not isinstance(entry, dict):
            continue
        tid = entry.get("task_id")
        tag = f"active_work_packages.json[{i}]" + (f" ({tid})" if isinstance(tid, str) and tid else "")
        heartbeat_at = entry.get("heartbeat_at")
        stale_after = entry.get("stale_after_seconds")
        if (isinstance(heartbeat_at, str) and isinstance(stale_after, (int, float))
                and not isinstance(stale_after, bool) and stale_after > 0):
            try:
                hb = datetime.fromisoformat(heartbeat_at.replace("Z", "+00:00"))
            except ValueError:
                hb = None
            if hb is not None:
                elapsed = (now - hb).total_seconds()
                if elapsed > stale_after and entry.get("status") != "STALE":
                    out.append(f"{tag}: heartbeat_at устарел на {elapsed - stale_after:.0f}s сверх "
                               f"stale_after_seconds={stale_after} относительно "
                               f"{'--now' if now_str else 'текущего времени'}, но "
                               f"status={entry.get('status')!r}, не STALE — аренда должна быть "
                               f"помечена STALE (v2.9.119, §15 внешнего аудита v2.9.118)")
        lease_expires_at = entry.get("lease_expires_at")
        if isinstance(lease_expires_at, str):
            try:
                exp = datetime.fromisoformat(lease_expires_at.replace("Z", "+00:00"))
            except ValueError:
                exp = None
            if exp is not None and now > exp:
                out.append(f"{tag}: lease_expires_at ({lease_expires_at}) в прошлом относительно "
                           f"{'--now' if now_str else 'текущего времени'} — аренда просрочена "
                           f"(v2.9.119, §15 внешнего аудита v2.9.118)")
    return out


def _git_ref_resolves(root: Path, ref: str, timeout_seconds: int = 10) -> bool:
    """v2.9.123 (P1 внешнего аудита v2.9.122, A-2): `git rev-parse --verify
    --quiet <ref>` — тот же самый тест, что уже был в bash-шаблонах CI
    (`git rev-parse --verify --quiet "origin/$DEFAULT_BRANCH"`), теперь
    доступен и инструменту напрямую. Отличается от `_resolve_merge_base()`:
    та функция МОЛЧА деградирует к literal base_ref/"HEAD", если `git
    merge-base` не находит точку (unrelated histories, ref не существует
    вовсе) — это подходит, когда сравнение просто необязательно ловит
    меньше, но НЕ подходит, когда вызывающему нужно ЗНАТЬ, был ли ref
    вообще резолвируемым, прежде чем доверять чему-либо, вычисленному
    относительно него."""
    try:
        proc = subprocess.run(["git", "rev-parse", "--verify", "--quiet", ref],
                              cwd=root, capture_output=True, timeout=timeout_seconds)
    except (subprocess.TimeoutExpired, OSError):
        return False
    return proc.returncode == 0


def _resolve_merge_base(root: Path, base_ref: str | None,
                        timeout_seconds: int = 30) -> tuple[str, str | None]:
    """v2.9.122 (вынесено из _git_changed_files — переиспользуется местами,
    которым не нужен сам diff, только точка сравнения, напр.
    check_parallel_ai_development()): база_ref сверяется через `git
    merge-base base_ref HEAD`, не напрямую. Если base_ref не задан —
    "HEAD". Если merge-base не находится (напр. unrelated histories) —
    base_ref возвращается как есть. Возвращает (resolved_ref, err) — err
    не None означает "git не смог выполниться", resolved_ref в этом
    случае — base_ref/"HEAD" как лучший доступный fallback."""
    diff_target = "HEAD"
    if base_ref:
        diff_target = base_ref
        try:
            mb_proc = subprocess.run(["git", "merge-base", base_ref, "HEAD"],
                                     cwd=root, capture_output=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            return diff_target, f"git merge-base не завершился за {timeout_seconds}с"
        except OSError as exc:
            return diff_target, f"не удалось запустить git: {exc}"
        if mb_proc.returncode == 0:
            merge_base = mb_proc.stdout.decode("utf-8", errors="replace").strip()
            if merge_base:
                diff_target = merge_base
    return diff_target, None


def _git_changed_files(root: Path, base_ref: str | None,
                        timeout_seconds: int = 30) -> tuple[list[str] | None, str | None, str]:
    """v2.9.115: РЕАЛЬНО изменённые файлы — committed since base_ref (или
    просто working tree vs HEAD, если base_ref не задан) + staged + unstaged
    + untracked. "git diff <ref>" (без --cached) сравнивает ref с РАБОЧИМ
    ДЕРЕВОМ, что уже покрывает committed-since-ref/staged/unstaged одним
    вызовом; untracked файлы git diff никогда не показывает ни при каких
    флагах — добавляются отдельным git ls-files. NUL-separated (-z), тот же
    принцип устойчивости к пробелам/юникоду в путях, что уже применён в
    run_user_function_tests.py (v2.9.97). Возвращает (files, err, resolved_ref)
    — err не None означает "не удалось определить", не "изменений нет".

    v2.9.119 (P0 внешнего аудита v2.9.118 §4): base_ref сверяется через
    merge-base с HEAD, не напрямую (см. _resolve_merge_base) — раньше
    `git diff base_ref` сравнивал base_ref С ТЕКУЩИМ рабочим деревом
    буквально — если base_ref (напр. `origin/main`) продвинулся ПОСЛЕ того,
    как feature-ветка от него отделилась, diff показывал бы ВСЕ изменения
    main с момента divergence, включая чужие, не имеющие отношения к
    текущей задаче. merge-base находит точку реального расхождения — diff
    показывает только то, что реально сделано НА этой ветке.

    v2.9.121 (P0 внешнего аудита v2.9.120): третий элемент кортежа —
    resolved_ref (реально использованная точка сравнения — merge-base, или
    base_ref как есть, или "HEAD") — теперь возвращается наружу, чтобы
    check_active_task_diff() мог прочитать control-plane JSON-файлы (allowed_
    paths) НА ТОЙ ЖЕ точке, а не только сравнить пути диффа с ней."""
    if not (root / ".git").exists():
        proc = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"],
                              cwd=root, capture_output=True, timeout=timeout_seconds)
        if proc.returncode != 0:
            return None, "не git-репозиторий (--root не внутри рабочего дерева git)", "HEAD"
    diff_target, mb_err = _resolve_merge_base(root, base_ref, timeout_seconds)
    if mb_err:
        return None, mb_err, diff_target
    try:
        proc = subprocess.run(["git", "diff", "--name-only", "-z", diff_target],
                              cwd=root, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return None, f"git diff не завершился за {timeout_seconds}с", diff_target
    except OSError as exc:
        return None, f"не удалось запустить git: {exc}", diff_target
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        return None, f"git diff {diff_target} завершился с ошибкой: {stderr}", diff_target
    files = {f for f in proc.stdout.decode("utf-8", errors="replace").split("\0") if f}
    try:
        proc2 = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "-z"],
                               cwd=root, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return None, f"git ls-files не завершился за {timeout_seconds}с", diff_target
    except OSError as exc:
        return None, f"не удалось запустить git: {exc}", diff_target
    if proc2.returncode != 0:
        stderr = proc2.stderr.decode("utf-8", errors="replace").strip()
        return None, f"git ls-files завершился с ошибкой: {stderr}", diff_target
    files.update(f for f in proc2.stdout.decode("utf-8", errors="replace").split("\0") if f)
    return sorted(files), None, diff_target


def _ecosystem_changed_contracts(
    root: Path,
    declared: list[str],
    base_ref: str | None,
) -> tuple[set[str], str | None, str | None]:
    """Дополняет явный список HTTP-договоров реальным Git diff от base_ref."""
    changed_contracts = set(declared)
    if not base_ref:
        return changed_contracts, None, None
    changed_files, error, resolved_ref = _git_changed_files(root, base_ref)
    if error:
        return changed_contracts, error, resolved_ref
    changed_contracts.update(changed_files or [])
    return changed_contracts, None, resolved_ref


def _read_json_at_git_ref(root: Path, ref: str, rel_path: str,
                          timeout_seconds: int = 30) -> tuple[object, str | None]:
    """git show <ref>:<rel_path> — читает JSON КАК ОН БЫЛ на ref, не из
    рабочего дерева (v2.9.121, P0 внешнего аудита v2.9.120: «implementation
    agent может сам расширить собственный machine scope» — живое рабочее
    дерево это та же ветка, что проверяется, ей нельзя доверять как
    источнику истины про СОБСТВЕННЫЙ scope). Возвращает (None, None), если
    путь не существовал на ref (новый файл — не путать с ошибкой git; ref
    к этому моменту уже проверен успешным вызовом `git diff` выше по стеку
    в _git_changed_files, так что неудача здесь практически всегда означает
    «файла там не было», не «ref нечитаем»). (None, err) — git не смог
    выполниться или содержимое не парсится как JSON."""
    try:
        prefix_proc = subprocess.run(["git", "rev-parse", "--show-prefix"], cwd=root,
                                     capture_output=True, text=True, timeout=timeout_seconds)
        prefix = prefix_proc.stdout.strip() if prefix_proc.returncode == 0 else ""
        repo_rel_path = f"{prefix}{rel_path}"
        proc = subprocess.run(["git", "show", f"{ref}:{repo_rel_path}"],
                              cwd=root, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return None, f"git show {ref}:{rel_path} не завершился за {timeout_seconds}с"
    except OSError as exc:
        return None, f"не удалось запустить git: {exc}"
    if proc.returncode != 0:
        return None, None
    try:
        return json.loads(proc.stdout.decode("utf-8", errors="replace")), None
    except json.JSONDecodeError as exc:
        return None, f"битый JSON на {ref}:{rel_path}: {exc}"


def _parallel_mode_enabled_trusted(root: Path, resolved_ref: str | None) -> bool:
    """v2.9.122 (P0 внешнего аудита v2.9.121 §4 — «ветка может отключить
    сам scope-gate»): репродуцировано напрямую — implementation-ветка в
    ОДНОМ коммите удаляет свою же активную аренду И меняет
    project_profile.json.parallel_ai_development.enabled на false (или
    удаляет файл целиком); CI читал ТОЛЬКО live-состояние для решения
    «нужно ли вообще проверять scope» — TASK_ID не резолвился (аренда
    удалена), enabled читался как false, active-task-diff молча
    пропускался, exit 0. check_active_task_diff() к этому моменту вообще
    не вызывался — base-lock allowed_paths (v2.9.121) тут бессилен, т.к.
    защищает только СОДЕРЖИМОЕ проверки, не решение «запускать ли её».

    OR-семантика: включено, если true либо на live, либо на resolved_ref.
    Ветка может ТОЛЬКО усилить governance изнутри себя (первое включение
    parallel-режима — легитимный bootstrap), но никогда не ослабить то,
    что уже было включено на базовой точке — нет обратного сценария, когда
    implementation-ветке законно нужно ВЫКЛЮЧИТЬ project-wide governance
    флаг, поставленный до её создания."""
    live_enabled = False
    live_path = root / "docs" / "registry" / "project_profile.json"
    if live_path.exists():
        live_data, live_err = load_json(live_path)
        if not live_err and isinstance(live_data, dict):
            pad = live_data.get("parallel_ai_development")
            if isinstance(pad, dict) and pad.get("enabled") is True:
                live_enabled = True
    if live_enabled or not resolved_ref:
        return live_enabled
    base_data, base_err = _read_json_at_git_ref(
        root, resolved_ref, "docs/registry/project_profile.json")
    if not base_err and isinstance(base_data, dict):
        pad = base_data.get("parallel_ai_development")
        if isinstance(pad, dict) and pad.get("enabled") is True:
            return True
    return False


def _git_worktree_branch_map(root: Path, timeout_seconds: int = 30) -> tuple[dict[str, str | None], str | None]:
    """v2.9.118 (P0 внешнего аудита v2.9.117): реальные git worktree и их
    checked-out ветки — `git worktree list --porcelain` даёт оба факта
    одним вызовом (блок на worktree, HEAD sha, `branch refs/heads/<name>`
    либо `detached`). Пути в выводе — абсолютные; ключи словаря —
    абсолютные Path.resolve(), сравнение с active_work_packages.json.
    worktree ведётся через сравнение резолвленных путей, не строк.
    Возвращает ({}, err) при ошибке — err не None означает "не удалось
    определить", не "worktree нет"."""
    try:
        proc = subprocess.run(["git", "worktree", "list", "--porcelain"],
                              cwd=root, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return {}, f"git worktree list не завершился за {timeout_seconds}с"
    except OSError as exc:
        return {}, f"не удалось запустить git: {exc}"
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        return {}, f"git worktree list завершился с ошибкой: {stderr}"
    result: dict[str, str | None] = {}
    current_path: str | None = None
    for line in proc.stdout.decode("utf-8", errors="replace").splitlines():
        if line.startswith("worktree "):
            current_path = line[len("worktree "):].strip()
            result[current_path] = None
        elif line.startswith("branch ") and current_path is not None:
            ref = line[len("branch "):].strip()
            result[current_path] = ref[len("refs/heads/"):] if ref.startswith("refs/heads/") else ref
    return result, None


def _git_branch_exists(root: Path, branch: str, timeout_seconds: int = 30) -> tuple[bool | None, str | None]:
    """v2.9.118: существует ли локальная ветка — `git branch --list <name>`
    (пустой вывод — не существует). Возвращает (None, err) при ошибке
    самого git, не путать с (False, None) — «git отработал, ветки нет»."""
    try:
        proc = subprocess.run(["git", "branch", "--list", branch],
                              cwd=root, capture_output=True, timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        return None, f"git branch --list не завершился за {timeout_seconds}с"
    except OSError as exc:
        return None, f"не удалось запустить git: {exc}"
    if proc.returncode != 0:
        stderr = proc.stderr.decode("utf-8", errors="replace").strip()
        return None, f"git branch --list завершился с ошибкой: {stderr}"
    return bool(proc.stdout.decode("utf-8", errors="replace").strip()), None


def check_active_task_diff(root: Path, task_id: str, base_ref: str | None,
                           current_branch: str | None = None) -> list[str]:
    """--check-active-task-diff --task-id <id> [--base-ref <ref>]
    [--current-branch <name>] (v2.9.115, реализует «главный остающийся
    разрыв» ревью v2.9.114): читает ЖИВОЕ состояние git (git diff), а не
    только статичные registry-файлы — остальные проверки в основном
    статика, за одним исключением: v2.9.118 добавил вторую git-читающую
    проверку, `check_work_package_overlap()` (git worktree list/git branch
    --list для сверки branch/worktree активной аренды с реальностью, см. её
    docstring) — этот файл больше не "только одна git-проверка", а "две,
    обе явно документированы".

    Даже идеальный active_work_packages.json — только декларация намерения
    («агенту разрешено менять эти пути»). --check-work-package-overlap
    ловит конфликт МЕЖДУ двумя декларациями в самом реестре, но не ловит,
    если задача РЕАЛЬНО поменяла файл вне заявленного allowed_paths — эту
    сверку и делает эта проверка: находит активную запись task_id в
    active_work_packages.json, берёт её allowed_paths, сравнивает с
    реальными изменёнными файлами (git diff since base_ref/HEAD + staged +
    unstaged + untracked).

    v2.9.121 (P0 внешнего аудита v2.9.120: «implementation agent может сам
    расширить собственный machine scope» — репродуцировано напрямую: агент
    в своей ветке одновременно расширяет active_work_packages.json.
    allowed_paths И agent_tasks/<id>.json.allowed_paths до "src/**,
    docs/registry/**", затем добавляет файл вне исходного scope — обе
    проверки (эта и check_agent_workflow_integrity) возвращали 0 находок,
    т.к. allowed_paths читался из ТОЙ ЖЕ ветки, что проверяется). Теперь
    live-версия ОБОИХ файлов (лизинг + task contract) сверяется с версией
    НА base_ref (той же точке, что уже используется для самого git diff —
    merge-base, см. _git_changed_files) через `git show <ref>:<path>`.
    Расхождение — жёсткая находка, а для самой проверки allowed_paths
    используется BASE-значение, не live: ветка не может подтвердить
    расширение собственных прав самой себе. Если задача не существовала на
    base_ref вообще (создана впервые в этой же ветке) — сравнивать не с
    чем, используется live-значение как раньше (осознанно принятая
    остаточная граница, тот же принцип честного разграничения, что и в
    §5 AGENT_RESULT_CONTRACT.md: для СОВСЕМ новой задачи другого источника
    истины не существует).

    v2.9.121 (P1 того же аудита — «TASK_ID не привязан к текущей ветке»):
    --current-branch опционален для обратной совместимости, но если
    передан — активная аренда task_id обязана быть привязана именно к этой
    ветке (entry.branch), иначе ветка могла бы «занять» scope чужой
    активной задачи через workflow_dispatch input/repository variable
    (единственные два источника TASK_ID, которые НЕ проверяют branch-match
    сами по себе — см. templates/ci_validate.yml).

    v2.9.122 (P0 внешнего аудита v2.9.121 §5 — «bootstrap новой задачи
    остаётся self-authorized»): это ОСОЗНАННО принятое решение v2.9.121
    (задача без версии на base_ref — верить live, другого источника истины
    нет) пересмотрено владельцем на hard fail именно в parallel-режиме —
    репродуцировано: новая ветка создаёт СВОИ task+lease с произвольным
    allowed_paths и тут же использует его, 0 находок. Теперь: если задачи
    НЕ было в active_work_packages.json на base_ref, а parallel_ai_
    development.enabled=true (см. _parallel_mode_enabled_trusted) — жёсткая
    ошибка вместо доверия live. Вне parallel-режима поведение не изменилось
    (bootstrap по-прежнему доверяется — тот же принцип честного
    разграничения, что и в §5 AGENT_RESULT_CONTRACT.md).

    v2.9.122 (P1 того же аудита §6 — «base-lock защищает только allowed_
    paths, не identity lease»): репродуцировано — ветка meняет ТОЛЬКО
    entry.branch (allowed_paths не трогая) и проходит --current-branch,
    т.к. сверка шла с LIVE branch, не с base. check_work_package_overlap
    это не ловит (её real-git сверка проверяет согласованность с РЕАЛЬНЫМ
    git, не с base_ref — ветка, реально находящаяся на agent/b, «честно»
    заявляет agent/b). branch теперь входит в тот же base-lock, что и
    allowed_paths: --current-branch сверяется с BASE-версией branch, когда
    задача существовала на base_ref."""
    out: list[str] = []
    # v2.9.121 (P1 внешнего аудита v2.9.120): task_id участвует в построении
    # путей ниже (agent_tasks/<task_id>.json, agent_results/<task_id>.json,
    # git show <ref>:docs/registry/agent_tasks/<task_id>.json) — небезопасный
    # task_id (../, /) отклоняется здесь ОДИН раз, до любого построения пути.
    if not _SAFE_REGISTRY_ID_RE.match(task_id):
        out.append(f"active-task-diff: task_id {task_id!r} использует небезопасные символы — "
                   f"разрешены только буквы/цифры/./_/-")
        return out
    data = _load_registry_json(root, "active_work_packages.json", "active_work_packages.schema.json",
                               None, out)
    if not isinstance(data, dict):
        return out
    active = data.get("active")
    if not isinstance(active, list):
        return out
    entry = next((e for e in active if isinstance(e, dict) and e.get("task_id") == task_id), None)
    if entry is None:
        out.append(f"active-task-diff: task_id {task_id!r} не найден в active_work_packages.json")
        return out
    live_allowed = [p for p in (entry.get("allowed_paths") or []) if isinstance(p, str) and p]
    live_branch = entry.get("branch") if isinstance(entry.get("branch"), str) else None
    changed, err, resolved_ref = _git_changed_files(root, base_ref)
    if err:
        out.append(f"active-task-diff: {err}")
        return out
    allowed = live_allowed
    effective_branch = live_branch
    base_awp, base_awp_err = _read_json_at_git_ref(
        root, resolved_ref, "docs/registry/active_work_packages.json")
    if base_awp_err:
        out.append(f"active-task-diff: {task_id}: не удалось прочитать "
                   f"active_work_packages.json на {resolved_ref}: {base_awp_err}")
        return out
    base_entry = None
    if isinstance(base_awp, dict):
        base_entry = next((e for e in (base_awp.get("active") or [])
                           if isinstance(e, dict) and e.get("task_id") == task_id), None)
    if base_entry is None:
        if _parallel_mode_enabled_trusted(root, resolved_ref):
            out.append(f"active-task-diff: {task_id}: активная аренда не существовала на "
                       f"{resolved_ref} — задача создана ВНУТРИ проверяемой ветки, а "
                       f"parallel_ai_development.enabled=true. В parallel-режиме task/lease "
                       f"обязаны существовать до начала работы агента (governance-коммитом "
                       f"на базовой ветке) — ветка не может сама себя авторизовать (v2.9.122, "
                       f"P0 внешнего аудита v2.9.121 §5)")
            return out
    else:
        base_allowed = sorted(p for p in (base_entry.get("allowed_paths") or [])
                              if isinstance(p, str) and p)
        if sorted(live_allowed) != base_allowed:
            out.append(f"active-task-diff: {task_id}: active_work_packages.json."
                       f"allowed_paths изменился ВНУТРИ проверяемой ветки (был "
                       f"{base_allowed!r} на {resolved_ref}, стал {sorted(live_allowed)!r}) "
                       f"— ветка не может расширять scope, который она же и должна "
                       f"соблюдать; используется базовое значение")
        allowed = [p for p in (base_entry.get("allowed_paths") or [])
                  if isinstance(p, str) and p]
        base_branch = base_entry.get("branch") if isinstance(base_entry.get("branch"), str) else None
        if base_branch != live_branch:
            out.append(f"active-task-diff: {task_id}: active_work_packages.json.branch "
                       f"изменился ВНУТРИ проверяемой ветки (был {base_branch!r} на "
                       f"{resolved_ref}, стал {live_branch!r}) — ветка не может "
                       f"перепривязать чужую аренду на себя; используется базовое значение "
                       f"(v2.9.122, P1 внешнего аудита v2.9.121 §6)")
        effective_branch = base_branch
    if current_branch is not None:
        if isinstance(effective_branch, str) and effective_branch and effective_branch != current_branch:
            out.append(f"active-task-diff: {task_id}: активная аренда привязана к ветке "
                       f"{effective_branch!r}, а проверяется ветка {current_branch!r} — эта "
                       f"ветка не может использовать scope чужой задачи")
            return out
    base_task, base_task_err = _read_json_at_git_ref(
        root, resolved_ref, f"docs/registry/agent_tasks/{task_id}.json")
    if base_task_err:
        out.append(f"active-task-diff: {task_id}: не удалось прочитать "
                   f"agent_tasks/{task_id}.json на {resolved_ref}: {base_task_err}")
        return out
    if isinstance(base_task, dict):
        task_path = root / "docs" / "registry" / "agent_tasks" / f"{task_id}.json"
        live_task = None
        if task_path.exists():
            live_task, _ = load_json(task_path)
        base_task_allowed = sorted(p for p in (base_task.get("allowed_paths") or [])
                                   if isinstance(p, str) and p)
        if isinstance(live_task, dict):
            live_task_allowed = sorted(p for p in (live_task.get("allowed_paths") or [])
                                       if isinstance(p, str) and p)
            if live_task_allowed != base_task_allowed:
                out.append(f"active-task-diff: {task_id}: agent_tasks/{task_id}.json."
                           f"allowed_paths изменился ВНУТРИ проверяемой ветки (был "
                           f"{base_task_allowed!r} на {resolved_ref}, стал "
                           f"{live_task_allowed!r}) — тот же принцип, что и для "
                           f"active_work_packages.json")
    invalid = [p for p in allowed if not _is_simple_scope_pattern(p)]
    if invalid:
        out.append(f"active-task-diff: {task_id}: allowed_paths использует неподдерживаемый "
                   f"glob-синтаксис {invalid!r} — --check-work-package-overlap должен был это "
                   f"поймать раньше")
        return out
    if not allowed:
        out.append(f"active-task-diff: {task_id}: allowed_paths пуст — ничего не разрешено, "
                   f"любое изменение будет вне scope")
    # v2.9.121 (P1 внешнего аудита v2.9.120): собственный result-файл задачи
    # — системный путь, не бизнес-scope; без исключения задача НИКОГДА не
    # может пройти эту проверку начисто, т.к. стандарт ОБЯЗЫВАЕТ создать
    # именно этот файл (см. AGENT_RESULT_CONTRACT.md), а типовой allowed_
    # paths (напр. src/a/**) его не покрывает.
    own_result_path = f"docs/registry/agent_results/{task_id}.json"
    # v2.9.123 (P2 внешнего аудита v2.9.122, A-7, репродуцировано):
    # worktree, объявленный в аренде (templates/active_work_packages.json
    # документирует `.worktrees/<name>` как единственную поддерживаемую
    # раскладку), — тоже системный путь: при прогоне из основной папки git
    # видит содержимое ЧУЖОГО (не текущего) рабочего дерева worktree как
    # untracked, и без исключения оно ложно флагуется вне allowed_paths.
    # Тот же принцип, что и у own_result_path — исключение системного пути
    # из diff-сверки, не расширение allowed_paths.
    worktree = entry.get("worktree")
    worktree_prefix = f"{worktree.rstrip('/')}/" if isinstance(worktree, str) and worktree.strip() else None

    def _is_lease_system_path(f: str) -> bool:
        if f == own_result_path:
            return True
        if worktree_prefix and f.startswith(worktree_prefix):
            return True
        return False

    for f in changed or []:
        if _is_lease_system_path(f):
            continue
        if not _path_within_scope(f, allowed):
            out.append(f"active-task-diff: {task_id}: {f} изменён, но не входит в "
                       f"allowed_paths {allowed!r}")
    # v2.9.118 (P0 внешнего аудита v2.9.117 §8): agent_result.changed_files
    # == реальный git diff, с честными исключениями (generated_files/
    # ignored_diff_entries), не свободным текстом.
    result_path = root / "docs" / "registry" / "agent_results" / f"{task_id}.json"
    if result_path.exists():
        result_data, result_err = load_json(result_path)
        if result_err:
            out.append(f"active-task-diff: {task_id}: agent_results/{task_id}.json: "
                       f"битый JSON: {result_err}")
        elif isinstance(result_data, dict):
            # v2.9.123 (P2 внешнего аудита v2.9.122, A-5, репродуцировано:
            # шаблонный agent_result.json не проходил бы собственный гейт):
            # own_result_path исключён из allowed_paths-проверки выше, но
            # symmetric-исключения из changed_files-сверки не было — агент
            # был ОБЯЗАН сам себя перечислить в changed_files, хотя ничто
            # это не документировало. Тот же принцип — системный путь не
            # входит ни в одну из двух сверок, не в одну из двух.
            actual = {f for f in (changed or []) if not _is_lease_system_path(f)}
            # v2.9.123: системный путь исключается СИММЕТРИЧНО — если агент
            # всё же перечислил own_result_path/файлы внутри своего worktree
            # в changed_files (разумное, но необязательное поведение), это
            # не должно давать "claimed файл, которого нет в реальном diff"
            # (phantom) только потому, что тот же путь больше не входит в
            # actual. Системный путь одинаково невидим для обеих сторон
            # сверки, не только для одной.
            claimed = {f for f in _as_list(result_data.get("changed_files"))
                      if isinstance(f, str) and not _is_lease_system_path(f)}
            # v2.9.119 (P2 внешнего аудита v2.9.118): generated_files[] стал
            # структурированным (path/generator) — та же валидация плейсхолдеров,
            # что уже применена к ignored_diff_entries чуть ниже (раньше любая
            # строка принималась как "сгенерированный файл" без обоснования).
            generated_entries = _as_list(result_data.get("generated_files"))
            generated: set[str] = set()
            for j, e in enumerate(generated_entries):
                if not isinstance(e, dict):
                    continue
                for field in ("path", "generator"):
                    if _is_placeholder_value(e.get(field)):
                        out.append(f"active-task-diff: {task_id}: agent_results/{task_id}.json."
                                   f"generated_files[{j}].{field} — плейсхолдер или пусто")
                if isinstance(e.get("path"), str) and not _is_placeholder_value(e.get("path")):
                    generated.add(e["path"])
            ignored_entries = _as_list(result_data.get("ignored_diff_entries"))
            ignored: set[str] = set()
            for j, e in enumerate(ignored_entries):
                if not isinstance(e, dict):
                    continue
                # v2.9.118 (§13.2 внешнего аудита v2.9.117): reason/approved_by
                # — обязательные строки-обоснования исключения файла из diff-
                # проверки; "   " проходил бы minLength:1 в схеме и снимал бы
                # ответственность с одобряющего без реального обоснования.
                for field in ("path", "reason", "approved_by"):
                    if _is_placeholder_value(e.get(field)):
                        out.append(f"active-task-diff: {task_id}: agent_results/{task_id}.json."
                                   f"ignored_diff_entries[{j}].{field} — плейсхолдер или пусто")
                if isinstance(e.get("path"), str) and not _is_placeholder_value(e.get("path")):
                    ignored.add(e["path"])
            unaccounted = sorted(actual - claimed - generated - ignored)
            phantom = sorted(claimed - actual)
            if unaccounted:
                out.append(f"active-task-diff: {task_id}: agent_results/{task_id}.json."
                           f"changed_files не отражает реально изменённые файлы "
                           f"{unaccounted!r} — не в changed_files, не в generated_files, "
                           f"не в ignored_diff_entries (v2.9.118)")
            if phantom:
                out.append(f"active-task-diff: {task_id}: agent_results/{task_id}.json."
                           f"changed_files заявляет файлы {phantom!r}, которых нет в "
                           f"реальном git diff (v2.9.118)")
    return out



def _control_plane_manifest_data(root: Path, schemas_root_arg: str | None,
                                 out: list[str]) -> dict | None:
    path = root / "docs" / "registry" / "control_plane_manifest.json"
    if not path.exists():
        return None
    data, err = load_json(path)
    if err:
        out.append(f"control_plane_manifest.json: битый JSON: {err}")
        return None
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    schema_path = schemas_root / "control_plane_manifest.schema.json" if schemas_root else None
    if schema_path and schema_path.exists():
        schema, serr = load_json(schema_path)
        if not serr and isinstance(schema, dict):
            out.extend(validate_schema(data, schema, "control_plane_manifest.json"))
    return data if isinstance(data, dict) else None


_MANDATORY_CONTROL_PLANE_CLASSES = {
    "project_profile", "control_plane_manifest", "module_registry", "code_ownership",
    "work_package_graph", "active_leases", "check_registry", "agent_task_contracts",
    "approved_tools_registry",
    "agent_results_policy", "critical_schemas", "validator_tools", "release_gate",
    "test_runner", "ci_workflows", "capability_registry", "release_receipt_policy",
}


def _control_plane_semantic_findings(data: dict, prefix: str = "control-plane") -> list[str]:
    out: list[str] = []
    classes = data.get("governance_classes")
    paths = data.get("governance_paths")
    if not isinstance(classes, dict):
        return [f"{prefix}: MANDATORY_GOVERNANCE_CLASSES_MISSING"]
    missing = sorted(_MANDATORY_CONTROL_PLANE_CLASSES - set(classes))
    if missing:
        out.append(f"{prefix}: MANDATORY_GOVERNANCE_CLASSES_MISSING {missing!r}")
    flattened: list[str] = []
    for class_id in sorted(_MANDATORY_CONTROL_PLANE_CLASSES):
        class_paths = classes.get(class_id)
        if not isinstance(class_paths, list) or not class_paths or not all(isinstance(item, str) and item.strip() for item in class_paths):
            out.append(f"{prefix}: GOVERNANCE_CLASS_EMPTY_OR_INVALID {class_id!r}")
            continue
        flattened.extend(class_paths)
    if isinstance(paths, list):
        missing_from_flat = sorted(set(flattened) - {item for item in paths if isinstance(item, str)})
        if missing_from_flat:
            out.append(f"{prefix}: GOVERNANCE_CLASS_PATH_NOT_PROTECTED {missing_from_flat!r}")
    else:
        out.append(f"{prefix}: GOVERNANCE_PATHS_INVALID")
    return out


def _semantic_control_plane_v2(root: Path, data: dict, schemas_root_arg: str | None,
                               *, prefix: str) -> list[str]:
    """Semantic protocol 2.0 validation.

    Protocol 1.1 remains readable only for backward-compatible human-supervised
    projects and historical fixtures. Executable parallel/autonomous profiles
    reject it in tools/agent_gate.py and shipped templates use protocol 2.0.
    """
    if str(data.get("protocol_version", "")) != "2.0":
        return []
    return semantic_control_plane_findings(
        root, data, resolve_schemas_root(root, schemas_root_arg), prefix=prefix
    )


def check_control_plane_integrity(root: Path, schemas_root_arg: str | None,
                                  base_ref: str | None = None) -> list[str]:
    """Trusted control plane v1 (v2.9.126).

    Governance policy and implementation code may not change in the same
    branch/PR. The manifest itself and governance path list are read from the
    merge-base whenever available, preventing the implementation branch from
    shrinking its own protected set.
    """
    out: list[str] = []
    live = _control_plane_manifest_data(root, schemas_root_arg, out)
    if isinstance(live, dict):
        out.extend(_control_plane_semantic_findings(live))
        out.extend(_semantic_control_plane_v2(root, live, schemas_root_arg, prefix="control-plane"))
    if live is None:
        resolved, _ = _resolve_merge_base(root, base_ref) if base_ref else (None, None)
        if _parallel_mode_enabled_trusted(root, resolved):
            out.append("CONTROL_PLANE_NOT_TRUSTED: parallel mode requires docs/registry/control_plane_manifest.json")
        return out
    if not base_ref:
        return out
    if not _git_ref_resolves(root, base_ref):
        out.append(f"CONTROL_PLANE_NOT_TRUSTED: --base-ref={base_ref!r} не резолвится")
        return out
    resolved, err = _resolve_merge_base(root, base_ref)
    if err or not resolved:
        out.append(f"CONTROL_PLANE_NOT_TRUSTED: merge-base не определён: {err}")
        return out
    base, berr = _read_json_at_git_ref(root, resolved, "docs/registry/control_plane_manifest.json")
    if berr or not isinstance(base, dict):
        out.append("CONTROL_PLANE_NOT_TRUSTED: manifest отсутствует/нечитаем на trusted base; сначала отдельный governance PR")
        return out
    base_findings = _control_plane_semantic_findings(base, "trusted-base-control-plane")
    base_findings.extend(_semantic_control_plane_v2(root, base, schemas_root_arg, prefix="trusted-base-control-plane"))
    if base_findings:
        out.extend(base_findings)
        out.append("CONTROL_PLANE_NOT_TRUSTED: trusted base manifest не содержит обязательный governance set")
        return out
    paths = [x for x in base.get("governance_paths", []) if isinstance(x, str) and x]
    changed, cerr, _ = _git_changed_files(root, resolved)
    if cerr:
        out.append(f"CONTROL_PLANE_NOT_TRUSTED: git diff недоступен: {cerr}")
        return out
    changed_set = set(changed or [])
    try:
        pp = subprocess.run(["git", "rev-parse", "--show-prefix"], cwd=root,
                            capture_output=True, text=True, timeout=10)
        prefix = pp.stdout.strip() if pp.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        prefix = ""
    if prefix:
        changed_set = {f[len(prefix):] for f in changed_set if f.startswith(prefix)}
    controlled = [x for x in base.get("controlled_activation_paths", []) if isinstance(x, str) and x]
    governance = {f for f in changed_set if _path_within_scope(f, paths) and not _path_within_scope(f, controlled)}
    implementation = changed_set - governance
    if governance and implementation:
        out.append("CONTROL_PLANE_CHANGED_IN_IMPLEMENTATION_BRANCH: governance files "
                   f"{sorted(governance)!r} изменены вместе с implementation files "
                   f"{sorted(implementation)!r}; требуются отдельный governance PR, merge в "
                   "защищённую base-ветку и новая implementation-ветка")
    return out


def check_ci_security(root: Path) -> list[str]:
    """YAML-aware GitHub Actions policy for templates and actual workflows."""
    out: list[str] = []
    candidates: list[Path] = [root / "templates" / "ci_validate.yml"]
    workflow_root = root / ".github" / "workflows"
    if workflow_root.exists():
        candidates.extend(sorted(workflow_root.glob("*.yml")))
        candidates.extend(sorted(workflow_root.glob("*.yaml")))
    examples = root / "examples"
    if examples.exists():
        candidates.extend(sorted(examples.glob("**/.github/workflows/*.yml")))
        candidates.extend(sorted(examples.glob("**/.github/workflows/*.yaml")))
    candidates = list(dict.fromkeys(path for path in candidates if path.exists()))

    try:
        import yaml  # type: ignore
    except ImportError:
        return ["CI_SECURITY_YAML_PARSER_UNAVAILABLE: install pinned PyYAML toolchain"]

    sha_re = re.compile(r"^[0-9a-f]{40}$")
    dangerous_shell = re.compile(
        r"(?mi)(?:^|[;&|]\s*)(?:sudo\b|eval\b|rm\s+-rf\s+/(?:\s|$)|"
        r"chmod\s+777\b|\|\s*(?:ba)?sh\b|(?:curl|wget)\b[^\n|]*\|\s*(?:ba)?sh\b)"
    )

    def permissions_findings(rel: Path, value: Any, where: str) -> list[str]:
        findings: list[str] = []
        if value == "write-all":
            return [f"{rel}: {where} permissions: write-all запрещён"]
        if value is None:
            return [f"{rel}: отсутствует explicit minimal permissions: contents: read"]
        if not isinstance(value, dict):
            return [f"{rel}: {where} permissions должен быть mapping с contents: read"]
        if value.get("contents") != "read":
            findings.append(f"{rel}: {where} permissions.contents должен быть read")
        for scope, access in value.items():
            if isinstance(access, str) and access.lower().endswith("write"):
                findings.append(f"{rel}: {where} write permission {scope}: {access} запрещён без отдельного trusted workflow")
        return findings

    for path in candidates:
        rel = path.relative_to(root)
        text = path.read_text(encoding="utf-8", errors="ignore")
        try:
            data = yaml.safe_load(text)
        except Exception as exc:
            out.append(f"{rel}: CI_WORKFLOW_YAML_INVALID: {exc}")
            continue
        if not isinstance(data, dict):
            out.append(f"{rel}: workflow root должен быть mapping")
            continue
        if re.search(r"\bpull_request_target\b", text):
            out.append(f"{rel}: pull_request_target запрещён для исполнения PR-кода")
        out.extend(permissions_findings(rel, data.get("permissions"), "top-level"))

        trigger = data.get("on") if "on" in data else data.get(True)  # PyYAML 1.1 may parse `on` as True.
        trigger_text = json.dumps(trigger, ensure_ascii=False) if trigger is not None else ""
        pr_controlled = "pull_request" in trigger_text or bool(re.search(r"(?m)^\s*pull_request\s*:", text))
        secret_expr = re.compile(
            r"\$\{\{\s*(?:secrets(?:\.|\s*\[)|github(?:\.token|\s*\[\s*[\"\']token[\"\']\s*\]))",
            re.IGNORECASE,
        )

        if pr_controlled:
            workflow_env = data.get("env")
            rendered_workflow_env = json.dumps(workflow_env, ensure_ascii=False) if workflow_env is not None else ""
            if secret_expr.search(rendered_workflow_env):
                out.append(f"{rel}: CI_SECRET_EXPOSED_TO_PR_CODE: workflow-level env")

        jobs = data.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            out.append(f"{rel}: jobs отсутствует или пуст")
            continue
        all_runs: list[str] = []
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                out.append(f"{rel}: job {job_id!r} должен быть mapping")
                continue
            if "permissions" in job:
                out.extend(permissions_findings(rel, job.get("permissions"), f"job {job_id}"))
            if pr_controlled:
                for field in ("env", "with", "secrets", "environment", "container", "services"):
                    value = job.get(field)
                    rendered = json.dumps(value, ensure_ascii=False) if value is not None else ""
                    if secret_expr.search(rendered) or (field == "secrets" and value == "inherit"):
                        out.append(f"{rel}: CI_SECRET_EXPOSED_TO_PR_CODE: job {job_id!r}.{field}")
                if job.get("secrets") == "inherit":
                    out.append(f"{rel}: CI_SECRETS_INHERIT_FOR_PR_CODE: job {job_id!r}")
            steps = job.get("steps", [])
            if not isinstance(steps, list):
                out.append(f"{rel}: job {job_id!r}.steps должен быть array")
                continue
            for index, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if pr_controlled:
                    for field in ("env", "with"):
                        value = step.get(field)
                        rendered = json.dumps(value, ensure_ascii=False) if value is not None else ""
                        if secret_expr.search(rendered):
                            out.append(f"{rel}: CI_SECRET_EXPOSED_TO_PR_CODE: job {job_id!r}.steps[{index}].{field}")
                    if isinstance(uses, str) and (uses.startswith("./") or uses.endswith(".yml") or uses.endswith(".yaml")):
                        rendered = json.dumps(step.get("with", {}), ensure_ascii=False)
                        if secret_expr.search(rendered):
                            out.append(f"{rel}: CI_REUSABLE_WORKFLOW_SECRET_FLOW: job {job_id!r}.steps[{index}]")
                if isinstance(uses, str) and not uses.startswith("./"):
                    if "@" not in uses:
                        out.append(f"{rel}: uses без ref: {uses}")
                    else:
                        action, ref = uses.rsplit("@", 1)
                        if not sha_re.fullmatch(ref):
                            out.append(f"{rel}: action {action} не SHA-pinned: @{ref}")
                        pattern = re.compile(rf"(?m)^\s*-?\s*uses:\s*{re.escape(uses)}\s*(?:#\s*(.+))?$")
                        match = pattern.search(text)
                        if not match or not (match.group(1) or "").strip():
                            out.append(f"{rel}: SHA-pinned action {action} должен иметь комментарий версии")
                run = step.get("run")
                if isinstance(run, str):
                    all_runs.append(run)
                    if "${{" in run:
                        out.append(f"{rel}: job {job_id!r}.steps[{index}].run содержит direct GitHub expression; передай значение через env")
                    if re.search(r"(?mi)(?:python\s+-m\s+)?pip\s+install\s+(?:-e|--editable)\b", run):
                        out.append(f"{rel}: editable install исполняет PR-controlled packaging code")
                    if re.search(r"(?mi)(?:python\s+-m\s+)?pip\s+install\s+\.(?:\s|$)", run):
                        out.append(f"{rel}: local package install в PR workflow запрещён")
                    if dangerous_shell.search(run) or re.search(r"\|\s*(?:ba)?sh\b", run):
                        out.append(f"{rel}: dangerous shell construct в job {job_id!r}.steps[{index}]")

        joined = "\n".join(all_runs)
        name = str(data.get("name", "")).lower()
        is_validation = "validate" in path.name.lower() or "validat" in name or "validate_structure.py" in joined
        if is_validation:
            if "--check-ci-security" not in joined:
                out.append(f"{rel}: validation workflow не запускает обязательный --check-ci-security")
            if "run_test_suite.py" not in joined:
                out.append(f"{rel}: validation workflow не запускает canonical run_test_suite.py")
    return out


def check_standard_capabilities(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Machine-readable capability evidence graph + generated markdown."""
    out: list[str] = []
    path = root / "reference" / "standard_capabilities.json"
    data, err = load_json(path)
    if err or not isinstance(data, dict):
        return [f"standard-capabilities: registry не читается: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    sp = schemas_root / "standard_capabilities.schema.json" if schemas_root else None
    if sp and sp.exists():
        sch, serr = load_json(sp)
        if not serr and isinstance(sch, dict):
            out.extend(validate_schema(data, sch, "standard_capabilities.json"))
    seen: set[str] = set()
    for i, cap in enumerate(data.get("capabilities", [])):
        if not isinstance(cap, dict):
            continue
        cid = cap.get("id")
        if isinstance(cid, str):
            if cid in seen: out.append(f"standard-capabilities: duplicate id {cid!r}")
            seen.add(cid)
        for field in ("normative_docs", "schemas", "validators", "tests", "release_gates", "prompt_paths"):
            for rel in cap.get(field, []) or []:
                if isinstance(rel, str) and not (root / rel).exists():
                    out.append(f"standard-capabilities: {cid}.{field} target не существует: {rel}")
        known_flags = _known_validator_flags(root, "tools/validate_structure.py") or set()
        for flag in cap.get("validator_flags", []) or []:
            if isinstance(flag, str) and flag not in known_flags:
                out.append(f"standard-capabilities: {cid}.validator_flags содержит "
                           f"незарегистрированный флаг {flag!r}")
        test_source = "\n".join(
            (root / rel).read_text(encoding="utf-8", errors="ignore")
            for rel in cap.get("tests", []) or []
            if isinstance(rel, str) and (root / rel).exists()
        )
        for test_id in cap.get("test_ids", []) or []:
            if isinstance(test_id, str) and not re.search(rf"(?m)^def\s+{re.escape(test_id)}\s*\(", test_source):
                out.append(f"standard-capabilities: {cid}.test_ids ссылается на отсутствующий test {test_id!r}")
        if set(cap.get("test_ids", []) or []) != set((cap.get("positive_test_ids", []) or []) + (cap.get("negative_test_ids", []) or [])):
            out.append(f"standard-capabilities: {cid}.test_ids не равен union positive_test_ids+negative_test_ids")
        if cap.get("status") == "FULLY_ENFORCED":
            for field in ("normative_docs", "validators", "tests", "release_gates", "positive_test_ids", "negative_test_ids", "applicable_profiles"):
                if not cap.get(field):
                    out.append(f"standard-capabilities: {cid} FULLY_ENFORCED без {field}")
            if cap.get("evidence_level") != "NEGATIVE_TESTED":
                out.append(f"standard-capabilities: {cid} FULLY_ENFORCED без evidence_level=NEGATIVE_TESTED")
            if cap.get("negative_tested") is not True:
                out.append(f"standard-capabilities: {cid} FULLY_ENFORCED без negative_tested=true")
            if cap.get("release_enforced") is not True:
                out.append(f"standard-capabilities: {cid} FULLY_ENFORCED без release_enforced=true")
            if cap.get("external_control_required") is True:
                out.append(f"standard-capabilities: {cid} требует external control и не может быть FULLY_ENFORCED")
        if cap.get("status") == "PLANNED_NOT_IMPLEMENTED":
            for field in ("validators", "validator_flags", "tests", "release_gates", "test_ids"):
                if cap.get(field):
                    out.append(f"standard-capabilities: {cid} PLANNED_NOT_IMPLEMENTED не должен иметь {field}")
            if cap.get("release_enforced") or cap.get("negative_tested"):
                out.append(f"standard-capabilities: {cid} PLANNED_NOT_IMPLEMENTED не может иметь executable evidence")
    generator = root / "tools" / "generate_capabilities.py"
    if generator.exists():
        proc = subprocess.run([sys.executable, str(generator), "--root", str(root), "--check"],
                              cwd=root, capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            out.append("standard-capabilities: CAPABILITIES.md не совпадает с registry")
    return out

_PARALLEL_AI_DEV_REQUIRED_FILES = (
    "module_registry.json", "code_ownership.json",
    "work_package_graph.json", "active_work_packages.json",
    "control_plane_manifest.json",
)


def check_parallel_ai_development(root: Path, schemas_root_arg: str | None,
                                  base_ref: str | None = None) -> list[str]:
    """docs/registry/project_profile.json.parallel_ai_development.enabled
    (v2.9.115, реализует предложение ревью v2.9.114 «capability, делающий
    модульные слои обязательными»): без project_profile.json или с
    enabled отличным от true — no-op, тот же opt-in принцип, что у самих
    модульных слоёв (сейчас проект может запускать несколько AI-помощников
    параллельно, не имея НИ ОДНОГО из четырёх модульных реестров, и пройти
    CI чисто).

    Когда enabled=true (см. _parallel_mode_enabled_trusted — доверенное,
    не только live-значение с v2.9.122): все 4 файла (module_registry/
    code_ownership/work_package_graph/active_work_packages) обязаны
    СУЩЕСТВОВАТЬ, и эта проверка АГРЕГИРУЕТ результаты их собственных
    check_* функций — сознательно, не просто require-существование: иначе
    флаг мог бы существовать в проекте, но кто-то забыл бы добавить
    остальные --check-* в CI, и enabled=true осталось бы декларацией без
    реального enforcement (тот же класс проблемы, который сам этот флаг
    призван закрыть).

    v2.9.122 (P0 внешнего аудита v2.9.121 §4, репродуцировано напрямую):
    implementation-ветка одновременно удаляла свою же активную аренду И
    меняла enabled на false (или удаляла файл) — TASK_ID переставал
    резолвиться, CI читал live enabled=false, active-task-diff тихо
    пропускался целиком, exit 0; check_active_task_diff() со всем своим
    base-lock allowed_paths (v2.9.121) вообще не вызывался. --base-ref
    (опционален, обратная совместимость) позволяет сверить live-значение с
    версией на базовой точке — если было true там, а в проверяемой ветке
    false/отсутствует, это отдельная жёсткая находка, а ДАЛЬШЕ по функции
    используется доверенное (OR по live/base) значение, не сырое live."""
    out: list[str] = []
    profile_path = root / "docs" / "registry" / "project_profile.json"
    live_data = None
    if profile_path.exists():
        live_data, err = load_json(profile_path)
        if err:
            return [f"project_profile.json: битый JSON: {err}"]
    live_pad = live_data.get("parallel_ai_development") if isinstance(live_data, dict) else None
    live_enabled = isinstance(live_pad, dict) and live_pad.get("enabled") is True
    # v2.9.123 (P1 внешнего аудита v2.9.122, A-2, репродуцировано фактическими
    # run:-скриптами шаблона): --base-ref был ЗАДАН вызывающим (обычно CI),
    # но не резолвится (недостижимый origin/<default_branch> — shallow
    # checkout без fetch-depth:0, self-hosted runner с кастомным clone,
    # зеркало) — раньше это тихо деградировало к live-only сравнению
    # (тот же результат, что и при base_ref=None вовсе), то есть от
    # ОДНОЙ причины (недостижимый origin) тихо теряли governance-защиту
    # ОБА шага шаблона одновременно. Если профиль СУЩЕСТВУЕТ в живой
    # ветке — есть что защищать — недостижимость запрошенного base_ref
    # для этого прогона это отдельная, громкая находка, не молчаливый
    # fallback. Профиля нет вовсе — нечего защищать, тот же opt-in
    # принцип, что и везде в этом файле.
    if base_ref and live_data is not None and not _git_ref_resolves(root, base_ref):
        out.append(f"parallel-ai-development: --base-ref={base_ref!r} не резолвится "
                   f"(git rev-parse --verify --quiet), а docs/registry/project_profile.json "
                   f"существует в проверяемой ветке — доверенное сравнение с базовой веткой "
                   f"невозможно для этого прогона, self-disable не может быть обнаружен. "
                   f"Обеспечь fetch-depth:0 и доступный base ref (v2.9.123, P1 внешнего "
                   f"аудита v2.9.122, A-2)")
    resolved_ref, _ = _resolve_merge_base(root, base_ref) if base_ref else (None, None)
    trusted_enabled = _parallel_mode_enabled_trusted(root, resolved_ref)
    if trusted_enabled and not live_enabled:
        out.append(f"parallel-ai-development: parallel_ai_development.enabled было true на "
                   f"{resolved_ref!r}, но в проверяемой ветке — false или файл отсутствует — "
                   f"implementation-ветка не может отключить собственный governance-режим "
                   f"(v2.9.122, P0 внешнего аудита v2.9.121 §4)")
    if not trusted_enabled:
        return out
    for fname in _PARALLEL_AI_DEV_REQUIRED_FILES:
        if not (root / "docs" / "registry" / fname).exists():
            out.append(f"parallel-ai-development: enabled=true требует docs/registry/{fname}, "
                       f"файл отсутствует")
    out.extend(check_control_plane_integrity(root, schemas_root_arg, base_ref))
    out.extend(check_module_registry(root, schemas_root_arg))
    out.extend(check_code_ownership(root, schemas_root_arg))
    out.extend(check_module_boundaries(root, schemas_root_arg))
    out.extend(check_work_package_graph(root, schemas_root_arg))
    out.extend(check_work_package_overlap(root, schemas_root_arg))
    return out


def check_sync_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/sync_jobs.json: каналы по классам данных. bidirectional —
    только documents; rsync one_way (+dry-run при delete); restic — retention+check;
    секреты не синкаются; цели — имена, не голые IP. См. SYNC_AND_BACKUP_STANDARD."""
    out: list[str] = []
    data = _load_registry_json(root, "sync_jobs.json", "sync_jobs.schema.json",
                               schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    if data.get("transport") != "tailscale" and not data.get("transport_exception"):
        out.append("sync_jobs.json: transport не tailscale и нет transport_exception")
    ip_re = re.compile(r"(?<![\d.])\d{1,3}(\.\d{1,3}){3}(?![\d.])")
    # главная идея слоя: каждому классу данных — свой канал (v2.9.49, P1 ревью)
    allowed_class_tool = {"code": {"git"}, "documents": {"syncthing"},
                          "large_data": {"rsync"}, "backup": {"restic"},
                          "secrets": {"git"}}
    for i, j in enumerate(data.get("jobs", []) or []):
        if not isinstance(j, dict):
            continue
        jid = j.get("id", f"[{i}]")
        cls, tool, mode = j.get("class"), j.get("tool"), j.get("mode")
        allowed = allowed_class_tool.get(cls)
        if allowed and tool not in allowed:
            out.append(f"sync_jobs.json {jid}: class={cls} должен использовать "
                       f"{sorted(allowed)}, не {tool} (каждому классу — свой канал)")
        if cls == "secrets" and tool in ("syncthing", "rsync"):
            out.append(f"sync_jobs.json {jid}: секреты не синхронизируются {tool} "
                       f"(только .env.enc через Git — ENCRYPTED_ENV_STANDARD)")
        if mode == "bidirectional" and cls != "documents":
            out.append(f"sync_jobs.json {jid}: bidirectional разрешён только для documents, не {cls}")
        if tool == "syncthing":
            exc = j.get("exclude") or []
            for must in (".env", ".git", ".venv"):
                if must not in exc:
                    out.append(f"sync_jobs.json {jid}: syncthing exclude без {must}")
            if j.get("versioning_required") is not True:
                out.append(f"sync_jobs.json {jid}: syncthing требует versioning_required: true")
        if tool == "rsync":
            if mode != "one_way":
                out.append(f"sync_jobs.json {jid}: rsync только one_way")
            if j.get("delete") and j.get("dry_run_required_before_first_run") is not True:
                out.append(f"sync_jobs.json {jid}: delete=true требует dry_run_required_before_first_run")
            if ".env" not in (j.get("exclude") or []):
                out.append(f"sync_jobs.json {jid}: rsync exclude без .env")
        if tool == "restic":
            if not isinstance(j.get("retention"), dict):
                out.append(f"sync_jobs.json {jid}: restic без retention")
            if j.get("check_required") is not True:
                out.append(f"sync_jobs.json {jid}: restic требует check_required: true")
        for field in ("target", "repository", "server_path"):
            val = j.get(field)
            if isinstance(val, str) and ip_re.search(val):
                out.append(f"sync_jobs.json {jid}: {field} содержит голый IP — "
                           f"используй tailscale_name/hostname")
    return out


def check_encrypted_env(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Секреты через .env.enc: plaintext .env не идёт в Git, .env.enc не
    заблокирован .gitignore-паттерном .env.*, бандл — JSON-конверт (не plaintext),
    passphrase_env описан в env_vars.json без default. Статические проверки;
    runtime (--verify) — в CI проекта. См. ENCRYPTED_ENV_STANDARD."""
    out: list[str] = []
    gi = root / ".gitignore"
    gi_lines = [l.strip() for l in gi.read_text(encoding="utf-8", errors="ignore").splitlines()] \
        if gi.exists() else []
    env_f = root / ".env"
    if env_f.exists():
        covered = any(l in (".env", "/.env") or l.startswith(".env*") or l == ".env.*"
                      for l in gi_lines) or ".env" in gi_lines
        if not covered:
            out.append(".env существует и не покрыт .gitignore — plaintext-секреты на пути в Git")
    enc_f = root / ".env.enc"
    blocking = [l for l in gi_lines if l in (".env.*", ".env*")]
    if enc_f.exists() and blocking and "!.env.enc" not in gi_lines:
        out.append(f".gitignore: паттерн {blocking[0]} блокирует .env.enc — добавь !.env.enc "
                   f"(иначе бандл не попадёт в Git)")
    if enc_f.exists():
        head = enc_f.read_text(encoding="utf-8", errors="ignore")
        has_plain = re.search(r"^[A-Z][A-Z0-9_]*=", head[:2000], re.M)
        payload, perr = load_json(enc_f)
        if has_plain or perr or not isinstance(payload, dict):
            out.append(".env.enc выглядит как plaintext dotenv, а не зашифрованный JSON-конверт")
        else:
            # канонический формат: {"salt": b64, "data": b64} (v2.9.49, P1 ревью)
            # + минимальная длина после decode (v2.9.50, P2 ревью) — не Fernet-
            # verify (это runtime, не в валидаторе), но отсекает мусор вроде
            # {"salt":"eA==","data":"eA=="} (1-байтные "значения")
            import base64 as _b64
            _MIN_LEN = {"salt": 16, "data": 40}  # salt=os.urandom(16); Fernet-token >= ~73B
            for field in ("salt", "data"):
                val = payload.get(field)
                if not isinstance(val, str) or not val:
                    out.append(f".env.enc: нет обязательного поля {field} (формат JSON{{salt,data}})")
                    continue
                try:
                    decoded = _b64.b64decode(val, validate=True)
                except Exception:
                    out.append(f".env.enc: {field} должен быть валидным base64")
                    continue
                if len(decoded) < _MIN_LEN[field]:
                    out.append(f".env.enc: {field} слишком короткий после decode "
                              f"({len(decoded)} байт < {_MIN_LEN[field]}) — не похоже на реальный bundle")
                elif field == "data" and not decoded.startswith(b"gAAAAA"):
                    # Fernet-token heuristic (v2.9.51, P2 ревью): наш формат
                    # двойного кодирования — data это base64(fernet_token), а
                    # сам fernet_token всегда начинается с "gAAAAA" (версия-байт
                    # 0x80 + почти всегда нулевой старший байт timestamp).
                    # Не полноценная расшифровка (нужна passphrase) — только
                    # доп. фильтр мусора поверх формата/длины; warning, не error.
                    out.append(f"{WARN_PREFIX}.env.enc: data не похож на Fernet-токен "
                              f"(не начинается с 'gAAAAA' после decode) — возможно, "
                              f"битый bundle или другая схема шифрования")
    policy = _load_registry_json(root, "encrypted_env_policy.json",
                                 "encrypted_env_policy.schema.json", schemas_root_arg, out)
    if isinstance(policy, dict):
        tool = policy.get("tool")
        if isinstance(tool, str) and not (root / tool).exists():
            out.append(f"encrypted_env_policy.json: tool не найден: {tool}")
        loader = policy.get("loader")
        if isinstance(loader, str) and not (root / loader).exists():
            out.append(f"encrypted_env_policy.json: loader не найден: {loader}")
        pe = policy.get("passphrase_env")
        if isinstance(pe, str):
            env_reg = root / "docs" / "registry" / "env_vars.json"
            if env_reg.exists():
                ed, _ = load_json(env_reg)
                entry = next((e for e in ed if isinstance(e, dict) and e.get("variable") == pe), None) \
                    if isinstance(ed, list) else None
                if entry is None:
                    out.append(f"encrypted_env_policy.json: {pe} не описан в env_vars.json")
                else:
                    if entry.get("secret") is not True:
                        out.append(f"env_vars.json: {pe} должен быть secret: true")
                    if "default" in entry:
                        out.append(f"env_vars.json: {pe} не должен иметь default (bootstrap-секрет)")
        ex = policy.get("example_file")
        if isinstance(ex, str) and not (root / ex).exists():
            out.append(f"encrypted_env_policy.json: example_file не найден: {ex}")
        it_min = policy.get("kdf_iterations_min")
        if isinstance(tool, str) and (root / tool).exists() and isinstance(it_min, int):
            src = (root / tool).read_text(encoding="utf-8", errors="ignore")
            found = [int(m.replace("_", "")) for m in
                     re.findall(r"iterations\s*=\s*(\d[\d_]*)", src, re.I)]
            if not found:
                # молчаливый пропуск = невыполненное обещание policy (v2.9.49)
                out.append(f"{tool}: не найдено значение PBKDF2 iterations (policy требует ≥ {it_min})")
            elif max(found) < it_min:
                out.append(f"{tool}: PBKDF2 iterations {max(found)} < {it_min}")
    return out


def _command_leak_findings(cmd: str, label: str) -> list[str]:
    """Эвристики раскрытия секретов в shell-команде (cat .env, echo $SECRET,
    трассировка -x, env|grep, printenv SECRET, plaintext-присвоение). Общая
    для --check-automation-jobs и --check-code-audit-policy (v2.9.52) — не
    дублируется, живёт в одном месте. Точное статическое обнаружение
    невозможно, это базовые паттерны, не полный анализ."""
    out: list[str] = []
    if re.search(r"\bcat\s+\.env\b", cmd):
        out.append(f"{label}: command делает cat .env — запрещено")
    if re.search(r"\bprintenv\b|(^|[;&|]\s*)env\s*$", cmd):
        out.append(f"{label}: command печатает env целиком — запрещено")
    if re.search(r"(password|token|secret|api[_-]?key)\s*=\s*\S", cmd, re.I):
        out.append(f"{label}: похоже на plaintext-секрет в command")
    if re.search(r'\becho\b[^|;&]*\$\{?[A-Z_]*(PASSWORD|TOKEN|SECRET|API[_-]?KEY|PASSPHRASE)[A-Z0-9_]*\}?', cmd, re.I):
        out.append(f"{label}: echo секрет-подобной переменной в command — может напечатать значение")
    if re.search(r"(^|[;&|]\s*)(set\s+-\w*x\w*|bash\s+-x|sh\s+-x)\b", cmd):
        out.append(f"{label}: трассировка (-x) печатает значения переменных в лог")
    if re.search(r"\benv\s*\|\s*grep\b", cmd):
        out.append(f"{label}: env | grep — риск утечки значения в лог")
    if re.search(r"\bprintenv\s+\w*(PASSWORD|TOKEN|SECRET|API[_-]?KEY|PASSPHRASE)\w*\b", cmd, re.I):
        out.append(f"{label}: printenv секрет-подобной переменной печатает значение")
    return out


def _flag_letters_and_long(flags: list[str]) -> tuple[set[str], set[str]]:
    """Разводит bundled short-флаги (`-fdx` → {f,d,x}) и long-флаги (`--force`),
    независимо от порядка/склейки — используется деструктивными git-детекторами
    ниже, чтобы `-d -f`/`-d --force`/`--delete --force` ловились так же, как
    склеенная форма `-df`."""
    letters: set[str] = set()
    longs: set[str] = set()
    for f in flags:
        if f.startswith("--"):
            longs.add(f)
        elif f.startswith("-") and len(f) > 1:
            letters |= set(f[1:])
    return letters, longs


def _git_destructive_command_findings(cmd: str, label: str) -> list[str]:
    """Деструктивные git-команды в scheduled job без approval/dry-run —
    отдельно от утечки секретов (_command_leak_findings). v2.9.89, см.
    GIT_WORKSPACE_HYGIENE_STANDARD.md §4.4/§10: git branch -D (или -d/--delete
    вместе с -f/--force в любом порядке/раздельно) и git worktree remove
    --force (или -f, в любой позиции) запрещены в автоматизации (необратимо
    без подтверждения человека); git clean с флагами f+d+x вместе (склеенными
    или раздельными) запрещён без explicit allowlist; git remote prune origin
    в scheduled job требует --dry-run/-n в самой команде. v2.9.90 (P1 внешнего
    ревью v2.9.89): раньше это был regex по буквальной подстроке — `git branch
    -d -f`/`git branch --delete --force`/`git worktree remove <path> --force`
    (флаг не сразу после `remove`)/`git clean -f -d -x` (раздельные флаги)
    проходили незамеченными. Теперь — токенизация по shell-сегментам
    (`_shell_segments`) + разбор флагов через `_flag_letters_and_long`,
    независимо от порядка и формы записи."""
    out: list[str] = []
    for argv in _shell_segments(cmd):
        while argv and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", argv[0]):
            argv = argv[1:]
        if not argv or argv[0] != "git" or len(argv) < 2:
            continue
        sub, rest = argv[1], argv[2:]
        if sub == "branch":
            letters, longs = _flag_letters_and_long(rest)
            has_delete = "D" in letters or "d" in letters or "--delete" in longs
            has_force = "f" in letters or "--force" in longs
            if "D" in letters or (has_delete and has_force):
                out.append(f"{label}: git branch {' '.join(rest)} в scheduled job — "
                           f"force-delete ветки без подтверждения человека запрещён")
        elif sub == "worktree" and rest[:1] == ["remove"]:
            wt_rest = rest[1:]
            letters, longs = _flag_letters_and_long(wt_rest)
            if "f" in letters or "--force" in longs:
                out.append(f"{label}: git worktree remove {' '.join(wt_rest)} в scheduled "
                           f"job — без подтверждения человека запрещён")
        elif sub == "clean":
            letters, longs = _flag_letters_and_long(rest)
            if "--force" in longs:
                letters.add("f")
            if {"f", "d", "x"} <= letters:
                out.append(f"{label}: git clean {' '.join(rest)} в scheduled job — "
                           f"сочетание f+d+x без explicit allowlist запрещено")
        elif sub == "remote" and rest[:1] == ["prune"]:
            prune_rest = rest[1:]
            if "origin" in prune_rest and "--dry-run" not in prune_rest and "-n" not in prune_rest:
                out.append(f"{label}: git remote prune {' '.join(prune_rest)} в scheduled "
                           f"job без --dry-run — нужен предварительный dry-run/report")
    return out


def check_automation_jobs(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/automation_jobs.json: дисциплина job'ов automation_server —
    lock/redact/notify/retention/dry-run; command без plaintext-секретов и без
    cat .env / printenv; command без деструктивных git-команд без approval/
    dry-run (v2.9.89, GIT_WORKSPACE_HYGIENE_STANDARD). См. AUTOMATION_SERVER_SYNC_STANDARD."""
    out: list[str] = []
    data = _load_registry_json(root, "automation_jobs.json",
                               "automation_jobs.schema.json", schemas_root_arg, out)
    if not isinstance(data, list):
        return out
    for i, j in enumerate(data):
        if not isinstance(j, dict):
            continue
        jid = j.get("id", f"[{i}]")
        if not j.get("schedule") and not j.get("trigger"):
            out.append(f"automation_jobs.json {jid}: нужен schedule или trigger")
        jt = j.get("type")
        if jt in ("sync", "backup", "project_job") and j.get("lock") is not True:
            out.append(f"automation_jobs.json {jid}: type={jt} требует lock: true")
        if jt == "project_job" and j.get("redact_logs") is not True:
            out.append(f"automation_jobs.json {jid}: project_job требует redact_logs: true")
        if jt == "backup" and not isinstance(j.get("retention"), dict):
            out.append(f"automation_jobs.json {jid}: backup требует retention")
        if j.get("notify_on_failure") is not True:
            out.append(f"automation_jobs.json {jid}: требуется notify_on_failure: true")
        cmd = j.get("command", "")
        if isinstance(cmd, str):
            # v2.9.90 (P2 внешнего ревью v2.9.89): раньше голая подстрока "--delete"
            # ловила и git branch --delete/--delete --force — сузили до rsync,
            # чтобы не путать причину находки.
            if "rsync" in cmd and "--delete" in cmd and j.get("dry_run_before_first_run") is not True:
                out.append(f"automation_jobs.json {jid}: rsync --delete требует dry_run_before_first_run")
            out.extend(_command_leak_findings(cmd, f"automation_jobs.json {jid}"))
            out.extend(_git_destructive_command_findings(cmd, f"automation_jobs.json {jid}"))
    return out


_TYPICAL_PROTECTED_BRANCHES = {"main", "master", "release", "release/*"}


def check_git_agent_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/git_agent_policy.json: commit/push режим агента.
    Два инварианта нельзя выключить — forbid_force_push и
    forbid_push_to_protected_branches, оба обязаны быть true. auto_push_after_green
    без push_requires_explicit_user_approval требует явного waiver_reason
    (v2.9.53, P2 ревью) — иначе агент может получить конфиг, где он пушит без
    вопроса, и это не будет видно из самого файла. protected_branches обязан
    содержать типовую защищённую ветку (main/master/release/release/*) либо
    проект обязан явно обосновать нетиповую схему через
    custom_branch_policy_reason (v2.9.54, P2 ревью) — иначе ["foo"] формально
    непустой, но реально ничего не защищает. merge_policy.auto_merge_after_gate_pass
    (v2.9.93) — опциональный override для контролируемой autonomy-среды (напр.
    IskInoSfera): по умолчанию отсутствует/false — мерж в защищённую ветку
    требует человека, как и раньше; включить можно, но той же waiver-идиомой,
    что и auto_push, плюс обязателен merge_only_via_reviewable_pr (не прямой
    push в защищённую ветку в обход PR). v2.9.95 (P1 внешнего ревью v2.9.94):
    *_requires_explicit_user_approval обязан присутствовать явно (true/false),
    когда auto_push_after_green/auto_merge_after_gate_pass=true — раньше
    ОТСУТСТВУЮЩЕЕ поле не отличалось от «подтверждение не нужно» и обходило
    waiver (репродуцировано: конфиг без approval-поля проходил PASS). Остальное
    — поведенческая дисциплина сессии, не проверяется статически. См.
    GIT_AGENT_WORKFLOW_STANDARD."""
    out: list[str] = []
    data = _load_registry_json(root, "git_agent_policy.json",
                               "git_agent_policy.schema.json", schemas_root_arg, out)
    if data is None:
        return out
    if not isinstance(data, dict):
        return out + ["git_agent_policy.json: ожидался объект"]
    push = data.get("push_policy") or {}
    if isinstance(push, dict):
        if push.get("forbid_force_push") is False:
            out.append("git_agent_policy.json: push_policy.forbid_force_push=false — "
                       "нельзя отключать защиту от force-push (необратимая операция)")
        if push.get("forbid_push_to_protected_branches") is False:
            out.append("git_agent_policy.json: push_policy.forbid_push_to_protected_branches=false — "
                       "нельзя отключать защиту защищённых веток")
        if push.get("auto_push_after_green") is True:
            approval = push.get("push_requires_explicit_user_approval")
            if approval is None:
                out.append("git_agent_policy.json: push_policy.auto_push_after_green=true "
                           "требует явного push_requires_explicit_user_approval (true/false) — "
                           "отсутствие поля неотличимо от «подтверждение не нужно» (P1 "
                           "внешнего ревью v2.9.94: отсутствующее поле обходило waiver)")
            elif approval is False and not push.get("waiver_reason"):
                out.append("git_agent_policy.json: push_policy.auto_push_after_green=true и "
                           "push_requires_explicit_user_approval=false без waiver_reason — "
                           "агент будет пушить без вопроса пользователю, это требует явного "
                           "обоснования в waiver_reason")
    merge = data.get("merge_policy") or {}
    if isinstance(merge, dict) and merge.get("auto_merge_after_gate_pass") is True:
        if merge.get("merge_only_via_reviewable_pr") is not True:
            out.append("git_agent_policy.json: merge_policy.auto_merge_after_gate_pass=true "
                       "требует merge_only_via_reviewable_pr=true — автомерж только через "
                       "проверяемый PR, не прямой push в защищённую ветку в обход истории")
        merge_approval = merge.get("merge_requires_explicit_user_approval")
        if merge_approval is None:
            out.append("git_agent_policy.json: merge_policy.auto_merge_after_gate_pass=true "
                       "требует явного merge_requires_explicit_user_approval (true/false) — "
                       "отсутствие поля неотличимо от «подтверждение не нужно» (P1 внешнего "
                       "ревью v2.9.94: отсутствующее поле обходило waiver)")
        elif merge_approval is False and not merge.get("waiver_reason"):
            out.append("git_agent_policy.json: merge_policy.auto_merge_after_gate_pass=true и "
                       "merge_requires_explicit_user_approval=false без waiver_reason — "
                       "автомерж без подтверждения человека требует явного обоснования "
                       "(контролируемая autonomy-среда, не любой проект по умолчанию)")
    pb = data.get("protected_branches")
    if isinstance(pb, list):
        if not pb:
            out.append("git_agent_policy.json: protected_branches не должен быть пустым")
        elif (not (set(pb) & _TYPICAL_PROTECTED_BRANCHES)
                and not data.get("custom_branch_policy_reason")):
            out.append(f"git_agent_policy.json: protected_branches={pb!r} не содержит ни "
                       f"одной типовой защищённой ветки ({sorted(_TYPICAL_PROTECTED_BRANCHES)}) "
                       f"— если у проекта нетиповая схема веток, обоснуй через "
                       f"custom_branch_policy_reason")
    return out


def check_agent_results(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/agent_results/*.json (опционален, v2.9.93): структурированный
    результат работы агента вместо свободного текста — AGENT_RESULT_CONTRACT.md.
    Директория опциональна целиком; если есть хотя бы один файл — каждый
    валидируется по схеме + семантические инварианты: status=COMPLETED
    несовместим с непустым unverified_claims (нельзя одновременно заявить
    «всё подтверждено» и «есть неподтверждённые утверждения») — для такого
    случая есть отдельный статус COMPLETED_WITH_CAVEATS. BLOCKED/FAILED без
    blocked_reason — тоже ошибка (тот же waiver-принцип: рискованное/неполное
    состояние требует объяснения, не тихого молчания). Усилено в v2.9.95
    (P2 внешнего ревью v2.9.94, репродуцировано): status=COMPLETED несовместим
    с любым tests[].result=failed (нельзя заявить «завершено» при упавшем
    тесте) — обязан быть COMPLETED_WITH_CAVEATS/BLOCKED/FAILED; status=
    COMPLETED_WITH_CAVEATS обязан иметь непустой unverified_claims (иначе не
    отличить от обычного COMPLETED — сам статус и есть заявление «что-то не
    подтверждено»). Расширено в v2.9.110 (AI_TO_AI_COMMUNICATION_STANDARD.md):
    новый статус PARTIAL (выполнена только часть scope) обязан иметь непустой
    limitations — тот же waiver-принцип, что и у BLOCKED/FAILED. Усилено в
    v2.9.111 (P1×3 внешнего ревью v2.9.110, репродуцировано): status=COMPLETED
    с пустыми tests[]/checks[] проходил без единой находки, хотя AI_TO_AI_
    COMMUNICATION_STANDARD.md §10 прямо запрещает COMPLETED без evidence —
    теперь обязателен хотя бы один tests[].result=passed либо здоровый checks[];
    новое поле checks[] (v2.9.110) не участвовало в COMPLETED-инварианте вовсе
    (упавший checks[] проходил как упавший tests[] раньше не проходил) —
    добавлена та же проверка; blocked_reason/limitations[] принимали пробельные
    и плейсхолдерные значения (minLength:1 не режет пробелы) — теперь через
    _is_placeholder_value(), тот же принцип, что уже применён в v2.9.108 для
    knowledge_access.reason.

    v2.9.116 (Fowler «Рефакторинг», REFACTORING_SAFETY_STANDARD.md §7):
    task_type связанной задачи резолвится тем же <id>, что и имя файла
    результата (docs/registry/agent_tasks/<id>.json <-> docs/registry/
    agent_results/<id>.json) — AI_TO_AI_COMMUNICATION_STANDARD.md §14
    сознательно не вводит отдельное поле-ссылку внутри результата (совпадение
    имён файлов уже даёт однозначную связь, дублирующее поле только создаёт
    риск рассинхронизации); без файла задачи с тем же <id> type-зависимые
    проверки не применяются (opt-in, как и вся эта проверка целиком). Когда
    связанная задача task_type=refactoring: behavior_baseline/tests_before[]/
    structural_changes[] обязаны быть непустыми и не placeholder; status=
    COMPLETED с public_contract_changed=true — жёсткий блок (изменённый
    публичный контракт не может быть чистым рефакторингом).

    v2.9.117 (P1 внешнего ревью v2.9.116, репродуцировано): checks[]
    без exit_code («not run», «skipped» и т.п. без числового кода) считался
    здоровой проверкой (exit_code in (None, 0) трактовал отсутствие поля как
    ноль) — {"command": "pytest", "result": "not run"} проходил как evidence
    для COMPLETED. Теперь healthy-checks[] требует ЯВНЫЙ exit_code == 0 —
    отсутствие exit_code больше не считается успехом. v2.9.118 сделал
    result[] строгим enum (passed/failed/skipped/not_run) — эта часть
    докстринга устарела и была поправлена в v2.9.119 (P2 внешнего аудита
    v2.9.118, собственная находка при сверке докстринга с кодом).

    v2.9.119 (P0 внешнего аудита v2.9.118, ломающее изменение): required_
    for_statuses удалён из agent_task_contract.required_checks[] —
    required_checks[rc_id] обязателен для ОБОИХ статусов COMPLETED и
    COMPLETED_WITH_CAVEATS без исключений. Раньше задача могла объявить
    check «required только для COMPLETED_WITH_CAVEATS», и тогда result
    COMPLETED с пустыми tests[]/checks[] проходил без единой находки —
    unsatisfied_required пропускал проверку (status not in required_for),
    а базовый evidence-floor ниже (строка 'required_checks is None') тоже
    не срабатывал, потому что required_checks СУЩЕСТВОВАЛ у задачи (просто
    не покрывал этот статус). Прямо воспроизведено перед фиксом."""
    out: list[str] = []
    results_dir = root / "docs" / "registry" / "agent_results"
    if not results_dir.is_dir():
        return out
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    schema = None
    if schemas_root and (schemas_root / "agent_result.schema.json").exists():
        loaded, err = load_json(schemas_root / "agent_result.schema.json")
        if err:
            return [f"agent_results: битая схема agent_result.schema.json: {err}"]
        if isinstance(loaded, dict):
            schema = loaded
    task_type_by_stem: dict[str, str] = {}
    required_checks_by_stem: dict[str, list] = {}
    tasks_dir = root / "docs" / "registry" / "agent_tasks"
    if tasks_dir.is_dir():
        for tf in tasks_dir.glob("*.json"):
            tdata, terr = load_json(tf)
            if terr or not isinstance(tdata, dict):
                continue
            ttype = tdata.get("task_type")
            if isinstance(ttype, str):
                task_type_by_stem[tf.stem] = ttype
            rc = tdata.get("required_checks")
            if isinstance(rc, list):
                required_checks_by_stem[tf.stem] = [c for c in rc if isinstance(c, dict)]
    parallel_enabled = False
    profile_path = root / "docs" / "registry" / "project_profile.json"
    if profile_path.exists():
        pdata, perr = load_json(profile_path)
        if not perr and isinstance(pdata, dict):
            pad = pdata.get("parallel_ai_development")
            if isinstance(pad, dict) and pad.get("enabled") is True:
                parallel_enabled = True
    for f in sorted(results_dir.glob("*.json")):
        rel = f.relative_to(root)
        data, err = load_json(f)
        if err:
            out.append(f"{rel}: битый JSON: {err}")
            continue
        if not isinstance(data, dict):
            out.append(f"{rel}: ожидался объект")
            continue
        if schema:
            out.extend(validate_schema(data, schema, str(rel)))
        # v2.9.122 (P1 внешнего аудита v2.9.121 §10, репродуцировано: агент,
        # удаливший СВОЙ agent_tasks/<id>.json, обходит required_checks/
        # task_type-специфичные инварианты, а система не отличает эту
        # ситуацию от легитимной human-origin задачи — обе выглядят как
        # "task contract отсутствует"): опциональное task_origin делает
        # различие ЯВНЫМ, не выводимым из отсутствия каталога. Не ломает
        # уже принятое решение "DONE не требует task contract" (CHANGELOG
        # v2.9.120 §8) — только 'machine' добавляет требование, отсутствие
        # поля/'human' ведут себя как раньше.
        if data.get("task_origin") == "machine":
            task_path = root / "docs" / "registry" / "agent_tasks" / f"{f.stem}.json"
            if not task_path.exists():
                out.append(f"{rel}: task_origin='machine', но docs/registry/agent_tasks/"
                           f"{f.stem}.json не существует — machine-origin результат обязан "
                           f"иметь машинный task contract (v2.9.122, P1 внешнего аудита "
                           f"v2.9.121 §10)")
        status = data.get("status")
        tests = data.get("tests") if isinstance(data.get("tests"), list) else []
        checks = data.get("checks") if isinstance(data.get("checks"), list) else []
        has_failed_test = any(isinstance(t, dict) and t.get("result") == "failed" for t in tests)
        has_passed_test = any(isinstance(t, dict) and t.get("result") == "passed" for t in tests)
        has_failed_check = any(isinstance(c, dict) and c.get("result") == "failed" for c in checks)
        has_healthy_check = any(isinstance(c, dict) and c.get("result") == "passed"
                                 and c.get("exit_code") == 0 for c in checks)

        # v2.9.118 (P0 внешнего аудита v2.9.117): required_checks[] задачи и
        # checks[] результата были параллельными фактами БЕЗ связи по id —
        # задача могла требовать "python -m pytest tests/full", а результат
        # подтвердить себя любой другой командой; напрямую репродуцировано.
        # required_checks_by_stem[f.stem] — required_checks связанной задачи
        # (тот же принцип связи по имени файла, что и task_type). Для каждой
        # записи, required для ТЕКУЩЕГО status (required_for_statuses, по
        # умолчанию COMPLETED+COMPLETED_WITH_CAVEATS), обязана существовать
        # РОВНО ОДНА checks[] запись с тем же check_id, result=passed,
        # exit_code из expected_exit_codes (по умолчанию [0]).
        required_checks = required_checks_by_stem.get(f.stem)
        checks_by_id: dict[str, list] = {}
        for j, c in enumerate(checks):
            if not isinstance(c, dict):
                continue
            cid = c.get("check_id")
            # v2.9.118 (§13.2 внешнего аудита v2.9.117): обязательная строка
            # валидируется после strip() — "   " проходил бы minLength:1 в
            # схеме (нет pattern у check_id, в отличие от required_checks[].id
            # задачи) и молча собирался бы в checks_by_id как "валидный" id.
            if _is_placeholder_value(cid):
                out.append(f"{rel}: checks[{j}].check_id — плейсхолдер или пусто")
                continue
            if isinstance(cid, str):
                checks_by_id.setdefault(cid, []).append(c)
        if required_checks is not None:
            known_ids = {rc.get("id") for rc in required_checks if isinstance(rc.get("id"), str)}
            for cid in sorted(checks_by_id):
                if cid not in known_ids:
                    out.append(f"{rel}: checks[].check_id {cid!r} не найден в required_checks "
                               f"связанной задачи {f.stem!r} — неизвестный check_id "
                               f"(v2.9.118, P0 внешнего аудита v2.9.117)")
        for cid, entries in checks_by_id.items():
            if len(entries) > 1:
                out.append(f"{rel}: checks[].check_id {cid!r} встречается {len(entries)} раз "
                           f"— должен быть уникален в пределах результата (v2.9.118)")
        # v2.9.119 (P0 внешнего аудита v2.9.118): required_for_statuses
        # удалён — каждый required_checks[] обязателен для ОБОИХ статусов
        # COMPLETED и COMPLETED_WITH_CAVEATS без исключений (раньше задача
        # могла сузить required_for_statuses до COMPLETED_WITH_CAVEATS, и
        # тогда COMPLETED с пустыми tests[]/checks[] проходил без единой
        # находки — прямо воспроизведено перед фиксом).
        unsatisfied_required: list[str] = []
        if required_checks and status in ("COMPLETED", "COMPLETED_WITH_CAVEATS"):
            for rc in required_checks:
                rc_id = rc.get("id")
                if not isinstance(rc_id, str):
                    continue
                entries = checks_by_id.get(rc_id) or []
                matching = entries[0] if len(entries) == 1 else None
                expected_codes = rc.get("expected_exit_codes") or [0]
                if (matching is None or matching.get("result") != "passed"
                        or matching.get("exit_code") not in expected_codes):
                    unsatisfied_required.append(rc_id)
        if unsatisfied_required:
            out.append(f"{rel}: status={status} требует пройденных required_checks "
                       f"{unsatisfied_required!r} связанной задачи {f.stem!r} (result=passed, "
                       f"exit_code из expected_exit_codes) — COMPLETED/COMPLETED_WITH_CAVEATS "
                       f"запрещены, пока хотя бы один required check failed/not_run/пропущен "
                       f"(используй PARTIAL/BLOCKED/FAILED). v2.9.118, P0 внешнего аудита v2.9.117 "
                       f"(репродуцировано: COMPLETED_WITH_CAVEATS с явно failed check проходил "
                       f"без единой находки).")

        if parallel_enabled and tasks_dir.is_dir() and f.stem not in task_type_by_stem:
            out.append(f"{rel}: parallel_ai_development.enabled=true требует связанной задачи "
                       f"docs/registry/agent_tasks/{f.stem}.json — результат без задачи не может "
                       f"быть отслежен (нет task_type — type-зависимые проверки, напр. для "
                       f"refactoring, были бы бесшумно пропущены)")
        if status == "COMPLETED" and data.get("unverified_claims"):
            out.append(f"{rel}: status=COMPLETED несовместим с непустым unverified_claims "
                       f"— используй status=COMPLETED_WITH_CAVEATS")
        if status == "COMPLETED" and has_failed_test:
            out.append(f"{rel}: status=COMPLETED несовместим с tests[].result=failed "
                       f"— упавший тест означает задача не завершена чисто "
                       f"(COMPLETED_WITH_CAVEATS/BLOCKED/FAILED, не COMPLETED)")
        if status in ("COMPLETED", "COMPLETED_WITH_CAVEATS") and has_failed_check:
            out.append(f"{rel}: status={status} несовместим с явно упавшей checks[] "
                       f"(result=failed) — v2.9.118 расширил проверку с COMPLETED и на "
                       f"COMPLETED_WITH_CAVEATS (P0 внешнего аудита v2.9.117, репродуцировано: "
                       f"раньше упавший check не блокировал COMPLETED_WITH_CAVEATS)")
        if status == "COMPLETED" and required_checks is None and not (has_passed_test or has_healthy_check):
            out.append(f"{rel}: status=COMPLETED требует хотя бы одного подтверждения "
                       f"— непустой tests[] с result=passed либо checks[] без ошибки; "
                       f"AI_TO_AI_COMMUNICATION_STANDARD.md §10 прямо запрещает COMPLETED "
                       f"без evidence (v2.9.111). Применяется только когда нет связанной задачи "
                       f"с required_checks — иначе строже проверяет unsatisfied_required выше "
                       f"(v2.9.118).")
        if status == "COMPLETED_WITH_CAVEATS" and not data.get("unverified_claims"):
            out.append(f"{rel}: status=COMPLETED_WITH_CAVEATS требует непустого "
                       f"unverified_claims — иначе не отличить от обычного COMPLETED, "
                       f"используй status=COMPLETED если действительно нечего оговаривать")
        if status == "COMPLETED_WITH_CAVEATS":
            # v2.9.123 (P1 внешнего аудита v2.9.122, A-3: «серьёзность оговорок
            # классифицирует сам исполнитель» — blocking_caveats был опциональным
            # подмножеством, и пустой/отсутствующий разблокировал DONE наравне с
            # непустым, независимо от того, была ли реально оценена критичность
            # каждой claim — прямое противоречие reference/SUCCESS_PATTERNS.md
            # extractor-agent-never-self-certifies). Каждый unverified_claims[]
            # теперь обязан появиться РОВНО в одном из двух мест — молчание
            # больше не эквивалентно «не блокирует».
            claims = [c for c in _as_list(data.get("unverified_claims")) if isinstance(c, str)]
            blocking_set = {c for c in _as_list(data.get("blocking_caveats")) if isinstance(c, str)}
            non_blocking_entries = [e for e in _as_list(data.get("non_blocking_caveats")) if isinstance(e, dict)]
            for j, e in enumerate(non_blocking_entries):
                for field in ("claim", "reason", "approved_by"):
                    if _is_placeholder_value(e.get(field)):
                        out.append(f"{rel}: non_blocking_caveats[{j}].{field} — плейсхолдер или "
                                   f"пусто (v2.9.123)")
            non_blocking_set = {e.get("claim") for e in non_blocking_entries
                                if isinstance(e.get("claim"), str) and not _is_placeholder_value(e.get("claim"))}
            unclassified = [c for c in claims if c not in blocking_set and c not in non_blocking_set]
            double_classified = sorted(c for c in claims if c in blocking_set and c in non_blocking_set)
            if unclassified:
                out.append(f"{rel}: unverified_claims содержит неклассифицированные оговорки "
                           f"{unclassified!r} — каждая обязана попасть либо в blocking_caveats[], "
                           f"либо в non_blocking_caveats[] (с reason/approved_by); молчание больше "
                           f"не значит «не блокирует» (v2.9.123, P1 внешнего аудита v2.9.122, A-3)")
            if double_classified:
                out.append(f"{rel}: {double_classified!r} одновременно в blocking_caveats[] и "
                           f"non_blocking_caveats[] — ровно одна классификация на оговорку (v2.9.123)")
            unknown_blocking = sorted(c for c in blocking_set if c not in claims)
            if unknown_blocking:
                out.append(f"{rel}: blocking_caveats ссылается на {unknown_blocking!r}, чего нет в "
                           f"unverified_claims — blocking_caveats обязан быть его подмножеством "
                           f"(v2.9.123)")
            unknown_non_blocking = sorted(non_blocking_set - set(claims))
            if unknown_non_blocking:
                out.append(f"{rel}: non_blocking_caveats ссылается на claim {unknown_non_blocking!r}, "
                           f"чего нет в unverified_claims (v2.9.123)")
        blocked_reason = data.get("blocked_reason")
        if status in ("BLOCKED", "FAILED") and (not blocked_reason or _is_placeholder_value(blocked_reason)):
            out.append(f"{rel}: status={status} требует непустого содержательного blocked_reason "
                       f"(не плейсхолдер и не пробел, v2.9.111)")
        limitations = data.get("limitations")
        if status == "PARTIAL" and not limitations:
            out.append(f"{rel}: status=PARTIAL требует непустого limitations "
                       f"— остаток scope обязан быть перечислен явно (v2.9.110)")
        for i, item in enumerate(limitations or []):
            if _is_placeholder_value(item):
                out.append(f"{rel}: limitations[{i}] — плейсхолдер или пусто (v2.9.111)")
        task_type = task_type_by_stem.get(f.stem)
        if task_type == "refactoring":
            behavior_baseline = data.get("behavior_baseline")
            if not isinstance(behavior_baseline, str) or _is_placeholder_value(behavior_baseline):
                out.append(f"{rel}: связанная задача {f.stem!r} — task_type=refactoring, "
                           f"требует непустой behavior_baseline (REFACTORING_SAFETY_STANDARD.md §7)")
            tests_before = data.get("tests_before")
            if not isinstance(tests_before, list) or not tests_before:
                out.append(f"{rel}: связанная задача {f.stem!r} — task_type=refactoring, "
                           f"требует непустой tests_before (REFACTORING_SAFETY_STANDARD.md §7)")
            else:
                for i, item in enumerate(tests_before):
                    if _is_placeholder_value(item):
                        out.append(f"{rel}: tests_before[{i}] — плейсхолдер или пусто")
            structural_changes = data.get("structural_changes")
            if not isinstance(structural_changes, list) or not structural_changes:
                out.append(f"{rel}: связанная задача {f.stem!r} — task_type=refactoring, "
                           f"требует непустой structural_changes (REFACTORING_SAFETY_STANDARD.md §7)")
            else:
                for i, item in enumerate(structural_changes):
                    if _is_placeholder_value(item):
                        out.append(f"{rel}: structural_changes[{i}] — плейсхолдер или пусто")
            public_contract_changed = data.get("public_contract_changed")
            if not isinstance(public_contract_changed, bool):
                out.append(f"{rel}: связанная задача {f.stem!r} — task_type=refactoring, "
                           f"требует явного boolean public_contract_changed (true/false, не "
                           f"отсутствие поля) — иначе не отличить «контракт проверен и не "
                           f"менялся» от «агент не сообщил о нём»")
            if status in ("COMPLETED", "COMPLETED_WITH_CAVEATS") and public_contract_changed is True:
                out.append(f"{rel}: status={status} запрещён при public_contract_changed=true "
                           f"для task_type=refactoring — либо задача неверно классифицирована, "
                           f"либо работа выходит за рамки чистого рефакторинга "
                           f"(REFACTORING_SAFETY_STANDARD.md §5, §7)")
    return out


# --- agent_task_contracts: машинный контракт задачи AI -> AI (v2.9.111) ----
def _registry_ids_from_data(data: object) -> set[str]:
    if not isinstance(data, dict) or not isinstance(data.get("checks"), list):
        return set()
    return {c["id"] for c in data["checks"] if isinstance(c, dict) and isinstance(c.get("id"), str)}


def check_check_registry(root: Path, schemas_root_arg: str | None,
                         base_ref: str | None = None) -> list[str]:
    """--check-check-registry, docs/registry/check_registry.json (опционален,
    v2.9.122, P1 внешнего аудита v2.9.121 §9 — третий цикл подряд с новыми
    argv-обходами blocklist-эвристики: env -u/timeout --signal/chrt/ionice/
    doas/bare xargs — решено прекратить бесконечно расширять список и
    построить доверенный реестр): agent_task_contract.required_checks[]
    может ссылаться на check_ref сюда ВМЕСТО свободного argv — task
    contract выбирает УЖЕ утверждённую команду, не изобретает новую на
    лету. Каждая запись здесь ВСЁ РАВНО проходит ту же argv-эвристику
    (_check_argv_safety — shell-метасимволы + interpreter+inline-flag,
    после разворачивания wrapper-команд), но теперь ОДИН раз для
    утверждённого набора, а не бесконечно для любого argv, который решит
    написать любой task contract. Директория опциональна целиком — слой
    не enforced по умолчанию, тот же opt-in принцип, что и везде в этом
    файле."""
    out: list[str] = []
    data = _load_registry_json(root, "check_registry.json", "check_registry.schema.json",
                               schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    checks = data.get("checks")
    if not isinstance(checks, list):
        return out
    seen_ids: set[str] = set()
    for i, c in enumerate(checks):
        if not isinstance(c, dict):
            continue
        cid = c.get("id")
        tag = f"check_registry.json.checks[{i}]" + (f" ({cid})" if isinstance(cid, str) and cid else "")
        if isinstance(cid, str) and cid:
            if cid in seen_ids:
                out.append(f"{tag}: дублирующийся id — check_ref ссылается на него "
                           f"однозначно")
            seen_ids.add(cid)
        for field in ("description", "approved_by"):
            if _is_placeholder_value(c.get(field)):
                out.append(f"{tag}: {field} — плейсхолдер или пусто")
        _check_argv_safety(c.get("argv"), c.get("cwd"), root, tag, out)
    # v2.9.123 (P2 внешнего аудита v2.9.122, A-9, репродуцировано: запись с
    # approved_by="agent/wp-a (сам себя)" проходила — проверяется только
    # "не плейсхолдер", не то, что запись реально прошла ревью где-то вне
    # проверяемой ветки). Тот же base-lock, что уже применён к allowed_paths/
    # branch/parallel_ai_development.enabled (v2.9.121/122): implementation-
    # ветка не может добавить СЕБЕ новую запись (или подменить argv/
    # approved_by уже существующей) и тут же на неё сослаться через
    # check_ref — обе стороны сверяются по id, новая/изменённая запись без
    # версии на --base-ref обязана быть добавлена governance-коммитом на
    # базовой ветке, не той же веткой, что её использует.
    if base_ref:
        resolved_ref, _ = _resolve_merge_base(root, base_ref)
        base_data, base_err = _read_json_at_git_ref(root, resolved_ref, "docs/registry/check_registry.json")
        # v2.9.123: намеренно СТРОЖЕ, чем «нет версии на base_ref — live
        # авторитетен» (тот принцип уже применялся к active_work_packages.json
        # ДО v2.9.122 и был осознанно развёрнут владельцем именно потому, что
        # ветка может объявить что угодно «совсем новым» — см. A-2/bootstrap
        # trust reversal в этом же цикле). Реестр проверок целиком, впервые
        # заведённый в проверяемой ветке, — тот же паттерн self-authorization,
        # что и bootstrap новой аренды: запись обязана появиться governance-
        # коммитом на базовой ветке ДО того, как на неё сошлётся check_ref,
        # даже если это значит завести файл в отдельном, более раннем коммите.
        if not base_err:
            base_by_id = {c["id"]: c for c in (base_data.get("checks") if isinstance(base_data, dict) else []) or []
                          if isinstance(c, dict) and isinstance(c.get("id"), str)} if base_data is not None else {}
            for c in checks:
                if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not c["id"]:
                    continue
                cid = c["id"]
                base_entry = base_by_id.get(cid)
                if base_entry is None:
                    out.append(f"check_registry.json.checks[{cid}]: записи не существовало на "
                               f"{resolved_ref} — новая запись обязана появиться governance-"
                               f"коммитом на базовой ветке, не той же веткой, что на неё "
                               f"ссылается через check_ref (v2.9.123, P2 внешнего аудита v2.9.122)")
                elif base_entry != c:
                    out.append(f"check_registry.json.checks[{cid}]: содержимое изменилось "
                               f"ВНУТРИ проверяемой ветки относительно {resolved_ref} — argv/"
                               f"approved_by/description доверенной записи не могут быть тихо "
                               f"подменены той же веткой, что на неё ссылается (v2.9.123)")
    return out


def _check_registry_ids(root: Path) -> set[str] | None:
    """id -> задан в check_registry.json.checks[] — None означает "реестра
    нет вообще" (нечего сверять), не "id не существует". Используется
    check_agent_task_contracts() для проверки required_checks[].check_ref."""
    path = root / "docs" / "registry" / "check_registry.json"
    if not path.exists():
        return None
    data, err = load_json(path)
    if err or not isinstance(data, dict) or not isinstance(data.get("checks"), list):
        return set()
    return {c["id"] for c in data["checks"] if isinstance(c, dict) and isinstance(c.get("id"), str)}


def _check_registry_ids_trusted(root: Path, base_ref: str | None) -> set[str] | None:
    """v2.9.123 (P2 внешнего аудита v2.9.122, A-9): check_ref обязан
    резолвиться против БАЗОВОЙ версии check_registry.json, когда она
    доступна — тот же base-lock, что уже применён к allowed_paths/branch/
    parallel_ai_development.enabled (v2.9.121/122): implementation-ветка
    не может добавить себе новую запись и тут же сослаться на неё через
    check_ref в этом же коммите. Нет --base-ref, файл не резолвится на нём
    или задача (реестр) только что создана в этой же ветке — используется
    live (тот же принцип «у совсем новой сущности другого источника
    истины нет», уже применённый к active_work_packages.json в
    check_active_task_diff())."""
    live_ids = _check_registry_ids(root)
    if not base_ref:
        return live_ids
    resolved_ref, _ = _resolve_merge_base(root, base_ref)
    base_data, base_err = _read_json_at_git_ref(root, resolved_ref, "docs/registry/check_registry.json")
    if base_err or base_data is None:
        return live_ids
    return _registry_ids_from_data(base_data)


# --- verification gauntlet + tool governance (v2.9.140) -----------------
_UNBOUNDED_TOOL_REFS = {"latest", "*", "main", "master", "head", "unbounded"}
_VERIFICATION_REQUIRED = {
    "FAST": {"unit_tests", "regression_tests", "static_checks", "diff_scope", "standard_ci"},
    "ASSURED": {
        "unit_tests", "regression_tests", "static_checks", "diff_scope", "standard_ci",
        "acceptance_tests", "integration_tests", "coverage", "complexity", "duplication",
        "architecture_review", "independent_review", "mutation",
    },
    "CRITICAL": {
        "unit_tests", "regression_tests", "static_checks", "diff_scope", "standard_ci",
        "acceptance_tests", "integration_tests", "coverage", "complexity", "duplication",
        "architecture_review", "independent_review", "mutation", "property_tests",
        "acceptance_mutation", "user_facing_qa", "security_review", "failure_injection",
        "performance_checks",
    },
}
_INDEPENDENT_VERIFICATION_LAYERS = {"independent_review", "user_facing_qa", "security_review"}


def _registry_objects(root: Path, name: str, key: str) -> list[dict[str, Any]]:
    path = root / "docs" / "registry" / name
    if not path.exists():
        return []
    data, err = load_json(path)
    if err or not isinstance(data, dict) or not isinstance(data.get(key), list):
        return []
    return [item for item in data[key] if isinstance(item, dict)]


def _registry_by_id(root: Path, name: str, key: str) -> dict[str, dict[str, Any]]:
    return {
        item["id"]: item
        for item in _registry_objects(root, name, key)
        if isinstance(item.get("id"), str) and item["id"]
    }


@enforces_rule("APS-TOOL-DISCOVERY-PINNING-001")
@emits_diagnostic("APS-TOOL-DISCOVERY-PINNING-001", "TOOL_CANDIDATE_DUPLICATE_ID")
@emits_diagnostic("APS-TOOL-DISCOVERY-PINNING-001", "TOOL_CANDIDATE_VERSION_UNPINNED")
@emits_diagnostic("APS-TOOL-DISCOVERY-PINNING-001", "TOOL_CANDIDATE_PILOT_EVIDENCE_MISSING")
def check_tool_candidates(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Проверяет, что обнаружение инструмента не превращается в latest-install.

    Реестр опционален. Запись со статусом EVALUATED обязана ссылаться на
    фактические материалы пилота, а версия и commit фиксируются до оценки.
    """
    out: list[str] = []
    data = _load_registry_json(
        root, "tool_candidates.json", "tool_candidates.schema.json", schemas_root_arg, out
    )
    if not isinstance(data, dict) or not isinstance(data.get("candidates"), list):
        return out
    seen: set[str] = set()
    for index, item in enumerate(data["candidates"]):
        if not isinstance(item, dict):
            continue
        tag = f"tool_candidates.json.candidates[{index}]"
        candidate_id = item.get("id")
        if isinstance(candidate_id, str):
            if candidate_id in seen:
                out.append(f"TOOL_CANDIDATE_DUPLICATE_ID:{tag}: дублирующийся id {candidate_id!r}")
            seen.add(candidate_id)
        version = str(item.get("discovered_version", "")).strip().lower()
        commit = str(item.get("discovered_commit", "")).strip().lower()
        if version in _UNBOUNDED_TOOL_REFS or commit in _UNBOUNDED_TOOL_REFS or (
            commit and set(commit) == {"0"}
        ):
            out.append(
                f"TOOL_CANDIDATE_VERSION_UNPINNED:{tag}: версия и commit должны быть "
                "закреплены; latest/main/нулевой commit запрещены"
            )
        evidence = item.get("evidence")
        if item.get("status") == "EVALUATED" and (
            not isinstance(evidence, list) or not evidence or any(_is_placeholder_value(x) for x in evidence)
        ):
            out.append(
                f"TOOL_CANDIDATE_PILOT_EVIDENCE_MISSING:{tag}: EVALUATED требует "
                "ссылку на материалы реального пилота"
            )
    return out


def _approved_tool_security_reviews(root: Path) -> dict[str, dict[str, Any]]:
    return {
        item["name"]: item
        for item in _registry_objects(root, "tooling_security_reviews.json", "reviews")
        if isinstance(item.get("name"), str) and item["name"]
    }


@enforces_rule("APS-APPROVED-TOOL-REGISTRY-001")
@emits_diagnostic("APS-APPROVED-TOOL-REGISTRY-001", "APPROVED_TOOL_DUPLICATE_ID")
@emits_diagnostic("APS-APPROVED-TOOL-REGISTRY-001", "APPROVED_TOOL_VERSION_UNPINNED")
@emits_diagnostic("APS-APPROVED-TOOL-REGISTRY-001", "APPROVED_TOOL_SECURITY_REVIEW_MISSING")
@emits_diagnostic("APS-APPROVED-TOOL-REGISTRY-001", "APPROVED_TOOL_SECURITY_REVIEW_REJECTED")
@emits_diagnostic("APS-APPROVED-TOOL-REGISTRY-001", "APPROVED_TOOL_BINARY_HASH_MISSING")
@emits_diagnostic("APS-APPROVED-TOOL-REGISTRY-001", "APPROVED_TOOL_SELF_AUTHORIZATION")
def check_approved_tools(
    root: Path, schemas_root_arg: str | None, base_ref: str | None = None
) -> list[str]:
    """Проверяет закрепление, ИБ-решение и независимое утверждение tools."""
    out: list[str] = []
    data = _load_registry_json(
        root, "approved_tools.json", "approved_tools.schema.json", schemas_root_arg, out
    )
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        return out
    reviews = _approved_tool_security_reviews(root)
    seen: set[str] = set()
    live_by_id: dict[str, dict[str, Any]] = {}
    for index, tool in enumerate(data["tools"]):
        if not isinstance(tool, dict):
            continue
        tag = f"approved_tools.json.tools[{index}]"
        tool_id = tool.get("id")
        if isinstance(tool_id, str):
            if tool_id in seen:
                out.append(f"APPROVED_TOOL_DUPLICATE_ID:{tag}: дублирующийся id {tool_id!r}")
            seen.add(tool_id)
            live_by_id[tool_id] = tool
        version = str(tool.get("version", "")).strip().lower()
        commit = str(tool.get("commit", "")).strip().lower()
        if version in _UNBOUNDED_TOOL_REFS or commit in _UNBOUNDED_TOOL_REFS or (
            commit and set(commit) == {"0"}
        ):
            out.append(
                f"APPROVED_TOOL_VERSION_UNPINNED:{tag}: version/commit не закреплены"
            )
        review_ref = tool.get("security_review")
        review = reviews.get(review_ref) if isinstance(review_ref, str) else None
        if review is None:
            out.append(
                f"APPROVED_TOOL_SECURITY_REVIEW_MISSING:{tag}: security_review "
                "не найден в tooling_security_reviews.json"
            )
        elif review.get("decision") not in {"approved", "approved_with_waiver"}:
            out.append(
                f"APPROVED_TOOL_SECURITY_REVIEW_REJECTED:{tag}: ИБ-проверка "
                f"{review_ref!r} имеет decision={review.get('decision')!r}"
            )
        installation = tool.get("installation") if isinstance(tool.get("installation"), dict) else {}
        hashes = installation.get("hashes")
        if installation.get("method") in {"binary", "download"} and (
            not isinstance(hashes, list) or not hashes
        ):
            out.append(
                f"APPROVED_TOOL_BINARY_HASH_MISSING:{tag}: downloaded binary требует checksum/hash"
            )
        if _is_placeholder_value(tool.get("approved_by")):
            out.append(
                f"APPROVED_TOOL_SELF_AUTHORIZATION:{tag}: approved_by не может быть пустым "
                "или плейсхолдером"
            )

    if base_ref:
        resolved_ref, _ = _resolve_merge_base(root, base_ref)
        base_data, base_err = _read_json_at_git_ref(
            root, resolved_ref, "docs/registry/approved_tools.json"
        )
        if not base_err and isinstance(base_data, dict):
            base_by_id = {
                item["id"]: item
                for item in base_data.get("tools", [])
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            }
            for tool_id, tool in live_by_id.items():
                if base_by_id.get(tool_id) != tool:
                    out.append(
                        f"APPROVED_TOOL_SELF_AUTHORIZATION:approved_tools.json.tools[{tool_id}]: "
                        f"запись отсутствует или отличается на trusted base {resolved_ref}; "
                        "утверждение инструмента выполняется отдельным governance-изменением"
                    )
    return out


def _load_verification_evidence(
    path: Path, root: Path, schemas_root_arg: str | None, out: list[str]
) -> dict[str, Any] | None:
    label = str(path.relative_to(root))
    data, err = load_json(path)
    if err or not isinstance(data, dict):
        out.append(f"VERIFICATION_EVIDENCE_INVALID:{label}: битый JSON: {err or 'ожидался object'}")
        return None
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    schema_path = schemas_root / "verification_evidence.schema.json" if schemas_root else None
    if not schema_path or not schema_path.exists():
        out.append(f"VERIFICATION_EVIDENCE_INVALID:{label}: не найдена схема verification_evidence.schema.json")
        return data
    schema, schema_err = load_json(schema_path)
    if schema_err or not isinstance(schema, dict):
        out.append(f"VERIFICATION_EVIDENCE_INVALID:{label}: битая схема: {schema_err}")
        return data
    out.extend(validate_schema(data, schema, label))
    return data


def _artifact_reference_is_local_and_present(root: Path, value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    path = Path(value)
    if path.is_absolute() or ".." in path.parts:
        return False
    return (root / path).is_file()


@enforces_rule("APS-VERIFICATION-EVIDENCE-001")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_REQUIRED")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_INVALID")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_REFERENCE_UNKNOWN")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_TOOL_VERSION_MISMATCH")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_ARTIFACT_MISSING")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_INDEPENDENCE_REQUIRED")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_SELF_APPROVAL")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_LAYER_MISSING")
@emits_diagnostic("APS-VERIFICATION-EVIDENCE-001", "VERIFICATION_EVIDENCE_RESULT_MISMATCH")
def check_verification_evidence(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Связывает профиль задачи с checks, pinned tools, artifacts и result."""
    out: list[str] = []
    tasks_dir = root / "docs" / "registry" / "agent_tasks"
    if not tasks_dir.is_dir():
        return out
    evidence_dir = root / "docs" / "registry" / "verification_evidence"
    approved_tools = _registry_by_id(root, "approved_tools.json", "tools")
    checks = _registry_by_id(root, "check_registry.json", "checks")
    for task_path in sorted(tasks_dir.glob("*.json")):
        task, task_err = load_json(task_path)
        if task_err or not isinstance(task, dict):
            continue
        profile = task.get("verification_profile")
        if profile not in _VERIFICATION_REQUIRED:
            continue
        task_id = task.get("task_id")
        if not isinstance(task_id, str) or not task_id:
            continue
        evidence_path = evidence_dir / f"{task_id}.json"
        if not evidence_path.is_file():
            out.append(
                f"VERIFICATION_EVIDENCE_REQUIRED:{task_id}: профиль {profile} требует "
                f"docs/registry/verification_evidence/{task_id}.json"
            )
            continue
        label = str(evidence_path.relative_to(root))
        evidence = _load_verification_evidence(evidence_path, root, schemas_root_arg, out)
        if not isinstance(evidence, dict):
            continue
        if evidence.get("task_id") != task_id or evidence.get("verification_profile") != profile:
            out.append(
                f"VERIFICATION_EVIDENCE_INVALID:{label}: task_id/profile не совпадают "
                "с agent task contract"
            )
        passed_layers: set[str] = set()
        for index, entry in enumerate(evidence.get("entries") or []):
            if not isinstance(entry, dict):
                continue
            tag = f"{label}.entries[{index}]"
            layer = entry.get("layer")
            if isinstance(layer, str) and layer in passed_layers:
                out.append(f"VERIFICATION_EVIDENCE_INVALID:{tag}: дублирующийся layer {layer!r}")
            check = checks.get(entry.get("check_ref"))
            tool = approved_tools.get(entry.get("tool_ref"))
            if check is None or tool is None:
                out.append(
                    f"VERIFICATION_EVIDENCE_REFERENCE_UNKNOWN:{tag}: check_ref/tool_ref "
                    "не найдены в доверенных реестрах"
                )
            else:
                if entry.get("tool_version") != tool.get("version"):
                    out.append(
                        f"VERIFICATION_EVIDENCE_TOOL_VERSION_MISMATCH:{tag}: tool_version "
                        "не совпадает с approved_tools.json"
                    )
                if profile not in (tool.get("supported_profiles") or []):
                    out.append(
                        f"VERIFICATION_EVIDENCE_REFERENCE_UNKNOWN:{tag}: инструмент не "
                        f"утверждён для профиля {profile}"
                    )
                if check.get("tool_ref") and check.get("tool_ref") != entry.get("tool_ref"):
                    out.append(
                        f"VERIFICATION_EVIDENCE_REFERENCE_UNKNOWN:{tag}: check_ref связан "
                        "с другим tool_ref"
                    )
                expected_exit_codes = check.get("expected_exit_codes") or [0]
                if entry.get("result") == "passed" and entry.get("exit_code") not in expected_exit_codes:
                    out.append(
                        f"VERIFICATION_EVIDENCE_INVALID:{tag}: passed с недопустимым exit_code"
                    )
            if entry.get("result") == "passed" and isinstance(layer, str):
                passed_layers.add(layer)
            if not _artifact_reference_is_local_and_present(root, entry.get("artifact")):
                out.append(
                    f"VERIFICATION_EVIDENCE_ARTIFACT_MISSING:{tag}: artifact отсутствует "
                    "внутри проекта или выходит за его границы"
                )
            if layer in _INDEPENDENT_VERIFICATION_LAYERS:
                produced_by = entry.get("produced_by")
                reviewed_by = entry.get("reviewed_by")
                if (
                    _is_placeholder_value(reviewed_by)
                    or reviewed_by == produced_by
                ):
                    out.append(
                        f"VERIFICATION_EVIDENCE_INDEPENDENCE_REQUIRED:{tag}: слой {layer} "
                        "требует независимого reviewed_by"
                    )
        exempt_layers: set[str] = set()
        for index, exemption in enumerate(evidence.get("exemptions") or []):
            if not isinstance(exemption, dict):
                continue
            if exemption.get("requested_by") == exemption.get("approved_by") or any(
                _is_placeholder_value(exemption.get(field))
                for field in ("reason", "requested_by", "approved_by")
            ):
                out.append(
                    f"VERIFICATION_EVIDENCE_SELF_APPROVAL:{label}.exemptions[{index}]: "
                    "self-approval и плейсхолдеры запрещены"
                )
            elif isinstance(exemption.get("layer"), str):
                exempt_layers.add(exemption["layer"])
        missing_layers = _VERIFICATION_REQUIRED[profile] - passed_layers - exempt_layers
        if missing_layers:
            out.append(
                f"VERIFICATION_EVIDENCE_LAYER_MISSING:{label}: для {profile} отсутствуют "
                f"обязательные слои {sorted(missing_layers)!r}"
            )
        result_path = root / "docs" / "registry" / "agent_results" / f"{task_id}.json"
        if result_path.is_file():
            result, _ = load_json(result_path)
            if isinstance(result, dict):
                commit_candidates = {result.get("commit"), result.get("implementation_commit")}
                commit_candidates.discard(None)
                if (
                    result.get("verification_profile") != profile
                    or result.get("verification_evidence_ref") != label
                    or (commit_candidates and evidence.get("commit") not in commit_candidates)
                ):
                    out.append(
                        f"VERIFICATION_EVIDENCE_RESULT_MISMATCH:{result_path.relative_to(root)}: "
                        "profile/evidence_ref/commit не согласованы с verification evidence"
                    )
    return out


# P1×3 внешнего ревью v2.9.110, репродуцировано: schemas/agent_task_contract.
# schema.json видит только синтаксис поля-за-полем, не то, что схема структурно
# не может выразить — abs/traversal путь в sources_of_truth/allowed_paths/
# forbidden_paths (тот же класс уязвимости, что уже закрыт для test_runner/
# test_coverage/user_functions/knowledge_index в v2.9.101/108, здесь не был
# подключён), allowed_paths и forbidden_paths, называющие один и тот же путь
# одновременно, пробельные/плейсхолдерные task_id/goal/sources_of_truth/
# acceptance_criteria. Директория (как и agent_results/) опциональна целиком —
# слой не enforced по умолчанию, включается флагом.
def check_agent_task_contracts(root: Path, schemas_root_arg: str | None,
                               base_ref: str | None = None) -> list[str]:
    """docs/registry/agent_tasks/*.json (опционален, v2.9.111): машинный
    контракт задачи AI -> AI — AI_TO_AI_COMMUNICATION_STANDARD.md §13.
    Директория опциональна целиком; если есть хотя бы один файл — каждый
    валидируется по схеме (schemas/agent_task_contract.schema.json,
    required[] покрывает 10 обязательных элементов из §4) + инварианты,
    которые схема сама по себе не видит: пути не выходят за пределы проекта
    (abs/traversal), allowed_paths и forbidden_paths не пересекаются,
    task_id/goal/sources_of_truth[]/acceptance_criteria[] не placeholder и
    не пробельные. Существование sources_of_truth/allowed_paths на диске
    сознательно НЕ проверяется — sources_of_truth может ссылаться на внешний
    URL/ADR, allowed_paths может называть ещё не созданный путь (задача и
    есть его создать); проверяется только то, что путь не выходит за root.

    v2.9.114 (P1 внешнего ревью v2.9.113: «машинный AI-task не связан с
    модулем»): опциональный module_id (если задан) сверяется с id из
    docs/registry/module_registry.json, когда тот реестр существует —
    остальные модульные поля (owned_data/forbidden_imports/public_api) НЕ
    дублируются в контракт задачи, читаются по этой ссылке из
    module_registry.json (см. schemas/agent_task_contract.schema.json).

    v2.9.115 (P2 внешнего ревью v2.9.114): allowed_paths/forbidden_paths
    теперь обязаны быть простой формы (_is_simple_scope_pattern). Когда
    module_id задан и резолвится, allowed_paths задачи проверяется на
    вложенность в module.root + module.related_paths (реализует «задача
    ссылается на модуль, но работает вне него» — P2 ревью v2.9.114).

    v2.9.116 (classical engineering foundations, Fowler «Refactoring»):
    task_type теперь обязателен в схеме; схема сама не умеет if/then
    (draft-07 подмножество этого валидатора), поэтому type-зависимая
    обязательность полей проверяется здесь кодом: task_type=refactoring
    требует непустых behavior_baseline и tests_before[]; task_type=
    architecture требует непустых alternatives_considered[],
    consequences[], migration_plan, verification_plan. См.
    REFACTORING_SAFETY_STANDARD.md §7."""
    out: list[str] = []
    resolved_ref, _ = _resolve_merge_base(root, base_ref) if base_ref else (None, None)
    parallel_or_autonomous = _parallel_mode_enabled_trusted(root, resolved_ref)
    profile_path = root / "docs" / "registry" / "project_profile.json"
    if profile_path.exists():
        pdata, perr = load_json(profile_path)
        if not perr and isinstance(pdata, dict) and pdata.get("autonomy_level") in {"A2", "A3", "A4"}:
            parallel_or_autonomous = True
    # v2.9.122 (P1 внешнего аудита v2.9.121 §9): check_registry.json — своя
    # внутренняя валидность (argv-безопасность, дубли id, плейсхолдеры)
    # проверяется здесь всегда, независимо от того, есть ли уже
    # agent_tasks/ — projeckt может завести реестр проверок раньше первой
    # задачи, ссылающейся на него.
    out.extend(check_check_registry(root, schemas_root_arg, base_ref))
    tasks_dir = root / "docs" / "registry" / "agent_tasks"
    if not tasks_dir.is_dir():
        return out
    modules_by_id: dict[str, dict] = {}
    mr_path = root / "docs" / "registry" / "module_registry.json"
    if mr_path.exists():
        mr_data, mr_err = load_json(mr_path)
        if not mr_err and isinstance(mr_data, dict) and isinstance(mr_data.get("modules"), list):
            modules_by_id = {m["id"]: m for m in mr_data["modules"]
                             if isinstance(m, dict) and isinstance(m.get("id"), str)}
    module_ids: set[str] | None = set(modules_by_id) if mr_path.exists() else None
    graph_depends_on = _work_package_graph_depends_on_by_id(root)
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    schema = None
    if schemas_root and (schemas_root / "agent_task_contract.schema.json").exists():
        loaded, err = load_json(schemas_root / "agent_task_contract.schema.json")
        if err:
            return [f"agent_tasks: битая схема agent_task_contract.schema.json: {err}"]
        if isinstance(loaded, dict):
            schema = loaded
    seen_task_ids: dict[str, Path] = {}
    for f in sorted(tasks_dir.glob("*.json")):
        rel = f.relative_to(root)
        data, err = load_json(f)
        if err:
            out.append(f"{rel}: битый JSON: {err}")
            continue
        if not isinstance(data, dict):
            out.append(f"{rel}: ожидался объект")
            continue
        if schema:
            out.extend(validate_schema(data, schema, str(rel)))
        for field in ("task_id", "goal"):
            if _is_placeholder_value(data.get(field)):
                out.append(f"{rel}: {field} — плейсхолдер или пусто")
        task_id = data.get("task_id")
        if isinstance(task_id, str) and task_id:
            if task_id != f.stem:
                out.append(f"{rel}: task_id {task_id!r} не совпадает с именем файла "
                           f"{f.stem!r} — agent_results/*.json связывается с задачей по имени "
                           f"файла (AI_TO_AI_COMMUNICATION_STANDARD.md §14), расхождение делает "
                           f"эту связь ненадёжной")
            if task_id in seen_task_ids:
                out.append(f"{rel}: task_id {task_id!r} дублирует {seen_task_ids[task_id]} — "
                           f"task_id обязан быть уникальным среди docs/registry/agent_tasks/*.json")
            else:
                seen_task_ids[task_id] = rel
        # v2.9.118 (P0 внешнего аудита v2.9.117: «зависимости дублируются
        # между agent_task_contract.depends_on и work_package_graph.json,
        # могут расходиться»): work_package_graph.json — единственный
        # источник истины; когда граф существует И содержит узел с этим же
        # id (по имени файла, тот же принцип связи, что и с agent_results),
        # task.depends_on обязан быть согласованным snapshot — совпадать с
        # graph.node.depends_on как множество (порядок не важен).
        if graph_depends_on is not None and f.stem in graph_depends_on:
            task_deps = {d for d in (data.get("depends_on") or []) if isinstance(d, str)}
            graph_deps = set(graph_depends_on[f.stem])
            if task_deps != graph_deps:
                missing_from_task = sorted(graph_deps - task_deps)
                extra_in_task = sorted(task_deps - graph_deps)
                detail = []
                if missing_from_task:
                    detail.append(f"есть в графе, нет в задаче: {missing_from_task!r}")
                if extra_in_task:
                    detail.append(f"есть в задаче, нет в графе: {extra_in_task!r}")
                out.append(f"{rel}: depends_on расходится с work_package_graph.json "
                           f"(узел {f.stem!r}) — {'; '.join(detail)}. Граф — единственный "
                           f"источник истины зависимостей (v2.9.118), depends_on задачи "
                           f"обязан быть согласованным snapshot")
        for field in ("sources_of_truth", "acceptance_criteria", "invariants",
                      "required_evidence"):
            for i, item in enumerate(data.get(field) or []):
                if _is_placeholder_value(item):
                    out.append(f"{rel}: {field}[{i}] — плейсхолдер или пусто")
        # v2.9.118 (P0 внешнего аудита v2.9.117, ломающее изменение): required_checks[]
        # стал массивом объектов (был массивом свободнотекстовых shell-строк) —
        # _is_placeholder_value(dict) всегда False, поэтому required_checks
        # выведен из строкового цикла выше в собственную структурную проверку.
        seen_check_ids: set[str] = set()
        # v2.9.122 (P1 внешнего аудита v2.9.121 §9): check_ref — ссылка в
        # docs/registry/check_registry.json ВМЕСТО свободного argv. None —
        # реестра нет вообще (нечего сверять), не "id не существует".
        registry_check_ids = _check_registry_ids_trusted(root, base_ref)
        for i, rc in enumerate(_as_list(data.get("required_checks"))):
            if not isinstance(rc, dict):
                continue
            rc_id = rc.get("id")
            if isinstance(rc_id, str) and rc_id:
                if rc_id in seen_check_ids:
                    out.append(f"{rel}: required_checks[{i}].id {rc_id!r} дублирует более "
                               f"раннюю запись в этой же задаче — id обязан быть уникален "
                               f"в пределах задачи (agent_result.checks[].check_id ссылается "
                               f"на него однозначно)")
                seen_check_ids.add(rc_id)
            has_argv = isinstance(rc.get("argv"), list) and bool(rc.get("argv"))
            check_ref = rc.get("check_ref")
            has_check_ref = isinstance(check_ref, str) and bool(check_ref)
            if has_argv and has_check_ref:
                out.append(f"{rel}: required_checks[{i}] задаёт И argv, И check_ref — "
                           f"ровно один из двух обязан быть задан, не оба (v2.9.122, P1 "
                           f"внешнего аудита v2.9.121 §9)")
            elif has_check_ref:
                for field in ("cwd", "timeout_seconds", "expected_exit_codes"):
                    if rc.get(field) is not None:
                        out.append(f"{rel}: required_checks[{i}].{field} задан вместе с "
                                   f"check_ref — эти поля берутся ИЗ утверждённой записи "
                                   f"check_registry.json, не переопределяются per-task "
                                   f"(v2.9.122)")
                if registry_check_ids is None:
                    out.append(f"{rel}: required_checks[{i}].check_ref={check_ref!r}, но "
                               f"docs/registry/check_registry.json не существует — сначала "
                               f"зарегистрируй проверку там (v2.9.122)")
                elif check_ref not in registry_check_ids:
                    out.append(f"{rel}: required_checks[{i}].check_ref={check_ref!r} не "
                               f"найден в docs/registry/check_registry.json.checks[].id "
                               f"(v2.9.122)")
            elif has_argv:
                if parallel_or_autonomous:
                    out.append(f"{rel}: required_checks[{i}].argv запрещён в parallel/autonomous profile — "
                               f"используй только base-approved check_ref (LEGACY_ARGV_FORBIDDEN)")
                    continue
                # v2.9.119/120/121 (P1 трёх подряд внешних аудитов, репродуцировано
                # каждый раз новыми обходами — env/timeout/nice/stdbuf/sudo/cmd.exe/
                # env -S, затем env -u/timeout --signal/chrt/ionice/doas/xargs):
                # legacy-путь, та же эвристика, что и check_registry.json.checks[]
                # (см. _check_argv_safety) — check_ref (выше) закрывает класс
                # целиком для нового кода, этот путь остаётся для обратной
                # совместимости.
                _check_argv_safety(rc.get("argv"), rc.get("cwd"), root,
                                   f"{rel}: required_checks[{i}]", out)
            else:
                out.append(f"{rel}: required_checks[{i}] не задаёт ни argv, ни check_ref — "
                           f"ровно один из двух обязан быть задан (v2.9.122, P1 внешнего "
                           f"аудита v2.9.121 §9)")
        allowed = {p for p in (data.get("allowed_paths") or []) if isinstance(p, str)}
        forbidden = {p for p in (data.get("forbidden_paths") or []) if isinstance(p, str)}
        overlap = allowed & forbidden
        if overlap:
            out.append(f"{rel}: allowed_paths и forbidden_paths одновременно называют "
                       f"{sorted(overlap)!r} — путь не может быть и разрешён, и запрещён")
        for field in ("allowed_paths", "forbidden_paths", "sources_of_truth"):
            for p in (data.get(field) or []):
                if isinstance(p, str) and _path_escapes_root(root, p):
                    out.append(f"{rel}: {field}-путь выходит за пределы проекта: {p}")
        for field in ("allowed_paths", "forbidden_paths"):
            for p in (data.get(field) or []):
                if isinstance(p, str) and p and not _path_escapes_root(root, p) \
                        and not _is_simple_scope_pattern(p):
                    out.append(f"{rel}: {field} использует неподдерживаемый glob-синтаксис "
                               f"{p!r} — поддерживаются только точный путь или dir/**")
        module_id = data.get("module_id")
        if isinstance(module_id, str) and module_id and module_ids is not None \
                and module_id not in module_ids:
            out.append(f"{rel}: module_id {module_id!r} не найден в module_registry.json")
        elif isinstance(module_id, str) and module_id and module_id in modules_by_id:
            module = modules_by_id[module_id]
            module_root = module.get("root")
            related = [p for p in (module.get("related_paths") or []) if isinstance(p, str) and p]
            scopes = ([module_root] if isinstance(module_root, str) and module_root else []) + related
            if scopes:
                for p in (data.get("allowed_paths") or []):
                    if not isinstance(p, str) or not p:
                        continue
                    if not any(_pattern_within(p, s) or p == s for s in scopes):
                        out.append(f"{rel}: allowed_paths {p!r} вне границ модуля {module_id!r} "
                                   f"(root={module_root!r}, related_paths={related!r})")
        task_type = data.get("task_type")
        if task_type == "refactoring":
            behavior_baseline = data.get("behavior_baseline")
            if not isinstance(behavior_baseline, str) or _is_placeholder_value(behavior_baseline):
                out.append(f"{rel}: task_type=refactoring требует непустой behavior_baseline "
                           f"(REFACTORING_SAFETY_STANDARD.md §2)")
            tests_before = data.get("tests_before")
            if not isinstance(tests_before, list) or not tests_before:
                out.append(f"{rel}: task_type=refactoring требует непустой tests_before "
                           f"(REFACTORING_SAFETY_STANDARD.md §2-3)")
            else:
                for i, item in enumerate(tests_before):
                    if _is_placeholder_value(item):
                        out.append(f"{rel}: tests_before[{i}] — плейсхолдер или пусто")
        elif task_type == "architecture":
            for field in ("alternatives_considered", "consequences"):
                val = data.get(field)
                if not isinstance(val, list) or not val:
                    out.append(f"{rel}: task_type=architecture требует непустой {field}")
                else:
                    for i, item in enumerate(val):
                        if _is_placeholder_value(item):
                            out.append(f"{rel}: {field}[{i}] — плейсхолдер или пусто")
            for field in ("migration_plan", "verification_plan"):
                val = data.get(field)
                if not isinstance(val, str) or _is_placeholder_value(val):
                    out.append(f"{rel}: task_type=architecture требует непустой {field}")
    return out


def check_agent_workflow_integrity(root: Path, schemas_root_arg: str | None,
                                   base_ref: str | None = None) -> list[str]:
    """Агрегатор referential integrity всей agent-workflow системы документов
    (v2.9.118, §9 внешнего аудита v2.9.117: «проверять все документы как
    единую систему, а не по отдельности»). Объединяет findings из четырёх
    уже существующих проверок (без дублей — тот же паттерн, что и
    check_best_style()):

        check_agent_task_contracts()  — docs/registry/agent_tasks/*.json
        check_agent_results()         — docs/registry/agent_results/*.json
        check_work_package_graph()    — docs/registry/work_package_graph.json
        check_work_package_overlap()  — docs/registry/active_work_packages.json

    Плюс связи, которые ни одна из них по отдельности не покрывает (все —
    hard error только при parallel_ai_development.enabled=true, §9: «для
    parallel mode отсутствие любой связи — hard error»; вне parallel-режима
    graph/lease — необязательный слой):

    1. «task существует в graph» (не только обратное — «lease существует
       только для task из graph», это уже check_work_package_overlap()).
       Как и «result существует только при наличии task» (check_agent_results).
    2. (v2.9.119, P1 внешнего аудита v2.9.118) graph.status=DONE требует
       agent_results/<id>.json с status ∈ {COMPLETED, COMPLETED_WITH_CAVEATS}
       — иначе downstream-задача может начаться на основании DONE, за
       которым нет вообще никакого результата (прямо названо аудитом:
       «граф может объявить задачу DONE без результата»).
    3. (v2.9.119, P1 внешнего аудита v2.9.118) graph.status=WIP требует ОБА:
       agent_tasks/<id>.json (иначе work-package «выполняется», а машинного
       контракта, что именно выполняется, не существует) И активную запись
       в active_work_packages.json.active[] (иначе work-package «выполняется»
       без единой аренды scope — тот же класс дыры, что уже закрыт в
       обратном направлении check_work_package_overlap()'ом в v2.9.118).
       Раньше active=[] (или просто отсутствие WIP-id среди активных
       записей) не ловилось НИГДЕ — check_work_package_overlap() итерирует
       ТОЛЬКО существующие записи active[], у него нет обратного
       направления «граф → аренда»."""
    out: list[str] = []
    out += check_agent_task_contracts(root, schemas_root_arg, base_ref)
    out += check_control_plane_integrity(root, schemas_root_arg, base_ref)
    out += check_agent_results(root, schemas_root_arg)
    out += check_work_package_graph(root, schemas_root_arg)
    out += check_work_package_overlap(root, schemas_root_arg)

    parallel_enabled = False
    profile_path = root / "docs" / "registry" / "project_profile.json"
    if profile_path.exists():
        pdata, perr = load_json(profile_path)
        if not perr and isinstance(pdata, dict):
            pad = pdata.get("parallel_ai_development")
            if isinstance(pad, dict) and pad.get("enabled") is True:
                parallel_enabled = True
    graph_ids = _work_package_graph_ids(root)
    tasks_dir = root / "docs" / "registry" / "agent_tasks"
    if parallel_enabled and graph_ids is not None and tasks_dir.is_dir():
        for tf in sorted(tasks_dir.glob("*.json")):
            tdata, terr = load_json(tf)
            if terr or not isinstance(tdata, dict):
                continue
            if tf.stem not in graph_ids:
                out.append(f"agent-workflow-integrity: docs/registry/agent_tasks/{tf.stem}.json: "
                           f"parallel_ai_development.enabled=true требует узла {tf.stem!r} в "
                           f"work_package_graph.json — задача без узла графа не отслеживается "
                           f"как часть общего плана работ (v2.9.118, §9 внешнего аудита v2.9.117)")

    if parallel_enabled:
        graph_status = _work_package_graph_status_by_id(root)
        # v2.9.120 (P1 внешнего аудита v2.9.119, репродуцировано): v2.9.119
        # трактовал ПОЛНОСТЬЮ отсутствующие agent_tasks//active_work_packages.
        # json как "нечего сверять" (None) — под parallel_ai_development.
        # enabled=true, с уже существующим WIP-узлом графа, это неверно:
        # "директория ещё не заведена" здесь неотличимо от "интеграция
        # реально сломана", а сигнал (граф уже используется) говорит, что
        # проект НЕ находится в состоянии "слой не адаптирован". Только
        # ВНУТРИ parallel_enabled — вне этого режима None остаётся None
        # (тот же opt-in принцип, что и везде в этом файле).
        task_ids = _agent_tasks_index(root) or {}
        task_ids = set(task_ids)
        lease_ids = _active_lease_task_ids(root) or set()
        results_dir = root / "docs" / "registry" / "agent_results"
        for wid, status in (graph_status or {}).items():
            # v2.9.121 (P1 внешнего аудита v2.9.120, репродуцировано: id
            # "../../outside" + status=DONE резолвил rf ВНЕ agent_results/ —
            # найден существующий docs/outside.json с {"status":
            # "COMPLETED"}, DONE считался подтверждённым. check_work_
            # package_graph() уже ловит это статически (если запущен), но
            # --check-agent-workflow-integrity — отдельный флаг, может быть
            # вызван без него — защита нужна на самом месте построения пути,
            # не только там, где id впервые встречается.
            if not _SAFE_REGISTRY_ID_RE.match(wid):
                out.append(f"agent-workflow-integrity: work_package_graph.json узел {wid!r} "
                           f"использует небезопасный id — разрешены только буквы/цифры/./_/- "
                           f"(id участвует в построении пути agent_results/<id>.json)")
                continue
            if status == "DONE":
                rf = results_dir / f"{wid}.json"
                rdata, rerr = load_json(rf) if rf.exists() else (None, None)
                r_status = rdata.get("status") if isinstance(rdata, dict) else None
                if not rf.exists():
                    out.append(f"agent-workflow-integrity: work_package_graph.json узел {wid!r} "
                               f"имеет status=DONE, но docs/registry/agent_results/{wid}.json "
                               f"не существует — DONE без единого результата (v2.9.119, P1 "
                               f"внешнего аудита v2.9.118: «граф может объявить задачу DONE без "
                               f"результата»)")
                elif rerr or r_status not in ("COMPLETED", "COMPLETED_WITH_CAVEATS"):
                    out.append(f"agent-workflow-integrity: work_package_graph.json узел {wid!r} "
                               f"имеет status=DONE, но agent_results/{wid}.json.status="
                               f"{r_status!r} — DONE обязан соответствовать успешному результату "
                               f"(COMPLETED/COMPLETED_WITH_CAVEATS), не {r_status!r} (v2.9.119, "
                               f"P1 внешнего аудита v2.9.118)")
                elif r_status == "COMPLETED_WITH_CAVEATS":
                    # v2.9.121 (P1 внешнего аудита v2.9.120, третий раз подряд
                    # — дважды осознанно отложено как «не в объёме цикла»,
                    # см. CHANGELOG v2.9.120/v2.9.119): COMPLETED_WITH_CAVEATS
                    # раньше разблокировал DONE наравне с COMPLETED
                    # независимо от серьёзности unverified_claims — «не
                    # проверен опциональный бенчмарк» и «не проверена
                    # совместимость публичного API» блокировались одинаково
                    # (никак). blocking_caveats — опциональное подмножество,
                    # непустое значение которого явно останавливает DONE.
                    blocking = [c for c in _as_list(rdata.get("blocking_caveats"))
                               if isinstance(c, str) and c.strip()]
                    if blocking:
                        out.append(f"agent-workflow-integrity: work_package_graph.json узел "
                                   f"{wid!r} имеет status=DONE, но agent_results/{wid}.json."
                                   f"blocking_caveats не пуст {blocking!r} — DONE заблокирован "
                                   f"явно помеченными блокирующими оговорками (v2.9.121, P1 "
                                   f"внешнего аудита v2.9.120)")
                # v2.9.120 (внешний аудит v2.9.119 §8): DONE НЕ требует
                # agent_tasks/<id>.json — AI_TO_AI_COMMUNICATION_STANDARD.md
                # §14 уже документирует обратное как легитимное («результат
                # без файла контракта — не каждая задача обязана иметь
                # формальный JSON-контракт, особенно для задач, поставленных
                # человеком через WORK_PACKAGE_TEMPLATE.md»); аудит это
                # предложение прямо противоречит уже принятому решению —
                # осознанно не реализовано.
            elif status == "WIP":
                if wid not in task_ids:
                    out.append(f"agent-workflow-integrity: work_package_graph.json узел {wid!r} "
                               f"имеет status=WIP, но docs/registry/agent_tasks/{wid}.json не "
                               f"существует — WIP без машинного task contract (v2.9.119/120, P1 "
                               f"внешнего аудита v2.9.118/119: «WIP допускается без task contract», "
                               f"включая случай, когда agent_tasks/ отсутствует целиком)")
                if wid not in lease_ids:
                    out.append(f"agent-workflow-integrity: work_package_graph.json узел {wid!r} "
                               f"имеет status=WIP, но active_work_packages.json.active[] не "
                               f"содержит {wid!r} — WIP без активной аренды scope (v2.9.119/120, "
                               f"P1 внешнего аудита v2.9.118/119: обратное направление «граф → "
                               f"аренда», включая случай, когда active_work_packages.json "
                               f"отсутствует целиком)")

    seen: set[str] = set()
    deduped: list[str] = []
    for p in out:
        if p not in seen:
            seen.add(p)
            deduped.append(p)
    return deduped


def _known_validator_flags(root: Path, validator_path: str) -> set[str] | None:
    """v2.9.118 (§11.1 внешнего аудита v2.9.117): реально зарегистрированные
    --флаги в исходнике validator_path (обычно tools/validate_structure.py
    этого же пакета) — извлекается regex'ом по add_argument("--флаг" ...),
    не хардкодится отдельным списком (иначе список сам стал бы источником
    рассинхронизации при добавлении новых --check-* флагов). None — файл
    не существует/не читается (существование path — уже отдельная находка
    выше по стеку в check_classical_engineering_foundations())."""
    full = root / validator_path
    if not full.is_file():
        return None
    try:
        text = full.read_text(encoding="utf-8")
    except OSError:
        return None
    return set(re.findall(r'add_argument\("(--[a-z][a-z0-9-]*)"', text))


_BENCHMARK_SELECTION_SECTIONS = [
    ("критерии", "критери"), ("кандидаты", "кандидат"),
    ("причины выбора", "причин"), ("контрпримеры", "контрпример"),
]


def check_classical_engineering_foundations(root: Path, schemas_root_arg: str | None) -> list[str]:
    """reference/classical_engineering_foundations.json (опционален, v2.9.116):
    машинная сторона матрицы трассировки reference/CLASSICAL_ENGINEERING_
    FOUNDATIONS.md — принцип классической программной инженерии (Code
    Complete, Design Patterns, Clean Architecture, Clean Code, Refactoring)
    → классификация → где реализован → AI-адаптация → enforcement.

    Файл package-self-referential: описывает принципы САМОГО стандарта, не
    проекта-потребителя, поэтому живёт в reference/, не в docs/registry/, и
    для произвольного целевого проекта (--root указывает не на этот пакет)
    просто отсутствует — тот же opt-in, что и весь остальной реестровый слой.

    Схема (`classical_engineering_foundations.schema.json`) покрывает
    структуру поля-за-полем (обязательные поля, enum classification, non-empty
    principle). Здесь — то, что схема сама не видит: дубли id (schema не
    умеет uniqueness по вложенному полю) и implemented_in[], указывающий на
    несуществующий на диске путь (тот же принцип path-эскейпа, что уже
    применён к sources_of_truth/allowed_paths в check_agent_task_contracts).

    v2.9.117 (P1 внешнего ревью v2.9.116, репродуцировано — «машинная карта
    классических принципов допускает фиктивную полноту»): schema.json уже
    ОПИСЫВАЛА эти инварианты в description-полях («Пусто/отсутствует
    допустимо только для classification=NOT_ADOPTED»), но код их не
    проверял вовсе. Теперь: status=ADOPTED требует непустых, не-placeholder
    ai_adaptation и enforced_by[] (minLength:1 в схеме не режет пробельные
    значения — тот же класс дыры, что уже закрыт в v2.9.111 через
    _is_placeholder_value()); status=NOT_ADOPTED требует classification=
    NOT_ADOPTED и наоборот (иначе противоречие — принцип одновременно
    FOUNDATIONAL и сознательно не принят); source/principle не может быть
    пробельной строкой (та же minLength-дыра).

    v2.9.118 (§11.1 внешнего аудита v2.9.117): enforced_by[] — типизированные
    объекты {kind, path?, check?, note?} вместо свободнотекстовых строк
    (kind ∈ validator_flag/schema/test/ci_workflow/review_only — см. схему).
    Для validator_flag/schema/test/ci_workflow path обязателен и обязан
    существовать на диске; для review_only — опционален, но если задан —
    тоже проверяется. kind=validator_flag дополнительно требует check
    (--флаг) и сверяет его с РЕАЛЬНО зарегистрированными флагами в исходнике
    по path (regex по add_argument(...), не хардкод — см.
    _known_validator_flags()), не просто синтаксис «похоже на флаг».
    fully_enforced=true не может опираться исключительно на review_only
    (или пустой enforced_by) — требует хотя бы одну запись другого kind.

    v2.9.117 (P1 внешнего ревью v2.9.116, отдельная находка — «почти нет
    конкретных современных GitHub evidence, только цитаты книг»): status=
    ADOPTED теперь также требует непустой modern_evidence[] (реальные
    современные open-source примеры, не восстановленные по памяти — см.
    schemas/classical_engineering_foundations.schema.json), с проверкой
    project/mechanism на placeholder тем же _is_placeholder_value().

    v2.9.118 (§11.2 внешнего аудита v2.9.117): modern_evidence[] богаче —
    repository/commit/path/evidence_level/verified_at/content_hash. commit-
    format, hash-format и допустимый evidence_level — схема (pattern/enum).
    Здесь — то, что схема НЕ видит: СОГЛАСОВАННОСТЬ заявленного evidence_
    level с фактически заполненными repository/commit (E1 требует оба, E2
    требует repository) — иначе можно заявить E1, не имея реального
    commit-пиннинга. Проверяется только направление «заявлено сильнее, чем
    структура подтверждает» — обратное (занижен уровень при более полных
    данных) не флагуется, чтобы не быть избыточно строгим.

    v2.9.118 (§11.3 внешнего аудита v2.9.117: «не путать examples и
    best-in-class»): modern_evidence[].example_status (MODERN_EXAMPLE/
    STRONG_IMPLEMENTATION/BENCHMARK_CANDIDATE/BEST_IN_CLASS_CONFIRMED) —
    возрастающая по строгости заявка, enum схемой. Только BEST_IN_CLASS_
    CONFIRMED проверяется кодом: требует evidence_level=E1 (commit-pinned)
    И существования reference/BENCHMARK_SELECTION.md, содержащего все 4
    обязательных раздела (критерии/кандидаты/причины выбора/контрпримеры —
    эвристический поиск подстроки-основы слова, не точный формат заголовка).
    В этом реестре пока НИ ОДНА запись не заявляет BEST_IN_CLASS_CONFIRMED —
    формальный отбор с контрпримерами не проводился ни для одного принципа,
    заявлять его было бы overclaiming; все 38 записей — MODERN_EXAMPLE."""
    out: list[str] = []
    f = root / "reference" / "classical_engineering_foundations.json"
    if not f.exists():
        return out
    data, err = load_json(f)
    if err:
        return [f"reference/classical_engineering_foundations.json: битый JSON: {err}"]
    if not isinstance(data, dict):
        return ["reference/classical_engineering_foundations.json: ожидался объект"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    if schemas_root and (schemas_root / "classical_engineering_foundations.schema.json").exists():
        loaded, serr = load_json(schemas_root / "classical_engineering_foundations.schema.json")
        if serr:
            return [f"classical_engineering_foundations: битая схема: {serr}"]
        if isinstance(loaded, dict):
            out.extend(validate_schema(data, loaded, "classical_engineering_foundations.json"))
    principles = data.get("principles")
    if not isinstance(principles, list):
        return out
    seen_ids: dict[str, int] = {}
    for i, p in enumerate(principles):
        if not isinstance(p, dict):
            continue
        pid = p.get("id")
        if isinstance(pid, str) and pid:
            if pid in seen_ids:
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}].id {pid!r} дублирует principles[{seen_ids[pid]}]")
            else:
                seen_ids[pid] = i
        for path in (p.get("implemented_in") or []):
            if not isinstance(path, str) or not path:
                continue
            if _path_escapes_root(root, path):
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}].implemented_in путь выходит за пределы проекта: {path}")
            elif not (root / path).exists():
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}].implemented_in ссылается на несуществующий путь: {path}")
        status = p.get("status")
        classification = p.get("classification")
        if status == "NOT_ADOPTED" and classification != "NOT_ADOPTED":
            out.append(f"reference/classical_engineering_foundations.json: "
                       f"principles[{i}] status=NOT_ADOPTED требует classification=NOT_ADOPTED "
                       f"(сейчас {classification!r}) — иначе принцип одновременно "
                       f"{classification!r} и сознательно не принят")
        if status == "ADOPTED" and classification == "NOT_ADOPTED":
            out.append(f"reference/classical_engineering_foundations.json: "
                       f"principles[{i}] status=ADOPTED несовместим с classification=NOT_ADOPTED")
        for field in ("source", "principle"):
            if _is_placeholder_value(p.get(field)):
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}].{field} — плейсхолдер или пусто")
        if status == "ADOPTED":
            ai_adaptation = p.get("ai_adaptation")
            if _is_placeholder_value(ai_adaptation) or not isinstance(ai_adaptation, str):
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}] status=ADOPTED требует непустой ai_adaptation "
                           f"(допустимо пусто только для NOT_ADOPTED)")
            enforced_by = p.get("enforced_by")
            if not isinstance(enforced_by, list) or not enforced_by:
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}] status=ADOPTED требует непустой enforced_by "
                           f"(допустимо пусто только для NOT_ADOPTED)")
                enforced_by = []
            else:
                # v2.9.118 (§11.1 внешнего аудита v2.9.117): enforced_by[] —
                # типизированные объекты {kind, path?, check?, note?} вместо
                # свободнотекстовых строк. kind/структура — схема; здесь то,
                # что схема не видит: path реально существует на диске,
                # validator_flag.check реально зарегистрирован в исходнике
                # path (не просто похож на флаг синтаксически).
                for j, entry in enumerate(enforced_by):
                    if not isinstance(entry, dict):
                        out.append(f"reference/classical_engineering_foundations.json: "
                                   f"principles[{i}].enforced_by[{j}] — ожидался объект "
                                   f"{{kind, path?, check?, note?}}, не строка (v2.9.118)")
                        continue
                    kind = entry.get("kind")
                    path = entry.get("path")
                    check = entry.get("check")
                    path_required = kind in ("validator_flag", "schema", "test", "ci_workflow")
                    if path_required or (kind == "review_only" and isinstance(path, str) and path):
                        if path_required and (not isinstance(path, str) or _is_placeholder_value(path)):
                            out.append(f"reference/classical_engineering_foundations.json: "
                                       f"principles[{i}].enforced_by[{j}] kind={kind!r} требует "
                                       f"непустой path")
                        elif isinstance(path, str) and path:
                            if _path_escapes_root(root, path):
                                out.append(f"reference/classical_engineering_foundations.json: "
                                           f"principles[{i}].enforced_by[{j}].path выходит за "
                                           f"пределы проекта: {path!r}")
                            elif not (root / path).exists():
                                out.append(f"reference/classical_engineering_foundations.json: "
                                           f"principles[{i}].enforced_by[{j}].path ссылается на "
                                           f"несуществующий путь: {path!r}")
                    if kind == "validator_flag":
                        if not isinstance(check, str) or _is_placeholder_value(check):
                            out.append(f"reference/classical_engineering_foundations.json: "
                                       f"principles[{i}].enforced_by[{j}] kind=validator_flag "
                                       f"требует непустой check (--флаг)")
                        elif isinstance(path, str) and path and (root / path).is_file():
                            known_flags = _known_validator_flags(root, path)
                            if known_flags is not None and check not in known_flags:
                                out.append(f"reference/classical_engineering_foundations.json: "
                                           f"principles[{i}].enforced_by[{j}].check {check!r} не "
                                           f"найден среди реально зарегистрированных флагов "
                                           f"{path} — проверь --check-* существует, не только "
                                           f"похоже названо (v2.9.118, §11.1 внешнего аудита "
                                           f"v2.9.117)")
            fully_enforced = p.get("fully_enforced")
            if fully_enforced is True:
                non_review = [e for e in enforced_by if isinstance(e, dict)
                              and e.get("kind") not in (None, "review_only")]
                if not non_review:
                    out.append(f"reference/classical_engineering_foundations.json: "
                               f"principles[{i}].fully_enforced=true не может опираться "
                               f"исключительно на review_only (или пустой enforced_by) — нужна "
                               f"хотя бы одна validator_flag/schema/test/ci_workflow запись "
                               f"(v2.9.118, §11.1 внешнего аудита v2.9.117)")
            modern_evidence = p.get("modern_evidence")
            if not isinstance(modern_evidence, list) or not modern_evidence:
                out.append(f"reference/classical_engineering_foundations.json: "
                           f"principles[{i}] status=ADOPTED требует непустой modern_evidence "
                           f"(v2.9.117, P1 внешнего ревью v2.9.116 — принцип без современного "
                           f"примера подтверждён только цитатой книги)")
            else:
                for j, ev in enumerate(modern_evidence):
                    if not isinstance(ev, dict):
                        continue
                    for field in ("project", "mechanism"):
                        if _is_placeholder_value(ev.get(field)):
                            out.append(f"reference/classical_engineering_foundations.json: "
                                       f"principles[{i}].modern_evidence[{j}].{field} — "
                                       f"плейсхолдер или пусто")
                    # v2.9.118 (§11.2 внешнего аудита v2.9.117): evidence_level —
                    # структурная классификация, схема не видит СОГЛАСОВАННОСТЬ
                    # заявленного уровня с фактически заполненными repository/
                    # commit (только их формат — pattern). E1 без commit или E2
                    # без repository — заявка сильнее, чем структура подтверждает
                    # (опасное направление — переоценка доказательности; обратное,
                    # заниженный уровень при более полных данных, не проверяется —
                    # излишне строго и не о чем предупреждать владельца).
                    level = ev.get("evidence_level")
                    repository = ev.get("repository")
                    commit = ev.get("commit")
                    has_repo = isinstance(repository, str) and bool(repository)
                    has_commit = isinstance(commit, str) and bool(commit)
                    if level == "E1" and not (has_repo and has_commit):
                        out.append(f"reference/classical_engineering_foundations.json: "
                                   f"principles[{i}].modern_evidence[{j}].evidence_level=E1 "
                                   f"требует repository И commit (commit-pinned) — сейчас "
                                   f"repository={repository!r}, commit={commit!r}")
                    elif level == "E2" and not has_repo:
                        out.append(f"reference/classical_engineering_foundations.json: "
                                   f"principles[{i}].modern_evidence[{j}].evidence_level=E2 "
                                   f"требует repository — сейчас repository={repository!r}")
                    # v2.9.118 (§11.3 внешнего аудита v2.9.117: «не путать
                    # examples и best-in-class») — BEST_IN_CLASS_CONFIRMED
                    # требует И commit-pinned evidence (evidence_level=E1),
                    # И reference/BENCHMARK_SELECTION.md с 4 разделами
                    # (критерии/кандидаты/причины выбора/контрпримеры).
                    # Содержательность отбора — не забота локального
                    # release-gate (см. общий принцип §11.2 выше), только
                    # структурное наличие.
                    if ev.get("example_status") == "BEST_IN_CLASS_CONFIRMED":
                        if level != "E1":
                            out.append(f"reference/classical_engineering_foundations.json: "
                                       f"principles[{i}].modern_evidence[{j}].example_status="
                                       f"BEST_IN_CLASS_CONFIRMED требует evidence_level=E1 "
                                       f"(commit-pinned) — сейчас evidence_level={level!r}")
                        bench = root / "reference" / "BENCHMARK_SELECTION.md"
                        if not bench.is_file():
                            out.append(f"reference/classical_engineering_foundations.json: "
                                       f"principles[{i}].modern_evidence[{j}].example_status="
                                       f"BEST_IN_CLASS_CONFIRMED требует reference/"
                                       f"BENCHMARK_SELECTION.md (критерии/кандидаты/причины "
                                       f"выбора/контрпримеры) — файл не найден")
                        else:
                            missing = [name for name, stem in _BENCHMARK_SELECTION_SECTIONS
                                      if stem not in bench.read_text(encoding="utf-8").lower()]
                            if missing:
                                out.append(f"reference/classical_engineering_foundations.json: "
                                           f"principles[{i}].modern_evidence[{j}].example_status="
                                           f"BEST_IN_CLASS_CONFIRMED — reference/BENCHMARK_"
                                           f"SELECTION.md не содержит разделы: {missing!r}")
    return out


_REQUIRED_POST_MERGE_CLEANUP_STEPS = {
    "switch_primary_workspace_to_main", "pull_main_ff_only",
    "delete_merged_local_branch", "remove_associated_clean_worktree",
    "remote_prune_origin", "verify_clean_status", "verify_worktree_list",
}


def _branch_matches_patterns(branch: str, patterns: list) -> bool:
    """`release/*`-подобные паттерны — префикс до `/*`; иначе точное имя."""
    for p in patterns:
        if not isinstance(p, str):
            continue
        if p.endswith("/*"):
            if branch.startswith(p[:-1]):
                return True
        elif branch == p:
            return True
    return False


def check_git_workspace_hygiene(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/git_workspace_hygiene.json (опционален, v2.9.89): политика
    жизненного цикла веток/worktree — основная папка проекта всегда на
    защищённой ветке, без feature-разработки и без detached HEAD; unmerged
    ветка и dirty worktree не удаляются автоматически (delete_unmerged_branch/
    remove_dirty_worktree обязаны быть "forbidden"); force-delete/force-remove
    требуют подтверждения человека; post-merge cleanup обязателен и
    remote prune всегда через dry-run сначала; scheduled destructive cleanup
    без requires_human_confirmation запрещён. v2.9.90 (P1 внешнего ревью
    v2.9.89): раньше сами инварианты правила (primary_workspace.branch не
    входит в protected_branch_patterns, allow_dirty_status, new_work_requires_
    branch, changes_enter_main_only_via_pr, parallel_agent_work_requires_
    worktree, one_task_per_worktree, remove_after_merge, post_merge_cleanup.
    when/steps) можно было молча отключить в самом policy-файле — теперь
    проверяются тоже. Статический валидатор не трогает реальные ветки/
    worktree — это делает только runtime-инвентаризация
    (tools/git_workspace_hygiene.py, read-only режимы). См.
    GIT_WORKSPACE_HYGIENE_STANDARD.md."""
    out: list[str] = []
    data = _load_registry_json(root, "git_workspace_hygiene.json",
                               "git_workspace_hygiene.schema.json", schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    pw = data.get("primary_workspace")
    bp = data.get("branch_policy")
    if isinstance(pw, dict):
        if pw.get("direct_development_allowed") is True:
            out.append("git_workspace_hygiene.json: primary_workspace.direct_development_allowed="
                       "true — основная папка не должна быть местом feature-разработки")
        if pw.get("must_remain_on_branch") is False:
            out.append("git_workspace_hygiene.json: primary_workspace.must_remain_on_branch="
                       "false — инвариант основной папки нельзя отключать")
        if pw.get("allow_detached_head") is True:
            out.append("git_workspace_hygiene.json: primary_workspace.allow_detached_head="
                       "true — detached HEAD в основной папке не должен быть разрешён")
        if pw.get("allow_dirty_status") is True:
            out.append("git_workspace_hygiene.json: primary_workspace.allow_dirty_status="
                       "true — основная папка должна оставаться стабильной чистой базой")
        branch = pw.get("branch")
        pbp_for_branch = bp.get("protected_branch_patterns") if isinstance(bp, dict) else None
        if (isinstance(branch, str) and isinstance(pbp_for_branch, list)
                and not _branch_matches_patterns(branch, pbp_for_branch)):
            out.append(f"git_workspace_hygiene.json: primary_workspace.branch={branch!r} не "
                       f"входит в branch_policy.protected_branch_patterns={pbp_for_branch!r} — "
                       f"основная папка обязана жить на защищённой ветке")
    if isinstance(bp, dict):
        if bp.get("delete_unmerged_branch") != "forbidden":
            out.append("git_workspace_hygiene.json: branch_policy.delete_unmerged_branch "
                       "должен быть \"forbidden\" — unmerged ветка не удаляется автоматически")
        if bp.get("force_delete_requires_human_confirmation") is not True:
            out.append("git_workspace_hygiene.json: branch_policy."
                       "force_delete_requires_human_confirmation должен быть true — "
                       "git branch -D без подтверждения человека запрещён")
        if bp.get("new_work_requires_branch") is False:
            out.append("git_workspace_hygiene.json: branch_policy.new_work_requires_branch="
                       "false — новая работа обязана идти через отдельную ветку")
        if bp.get("changes_enter_main_only_via_pr") is False:
            out.append("git_workspace_hygiene.json: branch_policy.changes_enter_main_only_via_pr="
                       "false — изменения обязаны попадать в основную ветку только через PR")
        pbp = bp.get("protected_branch_patterns")
        if isinstance(pbp, list) and not (set(pbp) & _TYPICAL_PROTECTED_BRANCHES):
            out.append(f"git_workspace_hygiene.json: branch_policy.protected_branch_patterns="
                       f"{pbp!r} не содержит ни одной типовой защищённой ветки "
                       f"({sorted(_TYPICAL_PROTECTED_BRANCHES)})")
    wp = data.get("worktree_policy")
    if isinstance(wp, dict):
        if wp.get("remove_dirty_worktree") != "forbidden":
            out.append("git_workspace_hygiene.json: worktree_policy.remove_dirty_worktree "
                       "должен быть \"forbidden\" — dirty worktree не удаляется автоматически")
        if wp.get("force_remove_requires_human_confirmation") is not True:
            out.append("git_workspace_hygiene.json: worktree_policy."
                       "force_remove_requires_human_confirmation должен быть true — "
                       "git worktree remove --force без подтверждения человека запрещён")
        if wp.get("parallel_agent_work_requires_worktree") is False:
            out.append("git_workspace_hygiene.json: worktree_policy."
                       "parallel_agent_work_requires_worktree=false — параллельная работа "
                       "нескольких агентов обязана идти через отдельный worktree")
        if wp.get("one_task_per_worktree") is False:
            out.append("git_workspace_hygiene.json: worktree_policy.one_task_per_worktree="
                       "false — один worktree обязан соответствовать одной задаче")
        if wp.get("remove_after_merge") is False:
            out.append("git_workspace_hygiene.json: worktree_policy.remove_after_merge="
                       "false — worktree после merge обязан удаляться")
    pmc = data.get("post_merge_cleanup")
    if isinstance(pmc, dict):
        if pmc.get("required") is not True:
            out.append("git_workspace_hygiene.json: post_merge_cleanup.required должен быть "
                       "true — уборка после merge не опциональна")
        if pmc.get("remote_prune_requires_dry_run_first") is not True:
            out.append("git_workspace_hygiene.json: post_merge_cleanup."
                       "remote_prune_requires_dry_run_first должен быть true — "
                       "git remote prune origin сначала dry-run")
        when = pmc.get("when")
        if when is not None and when != "immediately_after_merge":
            out.append(f"git_workspace_hygiene.json: post_merge_cleanup.when={when!r} — "
                       f"должен быть \"immediately_after_merge\", уборка не должна откладываться")
        steps = pmc.get("steps")
        if steps is not None:
            missing = _REQUIRED_POST_MERGE_CLEANUP_STEPS - set(steps if isinstance(steps, list) else [])
            if missing:
                out.append(f"git_workspace_hygiene.json: post_merge_cleanup.steps не содержит "
                           f"обязательные шаги: {sorted(missing)}")
    sc = data.get("scheduled_checks")
    if isinstance(sc, dict):
        dc = sc.get("destructive_cleanup")
        if (isinstance(dc, dict) and dc.get("enabled") is True
                and dc.get("requires_human_confirmation") is not True):
            out.append("git_workspace_hygiene.json: scheduled_checks.destructive_cleanup."
                       "enabled=true без requires_human_confirmation=true — деструктивная "
                       "уборка по расписанию без подтверждения человека запрещена")
    return out


_REQUIRED_AUDIT_FLAGS = {"hardcode": "--check-hardcode", "data_in_code": "--check-data-in-code"}


def check_code_audit_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/code_audit_jobs.json: три момента проверки кода
    (after_task/ci/scheduled) — все три обязательны (v2.9.53, P1 ревью:
    пустой {} раньше проходил). scheduled.orchestrator обязан быть
    automation_server (голый cron теряет lock/redact/notify/retention),
    должен быть хотя бы один job (daily+weekly). Если проект объявил
    required_audits (v2.9.54, P2 ревью) — отсутствие покрытия хотя бы одним
    scheduled-job'ом это ОШИБКА, не совет; без required_audits — как раньше,
    мягкий warning про hardcode/data-in-code. scheduled-job'ы — те же
    эвристики утечки секретов, что automation_jobs (общая
    _command_leak_findings). См. AUTOMATED_CODE_AUDIT_STANDARD."""
    out: list[str] = []
    data = _load_registry_json(root, "code_audit_jobs.json",
                               "code_audit_jobs.schema.json", schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    at = data.get("after_task")
    if isinstance(at, dict):
        cmds = at.get("commands") or []
        if not cmds:
            out.append("code_audit_jobs.json: after_task.commands пуст — "
                       "нечего гонять перед отчётом о завершении задачи")
        if not any(re.search(r"\bpytest\b|\btest\b", c, re.I) for c in cmds if isinstance(c, str)):
            out.append(f"{WARN_PREFIX}code_audit_jobs.json: after_task.commands не содержит "
                       f"команду тестов (pytest/test) — если в проекте есть тесты, добавь")
        for c in cmds:
            if isinstance(c, str):
                out.extend(_command_leak_findings(c, "code_audit_jobs.json after_task"))
    ci = data.get("ci")
    if isinstance(ci, dict):
        on = ci.get("on") or []
        missing = {"push", "pull_request"} - set(on)
        if missing:
            out.append(f"code_audit_jobs.json: ci.on не содержит {sorted(missing)} — "
                       f"CI должен гонять и на push, и на pull_request")
    sched = data.get("scheduled") or {}
    all_jobs: list[tuple[str, dict]] = []
    if isinstance(sched, dict):
        orchestrator = sched.get("orchestrator")
        if orchestrator != "automation_server":
            out.append(f"code_audit_jobs.json: scheduled.orchestrator={orchestrator!r} — "
                       f"должен быть automation_server (иначе теряется lock/redact/"
                       f"notify/retention из AUTOMATION_SERVER_SYNC_STANDARD)")
        for freq in ("daily", "weekly"):
            for j in sched.get(freq, []) or []:
                if isinstance(j, dict):
                    all_jobs.append((freq, j))
        if not all_jobs:
            out.append("code_audit_jobs.json: scheduled.daily и scheduled.weekly оба пусты — "
                       "нет ни одной запланированной проверки")
        all_cmds = [j.get("command") for _freq, j in all_jobs if isinstance(j.get("command"), str)]
        combined = " ".join(all_cmds)
        required_audits = data.get("required_audits") or []
        if required_audits:
            missing_audits = [a for a in required_audits
                              if _REQUIRED_AUDIT_FLAGS.get(a, a) not in combined]
            if missing_audits:
                out.append(f"code_audit_jobs.json: required_audits {missing_audits} не покрыты "
                           f"ни одним scheduled job — это объявленный контракт, не рекомендация")
        elif all_jobs and not re.search(r"--check-hardcode|--check-data-in-code", combined):
            out.append(f"{WARN_PREFIX}code_audit_jobs.json: ни один scheduled job не гоняет "
                       f"--check-hardcode/--check-data-in-code — на хардкод ежедневно/еженедельно "
                       f"никто не проверяет")
        for freq, j in all_jobs:
            cmd = j.get("command", "")
            if isinstance(cmd, str):
                out.extend(_command_leak_findings(
                    cmd, f"code_audit_jobs.json scheduled.{freq} {j.get('id', '?')}"))
    return out


def check_license_integration_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/license_integration_policy.json: обзорная runtime-политика
    интеграции с License-сервером — связывает ENTITLEMENTS_STANDARD (зеркало
    прав) и ENCRYPTED_ENV_STANDARD (секреты) и добавляет то, чего в них нет:
    поведение при недоступности Hub. fail_mode=fail-open без fail_open_reason —
    ошибка (тихий риск требует явного обоснования, тот же принцип, что
    waiver_reason в GIT_AGENT_WORKFLOW_STANDARD). hub_url_env — имя
    env-переменной (не литеральный URL), обязана быть описана в env_vars.json
    (v2.9.56, P1 ревью — та же дисциплина, что у passphrase_env в
    check_encrypted_env). entitlements_ref/encrypted_env_ref — пути обязаны
    существовать и не указывать на *.example.json без example_ref_waiver_reason
    (v2.9.56, P2). audit_log_required=false требует audit_waiver_reason
    (v2.9.56, P2 — тот же принцип waiver, что и у fail-open). cache_ttl_seconds —
    положительное целое. Файл ОПЦИОНАЛЕН. Валидатор офлайн — Hub не дёргает.
    См. LICENSE_SERVER_INTEGRATION_STANDARD.md."""
    out: list[str] = []
    data = _load_registry_json(root, "license_integration_policy.json",
                               "license_integration_policy.schema.json", schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    ue = data.get("hub_url_env")
    if isinstance(ue, str):
        if "://" in ue:
            out.append(f"license_integration_policy.json: hub_url_env — имя env-переменной, "
                       f"не URL: {ue}")
        elif not re.match(r"^[A-Z][A-Z0-9_]*$", ue):
            out.append(f"license_integration_policy.json: hub_url_env не в UPPER_SNAKE: {ue}")
        else:
            env_reg = root / "docs" / "registry" / "env_vars.json"
            if env_reg.exists():
                ed, _ = load_json(env_reg)
                known = {e.get("variable") for e in ed if isinstance(e, dict)} \
                    if isinstance(ed, list) else set()
                if ue not in known:
                    out.append(f"license_integration_policy.json: hub_url_env={ue} не описан "
                               f"в docs/registry/env_vars.json")
    fail_mode = data.get("fail_mode")
    if fail_mode == "fail-open" and not (isinstance(data.get("fail_open_reason"), str)
                                         and data["fail_open_reason"].strip()):
        out.append("license_integration_policy.json: fail_mode=fail-open без fail_open_reason — "
                   "тихий отказ в разрешительную сторону требует явного обоснования")
    if data.get("audit_log_required") is False and not (
            isinstance(data.get("audit_waiver_reason"), str) and data["audit_waiver_reason"].strip()):
        out.append("license_integration_policy.json: audit_log_required=false без "
                   "audit_waiver_reason — отсутствие audit trail для контроля доступа "
                   "требует явного обоснования")
    has_example_ref = False
    for field in ("entitlements_ref", "encrypted_env_ref"):
        ref = data.get(field)
        if isinstance(ref, str) and ref.strip():
            if not (root / ref).exists():
                out.append(f"license_integration_policy.json: {field} указывает на "
                           f"несуществующий путь: {ref}")
            if ref.endswith(".example.json"):
                has_example_ref = True
    if has_example_ref and not (isinstance(data.get("example_ref_waiver_reason"), str)
                                and data["example_ref_waiver_reason"].strip()):
        out.append("license_integration_policy.json: entitlements_ref/encrypted_env_ref "
                   "указывают на *.example.json без example_ref_waiver_reason — активированная "
                   "политика не должна тихо ссылаться на демо-файлы")
    ttl = data.get("cache_ttl_seconds")
    if isinstance(ttl, int) and not isinstance(ttl, bool) and ttl <= 0:
        out.append(f"license_integration_policy.json: cache_ttl_seconds={ttl} — должен быть "
                   f"положительным (0/отрицательное на практике значит «спрашивать Hub каждый "
                   f"раз» — назови это явно, убрав поле, а не через 0)")
    timeout = data.get("request_timeout_seconds")
    if isinstance(timeout, (int, float)) and not isinstance(timeout, bool) and timeout <= 0:
        out.append(f"license_integration_policy.json: request_timeout_seconds={timeout} — "
                   f"должен быть положительным")
    retry = data.get("retry")
    if isinstance(retry, dict):
        attempts = retry.get("attempts")
        if isinstance(attempts, int) and not isinstance(attempts, bool) and attempts < 0:
            out.append("license_integration_policy.json: retry.attempts не может быть отрицательным")
        backoff = retry.get("backoff_seconds")
        if isinstance(backoff, (int, float)) and not isinstance(backoff, bool) and backoff < 0:
            out.append("license_integration_policy.json: retry.backoff_seconds не может быть "
                       "отрицательным")
    return out


_QAI_HIGH_STAKES_PROFILES = {"api_contract", "rag_quality", "llm_generation_quality",
                             "classification_quality", "nightly_regression"}


_QAI_VALID_PROFILES = {"validate", "smoke", "nightly"}


def _qai_argv(cmd: str) -> list[str] | None:
    """Реальный argv QAI Fabric после снятия обёрток, или None если команда
    QAI не запускает (v2.9.60, P1 ревью v2.9.59: одного executable мало —
    нужно видеть subcommand, чтобы отличить `qai validate` от `qai run`).
    Нормализует к форме `["qai", <subcommand>, ...]`. Executable-проверка
    через shlex: прямой `qai`, `python -m qai`, tool-wrappers (uv/poetry/
    pdm/hatch run), явный shell-wrapper `bash -lc '...'` (рекурсивно). echo/
    printf/cat/`python -c` не проходят по построению (их argv[0] не qai)."""
    try:
        parts = shlex.split(cmd)
    except ValueError:
        return None
    if not parts:
        return None
    if parts[0] == "qai":
        return parts
    if len(parts) >= 3 and parts[0] in {"python", "python3"} and parts[1:3] == ["-m", "qai"]:
        return ["qai"] + parts[3:]
    if len(parts) >= 3 and parts[0] in {"uv", "poetry", "pdm", "hatch"} and parts[1] == "run":
        if parts[2] == "qai":
            return parts[2:]
        if len(parts) >= 5 and parts[2] in {"python", "python3"} and parts[3:5] == ["-m", "qai"]:
            return ["qai"] + parts[5:]
        return None
    if len(parts) >= 3 and parts[0] in {"bash", "sh"} and parts[1] in {"-c", "-lc"}:
        return _qai_argv(parts[2])
    return None


def _is_qai_command(cmd: str) -> bool:
    return _qai_argv(cmd) is not None


# роль команды → обязательный QAI subcommand: validate проверяет сценарий,
# smoke/nightly реально прогоняют (`qai run`) — иначе смысловая подмена
# (validate=`qai run`, smoke=`qai validate`) прошла бы (v2.9.60, P1 ревью v2.9.59)
_QAI_ROLE_SUBCOMMAND = {"validate": "validate", "smoke": "run", "nightly": "run"}


def _qai_command_has_subcommand(cmd: str, expected: str) -> bool:
    argv = _qai_argv(cmd)
    return argv is not None and len(argv) >= 2 and argv[1] == expected


def _qai_has_scenario(argv: list[str]) -> bool:
    """Есть ли явный config/scenario path сразу после subcommand (v2.9.61, P2.2
    ревью v2.9.60): `qai validate` / `qai run --json ...` без сценария — контракт
    неполон. Сценарий по конвенции QAI — первый positional после subcommand."""
    return len(argv) >= 3 and not argv[2].startswith("-")


def _argv_flag(argv: list[str], flag: str) -> tuple[bool, str | None]:
    """(есть ли флаг в argv, его путь-аргумент или None). Работает по УЖЕ
    нормализованному QAI-argv из _qai_argv (v2.9.61, P2.1 ревью v2.9.60: старый
    _report_flag_path разбирал внешнюю команду, поэтому `bash -lc 'qai run ...
    --json ...'` давал ложную ошибку — флаги были внутри строки bash -lc).
    Формы `--flag path` и `--flag=path`."""
    for i, p in enumerate(argv):
        if p == flag:
            if i + 1 < len(argv) and not argv[i + 1].startswith("-"):
                return True, argv[i + 1]
            return True, None
        if p.startswith(flag + "="):
            val = p[len(flag) + 1:]
            return True, (val or None)
    return False, None


def check_qai_fabric_policy(root: Path, schemas_root_arg: str | None) -> list[str]:
    """docs/registry/qai_fabric_policy.json: когда и как включать внешний
    QA-адаптер (например qai-fabric). validate_structure.py — инженерная
    дисциплина репозитория, QAI Fabric — глубокая QA-оценка поведения
    продукта (API-контракты/RAG/LLM/classification quality). quality_profile
    с высокостейковым классом требует enabled=true; nightly_regression
    дополнительно требует commands.nightly + scheduled.profile=nightly
    (v2.9.58, P2.3). enabled=true требует commands.validate + (commands.smoke
    или commands.nightly), и каждая непустая команда обязана реально
    вызывать qai/python -m qai — иначе агент может формально включить слой,
    подменив команды на echo (v2.9.58, P1.1). ci.profile/scheduled.profile —
    только validate/smoke/nightly и обязаны ссылаться на существующую
    commands.<profile> (v2.9.58, P1.2 — иначе CI/scheduled декларативно
    ссылаются в никуда). ci.profile не может быть nightly (дорогой прогон не
    на каждый PR). scheduled — тот же принцип, что AUTOMATED_CODE_AUDIT_
    STANDARD: orchestrator обязан быть automation_server, notify_on_failure
    обязателен. reports.required требует json+markdown в декларации И
    реальные --json/--markdown флаги в smoke/nightly командах (v2.9.58,
    P2.2). quality_profile, если задан, не может быть пустым (v2.9.58,
    P2.1). Команды — те же эвристики утечки секретов, что в
    --check-automation-jobs. Файл ОПЦИОНАЛЕН. См. QAI_FABRIC_ADAPTER_STANDARD.md."""
    out: list[str] = []
    data = _load_registry_json(root, "qai_fabric_policy.json",
                               "qai_fabric_policy.schema.json", schemas_root_arg, out)
    if not isinstance(data, dict):
        return out
    qp = data.get("quality_profile")
    if isinstance(qp, list) and not qp:
        out.append("qai_fabric_policy.json: quality_profile пуст — ничего не сообщает агенту")
    profile = set(qp or [])
    high_stakes = profile & _QAI_HIGH_STAKES_PROFILES
    enabled = data.get("enabled")
    if high_stakes and enabled is not True:
        out.append(f"qai_fabric_policy.json: quality_profile содержит {sorted(high_stakes)}, "
                   f"но enabled != true — этот класс качества требует QAI Fabric")
    cmds = data.get("commands") or {}
    if enabled is True:
        if not (isinstance(cmds.get("validate"), str) and cmds["validate"].strip()):
            out.append("qai_fabric_policy.json: enabled=true, но нет commands.validate")
        if not any(isinstance(cmds.get(k), str) and cmds[k].strip() for k in ("smoke", "nightly")):
            out.append("qai_fabric_policy.json: enabled=true, но нет ни commands.smoke, "
                       "ни commands.nightly — нечем реально гонять")
        for name in ("validate", "smoke", "nightly"):
            cmd = cmds.get(name)
            if not (isinstance(cmd, str) and cmd.strip()):
                continue
            if not _is_qai_command(cmd):
                out.append(f"qai_fabric_policy.json commands.{name}: enabled=true, но команда "
                           f"не вызывает qai/python -m qai — формальное включение без "
                           f"реального QA-адаптера")
                continue
            expected = _QAI_ROLE_SUBCOMMAND[name]
            if not _qai_command_has_subcommand(cmd, expected):
                out.append(f"qai_fabric_policy.json commands.{name}: должна быть `qai {expected} "
                           f"...` (роль {name} → subcommand {expected}) — голый `qai` без "
                           f"подкоманды или подмена роли не считается")
                continue
            argv = _qai_argv(cmd)
            if argv is not None and not _qai_has_scenario(argv):
                out.append(f"qai_fabric_policy.json commands.{name}: `qai {expected}` без "
                           f"явного config/scenario path — укажи сценарий "
                           f"(`qai {expected} <scenario.yaml> ...`)")
    for name, cmd in cmds.items():
        if isinstance(cmd, str):
            out.extend(_command_leak_findings(cmd, f"qai_fabric_policy.json commands.{name}"))
    ci = data.get("ci")
    if isinstance(ci, dict):
        ci_profile = ci.get("profile")
        if isinstance(ci_profile, str):
            if ci_profile == "nightly":
                out.append("qai_fabric_policy.json: ci.profile=nightly — дорогой прогон не "
                           "должен идти на каждый PR, используй smoke/validate")
            elif ci_profile not in _QAI_VALID_PROFILES:
                out.append(f"qai_fabric_policy.json: ci.profile={ci_profile!r} — должен быть "
                           f"одним из {sorted(_QAI_VALID_PROFILES)}")
            elif not (isinstance(cmds.get(ci_profile), str) and cmds[ci_profile].strip()):
                out.append(f"qai_fabric_policy.json: ci.profile={ci_profile!r}, но "
                           f"commands.{ci_profile} не задан — CI ссылается в никуда")
    sched = data.get("scheduled")
    if isinstance(sched, dict):
        if sched.get("orchestrator") != "automation_server":
            out.append(f"qai_fabric_policy.json: scheduled.orchestrator="
                       f"{sched.get('orchestrator')!r} — должен быть automation_server")
        if sched.get("notify_on_failure") is not True:
            out.append("qai_fabric_policy.json: scheduled без notify_on_failure=true")
        sched_profile = sched.get("profile")
        if isinstance(sched_profile, str):
            if sched_profile not in _QAI_VALID_PROFILES:
                out.append(f"qai_fabric_policy.json: scheduled.profile={sched_profile!r} — "
                           f"должен быть одним из {sorted(_QAI_VALID_PROFILES)}")
            elif not (isinstance(cmds.get(sched_profile), str) and cmds[sched_profile].strip()):
                out.append(f"qai_fabric_policy.json: scheduled.profile={sched_profile!r}, но "
                           f"commands.{sched_profile} не задан — расписание ссылается в никуда")
    if "nightly_regression" in profile:
        if not (isinstance(cmds.get("nightly"), str) and cmds["nightly"].strip()):
            out.append("qai_fabric_policy.json: quality_profile содержит nightly_regression, "
                       "но нет commands.nightly")
        if not (isinstance(sched, dict) and sched.get("profile") == "nightly"):
            out.append("qai_fabric_policy.json: quality_profile содержит nightly_regression, "
                       "но scheduled.profile != nightly")
    fp = data.get("failure_policy")
    if enabled is True and not isinstance(fp, dict):
        out.append("qai_fabric_policy.json: enabled=true без failure_policy — CI/"
                   "automation_server должны знать, как трактовать exit code (0 passed / "
                   "1 execution / 2 quality threshold) (v2.9.60, P2.3)")
    if isinstance(fp, dict):
        ec1 = fp.get("exit_code_1")
        if isinstance(ec1, str) and not re.search(r"execution|infrastructure", ec1, re.I):
            out.append(f"qai_fabric_policy.json: failure_policy.exit_code_1={ec1!r} — "
                       f"должен описывать сбой выполнения/инфраструктуры (execution/"
                       f"infrastructure) (v2.9.60, семантика exit code 1)")
        ec2 = fp.get("exit_code_2")
        if isinstance(ec2, str) and "threshold" not in ec2.lower():
            out.append(f"qai_fabric_policy.json: failure_policy.exit_code_2={ec2!r} — "
                       f"должен описывать провал quality-порога (threshold), не "
                       f"инфраструктурный сбой (v2.9.59, семантика exit code 2)")
    reports = data.get("reports")
    if isinstance(reports, dict) and reports.get("required") is True:
        if reports.get("json") is not True or reports.get("markdown") is not True:
            out.append("qai_fabric_policy.json: reports.required=true требует "
                       "reports.json=true и reports.markdown=true")
        # пути отчётов должны идти в reports/ (артефакт репозитория, а не /tmp),
        # иначе — явный report_path_waiver_reason (v2.9.60, P2.1)
        waiver = isinstance(data.get("report_path_waiver_reason"), str) \
            and data["report_path_waiver_reason"].strip()
        # флаги ищем в НОРМАЛИЗОВАННОМ QAI-argv (v2.9.61, P2.1) — иначе
        # `bash -lc 'qai run ... --json ...'` даёт ложную ошибку (флаги внутри
        # строки-обёртки, внешний shlex их не видит)
        flag_ext = {"--json": (".json",), "--markdown": (".md", ".markdown")}
        for name in ("smoke", "nightly"):
            cmd = cmds.get(name)
            if not (isinstance(cmd, str) and cmd.strip()):
                continue
            argv = _qai_argv(cmd)
            if argv is None:
                continue  # не qai-команда — поймано в enabled-блоке выше
            for flag, exts in flag_ext.items():
                present, path = _argv_flag(argv, flag)
                if not present:
                    out.append(f"qai_fabric_policy.json: reports.required=true, но "
                               f"commands.{name} не содержит {flag} — декларация отчётов "
                               f"не подкреплена реальной командой")
                    continue
                if path is None:
                    out.append(f"qai_fabric_policy.json: commands.{name}: у {flag} "
                               f"нет пути-аргумента — отчёт некуда писать")
                    continue
                if not path.startswith("reports/") and not waiver:
                    out.append(f"qai_fabric_policy.json: commands.{name}: {flag} пишет в "
                               f"{path!r} вне reports/ — отчёты кладут в reports/ (артефакт "
                               f"репозитория) либо обоснуй через report_path_waiver_reason")
                if not path.endswith(exts):
                    out.append(f"qai_fabric_policy.json: commands.{name}: {flag} пишет в "
                               f"{path!r} — расширение не {'/'.join(exts)} (возможна "
                               f"перестановка выходных артефактов)")
    return out


# --- golden-path portability: команды и активация переносимы (v2.9.63) ---
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_WRAP_WITH_ARG = {"timeout"}                    # timeout <dur> <cmd>
# time/command/sudo/doas — обёртки без обязательного аргумента (v2.9.66 P1.2;
# v2.9.67, P1.1 ревью v2.9.66: sudo pytest -q проходил незамеченным)
_WRAP_NO_ARG = {"xvfb-run", "nice", "ionice", "stdbuf", "nohup", "time", "command",
                "sudo", "doas"}
_PUNCT_CHARS = set(";&|()")      # символы-разделители shell-выражения
_GROUP_TOKENS = {"{", "}", "(", ")"}
# console-script pytest в любой форме: голый, по пути, .exe, versioned (v2.9.66, P1.2)
_PYTEST_EXES = {"pytest", "pytest.exe", "pytest3"}
# control-flow ключевые слова shell (if/while/until-конструкции) и унарное
# отрицание `!` — не команды, а разметка вокруг реальной команды (v2.9.67, P1.1
# ревью v2.9.66: `if pytest -q; then ...; fi` проскакивал, т.к. executable
# сегмента был `if`, а не `pytest`)
_CONTROL_KEYWORDS = {"if", "then", "elif", "else", "fi", "while", "until", "do", "done"}
_NEGATION = "!"
# флаги-с-значением у конкретных wrapper'ов: снимать не только флаг, но и его
# отдельно стоящий аргумент (v2.9.68, P1.1 ревью v2.9.67: `sudo -u runner pytest`
# оставлял `runner pytest` как "команду" — generic strip снимал только `-u`)
_OPTION_ARG_SPECS: dict[str, set[str]] = {
    "sudo": {"-u", "--user", "-g", "--group", "-h", "--host", "-p", "--prompt",
             "-C", "--close-from"},
    "doas": {"-u"},
    # -S/--split-string НЕ здесь: это не "флаг+значение для отбрасывания", а
    # встроенная команда (v2.9.69, P1.1) — обрабатывается отдельно в env-ветке
    "env": {"-u", "--unset", "-C", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "ionice": {"-c", "--class", "-n", "--classdata"},
}
# env -S/--split-string разбивает следующий токен как ПОЛНУЮ команду (GNU env,
# используется в shebang `#!/usr/bin/env -S python3 -u`) — не значение флага
# для отбрасывания, а вложенная команда для рекурсии (v2.9.69, P1.1 ревью
# v2.9.68: `env -S "pytest -q"` проходил, т.к. generic wrapper-parser съедал
# `-S` и его "значение" как обычный флаг)
_ENV_SPLIT_STRING_FLAGS = ("-S", "--split-string")
# bash/sh launcher: опции с обязательным следующим токеном-значением (`-o
# pipefail`) — при поиске `-c`/`-lc` их значение нужно пропускать, а не
# принимать за command string (v2.9.69, P1.1)
_BASH_ARG_OPTS = {"-o"}
# python3.11/python3.12/... и Windows py-launcher (`py -3`/`py -3.11`) — не
# каноническая golden-path форма (v2.9.68, P2.1)
_PY_VERSIONED_RE = re.compile(r"^python3\.\d+$")
_PY_LAUNCHER_ARG_RE = re.compile(r"^-3(\.\d+)?$")


def _exe_basename(exe: str) -> str:
    """Имя исполняемого без пути (POSIX и Windows-разделители): `./.venv/bin/pytest`
    → `pytest`, `C:\\py\\pytest.exe` → `pytest.exe` (v2.9.66, P1.2)."""
    return exe.replace("\\", "/").rsplit("/", 1)[-1]


# backtick command substitution (`` `pytest -q` ``) — legacy-форма $(...):
# shlex не трактует backtick как кавычку/группировку, поэтому `pytest` внутри
# приклеивается к соседним символам ("`pytest") и не распознаётся как
# executable. Извлекаем содержимое ДО обычной сегментации, чтобы не портить
# разбор остальной команды (v2.9.75, P2 ревью v2.9.74 — просили трижды).
_BACKTICK_RE = re.compile(r"`([^`\n]+)`")


def _shell_segments(cmd: str) -> list[list[str]]:
    """Разбить shell-команду на сегменты-argv по `;`/`&&`/`||`/`|`/`&` и группировке
    `(...)`/`{...}`, с учётом кавычек и комментариев (shlex: punctuation_chars +
    commenters). v2.9.65: голый pytest после `cd &&`/env/`;`/`bash -lc` проскакивал.
    v2.9.66, P1.2 ревью v2.9.65: subshell `(pytest -q)` и group `{ pytest -q; }` —
    executable внутри группировки тоже разбирается (`(`/`)` в punctuation_chars,
    `{`/`}` как разделители-слова)."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|()")
        lex.whitespace_split = True
        lex.commenters = "#"          # `# comment` — с учётом кавычек, не regex
        tokens = list(lex)
    except ValueError:
        return []
    segments: list[list[str]] = []
    cur: list[str] = []
    for t in tokens:
        # разделитель: `{`/`}` (слово-токен) ИЛИ run пунктуации (`;`/`&&`/`|`/`(`/`)`/
        # даже склеенный `&&(` — shlex объединяет соседнюю пунктуацию в один токен)
        if t in ("{", "}") or (t and all(c in _PUNCT_CHARS for c in t)):
            if cur:
                segments.append(cur)
                cur = []
        else:
            cur.append(t)
    if cur:
        segments.append(cur)
    return segments


def _consume_wrapper_options(argv: list[str], arg_flags: set[str]) -> list[str]:
    """Снять ведущие `-флаги` wrapper'а: булевы флаги (`-E`) по одному токену,
    value-флаги из `arg_flags` — флаг + отдельно стоящее значение (`-u runner`,
    `--user runner`), комбинированная форма `--user=runner` — один токен уже
    несёт значение. `--` — terminator, всё после него не флаги wrapper'а, а
    команда (v2.9.68, P1.1 ревью v2.9.67)."""
    argv = list(argv)
    while argv:
        head = argv[0]
        if head == "--":
            argv = argv[1:]
            break
        if not head.startswith("-"):
            break
        argv = argv[1:]
        if "=" not in head and head in arg_flags and argv:
            argv = argv[1:]            # отдельно стоящее значение флага
    return argv


def _strip_wrappers(argv: list[str]) -> list[str]:
    """Снять группировку, control-keywords/negation, env-присвоения и wrapper'ы
    (env/timeout/xvfb-run/nice/time/command/sudo/doas/...) перед реальной
    командой (v2.9.65, P2.2; v2.9.66 P1.2 — группировка/time/command; v2.9.67
    P1.1 — if/while/until-keywords и `!`; v2.9.68 P1.1 — value-флаги wrapper'ов
    типа `sudo -u runner`/`env -u VAR`/`nice -n 10` через `_OPTION_ARG_SPECS`)."""
    argv = list(argv)
    while argv:
        head = argv[0]
        if head in _GROUP_TOKENS:      # остаток `(`/`)`/`{`/`}` внутри сегмента
            argv = argv[1:]
            continue
        if head in _CONTROL_KEYWORDS or head == _NEGATION:
            argv = argv[1:]
            continue
        if _ENV_ASSIGN_RE.match(head):
            argv = argv[1:]
            continue
        if head == "env":
            argv = argv[1:]
            while argv:
                if _ENV_ASSIGN_RE.match(argv[0]):
                    argv = argv[1:]
                    continue
                if argv[0] in _ENV_SPLIT_STRING_FLAGS:
                    # значение -S — не флаг, а вложенная команда; разбить и
                    # подставить как новый argv (v2.9.69, P1.1)
                    if len(argv) >= 2:
                        try:
                            argv = shlex.split(argv[1])
                        except ValueError:
                            argv = []
                    else:
                        argv = []
                    break
                if argv[0].startswith("-"):
                    argv = _consume_wrapper_options(argv, _OPTION_ARG_SPECS.get("env", set()))
                    continue
                break
            continue
        if head in _WRAP_WITH_ARG:
            argv = argv[1:]
            if argv:
                argv = argv[1:]        # аргумент wrapper'а (напр. длительность)
            continue
        if head in _WRAP_NO_ARG:
            argv = argv[1:]
            argv = _consume_wrapper_options(argv, _OPTION_ARG_SPECS.get(head, set()))
            continue
        break
    return argv


def _shell_launcher_command(argv: list[str]) -> str | None:
    """Найти `-c`/`-lc` среди опций bash/sh launcher'а, пропуская опции-флаги
    (`-e`/`-x`/`--login`/`--noprofile`/...) и опции со значением (`-o
    pipefail`), и вернуть следующий токен как command string. `None`, если
    `-c`/`-lc` не найден. Раньше -c/-lc искался строго в argv[1] — `bash -e -c
    "..."`, `bash -o pipefail -c "..."`, `bash --login -c "..."` проскакивали
    (v2.9.69, P1.1 ревью v2.9.68)."""
    if not argv or argv[0] not in {"bash", "sh"}:
        return None
    i = 1
    while i < len(argv):
        tok = argv[i]
        if tok in ("-c", "-lc"):
            return argv[i + 1] if i + 1 < len(argv) else None
        if tok in _BASH_ARG_OPTS:
            i += 2
            continue
        if tok.startswith("-"):
            i += 1
            continue
        break
    return None


def _classify_argv(argv: list[str]):
    """bare/module/managed/managed_module/None для ОДНОГО argv-сегмента (после
    снятия обёрток). `bash -lc "..."` — рекурсивно во вложенную строку."""
    argv = _strip_wrappers(argv)
    if not argv:
        return None
    exe = argv[0]
    base = _exe_basename(exe)
    if base in _PYTEST_EXES:
        # одиночное слово `pytest` без пути/аргументов — это лейбл (enum "kind",
        # required_checks:["pytest"]), не команда; путь/расширение/аргументы —
        # реальный запуск console-script (v2.9.66, P1.2: `./.venv/bin/pytest`)
        if exe == "pytest" and len(argv) == 1:
            return None
        return "bare"
    if len(argv) >= 3 and exe in {"python", "python3"} \
            and argv[1] == "-m" and argv[2] == "pytest":
        return "module"
    # версионный интерпретатор (python3.11) или Windows py-launcher (py -3) —
    # не bare, но и не каноническая форма golden path (после активации venv
    # достаточно `python`) → warning, вариант Б (v2.9.68, P2.1 ревью v2.9.67)
    if len(argv) >= 3 and _PY_VERSIONED_RE.match(exe) \
            and argv[1] == "-m" and argv[2] == "pytest":
        return "module_versioned"
    if len(argv) >= 4 and exe == "py" and _PY_LAUNCHER_ARG_RE.match(argv[1]) \
            and argv[2] == "-m" and argv[3] == "pytest":
        return "module_versioned"
    if len(argv) >= 3 and exe in {"uv", "poetry", "pdm", "hatch"} and argv[1] == "run":
        if argv[2] == "pytest":
            return "managed"
        if len(argv) >= 5 and argv[2] in {"python", "python3"} \
                and argv[3] == "-m" and argv[4] == "pytest":
            return "managed_module"
        return None
    if len(argv) >= 3 and exe == "pipenv" and argv[1] == "run":
        # pipenv не рекомендованный managed-wrapper стандарта (uv — текущий
        # default) — не bare, но и не golden-path форма → warning (v2.9.67, P2.1
        # ревью v2.9.66, вариант Б)
        if argv[2] == "pytest" or (len(argv) >= 5 and argv[2] in {"python", "python3"}
                                    and argv[3] == "-m" and argv[4] == "pytest"):
            return "managed_warn"
        return None
    if exe in {"bash", "sh"}:
        # -c/-lc не всегда argv[1]: перед ним бывают shell-опции (-e, -o
        # pipefail, --login, --noprofile, ...) — искать через launcher-парсер,
        # не строгую позицию (v2.9.69, P1.1 ревью v2.9.68)
        inner = _shell_launcher_command(argv)
        return _pytest_invocation(inner) if inner is not None else None
    return None


def _pytest_invocation(cmd: str):
    """Как команда запускает pytest — разбирая shell-выражение на сегменты и
    снимая обёртки (v2.9.65, P1 ревью v2.9.64: `cd app && pytest`, env-присвоения,
    `bash -lc "..."`, `;`, `timeout`/`xvfb-run` теперь ловятся). Возвращает
    худшую классификацию по сегментам: 'bare' (голый console-script) >
    'managed_module' (uv run python -m pytest — warning) > 'managed_warn'
    (pipenv run — warning, не golden-path wrapper) > 'module_versioned'
    (python3.11/py -3 -m pytest — warning, не каноническая форма) >
    'module'/'managed' (ок) > None. Backtick command substitution
    (`` `pytest -q` ``) разбирается рекурсивно как вложенная команда — та же
    механика, что и для `bash -lc "..."` (v2.9.75, P2 ревью v2.9.74). См.
    GOLDEN_PATH_STANDARD §1a."""
    # backtick-подстановки — вложенные команды; извлекаем и классифицируем
    # ДО обычной сегментации, иначе shlex приклеивает backtick к соседнему
    # токену и `pytest` внутри перестаёт быть узнаваемым executable
    backtick_results = [_pytest_invocation(m.group(1)) for m in _BACKTICK_RE.finditer(cmd)]
    outer_cmd = _BACKTICK_RE.sub(" ", cmd)
    results = backtick_results + [_classify_argv(seg) for seg in _shell_segments(outer_cmd)]
    if "bare" in results:
        return "bare"
    if "managed_module" in results:
        return "managed_module"
    if "managed_warn" in results:
        return "managed_warn"
    if "module_versioned" in results:
        return "module_versioned"
    for r in results:
        if r in ("module", "managed"):
            return r
    return None


def _candidate_commands(text: str):
    """Команды из текста: каждый `run: <cmd>` (inline) + строки block-scalar
    `run: |`/`run: >` (v2.9.64, P1 ревью v2.9.63: multiline run пропускался);
    если run: нет вовсе — весь текст как одна команда (JSON-поле `command`/cli)."""
    lines = text.split("\n")
    has_run = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.search(r"(^|\s)run:\s*[|>][-+]?\s*$", line):
            has_run = True
            base = len(line) - len(line.lstrip())
            j = i + 1
            while j < len(lines):
                bl = lines[j]
                if bl.strip():
                    if (len(bl) - len(bl.lstrip())) <= base:
                        break
                    yield bl
                j += 1
            i = j
            continue
        mi = re.search(r"(^|\s)run:\s*(\S.*)$", line)
        if mi:
            has_run = True
            yield mi.group(2)
        i += 1
    if not has_run:
        yield text


def _walk_json_strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _walk_json_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_json_strings(v)


_PSEUDO_CMDS = {"echo", "printf", "cat", "true", ":"}


def _is_pseudo_test_command(cmd: str) -> bool:
    """Команда только печатает/ничего не делает (echo/printf/cat/true) —
    псевдотест (v2.9.65, P2.1 ревью v2.9.64: `echo uv run pytest` в
    test_runner.cli выглядит как тест, но не запускает его). Строгая форма:
    любой echo/printf/cat в поле, которое ОБЯЗАНО быть тестовой командой.
    Проверяет ВСЕ сегменты (v2.9.67, P2.2 ревью v2.9.66: `echo prepare; echo
    ...` — первый сегмент не псевдотест, а второй мог проскочить, если
    смотреть только на segs[0])."""
    segs = _shell_segments(cmd)
    return any(_strip_wrappers(seg) and _strip_wrappers(seg)[0] in _PSEUDO_CMDS for seg in segs)


def _pseudo_wraps_test(cmd: str) -> bool:
    """echo/printf/cat, ЗА которым идёт похожая на тест команда (`echo uv run
    pytest -q`) — печатает тест вместо запуска (v2.9.66, P2.1 ревью v2.9.65).
    Отличие от _is_pseudo_test_command: обычный `echo "Running"` НЕ ловится
    (нужен реальный pytest в аргументах) — годится для CI/audit, где echo для
    логов легитимен. Проверяет ВСЕ сегменты (v2.9.67, P2.2 ревью v2.9.66:
    `echo prepare; echo uv run pytest -q` — вторым сегментом)."""
    for seg in _shell_segments(cmd):
        argv = _strip_wrappers(seg)
        if argv and argv[0] in _PSEUDO_CMDS and _classify_argv(argv[1:]) is not None:
            return True
    return False


def check_golden_path_portability(root: Path) -> list[str]:
    """Активные шаблоны/registry/CI не должны учить голому `pytest`, а README —
    POSIX-only активации без Windows-эквивалента (v2.9.63, P2.3 ревью v2.9.62:
    иначе кросс-платформенный golden path сам себе противоречит, и агент на
    Windows/CI/subprocess воспроизводит ровно ту ошибку, что стандарт закрыл).
    Историческое (CHANGELOG/RELEASE_NOTES/calibration) не сканируется.
    См. GOLDEN_PATH_STANDARD §1a."""
    out: list[str] = []

    def _flag(where: str, cmd: str) -> None:
        inv = _pytest_invocation(cmd)
        if inv == "bare":
            out.append(f"{where}: команда `{cmd.strip()}` — голый pytest; используй "
                       f"`python -m pytest` (или `uv run pytest`) (GOLDEN_PATH_STANDARD §1a)")
        elif inv == "managed_module":
            out.append(f"{WARN_PREFIX}{where}: `uv run python -m pytest` не golden-path "
                       f"форма (эмпирически падает без dev-extra) — используй `uv run pytest` "
                       f"(GOLDEN_PATH_STANDARD §1a)")
        elif inv == "managed_warn":
            out.append(f"{WARN_PREFIX}{where}: `pipenv run` не golden-path wrapper "
                       f"стандарта — рекомендованный менеджер `uv run pytest` "
                       f"(DEPENDENCY_MANAGEMENT_STANDARD)")
        elif inv == "module_versioned":
            out.append(f"{WARN_PREFIX}{where}: команда `{cmd.strip()}` — версионный "
                       f"интерпретатор (python3.X / py -3), не каноническая golden-path "
                       f"форма — после активации venv достаточно `python -m pytest` "
                       f"(GOLDEN_PATH_STANDARD §1a)")

    json_files: list[Path] = []
    for pat in ("templates/*.json", "docs/registry/*.json",
                "examples/reference_python_project/docs/registry/*.json"):
        json_files += sorted(root.glob(pat))
    for f in json_files:
        data, err = load_json(f)
        if err or data is None:
            continue
        for s in _walk_json_strings(data):
            for cmd in _candidate_commands(s):
                _flag(str(f.relative_to(root)), cmd)
    yml_files: list[Path] = []
    for pat in ("templates/ci_validate.yml", ".github/workflows/*.yml",
                "examples/reference_python_project/.github/workflows/*.yml"):
        yml_files += sorted(root.glob(pat))
    for f in yml_files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for cmd in _candidate_commands(text):
            _flag(str(f.relative_to(root)), cmd)
            # `echo uv run pytest` в CI-шаге — псевдотест; в машинных
            # registry/CI это почти всегда ошибка, не мягкая рекомендация →
            # hard error, не warning (v2.9.68, P2.3 ревью v2.9.67; было
            # warning с v2.9.66 P2.1). Обычный echo для логов не ловится
            # (нужен реальный pytest в аргументах).
            if _pseudo_wraps_test(cmd):
                out.append(f"{f.relative_to(root)}: `{cmd.strip()}` — "
                           f"псевдотест (echo/printf печатает тест-команду, а не запускает)")
    # псевдотест в командных полях code_audit_jobs (after_task/scheduled) — те же
    # правила, что для CI; hard error (v2.9.68, P2.3)
    for pat in ("templates/code_audit_jobs.json", "docs/registry/code_audit_jobs.json",
                "examples/reference_python_project/docs/registry/code_audit_jobs.json"):
        f = root / pat
        if not f.exists():
            continue
        data, err = load_json(f)
        if err or data is None:
            continue
        for s in _walk_json_strings(data):
            if _pseudo_wraps_test(s):
                out.append(f"{f.relative_to(root)}: `{s.strip()}` — "
                           f"псевдотест (echo/printf печатает тест-команду, а не запускает)")
    # псевдотест в test_runner.cli: echo/printf/cat вместо реального прогона
    # scoped на поле cli, не на любую строку; hard error (v2.9.68, P2.3 —
    # было warning с v2.9.65 P2.1)
    for pat in ("docs/registry/test_runner.json",
                "examples/reference_python_project/docs/registry/test_runner.json"):
        f = root / pat
        if not f.exists():
            continue
        data, err = load_json(f)
        cli = data.get("cli") if isinstance(data, dict) else None
        if isinstance(cli, dict):
            for name, cmd in cli.items():
                if isinstance(cmd, str) and _is_pseudo_test_command(cmd):
                    out.append(f"{f.relative_to(root)}: cli.{name}=`{cmd}` — "
                               f"псевдотест (echo/printf/cat не запускает тесты)")
    readme_ok = ("Activate.ps1", "activate.bat", "§1a", "GOLDEN_PATH")
    for pat in ("README.md", "templates/README_TEMPLATE.md",
                "examples/reference_python_project/README.md"):
        f = root / pat
        if not f.exists():
            continue
        text = f.read_text(encoding="utf-8", errors="ignore")
        if ".venv/bin/activate" in text and not any(m in text for m in readme_ok):
            out.append(f"{f.relative_to(root)}: POSIX-only активация "
                       f"(`source .venv/bin/activate`) без Windows-эквивалента — добавь "
                       f"`.venv\\Scripts\\Activate.ps1` или ссылку на GOLDEN_PATH_STANDARD §1a")
    return out


# --- prompt catalog + generated overview (v2.9.125) ---
def check_prompt_catalog(root: Path, schemas_root_arg: str | None) -> list[str]:
    """Проверяет Prompt Catalog, digests и read-only audit contracts."""
    out: list[str] = []
    registry_path = root / "prompts" / "registry.json"
    if not registry_path.exists():
        return ["prompt-catalog: нет prompts/registry.json"]
    data, err = load_json(registry_path)
    if err or not isinstance(data, dict):
        return [f"prompt-catalog: битый prompts/registry.json: {err}"]
    schemas_root = resolve_schemas_root(root, schemas_root_arg)
    schema_path = schemas_root / "prompt_registry.schema.json" if schemas_root else None
    if not schema_path or not schema_path.exists():
        out.append("prompt-catalog: не найдена schemas/prompt_registry.schema.json")
    else:
        schema, schema_err = load_json(schema_path)
        if schema_err or not isinstance(schema, dict):
            out.append(f"prompt-catalog: битая schema: {schema_err}")
        else:
            out.extend(validate_schema(data, schema, "prompts/registry.json"))

    entries = data.get("prompts", [])
    if not isinstance(entries, list):
        return out
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    prompts_root = root / "prompts"
    registered: set[str] = set()
    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        raw_id = entry.get("id")
        prompt_id = entry.get("prompt_id")
        pid = prompt_id or raw_id
        if prompt_id and raw_id != prompt_id:
            out.append(f"prompt-catalog: id/prompt_id mismatch: {raw_id} != {prompt_id}")
        for candidate_id in {item for item in (raw_id, prompt_id) if isinstance(item, str)}:
            if candidate_id in seen_ids:
                out.append(f"prompt-catalog: duplicate id {candidate_id!r}")
            seen_ids.add(candidate_id)
        rel = entry.get("path")
        mode = entry.get("mode")
        policy = entry.get("automation_policy")
        if not isinstance(rel, str):
            continue
        if rel in seen_paths:
            out.append(f"prompt-catalog: один path зарегистрирован дважды: {rel}")
        seen_paths.add(rel)
        rel_path = Path(rel)
        if rel_path.is_absolute() or ".." in rel_path.parts:
            out.append(f"prompt-catalog: небезопасный path: {rel}")
            continue
        prompt_path = root / rel_path if rel_path.parts and rel_path.parts[0] == "prompts" else prompts_root / rel_path
        try:
            canonical_rel = prompt_path.resolve().relative_to(prompts_root.resolve()).as_posix()
        except ValueError:
            out.append(f"prompt-catalog: path выходит за prompts/: {rel}")
            continue
        registered.add(canonical_rel)
        if not prompt_path.is_file():
            out.append(f"prompt-catalog: prompt file не найден: {rel}")
            continue
        raw = prompt_path.read_bytes()
        if not raw.strip():
            out.append(f"prompt-catalog: пустой prompt: {rel}")
        actual_hash = hashlib.sha256(raw).hexdigest()
        for hash_field in ("sha256", "content_sha256"):
            expected_hash = entry.get(hash_field)
            if isinstance(expected_hash, str) and expected_hash != actual_hash:
                out.append(f"prompt-catalog: {'SHA-256' if hash_field == 'sha256' else hash_field} не совпадает для {rel}: {expected_hash} != {actual_hash}")
        if mode == "REMEDIATION" and policy == "AUTO_READ_ONLY":
            out.append(f"prompt-catalog: {pid}: REMEDIATION не может иметь AUTO_READ_ONLY")
        if mode == "MIGRATION" and policy != "APPROVAL_REQUIRED":
            out.append(f"prompt-catalog: {pid}: MIGRATION требует APPROVAL_REQUIRED")
        if mode in {"AUDIT_ONLY", "READ_ONLY", "READ_ONLY_EXTENSION"} and policy == "APPROVAL_REQUIRED":
            out.append(f"prompt-catalog: {pid}: read-only prompt не должен маскироваться как write-approved workflow")
        if mode in {"READ_ONLY", "READ_ONLY_EXTENSION"} and entry.get("side_effects_allowed") is not False:
            out.append(f"prompt-catalog: {pid}: side_effects_allowed должен быть false")

    excluded = {"README.md", "PROMPT_CHANGELOG.md"}
    actual_prompts = {
        str(f.relative_to(prompts_root))
        for f in prompts_root.rglob("*.md")
        if f.name not in excluded and "templates" not in f.relative_to(prompts_root).parts
    }
    for rel in sorted(actual_prompts - registered):
        out.append(f"prompt-catalog: production prompt не зарегистрирован: prompts/{rel}")
    for rel in sorted(registered - actual_prompts):
        if (prompts_root / rel).exists():
            out.append(f"prompt-catalog: registry path не относится к production prompt: prompts/{rel}")
    try:
        from prompt_audit_contract import validate_audit_prompt_catalog
        for finding in validate_audit_prompt_catalog(root):
            if finding.severity == "ERROR":
                out.append(f"prompt-catalog: {finding.code}: {finding.message}")
    except (ImportError, OSError, ValueError, json.JSONDecodeError) as exc:
        out.append(f"prompt-catalog: audit prompt contract validator failed: {type(exc).__name__}: {exc}")
    package_manifest = root / "prompt_sources" / "package_manifest.json"
    if package_manifest.exists():
        try:
            from prompt_package import validate_package
            for finding in validate_package(root):
                if finding.severity == "ERROR":
                    out.append(f"prompt-package: {finding.code}: {finding.message}")
        except (ImportError, OSError, ValueError, json.JSONDecodeError) as exc:
            out.append(f"prompt-package: validator failed: {type(exc).__name__}: {exc}")
    return out

def check_memory_governance(root: Path) -> list[str]:
    """Validate memory taxonomy, trust boundary and technology decisions."""
    out: list[str] = []
    try:
        from memory_governance import validate_package
        for finding in validate_package(root):
            if finding.severity == "ERROR":
                out.append(f"memory-governance: {finding.code}: {finding.message}")
    except (ImportError, OSError, ValueError, json.JSONDecodeError) as exc:
        out.append(f"memory-governance: validator failed: {type(exc).__name__}: {exc}")
    return out


def check_rag_action_governance(root: Path) -> list[str]:
    """Validate RAG-to-action modes, trust boundary and typed action catalog."""
    out: list[str] = []
    try:
        from rag_action_governance import validate_package
        for finding in validate_package(root):
            if finding.severity == "ERROR":
                out.append(f"rag-action-governance: {finding.code}: {finding.message}")
    except (ImportError, OSError, ValueError, json.JSONDecodeError) as exc:
        out.append(f"rag-action-governance: validator failed: {type(exc).__name__}: {exc}")
    return out



def check_dead_code(root: Path, profile: str) -> list[str]:
    """Run the production dead-code/reachability validator."""
    out: list[str] = []
    try:
        from dead_code_audit import audit_project
        report = audit_project(root, profile)
        if report.get("status") != "PASS":
            summary = report.get("summary", {})
            out.append(
                "dead-code: status=%s high=%s review=%s invalid_allowlist=%s unknown_entrypoints=%s"
                % (
                    report.get("status"), summary.get("high_confidence_findings", 0),
                    summary.get("review_required_findings", 0), summary.get("invalid_allowlist_entries", 0),
                    summary.get("unknown_entrypoints", 0),
                )
            )
    except (ImportError, OSError, ValueError, json.JSONDecodeError, SyntaxError) as exc:
        out.append(f"dead-code: validator failed: {type(exc).__name__}: {exc}")
    return out


def check_tz_governance_contract(root: Path, *, audit_sequence_only: bool = False) -> list[str]:
    """Validate canonical TZ lifecycle and machine-readable audit ordering."""
    from tz_governance import run_all_checks, validate_audit_sequence

    findings = validate_audit_sequence(root) if audit_sequence_only else run_all_checks(root)
    # WARNING больше не отбрасывается молча: до v2.9.157 сюда попадали только
    # ERROR, поэтому предупреждение не могло дойти до пользователя вообще, и
    # уровень WARNING был декоративным. Теперь оно видно и поднимается до
    # ошибки флагом --warnings-as-errors.
    return [
        (WARN_PREFIX if item.severity == "WARNING" else "") + f"{item.code}:{item.rule_id}:{item.message}"
        for item in findings
        if item.severity in {"ERROR", "WARNING"}
    ]

def _overview_capability_names(root: Path) -> list[str]:
    text = (root / "CAPABILITIES.md").read_text(encoding="utf-8", errors="ignore") if (root / "CAPABILITIES.md").exists() else ""
    out: list[str] = []
    active = False
    for line in text.splitlines():
        if line.startswith("| Слой |"):
            active = True
            continue
        if not active:
            continue
        if line.startswith("|---"):
            continue
        if not line.startswith("|"):
            if out:
                break
            continue
        cell = line.strip("|").split("|", 1)[0].strip()
        cell = re.sub(r"[`*]", "", cell).strip()
        if cell:
            out.append(cell)
    return out


def check_standard_overview(root: Path) -> list[str]:
    """Проверяет generated HTML и его детерминированное соответствие sources."""
    out: list[str] = []
    html_path = root / "STANDARD_OVERVIEW.html"
    generator = root / "tools" / "generate_standard_overview.py"
    if not html_path.exists():
        return ["standard-overview: нет STANDARD_OVERVIEW.html"]
    if not generator.exists():
        return ["standard-overview: нет tools/generate_standard_overview.py"]
    html = html_path.read_text(encoding="utf-8", errors="ignore")
    manifest, err = load_json(root / "manifest.json")
    version = manifest.get("version") if isinstance(manifest, dict) else None
    if isinstance(version, str) and f'content="{version}"' not in html:
        out.append(f"standard-overview: HTML не содержит manifest.version={version}")
    for anchor in ("benefits", "flow", "verification-profiles", "capabilities", "prompt-catalog", "runtime-profiles", "ai-use", "sources", "start", "limits"):
        if f'id="{anchor}"' not in html:
            out.append(f"standard-overview: нет обязательного anchor #{anchor}")
    if re.search(r"<script[^>]+src=[\"']https?://", html, re.IGNORECASE):
        out.append("standard-overview: запрещён внешний script dependency")
    if re.search(r"(?:cdn\.|google-analytics|googletagmanager|plausible\.io)", html, re.IGNORECASE):
        out.append("standard-overview: обнаружен CDN/analytics dependency")
    for href in re.findall(r"href=[\"']([^\"']+)[\"']", html):
        if href.startswith(("#", "http://", "https://", "mailto:")):
            continue
        local = href.split("#", 1)[0]
        if local and not (root / local).exists():
            out.append(f"standard-overview: битая локальная ссылка: {href}")
    for name in _overview_capability_names(root):
        if escape_html_text(name) not in html and name not in html:
            out.append(f"standard-overview: capability не отражена: {name}")
    registry, reg_err = load_json(root / "prompts" / "registry.json")
    if not reg_err and isinstance(registry, dict):
        for item in registry.get("prompts", []):
            pid = item.get("id") if isinstance(item, dict) else None
            if isinstance(pid, str) and pid not in html:
                out.append(f"standard-overview: prompt id не отражён: {pid}")
    if "Project-owned profile" not in html:
        out.append("standard-overview: граница project-owned runtime profile не отражена")
    try:
        with tempfile.TemporaryDirectory(prefix="aps-overview-") as td:
            generated = Path(td) / "STANDARD_OVERVIEW.html"
            proc = subprocess.run(
                [sys.executable, str(generator), "--root", str(root), "--output", str(generated)],
                cwd=root, capture_output=True, text=True, timeout=60, check=False,
            )
            if proc.returncode != 0:
                out.append(f"standard-overview: generator exit={proc.returncode}: {(proc.stderr or proc.stdout).strip()[:500]}")
            elif generated.read_bytes() != html_path.read_bytes():
                out.append("standard-overview: tracked HTML устарел — generator создаёт diff")
    except (OSError, subprocess.TimeoutExpired) as exc:
        out.append(f"standard-overview: не удалось проверить generator: {exc}")
    return out


def escape_html_text(value: str) -> str:
    return (value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                 .replace('"', "&quot;").replace("'", "&#x27;"))


# ======================================================================
# RELEASE VERSIONED COMMANDS — APS-RELEASE-VERSION-SYNC-001
# ======================================================================

@enforces_rule("APS-RELEASE-VERSION-SYNC-001")
@emits_diagnostic("APS-RELEASE-VERSION-SYNC-001", "RELEASE_VERSIONED_COMMANDS_VALID")
@emits_diagnostic("APS-RELEASE-VERSION-SYNC-001", "RELEASE_INSTALLATION_RECEIPT_VERSION_MISMATCH")
@emits_diagnostic("APS-RELEASE-VERSION-SYNC-001", "RELEASE_VERSIONED_COMMAND_DRIFT")
def validate_versioned_receipt_commands(root: Path, version: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    expected = version.replace(".", "_")
    readme = root / "README.md"
    if not readme.is_file():
        return [RuleFinding("RELEASE_VERSIONED_COMMAND_DRIFT", "APS-RELEASE-VERSION-SYNC-001", "README.md is missing.", "ERROR", {})]
    text = readme.read_text(encoding="utf-8", errors="ignore")
    for match in re.finditer(r"V(\d+_\d+_\d+)_INSTALLATION_RECEIPT\.json", text):
        if match.group(1) != expected:
            findings.append(RuleFinding(
                "RELEASE_INSTALLATION_RECEIPT_VERSION_MISMATCH",
                "APS-RELEASE-VERSION-SYNC-001",
                "Installation receipt command uses a stale release version.",
                "ERROR",
                {"observed": match.group(1), "expected": expected},
            ))
    for match in re.finditer(r"V(\d+_\d+_\d+)_(?:RELEASE_RECEIPT|RELEASE_EVIDENCE)\.(?:json|zip)", text):
        if match.group(1) != expected:
            findings.append(RuleFinding(
                "RELEASE_VERSIONED_COMMAND_DRIFT",
                "APS-RELEASE-VERSION-SYNC-001",
                "Release command uses a stale version-bearing evidence filename.",
                "ERROR",
                {"observed": match.group(1), "expected": expected},
            ))
    if not findings:
        findings.append(RuleFinding(
            "RELEASE_VERSIONED_COMMANDS_VALID",
            "APS-RELEASE-VERSION-SYNC-001",
            "Version-bearing receipt and evidence commands match manifest.version.",
            "INFO",
            {"version": version},
        ))
    return findings


# ======================================================================
# CANONICAL RELEASE HEADING — APS-RELEASE-HEADING-SYNC-001
# ======================================================================

@enforces_rule("APS-RELEASE-HEADING-SYNC-001")
@emits_diagnostic("APS-RELEASE-HEADING-SYNC-001", "RELEASE_CANONICAL_HEADING_VALID")
@emits_diagnostic("APS-RELEASE-HEADING-SYNC-001", "RELEASE_CANONICAL_HEADING_VERSION_MISMATCH")
def validate_canonical_release_heading(root: Path, version: str) -> list[RuleFinding]:
    readme = root / "README.md"
    if not readme.is_file():
        return [RuleFinding(
            "RELEASE_CANONICAL_HEADING_VERSION_MISMATCH",
            "APS-RELEASE-HEADING-SYNC-001",
            "README.md is missing; canonical release heading cannot be verified.",
            "ERROR",
            {"expected": version},
        )]
    text = readme.read_text(encoding="utf-8", errors="ignore")
    heading_re = re.compile(r"(?mi)^##[ \t]+(?P<title>[^\n]+?)[ \t]*$")
    phrase_re = re.compile(r"(?:Канонический[ \t]+выпуск|Canonical[ \t]+release)", re.IGNORECASE)
    version_re = re.compile(r"v(?P<version>\d+\.\d+\.\d+)", re.IGNORECASE)
    historical_re = re.compile(r"\b(?:HISTORICAL|ARCHIVED)\b", re.IGNORECASE)
    candidates: list[dict[str, Any]] = []
    for match in heading_re.finditer(text):
        title = match.group("title").strip()
        if not phrase_re.search(title):
            continue
        version_match = version_re.search(title)
        if not version_match:
            continue
        candidates.append({
            "heading": match.group(0),
            "title": title,
            "version": version_match.group("version"),
            "historical": bool(historical_re.search(title)),
        })
    active = [item for item in candidates if not item["historical"]]
    if len(active) != 1:
        return [RuleFinding(
            "RELEASE_CANONICAL_HEADING_VERSION_MISMATCH",
            "APS-RELEASE-HEADING-SYNC-001",
            "README must contain exactly one active canonical release heading; stale headings are allowed only when the same heading is marked HISTORICAL or ARCHIVED.",
            "ERROR",
            {"expected": version, "active_candidates": active, "all_candidates": candidates},
        )]
    candidate = active[0]
    if candidate["version"] != version:
        return [RuleFinding(
            "RELEASE_CANONICAL_HEADING_VERSION_MISMATCH",
            "APS-RELEASE-HEADING-SYNC-001",
            "Canonical release heading uses a stale standard version.",
            "ERROR",
            {"observed": candidate["version"], "expected": version, "heading": candidate["heading"]},
        )]
    return [RuleFinding(
        "RELEASE_CANONICAL_HEADING_VALID",
        "APS-RELEASE-HEADING-SYNC-001",
        "Exactly one active canonical release heading matches manifest.version; stale candidates are explicitly historical or archived.",
        "INFO",
        {"version": version, "candidate_count": len(candidates)},
    )]


# --- version-sync: версия едина по всем точкам пакета ---
def check_version_sync(root: Path) -> list[str]:
    """Сверяет manifest.version с: distribution.artifact, based_on, главным
    заголовком README, заголовком канонического выпуска, underscored-ссылками
    README (дерево/архив), статусной строкой
    RELEASE_NOTES, верхней версией CHANGELOG. Для профиля standard-package:
    версия-хвосты трижды всплывали в ревью — теперь ловятся машинно."""
    out: list[str] = []
    mf, err = load_json(root / "manifest.json")
    if err or not isinstance(mf, dict):
        return ["version-sync: не читается manifest.json"]
    ver = mf.get("version")
    if not isinstance(ver, str) or not re.match(r"^\d+\.\d+\.\d+$", ver):
        return ["version-sync: manifest.version отсутствует или не X.Y.Z"]
    vu = ver.replace(".", "_")
    for finding in validate_versioned_receipt_commands(root, ver):
        if finding.severity == "ERROR":
            out.append(f"version-sync: {finding.code}: {finding.message}")
    for finding in validate_canonical_release_heading(root, ver):
        if finding.severity == "ERROR":
            out.append(f"version-sync: {finding.code}: {finding.message}")
    # 1. distribution.artifact
    dist = (mf.get("distribution") or {}).get("artifact")
    expected_zip = f"agent_project_standard_v{vu}.zip"
    if isinstance(dist, str) and dist != expected_zip:
        out.append(f"version-sync: distribution.artifact = {dist}, ожидается {expected_zip}")
    # 2. based_on доведён до текущей версии
    based = mf.get("based_on")
    if isinstance(based, str) and f"→ v{ver}" not in based:
        out.append(f"version-sync: based_on не доведён до v{ver}")
    # 2a. status (v2.9.114, P2 внешнего ревью v2.9.113, репродуцировано:
    # manifest.status годами нёс собственный "vX.Y.Z"-хвост, который version-
    # sync никогда не проверял — версия успела разойтись на 2 релиза, прежде
    # чем поймано). Ищем ЛЮБОЙ "vX.Y.Z" в строке status, а не точное
    # совпадение всей строки — status несёт больше текста, чем просто версию.
    status_val = mf.get("status")
    if isinstance(status_val, str):
        sm = re.search(r"v(\d+\.\d+\.\d+)", status_val)
        if sm and sm.group(1) != ver:
            out.append(f"version-sync: manifest.status ссылается на v{sm.group(1)}, текущая v{ver}: {status_val[:80]}")
    # 3-4. README: заголовок + underscored-ссылки (история в булетах пишется
    # точечно v2.9.38 и под underscored-паттерн не попадает)
    readme = root / "README.md"
    if readme.exists():
        text = readme.read_text(encoding="utf-8", errors="ignore")
        first = text.splitlines()[0] if text else ""
        if first.startswith("#") and f"(v{ver})" not in first:
            out.append(f"version-sync: заголовок README не содержит (v{ver}): {first[:80]}")
        for m in re.finditer(r"agent_project_standard_v(\d+_\d+_\d+)", text):
            if m.group(1) != vu:
                out.append(f"version-sync: README ссылается на agent_project_standard_v{m.group(1)}, текущая v{vu}")
    # 5. RELEASE_NOTES: активный журнал определяется линией X.Y текущей
    # версии. Журналы прежних линий остаются историческими и не меняются.
    major, minor, _patch = ver.split(".")
    rn = root / f"RELEASE_NOTES_v{major}_{minor}.md"
    if rn.exists():
        rtext = rn.read_text(encoding="utf-8", errors="ignore")
        status = next((l for l in rtext.splitlines() if l.startswith("Статус:")), "")
        if status and f"v{ver}" not in status:
            out.append(f"version-sync: статус RELEASE_NOTES не v{ver}: {status[:80]}")
    # 6. CHANGELOG: верхняя версия
    ch = root / "CHANGELOG.md"
    if ch.exists():
        top = next((l for l in ch.read_text(encoding="utf-8", errors="ignore").splitlines()
                    if l.startswith("## v")), "")
        if top and not top.startswith(f"## v{ver} "):
            out.append(f"version-sync: верхняя версия CHANGELOG не v{ver}: {top[:60]}")
    # v2.9.126: manifest declares every version-bearing document.
    for rel in mf.get("version_bearing_files", []) or []:
        if not isinstance(rel, str) or not rel:
            continue
        fp = root / rel
        if not fp.exists():
            out.append(f"version-sync: version-bearing file отсутствует: {rel}")
            continue
        text = fp.read_text(encoding="utf-8", errors="ignore")
        versions = set(re.findall(r"v(\d+\.\d+\.\d+)", text))
        current_mentions = ver in versions
        if not current_mentions:
            out.append(f"version-sync: {rel} не содержит текущую v{ver}")
    # v2.9.171: часть JSON-реестров обязана идти в ногу с версией пакета, и
    # version_bearing_files их не покрывает — там markdown и html. Расхождение
    # жило молча: в цикле 2.9.170 три таких файла всплыли только потому, что
    # их сверяет с манифестом --check-dead-code.
    #
    # Список объявляется явно, а не выводится обходом всех JSON с полем
    # standard_version. У большинства реестров это поле означает «версия, в
    # которой контракт менялся последний раз»: audit_sequence несёт 2.9.157,
    # профили памяти — 2.9.145, trusted_tools_manifest — 2.9.151 и вдобавок
    # закрыт внешним SHA-256 pin. Требовать от них текущую версию значило бы
    # заставить их записать неправду о собственной истории.
    for rel in mf.get("version_bearing_registries", []) or []:
        if not isinstance(rel, str) or not rel:
            continue
        fp = root / rel
        if not fp.is_file():
            out.append(f"version-sync: version-bearing registry отсутствует: {rel}")
            continue
        data, jerr = load_json(fp)
        if jerr or not isinstance(data, dict):
            out.append(f"version-sync: не читается version-bearing registry: {rel}")
            continue
        declared = data.get("standard_version")
        if declared != ver:
            out.append(f"version-sync: {rel}.standard_version = {declared}, ожидается {ver}")
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", choices=["target-project", "standard-package", "architect_library"], default="target-project")
    parser.add_argument("--language-profile", choices=["ru_internal", "en_public", "mixed"], default="ru_internal", help="какие doc-файлы и каталог спеки обязательны")
    parser.add_argument("--check-registry", action="store_true")
    parser.add_argument("--check-schemas", action="store_true", help="проверить docs/registry/*.json по schemas/*.schema.json")
    parser.add_argument("--check-paths", action="store_true", help="проверить существование путей из registry")
    parser.add_argument("--check-symbols", action="store_true", help="проверить public Python-символы из functions.json через ast")
    parser.add_argument("--check-registry-completeness", action="store_true", help="обратное направление: каждый публичный символ кода (module-level function/class без ведущего _) заявлен в functions.json, иначе — waiver с reason (v2.9.91)")
    parser.add_argument("--check-skills", action="store_true", help="проверить front-matter навыков skills/**/SKILL.md по skill.schema.json")
    parser.add_argument("--check-agent-config", action="store_true", help="единый AGENTS.md, один конфиг на инструмент, реальные пути")
    parser.add_argument("--check-reference-data", action="store_true", help="ref/*-зеркала помечены (_MIRROR.md или _mirror_of)")
    parser.add_argument("--check-spec-sync", action="store_true", help="спека DONE ссылается на существующие тесты (живая спека)")
    parser.add_argument("--check-manifest", action="store_true", help="manifest.json сверяется с фактическим составом пакета")
    parser.add_argument("--check-skills-manifest", action="store_true", help="skills.manifest.json: выбранные скилы валидны и присутствуют")
    parser.add_argument("--check-hardcode", action="store_true", help="эвристика: захардкоженные URL и абсолютные пути в .py")
    parser.add_argument("--check-user-functions", action="store_true", help="docs/registry/user_functions.json: схема, id, ACTIVE/critical, пути, related_registry")
    parser.add_argument("--check-user-function-interfaces", action="store_true", help="v2.9.173: у ACTIVE-функции обе двери — визуальная (kind=ui) и через помощника (kind=assistant); опционально, у библиотек и CLI визуального интерфейса нет законно")
    parser.add_argument("--check-user-function-registry", action="store_true", help="v2.9.128: lifecycle-aware user_functions.json")
    parser.add_argument("--check-function-registry", action="store_true", help="v2.9.128: technical symbol registry + AST existence")
    parser.add_argument("--check-function-duplication", action="store_true", help="v2.9.128: duplicate IDs/symbols/signatures/routes/CLI/semantic intents")
    parser.add_argument("--check-registry-task-linkage", action="store_true", help="v2.9.128: task ↔ user/technical function ↔ lease linkage")
    parser.add_argument("--check-function-lifecycle", action="store_true", help="v2.9.128: machine-readable function lifecycle transitions")
    parser.add_argument("--check-change-journal", action="store_true", help="v2.9.128: append-only change journal and lifecycle chain")
    parser.add_argument("--check-function-test-evidence", action="store_true", help="v2.9.128: targeted/affected/full trusted evidence")
    parser.add_argument("--check-function-merge-status", action="store_true", help="v2.9.128: MERGED/DONE commit is in protected main")
    parser.add_argument("--check-project-snapshot", action="store_true", help="docs/PROJECT_SNAPSHOT.md + project_snapshot.json: схема, ссылки на user_functions, spec_dir")
    parser.add_argument("--check-test-runner", action="store_true", help="docs/registry/test_runner.json: схема, registry-путь, env-плейсхолдеры без хардкода")
    parser.add_argument("--check-project-layout", action="store_true", help="раскладка проекта по PROJECT_LAYOUT_STANDARD (README/AGENTS/pyproject/src/tests/docs/registry/configs)")
    parser.add_argument("--check-entrypoints", action="store_true", help="canonical entrypoint (python -m / [project.scripts]); bin/ — только thin wrappers")
    parser.add_argument("--check-launch-section", action="store_true", help="раздел `Запуск` в README.md: основная команда и глаголы языкового профиля")
    parser.add_argument("--check-docs-sections-declared", action="store_true", help="каталог docs/ вне известного списка объявлен в docs/README.md (DOCUMENTATION_STANDARD §2.1)")
    parser.add_argument("--check-file-size", action="store_true", help="лимиты размера: .py>800, .md>900, функция>120, класс>500 (SOURCE_FILE_STANDARD)")
    parser.add_argument("--check-code-language", action="store_true", help="ASCII-идентификаторы, UPPER_SNAKE env, snake_case config keys (CODE_LANGUAGE_POLICY)")
    parser.add_argument("--check-best-style", action="store_true", help="агрегатор инженерного стиля: layout+entrypoints+file-size+code-language+hardcode+user-functions+project-snapshot+test-runner")
    parser.add_argument("--check-pattern-memory", action="store_true", help="память паттернов: SUCCESS_PATTERNS/ANTI_PATTERNS + engineering_patterns.json (LEARNING_LOOP_STANDARD)")
    parser.add_argument("--check-markdown-links", action="store_true", help="локальные относительные markdown-ссылки резолвятся (внешние/якоря/код-блоки пропускаются)")
    parser.add_argument("--check-loop-safe-mutation", action="store_true", help="коллекция не изменяется во время обхода её же самой: for x in items с items.append/remove/del items[...] в теле — молчаливый пропуск элементов у list, RuntimeError у dict/set (CC-LOOP-SAFE-MUTATION, v2.9.158)")
    parser.add_argument("--check-data-in-code", action="store_true", help="крупные литеральные справочники/прайсы/каталоги в .py вне reference/ (НСИ не в коде)")
    parser.add_argument("--check-release-hygiene", action="store_true", help="в поставке нет артефактов сборки/кэшей (.pytest_cache, __pycache__, *.pyc, .DS_Store, dist/build, …)")
    parser.add_argument("--check-test-coverage", action="store_true", help="regression-guard: каждый ACTIVE public символ functions.json покрыт тестом в test_coverage.json")
    parser.add_argument("--check-knowledge-index", action="store_true", help="docs/registry/knowledge_index.json: схема, реальность summary_first/digests, адрес вектор-базы только через env (KNOWLEDGE_INDEX_STANDARD)")
    parser.add_argument("--check-entitlements", action="store_true", help="docs/registry/entitlements.json: схема, адрес Hub через env, covers→user_functions, уникальные module_code (ENTITLEMENTS_STANDARD)")
    parser.add_argument("--check-dependency-policy", action="store_true", help="менеджер зависимостей: lock-файл соответствует manager, конфликт lock-файлов без policy, requirements.txt-роль названа, CI-команда сверяется эвристически (DEPENDENCY_MANAGEMENT_STANDARD)")
    parser.add_argument("--check-dependency-selection-policy", action="store_true", help="docs/registry/dependency_decisions.json: risky maintenance_status (archived/deprecated/unmaintained) требует decision=accepted_with_waiver+waiver_reason, не тихий accepted (DEPENDENCY_MANAGEMENT_STANDARD §6)")
    parser.add_argument("--check-tooling-security-review", action="store_true", help="docs/registry/tooling_security_reviews.json: ИБ-ревью внешних Skills/MCP/плагинов перед установкой — source=external/unknown или red_flags_found требует approved_with_waiver+waiver_reason; плюс эвристический скан SKILL.md на red-flag паттерны (TOOLING_SECURITY_REVIEW_STANDARD)")
    parser.add_argument("--check-tool-candidates", action="store_true", help="tool_candidates.json: обнаружение создаёт рекомендацию, а EVALUATED требует pinned version/commit и evidence реального пилота")
    parser.add_argument("--check-approved-tools", action="store_true", help="approved_tools.json: только pinned инструменты с разрешающей ИБ-проверкой; binary/download требует checksum")
    parser.add_argument("--check-verification-evidence", action="store_true", help="FAST/ASSURED/CRITICAL: структурированные evidence-слои с trusted check_ref, approved tool_ref и существующими artifacts")
    parser.add_argument("--check-module-registry", action="store_true", help="docs/registry/module_registry.json: границы независимых модулей — уникальность id, root/public_api не выходят за --root, id не в собственном must_not_import (MODULE_BOUNDARIES_STANDARD §10.1)")
    parser.add_argument("--check-code-ownership", action="store_true", help="docs/registry/code_ownership.json: path не выходит за --root, без точных дубликатов пути (MODULE_BOUNDARIES_STANDARD §10.2)")
    parser.add_argument("--check-module-boundaries", action="store_true", help="AST: запрещённые импорты по module_registry.json[].must_not_import — только абсолютные импорты, только явный denylist (MODULE_BOUNDARIES_STANDARD §11)")
    parser.add_argument("--check-work-package-graph", action="store_true", help="docs/registry/work_package_graph.json: уникальность id, неизвестные depends_on, self-dependency, циклы, зависимость от FAILED, WIP/DONE до готовности предпосылки (MODULE_BOUNDARIES_STANDARD §10.3)")
    parser.add_argument("--check-work-package-overlap", action="store_true", help="docs/registry/active_work_packages.json: уникальность task_id, allowed_paths не выходят за --root, пересечение allowed_paths между разными активными задачами (MODULE_BOUNDARIES_STANDARD §10.4)")
    parser.add_argument("--check-active-task-diff", action="store_true", help="Реальный git diff (committed since --base-ref + staged + unstaged + untracked) против allowed_paths активной задачи --task-id в active_work_packages.json (MODULE_BOUNDARIES_STANDARD §10.4)")
    parser.add_argument("--task-id", default=None, help="task_id из active_work_packages.json — обязателен вместе с --check-active-task-diff")
    parser.add_argument("--base-ref", default=None, help="git-ref для сравнения committed-изменений (--check-active-task-diff); по умолчанию HEAD (только staged/unstaged/untracked)")
    parser.add_argument("--protected-ref", default="HEAD", help="protected main ref for MERGED/DONE verification")
    parser.add_argument("--current-branch", default=None, help="Имя реально проверяемой ветки (--check-active-task-diff); если задан — активная аренда --task-id обязана быть привязана именно к этой ветке, иначе жёсткая ошибка (v2.9.121, P1 внешнего аудита v2.9.120: TASK_ID из workflow_dispatch/repository variable сам по себе не привязан к ветке)")
    parser.add_argument("--check-lease-expiry", action="store_true", help="Opt-in runtime-проверка: heartbeat_at/lease_expires_at активных аренд в active_work_packages.json против --now (или реального текущего времени) — единственная проверка в этом инструменте, зависящая от wall-clock; НЕ входит в статический release-gate (v2.9.119, §15 внешнего аудита v2.9.118)")
    parser.add_argument("--now", default=None, help="ISO-8601 datetime с timezone для --check-lease-expiry (тестируемость/детерминизм); по умолчанию — реальное текущее время (UTC)")
    parser.add_argument("--check-parallel-ai-development", action="store_true", help="docs/registry/project_profile.json.parallel_ai_development.enabled: если true, 4 модульных registry-файла обязательны и агрегирует их собственные проверки (MODULE_BOUNDARIES_STANDARD §11)")
    parser.add_argument("--check-sync-policy", action="store_true", help="docs/registry/sync_jobs.json: каналы по классам, bidirectional только documents, rsync one_way+dry-run, restic retention+check, секреты не синкаются (SYNC_AND_BACKUP_STANDARD)")
    parser.add_argument("--check-encrypted-env", action="store_true", help="секреты через .env.enc: .env не в Git, !.env.enc в .gitignore, бандл не plaintext, passphrase_env в env_vars без default (ENCRYPTED_ENV_STANDARD)")
    parser.add_argument("--check-automation-jobs", action="store_true", help="docs/registry/automation_jobs.json: lock/redact/notify/retention/dry-run, command без cat .env/printenv/секретов (AUTOMATION_SERVER_SYNC_STANDARD)")
    parser.add_argument("--check-git-agent-policy", action="store_true", help="docs/registry/git_agent_policy.json: forbid_force_push/forbid_push_to_protected_branches нельзя выключить (GIT_AGENT_WORKFLOW_STANDARD)")
    parser.add_argument("--check-agent-results", action="store_true", help="docs/registry/agent_results/*.json: структурированный результат работы агента вместо свободного текста (AGENT_RESULT_CONTRACT, v2.9.93)")
    parser.add_argument("--check-agent-task-contracts", action="store_true", help="docs/registry/agent_tasks/*.json: машинный контракт задачи AI -> AI — 10 обязательных элементов, пути не выходят за root, allowed/forbidden не пересекаются, без placeholder (AI_TO_AI_COMMUNICATION_STANDARD, v2.9.111); включает check-check-registry")
    parser.add_argument("--check-check-registry", action="store_true", help="docs/registry/check_registry.json: реестр утверждённых машинных проверок (trusted check registry) — required_checks[].check_ref ссылается сюда вместо свободного argv; та же argv-эвристика, что и у required_checks (v2.9.122, P1 внешнего аудита v2.9.121 §9)")
    parser.add_argument("--check-agent-workflow-integrity", action="store_true", help="агрегатор: task_contracts+results+work_package_graph+work_package_overlap как единая система (без дублей) + task существует в graph (parallel-mode hard error) — удобно для разового прогона вместо перечисления 4 отдельных флагов (AI_TO_AI_COMMUNICATION_STANDARD §9, v2.9.118)")
    parser.add_argument("--check-classical-engineering-foundations", action="store_true", help="reference/classical_engineering_foundations.json: трассировка классических принципов (Code Complete/Design Patterns/Clean Architecture/Clean Code/Refactoring) — без дублей id, implemented_in указывает на существующий путь (CLASSICAL_ENGINEERING_FOUNDATIONS.md, v2.9.116)")
    parser.add_argument("--check-git-workspace-hygiene", action="store_true", help="docs/registry/git_workspace_hygiene.json: primary workspace на защищённой ветке без feature-разработки, unmerged branch/dirty worktree не удаляются автоматически, post-merge cleanup обязателен, remote prune только через dry-run (GIT_WORKSPACE_HYGIENE_STANDARD)")
    parser.add_argument("--check-code-audit-policy", action="store_true", help="docs/registry/code_audit_jobs.json: after_task/ci/scheduled — команды без утечки секретов, scheduled job'ы валидны (AUTOMATED_CODE_AUDIT_STANDARD)")
    parser.add_argument("--check-license-integration-policy", action="store_true", help="docs/registry/license_integration_policy.json: hub_url_env через env, fail-open требует fail_open_reason, entitlements_ref/encrypted_env_ref существуют, cache_ttl_seconds положителен (LICENSE_SERVER_INTEGRATION_STANDARD)")
    parser.add_argument("--check-qai-fabric-policy", action="store_true", help="docs/registry/qai_fabric_policy.json: quality_profile с высокостейковым классом требует enabled=true, commands.validate+smoke/nightly, ci.profile не nightly, scheduled.orchestrator=automation_server (QAI_FABRIC_ADAPTER_STANDARD)")
    parser.add_argument("--check-golden-path-portability", action="store_true", help="активные templates/registry/CI не учат голому pytest (нужен python -m pytest); README не POSIX-only по активации venv (GOLDEN_PATH_STANDARD §1a)")
    parser.add_argument("--check-prompt-catalog", action="store_true", help="prompts/registry.json: schema, unique IDs/paths, SHA-256, mode/automation safety и отсутствие незарегистрированных production prompts (PROMPT_CATALOG_AND_EXECUTION_STANDARD)")
    parser.add_argument("--check-standard-overview", action="store_true", help="STANDARD_OVERVIEW.html: version, sections, local links, capabilities/prompts/runtime profile, no CDN/scripts и deterministic rebuild")
    parser.add_argument("--check-memory-governance", action="store_true", help="memory taxonomy, raw/derived layers, trust boundary, exact graph identity, degraded mode and technology selection profile")
    parser.add_argument("--check-rag-action-governance", action="store_true", help="ANSWER/PROPOSE/EXECUTE/VERIFY modes, RAG/live-state boundary, Trusted Action Catalog, risk, receipts and result verification")
    parser.add_argument("--check-dead-code", action="store_true", help="Python high-confidence dead code, production/test reachability, dynamic entrypoints and bounded allowlist")
    parser.add_argument("--check-tz-governance", action="store_true", help="единый корень ТЗ, status authority, DONE evidence, independent verification and duplicates")
    parser.add_argument("--check-audit-sequence", action="store_true", help="machine-readable 00→10→20/25→30→90 audit DAG and read-only modes")
    parser.add_argument("--check-control-plane-integrity", action="store_true", help="trusted governance snapshot: policy и implementation не меняются в одном PR")
    parser.add_argument("--check-ci-security", action="store_true", help="GitHub Actions: minimal permissions, SHA-pinned actions, no pull_request_target")
    parser.add_argument("--check-standard-capabilities", action="store_true", help="reference/standard_capabilities.json: schema/evidence + generated CAPABILITIES.md")
    parser.add_argument("--check-capability-evidence", action="store_true", help="v2.9.128: structured executable positive/negative/bypass evidence semantics")
    parser.add_argument("--check-ecosystem-reuse", action="store_true", help="docs/registry/reuse_decisions.json: закреплённый канон, adopted/expected/local/waiver/proposed, реальная зависимость и интеграционный тест")
    parser.add_argument("--check-ecosystem-profile", action="store_true", help="две оси профиля проекта, два интерфейса, OpenAPI 3.2.0, локализация, доступность, платформы и специальные границы")
    parser.add_argument("--check-runtime-resource-safety", action="store_true", help="docs/registry/runtime_resource_safety.json: тяжёлые локальные операции, три режима допуска, подтверждение, координация и честный статус раскатки")
    parser.add_argument("--reuse-decisions-path", default=None, help="локальный reuse_decisions.json; по умолчанию docs/registry/reuse_decisions.json")
    parser.add_argument("--ecosystem-profile-path", default=None, help="локальный ecosystem_project_profile.json; по умолчанию docs/registry/ecosystem_project_profile.json")
    parser.add_argument("--runtime-resource-safety-path", default=None, help="локальный runtime_resource_safety.json; по умолчанию docs/registry/runtime_resource_safety.json")
    parser.add_argument("--standard-repository", default=None, help="репозиторий стандарта для проверки заявления rolled_out")
    parser.add_argument("--resource-safety-consumer-root", default=None, help="корень реального проекта-потребителя для проверки его docs/dev/standard/SOURCE.json")
    parser.add_argument("--canonical-registry", default=None, help="явно переданный канонический shared_modules.yaml; не копируется в проект")
    parser.add_argument("--changed-http-contract", action="append", default=[], help="путь нового/изменённого HTTP-договора; можно передать несколько раз")
    parser.add_argument("--owner-boundary-artifact", action="append", default=[], help="явный договор владельца: repository:path@version=artifact; можно передать несколько раз")
    parser.add_argument("--check-version-sync", action="store_true", help="версия едина во всех manifest.version_bearing_files, artifact, README, RELEASE_NOTES, CHANGELOG")
    parser.add_argument("--check-rule-traceability", action="store_true", help="APS-RULE-ID-001: stable rule IDs link docs, registry, implementation, exact tests and diagnostics")
    parser.add_argument("--check-rule-inventory", action="store_true", help="APS-RULE-INVENTORY-001: complete declared-root human rule inventory")
    parser.add_argument("--check-rule-semantic-continuity", action="store_true", help="APS-RULE-SEMANTIC-001: previous-release ID and semantic digest continuity")
    parser.add_argument("--check-rule-implementation-linkage", action="store_true", help="APS-RULE-STRUCTURAL-001: exact implementation symbols and gate reachability")
    parser.add_argument("--check-rule-diagnostics", action="store_true", help="APS-RULE-STRUCTURAL-001: exact structured diagnostic linkage")
    parser.add_argument("--check-rule-test-evidence", action="store_true", help="APS-RULE-STRUCTURAL-001: behavioral positive/negative/bypass test linkage")
    parser.add_argument("--artifact", default=None, help="путь к собранному ZIP — проверить по listing (без распаковки): нет venv/кэшей/*.pyc/*.egg-info/*.dist-info/секретов в самой поставке (release-artifact)")
    parser.add_argument("--schemas-root", default=None, help="путь к папке schemas/; по умолчанию ищется в проекте и рядом с валидатором")
    parser.add_argument("--warnings-as-errors", action="store_true", help="считать предупреждения ([warning]) ошибкой (exit 1); по умолчанию warning не влияет на exit code")
    parser.add_argument("--print-parallel-mode", action="store_true", help="утилитарный режим (не release-gate): печатает true/false — доверенное (см. _parallel_mode_enabled_trusted) значение parallel_ai_development.enabled — и выходит немедленно, не запуская остальные --check-*. v2.9.123 (P1 внешнего аудита v2.9.122, A-2): решение больше не пересчитывается заново в bash каждого CI-шаблона отдельно — инструмент единственный источник истины, вызывающий может требовать её через --require-resolved-base-ref")
    parser.add_argument("--require-resolved-base-ref", action="store_true", help="с --print-parallel-mode: если задан --base-ref, но он не резолвится (git rev-parse --verify --quiet), команда завершается с exit 2 и НЕ печатает потенциально ненадёжное значение, вместо тихой деградации к live-только сравнению (v2.9.123, P1 внешнего аудита v2.9.122, A-2)")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    if args.print_parallel_mode:
        if args.base_ref and args.require_resolved_base_ref and not _git_ref_resolves(root, args.base_ref):
            print(f"--base-ref={args.base_ref!r} не резолвится (git rev-parse --verify --quiet) — "
                  f"доверенное значение parallel_ai_development.enabled получить нельзя "
                  f"(v2.9.123, A-2)", file=sys.stderr)
            return 2
        resolved_ref, _ = _resolve_merge_base(root, args.base_ref) if args.base_ref else (None, None)
        print("true" if _parallel_mode_enabled_trusted(root, resolved_ref) else "false")
        return 0
    if args.profile == "standard-package":
        problems = missing(root, PACKAGE_REQUIRED)
    elif args.profile == "architect_library":
        from architect_readiness import validate_architect_library
        architect_findings = validate_architect_library(root)
        for finding in architect_findings:
            print("APS_ARCH_DIAGNOSTIC:" + json.dumps(
                finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ))
        problems = [
            f"{finding.code}:{finding.rule_id}:{finding.message}"
            for finding in architect_findings
            if finding.severity == "ERROR"
        ]
    else:
        problems = project_doc_problems(root, args.language_profile) + check_statuses(root, args.language_profile)
        if args.check_registry or args.check_schemas or args.check_paths or args.check_symbols:
            problems += check_registry(root, args.check_schemas, args.check_paths, args.check_symbols, args.schemas_root)
        if args.check_registry_completeness:
            problems += check_registry_completeness(root)
    if args.check_skills:
        problems += check_skills(root, args.schemas_root)
    if args.check_agent_config:
        problems += check_agent_config(root)
    if args.check_reference_data:
        problems += check_reference_data(root)
    if args.check_spec_sync:
        problems += check_spec_sync(root, args.language_profile)
    if args.check_manifest:
        problems += check_manifest(root)
    if args.check_skills_manifest:
        problems += check_skills_manifest(root, args.schemas_root)
    if args.check_hardcode:
        problems += check_hardcode(root)
    if args.check_user_functions:
        problems += check_user_functions(root, args.schemas_root)
    if args.check_user_function_interfaces:
        problems += check_user_function_interfaces(root)
    if args.check_user_function_registry:
        problems += check_user_function_registry_v128(root)
    if args.check_function_registry:
        problems += check_function_registry_v128(root, public_symbol_coverage=False)
    if args.check_function_duplication:
        problems += check_function_duplication_v128(root)
    if args.check_registry_task_linkage:
        problems += check_registry_task_linkage_v128(root)
    if args.check_function_lifecycle:
        problems += check_function_lifecycle_v128(root)
    if args.check_change_journal:
        problems += check_change_journal_v128(root, args.base_ref)
    if args.check_function_test_evidence:
        problems += check_function_test_evidence_v128(root)
    if args.check_function_merge_status:
        problems += check_function_merge_status_v128(root, args.protected_ref)
    if args.check_project_snapshot:
        problems += check_project_snapshot(root, args.schemas_root, args.language_profile)
    if args.check_test_runner:
        problems += check_test_runner(root, args.schemas_root)
    if args.check_project_layout:
        problems += check_project_layout(root)
    if args.check_entrypoints:
        problems += check_entrypoints(root)
    if args.check_launch_section:
        problems += check_launch_section(root, args.language_profile)
    if args.check_docs_sections_declared:
        problems += check_docs_sections_declared(root)
    if args.check_file_size:
        problems += check_file_size(root)
    if args.check_code_language:
        problems += check_code_language(root, args.language_profile)
    if args.check_best_style:
        problems += check_best_style(root, args.language_profile, args.schemas_root)
    if args.check_pattern_memory:
        problems += check_pattern_memory(root, args.schemas_root)
    if args.check_markdown_links:
        problems += check_markdown_links(root)
    if args.check_loop_safe_mutation:
        problems += check_loop_safe_mutation(root)
    if args.check_data_in_code:
        problems += check_data_in_code(root)
    if args.check_release_hygiene:
        problems += check_release_hygiene(root)
    if args.check_test_coverage:
        problems += check_test_coverage(root, args.schemas_root)
    if args.check_knowledge_index:
        problems += check_knowledge_index(root, args.schemas_root)
    if args.check_entitlements:
        problems += check_entitlements(root, args.schemas_root)
    if args.check_dependency_policy:
        problems += check_dependency_policy(root, args.schemas_root)
    if args.check_dependency_selection_policy:
        problems += check_dependency_selection_policy(root, args.schemas_root)
    if args.check_tooling_security_review:
        problems += check_tooling_security_review(root, args.schemas_root)
    if args.check_tool_candidates:
        problems += check_tool_candidates(root, args.schemas_root)
    if args.check_approved_tools:
        problems += check_approved_tools(root, args.schemas_root, args.base_ref)
    if args.check_verification_evidence:
        problems += check_verification_evidence(root, args.schemas_root)
    if args.check_module_registry:
        problems += check_module_registry(root, args.schemas_root)
    if args.check_code_ownership:
        problems += check_code_ownership(root, args.schemas_root)
    if args.check_module_boundaries:
        problems += check_module_boundaries(root, args.schemas_root)
    if args.check_work_package_graph:
        problems += check_work_package_graph(root, args.schemas_root)
    if args.check_work_package_overlap:
        problems += check_work_package_overlap(root, args.schemas_root)
    if args.check_active_task_diff:
        if not args.task_id:
            problems.append("active-task-diff: --task-id обязателен вместе с --check-active-task-diff")
        else:
            problems += check_active_task_diff(root, args.task_id, args.base_ref, args.current_branch)
    if args.check_lease_expiry:
        problems += check_lease_expiry(root, args.now)
    if args.check_parallel_ai_development:
        problems += check_parallel_ai_development(root, args.schemas_root, args.base_ref)
    if args.check_sync_policy:
        problems += check_sync_policy(root, args.schemas_root)
    if args.check_encrypted_env:
        problems += check_encrypted_env(root, args.schemas_root)
    if args.check_automation_jobs:
        problems += check_automation_jobs(root, args.schemas_root)
    if args.check_git_agent_policy:
        problems += check_git_agent_policy(root, args.schemas_root)
    if args.check_agent_results:
        problems += check_agent_results(root, args.schemas_root)
    if args.check_check_registry:
        problems += check_check_registry(root, args.schemas_root, args.base_ref)
    if args.check_agent_task_contracts:
        problems += check_agent_task_contracts(root, args.schemas_root, args.base_ref)
    if args.check_agent_workflow_integrity:
        problems += check_agent_workflow_integrity(root, args.schemas_root, args.base_ref)
    if args.check_classical_engineering_foundations:
        problems += check_classical_engineering_foundations(root, args.schemas_root)
    if args.check_git_workspace_hygiene:
        problems += check_git_workspace_hygiene(root, args.schemas_root)
    if args.check_code_audit_policy:
        problems += check_code_audit_policy(root, args.schemas_root)
    if args.check_license_integration_policy:
        problems += check_license_integration_policy(root, args.schemas_root)
    if args.check_qai_fabric_policy:
        problems += check_qai_fabric_policy(root, args.schemas_root)
    if args.check_golden_path_portability:
        problems += check_golden_path_portability(root)
    if args.check_prompt_catalog:
        problems += check_prompt_catalog(root, args.schemas_root)
    if args.check_standard_overview:
        problems += check_standard_overview(root)
    if args.check_memory_governance:
        problems += check_memory_governance(root)
    if args.check_rag_action_governance:
        problems += check_rag_action_governance(root)
    if args.check_dead_code:
        problems += check_dead_code(root, args.profile)
    if args.check_tz_governance:
        problems += check_tz_governance_contract(root)
    if args.check_audit_sequence:
        problems += check_tz_governance_contract(root, audit_sequence_only=True)
    if args.check_control_plane_integrity:
        problems += check_control_plane_integrity(root, args.schemas_root, args.base_ref)
    if args.check_ci_security:
        problems += check_ci_security(root)
    if args.check_standard_capabilities:
        problems += check_standard_capabilities(root, args.schemas_root)
    if args.check_capability_evidence:
        problems += check_capability_evidence_contract(root)
    if args.check_ecosystem_reuse or args.check_ecosystem_profile:
        try:
            from ecosystem_project_validation import (
                parse_owner_artifact_args,
                validate_ecosystem_profile,
                validate_reuse_decisions,
            )

            ecosystem_findings = []
            changed_http_contracts, change_error, resolved_ref = (
                _ecosystem_changed_contracts(
                    root,
                    args.changed_http_contract,
                    args.base_ref if args.check_ecosystem_profile else None,
                )
            )
            if args.check_ecosystem_profile and change_error:
                ecosystem_findings.append(RuleFinding(
                    "OPENAPI_CHANGESET_UNVERIFIED",
                    "APS-CORE-HTTP32-001",
                    "Не удалось определить новые и изменённые HTTP-договоры по Git; проверка блокирует продолжение.",
                    "ERROR",
                    {
                        "base_ref": args.base_ref,
                        "resolved_ref": resolved_ref,
                        "detail": change_error,
                    },
                ))
            if args.check_ecosystem_reuse:
                reuse_path = Path(args.reuse_decisions_path) if args.reuse_decisions_path else None
                if reuse_path is not None and not reuse_path.is_absolute():
                    reuse_path = root / reuse_path
                canon_path = Path(args.canonical_registry) if args.canonical_registry else None
                if canon_path is not None and not canon_path.is_absolute():
                    canon_path = root / canon_path
                ecosystem_findings.extend(validate_reuse_decisions(
                    root,
                    decisions_path=reuse_path,
                    canonical_registry_path=canon_path,
                ))
            if args.check_ecosystem_profile:
                profile_path = Path(args.ecosystem_profile_path) if args.ecosystem_profile_path else None
                if profile_path is not None and not profile_path.is_absolute():
                    profile_path = root / profile_path
                ecosystem_findings.extend(validate_ecosystem_profile(
                    root,
                    profile_path=profile_path,
                    changed_contracts=changed_http_contracts,
                    owner_artifacts=parse_owner_artifact_args(args.owner_boundary_artifact),
                ))
            for finding in ecosystem_findings:
                print("APS_RULE_DIAGNOSTIC:" + json.dumps(
                    finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ))
                if finding.severity == "ERROR":
                    problems.append(f"{finding.code}:{finding.rule_id}:{finding.message}")
        except Exception as exc:
            finding = RuleFinding(
                "ECOSYSTEM_VALIDATOR_INTERNAL_ERROR",
                "APS-CORE-ECOSYSTEMREUSE-001",
                "Внутренняя ошибка экосистемной проверки блокирует продолжение.",
                "ERROR",
                {"detail": f"{type(exc).__name__}: {exc}"},
            )
            print("APS_RULE_DIAGNOSTIC:" + json.dumps(
                finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ))
            problems.append(f"{finding.code}:{finding.rule_id}:{finding.message}")
    if args.check_runtime_resource_safety:
        try:
            from runtime_resource_safety import validate_resource_safety_registry

            policy_path = Path(args.runtime_resource_safety_path) if args.runtime_resource_safety_path else None
            if policy_path is not None and not policy_path.is_absolute():
                policy_path = root / policy_path
            resource_findings = validate_resource_safety_registry(
                root,
                policy_path=policy_path,
                standard_repository=Path(args.standard_repository).resolve() if args.standard_repository else None,
                consumer_root=Path(args.resource_safety_consumer_root).resolve() if args.resource_safety_consumer_root else None,
            )
            for finding in resource_findings:
                print("APS_RULE_DIAGNOSTIC:" + json.dumps(
                    finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
                ))
                if finding.severity == "ERROR":
                    problems.append(f"{finding.code}:{finding.rule_id}:{finding.message}")
        except Exception as exc:
            finding = RuleFinding(
                "RESOURCE_POLICY_INTERNAL_ERROR",
                "APS-CORE-RESOURCEOPERATION-001",
                "Внутренняя ошибка проверки безопасного допуска блокирует продолжение.",
                "ERROR",
                {"detail": f"{type(exc).__name__}: {exc}"},
            )
            print("APS_RULE_DIAGNOSTIC:" + json.dumps(
                finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ))
            problems.append(f"{finding.code}:{finding.rule_id}:{finding.message}")
    if args.check_version_sync:
        problems += check_version_sync(root)
    if any((
        args.check_rule_traceability,
        args.check_rule_inventory,
        args.check_rule_semantic_continuity,
        args.check_rule_implementation_linkage,
        args.check_rule_diagnostics,
        args.check_rule_test_evidence,
    )):
        from rule_traceability import validate_registry
        problems += validate_registry(root)
    if args.artifact:
        problems += check_release_artifact(Path(args.artifact))

    errors = [p for p in problems if not p.startswith(WARN_PREFIX)]
    warnings = [p[len(WARN_PREFIX):] for p in problems if p.startswith(WARN_PREFIX)]

    if warnings:
        print(f"Предупреждения ({args.profile}):")
        for w in warnings:
            print("  ~", w)
    if errors:
        print(f"Нарушения ({args.profile}):")
        for problem in errors:
            print("  -", problem)
        return 1
    if warnings and args.warnings_as_errors:
        print("(--warnings-as-errors: предупреждения считаются ошибкой)")
        return 1
    print(f"Структура в порядке ({args.profile})." + (f" Предупреждений: {len(warnings)}." if warnings else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
