#!/usr/bin/env python3
"""Проверяет многокомпонентный профиль проекта экосистемы."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

from ecosystem_reuse_validation import validate_reuse_decisions
from ecosystem_validation_common import (
    ACCESSIBILITY_RULE,
    AXES_RULE,
    CONTROLLER_RULE,
    DEFAULT_PROFILE_PATH,
    DUAL_INTERFACE_PURPOSES,
    DUAL_INTERFACE_RULE,
    HTTP32_RULE,
    INTEGRATION_BOUNDARY_RULE,
    KNOWN_OPENAPI_RE,
    LOCALIZATION_RULE,
    OPENAPI_VERSION_RE,
    PORTABILITY_RULE,
    REQUIRED_ACCESSIBILITY_CHECKS,
    REUSE_RULE,
    UI_FORMS,
    WEB_BOUNDARY_RULE,
    absolute_delivery as _absolute_delivery,
    existing_relative as _existing_relative,
    finding as _finding,
    is_safe_relative as _is_safe_relative,
    load_and_check_schema as _load_and_check_schema,
    load_json as _load_json,
    valid_iso_date as _valid_iso_date,
    with_pass as _with_pass,
)
from rule_traceability_types import (
    RuleFinding,
    emits_diagnostic,
    enforces_rule,
    print_diagnostic,
)


def _profile_file_error(root: Path, value: Any, code: str, rule_id: str, label: str) -> RuleFinding | None:
    if _existing_relative(root, value) is None:
        return _finding(code, rule_id, f"{label}: файл отсутствует или путь небезопасен", path=value)
    return None


@enforces_rule("APS-CORE-PROJECTAXES-001")
@emits_diagnostic("APS-CORE-PROJECTAXES-001", "PROJECT_AXES_VALID")
@emits_diagnostic("APS-CORE-PROJECTAXES-001", "PROJECT_AXES_INVALID")
def validate_project_axes(data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    forms = data.get("runtime_forms") if isinstance(data.get("runtime_forms"), list) else []
    purpose = data.get("purpose")
    ui = data.get("ui") if isinstance(data.get("ui"), dict) else {}
    if not forms or len(forms) != len(set(forms)) or not purpose:
        findings.append(_finding("PROJECT_AXES_INVALID", AXES_RULE, "Нужны независимые оси runtime_forms и purpose"))
    has_ui_form = bool(set(forms) & UI_FORMS)
    if bool(ui.get("present")) != has_ui_form:
        findings.append(_finding("PROJECT_AXES_INVALID", AXES_RULE, "ui.present должен соответствовать выбранной форме с интерфейсом", runtime_forms=forms))
    if purpose in {"public_site", "customer_portal"} and "web_pwa" not in forms:
        findings.append(_finding("PROJECT_AXES_INVALID", AXES_RULE, "Сайт и личный кабинет требуют web_pwa", purpose=purpose))
    return _with_pass(findings, AXES_RULE, "PROJECT_AXES_VALID", "Форма исполнения и назначение заданы независимо")


def _valid_waiver(root: Path, waiver: Any, today: date) -> bool:
    if not isinstance(waiver, dict):
        return False
    expiry = _valid_iso_date(waiver.get("expires_on"))
    return (
        expiry is not None
        and expiry >= today
        and waiver.get("migration_target") == "3.2.0"
        and _existing_relative(root, waiver.get("adr")) is not None
        and bool(waiver.get("owner"))
        and bool(waiver.get("reason"))
    )


@enforces_rule("APS-CORE-HTTP32-001")
@emits_diagnostic("APS-CORE-HTTP32-001", "OPENAPI_32_VALID")
@emits_diagnostic("APS-CORE-HTTP32-001", "OPENAPI_VERSION_UNKNOWN")
@emits_diagnostic("APS-CORE-HTTP32-001", "OPENAPI_32_REQUIRED")
@emits_diagnostic("APS-CORE-HTTP32-001", "OPENAPI_WAIVER_INVALID")
@emits_diagnostic("APS-CORE-HTTP32-001", "OPENAPI_LEGACY_RECORD_INVALID")
@emits_diagnostic("APS-CORE-HTTP32-001", "OPENAPI_CHANGESET_UNVERIFIED")
def validate_http_contracts(
    root: Path,
    data: dict[str, Any],
    *,
    changed_contracts: set[str] | None = None,
    today: date | None = None,
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    changed = {Path(item).as_posix() for item in (changed_contracts or set())}
    validation_day = today or date.today()
    for contract in data.get("http_contracts", []) if isinstance(data.get("http_contracts"), list) else []:
        if not isinstance(contract, dict):
            continue
        rel = contract.get("path")
        path = _existing_relative(root, rel)
        if path is None:
            findings.append(_finding("OPENAPI_32_REQUIRED", HTTP32_RULE, "HTTP-договор отсутствует или путь небезопасен", path=rel))
            continue
        text = path.read_text(encoding="utf-8-sig", errors="ignore")
        match = OPENAPI_VERSION_RE.search(text)
        version = match.group("version") if match else None
        if version is None or KNOWN_OPENAPI_RE.fullmatch(version) is None:
            findings.append(_finding("OPENAPI_VERSION_UNKNOWN", HTTP32_RULE, "Версия OpenAPI отсутствует или неизвестна", path=rel, version=version))
            continue
        lifecycle = contract.get("lifecycle")
        effective_changed = lifecycle in {"new", "changed"} or Path(str(rel)).as_posix() in changed
        if effective_changed and version != "3.2.0":
            if not _valid_waiver(root, contract.get("waiver"), validation_day):
                code = "OPENAPI_WAIVER_INVALID" if "waiver" in contract else "OPENAPI_32_REQUIRED"
                findings.append(_finding(code, HTTP32_RULE, "Новый или изменённый HTTP-договор требует OpenAPI 3.2.0 либо действующее ADR-исключение", path=rel, version=version))
        if lifecycle == "legacy" and not effective_changed:
            legacy = contract.get("legacy_record")
            if not isinstance(legacy, dict) or _existing_relative(root, legacy.get("adr")) is None or not _valid_iso_date(legacy.get("recorded_on")):
                findings.append(_finding("OPENAPI_LEGACY_RECORD_INVALID", HTTP32_RULE, "Старый неизменяемый договор должен быть явно учтён", path=rel))
    return _with_pass(findings, HTTP32_RULE, "OPENAPI_32_VALID", "Новые и изменённые HTTP-договоры используют OpenAPI 3.2.0 либо действующее ADR-исключение")


@enforces_rule("APS-CORE-DUALINTERFACE-001")
@emits_diagnostic("APS-CORE-DUALINTERFACE-001", "DUAL_INTERFACE_VALID")
@emits_diagnostic("APS-CORE-DUALINTERFACE-001", "DUAL_INTERFACE_REQUIRED")
@emits_diagnostic("APS-CORE-DUALINTERFACE-001", "ISKIN_MUTATING_ACTIONS_NOT_READY")
def validate_dual_interface(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    purpose = data.get("purpose")
    ui = data.get("ui") if isinstance(data.get("ui"), dict) else {}
    required = purpose in DUAL_INTERFACE_PURPOSES or bool(ui.get("domain_operations"))
    if required:
        operations = ui.get("operations") if isinstance(ui.get("operations"), list) else []
        iskin = ui.get("iskin_integration") if isinstance(ui.get("iskin_integration"), dict) else {}
        required_files = (
            (ui.get("operation_catalog_path"), "каталог ручных операций"),
            (iskin.get("iskin_actions_path"), "iskin_actions"),
            (iskin.get("risk_policy_path"), "политика риска"),
        )
        if not ui.get("present") or not ui.get("manual_mode_without_iskinosfera") or not operations:
            findings.append(_finding("DUAL_INTERFACE_REQUIRED", DUAL_INTERFACE_RULE, "Пользовательский продукт требует ручной режим, операции и описание режима Иск-Ина", purpose=purpose))
        for value, label in required_files:
            error = _profile_file_error(root, value, "DUAL_INTERFACE_REQUIRED", DUAL_INTERFACE_RULE, label)
            if error:
                findings.append(error)
        operation_ids = [item.get("operation_id") for item in operations if isinstance(item, dict)]
        if len(operation_ids) != len(set(operation_ids)):
            findings.append(_finding("DUAL_INTERFACE_REQUIRED", DUAL_INTERFACE_RULE, "operation_id должны быть стабильными и уникальными"))
        actions_path = _existing_relative(root, iskin.get("iskin_actions_path"))
        if actions_path:
            actions_text = actions_path.read_text(encoding="utf-8", errors="ignore")
            for operation_id in operation_ids:
                if operation_id and operation_id not in actions_text:
                    findings.append(_finding("DUAL_INTERFACE_REQUIRED", DUAL_INTERFACE_RULE, "Операция не связана с iskin_actions", operation_id=operation_id))
        if iskin.get("mutating_actions_enabled") is not False:
            findings.append(_finding("ISKIN_MUTATING_ACTIONS_NOT_READY", DUAL_INTERFACE_RULE, "Профиль готовности не включает изменяющие действия до отдельного безопасного пилота"))
    return _with_pass(findings, DUAL_INTERFACE_RULE, "DUAL_INTERFACE_VALID", "Применимые пользовательские операции имеют ручной режим и безопасный профиль Иск-Ина", applicable=required)


@enforces_rule("APS-CORE-LOCALIZATION-001")
@emits_diagnostic("APS-CORE-LOCALIZATION-001", "LOCALIZATION_PROFILE_VALID")
@emits_diagnostic("APS-CORE-LOCALIZATION-001", "LOCALIZATION_PROFILE_REQUIRED")
@emits_diagnostic("APS-CORE-LOCALIZATION-001", "LOCALIZATION_KEYS_MISMATCH")
def validate_localization(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    ui = data.get("ui") if isinstance(data.get("ui"), dict) else {}
    if not ui.get("present"):
        return _with_pass(findings, LOCALIZATION_RULE, "LOCALIZATION_PROFILE_VALID", "Для проекта без UI профиль локализации неприменим", applicable=False)
    profile = data.get("localization") if isinstance(data.get("localization"), dict) else None
    if profile is None:
        findings.append(_finding("LOCALIZATION_PROFILE_REQUIRED", LOCALIZATION_RULE, "Проект с UI требует профиль локализации"))
        return findings
    supported = profile.get("supported_locales") if isinstance(profile.get("supported_locales"), list) else []
    if profile.get("base_locale") not in supported or profile.get("fallback_locale") not in supported:
        findings.append(_finding("LOCALIZATION_PROFILE_REQUIRED", LOCALIZATION_RULE, "Базовая и запасная локали должны входить в supported_locales"))
    directions = profile.get("text_directions") if isinstance(profile.get("text_directions"), dict) else {}
    if set(directions) != set(supported):
        findings.append(_finding("LOCALIZATION_PROFILE_REQUIRED", LOCALIZATION_RULE, "Направление письма нужно объявить для каждой локали"))
    catalogs = profile.get("catalogs") if isinstance(profile.get("catalogs"), list) else []
    by_locale = {item.get("locale"): item for item in catalogs if isinstance(item, dict)}
    if set(by_locale) != set(supported):
        findings.append(_finding("LOCALIZATION_PROFILE_REQUIRED", LOCALIZATION_RULE, "Каталог нужен ровно для каждой поддерживаемой локали"))
    key_sets: dict[str, set[str]] = {}
    for locale, item in by_locale.items():
        path = _existing_relative(root, item.get("path"))
        catalog, error = _load_json(path) if path else (None, "missing")
        if error or not isinstance(catalog, dict):
            findings.append(_finding("LOCALIZATION_PROFILE_REQUIRED", LOCALIZATION_RULE, "Каталог локали отсутствует или не является JSON-объектом", locale=locale, path=item.get("path")))
        else:
            key_sets[str(locale)] = set(catalog)
    if key_sets:
        base_keys = key_sets.get(str(profile.get("base_locale")), set())
        for locale, keys in key_sets.items():
            if keys != base_keys:
                findings.append(_finding("LOCALIZATION_KEYS_MISMATCH", LOCALIZATION_RULE, "В каталоге есть отсутствующие или лишние ключи", locale=locale, missing=sorted(base_keys - keys), extra=sorted(keys - base_keys)))
    for key, label in (
        ("hardcoded_strings_check_path", "проверка жёстко записанных строк"),
        ("overflow_or_pseudolocale_test_path", "псевдолокаль или проверка переполнения"),
    ):
        error = _profile_file_error(root, profile.get(key), "LOCALIZATION_PROFILE_REQUIRED", LOCALIZATION_RULE, label)
        if error:
            findings.append(error)
    return _with_pass(findings, LOCALIZATION_RULE, "LOCALIZATION_PROFILE_VALID", "Локали, форматирование, ключи и доказательства описаны машинно", locales=supported)


@enforces_rule("APS-CORE-ACCESSIBILITY-001")
@emits_diagnostic("APS-CORE-ACCESSIBILITY-001", "ACCESSIBILITY_EVIDENCE_VALID")
@emits_diagnostic("APS-CORE-ACCESSIBILITY-001", "ACCESSIBILITY_EVIDENCE_REQUIRED")
def validate_accessibility(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    ui = data.get("ui") if isinstance(data.get("ui"), dict) else {}
    if not ui.get("present"):
        return _with_pass(findings, ACCESSIBILITY_RULE, "ACCESSIBILITY_EVIDENCE_VALID", "Для проекта без UI профиль доступности неприменим", applicable=False)
    profile = data.get("accessibility") if isinstance(data.get("accessibility"), dict) else None
    if profile is None or profile.get("target") != "WCAG 2.2 AA":
        findings.append(_finding("ACCESSIBILITY_EVIDENCE_REQUIRED", ACCESSIBILITY_RULE, "Проект с UI требует профиль доказательств WCAG 2.2 AA"))
        return findings
    checks = set(profile.get("manual_checks", []))
    if not REQUIRED_ACCESSIBILITY_CHECKS.issubset(checks):
        findings.append(_finding("ACCESSIBILITY_EVIDENCE_REQUIRED", ACCESSIBILITY_RULE, "Ручная проверка доступности неполна", missing=sorted(REQUIRED_ACCESSIBILITY_CHECKS - checks)))
    for key, label in (
        ("automatic_test_path", "автоматическая проверка"),
        ("manual_review_path", "ручная проверка"),
    ):
        error = _profile_file_error(root, profile.get(key), "ACCESSIBILITY_EVIDENCE_REQUIRED", ACCESSIBILITY_RULE, label)
        if error:
            findings.append(error)
    return _with_pass(findings, ACCESSIBILITY_RULE, "ACCESSIBILITY_EVIDENCE_VALID", "Есть автоматические и ручные доказательства WCAG 2.2 AA")


@enforces_rule("APS-CORE-PORTABILITY-001")
@emits_diagnostic("APS-CORE-PORTABILITY-001", "PLATFORM_MATRIX_VALID")
@emits_diagnostic("APS-CORE-PORTABILITY-001", "PLATFORM_EVIDENCE_REQUIRED")
@emits_diagnostic("APS-CORE-PORTABILITY-001", "PLATFORM_ABSOLUTE_PATH_FORBIDDEN")
def validate_portability(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    profile = data.get("portability") if isinstance(data.get("portability"), dict) else {}
    platforms = profile.get("platforms") if isinstance(profile.get("platforms"), list) else []
    if not platforms:
        findings.append(_finding("PLATFORM_EVIDENCE_REQUIRED", PORTABILITY_RULE, "Нужна непустая проверяемая матрица платформ"))
    for platform in platforms:
        if not isinstance(platform, dict):
            continue
        evidence = platform.get("evidence") if isinstance(platform.get("evidence"), dict) else {}
        if _existing_relative(root, evidence.get("path")) is None:
            findings.append(_finding("PLATFORM_EVIDENCE_REQUIRED", PORTABILITY_RULE, "Заявленная платформа не имеет доказательства CI или внешнего контура", os=platform.get("os"), path=evidence.get("path")))
        mutable = platform.get("mutable_data") if isinstance(platform.get("mutable_data"), dict) else {}
        if _absolute_delivery(mutable.get("value")) or not mutable.get("strategy"):
            findings.append(_finding("PLATFORM_ABSOLUTE_PATH_FORBIDDEN", PORTABILITY_RULE, "Изменяемые данные нельзя закреплять абсолютным путём", os=platform.get("os"), value=mutable.get("value")))
        if platform.get("os") == "browser" and not platform.get("browsers"):
            findings.append(_finding("PLATFORM_EVIDENCE_REQUIRED", PORTABILITY_RULE, "Браузерная платформа требует список проверяемых браузеров"))
    return _with_pass(findings, PORTABILITY_RULE, "PLATFORM_MATRIX_VALID", "Каждая заявленная платформа имеет переносимые пути и доказательство", platforms=len(platforms))


@enforces_rule("APS-CORE-CONTROLLERPROFILE-001")
@emits_diagnostic("APS-CORE-CONTROLLERPROFILE-001", "CONTROLLER_PROFILE_VALID")
@emits_diagnostic("APS-CORE-CONTROLLERPROFILE-001", "CONTROLLER_PROFILE_REQUIRED")
@emits_diagnostic("APS-CORE-CONTROLLERPROFILE-001", "CONTROLLER_BUSINESS_REGISTRY_FORBIDDEN")
@emits_diagnostic("APS-CORE-CONTROLLERPROFILE-001", "CONTROLLER_PUBLIC_ACCESS_FORBIDDEN")
def validate_controller_profile(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    is_controller = data.get("purpose") == "controller_project"
    profile = data.get("controller_profile") if isinstance(data.get("controller_profile"), dict) else None
    if not is_controller:
        if profile is not None:
            findings.append(_finding("CONTROLLER_PROFILE_REQUIRED", CONTROLLER_RULE, "controller_profile допустим только для controller_project"))
        return _with_pass(findings, CONTROLLER_RULE, "CONTROLLER_PROFILE_VALID", "Проект не является контроллерным", applicable=False)
    if data.get("business_ecosystem_member") is not False:
        findings.append(_finding("CONTROLLER_BUSINESS_REGISTRY_FORBIDDEN", CONTROLLER_RULE, "Контроллерный проект не входит в реестр бизнес-экосистемы"))
    if "edge_agent" not in set(data.get("runtime_forms", [])):
        findings.append(_finding("CONTROLLER_PROFILE_REQUIRED", CONTROLLER_RULE, "Контроллерный проект требует edge_agent"))
    if profile is None:
        findings.append(_finding("CONTROLLER_PROFILE_REQUIRED", CONTROLLER_RULE, "Нет обязательного controller_profile"))
        return findings
    for key in (
        "ui_controller_boundary",
        "offline_operation",
        "local_state",
        "local_journal",
        "manual_fallback",
        "safe_update_and_rollback",
    ):
        if profile.get(key) is not True:
            findings.append(_finding("CONTROLLER_PROFILE_REQUIRED", CONTROLLER_RULE, "Не выполнено обязательное условие контроллерного проекта", field=key))
    if profile.get("direct_public_network_access") is not False:
        findings.append(_finding("CONTROLLER_PUBLIC_ACCESS_FORBIDDEN", CONTROLLER_RULE, "Прямой доступ из публичной сети запрещён"))
    error = _profile_file_error(root, profile.get("hardware_failure_test_path"), "CONTROLLER_PROFILE_REQUIRED", CONTROLLER_RULE, "тест отказа оборудования")
    if error:
        findings.append(error)
    return _with_pass(findings, CONTROLLER_RULE, "CONTROLLER_PROFILE_VALID", "Контроллерный проект отделён от бизнес-реестра и имеет безопасный пограничный профиль")


@enforces_rule("APS-CORE-WEBBOUNDARY-001")
@emits_diagnostic("APS-CORE-WEBBOUNDARY-001", "WEB_BOUNDARY_VALID")
@emits_diagnostic("APS-CORE-WEBBOUNDARY-001", "PUBLIC_SITE_BOUNDARY_INVALID")
@emits_diagnostic("APS-CORE-WEBBOUNDARY-001", "CUSTOMER_PORTAL_BOUNDARY_INVALID")
def validate_web_boundary(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    purpose = data.get("purpose")
    if purpose not in {"public_site", "customer_portal"}:
        return _with_pass(findings, WEB_BOUNDARY_RULE, "WEB_BOUNDARY_VALID", "Профиль сайта или кабинета неприменим", applicable=False)
    boundary = data.get("web_boundary") if isinstance(data.get("web_boundary"), dict) else None
    code = "PUBLIC_SITE_BOUNDARY_INVALID" if purpose == "public_site" else "CUSTOMER_PORTAL_BOUNDARY_INVALID"
    if boundary is None:
        return [_finding(code, WEB_BOUNDARY_RULE, "Нет обязательной границы web-проекта", purpose=purpose)]
    if boundary.get("direct_business_database_access") is not False:
        findings.append(_finding(code, WEB_BOUNDARY_RULE, "Web-слой не должен обращаться прямо к базе бизнес-продукта", purpose=purpose))
    if purpose == "public_site":
        if boundary.get("uses_customer_data") is not False or boundary.get("authentication") == "required" or boundary.get("tenant_isolation") is not False or boundary.get("product_port_refs"):
            findings.append(_finding(code, WEB_BOUNDARY_RULE, "Публичный сайт не является защищённым кабинетом и не получает данные клиента", purpose=purpose))
    else:
        if boundary.get("uses_customer_data") is not True or boundary.get("authentication") != "required" or boundary.get("tenant_isolation") is not True or not boundary.get("product_port_refs"):
            findings.append(_finding(code, WEB_BOUNDARY_RULE, "Личный кабинет требует вход, изоляцию арендаторов и обращение через продуктовые порты", purpose=purpose))
        web_refs = boundary.get("product_port_refs", [])
        integration = data.get("integration_boundaries")
        integration = integration if isinstance(integration, dict) else {}
        integration_refs = integration.get("product_port_refs", [])
        integration_refs = integration_refs if isinstance(integration_refs, list) else []
        integration_identities = {
            json.dumps(ref, ensure_ascii=False, sort_keys=True)
            for ref in integration_refs
        }
        for ref in web_refs:
            findings.extend(_owner_ref_findings(ref, WEB_BOUNDARY_RULE, code))
            identity = json.dumps(ref, ensure_ascii=False, sort_keys=True)
            if identity not in integration_identities:
                findings.append(_finding(code, WEB_BOUNDARY_RULE, "Ссылка Product Port личного кабинета должна идентично присутствовать в integration_boundaries", reference=_owner_ref_key(ref) if isinstance(ref, dict) else ref))
    return _with_pass(findings, WEB_BOUNDARY_RULE, "WEB_BOUNDARY_VALID", "Публичный сайт и защищённый кабинет имеют разные границы", purpose=purpose)


def _owner_ref_key(reference: dict[str, Any]) -> str:
    return (
        f"{reference.get('repository', '')}:{reference.get('path', '')}"
        f"@{reference.get('version', '')}"
    )


def _owner_ref_findings(
    reference: Any,
    rule_id: str,
    code: str,
) -> list[RuleFinding]:
    if not isinstance(reference, dict):
        return [_finding(code, rule_id, "Граница требует структурированную ссылку владельца")]
    findings: list[RuleFinding] = []
    required = ("owner", "repository", "path", "version")
    if any(not isinstance(reference.get(key), str) or not reference.get(key) for key in required):
        findings.append(_finding(code, rule_id, "Ссылка владельца неполна", reference=_owner_ref_key(reference)))
    if not _is_safe_relative(reference.get("path")):
        findings.append(_finding(code, rule_id, "Путь договора должен быть относительным внутри репозитория владельца", path=reference.get("path")))
    if "local_path" in reference or "artifact_path" in reference:
        findings.append(_finding(code, rule_id, "Рукописный локальный договор не является ссылкой владельца", reference=_owner_ref_key(reference)))
    commit = reference.get("git_commit")
    digest = reference.get("sha256")
    commit_valid = isinstance(commit, str) and re.fullmatch(r"[a-fA-F0-9]{7,64}", commit)
    digest_valid = isinstance(digest, str) and re.fullmatch(r"[a-fA-F0-9]{64}", digest)
    if not commit_valid and not digest_valid:
        findings.append(_finding(code, rule_id, "Ссылка владельца требует git_commit или sha256", reference=_owner_ref_key(reference)))
    return findings


def _projection_artifact(
    root: Path,
    reference: dict[str, Any],
) -> tuple[Path | None, list[RuleFinding], bool]:
    projection = reference.get("projection")
    if not isinstance(projection, dict):
        return None, [], False
    findings: list[RuleFinding] = []
    artifact = _existing_relative(root, projection.get("path"))
    generator = _existing_relative(root, projection.get("generator"))
    if projection.get("mode") != "generated" or projection.get("dereferenced") is not True or artifact is None or generator is None:
        findings.append(_finding("INTEGRATION_OWNER_REF_INVALID", INTEGRATION_BOUNDARY_RULE, "Локальная проекция должна быть воспроизводимо сгенерирована", reference=_owner_ref_key(reference)))
        return None, findings, False
    actual_digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    if projection.get("sha256") != actual_digest:
        findings.append(_finding("INTEGRATION_OWNER_REF_INVALID", INTEGRATION_BOUNDARY_RULE, "Контрольная сумма локальной проекции не совпадает", reference=_owner_ref_key(reference)))
    if reference.get("sha256") and projection.get("source_sha256") != reference.get("sha256"):
        findings.append(_finding("INTEGRATION_OWNER_REF_INVALID", INTEGRATION_BOUNDARY_RULE, "Проекция ссылается не на ту контрольную сумму источника", reference=_owner_ref_key(reference)))
    return artifact, findings, True


def _owner_artifact(
    root: Path,
    reference: dict[str, Any],
    owner_artifacts: dict[str, Path],
) -> tuple[Path | None, list[RuleFinding], bool]:
    key = _owner_ref_key(reference)
    expected_digest = reference.get("sha256")
    if not isinstance(expected_digest, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_digest):
        return None, [_finding("INTEGRATION_OWNER_REF_INVALID", INTEGRATION_BOUNDARY_RULE, "Содержательная проверка Product Port требует sha256 договора владельца", reference=key)], False
    explicit = owner_artifacts.get(key)
    if explicit is not None:
        if not explicit.is_file():
            return None, [_finding("INTEGRATION_OWNER_REF_INVALID", INTEGRATION_BOUNDARY_RULE, "Явно переданный договор владельца не найден", reference=key, path=str(explicit))], False
        if hashlib.sha256(explicit.read_bytes()).hexdigest() != expected_digest:
            return None, [_finding("INTEGRATION_OWNER_REF_INVALID", INTEGRATION_BOUNDARY_RULE, "Переданный договор владельца не совпадает с sha256 ссылки", reference=key)], False
        return explicit, [], False
    return _projection_artifact(root, reference)


def _nested_json_keys(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {
            str(key)
            for key in value
        } | {
            nested
            for item in value.values()
            for nested in _nested_json_keys(item)
        }
    if isinstance(value, list):
        return {nested for item in value for nested in _nested_json_keys(item)}
    return set()


def _json_references(value: Any) -> list[Any]:
    if isinstance(value, dict):
        references = [value["$ref"]] if "$ref" in value else []
        return references + [
            reference
            for item in value.values()
            for reference in _json_references(item)
        ]
    if isinstance(value, list):
        return [reference for item in value for reference in _json_references(item)]
    return []


def _json_pointer_resolves(document: Any, reference: Any) -> bool:
    if reference == "#":
        return True
    if not isinstance(reference, str) or not reference.startswith("#/"):
        return False
    current = document
    for raw_part in reference[2:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False
    return True


def _normalized_contract_key(value: str) -> str:
    snake = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    return snake.replace("-", "_").casefold()


def _product_port_content_findings(
    artifact: Path,
    reference: dict[str, Any],
) -> list[RuleFinding]:
    key = _owner_ref_key(reference)
    try:
        text = "\n".join(artifact.read_text(encoding="utf-8-sig").splitlines())
    except (OSError, UnicodeError) as exc:
        return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "Договор Product Port не читается", reference=key, detail=str(exc))]
    forbidden_prefixes = ("heartbeat", "lease", "telemetry", "metric")
    suffix = Path(str(reference.get("path", ""))).suffix.casefold()
    if suffix == ".json":
        try:
            document = json.loads(text)
        except json.JSONDecodeError as exc:
            return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "JSON-договор Product Port синтаксически неверен", reference=key, detail=str(exc))]
        unresolved = [
            reference
            for reference in _json_references(document)
            if not _json_pointer_resolves(document, reference)
        ]
        if unresolved:
            return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "JSON-договор Product Port содержит нерезолвимый $ref", reference=key, unresolved=unresolved)]
        keys = _nested_json_keys(document)
    elif suffix in {".yaml", ".yml"}:
        unsupported = re.search(
            r"(?m)^\s*\?|^[^#\n]*!include\b|\"[^\"\n]*\\[^\"\n]*\"\s*:",
            text,
        )
        if unsupported:
            return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "YAML-договор использует неподдерживаемую форму ключа", reference=key)]
        key_pattern = re.compile(
            r"(?<![A-Za-z0-9_])(?:\"(?P<double>[^\"]+)\"|'(?P<single>[^']+)'|(?P<plain>[A-Za-z_][A-Za-z0-9_-]*))\s*:"
        )
        keys = {
            next(value for value in match.groups() if value is not None)
            for match in key_pattern.finditer(text)
        }
        if not keys:
            return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "YAML-договор Product Port не содержит распознаваемых ключей", reference=key)]
        yaml_refs = re.findall(
            r"(?m)^\s*[\"']?\$ref[\"']?\s*:\s*(?P<value>\S+)",
            text,
        )
        if yaml_refs:
            return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "YAML-договор Product Port содержит $ref; нужна явно разыменованная сгенерированная проекция", reference=key, unresolved=yaml_refs)]
    else:
        return [_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "Поддерживаются только JSON и YAML договоры Product Port", reference=key, suffix=suffix)]
    normalized_keys = {_normalized_contract_key(key_name) for key_name in keys}
    found = sorted(
        key_name
        for key_name in normalized_keys
        if any(
            key_name.startswith(prefix) if prefix in {"heartbeat", "lease", "metric"} else prefix in key_name
            for prefix in forbidden_prefixes
        )
    )
    if found:
        return [_finding("PRODUCT_PORT_CONTROL_FIELDS_FORBIDDEN", INTEGRATION_BOUNDARY_RULE, "Product Port не передаёт heartbeat, аренды или телеметрию", reference=key, fields=found)]
    return []


@enforces_rule("APS-CORE-INTEGRATIONBOUNDARIES-001")
@emits_diagnostic("APS-CORE-INTEGRATIONBOUNDARIES-001", "INTEGRATION_BOUNDARIES_VALID")
@emits_diagnostic("APS-CORE-INTEGRATIONBOUNDARIES-001", "INTEGRATION_BOUNDARIES_MIXED")
@emits_diagnostic("APS-CORE-INTEGRATIONBOUNDARIES-001", "INTEGRATION_OWNER_REF_INVALID")
@emits_diagnostic("APS-CORE-INTEGRATIONBOUNDARIES-001", "PRODUCT_PORT_CONTENT_UNVERIFIED")
@emits_diagnostic("APS-CORE-INTEGRATIONBOUNDARIES-001", "PRODUCT_PORT_CONTROL_FIELDS_FORBIDDEN")
def validate_integration_boundaries(
    root: Path,
    data: dict[str, Any],
    *,
    owner_artifacts: dict[str, Path] | None = None,
) -> list[RuleFinding]:
    """Проверяет раздельность только явно объявленных машинных договоров."""
    findings: list[RuleFinding] = []
    boundaries = data.get("integration_boundaries")
    if not isinstance(boundaries, dict):
        return _with_pass(findings, INTEGRATION_BOUNDARY_RULE, "INTEGRATION_BOUNDARIES_VALID", "Интеграционные договоры не объявлены", applicable=False)
    product_refs = boundaries.get("product_port_refs") if isinstance(boundaries.get("product_port_refs"), list) else []
    named_refs = [
        boundaries.get("orchestrator_port_ref"),
        boundaries.get("executor_contract_ref"),
        boundaries.get("observability_contract_ref"),
    ]
    all_refs = [value for value in [*product_refs, *named_refs] if value]
    identities = [
        _owner_ref_key(value) if isinstance(value, dict) else json.dumps(value, sort_keys=True)
        for value in all_refs
    ]
    if len(identities) != len(set(identities)):
        findings.append(_finding("INTEGRATION_BOUNDARIES_MIXED", INTEGRATION_BOUNDARY_RULE, "Один файл нельзя одновременно объявить продуктовым портом, оркестратором, договором исполнителя или наблюдением"))
    for ref in all_refs:
        findings.extend(_owner_ref_findings(ref, INTEGRATION_BOUNDARY_RULE, "INTEGRATION_OWNER_REF_INVALID"))
    for ref in product_refs:
        if not isinstance(ref, dict):
            continue
        path, artifact_findings, _dereferenced = _owner_artifact(root, ref, owner_artifacts or {})
        findings.extend(artifact_findings)
        if path is None:
            findings.append(_finding("PRODUCT_PORT_CONTENT_UNVERIFIED", INTEGRATION_BOUNDARY_RULE, "Для проверки Product Port нужен явно переданный договор владельца или воспроизводимо сгенерированная проекция", reference=_owner_ref_key(ref)))
        else:
            findings.extend(_product_port_content_findings(path, ref))
    return _with_pass(findings, INTEGRATION_BOUNDARY_RULE, "INTEGRATION_BOUNDARIES_VALID", "Объявленные интеграционные договоры разделены")


def validate_ecosystem_profile(
    root: Path,
    *,
    profile_path: Path | None = None,
    changed_contracts: set[str] | None = None,
    owner_artifacts: dict[str, Path] | None = None,
    today: date | None = None,
) -> list[RuleFinding]:
    local_path = profile_path or (root / DEFAULT_PROFILE_PATH)
    data, error = _load_json(local_path)
    if error or not isinstance(data, dict):
        return [_finding("PROJECT_AXES_INVALID", AXES_RULE, "ecosystem_project_profile.json не читается", path=str(local_path), detail=error)]
    schema_details = _load_and_check_schema(data, "ecosystem_project_profile.schema.json")
    findings: list[RuleFinding] = [
        _finding(
            "PROJECT_AXES_INVALID",
            AXES_RULE,
            "Профиль проекта не соответствует схеме",
            detail=detail,
        )
        for detail in schema_details
    ]
    components = data.get("components") if isinstance(data.get("components"), list) else []
    component_ids = [item.get("component_id") for item in components if isinstance(item, dict)]
    if len(component_ids) != len(set(component_ids)):
        findings.append(_finding("PROJECT_AXES_INVALID", AXES_RULE, "component_id должен быть уникальным в пределах проекта", component_ids=component_ids))
    for component in components:
        if not isinstance(component, dict):
            continue
        findings.extend(validate_project_axes(component))
        findings.extend(validate_http_contracts(root, component, changed_contracts=changed_contracts, today=today))
        findings.extend(validate_dual_interface(root, component))
        findings.extend(validate_localization(root, component))
        findings.extend(validate_accessibility(root, component))
        findings.extend(validate_portability(root, component))
        findings.extend(validate_controller_profile(root, component))
        findings.extend(validate_web_boundary(root, component))
        findings.extend(validate_integration_boundaries(root, component, owner_artifacts=owner_artifacts))
    if schema_details:
        return [item for item in findings if item.severity == "ERROR"]
    return findings


def _emit(findings: list[RuleFinding], as_json: bool) -> None:
    if as_json:
        print(json.dumps({"findings": [item.as_dict() for item in findings]}, ensure_ascii=False, sort_keys=True))
        return
    for finding in findings:
        print_diagnostic(finding)


def parse_owner_artifact_args(values: list[str]) -> dict[str, Path]:
    """Разбирает повторяемое `repository:path@version=artifact` для запуска CI."""
    result: dict[str, Path] = {}
    for value in values:
        key, separator, raw_path = value.partition("=")
        if not separator or not key or not raw_path:
            raise ValueError(
                "--owner-boundary-artifact требует repository:path@version=artifact"
            )
        if key in result:
            raise ValueError(f"повторная ссылка договора владельца: {key}")
        result[key] = Path(raw_path).resolve()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--check-reuse", action="store_true")
    parser.add_argument("--check-profile", action="store_true")
    parser.add_argument("--reuse-decisions")
    parser.add_argument("--project-profile")
    parser.add_argument("--canonical-registry")
    parser.add_argument("--changed-contract", action="append", default=[])
    parser.add_argument("--owner-boundary-artifact", action="append", default=[])
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if not args.check_reuse and not args.check_profile:
        parser.error("укажите --check-reuse и/или --check-profile")
    root = Path(args.root).resolve()
    findings: list[RuleFinding] = []
    try:
        if args.check_reuse:
            findings.extend(validate_reuse_decisions(
                root,
                decisions_path=Path(args.reuse_decisions).resolve() if args.reuse_decisions else None,
                canonical_registry_path=Path(args.canonical_registry).resolve() if args.canonical_registry else None,
            ))
        if args.check_profile:
            findings.extend(validate_ecosystem_profile(
                root,
                profile_path=Path(args.project_profile).resolve() if args.project_profile else None,
                changed_contracts=set(args.changed_contract),
                owner_artifacts=parse_owner_artifact_args(args.owner_boundary_artifact),
            ))
    except Exception as exc:  # fail-closed: вызывающий получает код, не traceback
        findings.append(_finding("ECOSYSTEM_VALIDATOR_INTERNAL_ERROR", REUSE_RULE, "Внутренняя ошибка проверки блокирует продолжение", detail=f"{type(exc).__name__}: {exc}"))
    _emit(findings, args.json)
    return 1 if any(item.severity == "ERROR" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
