"""Проверяет локальные решения о переиспользовании по внешнему канону."""

from __future__ import annotations

import hashlib
import re
from datetime import date
from pathlib import Path
from typing import Any

from ecosystem_validation_common import (
    CONSUMER_RULE,
    DEFAULT_REUSE_PATH,
    REUSE_RULE,
    absolute_delivery,
    existing_relative,
    finding,
    is_safe_relative,
    load_and_check_schema,
    load_json,
    valid_iso_date,
    with_pass,
)
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule


def _strip_yaml_comment(value: str) -> str:
    quote: str | None = None
    for index, char in enumerate(value):
        if char in {"'", '"'}:
            quote = None if quote == char else (char if quote is None else quote)
        elif char == "#" and quote is None:
            return value[:index].rstrip()
    return value.rstrip()


def _yaml_scalar(value: str) -> Any:
    value = _strip_yaml_comment(value).strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return None if value in {"null", "~"} else value


def _parse_canonical_registry(
    path: Path,
) -> tuple[str | None, list[dict[str, Any]], str | None]:
    """Читает только поля канона, нужные для проверки; внешних YAML-зависимостей нет."""
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except (OSError, UnicodeError) as exc:
        return None, [], str(exc)
    version: str | None = None
    section: str | None = None
    current: dict[str, Any] | None = None
    active_list: str | None = None
    records: list[dict[str, Any]] = []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        top = re.match(r"^(?P<name>[A-Za-z_][A-Za-z0-9_-]*):\s*(?P<value>.*)$", raw)
        if top:
            if current:
                records.append(current)
                current = None
            section = top.group("name")
            active_list = None
            continue
        if section == "meta":
            match = re.match(r"^\s{2}version:\s*(?P<value>.+)$", raw)
            if match:
                version = str(_yaml_scalar(match.group("value")))
            continue
        start = re.match(
            r"^\s{2}-\s+(?P<key>[A-Za-z_][A-Za-z0-9_-]*):\s*(?P<value>.*)$",
            raw,
        )
        if start:
            if current:
                records.append(current)
            current = {
                "_section": section,
                start.group("key"): _yaml_scalar(start.group("value")),
            }
            active_list = None
            continue
        if current is None:
            continue
        field_match = re.match(
            r"^\s{4}(?P<key>[A-Za-z_][A-Za-z0-9_-]*):\s*(?P<value>.*)$",
            raw,
        )
        if field_match:
            key = field_match.group("key")
            raw_value = field_match.group("value")
            meaningful_value = _strip_yaml_comment(raw_value).strip()
            if meaningful_value:
                current[key] = _yaml_scalar(meaningful_value)
                active_list = None
            else:
                current[key] = []
                active_list = key
            continue
        list_item = re.match(r"^\s{6}-\s+(?P<value>.+)$", raw)
        if list_item and active_list:
            current.setdefault(active_list, []).append(
                _yaml_scalar(list_item.group("value"))
            )
    if current:
        records.append(current)
    return version, records, None


def _canon_index(
    records: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    candidates: dict[str, list[dict[str, Any]]] = {}
    for record in records:
        values: list[str] = []
        for field_name in ("id", "canon", "canon_id"):
            value = record.get(field_name)
            if isinstance(value, str) and value:
                values.append(value)
                if "/" in value:
                    values.append(value.rstrip("/").rsplit("/", 1)[-1])
        for value in values:
            candidates.setdefault(value.casefold(), []).append(record)
    ambiguous = {
        key
        for key, values in candidates.items()
        if len({id(item) for item in values}) > 1
    }
    return {
        key: values[0]
        for key, values in candidates.items()
        if key not in ambiguous
    }, ambiguous


def _consumer_matches(project_id: str, consumers: Any) -> bool:
    if not isinstance(consumers, list):
        return False
    expected = project_id.casefold()
    return any(
        isinstance(value, str)
        and (
            value.casefold() == expected
            or value.casefold().split("/", 1)[0] == expected
        )
        for value in consumers
    )


def _relative_evidence(root: Path, values: Any, context: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for value in values if isinstance(values, list) else []:
        if existing_relative(root, value) is None:
            findings.append(
                finding(
                    "ECOSYSTEM_REUSE_INPUT_INVALID",
                    REUSE_RULE,
                    f"{context}: доказательство отсутствует или путь небезопасен",
                    path=value,
                )
            )
    return findings


def _validate_adopted(
    root: Path,
    project_id: str,
    decision: dict[str, Any],
    record: dict[str, Any] | None,
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    decision_id = decision.get("decision_id")
    canon_id = decision.get("canon_id")
    for required in ("canon_id", "required_version", "dependency", "integration_test"):
        if required not in decision:
            findings.append(
                finding(
                    "ECOSYSTEM_REUSE_INPUT_INVALID",
                    REUSE_RULE,
                    "Для adopted не хватает обязательного поля",
                    decision_id=decision_id,
                    field=required,
                )
            )
    if record is not None:
        if record.get("status") != "canon":
            findings.append(
                finding(
                    "ECOSYSTEM_CANON_UNKNOWN",
                    REUSE_RULE,
                    "adopted разрешён только для записи со статусом canon",
                    canon_id=canon_id,
                    status=record.get("status"),
                )
            )
        if record.get("version") not in {None, decision.get("required_version")}:
            findings.append(
                finding(
                    "ECOSYSTEM_CANON_VERSION_MISMATCH",
                    REUSE_RULE,
                    "Требуемая версия не совпадает с канонической",
                    canon_id=canon_id,
                    expected=decision.get("required_version"),
                    observed=record.get("version"),
                )
            )
        if absolute_delivery(record.get("install")):
            findings.append(
                finding(
                    "ECOSYSTEM_ABSOLUTE_DELIVERY_FORBIDDEN",
                    REUSE_RULE,
                    "Канон предлагает абсолютный локальный путь поставки",
                    canon_id=canon_id,
                    install=record.get("install"),
                )
            )
        if not _consumer_matches(project_id, record.get("consumers")):
            findings.append(
                finding(
                    "ECOSYSTEM_ADOPTED_CONSUMER_UNREGISTERED",
                    CONSUMER_RULE,
                    "adopted требует реального потребителя в каноническом реестре",
                    project_id=project_id,
                    canon_id=canon_id,
                )
            )
    findings.extend(_validate_dependency(root, decision))
    findings.extend(_validate_integration_test(root, decision))
    return findings


def _validate_dependency(root: Path, decision: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    dependency = decision.get("dependency")
    dependency = dependency if isinstance(dependency, dict) else {}
    decision_id = decision.get("decision_id")
    declaration = str(dependency.get("declaration", ""))
    if absolute_delivery(declaration):
        findings.append(
            finding(
                "ECOSYSTEM_ABSOLUTE_DELIVERY_FORBIDDEN",
                REUSE_RULE,
                "Зависимость не может поставляться по абсолютному локальному пути",
                decision_id=decision_id,
                declaration=declaration,
            )
        )
    manifest = existing_relative(root, dependency.get("manifest_path"))
    pin = dependency.get("pin") if isinstance(dependency.get("pin"), dict) else {}
    pin_kind = pin.get("kind")
    pin_value = str(pin.get("value", ""))
    pin_valid = (
        pin_kind == "sha256" and re.fullmatch(r"[a-fA-F0-9]{64}", pin_value)
    ) or (
        pin_kind == "git_commit" and re.fullmatch(r"[a-fA-F0-9]{7,64}", pin_value)
    )
    if not pin_valid:
        findings.append(
            finding(
                "ECOSYSTEM_DEPENDENCY_MISSING",
                REUSE_RULE,
                "Закрепление зависимости не является sha256 или Git-коммитом",
                decision_id=decision_id,
                pin_kind=pin_kind,
            )
        )
    if manifest is None:
        findings.append(
            finding(
                "ECOSYSTEM_DEPENDENCY_MISSING",
                REUSE_RULE,
                "Файл зависимостей отсутствует или путь небезопасен",
                decision_id=decision_id,
                path=dependency.get("manifest_path"),
            )
        )
    else:
        manifest_text = manifest.read_text(encoding="utf-8", errors="ignore")
        if declaration not in manifest_text or pin_value not in manifest_text:
            findings.append(
                finding(
                    "ECOSYSTEM_DEPENDENCY_MISSING",
                    REUSE_RULE,
                    "В манифесте нет точной зависимости и закрепления",
                    decision_id=decision_id,
                    path=dependency.get("manifest_path"),
                )
            )
    if dependency.get("version") != decision.get("required_version"):
        findings.append(
            finding(
                "ECOSYSTEM_CANON_VERSION_MISMATCH",
                REUSE_RULE,
                "Версия зависимости не совпадает с required_version",
                decision_id=decision_id,
            )
        )
    return findings


def _validate_integration_test(root: Path, decision: dict[str, Any]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    test = decision.get("integration_test")
    test = test if isinstance(test, dict) else {}
    decision_id = decision.get("decision_id")
    test_path = existing_relative(root, test.get("path"))
    if test_path is None:
        findings.append(
            finding(
                "ECOSYSTEM_INTEGRATION_TEST_MISSING",
                REUSE_RULE,
                "Интеграционный тест отсутствует или путь небезопасен",
                decision_id=decision_id,
                path=test.get("path"),
            )
        )
    else:
        test_text = test_path.read_text(encoding="utf-8", errors="ignore")
        marker = str(test.get("canon_marker", ""))
        if not test_text.strip() or marker not in test_text:
            findings.append(
                finding(
                    "ECOSYSTEM_INTEGRATION_TEST_MISSING",
                    REUSE_RULE,
                    "Интеграционный тест не содержит маркер канона",
                    decision_id=decision_id,
                    marker=marker,
                )
            )
    if absolute_delivery(test.get("command")):
        findings.append(
            finding(
                "ECOSYSTEM_ABSOLUTE_DELIVERY_FORBIDDEN",
                REUSE_RULE,
                "Команда интеграционного теста содержит абсолютный путь",
                decision_id=decision_id,
            )
        )
    return findings


def _validate_other_status(
    root: Path,
    validation_day: date,
    project_id: str,
    decision: dict[str, Any],
    record: dict[str, Any] | None,
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    status = decision.get("status")
    decision_id = decision.get("decision_id")
    if status == "expected":
        if "dependency" in decision or "integration_test" in decision:
            findings.append(
                finding(
                    "ECOSYSTEM_REUSE_INPUT_INVALID",
                    REUSE_RULE,
                    "expected не может выдавать будущую зависимость или тест за подключение",
                    decision_id=decision_id,
                )
            )
        if record is not None and _consumer_matches(project_id, record.get("consumers")):
            findings.append(
                finding(
                    "ECOSYSTEM_EXPECTED_CONSUMER_MARKED_REAL",
                    CONSUMER_RULE,
                    "Локальный expected расходится с записью реального потребителя",
                    project_id=project_id,
                    canon_id=decision.get("canon_id"),
                )
            )
    elif status == "waiver":
        waiver = decision.get("waiver")
        waiver = waiver if isinstance(waiver, dict) else {}
        expiry = valid_iso_date(waiver.get("expires_on"))
        if expiry is None or expiry < validation_day:
            findings.append(
                finding(
                    "ECOSYSTEM_WAIVER_EXPIRED",
                    REUSE_RULE,
                    "Исключение просрочено или дата неверна",
                    decision_id=decision_id,
                    expires_on=waiver.get("expires_on"),
                )
            )
        if existing_relative(root, waiver.get("adr")) is None:
            findings.append(
                finding(
                    "ECOSYSTEM_REUSE_INPUT_INVALID",
                    REUSE_RULE,
                    "ADR исключения отсутствует или путь небезопасен",
                    decision_id=decision_id,
                    path=waiver.get("adr"),
                )
            )
    elif status == "proposed" and existing_relative(root, decision.get("proposal_adr")) is None:
        findings.append(
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "proposed требует существующий ADR-кандидат",
                decision_id=decision_id,
                path=decision.get("proposal_adr"),
            )
        )
    if status in {"local", "waiver", "proposed"} and any(
        key in decision for key in ("dependency", "integration_test")
    ):
        findings.append(
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "Только adopted подтверждает реальную зависимость и интеграционный тест",
                decision_id=decision_id,
                status=status,
            )
        )
    return findings


def _validate_machine_contract(decision: dict[str, Any]) -> list[RuleFinding]:
    contract = decision.get("machine_contract")
    if not isinstance(contract, dict):
        return []
    findings: list[RuleFinding] = []
    decision_id = decision.get("decision_id")
    mode = contract.get("mode")
    local_path = contract.get("local_path")
    if mode not in {"owner_reference", "package", "generated"}:
        findings.append(
            finding(
                "ECOSYSTEM_MANUAL_CONTRACT_COPY_FORBIDDEN",
                REUSE_RULE,
                "Ручная копия машинного договора запрещена",
                decision_id=decision_id,
                mode=mode,
            )
        )
    if not is_safe_relative(contract.get("owner_path")):
        findings.append(
            finding(
                "ECOSYSTEM_ABSOLUTE_DELIVERY_FORBIDDEN",
                REUSE_RULE,
                "Путь договора владельца должен быть относительным",
                decision_id=decision_id,
            )
        )
    if local_path is not None and mode != "generated":
        findings.append(
            finding(
                "ECOSYSTEM_MANUAL_CONTRACT_COPY_FORBIDDEN",
                REUSE_RULE,
                "Локальный договор допустим только как воспроизводимо сгенерированный артефакт",
                decision_id=decision_id,
                local_path=local_path,
            )
        )
    return findings


def _canonical_context(
    data: dict[str, Any],
    registry_path: Path,
) -> tuple[list[RuleFinding], dict[str, dict[str, Any]], set[str]]:
    findings: list[RuleFinding] = []
    source = data.get("registry_source")
    source = source if isinstance(source, dict) else {}
    if not is_safe_relative(source.get("path")):
        findings.append(
            finding(
                "ECOSYSTEM_ABSOLUTE_DELIVERY_FORBIDDEN",
                REUSE_RULE,
                "Путь к каноническому реестру должен быть относительным",
                value=source.get("path"),
            )
        )
    actual_digest = hashlib.sha256(registry_path.read_bytes()).hexdigest()
    if source.get("sha256") != actual_digest:
        findings.append(
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "Контрольная сумма канонического реестра не совпадает",
                expected=source.get("sha256"),
                observed=actual_digest,
            )
        )
    version, records, error = _parse_canonical_registry(registry_path)
    if error:
        findings.append(
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "Канонический реестр не читается",
                detail=error,
            )
        )
        return findings, {}, set()
    if source.get("version") != version:
        findings.append(
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "Версия закреплённого реестра не совпадает",
                expected=source.get("version"),
                observed=version,
            )
        )
    index, ambiguous = _canon_index(records)
    return findings, index, ambiguous


@enforces_rule("APS-CORE-ECOSYSTEMREUSE-001")
@enforces_rule("APS-CORE-CONSUMERSTATUS-001")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_REUSE_VALID")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_REUSE_INPUT_INVALID")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_CANON_UNKNOWN")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_CANON_VERSION_MISMATCH")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_DEPENDENCY_MISSING")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_INTEGRATION_TEST_MISSING")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_WAIVER_EXPIRED")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_ABSOLUTE_DELIVERY_FORBIDDEN")
@emits_diagnostic("APS-CORE-ECOSYSTEMREUSE-001", "ECOSYSTEM_MANUAL_CONTRACT_COPY_FORBIDDEN")
@emits_diagnostic("APS-CORE-CONSUMERSTATUS-001", "ECOSYSTEM_CONSUMER_STATUS_VALID")
@emits_diagnostic("APS-CORE-CONSUMERSTATUS-001", "ECOSYSTEM_ADOPTED_CONSUMER_UNREGISTERED")
@emits_diagnostic("APS-CORE-CONSUMERSTATUS-001", "ECOSYSTEM_EXPECTED_CONSUMER_MARKED_REAL")
def validate_reuse_decisions(
    root: Path,
    *,
    decisions_path: Path | None = None,
    canonical_registry_path: Path | None = None,
    today: date | None = None,
) -> list[RuleFinding]:
    """Проверяет локальные решения, не создавая и не меняя центральный реестр."""
    local_path = decisions_path or (root / DEFAULT_REUSE_PATH)
    data, error = load_json(local_path)
    if error or not isinstance(data, dict):
        return [
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "reuse_decisions.json не читается",
                path=str(local_path),
                detail=error,
            )
        ]
    findings = [
        finding(
            "ECOSYSTEM_REUSE_INPUT_INVALID",
            REUSE_RULE,
            "reuse_decisions.json не соответствует схеме",
            detail=detail,
        )
        for detail in load_and_check_schema(data, "reuse_decisions.schema.json")
    ]
    if canonical_registry_path is None or not canonical_registry_path.is_file():
        findings.append(
            finding(
                "ECOSYSTEM_REUSE_INPUT_INVALID",
                REUSE_RULE,
                "Нужен явно переданный канонический shared_modules.yaml из репозитория-владельца или временной рабочей копии для CI",
                registry=str(canonical_registry_path) if canonical_registry_path else None,
            )
        )
        return findings
    context_findings, canon_by_id, ambiguous = _canonical_context(
        data, canonical_registry_path
    )
    findings.extend(context_findings)
    project_id = str(data.get("project_id", ""))
    decisions = data.get("decisions") if isinstance(data.get("decisions"), list) else []
    decision_ids: set[str] = set()
    for index, decision in enumerate(decisions):
        if not isinstance(decision, dict):
            continue
        decision_id = str(decision.get("decision_id", ""))
        if decision_id in decision_ids:
            findings.append(
                finding(
                    "ECOSYSTEM_REUSE_INPUT_INVALID",
                    REUSE_RULE,
                    "decision_id должен быть уникальным",
                    decision_id=decision_id,
                )
            )
        decision_ids.add(decision_id)
        findings.extend(_relative_evidence(root, decision.get("evidence"), f"decisions[{index}]"))
        status = decision.get("status")
        record: dict[str, Any] | None = None
        if status in {"adopted", "expected"}:
            key = str(decision.get("canon_id") or "").casefold()
            if key in ambiguous or key not in canon_by_id:
                findings.append(
                    finding(
                        "ECOSYSTEM_CANON_UNKNOWN",
                        REUSE_RULE,
                        "canon_id отсутствует в переданном каноническом реестре или неоднозначен",
                        decision_id=decision_id,
                        canon_id=decision.get("canon_id"),
                    )
                )
            else:
                record = canon_by_id[key]
        if status == "adopted":
            findings.extend(_validate_adopted(root, project_id, decision, record))
        else:
            findings.extend(
                _validate_other_status(
                    root, today or date.today(), project_id, decision, record
                )
            )
        findings.extend(_validate_machine_contract(decision))
    with_pass(
        findings,
        REUSE_RULE,
        "ECOSYSTEM_REUSE_VALID",
        "Локальные решения ссылаются на закреплённый канон и подтверждены файлами",
        decisions=len(decisions),
    )
    with_pass(
        findings,
        CONSUMER_RULE,
        "ECOSYSTEM_CONSUMER_STATUS_VALID",
        "adopted и expected не смешаны с реальными потребителями",
    )
    return findings
