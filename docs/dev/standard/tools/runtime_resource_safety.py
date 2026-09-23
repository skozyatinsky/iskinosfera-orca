#!/usr/bin/env python3
"""Проверяет договор безопасного допуска тяжёлых локальных операций."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator

from rule_traceability_types import (
    RuleFinding,
    emits_diagnostic,
    enforces_rule,
    print_diagnostic,
)

DEFAULT_POLICY = Path("docs/registry/runtime_resource_safety.json")
SCHEMA = Path(__file__).resolve().parent.parent / "schemas" / "runtime_resource_safety.schema.json"
AUDIT_FIELDS = {
    "operation_id",
    "resource_snapshot",
    "thresholds",
    "policy_version",
    "human_decision",
    "timestamp",
    "correlation_id",
}
REQUIRED_INSTALLED_SUFFIXES = {
    "RUNTIME_RESOURCE_SAFETY_STANDARD.md",
    "runtime_resource_safety.py",
}


@dataclass(frozen=True)
class AdmissionDecision:
    status: str
    code: str
    operation_id: str
    reason: str
    consumed_confirmation_id: str | None = None


class ContractError(ValueError):
    """Вход не является строгим договором JSON."""


def _finding(code: str, rule_id: str, message: str, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def _pass(rule_id: str, code: str, message: str, **evidence: Any) -> list[RuleFinding]:
    return [_finding(code, rule_id, message, "INFO", **evidence)]


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ContractError(f"Повторяющийся ключ JSON: {key}")
        result[key] = value
    return result


def load_policy(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes().decode("utf-8-sig")
        data = json.loads(raw, object_pairs_hook=_strict_object)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ContractError) as exc:
        raise ContractError(f"Не удалось прочитать строгий JSON {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ContractError("Корень политики должен быть объектом")
    return data


def _inside(root: Path, relative: Any) -> Path | None:
    if not isinstance(relative, str) or not relative or Path(relative).is_absolute():
        return None
    try:
        candidate = (root / relative).resolve()
        candidate.relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError):
        return None
    return candidate


@enforces_rule("APS-CORE-RESOURCEOPERATION-001")
@emits_diagnostic("APS-CORE-RESOURCEOPERATION-001", "RESOURCE_OPERATION_VALID")
@emits_diagnostic("APS-CORE-RESOURCEOPERATION-001", "RESOURCE_OPERATION_INVALID")
def validate_operation_declaration(root: Path, operation: dict[str, Any]) -> list[RuleFinding]:
    rule_id = "APS-CORE-RESOURCEOPERATION-001"
    findings: list[RuleFinding] = []
    threshold_path = _inside(root, operation.get("thresholds_path"))
    if threshold_path is None or not threshold_path.is_file():
        findings.append(_finding(
            "RESOURCE_OPERATION_INVALID",
            rule_id,
            "Пороговые значения должны находиться в существующем файле конфигурации.",
            path=operation.get("thresholds_path"),
        ))
    if operation.get("check_immediately_before_allocation") is not True:
        findings.append(_finding(
            "RESOURCE_OPERATION_INVALID",
            rule_id,
            "Нужна проверка непосредственно перед выделением ресурсов.",
        ))
    boundaries = operation.get("safe_boundaries")
    if not isinstance(boundaries, list) or not boundaries:
        findings.append(_finding(
            "RESOURCE_OPERATION_INVALID",
            rule_id,
            "Нужна хотя бы одна безопасная граница повторного измерения.",
        ))
    if findings:
        return findings
    return _pass(rule_id, "RESOURCE_OPERATION_VALID", "Тяжёлая операция и границы повторной проверки объявлены.")


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


@enforces_rule("APS-CORE-RESOURCECONFIRMATION-001")
@emits_diagnostic("APS-CORE-RESOURCECONFIRMATION-001", "RESOURCE_CONFIRMATION_VALID")
@emits_diagnostic("APS-CORE-RESOURCECONFIRMATION-001", "RESOURCE_CONFIRMATION_REQUIRED")
@emits_diagnostic("APS-CORE-RESOURCECONFIRMATION-001", "RESOURCE_CONFIRMATION_INVALID")
def validate_runtime_confirmation(
    operation: dict[str, Any],
    policy_version: str,
    confirmation: dict[str, Any] | None,
    *,
    now: datetime | None = None,
    consumed_confirmation_ids: frozenset[str] = frozenset(),
) -> list[RuleFinding]:
    rule_id = "APS-CORE-RESOURCECONFIRMATION-001"
    if confirmation is None:
        return [_finding(
            "RESOURCE_CONFIRMATION_REQUIRED",
            rule_id,
            "Предупредительное состояние требует отдельного подтверждения.",
        )]
    current = now or datetime.now(timezone.utc)
    issued_at = _parse_time(confirmation.get("issued_at"))
    expires_at = _parse_time(confirmation.get("expires_at"))
    confirmation_id = confirmation.get("confirmation_id")
    confirmation_policy = operation.get("confirmation")
    ttl_seconds = (
        confirmation_policy.get("ttl_seconds")
        if isinstance(confirmation_policy, dict)
        else None
    )
    lifetime = (
        (expires_at - issued_at).total_seconds()
        if issued_at is not None and expires_at is not None
        else None
    )
    valid = (
        isinstance(confirmation_id, str)
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{7,127}", confirmation_id) is not None
        and confirmation_id not in consumed_confirmation_ids
        and confirmation.get("operation_id") == operation.get("operation_id")
        and confirmation.get("policy_version") == policy_version
        and confirmation.get("single_use") is True
        and isinstance(ttl_seconds, int)
        and not isinstance(ttl_seconds, bool)
        and issued_at is not None
        and expires_at is not None
        and issued_at <= current < expires_at
        and lifetime is not None
        and 0 < lifetime <= ttl_seconds
    )
    if not valid:
        return [_finding(
            "RESOURCE_CONFIRMATION_INVALID",
            rule_id,
            "Подтверждение недействительно, уже использовано, истекло или превышает установленный срок.",
        )]
    return _pass(
        rule_id,
        "RESOURCE_CONFIRMATION_VALID",
        "Одноразовое подтверждение действительно и должно быть атомарно отмечено использованным.",
        confirmation_id=confirmation_id,
    )


@enforces_rule("APS-CORE-RESOURCEADMISSION-001")
@emits_diagnostic("APS-CORE-RESOURCEADMISSION-001", "RESOURCE_SAFE_ALLOWED")
@emits_diagnostic("APS-CORE-RESOURCEADMISSION-001", "RESOURCE_CONFIRMATION_REQUIRED")
@emits_diagnostic("APS-CORE-RESOURCEADMISSION-001", "RESOURCE_WARNING_CONFIRMED")
@emits_diagnostic("APS-CORE-RESOURCEADMISSION-001", "RESOURCE_CRITICAL_DENIED")
@emits_diagnostic("APS-CORE-RESOURCEADMISSION-001", "RESOURCE_RESERVATION_DENIED")
def decide_resource_admission(
    operation: dict[str, Any],
    policy_version: str,
    resource_state: str,
    *,
    confirmation: dict[str, Any] | None = None,
    now: datetime | None = None,
    consumed_confirmation_ids: frozenset[str] = frozenset(),
    confirmation_consumer: Callable[[str], bool] | None = None,
    coordinator_available: bool = True,
    reservation_granted: bool = True,
) -> AdmissionDecision:
    operation_id = str(operation.get("operation_id", ""))
    if resource_state == "critical":
        return AdmissionDecision("DENY", "RESOURCE_CRITICAL_DENIED", operation_id, "Достигнут критический предел.")
    if coordinator_available and not reservation_granted:
        return AdmissionDecision("DENY", "RESOURCE_RESERVATION_DENIED", operation_id, "Общий диспетчер не выдал бронирование.")
    if resource_state == "warning":
        confirmation_findings = validate_runtime_confirmation(
            operation,
            policy_version,
            confirmation,
            now=now,
            consumed_confirmation_ids=consumed_confirmation_ids,
        )
        if any(item.severity == "ERROR" for item in confirmation_findings):
            code = confirmation_findings[0].code
            return AdmissionDecision("REQUIRE_CONFIRMATION", code, operation_id, confirmation_findings[0].message)
        confirmation_id = str(confirmation.get("confirmation_id")) if confirmation else None
        try:
            consumed = confirmation_consumer(confirmation_id) if confirmation_consumer and confirmation_id else False
        except Exception:
            consumed = False
        if not consumed:
            return AdmissionDecision(
                "REQUIRE_CONFIRMATION",
                "RESOURCE_CONFIRMATION_INVALID",
                operation_id,
                "Одноразовое подтверждение не удалось атомарно отметить использованным.",
            )
        return AdmissionDecision(
            "ALLOW",
            "RESOURCE_WARNING_CONFIRMED",
            operation_id,
            "Разрешён один запуск после атомарного погашения подтверждения.",
            confirmation_id,
        )
    if resource_state == "safe":
        reason = "Локальное измерение безопасно." if not coordinator_available else "Измерение и бронирование безопасны."
        return AdmissionDecision("ALLOW", "RESOURCE_SAFE_ALLOWED", operation_id, reason)
    return AdmissionDecision("DENY", "RESOURCE_CRITICAL_DENIED", operation_id, "Неизвестное состояние не разрешает запуск.")


@enforces_rule("APS-CORE-RESOURCECOORDINATION-001")
@emits_diagnostic("APS-CORE-RESOURCECOORDINATION-001", "RESOURCE_COORDINATION_VALID")
@emits_diagnostic("APS-CORE-RESOURCECOORDINATION-001", "RESOURCE_COORDINATION_INVALID")
def validate_coordination_contract(operation: dict[str, Any]) -> list[RuleFinding]:
    rule_id = "APS-CORE-RESOURCECOORDINATION-001"
    coordination = operation.get("coordination")
    if not isinstance(coordination, dict):
        return [_finding("RESOURCE_COORDINATION_INVALID", rule_id, "Договор координации отсутствует.")]
    shared = coordination.get("shared_machine") is True
    reservation_ttl = coordination.get("reservation_ttl_seconds")
    concurrency_limit = coordination.get("concurrency_limit")
    if (
        not isinstance(reservation_ttl, int)
        or isinstance(reservation_ttl, bool)
        or reservation_ttl <= 0
        or not isinstance(concurrency_limit, int)
        or isinstance(concurrency_limit, bool)
        or concurrency_limit <= 0
    ):
        return [_finding(
            "RESOURCE_COORDINATION_INVALID",
            rule_id,
            "Срок бронирования и предел параллельности должны быть положительными целыми числами.",
        )]
    if shared and (
        coordination.get("mode") != "common_admission_coordinator"
        or coordination.get("reservation") is not True
        or coordination.get("heartbeat") is not True
    ):
        return [_finding(
            "RESOURCE_COORDINATION_INVALID",
            rule_id,
            "Общая машина требует общего диспетчера, бронирования и контрольного сигнала.",
        )]
    if not shared and coordination.get("mode") != "single_product_local":
        return [_finding(
            "RESOURCE_COORDINATION_INVALID",
            rule_id,
            "Локальный режим допустим только для машины одного продукта.",
        )]
    if coordination.get("unavailable_behavior") != "local_measurement_fail_closed":
        return [_finding(
            "RESOURCE_COORDINATION_INVALID",
            rule_id,
            "Недоступность общего диспетчера не должна разрешать запуск без локального измерения.",
        )]
    return _pass(rule_id, "RESOURCE_COORDINATION_VALID", "Координация и безопасный запасной режим объявлены.")


@enforces_rule("APS-CORE-RESOURCEAUDIT-001")
@emits_diagnostic("APS-CORE-RESOURCEAUDIT-001", "RESOURCE_AUDIT_VALID")
@emits_diagnostic("APS-CORE-RESOURCEAUDIT-001", "RESOURCE_AUDIT_INVALID")
def validate_audit_contract(operation: dict[str, Any]) -> list[RuleFinding]:
    rule_id = "APS-CORE-RESOURCEAUDIT-001"
    audit = operation.get("audit") if isinstance(operation.get("audit"), dict) else {}
    message = operation.get("warning_message") if isinstance(operation.get("warning_message"), dict) else {}
    fields = set(audit.get("fields", [])) if isinstance(audit.get("fields"), list) else set()
    risks = set(message.get("explains_risks", [])) if isinstance(message.get("explains_risks"), list) else set()
    if not AUDIT_FIELDS.issubset(fields):
        return [_finding(
            "RESOURCE_AUDIT_INVALID",
            rule_id,
            "Журнал аудита не содержит все обязательные поля.",
            missing=sorted(AUDIT_FIELDS - fields),
        )]
    if message.get("shows_current_and_limits") is not True or message.get("blame_free") is not True:
        return [_finding(
            "RESOURCE_AUDIT_INVALID",
            rule_id,
            "Предупреждение должно показывать измерения и не перекладывать ответственность.",
        )]
    if not {"hang", "restart", "unsaved_data_loss"}.issubset(risks):
        return [_finding(
            "RESOURCE_AUDIT_INVALID",
            rule_id,
            "Предупреждение должно объяснять все обязательные последствия.",
        )]
    confirmation = operation.get("confirmation") if isinstance(operation.get("confirmation"), dict) else {}
    if confirmation.get("permanent_disable_allowed") is not False:
        return [_finding(
            "RESOURCE_AUDIT_INVALID",
            rule_id,
            "Постоянное отключение предупреждений запрещено.",
        )]
    return _pass(rule_id, "RESOURCE_AUDIT_VALID", "Настройки, аудит и объяснение риска соответствуют договору.")


def _git_is_ancestor(repository: Path, commit: str, main_ref: str) -> bool:
    try:
        resolved = subprocess.run(
            ["git", "rev-parse", "--verify", f"{main_ref}^{{commit}}"],
            cwd=repository,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, resolved],
            cwd=repository,
            text=True,
            capture_output=True,
            check=False,
        )
    except (OSError, subprocess.CalledProcessError):
        return False
    return result.returncode == 0


def _verified_source_files(consumer_root: Path, source: dict[str, Any]) -> bool:
    files = source.get("files")
    if not isinstance(files, dict):
        return False
    standard_root = consumer_root / "docs/dev/standard"
    matched: set[str] = set()
    for relative, expected_hash in files.items():
        if not isinstance(relative, str) or not isinstance(expected_hash, str):
            continue
        suffix = next((item for item in REQUIRED_INSTALLED_SUFFIXES if relative.endswith(item)), None)
        if suffix is None:
            continue
        path = _inside(standard_root, relative)
        if path is None or not path.is_file():
            return False
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected_hash:
            return False
        matched.add(suffix)
    return matched == REQUIRED_INSTALLED_SUFFIXES


@enforces_rule("APS-CORE-RESOURCEROLLOUT-001")
@emits_diagnostic("APS-CORE-RESOURCEROLLOUT-001", "RESOURCE_ROLLOUT_NOT_CLAIMED")
@emits_diagnostic("APS-CORE-RESOURCEROLLOUT-001", "RESOURCE_ROLLOUT_VERIFIED")
@emits_diagnostic("APS-CORE-RESOURCEROLLOUT-001", "RESOURCE_ROLLOUT_MAIN_REQUIRED")
@emits_diagnostic("APS-CORE-RESOURCEROLLOUT-001", "RESOURCE_ROLLOUT_SOURCE_REQUIRED")
@emits_diagnostic("APS-CORE-RESOURCEROLLOUT-001", "RESOURCE_ROLLOUT_SOURCE_MISMATCH")
def validate_rollout_claim(
    rollout: dict[str, Any],
    *,
    standard_repository: Path | None = None,
    consumer_root: Path | None = None,
) -> list[RuleFinding]:
    rule_id = "APS-CORE-RESOURCEROLLOUT-001"
    if rollout.get("status") != "rolled_out":
        return _pass(rule_id, "RESOURCE_ROLLOUT_NOT_CLAIMED", "Правило не объявлено раскатанным.")
    commit = rollout.get("release_commit")
    main_ref = rollout.get("main_ref")
    if (
        standard_repository is None
        or not isinstance(commit, str)
        or re.fullmatch(r"[0-9a-f]{40,64}", commit) is None
        or main_ref != "main"
        or not _git_is_ancestor(standard_repository, commit, main_ref)
    ):
        return [_finding(
            "RESOURCE_ROLLOUT_MAIN_REQUIRED",
            rule_id,
            "Коммит выпуска не подтверждён в main.",
            release_commit=commit,
        )]
    if consumer_root is None or rollout.get("consumer_source") != "docs/dev/standard/SOURCE.json":
        return [_finding(
            "RESOURCE_ROLLOUT_SOURCE_REQUIRED",
            rule_id,
            "Нужен SOURCE.json реального проекта-потребителя.",
        )]
    source_path = _inside(consumer_root, rollout["consumer_source"])
    try:
        source = load_policy(source_path) if source_path is not None else None
    except ContractError:
        source = None
    if not isinstance(source, dict):
        return [_finding("RESOURCE_ROLLOUT_SOURCE_REQUIRED", rule_id, "SOURCE.json отсутствует или повреждён.")]
    matches = (
        source.get("standard_version") == rollout.get("standard_version")
        and source.get("release_archive") == rollout.get("release_archive")
        and source.get("release_sha256") == rollout.get("release_sha256")
        and _verified_source_files(consumer_root, source)
    )
    if not matches:
        return [_finding(
            "RESOURCE_ROLLOUT_SOURCE_MISMATCH",
            rule_id,
            "SOURCE.json не подтверждает этот выпуск и установленные файлы слоя.",
        )]
    return _pass(rule_id, "RESOURCE_ROLLOUT_VERIFIED", "Коммит находится в main, SOURCE.json потребителя подтверждён.")


def validate_resource_safety_registry(
    root: Path,
    *,
    policy_path: Path | None = None,
    standard_repository: Path | None = None,
    consumer_root: Path | None = None,
) -> list[RuleFinding]:
    path = policy_path or root / DEFAULT_POLICY
    try:
        data = load_policy(path)
        schema = load_policy(SCHEMA)
    except ContractError as exc:
        return [_finding("RESOURCE_POLICY_INVALID", "APS-CORE-RESOURCEOPERATION-001", str(exc))]
    schema_errors = sorted(Draft202012Validator(schema).iter_errors(data), key=lambda item: list(item.absolute_path))
    if schema_errors:
        return [
            _finding(
                "RESOURCE_POLICY_INVALID",
                "APS-CORE-RESOURCEOPERATION-001",
                error.message,
                path="/".join(str(item) for item in error.absolute_path),
            )
            for error in schema_errors
        ]
    operations = data["operations"]
    applicable = data["applicability"]["heavy_local_operations"]
    if applicable != bool(operations):
        return [_finding(
            "RESOURCE_POLICY_INVALID",
            "APS-CORE-RESOURCEOPERATION-001",
            "operations должен быть непустым только при heavy_local_operations=true.",
        )]
    operation_ids = [item["operation_id"] for item in operations]
    if len(operation_ids) != len(set(operation_ids)):
        return [_finding(
            "RESOURCE_POLICY_INVALID",
            "APS-CORE-RESOURCEOPERATION-001",
            "operation_id должен быть уникальным.",
        )]
    findings: list[RuleFinding] = []
    for operation in operations:
        findings.extend(validate_operation_declaration(root, operation))
        findings.extend(validate_coordination_contract(operation))
        findings.extend(validate_audit_contract(operation))
    findings.extend(validate_rollout_claim(
        data["rollout"],
        standard_repository=standard_repository,
        consumer_root=consumer_root,
    ))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--policy", default=None)
    parser.add_argument("--standard-repository", default=None)
    parser.add_argument("--consumer-root", default=None)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    policy = Path(args.policy).resolve() if args.policy else None
    findings = validate_resource_safety_registry(
        root,
        policy_path=policy,
        standard_repository=Path(args.standard_repository).resolve() if args.standard_repository else None,
        consumer_root=Path(args.consumer_root).resolve() if args.consumer_root else None,
    )
    for finding in findings:
        print_diagnostic(finding)
    return 1 if any(item.severity == "ERROR" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
