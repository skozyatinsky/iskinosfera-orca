#!/usr/bin/env python3
# ======================================================================
# rule_traceability_types.py — версия 2.0
# Общие типы, decorators и structured diagnostics для APS v2.9.141.
# ======================================================================

from __future__ import annotations

import json
from pathlib import Path
from dataclasses import asdict, dataclass, field
from typing import Any, Callable, TypeVar

F = TypeVar("F", bound=Callable[..., Any])


# ======================================================================
# 1. СТРУКТУРИРОВАННАЯ ДИАГНОСТИКА
# Каждое finding несёт точный rule_id и диагностический код.
# ======================================================================

@dataclass(frozen=True, order=True)
class RuleFinding:
    code: str
    rule_id: str
    message: str
    severity: str = "ERROR"
    evidence: dict[str, Any] = field(default_factory=dict, compare=False)

    def legacy(self) -> str:
        """Возвращает стабильное строковое представление для старых API/tests."""
        suffix = self.evidence.get("detail")
        return f"{self.code}:{self.rule_id}" + (f":{suffix}" if suffix else "")

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class MissingCheckInput(Exception):
    """Обязательный вход проверки отсутствует или нечитаем.

    Отдельный тип нужен, чтобы вызывающий отличил «нечего проверять» от
    «проверка сломана» и вернул диагностический код вместо трассировки
    (`APS-CHECK-MISSING-INPUT-001`).
    """


def diagnostic_line(finding: RuleFinding) -> str:
    """Формирует machine-readable строку для runtime test evidence."""
    return "APS_RULE_DIAGNOSTIC:" + json.dumps(
        finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def print_diagnostic(finding: RuleFinding) -> None:
    print(diagnostic_line(finding))


# ======================================================================
# 2. PRODUCTION ANNOTATIONS
# Decorators сохраняют runtime metadata и одновременно распознаются AST-аудитом.
# ======================================================================

def enforces_rule(rule_id: str) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        current = tuple(getattr(func, "__aps_enforces_rules__", ()))
        setattr(func, "__aps_enforces_rules__", (*current, rule_id))
        return func
    return decorator


def emits_diagnostic(rule_id: str, diagnostic_code: str) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        current = tuple(getattr(func, "__aps_emits_diagnostics__", ()))
        setattr(func, "__aps_emits_diagnostics__", (*current, (rule_id, diagnostic_code)))
        return func
    return decorator


# ======================================================================
# 3. TEST ANNOTATIONS
# Полярность и expected diagnostic являются частью структурной связи test→rule.
# ======================================================================

def rule_test(
    rule_id: str,
    polarity: str,
    *,
    expected_diagnostic: str,
) -> Callable[[F], F]:
    if polarity not in {"positive", "negative", "bypass"}:
        raise ValueError(f"unsupported rule test polarity: {polarity}")

    def decorator(func: F) -> F:
        setattr(
            func,
            "__aps_rule_test__",
            {
                "rule_id": rule_id,
                "polarity": polarity,
                "expected_diagnostic": expected_diagnostic,
            },
        )
        return func

    return decorator


@enforces_rule("APS-RULE-FINDING-IDENTITY-001")
@emits_diagnostic("APS-RULE-FINDING-IDENTITY-001", "RULE_FINDING_IDENTITY_COLLAPSED")
def unique_findings(findings: list[RuleFinding]) -> list[RuleFinding]:
    """Убирает дубликаты, не теряя того, какого правила касается находка.

    `RuleFinding.evidence` объявлено `compare=False`, поэтому две записи об
    изменении текста РАЗНЫХ правил равны между собой: код, сообщение и
    уровень у них одинаковые, а `affected_rule_id` живёт в evidence.
    Прежний `sorted(set(findings))` схлопывал их в одну, и отчёт называл
    одно правило из пяти — гарантия неизменности молча превращалась в
    выборку из одного элемента (APS-RULE-FINDING-IDENTITY-001).

    Ключ включает evidence, поэтому настоящие дубликаты по-прежнему
    исчезают, а разные нарушения остаются каждое своей записью.
    """
    seen: set[tuple] = set()
    unique: list[RuleFinding] = []
    for finding in findings:
        key = (
            finding.code,
            finding.rule_id,
            finding.message,
            finding.severity,
            json.dumps(finding.evidence, ensure_ascii=False, sort_keys=True, default=str),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return sorted(unique, key=lambda f: (f.code, f.rule_id, f.severity, f.message,
                                         str(f.evidence.get("affected_rule_id") or ""),
                                         str(f.evidence.get("detail") or "")))


@enforces_rule("APS-CHECK-MISSING-INPUT-001")
@emits_diagnostic("APS-CHECK-MISSING-INPUT-001", "CHECK_INPUT_UNREADABLE")
def load_json_or_fail(path: Path) -> dict[str, Any]:
    """Читает JSON, превращая отсутствие файла в объявленный отказ.

    До v2.9.160 отсутствующий файл ронял валидатор трассировкой: шесть
    флагов трассируемости падали на любом проекте, у которого нет
    `reference/rule_traceability_registry.json` — то есть на любом
    проекте-потребителе.
    """
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except OSError as exc:
        raise MissingCheckInput(f"{path}: {exc.strerror or exc}") from exc
    except json.JSONDecodeError as exc:
        raise MissingCheckInput(f"{path}: {exc}") from exc


def _contract_findings(
    findings: list[RuleFinding],
    *,
    contract_rule_id: str,
    success_code: str,
    success_message: str,
) -> list[RuleFinding]:
    """Привязывает contract-level diagnostic к ID исполняемого правила."""
    errors = [item for item in findings if item.severity == "ERROR"]
    if not errors:
        return [RuleFinding(success_code, contract_rule_id, success_message, "INFO", {})]
    return [
        RuleFinding(
            item.code,
            contract_rule_id,
            item.message,
            item.severity,
            {**item.evidence, "affected_rule_id": item.rule_id},
        )
        for item in findings
    ]
