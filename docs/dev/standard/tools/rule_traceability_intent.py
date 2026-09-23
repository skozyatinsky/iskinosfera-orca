#!/usr/bin/env python3
# ======================================================================
# rule_traceability_intent.py — версия 1.0
# APS-RULE-INTENT-001: правило объявляет свою цену и свой результат.
# Вынесено из rule_traceability.py ради предела размера исходника.
# ======================================================================
from __future__ import annotations

import re
from typing import Any

from rule_traceability_types import (
    RuleFinding,
    _contract_findings,
    emits_diagnostic,
    enforces_rule,
)

INTENT_RULE_ID = "APS-RULE-INTENT-001"
# Версия, начиная с которой правило обязано объявлять цену и результат.
# Более ранние правила заполняются по мере пересмотра, а не пакетно.
INTENT_REQUIRED_FROM = (2, 9, 166)


def _version_tuple(value: str) -> tuple[int, ...]:
    """Версия как кортеж; неразбираемое значение не считается новым правилом."""
    parts = re.findall(r"\d+", value or "")
    return tuple(int(part) for part in parts[:3]) if parts else (0,)


def _intent_findings(rule: dict[str, Any]) -> list[RuleFinding]:
    rule_id = rule.get("rule_id", "<unknown>")
    title = (rule.get("title") or "").strip().casefold()
    required = _version_tuple(rule.get("introduced_in") or "") >= INTENT_REQUIRED_FROM
    findings: list[RuleFinding] = []
    for field, code in (("cost", "RULE_INTENT_COST_MISSING"),
                        ("observable_effect", "RULE_INTENT_EFFECT_MISSING")):
        value = (rule.get(field) or "").strip()
        if not value:
            if required:
                findings.append(RuleFinding(
                    code, INTENT_RULE_ID,
                    f"Rule {rule_id} introduced in {rule.get('introduced_in')} declares no {field}.",
                    "ERROR", {"affected_rule_id": rule_id, "field": field},
                ))
            continue
        if value.casefold() == title:
            findings.append(RuleFinding(
                "RULE_INTENT_RESTATES_TITLE", INTENT_RULE_ID,
                f"Rule {rule_id} field {field} only restates the title.",
                "ERROR", {"affected_rule_id": rule_id, "field": field},
            ))
    return findings


@enforces_rule("APS-RULE-INTENT-001")
@emits_diagnostic("APS-RULE-INTENT-001", "RULE_INTENT_DECLARED")
@emits_diagnostic("APS-RULE-INTENT-001", "RULE_INTENT_COST_MISSING")
@emits_diagnostic("APS-RULE-INTENT-001", "RULE_INTENT_EFFECT_MISSING")
@emits_diagnostic("APS-RULE-INTENT-001", "RULE_INTENT_RESTATES_TITLE")
def validate_rule_intent_contract(rules: list[dict[str, Any]]) -> list[RuleFinding]:
    """Правило объявляет свою цену и свой наблюдаемый результат.

    Требование действует вперёд, а не назад: обязательно для правил, введённых
    с `INTENT_REQUIRED_FROM`. Дозаполнить 445 прежних правил разом значило бы
    получить 445 правдоподобных строк, ни одна из которых не проверена
    практикой, — а проверка сочла бы их доказательством.

    Машинно ловится только грубая подделка — поле, дословно повторяющее
    заголовок. Убедительно звучащую пустоту здесь не отличить; это и есть
    объявленная цена самого правила.
    """
    findings: list[RuleFinding] = []
    for rule in rules:
        findings.extend(_intent_findings(rule))
    return _contract_findings(
        findings,
        contract_rule_id=INTENT_RULE_ID,
        success_code="RULE_INTENT_DECLARED",
        success_message="Rules introduced under the intent contract declare cost and observable effect.",
    )
