#!/usr/bin/env python3
# ======================================================================
# rule_traceability.py — версия 2.0
# Сквозная ID-трассируемость human rule → registry → code → test → evidence.
# ======================================================================

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from rule_traceability_intent import validate_rule_intent_contract
from rule_traceability_ast import (
    test_entries,
    validate_implementation_links,
    validate_test_links,
)
from rule_traceability_inventory import HumanRule, build_inventory
from rule_traceability_types import (
    MissingCheckInput,
    _contract_findings,
    load_json_or_fail,
    RuleFinding,
    emits_diagnostic,
    enforces_rule,
    print_diagnostic,
    rule_test,
    unique_findings,
)

__all__ = ("rule_test",)

RULE_TRACEABILITY_RULE_ID = "APS-RULE-ID-001"
INVENTORY_RULE_ID = "APS-RULE-INVENTORY-001"
STRUCTURAL_RULE_ID = "APS-RULE-STRUCTURAL-001"
SEMANTIC_RULE_ID = "APS-RULE-SEMANTIC-001"
CAPABILITY_RULE_ID = "APS-RULE-CAPABILITY-001"
LINKS_VALID = "RULE_TRACEABILITY_LINKS_VALID"
DUPLICATE = "RULE_ID_DUPLICATE_GLOBAL"
TEST_NOT_PASSING = "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE"
REGISTRY_PATH = Path("reference/rule_traceability_registry.json")
SCHEMA_PATH = Path("schemas/rule_traceability_registry.schema.json")

TRACEABILITY_DIAGNOSTICS = (
    "HUMAN_RULE_ID_MISSING",
    "HUMAN_RULE_NOT_REGISTERED",
    "ORPHAN_RULE_REGISTRY_ENTRY",
    "RULE_ID_DUPLICATE_GLOBAL",
    "RULE_ID_REUSE_FORBIDDEN",
    "RULE_SEMANTIC_DIGEST_CHANGED",
    "RULE_MEANING_CHANGED_WITHOUT_NEW_ID",
    "PUBLISHED_RULE_REMOVED",
    "DEPRECATED_RULE_ID_REUSED",
    "RULE_INVENTORY_DECREASED_WITHOUT_MIGRATION",
    "UNKNOWN_IMPLEMENTATION_SYMBOL",
    "RULE_IMPLEMENTATION_ANNOTATION_MISSING",
    "RULE_IMPLEMENTATION_NOT_REACHED_BY_GATE",
    "RULE_DIAGNOSTIC_NOT_EMITTED_BY_IMPLEMENTATION",
    "RULE_TEST_DOES_NOT_EXERCISE_IMPLEMENTATION",
    "RULE_TEST_ONLY_PRINTS_DIAGNOSTIC",
    "RULE_TEST_TRIVIAL_ASSERTION",
    "RULE_DIAGNOSTIC_RULE_ID_MISMATCH",
    "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE",
    "PREVIOUS_RULE_REGISTRY_REQUIRED",
    "PREVIOUS_RULE_REGISTRY_DIGEST_MISMATCH",
    "UNKNOWN_CAPABILITY_ID",
    "CAPABILITY_RULE_LINK_NOT_BIDIRECTIONAL",
    "SECURITY_RULE_TEST_POLARITY_INCOMPLETE",
    "RULE_TRACEABILITY_RECEIPT_COUNT_MISMATCH",
    "UNMARKED_NORMATIVE_STATEMENT",
)


# ======================================================================
# 1. БАЗОВЫЕ ОПЕРАЦИИ
# ======================================================================

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()



def load_registry(root: Path) -> dict[str, Any]:
    return load_json_or_fail(root / REGISTRY_PATH)


def load_previous_registry(path: Path | None) -> dict[str, Any] | None:
    return load_json_or_fail(path) if path is not None and path.is_file() else None


def _finding(
    code: str,
    rule_id: str,
    message: str,
    *,
    severity: str = "ERROR",
    **evidence: Any,
) -> RuleFinding:
    return RuleFinding(code, rule_id or RULE_TRACEABILITY_RULE_ID, message, severity, evidence)


def _registry_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    rules = data.get("rules", [])
    return [item for item in rules if isinstance(item, dict)] if isinstance(rules, list) else []


def _rule_id(rule: dict[str, Any]) -> str:
    return str(rule.get("rule_id") or rule.get("id") or "")


# ======================================================================
# 2. SCHEMA, HUMAN INVENTORY И EXACT SOURCE LINKAGE
# ======================================================================

def _validate_schema(root: Path, data: dict[str, Any]) -> list[RuleFinding]:
    schema = load_json_or_fail(root / SCHEMA_PATH)
    findings: list[RuleFinding] = []
    for error in Draft202012Validator(schema).iter_errors(data):
        findings.append(_finding(
            "RULE_TRACEABILITY_SCHEMA_INVALID",
            RULE_TRACEABILITY_RULE_ID,
            error.message,
            json_path=error.json_path,
            detail=f"{error.json_path}:{error.message}",
        ))
    return findings


def _validate_human_registry_links(
    human_rules: list[HumanRule],
    registry_rules: list[dict[str, Any]],
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    by_human: dict[str, list[HumanRule]] = {}
    by_registry: dict[str, list[dict[str, Any]]] = {}
    for item in human_rules:
        by_human.setdefault(item.rule_id, []).append(item)
    for item in registry_rules:
        by_registry.setdefault(_rule_id(item), []).append(item)

    for rule_id, entries in by_registry.items():
        if not rule_id:
            findings.append(_finding(
                "RULE_REGISTRY_ID_MISSING",
                RULE_TRACEABILITY_RULE_ID,
                "Registry rule is missing rule_id",
                detail="missing-rule-id",
            ))
        elif len(entries) > 1:
            findings.append(_finding(
                "RULE_ID_DUPLICATE_GLOBAL",
                rule_id,
                "Rule ID is duplicated in machine registry",
                count=len(entries),
                detail=rule_id,
            ))

    for rule_id, blocks in by_human.items():
        if rule_id not in by_registry:
            findings.append(_finding(
                "HUMAN_RULE_NOT_REGISTERED",
                rule_id,
                "Canonical human rule has no registry entry",
                sources=[item.source_key() for item in blocks],
                detail=blocks[0].path,
            ))
    for rule_id, entries in by_registry.items():
        if rule_id and rule_id not in by_human:
            findings.append(_finding(
                "ORPHAN_RULE_REGISTRY_ENTRY",
                rule_id,
                "Registry entry has no canonical human rule block",
                detail=rule_id,
            ))

    for rule_id in sorted(set(by_human) & set(by_registry)):
        if len(by_human[rule_id]) != 1 or len(by_registry[rule_id]) != 1:
            continue
        human = by_human[rule_id][0]
        entry = by_registry[rule_id][0]
        source = entry.get("human_source", {})
        if not isinstance(source, dict):
            findings.append(_finding(
                "RULE_HUMAN_SOURCE_INVALID",
                rule_id,
                "human_source must be an object",
                detail=rule_id,
            ))
            continue
        expected = {
            "kind": human.kind,
            "path": human.path,
            "anchor": human.anchor,
            "json_pointer": human.json_pointer,
            "rule_text_sha256": human.digest,
        }
        observed = {
            "kind": source.get("kind"),
            "path": source.get("path"),
            "anchor": source.get("anchor"),
            "json_pointer": source.get("json_pointer"),
            "rule_text_sha256": source.get("rule_text_sha256"),
        }
        for key, expected_value in expected.items():
            observed_value = observed[key]
            if expected_value is None and observed_value in {None, ""}:
                continue
            if observed_value != expected_value:
                code = "RULE_SEMANTIC_DIGEST_CHANGED" if key == "rule_text_sha256" else "RULE_HUMAN_SOURCE_MISMATCH"
                findings.append(_finding(
                    code,
                    rule_id,
                    f"human_source.{key} does not match canonical inventory",
                    expected=expected_value,
                    observed=observed_value,
                    detail=key,
                ))
        if entry.get("status") != human.status:
            findings.append(_finding(
                "RULE_HUMAN_STATUS_MISMATCH",
                rule_id,
                "Human block status differs from registry status",
                expected=human.status,
                observed=entry.get("status"),
                detail=human.path,
            ))
        if entry.get("semantic_contract_version") != human.semantic_contract_version:
            findings.append(_finding(
                "RULE_SEMANTIC_VERSION_MISMATCH",
                rule_id,
                "Human block semantic version differs from registry",
                expected=human.semantic_contract_version,
                observed=entry.get("semantic_contract_version"),
                detail=human.path,
            ))
    return findings


# ======================================================================
# 3. PREVIOUS-RELEASE CONTINUITY
# ======================================================================

def _previous_rule_map(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {_rule_id(item): item for item in _registry_rules(data) if _rule_id(item)}


def _semantic_digest(rule: dict[str, Any]) -> str | None:
    source = rule.get("human_source", {})
    if isinstance(source, dict):
        value = source.get("rule_text_sha256")
        return str(value) if value else None
    return None


def _validate_previous_continuity(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    release_mode: bool,
    previous_path: Path | None,
    expected_sha256: str | None,
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    if previous is None:
        if release_mode:
            findings.append(_finding(
                "PREVIOUS_RULE_REGISTRY_REQUIRED",
                RULE_TRACEABILITY_RULE_ID,
                "Release-grade validation requires a trusted previous registry",
                detail=str(previous_path) if previous_path else "missing",
            ))
        return findings
    if previous_path is not None and expected_sha256:
        actual = _sha256_bytes(previous_path.read_bytes())
        if actual != expected_sha256:
            findings.append(_finding(
                "PREVIOUS_RULE_REGISTRY_DIGEST_MISMATCH",
                RULE_TRACEABILITY_RULE_ID,
                "Previous registry does not match the trusted digest",
                expected=expected_sha256,
                observed=actual,
                detail=actual,
            ))
            return findings

    current_map = _previous_rule_map(current)
    previous_map = _previous_rule_map(previous)
    for rule_id, old in previous_map.items():
        new = current_map.get(rule_id)
        if new is None:
            findings.append(_finding(
                "PUBLISHED_RULE_REMOVED",
                rule_id,
                "Published rule disappeared without retained deprecation record",
                detail=rule_id,
            ))
            continue
        old_digest = _semantic_digest(old)
        new_digest = _semantic_digest(new)
        if old_digest and new_digest and old_digest != new_digest:
            findings.extend([
                _finding(
                    "RULE_SEMANTIC_DIGEST_CHANGED",
                    rule_id,
                    "Published rule semantic digest changed under the same ID",
                    previous=old_digest,
                    current=new_digest,
                    detail=rule_id,
                ),
                _finding(
                    "RULE_MEANING_CHANGED_WITHOUT_NEW_ID",
                    rule_id,
                    "A semantic change requires a new rule ID",
                    previous=old_digest,
                    current=new_digest,
                    detail=rule_id,
                ),
            ])
        old_status = old.get("status")
        new_status = new.get("status")
        if old_status in {"DEPRECATED", "SUPERSEDED"} and new_status not in {"DEPRECATED", "SUPERSEDED"}:
            findings.extend([
                _finding(
                    "DEPRECATED_RULE_ID_REUSED",
                    rule_id,
                    "Deprecated/superseded ID was reactivated",
                    detail=rule_id,
                ),
                _finding(
                    "RULE_ID_REUSE_FORBIDDEN",
                    rule_id,
                    "Published rule IDs remain permanently reserved",
                    detail=rule_id,
                ),
            ])

    previous_size = int(previous.get("published_inventory_size", len(previous_map)))
    current_size = len(current_map)
    migration = current.get("migration", {})
    decrease_approved = isinstance(migration, dict) and bool(migration.get("inventory_decrease_approved"))
    if current_size < previous_size and not decrease_approved:
        findings.append(_finding(
            "RULE_INVENTORY_DECREASED_WITHOUT_MIGRATION",
            RULE_TRACEABILITY_RULE_ID,
            "Rule inventory decreased without an approved migration record",
            previous=previous_size,
            current=current_size,
            detail=f"{previous_size}->{current_size}",
        ))
    return findings


# ======================================================================
# 4. STATUS, IMPLEMENTATION, TEST И CAPABILITY CONTRACTS
# ======================================================================

def _validate_status_contracts(root: Path, rules: list[dict[str, Any]]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for rule in rules:
        rule_id = _rule_id(rule)
        status = rule.get("status")
        implementation = rule.get("implementation", [])
        diagnostics = rule.get("diagnostics", [])
        tests = rule.get("tests", {})
        if status == "IMPLEMENTED":
            if not implementation:
                findings.append(_finding(
                    "IMPLEMENTED_RULE_WITHOUT_IMPLEMENTATION",
                    rule_id,
                    "IMPLEMENTED requires at least one production symbol",
                    detail=rule_id,
                ))
            if not diagnostics:
                findings.append(_finding(
                    "MISSING_STRUCTURED_DIAGNOSTIC",
                    rule_id,
                    "IMPLEMENTED requires structured diagnostics",
                    detail=rule_id,
                ))
            test_count = sum(
                len(tests.get(name, [])) if isinstance(tests, dict) and isinstance(tests.get(name, []), list) else 0
                for name in ("positive", "negative", "bypass")
            )
            if test_count == 0:
                findings.append(_finding(
                    "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE",
                    rule_id,
                    "IMPLEMENTED requires linked behavioral tests",
                    detail=rule_id,
                ))
        if status == "IMPLEMENTED":
            if rule.get("security_relevant") or rule.get("fail_closed"):
                missing = [
                    polarity
                    for polarity in ("positive", "negative", "bypass")
                    if not isinstance(tests, dict) or not tests.get(polarity)
                ]
                if missing:
                    findings.append(_finding(
                        "SECURITY_RULE_TEST_POLARITY_INCOMPLETE",
                        rule_id,
                        "Security/fail-closed rule requires positive, negative and bypass tests",
                        missing=missing,
                        detail=",".join(missing),
                    ))
    return findings


def _capability_map(root: Path) -> dict[str, dict[str, Any]]:
    data = load_json_or_fail(root / "reference/standard_capabilities.json")
    capabilities = data.get("capabilities", [])
    return {
        str(item.get("id")): item
        for item in capabilities
        if isinstance(item, dict) and item.get("id")
    }


def _validate_capability_links(root: Path, rules: list[dict[str, Any]]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    capabilities = _capability_map(root)
    for rule in rules:
        rule_id = _rule_id(rule)
        capability_ids = rule.get("capability_ids", [])
        if not isinstance(capability_ids, list):
            continue
        for capability_id in capability_ids:
            capability = capabilities.get(str(capability_id))
            if capability is None:
                findings.append(_finding(
                    "UNKNOWN_CAPABILITY_ID",
                    rule_id,
                    f"Unknown capability ID: {capability_id}",
                    capability_id=capability_id,
                    detail=str(capability_id),
                ))
                continue
            linked = capability.get("rule_ids", [])
            if rule_id not in linked:
                findings.append(_finding(
                    "CAPABILITY_RULE_LINK_NOT_BIDIRECTIONAL",
                    rule_id,
                    f"Capability {capability_id} does not link back to the rule",
                    capability_id=capability_id,
                    detail=str(capability_id),
                ))
    for capability_id, capability in capabilities.items():
        for rule_id in capability.get("rule_ids", []) or []:
            target = next((item for item in rules if _rule_id(item) == rule_id), None)
            if target is None or capability_id not in (target.get("capability_ids", []) or []):
                findings.append(_finding(
                    "CAPABILITY_RULE_LINK_NOT_BIDIRECTIONAL",
                    str(rule_id),
                    f"Rule does not link back to capability {capability_id}",
                    capability_id=capability_id,
                    detail=capability_id,
                ))
    return findings


# ======================================================================
# 5. RULE-SPECIFIC PRODUCTION CONTRACTS
# Каждый валидатор имеет собственный rule ID, exact diagnostics и прямой
# call path из release-grade aggregate gate.
# ======================================================================




@enforces_rule("APS-RULE-INVENTORY-001")
@emits_diagnostic("APS-RULE-INVENTORY-001", "RULE_INVENTORY_COMPLETE")
@emits_diagnostic("APS-RULE-INVENTORY-001", "HUMAN_RULE_ID_MISSING")
@emits_diagnostic("APS-RULE-INVENTORY-001", "HUMAN_RULE_NOT_REGISTERED")
@emits_diagnostic("APS-RULE-INVENTORY-001", "ORPHAN_RULE_REGISTRY_ENTRY")
@emits_diagnostic("APS-RULE-INVENTORY-001", "UNMARKED_NORMATIVE_STATEMENT")
@emits_diagnostic("APS-RULE-INVENTORY-001", "RULE_ID_DUPLICATE_GLOBAL")
def validate_human_inventory_contract(
    root: Path,
    data: dict[str, Any],
) -> tuple[list[RuleFinding], list[HumanRule], dict[str, Any]]:
    human_rules, inventory_findings, inventory_summary = build_inventory(
        root, data.get("normative_roots", [])
    )
    findings = [*inventory_findings, *_validate_human_registry_links(human_rules, _registry_rules(data))]
    allowed = {
        "HUMAN_RULE_ID_MISSING",
        "HUMAN_RULE_NOT_REGISTERED",
        "ORPHAN_RULE_REGISTRY_ENTRY",
        "UNMARKED_NORMATIVE_STATEMENT",
        "RULE_ID_DUPLICATE_GLOBAL",
    }
    contract = _contract_findings(
        [item for item in findings if item.code in allowed],
        contract_rule_id=INVENTORY_RULE_ID,
        success_code="RULE_INVENTORY_COMPLETE",
        success_message="Declared normative roots have a complete, unique rule inventory.",
    )
    # Non-contract parser/schema findings remain available to the aggregate gate.
    contract.extend(item for item in findings if item.code not in allowed)
    return contract, human_rules, inventory_summary


@enforces_rule("APS-RULE-STRUCTURAL-001")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_STRUCTURAL_LINKS_VALID")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "UNKNOWN_IMPLEMENTATION_SYMBOL")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_IMPLEMENTATION_ANNOTATION_MISSING")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_IMPLEMENTATION_NOT_REACHED_BY_GATE")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_DIAGNOSTIC_NOT_EMITTED_BY_IMPLEMENTATION")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_DOES_NOT_EXERCISE_IMPLEMENTATION")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_ONLY_PRINTS_DIAGNOSTIC")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_TRIVIAL_ASSERTION")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_DIAGNOSTIC_RULE_ID_MISMATCH")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "IMPLEMENTED_RULE_WITHOUT_IMPLEMENTATION")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "MISSING_STRUCTURED_DIAGNOSTIC")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "SECURITY_RULE_TEST_POLARITY_INCOMPLETE")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_IMPLEMENTATION_TRIVIAL")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_IMPLEMENTATION_GATE_MISSING")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "UNKNOWN_IMPLEMENTATION_GATE_SYMBOL")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_IMPLEMENTATION_DIAGNOSTIC_UNREGISTERED")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TESTS_INVALID")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_NODE_MISSING")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_ANNOTATION_MISSING")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_RULE_ID_MISMATCH")
@emits_diagnostic("APS-RULE-STRUCTURAL-001", "RULE_TEST_POLARITY_MISMATCH")
def validate_structural_evidence_contract(
    root: Path,
    rules: list[dict[str, Any]],
) -> list[RuleFinding]:
    findings: list[RuleFinding] = _validate_status_contracts(root, rules)
    for rule in rules:
        if rule.get("status") in {"IMPLEMENTED", "PARTIALLY_IMPLEMENTED"} and rule.get("implementation"):
            findings.extend(validate_implementation_links(root, rule))
        if rule.get("status") == "IMPLEMENTED":
            findings.extend(validate_test_links(root, rule))
    return _contract_findings(
        findings,
        contract_rule_id=STRUCTURAL_RULE_ID,
        success_code="RULE_STRUCTURAL_LINKS_VALID",
        success_message="Implementation, diagnostic and test links are structurally valid.",
    )


@enforces_rule("APS-RULE-SEMANTIC-001")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "RULE_SEMANTIC_CONTINUITY_VALID")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "PREVIOUS_RULE_REGISTRY_REQUIRED")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "PREVIOUS_RULE_REGISTRY_DIGEST_MISMATCH")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "RULE_SEMANTIC_DIGEST_CHANGED")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "RULE_MEANING_CHANGED_WITHOUT_NEW_ID")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "PUBLISHED_RULE_REMOVED")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "DEPRECATED_RULE_ID_REUSED")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "RULE_ID_REUSE_FORBIDDEN")
@emits_diagnostic("APS-RULE-SEMANTIC-001", "RULE_INVENTORY_DECREASED_WITHOUT_MIGRATION")
def validate_semantic_continuity_contract(
    current: dict[str, Any],
    previous: dict[str, Any] | None,
    *,
    release_mode: bool,
    previous_path: Path | None,
    expected_sha256: str | None,
) -> list[RuleFinding]:
    findings = _validate_previous_continuity(
        current,
        previous,
        release_mode=release_mode,
        previous_path=previous_path,
        expected_sha256=expected_sha256,
    )
    return _contract_findings(
        findings,
        contract_rule_id=SEMANTIC_RULE_ID,
        success_code="RULE_SEMANTIC_CONTINUITY_VALID",
        success_message="Published rule IDs and semantic digests are continuous.",
    )


@enforces_rule("APS-RULE-CAPABILITY-001")
@emits_diagnostic("APS-RULE-CAPABILITY-001", "RULE_CAPABILITY_LINKS_VALID")
@emits_diagnostic("APS-RULE-CAPABILITY-001", "UNKNOWN_CAPABILITY_ID")
@emits_diagnostic("APS-RULE-CAPABILITY-001", "CAPABILITY_RULE_LINK_NOT_BIDIRECTIONAL")
def validate_capability_contract(
    root: Path,
    rules: list[dict[str, Any]],
) -> list[RuleFinding]:
    return _contract_findings(
        _validate_capability_links(root, rules),
        contract_rule_id=CAPABILITY_RULE_ID,
        success_code="RULE_CAPABILITY_LINKS_VALID",
        success_message="Rule and capability links are exact and bidirectional.",
    )


# ======================================================================
# 6. AGGREGATE GATE — APS-RULE-ID-001
# ======================================================================

@enforces_rule("APS-RULE-ID-001")
@emits_diagnostic("APS-RULE-ID-001", "RULE_TRACEABILITY_LINKS_VALID")
@emits_diagnostic("APS-RULE-ID-001", "RULE_TEST_RULE_ID_MISMATCH")
@emits_diagnostic("APS-RULE-ID-001", "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE")
def validate_registry_detailed(
    root: Path,
    data: dict[str, Any] | None = None,
    *,
    previous_registry: dict[str, Any] | None = None,
    previous_registry_path: Path | None = None,
    previous_registry_sha256: str | None = None,
    release_mode: bool = False,
) -> tuple[list[RuleFinding], list[HumanRule], dict[str, Any]]:
    root = root.resolve()
    data = copy.deepcopy(data) if data is not None else load_registry(root)
    findings = _validate_schema(root, data)
    inventory_findings, human_rules, inventory_summary = validate_human_inventory_contract(root, data)
    findings.extend(inventory_findings)
    registry_rules = _registry_rules(data)
    findings.extend(validate_semantic_continuity_contract(
        data,
        previous_registry,
        release_mode=release_mode,
        previous_path=previous_registry_path,
        expected_sha256=previous_registry_sha256,
    ))
    structural_findings = validate_structural_evidence_contract(root, registry_rules)
    findings.extend(structural_findings)
    for item in structural_findings:
        if (
            item.code in {"RULE_TEST_RULE_ID_MISMATCH", "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE"}
            and item.evidence.get("affected_rule_id") == RULE_TRACEABILITY_RULE_ID
        ):
            findings.append(RuleFinding(
                item.code,
                RULE_TRACEABILITY_RULE_ID,
                item.message,
                item.severity,
                item.evidence,
            ))
    findings.extend(validate_capability_contract(root, registry_rules))
    findings.extend(validate_rule_intent_contract(registry_rules))
    errors = [item for item in findings if item.severity == "ERROR"]
    if not errors:
        findings.append(RuleFinding(
            LINKS_VALID,
            RULE_TRACEABILITY_RULE_ID,
            "All exact rule-ID traceability links are valid.",
            "INFO",
            {},
        ))
    return unique_findings(findings), human_rules, inventory_summary


def validate_registry(root: Path, data: dict[str, Any] | None = None) -> list[str]:
    """Backward-compatible API used by validate_structure and older tests.

    Отсутствие реестра — объявленный отказ с кодом, а не трассировка:
    проект-потребитель законно не имеет файлов самого пакета стандарта, и
    проверка обязана сказать это словами (`APS-CHECK-MISSING-INPUT-001`).
    """
    try:
        findings, _, _ = validate_registry_detailed(root, data)
    except MissingCheckInput as exc:
        return [f"CHECK_INPUT_UNREADABLE:{RULE_TRACEABILITY_RULE_ID}:{exc}"]
    return [item.legacy() for item in findings if item.severity == "ERROR"]


# ======================================================================
# 7. BEHAVIORAL TEST EXECUTION И RUNTIME EVIDENCE
# Реализация вынесена в отдельный модуль для соблюдения source-size contract.
# ======================================================================

from rule_traceability_runtime import execute_linked_tests


def evaluate_implemented(rule: dict[str, Any], outcomes: dict[str, bool]) -> list[str]:
    """Compatibility helper retained for v2.9.134 callers."""
    if rule.get("status") != "IMPLEMENTED":
        return []
    raw_tests = rule.get("tests", [])
    nodes: list[str] = []
    if isinstance(raw_tests, list):
        nodes = [str(item.get("node_id", "")) for item in raw_tests if isinstance(item, dict)]
    elif isinstance(raw_tests, dict):
        nodes = [str(item.get("node_id", "")) for _, item in test_entries(rule)]
    return [f"{TEST_NOT_PASSING}:{_rule_id(rule)}:{node}" for node in nodes if outcomes.get(node) is not True]


# ======================================================================
# 8. COUNTS И REPORTS
# Реализация вынесена в отдельный модуль, чтобы production validator оставался
# меньше установленного лимита размера исходного файла.
# ======================================================================

from rule_traceability_report import (
    build_inventory_document,
    build_report,
)


# ======================================================================
# 9. CLI
# ======================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--execute-tests", action="store_true")
    parser.add_argument("--previous-registry")
    parser.add_argument("--previous-registry-sha256")
    parser.add_argument("--release-mode", action="store_true")
    parser.add_argument("--output")
    parser.add_argument("--inventory-output")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(args.root).resolve()
    registry = load_registry(root)
    previous_path = Path(args.previous_registry).resolve() if args.previous_registry else None
    previous = load_previous_registry(previous_path)
    expected_sha = args.previous_registry_sha256
    if expected_sha is None and previous_path is not None:
        expected_sha = registry.get("previous_release", {}).get("registry_sha256")
    findings, human_rules, inventory_summary = validate_registry_detailed(
        root,
        registry,
        previous_registry=previous,
        previous_registry_path=previous_path,
        previous_registry_sha256=expected_sha,
        release_mode=args.release_mode or previous_path is not None,
    )
    test_results: list[dict[str, Any]] = []
    if args.execute_tests and not [item for item in findings if item.severity == "ERROR"]:
        test_results, dynamic = execute_linked_tests(root, registry)
        findings.extend(dynamic)
    report = build_report(
        root,
        registry,
        unique_findings(findings),
        human_rules,
        inventory_summary,
        test_results,
        previous_registry_sha256=expected_sha,
    )
    if not args.execute_tests and not [item for item in findings if item.severity == "ERROR"]:
        report["status"] = "PASS"
        report["capability_status"] = "STATICALLY_ENFORCED"
    if report["status"] == "PASS":
        print_diagnostic(RuleFinding(
            LINKS_VALID,
            RULE_TRACEABILITY_RULE_ID,
            "Rule traceability validation passed.",
            "INFO",
            {"counts": report["counts"]},
        ))
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.inventory_output:
        output = Path(args.inventory_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(build_inventory_document(human_rules), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
