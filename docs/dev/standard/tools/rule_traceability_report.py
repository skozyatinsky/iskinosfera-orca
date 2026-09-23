#!/usr/bin/env python3
# ======================================================================
# rule_traceability_report.py — версия 2.0
# Точные release counts, inventory artifact и итоговый report.
# ======================================================================

from __future__ import annotations

from pathlib import Path
from typing import Any

from rule_traceability_ast import test_entries
from rule_traceability_inventory import HumanRule
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

RULE_TRACEABILITY_RULE_ID = "APS-RULE-ID-001"
LINKS_VALID = "RULE_TRACEABILITY_LINKS_VALID"


def _registry_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    rules = data.get("rules", [])
    return [item for item in rules if isinstance(item, dict)] if isinstance(rules, list) else []


def build_counts(
    registry: dict[str, Any],
    human_rules: list[HumanRule],
    findings: list[RuleFinding],
    test_results: list[dict[str, Any]],
) -> dict[str, int]:
    rules = _registry_rules(registry)
    statuses = [str(item.get("status")) for item in rules]
    passing_rule_ids = {
        item["rule_id"] for item in test_results if item.get("status") == "PASS"
    }
    polarity_ids = {
        polarity: {
            item["rule_id"]
            for item in test_results
            if item.get("status") == "PASS" and item.get("polarity") == polarity
        }
        for polarity in ("positive", "negative", "bypass")
    }
    codes = [item.code for item in findings if item.severity == "ERROR"]
    implemented = sum(status == "IMPLEMENTED" for status in statuses)
    rules_with_test_flags = {
        str(rule.get("rule_id") or rule.get("id") or ""): any(True for _ in test_entries(rule))
        for rule in rules
    }
    rules_with_any_tests = sum(rules_with_test_flags.values())
    complete_triads = polarity_ids["positive"] & polarity_ids["negative"] & polarity_ids["bypass"]
    implemented_ids = {
        str(rule.get("rule_id") or rule.get("id") or "")
        for rule in rules if rule.get("status") == "IMPLEMENTED"
    }
    nonimplemented_ids = set(rules_with_test_flags) - implemented_ids
    return {
        "total_human_rule_blocks": len(human_rules),
        "total_registry_rules": len(rules),
        "implemented_rules": implemented,
        "partially_implemented_rules": sum(status == "PARTIALLY_IMPLEMENTED" for status in statuses),
        "documented_rules": sum(status == "DOCUMENTED" for status in statuses),
        "deprecated_rules": sum(status == "DEPRECATED" for status in statuses),
        "superseded_rules": sum(status == "SUPERSEDED" for status in statuses),
        "external_control_required_rules": sum(status == "EXTERNAL_CONTROL_REQUIRED" for status in statuses),
        "rules_with_passing_tests": len(passing_rule_ids),
        "rules_with_positive_tests": len(polarity_ids["positive"]),
        "rules_with_negative_tests": len(polarity_ids["negative"]),
        "rules_with_bypass_tests": len(polarity_ids["bypass"]),
        "rules_without_tests": len(rules) - rules_with_any_tests,
        "behavioral_tests_required_rules": implemented,
        "implemented_rules_with_complete_test_triad": len(implemented_ids & complete_triads),
        "untested_implemented_rules": len(implemented_ids - complete_triads),
        "rules_without_tests_by_design": sum(not rules_with_test_flags[rule_id] for rule_id in nonimplemented_ids),
        "nonimplemented_rules_with_tests": sum(rules_with_test_flags[rule_id] for rule_id in nonimplemented_ids),
        "unregistered_human_rules": codes.count("HUMAN_RULE_NOT_REGISTERED"),
        "orphan_registry_rules": codes.count("ORPHAN_RULE_REGISTRY_ENTRY"),
        "duplicate_rule_ids": codes.count("RULE_ID_DUPLICATE_GLOBAL"),
        "unknown_implementation_symbols": codes.count("UNKNOWN_IMPLEMENTATION_SYMBOL"),
        "missing_structured_diagnostics": codes.count("MISSING_STRUCTURED_DIAGNOSTIC"),
        "semantic_drift_findings": codes.count("RULE_SEMANTIC_DIGEST_CHANGED"),
        "removed_published_rules": codes.count("PUBLISHED_RULE_REMOVED"),
        "reused_rule_ids": codes.count("DEPRECATED_RULE_ID_REUSED") + codes.count("RULE_ID_REUSE_FORBIDDEN"),
    }


@enforces_rule("APS-RULE-TEST-CLASSIFICATION-001")
@emits_diagnostic("APS-RULE-TEST-CLASSIFICATION-001", "RULE_TEST_CLASSIFICATION_VALID")
@emits_diagnostic("APS-RULE-TEST-CLASSIFICATION-001", "UNTESTED_IMPLEMENTED_RULE")
@emits_diagnostic("APS-RULE-TEST-CLASSIFICATION-001", "RULE_TEST_CLASSIFICATION_COUNT_MISMATCH")
def behavioral_test_policy_valid(counts: dict[str, int]) -> bool:
    """Only IMPLEMENTED rules require a complete positive/negative/bypass triad."""
    required = (
        "implemented_rules",
        "behavioral_tests_required_rules",
        "implemented_rules_with_complete_test_triad",
        "untested_implemented_rules",
        "rules_without_tests",
        "rules_without_tests_by_design",
    )
    if any(not isinstance(counts.get(key), int) or isinstance(counts.get(key), bool) for key in required):
        return False
    return (
        counts["implemented_rules"] == counts["behavioral_tests_required_rules"]
        and counts["implemented_rules"] == counts["implemented_rules_with_complete_test_triad"]
        and counts["untested_implemented_rules"] == 0
        and counts["rules_without_tests"] == counts["rules_without_tests_by_design"]
    )


@enforces_rule("APS-RULE-RECEIPT-001")
@emits_diagnostic("APS-RULE-RECEIPT-001", "RULE_TRACEABILITY_RECEIPT_COUNTS_EXACT")
@emits_diagnostic("APS-RULE-RECEIPT-001", "RULE_TRACEABILITY_RECEIPT_COUNT_MISMATCH")
@emits_diagnostic("APS-RULE-RECEIPT-001", "SECURITY_RULE_TEST_POLARITY_INCOMPLETE")
def receipt_counts_valid(counts: dict[str, int]) -> bool:
    required = (
        "total_human_rule_blocks",
        "total_registry_rules",
        "unregistered_human_rules",
        "orphan_registry_rules",
        "duplicate_rule_ids",
        "unknown_implementation_symbols",
        "semantic_drift_findings",
        "removed_published_rules",
        "reused_rule_ids",
        "implemented_rules",
        "rules_with_passing_tests",
        "rules_with_positive_tests",
        "rules_with_negative_tests",
        "rules_with_bypass_tests",
        "behavioral_tests_required_rules",
        "implemented_rules_with_complete_test_triad",
        "untested_implemented_rules",
        "rules_without_tests_by_design",
    )
    if not isinstance(counts, dict) or any(
        not isinstance(counts.get(key), int) or isinstance(counts.get(key), bool)
        for key in required
    ):
        return False
    implemented = counts["implemented_rules"]
    return (
        counts["total_human_rule_blocks"] == counts["total_registry_rules"]
        and counts["unregistered_human_rules"] == 0
        and counts["orphan_registry_rules"] == 0
        and counts["duplicate_rule_ids"] == 0
        and counts["unknown_implementation_symbols"] == 0
        and counts["semantic_drift_findings"] == 0
        and counts["removed_published_rules"] == 0
        and counts["reused_rule_ids"] == 0
        and implemented == counts["rules_with_passing_tests"]
        and implemented == counts["rules_with_positive_tests"]
        and implemented == counts["rules_with_negative_tests"]
        and implemented == counts["rules_with_bypass_tests"]
        and implemented == counts["behavioral_tests_required_rules"]
        and implemented == counts["implemented_rules_with_complete_test_triad"]
        and counts["untested_implemented_rules"] == 0
        and behavioral_test_policy_valid(counts)
    )


def build_report(
    root: Path,
    registry: dict[str, Any],
    findings: list[RuleFinding],
    human_rules: list[HumanRule],
    inventory_summary: dict[str, Any],
    test_results: list[dict[str, Any]],
    *,
    previous_registry_sha256: str | None,
) -> dict[str, Any]:
    counts = build_counts(registry, human_rules, findings, test_results)
    errors = [item for item in findings if item.severity == "ERROR"]
    status = "PASS" if not errors and receipt_counts_valid(counts) else "FAIL"
    return {
        "schema_version": "2.0.0",
        "standard_version": registry.get("standard_version"),
        "rule_id": RULE_TRACEABILITY_RULE_ID,
        "status": status,
        "capability_status": "FULLY_ENFORCED" if status == "PASS" else "PARTIALLY_ENFORCED",
        "previous_registry_sha256": previous_registry_sha256,
        "counts": counts,
        "inventory_summary": inventory_summary,
        "behavioral_test_policy": {
            "required_statuses": ["IMPLEMENTED"],
            "not_required_statuses": [
                "DOCUMENTED", "PARTIALLY_IMPLEMENTED", "EXTERNAL_CONTROL_REQUIRED",
                "DEPRECATED", "SUPERSEDED"
            ],
            "claim": "Only IMPLEMENTED rules require positive, negative and bypass behavioral evidence.",
            "implemented_rules": counts["implemented_rules"],
            "implemented_rules_with_complete_test_triad": counts["implemented_rules_with_complete_test_triad"],
            "untested_implemented_rules": counts["untested_implemented_rules"],
            "rules_without_tests_by_design": counts["rules_without_tests_by_design"],
        },
        "findings": [item.as_dict() for item in findings],
        "runtime_test_evidence": test_results,
        "pass_diagnostic": RuleFinding(
            LINKS_VALID,
            RULE_TRACEABILITY_RULE_ID,
            "All declared rule-traceability invariants are satisfied.",
            "INFO",
            {"counts": counts},
        ).as_dict() if status == "PASS" else None,
    }


def build_inventory_document(human_rules: list[HumanRule]) -> dict[str, Any]:
    return {
        "schema_version": "1.0.0",
        "rules": [
            {
                "rule_id": item.rule_id,
                "title": item.title,
                "status": item.status,
                "semantic_contract_version": item.semantic_contract_version,
                "human_source": {
                    "kind": item.kind,
                    "path": item.path,
                    "anchor": item.anchor,
                    "json_pointer": item.json_pointer,
                    "rule_text_sha256": item.digest,
                    "line": item.line,
                },
            }
            for item in human_rules
        ],
    }
