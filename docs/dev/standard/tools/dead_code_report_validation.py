#!/usr/bin/env python3
# ======================================================================
# dead_code_report_validation.py — версия 1.0
# Executable JSON Schema and internal-accounting validation for dead-code
# reports.
# ======================================================================
from __future__ import annotations

# ======================================================================
# 1. IMPORTS
# ======================================================================
import json
from collections import Counter
from copy import deepcopy
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from rule_traceability_types import emits_diagnostic, enforces_rule


# ======================================================================
# 2. SCHEMA LOADING
# ======================================================================
def _default_schema_path() -> Path:
    return Path(__file__).resolve().parent.parent / "schemas/dead_code_report.schema.json"


def _load_schema(schema_path: Path | None) -> dict[str, Any]:
    path = schema_path or _default_schema_path()
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError("Dead-code report schema must be a JSON object.")
    Draft202012Validator.check_schema(data)
    return data


# ======================================================================
# 3. INTERNAL ACCOUNTING RECOMPUTATION
# ======================================================================
def recompute_report_accounting(report: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    findings = report.get("findings")
    if not isinstance(findings, list):
        return "FAIL", {}
    open_findings = [item for item in findings if isinstance(item, dict) and item.get("disposition") == "OPEN"]
    high = [item for item in open_findings if item.get("severity") == "ERROR" and item.get("confidence") == "HIGH"]
    review = [item for item in open_findings if item not in high]
    allowlisted = [item for item in findings if isinstance(item, dict) and item.get("disposition") == "ALLOWLISTED"]
    invalid_allow = [item for item in open_findings if item.get("category") == "invalid_allowlist"]
    unknown_entry = [
        item
        for item in open_findings
        if item.get("category") == "unknown_dynamic_entrypoint" and item.get("severity") == "ERROR"
    ]
    expected_status = "FAIL" if high or invalid_allow or unknown_entry else ("REVIEW_REQUIRED" if review else "PASS")
    categories = Counter(str(item.get("category")) for item in findings if isinstance(item, dict))
    summary = {
        "high_confidence_findings": len(high),
        "review_required_findings": len(review),
        "allowlisted_findings": len(allowlisted),
        "invalid_allowlist_entries": len(invalid_allow),
        "unknown_entrypoints": len(unknown_entry),
        "categories": dict(sorted(categories.items())),
    }
    return expected_status, summary


# ======================================================================
# 4. EXECUTABLE REPORT VALIDATION
# ======================================================================
@enforces_rule("APS-DEAD-CODE-REPORT-SCHEMA-001")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_VALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_INVALID")
def validate_dead_code_report(
    report: Any,
    schema_path: Path | None = None,
) -> list[str]:
    """Validate Draft 2020-12 shape and recompute derived report accounting."""
    if not isinstance(report, dict):
        return ["APS_DEAD_CODE_REPORT_SCHEMA_INVALID:$:report must be an object"]
    try:
        schema = _load_schema(schema_path)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return [f"APS_DEAD_CODE_REPORT_SCHEMA_INVALID:schema:{type(exc).__name__}"]
    problems: list[str] = []
    validator = Draft202012Validator(schema)
    for error in sorted(validator.iter_errors(report), key=lambda item: list(item.absolute_path)):
        location = "/".join(str(item) for item in error.absolute_path) or "$"
        problems.append(f"APS_DEAD_CODE_REPORT_SCHEMA_INVALID:{location}:{error.message}")
    if problems:
        return problems
    expected_status, expected_summary = recompute_report_accounting(report)
    if report.get("status") != expected_status:
        problems.append(
            f"APS_DEAD_CODE_REPORT_SCHEMA_INVALID:status:expected={expected_status}:actual={report.get('status')}"
        )
    summary = report.get("summary", {})
    for key, expected in expected_summary.items():
        if summary.get(key) != expected:
            problems.append(
                f"APS_DEAD_CODE_REPORT_SCHEMA_INVALID:summary/{key}:expected={expected!r}:actual={summary.get(key)!r}"
            )
    return problems


def normalized_dead_code_report(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize environment-specific fields before independent report comparison."""
    normalized = deepcopy(report)
    normalized["root"] = "${SOURCE_ROOT}"
    diagnostics = normalized.get("diagnostics")
    if diagnostics == []:
        normalized.pop("diagnostics", None)
    return normalized
