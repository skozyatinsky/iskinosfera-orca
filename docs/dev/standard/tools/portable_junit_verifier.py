#!/usr/bin/env python3
# ======================================================================
# portable_junit_verifier.py — версия 1.0
# Structured JUnit parsing boundary for the portable release verifier.
# ======================================================================

from __future__ import annotations

import zipfile
from typing import Any

from junit_evidence import JUnitAnalysis, JUnitEvidenceError, parse_junit_bytes
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

RULE_ID = "APS-PORTABLE-VERIFIER-JUNIT-ERROR-001"


def _finding(code: str, message: str, **evidence: Any) -> RuleFinding:
    return RuleFinding(code, RULE_ID, message, "ERROR", evidence)


@enforces_rule("APS-PORTABLE-VERIFIER-JUNIT-ERROR-001")
@emits_diagnostic("APS-PORTABLE-VERIFIER-JUNIT-ERROR-001", "PORTABLE_VERIFIER_JUNIT_EVIDENCE_VALID")
@emits_diagnostic("APS-PORTABLE-VERIFIER-JUNIT-ERROR-001", "PORTABLE_VERIFIER_JUNIT_FILE_MISSING")
@emits_diagnostic("APS-PORTABLE-VERIFIER-JUNIT-ERROR-001", "PORTABLE_VERIFIER_JUNIT_XML_MALFORMED")
@emits_diagnostic("APS-PORTABLE-VERIFIER-JUNIT-ERROR-001", "PORTABLE_VERIFIER_JUNIT_ACCOUNTING_INVALID")
def portable_junit_analysis(
    archive: zipfile.ZipFile,
    rel: str,
    *,
    step_id: str,
) -> tuple[JUnitAnalysis | None, list[RuleFinding]]:
    """Parse one exported JUnit file without allowing XML errors to escape."""
    try:
        payload = archive.read(rel)
    except KeyError:
        return None, [_finding(
            "PORTABLE_VERIFIER_JUNIT_FILE_MISSING",
            f"Portable verifier JUnit file is missing for {step_id}.",
            step_id=step_id,
            junit_xml=rel,
        )]
    try:
        analysis = parse_junit_bytes(payload, require_node_ids=True)
    except JUnitEvidenceError as exc:
        return None, [_finding(
            "PORTABLE_VERIFIER_JUNIT_XML_MALFORMED",
            f"Portable verifier rejected malformed JUnit for {step_id}.",
            step_id=step_id,
            junit_xml=rel,
            parser_diagnostic=str(exc).split(":", 1)[0],
        )]
    if analysis.summary.get("status") != "PASS":
        return analysis, [_finding(
            "PORTABLE_VERIFIER_JUNIT_ACCOUNTING_INVALID",
            f"Portable verifier rejected non-PASS JUnit accounting for {step_id}.",
            step_id=step_id,
            junit_xml=rel,
            summary=analysis.summary,
        )]
    return analysis, [RuleFinding(
        "PORTABLE_VERIFIER_JUNIT_EVIDENCE_VALID",
        RULE_ID,
        f"Portable verifier parsed JUnit for {step_id} without traceback.",
        "INFO",
        {"step_id": step_id, "junit_xml": rel},
    )]
