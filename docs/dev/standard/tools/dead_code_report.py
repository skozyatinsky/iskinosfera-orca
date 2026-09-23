#!/usr/bin/env python3
# ======================================================================
# dead_code_report.py — версия 1.0
# Формирование machine-readable отчёта dead-code audit.
# ======================================================================
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from dead_code_types import Finding


def build_report(*, root: Path, profile: str, production_entrypoints: list[dict[str, Any]], public_api_contracts: list[dict[str, Any]], files_scanned: int, symbols_scanned: int, findings: list[Finding], scan_exclusions: list[dict[str, Any]] | None = None, files_excluded: int = 0) -> dict[str, Any]:
    open_findings = [f for f in findings if f.disposition == "OPEN"]
    high = [f for f in open_findings if f.severity == "ERROR" and f.confidence == "HIGH"]
    review = [f for f in open_findings if f.severity != "ERROR" or f.confidence != "HIGH"]
    allowlisted = [f for f in findings if f.disposition == "ALLOWLISTED"]
    invalid_allow = [f for f in open_findings if f.category == "invalid_allowlist"]
    unknown_entry = [f for f in open_findings if f.category == "unknown_dynamic_entrypoint" and f.severity == "ERROR"]
    status = "FAIL" if high or invalid_allow or unknown_entry else ("REVIEW_REQUIRED" if review else "PASS")
    categories = Counter(f.category for f in findings)
    return {
        "schema_version": "1.0.0",
        "status": status,
        "root": str(root),
        "profile": profile,
        "production_entrypoints": production_entrypoints,
        "scan_scope": {
            "exclusions": list(scan_exclusions or []),
            "files_excluded": files_excluded,
        },
        "public_api_contracts": public_api_contracts,
        "summary": {
            "files_scanned": files_scanned,
            "symbols_scanned": symbols_scanned,
            "high_confidence_findings": len(high),
            "review_required_findings": len(review),
            "allowlisted_findings": len(allowlisted),
            "invalid_allowlist_entries": len(invalid_allow),
            "unknown_entrypoints": len(unknown_entry),
            "categories": dict(sorted(categories.items())),
        },
        "findings": [f.to_dict() for f in findings],
        "limitations": [
            "Static analysis cannot prove every dynamic Python entrypoint.",
            "Coverage is supporting evidence and is not treated as production reachability proof.",
            "Automatic deletion is disabled; findings require review and regression evidence.",
        ],
    }
