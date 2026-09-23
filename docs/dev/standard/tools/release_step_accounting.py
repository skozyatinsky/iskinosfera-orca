#!/usr/bin/env python3
# ======================================================================
# release_step_accounting.py — версия 1.0
# Exact allowlist and mandatory/optional/unknown release-step accounting.
# ======================================================================

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

STEP_GRAPH_RULE_ID = "APS-RELEASE-STEP-GRAPH-001"
STEP_ACCOUNTING_RULE_ID = "APS-RELEASE-STEP-ACCOUNTING-001"


def _ordered_unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def profile_step_sets(profile: dict[str, Any]) -> tuple[list[str], list[str], list[str]]:
    """Return ordered mandatory, optional and exact allowed step IDs.

    `allowed_skips` is the existing profile contract for steps that may be
    omitted. Such steps remain valid when observed, therefore the exact
    allowlist is mandatory_steps ∪ allowed_skips.
    """
    mandatory = _ordered_unique([item for item in profile.get("mandatory_steps", []) if isinstance(item, str)])
    optional = _ordered_unique([
        item for item in profile.get("allowed_skips", [])
        if isinstance(item, str) and item not in mandatory
    ])
    return mandatory, optional, [*mandatory, *optional]


@enforces_rule("APS-RELEASE-STEP-ACCOUNTING-001")
@emits_diagnostic("APS-RELEASE-STEP-ACCOUNTING-001", "RELEASE_STEP_ACCOUNTING_EXACT")
@emits_diagnostic("APS-RELEASE-STEP-ACCOUNTING-001", "RELEASE_STEP_ACCOUNTING_SEPARATED")
@emits_diagnostic("APS-RELEASE-STEP-ACCOUNTING-001", "RELEASE_STEP_ACCOUNTING_UNKNOWN_STEPS")
def build_step_accounting(data: dict[str, Any], profile: dict[str, Any]) -> tuple[dict[str, Any], list[RuleFinding]]:
    mandatory, optional, allowed = profile_step_sets(profile)
    steps = [item for item in data.get("steps", []) if isinstance(item, dict)]
    observed = [item.get("id") for item in steps if isinstance(item.get("id"), str)]
    observed_set = set(observed)
    optional_set = set(optional)
    allowed_set = set(allowed)
    by_id = {item.get("id"): item for item in steps if isinstance(item.get("id"), str)}

    missing = [item for item in mandatory if item not in observed_set]
    unknown = [item for item in observed if item not in allowed_set]
    optional_observed = [item for item in observed if item in optional_set]
    mandatory_observed = [item for item in mandatory if item in observed_set]
    mandatory_passed = [
        item for item in mandatory
        if item in by_id and by_id[item].get("status") == "PASS" and by_id[item].get("exit_code") == 0
    ]

    report = {
        "profile_id": profile.get("profile_id"),
        "mandatory_total": len(mandatory),
        "mandatory_observed": len(mandatory_observed),
        "mandatory_passed": len(mandatory_passed),
        "optional_total": len(optional),
        "optional_observed": len(optional_observed),
        "allowed_total": len(allowed),
        "observed_total": len(observed),
        "unknown_total": len(unknown),
        "missing_total": len(missing),
        "mandatory_steps": mandatory,
        "optional_steps": optional,
        "allowed_steps": allowed,
        "observed_steps": observed,
        "optional_observed_steps": optional_observed,
        "unknown_steps": unknown,
        "missing_steps": missing,
    }

    diagnostics: list[RuleFinding] = []
    if unknown:
        diagnostics.append(RuleFinding(
            "RELEASE_STEP_ACCOUNTING_UNKNOWN_STEPS",
            STEP_ACCOUNTING_RULE_ID,
            "Release step accounting contains step IDs outside the exact profile allowlist.",
            "ERROR",
            {"unknown_steps": unknown, "allowed_steps": allowed},
        ))
    elif optional_observed:
        diagnostics.append(RuleFinding(
            "RELEASE_STEP_ACCOUNTING_SEPARATED",
            STEP_ACCOUNTING_RULE_ID,
            "Mandatory, optional and observed step counts are reported separately.",
            "INFO",
            {"mandatory_total": len(mandatory), "optional_observed": len(optional_observed), "observed_total": len(observed)},
        ))
    else:
        diagnostics.append(RuleFinding(
            "RELEASE_STEP_ACCOUNTING_EXACT",
            STEP_ACCOUNTING_RULE_ID,
            "Release step accounting exactly matches the profile graph.",
            "INFO",
            {"mandatory_total": len(mandatory), "observed_total": len(observed), "unknown_total": 0},
        ))
    return report, diagnostics


@enforces_rule("APS-RELEASE-STEP-GRAPH-001")
@emits_diagnostic("APS-RELEASE-STEP-GRAPH-001", "RELEASE_STEP_GRAPH_EXACT")
@emits_diagnostic("APS-RELEASE-STEP-GRAPH-001", "RECEIPT_UNKNOWN_STEP_ID")
def validate_step_graph(data: dict[str, Any], profile: dict[str, Any]) -> tuple[dict[str, Any], list[RuleFinding]]:
    report, _ = build_step_accounting(data, profile)
    diagnostics: list[RuleFinding] = []
    for step_id in report["unknown_steps"]:
        diagnostics.append(RuleFinding(
            "RECEIPT_UNKNOWN_STEP_ID",
            STEP_GRAPH_RULE_ID,
            "Receipt contains a step ID outside the exact profile allowlist.",
            "ERROR",
            {"detail": step_id, "step_id": step_id},
        ))
    if not diagnostics:
        diagnostics.append(RuleFinding(
            "RELEASE_STEP_GRAPH_EXACT",
            STEP_GRAPH_RULE_ID,
            "Observed receipt step IDs are contained in the exact profile allowlist.",
            "INFO",
            {"observed_total": report["observed_total"], "allowed_total": report["allowed_total"]},
        ))
    return report, diagnostics


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--profiles", default="reference/release_profiles.json")
    parser.add_argument("--output")
    args = parser.parse_args()

    receipt = json.loads(Path(args.receipt).read_text(encoding="utf-8-sig"))
    profiles = json.loads(Path(args.profiles).read_text(encoding="utf-8-sig"))
    profile = profiles.get("profiles", {}).get(receipt.get("profile"))
    if not isinstance(profile, dict):
        print(f"RECEIPT_UNKNOWN_PROFILE:{receipt.get('profile')}")
        return 1
    report, diagnostics = build_step_accounting(receipt, profile)
    payload = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    for item in diagnostics:
        if item.severity == "ERROR":
            print(item.legacy())
    return 1 if report["unknown_total"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
