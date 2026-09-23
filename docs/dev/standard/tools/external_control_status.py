#!/usr/bin/env python3
# ======================================================================
# external_control_status.py — версия 1.0
# Точный machine-readable статус внешних trust controls.
# ======================================================================

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule, print_diagnostic  # noqa: E402

RULE_ID = "APS-TRUST-ROOT-CLAIM-PRECISION-001"
LEGACY_OVERSTATED_FIELD = "self_signed_builder_root_rejected"
REQUIRED_BOOLEAN_FIELDS = (
    "deployment_supplied_external_trust_root_required",
    "builder_controlled_default_trust_root_rejected",
    "cryptographic_builder_key_separation",
    "builder_key_denylist_enforced",
    "independent_key_provenance_verified",
)


def _finding(code: str, message: str, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, RULE_ID, message, severity, evidence)


def default_external_control_status(version: str) -> dict[str, Any]:
    """Return the honest default status when no external enrollment evidence exists."""
    return {
        "schema_version": "1.0.0",
        "standard_version": version,
        "formal_release_status": "NOT_READY",
        "trust_root_claims": {
            "deployment_supplied_external_trust_root_required": True,
            "builder_controlled_default_trust_root_rejected": True,
            "cryptographic_builder_key_separation": False,
            "builder_key_denylist_enforced": False,
            "independent_key_provenance_verified": False,
            "claim_basis": "deployment_configuration_boundary",
            "evidence_refs": [],
        },
        "certified_linux_suite": "EVIDENCE_NOT_PROVIDED",
        "external_project_adoption": "NOT_VERIFIED",
        "controlled_automatic_merge": "NOT_READY",
        "autonomous_ai": "DISABLED",
    }


@enforces_rule("APS-TRUST-ROOT-CLAIM-PRECISION-001")
@emits_diagnostic("APS-TRUST-ROOT-CLAIM-PRECISION-001", "TRUST_ROOT_CLAIMS_VALID")
@emits_diagnostic("APS-TRUST-ROOT-CLAIM-PRECISION-001", "TRUST_ROOT_CLAIM_REQUIRED")
@emits_diagnostic("APS-TRUST-ROOT-CLAIM-PRECISION-001", "TRUST_ROOT_CLAIM_OVERSTATED")
@emits_diagnostic("APS-TRUST-ROOT-CLAIM-PRECISION-001", "TRUST_ROOT_CLAIM_EVIDENCE_MISSING")
def validate_external_control_status(data: dict[str, Any]) -> list[RuleFinding]:
    """Validate that trust-root claims do not exceed the evidence actually declared."""
    findings: list[RuleFinding] = []
    claims = data.get("trust_root_claims")
    if not isinstance(claims, dict):
        return [_finding("TRUST_ROOT_CLAIM_REQUIRED", "trust_root_claims must be an object.")]

    if LEGACY_OVERSTATED_FIELD in claims or LEGACY_OVERSTATED_FIELD in data:
        findings.append(_finding(
            "TRUST_ROOT_CLAIM_OVERSTATED",
            "Legacy self_signed_builder_root_rejected claim is forbidden because it implies a cryptographic builder-key denylist.",
            field=LEGACY_OVERSTATED_FIELD,
        ))

    for field in REQUIRED_BOOLEAN_FIELDS:
        if not isinstance(claims.get(field), bool):
            findings.append(_finding(
                "TRUST_ROOT_CLAIM_REQUIRED",
                f"Trust-root claim {field} must be an explicit boolean.",
                field=field,
            ))

    if claims.get("deployment_supplied_external_trust_root_required") is not True:
        findings.append(_finding(
            "TRUST_ROOT_CLAIM_REQUIRED",
            "Formal trust root must be supplied by the deploying environment.",
            field="deployment_supplied_external_trust_root_required",
        ))
    if claims.get("builder_controlled_default_trust_root_rejected") is not True:
        findings.append(_finding(
            "TRUST_ROOT_CLAIM_REQUIRED",
            "Builder-controlled default trust roots must remain rejected.",
            field="builder_controlled_default_trust_root_rejected",
        ))

    cryptographic_separation = claims.get("cryptographic_builder_key_separation") is True
    denylist = claims.get("builder_key_denylist_enforced") is True
    provenance = claims.get("independent_key_provenance_verified") is True
    evidence_refs = claims.get("evidence_refs")
    if not isinstance(evidence_refs, list) or any(not isinstance(item, str) or not item.strip() for item in evidence_refs):
        findings.append(_finding(
            "TRUST_ROOT_CLAIM_REQUIRED",
            "trust_root_claims.evidence_refs must be a list of non-empty strings.",
            field="evidence_refs",
        ))
        evidence_refs = []

    if cryptographic_separation and not (denylist and provenance and evidence_refs):
        findings.append(_finding(
            "TRUST_ROOT_CLAIM_EVIDENCE_MISSING",
            "Cryptographic builder-key separation may be true only with denylist enforcement, independent provenance and evidence references.",
            builder_key_denylist_enforced=denylist,
            independent_key_provenance_verified=provenance,
            evidence_refs=evidence_refs,
        ))
    if (denylist or provenance) and not cryptographic_separation:
        findings.append(_finding(
            "TRUST_ROOT_CLAIM_OVERSTATED",
            "Builder-key denylist/provenance claims are inconsistent with cryptographic_builder_key_separation=false.",
            builder_key_denylist_enforced=denylist,
            independent_key_provenance_verified=provenance,
        ))

    if not findings:
        findings.append(_finding(
            "TRUST_ROOT_CLAIMS_VALID",
            "External-control trust-root claims are explicit and evidence-bounded.",
            "INFO",
            trust_root_claims=claims,
        ))
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", default="reference/external_control_status.json")
    parser.add_argument("--write-default")
    parser.add_argument("--version")
    args = parser.parse_args()

    if args.write_default:
        if not args.version:
            print("TRUST_ROOT_CLAIM_REQUIRED:--version", file=sys.stderr)
            return 2
        output = Path(args.write_default)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(
            json.dumps(default_external_control_status(args.version), ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return 0

    try:
        data = json.loads(Path(args.input).read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        print_diagnostic(_finding("TRUST_ROOT_CLAIM_REQUIRED", "External-control status is unreadable.", error=type(exc).__name__))
        return 2
    findings = validate_external_control_status(data)
    for finding in findings:
        print_diagnostic(finding)
    return 1 if any(item.severity == "ERROR" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
