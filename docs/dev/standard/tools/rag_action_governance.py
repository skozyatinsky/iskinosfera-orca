#!/usr/bin/env python3
# ======================================================================
# rag_action_governance.py — версия 1.0
# Release-enforced validation for RAG-to-action profiles and catalogs.
# ======================================================================

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

PROFILE_PATHS = (
    Path("docs/registry/rag_action_governance_profile.json"),
    Path("reference/rag_action_governance_profile.json"),
)
CATALOG_PATHS = (
    Path("docs/registry/trusted_action_catalog.json"),
    Path("reference/trusted_action_catalog.json"),
)
PROFILE_SCHEMA = Path("schemas/rag_action_governance_profile.schema.json")
CATALOG_SCHEMA = Path("schemas/trusted_action_catalog.schema.json")

EXPECTED_MODES = {"ANSWER", "PROPOSE", "EXECUTE", "VERIFY"}
EXPECTED_RISK_CLASSES = {"READ_ONLY", "LOW", "MEDIUM", "HIGH", "PROHIBITED"}
TRACE_FIELDS = {
    "request_id", "user_id", "tenant_id", "project_id", "mode", "source_ids",
    "source_versions", "applicable_rule_ids", "live_state_snapshot_sha256",
    "action_id", "action_schema_version", "policy_decision_id", "confirmation_id",
    "command_sha256", "execution_receipt_id", "verification_receipt_id", "final_status",
}


def _finding(code: str, rule_id: str, message: str, *, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def _first(root: Path, candidates: tuple[Path, ...]) -> Path | None:
    for rel in candidates:
        path = root / rel
        if path.is_file():
            return path
    return None


def _schema_errors(instance: dict[str, Any], schema_path: Path) -> list[str]:
    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    ]


def load_profile(root: Path) -> dict[str, Any]:
    path = _first(root, PROFILE_PATHS)
    if path is None:
        raise FileNotFoundError("rag_action_governance_profile.json not found")
    return _load_json(path)


def load_catalog(root: Path, profile: dict[str, Any] | None = None) -> dict[str, Any]:
    profile = profile or load_profile(root)
    declared = profile.get("action_catalog", {}).get("path")
    if isinstance(declared, str) and declared:
        path = root / declared
        if path.is_file():
            return _load_json(path)
    path = _first(root, CATALOG_PATHS)
    if path is None:
        raise FileNotFoundError("trusted_action_catalog.json not found")
    return _load_json(path)


@enforces_rule("APS-CORE-RAGACTION-001")
@enforces_rule("APS-CORE-RAGACTION-002")
@emits_diagnostic("APS-CORE-RAGACTION-001", "RAG_ACTION_MODES_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-001", "RAG_ACTION_MODES_INVALID")
@emits_diagnostic("APS-CORE-RAGACTION-002", "RAG_ACTION_BOUNDARY_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-002", "RAG_ACTION_BOUNDARY_INVALID")
def validate_modes_and_boundary(root: Path) -> list[RuleFinding]:
    try:
        profile = load_profile(root)
        errors = _schema_errors(profile, root / PROFILE_SCHEMA)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("RAG_ACTION_MODES_INVALID", "APS-CORE-RAGACTION-001", f"profile unavailable: {exc}")]
    findings: list[RuleFinding] = []
    if errors:
        findings.append(_finding("RAG_ACTION_MODES_INVALID", "APS-CORE-RAGACTION-001", "profile schema validation failed", errors=errors))
    modes = set(profile.get("allowed_modes", []))
    mode_policy = profile.get("mode_policy", {})
    if modes != EXPECTED_MODES or profile.get("default_mode") != "ANSWER":
        findings.append(_finding("RAG_ACTION_MODES_INVALID", "APS-CORE-RAGACTION-001", "ANSWER/PROPOSE/EXECUTE/VERIFY modes must be complete and ANSWER must be default"))
    if not isinstance(mode_policy, dict) or mode_policy.get("retrieved_text_may_change_mode") is not False or mode_policy.get("explicit_transition_to_execute_required") is not True:
        findings.append(_finding("RAG_ACTION_MODES_INVALID", "APS-CORE-RAGACTION-001", "retrieved text may not promote a request to EXECUTE"))
    boundary = profile.get("knowledge_state_boundary", {})
    if not isinstance(boundary, dict) or boundary.get("rag_may_prove_live_state") is not False or boundary.get("live_state_source") != "DOMAIN_SYSTEM_OR_TRUSTED_LIVE_API":
        findings.append(_finding("RAG_ACTION_BOUNDARY_INVALID", "APS-CORE-RAGACTION-002", "RAG must not be the source of live business state"))
    if findings:
        return findings
    return [
        _finding("RAG_ACTION_MODES_VALID", "APS-CORE-RAGACTION-001", "interaction modes are explicit and fail-closed", severity="INFO"),
        _finding("RAG_ACTION_BOUNDARY_VALID", "APS-CORE-RAGACTION-002", "knowledge and live-state sources are separated", severity="INFO"),
    ]


@enforces_rule("APS-CORE-RAGACTION-003")
@enforces_rule("APS-CORE-RAGACTION-004")
@emits_diagnostic("APS-CORE-RAGACTION-003", "RAG_ACTION_RETRIEVAL_TRUST_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-003", "RAG_ACTION_DIRECT_TOOL_CALL_FORBIDDEN")
@emits_diagnostic("APS-CORE-RAGACTION-004", "RAG_ACTION_CATALOG_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-004", "RAG_ACTION_CATALOG_INVALID")
def validate_retrieval_and_catalog(root: Path) -> list[RuleFinding]:
    try:
        profile = load_profile(root)
        catalog = load_catalog(root, profile)
        errors = _schema_errors(catalog, root / CATALOG_SCHEMA)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", f"catalog unavailable: {exc}")]
    findings: list[RuleFinding] = []
    trust = profile.get("retrieval_trust", {})
    if not isinstance(trust, dict) or any((
        trust.get("retrieved_content_authority") != "DATA_ONLY",
        trust.get("direct_tool_call_from_retrieval") is not False,
        trust.get("arbitrary_command_generation") is not False,
        trust.get("trusted_action_catalog_required") is not True,
        trust.get("candidate_action_ids_must_exist") is not True,
    )):
        findings.append(_finding("RAG_ACTION_DIRECT_TOOL_CALL_FORBIDDEN", "APS-CORE-RAGACTION-003", "retrieved content cannot directly invoke tools or create arbitrary commands"))
    if errors:
        findings.append(_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", "action catalog schema validation failed", errors=errors))
    actions = catalog.get("actions", [])
    ids = [item.get("action_id") for item in actions if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        findings.append(_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", "duplicate action_id"))
    for action in actions:
        if not isinstance(action, dict):
            continue
        risk = action.get("risk_class")
        mutation = action.get("mutation")
        confirmation = action.get("confirmation_policy")
        if risk not in EXPECTED_RISK_CLASSES:
            findings.append(_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", "unknown risk class", action_id=action.get("action_id")))
        if risk == "PROHIBITED" and confirmation != "FORBIDDEN":
            findings.append(_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", "PROHIBITED action must be forbidden", action_id=action.get("action_id")))
        if risk == "HIGH" and confirmation not in {"EXPLICIT_HUMAN", "EXTERNAL_TRUSTED_CONTROL"}:
            findings.append(_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", "HIGH action lacks mandatory confirmation", action_id=action.get("action_id")))
        if mutation is True and action.get("verification", {}).get("required") is not True:
            findings.append(_finding("RAG_ACTION_CATALOG_INVALID", "APS-CORE-RAGACTION-004", "mutating action lacks result verification", action_id=action.get("action_id")))
    if findings:
        return findings
    return [
        _finding("RAG_ACTION_RETRIEVAL_TRUST_VALID", "APS-CORE-RAGACTION-003", "retrieval is data-only and catalog-bound", severity="INFO"),
        _finding("RAG_ACTION_CATALOG_VALID", "APS-CORE-RAGACTION-004", "trusted action catalog is valid", severity="INFO"),
    ]


@enforces_rule("APS-CORE-RAGACTION-005")
@enforces_rule("APS-CORE-RAGACTION-006")
@enforces_rule("APS-CORE-RAGACTION-007")
@emits_diagnostic("APS-CORE-RAGACTION-005", "RAG_ACTION_TRACE_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-005", "RAG_ACTION_TRACE_INVALID")
@emits_diagnostic("APS-CORE-RAGACTION-006", "RAG_ACTION_FRESHNESS_POLICY_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-006", "RAG_ACTION_FRESHNESS_POLICY_INVALID")
@emits_diagnostic("APS-CORE-RAGACTION-007", "RAG_ACTION_RISK_POLICY_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-007", "RAG_ACTION_RISK_POLICY_INVALID")
def validate_trace_freshness_and_risk(root: Path) -> list[RuleFinding]:
    try:
        profile = load_profile(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("RAG_ACTION_TRACE_INVALID", "APS-CORE-RAGACTION-005", f"profile unavailable: {exc}")]
    findings: list[RuleFinding] = []
    fields = set(profile.get("traceability", {}).get("required_fields", []))
    if not TRACE_FIELDS <= fields:
        findings.append(_finding("RAG_ACTION_TRACE_INVALID", "APS-CORE-RAGACTION-005", "knowledge-to-action trace is incomplete", missing=sorted(TRACE_FIELDS-fields)))
    freshness = profile.get("freshness_and_conflicts", {})
    required_blocks = ["stale_source_execute_policy", "revoked_source_execute_policy", "conflicting_sources_execute_policy", "missing_citations_execute_policy"]
    if not isinstance(freshness, dict) or any(freshness.get(key) != "BLOCK" for key in required_blocks):
        findings.append(_finding("RAG_ACTION_FRESHNESS_POLICY_INVALID", "APS-CORE-RAGACTION-006", "stale/conflicting/uncited evidence must block EXECUTE"))
    risk = profile.get("risk_policy", {})
    if not isinstance(risk, dict) or set(risk.get("classes", [])) != EXPECTED_RISK_CLASSES or risk.get("agent_may_lower_risk") is not False or risk.get("high_requires_explicit_confirmation_or_external_control") is not True or risk.get("prohibited_may_execute") is not False or risk.get("gatekeeper_required") is not True:
        findings.append(_finding("RAG_ACTION_RISK_POLICY_INVALID", "APS-CORE-RAGACTION-007", "risk policy is not fail-closed"))
    if findings:
        return findings
    return [
        _finding("RAG_ACTION_TRACE_VALID", "APS-CORE-RAGACTION-005", "knowledge-to-action trace is complete", severity="INFO"),
        _finding("RAG_ACTION_FRESHNESS_POLICY_VALID", "APS-CORE-RAGACTION-006", "freshness and conflict policy is fail-closed", severity="INFO"),
        _finding("RAG_ACTION_RISK_POLICY_VALID", "APS-CORE-RAGACTION-007", "risk and confirmation policy is fail-closed", severity="INFO"),
    ]


@enforces_rule("APS-CORE-RAGACTION-008")
@enforces_rule("APS-CORE-RAGACTION-009")
@emits_diagnostic("APS-CORE-RAGACTION-008", "RAG_ACTION_EXECUTION_VERIFICATION_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-008", "RAG_ACTION_EXECUTION_VERIFICATION_INVALID")
@emits_diagnostic("APS-CORE-RAGACTION-009", "RAG_ACTION_RETRY_POLICY_VALID")
@emits_diagnostic("APS-CORE-RAGACTION-009", "RAG_ACTION_RETRY_POLICY_INVALID")
def validate_execution_and_retry(root: Path) -> list[RuleFinding]:
    try:
        profile = load_profile(root)
        catalog = load_catalog(root, profile)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("RAG_ACTION_EXECUTION_VERIFICATION_INVALID", "APS-CORE-RAGACTION-008", f"profile/catalog unavailable: {exc}")]
    findings: list[RuleFinding] = []
    policy = profile.get("execution_policy", {})
    expected_statuses = {"COMMAND_ACCEPTED", "COMMAND_EXECUTED", "BUSINESS_RESULT_VERIFIED"}
    if not isinstance(policy, dict) or set(policy.get("statuses", [])) != expected_statuses or policy.get("executor_success_is_business_verification") is not False or policy.get("unverified_final_status") != "EXECUTED_RESULT_NOT_VERIFIED":
        findings.append(_finding("RAG_ACTION_EXECUTION_VERIFICATION_INVALID", "APS-CORE-RAGACTION-008", "execution and result verification are not separated"))
    if not isinstance(policy, dict) or policy.get("retry_after_unknown_requires_live_verification") is not True or policy.get("idempotency_policy_required_for_mutation") is not True:
        findings.append(_finding("RAG_ACTION_RETRY_POLICY_INVALID", "APS-CORE-RAGACTION-009", "unknown-result retry is not fail-closed"))
    for action in catalog.get("actions", []):
        if not isinstance(action, dict) or action.get("mutation") is not True:
            continue
        idem = action.get("idempotency", {})
        if not isinstance(idem, dict) or idem.get("unknown_result_policy") != "VERIFY_BEFORE_RETRY":
            findings.append(_finding("RAG_ACTION_RETRY_POLICY_INVALID", "APS-CORE-RAGACTION-009", "mutating action may retry before verification", action_id=action.get("action_id")))
        if action.get("verification", {}).get("required") is not True:
            findings.append(_finding("RAG_ACTION_EXECUTION_VERIFICATION_INVALID", "APS-CORE-RAGACTION-008", "mutating action lacks independent verification", action_id=action.get("action_id")))
    if findings:
        return findings
    return [
        _finding("RAG_ACTION_EXECUTION_VERIFICATION_VALID", "APS-CORE-RAGACTION-008", "execution and independent verification are separated", severity="INFO"),
        _finding("RAG_ACTION_RETRY_POLICY_VALID", "APS-CORE-RAGACTION-009", "idempotency and unknown-result retry policy are fail-closed", severity="INFO"),
    ]


def validate_package(root: Path) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    findings.extend(validate_modes_and_boundary(root))
    findings.extend(validate_retrieval_and_catalog(root))
    findings.extend(validate_trace_freshness_and_risk(root))
    findings.extend(validate_execution_and_retry(root))
    return findings
