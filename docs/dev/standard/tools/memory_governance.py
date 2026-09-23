#!/usr/bin/env python3
# ======================================================================
# memory_governance.py — версия 1.0
# Production validation for APS memory/context governance profiles.
# ======================================================================

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

PROFILE_PATHS = (
    Path("docs/registry/memory_governance_profile.json"),
    Path("reference/memory_governance_profile.json"),
)
CATALOG_PATH = Path("reference/memory_technology_catalog.json")
PROFILE_SCHEMA = Path("schemas/memory_governance_profile.schema.json")
CATALOG_SCHEMA = Path("schemas/memory_technology_catalog.schema.json")

EXPECTED_MEMORY_CLASSES = {
    "USER_PROFILE_MEMORY",
    "EPISODIC_MEMORY",
    "TEMPORAL_FACT_MEMORY",
    "WORKING_MEMORY",
    "SHARED_AGENT_MEMORY",
    "KNOWLEDGE_MEMORY",
    "CODE_GRAPH_MEMORY",
    "EXECUTION_STATE",
    "RELEASE_EVIDENCE",
}
TEMPORAL_FIELDS = {
    "source_id",
    "observed_at",
    "recorded_at",
    "valid_from",
    "valid_until",
    "confidence",
    "trust_level",
    "supersedes",
}
PINNED_STATUSES = {"APPROVED", "PILOT"}


def _finding(code: str, rule_id: str, message: str, *, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def _load_json(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def profile_path(root: Path) -> Path | None:
    for rel in PROFILE_PATHS:
        candidate = root / rel
        if candidate.is_file():
            return candidate
    return None


def load_profile(root: Path) -> dict[str, Any]:
    path = profile_path(root)
    if path is None:
        raise FileNotFoundError("memory_governance_profile.json not found")
    return _load_json(path)


def _schema_errors(instance: dict[str, Any], schema_path: Path) -> list[str]:
    schema = _load_json(schema_path)
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    return [
        f"{'/'.join(str(part) for part in error.absolute_path) or '<root>'}: {error.message}"
        for error in sorted(validator.iter_errors(instance), key=lambda item: list(item.absolute_path))
    ]


@enforces_rule("APS-CORE-MEMORYGOV-001")
@emits_diagnostic("APS-CORE-MEMORYGOV-001", "MEMORY_GOVERNANCE_PROFILE_VALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-001", "MEMORY_GOVERNANCE_PROFILE_INVALID")
def validate_profile_contract(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-MEMORYGOV-001"
    path = profile_path(root)
    if path is None:
        return [_finding("MEMORY_GOVERNANCE_PROFILE_INVALID", rule, "memory governance profile is missing")]
    try:
        profile = _load_json(path)
        errors = _schema_errors(profile, root / PROFILE_SCHEMA)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("MEMORY_GOVERNANCE_PROFILE_INVALID", rule, f"profile unavailable: {exc}")]
    findings: list[RuleFinding] = []
    if errors:
        findings.append(_finding("MEMORY_GOVERNANCE_PROFILE_INVALID", rule, "profile schema validation failed", errors=errors))
    entries = profile.get("memory_types", [])
    ids = [item.get("id") for item in entries if isinstance(item, dict)]
    classes = [item.get("class") for item in entries if isinstance(item, dict)]
    if len(ids) != len(set(ids)):
        findings.append(_finding("MEMORY_GOVERNANCE_PROFILE_INVALID", rule, "duplicate memory type id"))
    if len(classes) != len(set(classes)):
        findings.append(_finding("MEMORY_GOVERNANCE_PROFILE_INVALID", rule, "duplicate memory class"))
    missing = sorted(EXPECTED_MEMORY_CLASSES - set(classes))
    unknown = sorted(set(classes) - EXPECTED_MEMORY_CLASSES)
    if missing or unknown:
        findings.append(_finding("MEMORY_GOVERNANCE_PROFILE_INVALID", rule, "memory taxonomy is incomplete", missing=missing, unknown=unknown))
    return findings or [_finding("MEMORY_GOVERNANCE_PROFILE_VALID", rule, "memory taxonomy and profile contract are valid", severity="INFO", path=str(path.relative_to(root)))]


@enforces_rule("APS-CORE-MEMORYGOV-002")
@emits_diagnostic("APS-CORE-MEMORYGOV-002", "MEMORY_KNOWLEDGE_LAYERS_VALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-002", "MEMORY_KNOWLEDGE_LAYERS_INVALID")
def validate_knowledge_layers(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-MEMORYGOV-002"
    try:
        layers = load_profile(root).get("knowledge_layers", {})
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("MEMORY_KNOWLEDGE_LAYERS_INVALID", rule, f"profile unavailable: {exc}")]
    findings: list[RuleFinding] = []
    raw = layers.get("raw", {}) if isinstance(layers, dict) else {}
    derived = layers.get("derived_wiki", {}) if isinstance(layers, dict) else {}
    schema = layers.get("schema", {}) if isinstance(layers, dict) else {}
    log = layers.get("operation_log", {}) if isinstance(layers, dict) else {}
    if not (raw.get("immutable") is True and raw.get("source_of_truth") is True and raw.get("derived") is False):
        findings.append(_finding("MEMORY_KNOWLEDGE_LAYERS_INVALID", rule, "raw layer must be immutable, canonical and non-derived"))
    if not (derived.get("derived") is True and derived.get("source_of_truth") is False and derived.get("rebuildable") is True):
        findings.append(_finding("MEMORY_KNOWLEDGE_LAYERS_INVALID", rule, "derived wiki must be non-canonical and rebuildable"))
    if not (schema.get("source_of_truth") is True and schema.get("derived") is False):
        findings.append(_finding("MEMORY_KNOWLEDGE_LAYERS_INVALID", rule, "knowledge schema must be versioned canonical configuration"))
    if not (log.get("append_only") is True and log.get("source_of_truth") is True):
        findings.append(_finding("MEMORY_KNOWLEDGE_LAYERS_INVALID", rule, "operation log must be append-only trusted record"))
    paths = [item.get("path") for item in (raw, derived, schema, log) if isinstance(item, dict)]
    if len(paths) != len(set(paths)):
        findings.append(_finding("MEMORY_KNOWLEDGE_LAYERS_INVALID", rule, "knowledge layer paths must be distinct"))
    return findings or [_finding("MEMORY_KNOWLEDGE_LAYERS_VALID", rule, "raw, derived, schema and log layers are separated", severity="INFO")]


@enforces_rule("APS-CORE-MEMORYGOV-004")
@emits_diagnostic("APS-CORE-MEMORYGOV-004", "MEMORY_TRUST_BOUNDARY_VALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-004", "MEMORY_TRUST_BOUNDARY_INVALID")
def validate_trust_boundary(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-MEMORYGOV-004"
    try:
        profile = load_profile(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("MEMORY_TRUST_BOUNDARY_INVALID", rule, f"profile unavailable: {exc}")]
    trust = profile.get("trust_boundary", {})
    isolation = profile.get("isolation", {})
    expected = {
        "retrieved_content_authority": "DATA_ONLY",
        "instruction_execution_from_memory": False,
        "tool_invocation_from_memory": False,
        "quarantine_required": True,
        "self_promotion_allowed": False,
        "secret_scan_required": True,
        "provenance_required": True,
    }
    findings: list[RuleFinding] = []
    for key, value in expected.items():
        if not isinstance(trust, dict) or trust.get(key) != value:
            findings.append(_finding("MEMORY_TRUST_BOUNDARY_INVALID", rule, f"unsafe trust-boundary value: {key}", field=key, expected=value, actual=trust.get(key) if isinstance(trust, dict) else None))
    if not isinstance(isolation, dict) or isolation.get("default_cross_tenant") != "DENY" or isolation.get("shared_memory_requires_contract") is not True:
        findings.append(_finding("MEMORY_TRUST_BOUNDARY_INVALID", rule, "tenant isolation or shared-memory contract is not fail-closed"))
    return findings or [_finding("MEMORY_TRUST_BOUNDARY_VALID", rule, "retrieved memory is data-only and isolation is fail-closed", severity="INFO")]


@enforces_rule("APS-CORE-MEMORYGOV-007")
@enforces_rule("APS-CORE-MEMORYGOV-008")
@emits_diagnostic("APS-CORE-MEMORYGOV-007", "MEMORY_IDENTITY_AND_DEGRADED_VALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-007", "MEMORY_IDENTITY_OR_DEGRADED_INVALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-008", "MEMORY_IDENTITY_AND_DEGRADED_VALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-008", "MEMORY_IDENTITY_OR_DEGRADED_INVALID")
def validate_identity_and_degraded(root: Path) -> list[RuleFinding]:
    identity_rule = "APS-CORE-MEMORYGOV-007"
    degraded_rule = "APS-CORE-MEMORYGOV-008"
    try:
        profile = load_profile(root)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("MEMORY_IDENTITY_OR_DEGRADED_INVALID", identity_rule, f"profile unavailable: {exc}")]
    graph = profile.get("code_graph", {})
    degraded = profile.get("degraded_mode", {})
    findings: list[RuleFinding] = []
    graph_expected = {
        "exact_commit_required": True,
        "exact_tree_required": True,
        "source_manifest_sha256_required": True,
        "stale_graph_policy": "REJECT",
    }
    for key, value in graph_expected.items():
        if not isinstance(graph, dict) or graph.get(key) != value:
            findings.append(_finding("MEMORY_IDENTITY_OR_DEGRADED_INVALID", identity_rule, f"code graph identity is not exact: {key}", field=key))
    provenance = set(graph.get("edge_provenance", [])) if isinstance(graph, dict) else set()
    if "EXTRACTED" not in provenance or not provenance <= {"EXTRACTED", "INFERRED"}:
        findings.append(_finding("MEMORY_IDENTITY_OR_DEGRADED_INVALID", identity_rule, "edge provenance must distinguish extracted and inferred data"))
    degraded_expected = {
        "must_be_visible": True,
        "persistent_to_volatile_status": "DEGRADED",
        "capability_report_required": True,
        "restart_persistence_must_be_declared": True,
    }
    for key, value in degraded_expected.items():
        if not isinstance(degraded, dict) or degraded.get(key) != value:
            findings.append(_finding("MEMORY_IDENTITY_OR_DEGRADED_INVALID", degraded_rule, f"degraded-mode reporting is incomplete: {key}", field=key))
    if findings:
        return findings
    return [
        _finding("MEMORY_IDENTITY_AND_DEGRADED_VALID", identity_rule, "code graph exact identity contract is valid", severity="INFO"),
        _finding("MEMORY_IDENTITY_AND_DEGRADED_VALID", degraded_rule, "degraded capability reporting contract is valid", severity="INFO"),
    ]


@enforces_rule("APS-CORE-MEMORYGOV-009")
@emits_diagnostic("APS-CORE-MEMORYGOV-009", "MEMORY_TECHNOLOGY_SELECTION_VALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-009", "MEMORY_TECHNOLOGY_SELECTION_INVALID")
@emits_diagnostic("APS-CORE-MEMORYGOV-009", "MEMORY_OBSIDIAN_CANONICAL_FORBIDDEN")
def validate_technology_selection(root: Path) -> list[RuleFinding]:
    rule = "APS-CORE-MEMORYGOV-009"
    try:
        profile = load_profile(root)
        catalog = _load_json(root / CATALOG_PATH)
        catalog_errors = _schema_errors(catalog, root / CATALOG_SCHEMA)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return [_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, f"technology profile/catalog unavailable: {exc}")]
    findings: list[RuleFinding] = []
    if catalog_errors:
        findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "technology catalog schema validation failed", errors=catalog_errors))
    catalog_entries = catalog.get("entries", [])
    catalog_ids = [item.get("id") for item in catalog_entries if isinstance(item, dict)]
    if len(catalog_ids) != len(set(catalog_ids)):
        findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "duplicate technology catalog id"))
    selections = profile.get("technology_selections", [])
    capability_ids = [item.get("capability_id") for item in selections if isinstance(item, dict)]
    if len(capability_ids) != len(set(capability_ids)):
        findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "duplicate technology capability selection"))
    for item in selections:
        if not isinstance(item, dict):
            findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "technology selection is not an object"))
            continue
        status = item.get("status")
        if status in PINNED_STATUSES:
            if not isinstance(item.get("exact_version"), str) or not item["exact_version"].strip():
                findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "APPROVED/PILOT selection lacks exact version", capability_id=item.get("capability_id")))
            if item.get("license_review") != "PASS" and item.get("license_review") != "NOT_APPLICABLE":
                findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "APPROVED/PILOT selection lacks completed license review", capability_id=item.get("capability_id")))
            if item.get("security_review_status") != "PASS" and item.get("security_review_status") != "NOT_APPLICABLE":
                findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "APPROVED/PILOT selection lacks completed security review", capability_id=item.get("capability_id")))
            if not isinstance(item.get("evaluation_evidence"), str) or not item["evaluation_evidence"].strip():
                findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "APPROVED/PILOT selection lacks evaluation evidence", capability_id=item.get("capability_id")))
        if str(item.get("technology", "")).casefold() == "obsidian" and item.get("canonical_store") is not False:
            findings.append(_finding("MEMORY_OBSIDIAN_CANONICAL_FORBIDDEN", rule, "Obsidian may be an operator UI but not the canonical store", capability_id=item.get("capability_id")))
        if str(item.get("technology", "")).casefold() == "obsidian" and item.get("role") != "OPTIONAL_OPERATOR_UI":
            findings.append(_finding("MEMORY_TECHNOLOGY_SELECTION_INVALID", rule, "Obsidian role must be OPTIONAL_OPERATOR_UI", capability_id=item.get("capability_id")))
    return findings or [_finding("MEMORY_TECHNOLOGY_SELECTION_VALID", rule, "technology decisions are explicit and Obsidian remains an optional UI", severity="INFO")]


def validate_package(root: Path) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    findings.extend(validate_profile_contract(root))
    findings.extend(validate_knowledge_layers(root))
    findings.extend(validate_trust_boundary(root))
    findings.extend(validate_identity_and_degraded(root))
    findings.extend(validate_technology_selection(root))
    return findings
