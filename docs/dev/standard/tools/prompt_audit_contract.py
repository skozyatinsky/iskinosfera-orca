#!/usr/bin/env python3
# ======================================================================
# prompt_audit_contract.py — версия 1.0
# Исполняемые контракты аудиторских prompt artifacts и Prompt Catalog.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule

PROMPT_IDS = (
    "APS-PROMPT-AUDIT-STANDARD-001",
    "APS-PROMPT-AUDIT-TZ-001",
    "APS-PROMPT-AUDIT-GIT-001",
    "APS-PROMPT-AUDIT-MATCHING-001",
)
REQUIRED_AUDIT_FIELDS = {
    "prompt_id", "version", "title", "path", "mode", "scope",
    "required_inputs", "optional_inputs", "outputs", "side_effects_allowed",
    "capability_ids", "rule_ids", "content_sha256", "introduced_in",
    "last_changed_in",
}
APS_PROMPT_RE = re.compile(r"<!--\s*aps-prompt\s*\n(?P<body>.*?)\n\s*-->", re.I | re.S)
FIXED_VERSION_RE = re.compile(r"(?<![A-Z0-9_])v?\d+\.\d+\.\d+(?![A-Z0-9_])", re.I)
MATCHING_TERMS_RE = re.compile(r"\b(?:matcher|matching|fuzzy|alias(?:es)?|famil(?:y|ies)|catalog precedence)\b", re.I)


def _finding(code: str, rule_id: str, message: str, *, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _catalog_entries(root: Path) -> list[dict[str, Any]]:
    data = _load_json(root / "prompts" / "registry.json")
    entries = data.get("prompts", [])
    return [item for item in entries if isinstance(item, dict)] if isinstance(entries, list) else []


def _entry_id(entry: dict[str, Any]) -> str:
    return str(entry.get("prompt_id") or entry.get("id") or "")


def _resolve_prompt_path(root: Path, value: str) -> Path:
    rel = Path(value)
    if rel.parts and rel.parts[0] == "prompts":
        return root / rel
    return root / "prompts" / rel


def _prompt_metadata(text: str) -> dict[str, str]:
    match = APS_PROMPT_RE.search(text)
    if not match:
        return {}
    result: dict[str, str] = {}
    for raw in match.group("body").splitlines():
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        result[key.strip()] = value.strip().strip('"\'')
    return result


def _base_entry_findings(root: Path, rule_id: str) -> tuple[dict[str, Any] | None, str, list[RuleFinding]]:
    matches = [entry for entry in _catalog_entries(root) if _entry_id(entry) == rule_id]
    if len(matches) != 1:
        return None, "", [_finding(
            "PROMPT_CATALOG_ENTRY_MISSING" if not matches else "PROMPT_ID_DUPLICATE",
            rule_id,
            "Prompt Catalog must contain exactly one entry for the stable prompt ID.",
            count=len(matches),
        )]
    entry = matches[0]
    missing = sorted(REQUIRED_AUDIT_FIELDS - set(entry))
    findings: list[RuleFinding] = []
    if missing:
        findings.append(_finding(
            "PROMPT_CATALOG_ENTRY_MISSING", rule_id,
            "Audit prompt catalog entry is missing mandatory contract fields.",
            missing=missing,
        ))
    if entry.get("prompt_id") != rule_id or entry.get("id") != rule_id:
        findings.append(_finding(
            "PROMPT_ID_DUPLICATE", rule_id,
            "Catalog id and prompt_id must both equal the stable prompt ID.",
            id=entry.get("id"), prompt_id=entry.get("prompt_id"),
        ))
    path_value = entry.get("path")
    if not isinstance(path_value, str):
        findings.append(_finding("PROMPT_FILE_MISSING", rule_id, "Prompt path is missing from the catalog."))
        return entry, "", findings
    path = _resolve_prompt_path(root, path_value)
    if not path.is_file():
        findings.append(_finding("PROMPT_FILE_MISSING", rule_id, "Catalogued prompt file does not exist.", path=path_value))
        return entry, "", findings
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()
    if entry.get("content_sha256") != digest or entry.get("sha256") != digest:
        findings.append(_finding(
            "PROMPT_CONTENT_DIGEST_MISMATCH", rule_id,
            "Prompt content digest differs from the catalog.",
            expected=entry.get("content_sha256"), actual=digest,
        ))
    metadata = _prompt_metadata(text)
    if metadata.get("prompt_id") != rule_id or metadata.get("version") != entry.get("version"):
        findings.append(_finding(
            "PROMPT_VERSION_NOT_UPDATED", rule_id,
            "aps-prompt metadata and catalog ID/version are not synchronized.",
            metadata=metadata, catalog_version=entry.get("version"),
        ))
    if entry.get("side_effects_allowed") is not False:
        findings.append(_finding(
            "READ_ONLY_AUDIT_MUTATION_DETECTED", rule_id,
            "Audit prompt must explicitly set side_effects_allowed=false.",
        ))
    capabilities_path = root / "reference" / "standard_capabilities.json"
    if capabilities_path.is_file():
        capability_data = _load_json(capabilities_path)
        known = {
            str(item.get("id")) for item in capability_data.get("capabilities", [])
            if isinstance(item, dict) and item.get("id")
        }
        unknown = sorted(set(entry.get("capability_ids", [])) - known) if isinstance(entry.get("capability_ids"), list) else []
        if unknown:
            findings.append(_finding(
                "UNKNOWN_PROMPT_CAPABILITY", rule_id,
                "Prompt Catalog references unknown capability IDs.",
                capability_ids=unknown,
            ))
    if rule_id == "APS-PROMPT-AUDIT-MATCHING-001":
        expected_mode = "READ_ONLY_EXTENSION"
    else:
        expected_mode = "READ_ONLY"
    if entry.get("mode") != expected_mode or metadata.get("mode") != expected_mode:
        findings.append(_finding(
            "PROMPT_CATALOG_ENTRY_MISSING", rule_id,
            "Prompt mode does not match its read-only execution contract.",
            expected=expected_mode, observed=entry.get("mode"),
        ))
    return entry, text, findings


@enforces_rule("APS-PROMPT-AUDIT-STANDARD-001")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "PROMPT_CONTRACT_VALID")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "PROMPT_CATALOG_ENTRY_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "PROMPT_FILE_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "PROMPT_CONTENT_DIGEST_MISMATCH")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "PROMPT_VERSION_NOT_UPDATED")
@emits_diagnostic("APS-PROMPT-AUDIT-STANDARD-001", "UNKNOWN_PROMPT_CAPABILITY")
def validate_standard_audit_prompt(root: Path) -> list[RuleFinding]:
    entry, text, findings = _base_entry_findings(root, "APS-PROMPT-AUDIT-STANDARD-001")
    if text:
        body = APS_PROMPT_RE.sub("", text)
        fixed = sorted(set(FIXED_VERSION_RE.findall(body)))
        if fixed:
            findings.append(_finding(
                "PROMPT_VERSION_NOT_UPDATED", "APS-PROMPT-AUDIT-STANDARD-001",
                "Universal release audit prompt contains a fixed release version.",
                versions=fixed,
            ))
        required = ("AUDIT_VERSION", "PREVIOUS_VERSION", "RELEASE_RECEIPT", "RELEASE_EVIDENCE")
        missing = [token for token in required if token not in text]
        if missing:
            findings.append(_finding(
                "PROMPT_CATALOG_ENTRY_MISSING", "APS-PROMPT-AUDIT-STANDARD-001",
                "Universal release audit prompt lacks required parameter placeholders.",
                missing=missing,
            ))
    if not findings:
        findings.append(_finding("PROMPT_CONTRACT_VALID", "APS-PROMPT-AUDIT-STANDARD-001", "Universal release audit prompt contract is valid.", severity="INFO"))
    return findings


@enforces_rule("APS-PROMPT-AUDIT-TZ-001")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "PROMPT_CONTRACT_VALID")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "PROMPT_CATALOG_ENTRY_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "PROMPT_FILE_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "PROMPT_CONTENT_DIGEST_MISMATCH")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "PROMPT_VERSION_NOT_UPDATED")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "UNKNOWN_PROMPT_CAPABILITY")
@emits_diagnostic("APS-PROMPT-AUDIT-TZ-001", "TZ_DONE_WITHOUT_SAME_ID_EVIDENCE")
def validate_tz_audit_prompt(root: Path) -> list[RuleFinding]:
    _entry, text, findings = _base_entry_findings(root, "APS-PROMPT-AUDIT-TZ-001")
    required = (
        "AUDIT-LOCAL-", "AUDIT_LOCAL_ID_NOT_PRODUCT_TRACEABILITY",
        "stable", "DONE", "behavioral", "тем же", "ID",
    )
    if text and any(token not in text for token in required):
        findings.append(_finding(
            "TZ_DONE_WITHOUT_SAME_ID_EVIDENCE", "APS-PROMPT-AUDIT-TZ-001",
            "TZ audit prompt does not enforce stable-ID and same-ID behavioral DONE evidence.",
        ))
    if text and re.search(r"(?:назнач|присво).{0,40}\bREQ-[A-Z0-9]", text, re.I | re.S):
        findings.append(_finding(
            "TZ_DONE_WITHOUT_SAME_ID_EVIDENCE", "APS-PROMPT-AUDIT-TZ-001",
            "TZ audit prompt allows temporary REQ-* IDs to replace published product IDs.",
        ))
    if not findings:
        findings.append(_finding("PROMPT_CONTRACT_VALID", "APS-PROMPT-AUDIT-TZ-001", "TZ implementation audit prompt contract is valid.", severity="INFO"))
    return findings


@enforces_rule("APS-PROMPT-AUDIT-GIT-001")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "PROMPT_CONTRACT_VALID")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "PROMPT_CATALOG_ENTRY_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "PROMPT_FILE_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "PROMPT_CONTENT_DIGEST_MISMATCH")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "PROMPT_VERSION_NOT_UPDATED")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "UNKNOWN_PROMPT_CAPABILITY")
@emits_diagnostic("APS-PROMPT-AUDIT-GIT-001", "GIT_AUDIT_PROJECT_SPECIFIC_CONTENT_LEAK")
def validate_git_audit_prompt(root: Path) -> list[RuleFinding]:
    _entry, text, findings = _base_entry_findings(root, "APS-PROMPT-AUDIT-GIT-001")
    if text and MATCHING_TERMS_RE.search(text):
        findings.append(_finding(
            "GIT_AUDIT_PROJECT_SPECIFIC_CONTENT_LEAK", "APS-PROMPT-AUDIT-GIT-001",
            "Base Git audit prompt contains matching/catalog-specific requirements.",
        ))
    required = ("worktree", "ahead/behind", "reflog", "unreachable", "Ничего не изменяй")
    if text and any(token not in text for token in required):
        findings.append(_finding(
            "PROMPT_CATALOG_ENTRY_MISSING", "APS-PROMPT-AUDIT-GIT-001",
            "Universal Git audit prompt lacks required read-only Git coverage.",
        ))
    if not findings:
        findings.append(_finding("PROMPT_CONTRACT_VALID", "APS-PROMPT-AUDIT-GIT-001", "Universal Git audit prompt contract is valid.", severity="INFO"))
    return findings


@enforces_rule("APS-PROMPT-AUDIT-MATCHING-001")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "PROMPT_CONTRACT_VALID")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "PROMPT_CATALOG_ENTRY_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "PROMPT_FILE_MISSING")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "PROMPT_CONTENT_DIGEST_MISMATCH")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "PROMPT_VERSION_NOT_UPDATED")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "UNKNOWN_PROMPT_CAPABILITY")
@emits_diagnostic("APS-PROMPT-AUDIT-MATCHING-001", "MATCHING_EXTENSION_BASE_PROMPT_REQUIRED")
def validate_matching_audit_extension(root: Path) -> list[RuleFinding]:
    entry, text, findings = _base_entry_findings(root, "APS-PROMPT-AUDIT-MATCHING-001")
    if entry is not None and entry.get("requires_prompt_id") != "APS-PROMPT-AUDIT-GIT-001":
        findings.append(_finding(
            "MATCHING_EXTENSION_BASE_PROMPT_REQUIRED", "APS-PROMPT-AUDIT-MATCHING-001",
            "Matching extension must require the base Git audit prompt.",
        ))
    metadata = _prompt_metadata(text) if text else {}
    if text and metadata.get("requires_prompt_id") != "APS-PROMPT-AUDIT-GIT-001":
        findings.append(_finding(
            "MATCHING_EXTENSION_BASE_PROMPT_REQUIRED", "APS-PROMPT-AUDIT-MATCHING-001",
            "Matching prompt metadata is not linked to the base Git audit prompt.",
        ))
    if text and "MATCHING_PRECEDENCE_NOT_DEFINED" not in text:
        findings.append(_finding(
            "PROMPT_CATALOG_ENTRY_MISSING", "APS-PROMPT-AUDIT-MATCHING-001",
            "Matching extension lacks the missing-policy diagnostic.",
        ))
    if not findings:
        findings.append(_finding("PROMPT_CONTRACT_VALID", "APS-PROMPT-AUDIT-MATCHING-001", "Matching audit extension contract is valid.", severity="INFO"))
    return findings


def validate_audit_prompt_catalog(root: Path) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    findings.extend(validate_standard_audit_prompt(root))
    findings.extend(validate_tz_audit_prompt(root))
    findings.extend(validate_git_audit_prompt(root))
    findings.extend(validate_matching_audit_extension(root))
    return findings


def prompt_catalog_metrics(root: Path) -> dict[str, int]:
    entries = _catalog_entries(root)
    prompts_root = root / "prompts"
    excluded = {"README.md", "PROMPT_CHANGELOG.md"}
    files = [
        path for path in prompts_root.rglob("*.md")
        if path.name not in excluded and "templates" not in path.relative_to(prompts_root).parts
    ]
    ids = [_entry_id(entry) for entry in entries]
    registered_paths: set[str] = set()
    valid_digest = 0
    with_tests = 0
    read_only = 0
    for entry in entries:
        value = entry.get("path")
        if isinstance(value, str):
            path = _resolve_prompt_path(root, value)
            if path.is_file():
                registered_paths.add(path.relative_to(prompts_root).as_posix())
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                if entry.get("sha256") == digest and (entry.get("content_sha256", digest) == digest):
                    valid_digest += 1
        if entry.get("mode") in {"READ_ONLY", "READ_ONLY_EXTENSION", "AUDIT_ONLY", "VERIFICATION"} and entry.get("side_effects_allowed", False) is False:
            read_only += 1
        if entry.get("test_ids"):
            with_tests += 1
    actual_paths = {path.relative_to(prompts_root).as_posix() for path in files}
    return {
        "total_prompts": len(files),
        "catalogued_prompts": len(entries),
        "read_only_prompts": read_only,
        "prompts_with_valid_digest": valid_digest,
        "prompts_with_tests": with_tests,
        "prompt_id_duplicates": len(ids) - len(set(ids)),
        "prompt_catalog_orphans": len(registered_paths - actual_paths),
        "prompt_file_orphans": len(actual_paths - registered_paths),
    }


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Validate catalogued audit prompt contracts.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--output")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    findings = validate_audit_prompt_catalog(root)
    metrics = prompt_catalog_metrics(root)
    errors = [item for item in findings if item.severity == "ERROR"]
    report = {
        "schema_version": "1.0.0",
        "status": "PASS" if not errors else "FAIL",
        "metrics": metrics,
        "findings": [item.as_dict() for item in findings],
    }
    if args.output:
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
