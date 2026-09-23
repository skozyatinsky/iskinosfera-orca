#!/usr/bin/env python3
# ======================================================================
# validate_release_receipt.py — версия 3.0
# Portable verifier: receipt ↔ artifact ↔ evidence ↔ Git/JUnit binding.
# ======================================================================

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from dead_code_evidence import evidence_test_nodes  # noqa: E402
from dead_code_report_validation import normalized_dead_code_report, validate_dead_code_report  # noqa: E402
from junit_evidence import JUnitEvidenceError, node_ids_sha256  # noqa: E402
from portable_junit_verifier import portable_junit_analysis  # noqa: E402
from release_integrity import (  # noqa: E402
    artifact_records,
    compare_records,
    manifest_digest,
    sha256_file,
)
from release_source_identity import (  # noqa: E402
    checkout_git_bundle_package, identify_release_source, verify_git_bundle,
)
from rule_traceability_report import receipt_counts_valid  # noqa: E402
from release_step_accounting import validate_step_graph  # noqa: E402
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule  # noqa: E402

try:
    from jsonschema import Draft7Validator
except ImportError:  # pragma: no cover
    Draft7Validator = None


TEST_STEP_IDS = ("direct_tests", "tests", "golden")
SUMMARY_KEYS = (
    "total", "completed", "accounted", "passed", "failed", "skipped",
    "xfailed", "xpassed", "errors", "unexpected_skipped", "status",
)



def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def validate_profiles_registry(profiles: dict[str, Any], schema: dict[str, Any]) -> list[str]:
    if Draft7Validator is None:
        return ["RELEASE_PROFILE_SCHEMA_VALIDATOR_UNAVAILABLE:jsonschema"]
    findings: list[str] = []
    validator = Draft7Validator(schema)
    for error in sorted(validator.iter_errors(profiles), key=lambda item: list(item.absolute_path)):
        location = "/".join(str(item) for item in error.absolute_path) or "$"
        findings.append(f"RELEASE_PROFILE_SCHEMA:{location}:{error.message}")
    return findings


@enforces_rule("APS-DEAD-CODE-RELEASE-GATE-001")
@emits_diagnostic("APS-DEAD-CODE-RELEASE-GATE-001", "APS_DEAD_CODE_RELEASE_GATE_PASS")
@emits_diagnostic("APS-DEAD-CODE-RELEASE-GATE-001", "APS_DEAD_CODE_RELEASE_BLOCKED")
def policy_findings(data: dict[str, Any], profiles: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    profile_name = data.get("profile")
    profile = profiles.get("profiles", {}).get(profile_name)
    if not isinstance(profile, dict):
        return [f"RECEIPT_UNKNOWN_PROFILE:{profile_name}"]
    if data.get("status") not in profile.get("allowed_receipt_statuses", []):
        findings.append(f"RECEIPT_STATUS_NOT_ALLOWED:{data.get('status')}")

    source = data.get("source", {})
    if profile.get("requires_git_repository") and source.get("git_repository") is not True:
        findings.append("RECEIPT_PROFILE_GIT_REPOSITORY_REQUIRED")
    clean_policy = profile.get("requires_clean_working_tree")
    if clean_policy == "always" and source.get("git_clean") is not True:
        findings.append("RECEIPT_PROFILE_CLEAN_SOURCE_REQUIRED")
    if clean_policy == "if_git" and source.get("git_repository") is True and source.get("git_clean") is not True:
        findings.append("RECEIPT_PROFILE_CLEAN_SOURCE_REQUIRED")
    if data.get("artifact", {}).get("published") and not profile.get("artifact_allowed"):
        findings.append("RECEIPT_PROFILE_ARTIFACT_NOT_ALLOWED")

    steps = data.get("steps", [])
    ids = [step.get("id") for step in steps if isinstance(step, dict)]
    if len(ids) != len(set(ids)):
        findings.append("RECEIPT_DUPLICATE_STEP_ID")
    mandatory = list(profile.get("mandatory_steps", []))
    missing = sorted(set(mandatory) - set(ids))
    _, step_graph_diagnostics = validate_step_graph(data, profile)
    for diagnostic in step_graph_diagnostics:
        if diagnostic.severity == "ERROR":
            findings.append(diagnostic.legacy())
    policy = data.get("policy", {})
    if policy.get("mandatory_steps") != mandatory:
        findings.append("RECEIPT_POLICY_MANDATORY_STEPS_MISMATCH")
    if policy.get("observed_steps") != ids:
        findings.append("RECEIPT_POLICY_OBSERVED_STEPS_MISMATCH")
    if policy.get("missing_steps") != missing:
        findings.append("RECEIPT_POLICY_MISSING_STEPS_MISMATCH")
    if policy.get("allowed_skips") != list(profile.get("allowed_skips", [])):
        findings.append("RECEIPT_POLICY_ALLOWED_SKIPS_MISMATCH")
    if policy.get("external_controls") != list(profile.get("external_controls", [])):
        findings.append("RECEIPT_POLICY_EXTERNAL_CONTROLS_MISMATCH")

    by_id = {step.get("id"): step for step in steps if isinstance(step, dict)}
    if data.get("status") == "PASS":
        if missing:
            findings.append("RECEIPT_PASS_MISSING_MANDATORY_STEPS")
        for step_id in mandatory:
            step = by_id.get(step_id, {})
            if step.get("status") != "PASS" or step.get("exit_code") != 0:
                findings.append(f"RECEIPT_PASS_STEP_NOT_SUCCESSFUL:{step_id}")
        for step_id in TEST_STEP_IDS:
            summary = by_id.get(step_id, {}).get("test_summary")
            if not isinstance(summary, dict):
                findings.append(f"RECEIPT_PASS_TEST_SUMMARY_MISSING:{step_id}")
                continue
            valid = (
                summary.get("completed") == summary.get("total")
                and summary.get("accounted") == summary.get("total")
                and summary.get("failed") == 0
                and summary.get("errors") == 0
                and summary.get("xpassed") == 0
                and summary.get("unexpected_skipped") == 0
                and summary.get("status") == "PASS"
            )
            if not valid:
                findings.append(f"RECEIPT_PASS_TEST_ACCOUNTING_INVALID:{step_id}")
        if not data.get("source", {}).get("source_unchanged"):
            findings.append("RECEIPT_PASS_SOURCE_NOT_IMMUTABLE")
        if not data.get("artifact", {}).get("source_manifest_matches"):
            findings.append("RECEIPT_PASS_ARTIFACT_SOURCE_MISMATCH")
        if not data.get("artifact", {}).get("published"):
            findings.append("RECEIPT_PASS_ARTIFACT_NOT_PUBLISHED")
        if not data.get("reproducibility", {}).get("all_passed"):
            findings.append("RECEIPT_PASS_REPRODUCIBILITY_INCOMPLETE")
        if not data.get("identity_binding", {}).get("verified"):
            findings.append("RECEIPT_PASS_IDENTITY_BINDING_NOT_VERIFIED")
        counts = data.get("rule_traceability", {})
        if not isinstance(counts, dict) or not receipt_counts_valid(counts):
            findings.append("RULE_TRACEABILITY_RECEIPT_COUNT_MISMATCH")
        prompt = data.get("prompt_catalog", {})
        prompt_valid = (
            isinstance(prompt, dict)
            and prompt.get("total_prompts", -1) == prompt.get("catalogued_prompts", -2)
            and prompt.get("prompts_with_valid_digest", -1) == prompt.get("total_prompts", -2)
            and isinstance(prompt.get("read_only_prompts"), int)
            and 0 <= prompt.get("read_only_prompts", -1) <= prompt.get("total_prompts", -2)
            and isinstance(prompt.get("prompts_with_tests"), int)
            and prompt.get("prompts_with_tests", 0) >= 4
            and prompt.get("prompt_id_duplicates") == 0
            and prompt.get("prompt_catalog_orphans") == 0
            and prompt.get("prompt_file_orphans") == 0
        )
        if not prompt_valid:
            findings.append("PROMPT_CATALOG_RECEIPT_COUNT_MISMATCH")
    return findings


def validate_receipt(
    data: dict[str, Any],
    schema: dict[str, Any],
    profiles: dict[str, Any],
    profiles_schema: dict[str, Any] | None = None,
) -> list[str]:
    findings: list[str] = []
    if profiles_schema is not None:
        findings.extend(validate_profiles_registry(profiles, profiles_schema))
    if Draft7Validator is None:
        return ["RECEIPT_SCHEMA_VALIDATOR_UNAVAILABLE:jsonschema"]
    validator = Draft7Validator(schema)
    for error in sorted(validator.iter_errors(data), key=lambda item: list(item.absolute_path)):
        location = "/".join(str(item) for item in error.absolute_path) or "$"
        findings.append(f"RECEIPT_SCHEMA:{location}:{error.message}")
    findings.extend(policy_findings(data, profiles))
    return findings


def _finding(code: str, rule_id: str, message: str, **details: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, "ERROR", details)


def _zip_entry_findings(infos: list[zipfile.ZipInfo], prefix: str) -> list[str]:
    findings: list[str] = []
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        findings.append(f"{prefix}_DUPLICATE_ENTRY")
    for info in infos:
        path = PurePosixPath(info.filename)
        if path.is_absolute() or ".." in path.parts or "\\" in info.filename:
            findings.append(f"{prefix}_UNSAFE_PATH:{info.filename}")
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            findings.append(f"{prefix}_SYMLINK_REJECTED:{info.filename}")
    return findings


@enforces_rule("APS-RELEASE-ARTIFACT-001")
@emits_diagnostic("APS-RELEASE-ARTIFACT-001", "RELEASE_ARTIFACT_RECORDS_VALID")
@emits_diagnostic("APS-RELEASE-ARTIFACT-001", "RELEASE_ARTIFACT_INVALID")
@emits_diagnostic("APS-RELEASE-ARTIFACT-001", "RELEASE_ARTIFACT_UNSAFE_ENTRY")
def read_artifact_records_safe(artifact: Path) -> tuple[list[dict[str, Any]] | None, list[RuleFinding]]:
    try:
        with zipfile.ZipFile(artifact) as archive:
            unsafe = _zip_entry_findings(archive.infolist(), "RELEASE_ARTIFACT")
            if unsafe:
                return None, [_finding("RELEASE_ARTIFACT_UNSAFE_ENTRY", "APS-RELEASE-ARTIFACT-001", item) for item in unsafe]
            bad_entry = archive.testzip()
            if bad_entry is not None:
                return None, [_finding(
                    "RELEASE_ARTIFACT_INVALID",
                    "APS-RELEASE-ARTIFACT-001",
                    "Artifact ZIP failed CRC validation.",
                    entry=bad_entry,
                )]
        records = artifact_records(artifact)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError) as exc:
        return None, [_finding("RELEASE_ARTIFACT_INVALID", "APS-RELEASE-ARTIFACT-001", "Artifact ZIP is malformed.", error=type(exc).__name__)]
    return records, [RuleFinding("RELEASE_ARTIFACT_RECORDS_VALID", "APS-RELEASE-ARTIFACT-001", "Artifact records were read safely.", "INFO", {"file_count": len(records)})]


@enforces_rule("APS-RELEASE-EVIDENCE-001")
@emits_diagnostic("APS-RELEASE-EVIDENCE-001", "RELEASE_EVIDENCE_CARDINALITY_VALID")
@emits_diagnostic("APS-RELEASE-EVIDENCE-001", "RELEASE_EVIDENCE_FILE_COUNT_MISMATCH")
@emits_diagnostic("APS-RELEASE-EVIDENCE-001", "RELEASE_EVIDENCE_MANIFEST_CARDINALITY_MISMATCH")
def validate_evidence_cardinality(
    receipt_count: Any,
    manifest: dict[str, Any],
    names: list[str],
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    actual_count = len(names)
    files = manifest.get("files")
    manifest_paths = [item.get("path") for item in files] if isinstance(files, list) else []
    expected_names = set(path for path in manifest_paths if isinstance(path, str)) | {"manifest.json"}
    if receipt_count != actual_count or manifest.get("file_count") != actual_count:
        findings.append(_finding("RELEASE_EVIDENCE_FILE_COUNT_MISMATCH", "APS-RELEASE-EVIDENCE-001", "Evidence file count does not match ZIP entries.", receipt=receipt_count, manifest=manifest.get("file_count"), actual=actual_count))
    if len(manifest_paths) != len(set(manifest_paths)) or set(names) != expected_names:
        findings.append(_finding("RELEASE_EVIDENCE_MANIFEST_CARDINALITY_MISMATCH", "APS-RELEASE-EVIDENCE-001", "Evidence manifest cardinality or exact file set differs from ZIP."))
    if not findings:
        findings.append(RuleFinding("RELEASE_EVIDENCE_CARDINALITY_VALID", "APS-RELEASE-EVIDENCE-001", "Evidence cardinality is exact.", "INFO", {"file_count": actual_count}))
    return findings


@enforces_rule("APS-RELEASE-IDENTITY-001")
@emits_diagnostic("APS-RELEASE-IDENTITY-001", "RELEASE_IDENTITY_BINDING_VALID")
@emits_diagnostic("APS-RELEASE-IDENTITY-001", "RELEASE_STANDARD_VERSION_MISMATCH")
@emits_diagnostic("APS-RELEASE-IDENTITY-001", "RELEASE_SOURCE_COMMIT_MISMATCH")
@emits_diagnostic("APS-RELEASE-IDENTITY-001", "RELEASE_SOURCE_TREE_MISMATCH")
@emits_diagnostic("APS-RELEASE-IDENTITY-001", "RELEASE_SOURCE_MANIFEST_MISMATCH")
def validate_release_identity_binding(
    data: dict[str, Any],
    manifest: dict[str, Any],
    identity: dict[str, Any],
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    receipt_source = data.get("source", {})
    identity_source = identity.get("source", {})
    manifest_source = manifest.get("source_identity", {})
    if not (data.get("standard_version") == manifest.get("standard_version") == identity.get("standard_version")):
        findings.append(_finding("RELEASE_STANDARD_VERSION_MISMATCH", "APS-RELEASE-IDENTITY-001", "Receipt, evidence manifest and identity record versions differ."))
    for field, code in (
        ("commit_sha", "RELEASE_SOURCE_COMMIT_MISMATCH"),
        ("tree_sha", "RELEASE_SOURCE_TREE_MISMATCH"),
        ("manifest_sha256", "RELEASE_SOURCE_MANIFEST_MISMATCH"),
    ):
        if not (receipt_source.get(field) == manifest_source.get(field) == identity_source.get(field)):
            findings.append(_finding(code, "APS-RELEASE-IDENTITY-001", f"Release source {field} binding differs."))
    if manifest_source.get("package_root_relative", ".") != identity_source.get(
        "package_root_relative", "."
    ):
        findings.append(_finding(
            "RELEASE_SOURCE_MANIFEST_MISMATCH",
            "APS-RELEASE-IDENTITY-001",
            "Release package root binding differs.",
        ))
    if receipt_source.get("file_count") != identity_source.get("file_count") or manifest_source.get("file_count") != identity_source.get("file_count"):
        findings.append(_finding("RELEASE_SOURCE_MANIFEST_MISMATCH", "APS-RELEASE-IDENTITY-001", "Release source file count binding differs."))
    if not findings:
        findings.append(RuleFinding("RELEASE_IDENTITY_BINDING_VALID", "APS-RELEASE-IDENTITY-001", "Portable release identity binding is consistent.", "INFO", {}))
    return findings


@enforces_rule("APS-RELEASE-GIT-MODE-IDENTITY-001")
@emits_diagnostic("APS-RELEASE-GIT-MODE-IDENTITY-001", "RELEASE_SOURCE_GIT_MODE_VALID")
@emits_diagnostic("APS-RELEASE-GIT-MODE-IDENTITY-001", "RELEASE_SOURCE_GIT_MODE_MISMATCH")
def _verify_git_bundle(
    archive: zipfile.ZipFile,
    identity: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[str]:
    return verify_git_bundle(archive, identity, records)


@enforces_rule("APS-RELEASE-TEST-EVIDENCE-001")
@emits_diagnostic("APS-RELEASE-TEST-EVIDENCE-001", "RELEASE_TEST_EVIDENCE_VALID")
@emits_diagnostic("APS-RELEASE-TEST-EVIDENCE-001", "RELEASE_TEST_JUNIT_MISSING")
@emits_diagnostic("APS-RELEASE-TEST-EVIDENCE-001", "RELEASE_TEST_ACCOUNTING_MISMATCH")
@emits_diagnostic("APS-RELEASE-TEST-EVIDENCE-001", "RELEASE_TEST_NODE_SET_MISMATCH")
def validate_test_evidence_binding(
    data: dict[str, Any],
    archive: zipfile.ZipFile,
    identity: dict[str, Any],
) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    steps = {step.get("id"): step for step in data.get("steps", []) if isinstance(step, dict)}
    identity_tests = identity.get("tests", {})
    observed_nodes: dict[str, tuple[str, ...]] = {}
    for step_id in TEST_STEP_IDS:
        step = steps.get(step_id, {})
        binding = identity_tests.get(step_id, {}) if isinstance(identity_tests, dict) else {}
        rel = step.get("junit_xml")
        if not isinstance(rel, str) or rel != binding.get("junit_xml"):
            findings.append(_finding("RELEASE_TEST_JUNIT_MISSING", "APS-RELEASE-TEST-EVIDENCE-001", f"JUnit binding missing for {step_id}."))
            continue
        try:
            payload = archive.read(rel)
        except KeyError:
            findings.append(_finding("RELEASE_TEST_JUNIT_MISSING", "APS-RELEASE-TEST-EVIDENCE-001", f"JUnit file missing for {step_id}."))
            continue
        actual_sha = hashlib.sha256(payload).hexdigest()
        expected_sha = step.get("output_hashes", {}).get("junit_xml_sha256")
        if actual_sha != expected_sha or actual_sha != binding.get("junit_xml_sha256"):
            findings.append(_finding("RELEASE_TEST_ACCOUNTING_MISMATCH", "APS-RELEASE-TEST-EVIDENCE-001", f"JUnit digest differs for {step_id}."))
            continue
        analysis, portable_findings = portable_junit_analysis(archive, rel, step_id=step_id)
        findings.extend(item for item in portable_findings if item.severity == "ERROR")
        if analysis is None:
            findings.append(_finding(
                "RELEASE_TEST_ACCOUNTING_MISMATCH",
                "APS-RELEASE-TEST-EVIDENCE-001",
                f"JUnit is invalid for {step_id}.",
                portable_diagnostics=[item.code for item in portable_findings],
            ))
            continue
        observed_nodes[step_id] = analysis.node_ids
        expected_node_sha = step.get("output_hashes", {}).get("junit_node_ids_sha256")
        if analysis.missing_node_id_count or analysis.duplicate_node_ids or node_ids_sha256(analysis.node_ids) != expected_node_sha or expected_node_sha != binding.get("junit_node_ids_sha256"):
            findings.append(_finding("RELEASE_TEST_NODE_SET_MISMATCH", "APS-RELEASE-TEST-EVIDENCE-001", f"JUnit node identities differ for {step_id}."))
        recomputed = analysis.summary
        declared = step.get("test_summary", {})
        identity_summary = binding.get("summary", {})
        if any(declared.get(key) != recomputed.get(key) or identity_summary.get(key) != recomputed.get(key) for key in SUMMARY_KEYS):
            findings.append(_finding("RELEASE_TEST_ACCOUNTING_MISMATCH", "APS-RELEASE-TEST-EVIDENCE-001", f"JUnit counts differ from receipt for {step_id}."))
        if recomputed.get("status") != "PASS":
            findings.append(_finding("RELEASE_TEST_ACCOUNTING_MISMATCH", "APS-RELEASE-TEST-EVIDENCE-001", f"JUnit PASS policy failed for {step_id}."))
    if observed_nodes.get("direct_tests") and observed_nodes.get("tests") and set(observed_nodes["direct_tests"]) != set(observed_nodes["tests"]):
        findings.append(_finding("RELEASE_TEST_NODE_SET_MISMATCH", "APS-RELEASE-TEST-EVIDENCE-001", "Direct and segmented full-suite node sets differ."))
    if not findings:
        findings.append(RuleFinding("RELEASE_TEST_EVIDENCE_VALID", "APS-RELEASE-TEST-EVIDENCE-001", "All test accounting was recomputed from exported JUnit.", "INFO", {}))
    return findings


def _dead_code_report_findings(
    data: dict[str, Any],
    archive: zipfile.ZipFile,
) -> tuple[dict[str, Any] | None, list[RuleFinding]]:
    findings: list[RuleFinding] = []
    step = next((item for item in data.get("steps", []) if item.get("id") == "dead_code_audit"), {})
    try:
        payload = archive.read("reports/dead_code_report.json")
        report = json.loads(payload)
    except (KeyError, json.JSONDecodeError) as exc:
        return None, [_finding(
            "APS_DEAD_CODE_REPORT_SCHEMA_INVALID",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Exported dead-code report is missing or malformed.",
            error=type(exc).__name__,
        )]
    if hashlib.sha256(payload).hexdigest() != step.get("output_hashes", {}).get("dead_code_report_sha256"):
        findings.append(_finding(
            "APS_DEAD_CODE_REPORT_SCHEMA_INVALID",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Dead-code report digest is not bound to the release step.",
        ))
    for problem in validate_dead_code_report(report):
        findings.append(_finding(
            "APS_DEAD_CODE_REPORT_SCHEMA_INVALID",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            problem,
        ))
    if report.get("status") != "PASS":
        findings.append(_finding(
            "APS_DEAD_CODE_REPORT_SCHEMA_INVALID",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Formal release dead-code report is not PASS.",
            status=report.get("status"),
        ))
    return report, findings


def _checkout_dead_code_bundle(
    archive: zipfile.ZipFile,
    identity: dict[str, Any],
    records: list[dict[str, Any]],
    temp: Path,
) -> tuple[Path | None, list[RuleFinding]]:
    bundle_path = identity.get("source", {}).get("git_bundle")
    if not isinstance(bundle_path, str):
        return None, [_finding(
            "APS_DEAD_CODE_REPORT_RECOMPUTE_MISMATCH",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Source Git bundle binding is missing.",
        )]
    try:
        bundle_payload = archive.read(bundle_path)
    except KeyError:
        return None, [_finding(
            "APS_DEAD_CODE_REPORT_RECOMPUTE_MISMATCH",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Source Git bundle is absent from evidence.",
        )]
    _, package_checkout, _, _ = checkout_git_bundle_package(
        bundle_payload, identity, records, temp,
    )
    return package_checkout, []


def _recompute_dead_code_report(
    checkout: Path,
    submitted: dict[str, Any],
    temp: Path,
) -> list[RuleFinding]:
    output = temp / "recomputed_dead_code_report.json"
    env = {
        **os.environ,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    run = subprocess.run(
        [
            sys.executable,
            str(checkout / "tools/dead_code_audit.py"),
            "--root", str(checkout),
            "--profile", "standard-package",
            "--output", str(output),
        ],
        cwd=checkout, capture_output=True, text=True, timeout=600, env=env,
    )
    if run.returncode != 0 or not output.is_file():
        return [_finding(
            "APS_DEAD_CODE_REPORT_RECOMPUTE_MISMATCH",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Independent dead-code audit did not reproduce PASS.",
            exit_code=run.returncode,
        )]
    recomputed = json.loads(output.read_text(encoding="utf-8-sig"))
    findings = [
        _finding(
            "APS_DEAD_CODE_REPORT_SCHEMA_INVALID",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            f"Recomputed report invalid: {problem}",
        )
        for problem in validate_dead_code_report(
            recomputed, checkout / "schemas/dead_code_report.schema.json"
        )
    ]
    if normalized_dead_code_report(submitted) != normalized_dead_code_report(recomputed):
        findings.append(_finding(
            "APS_DEAD_CODE_REPORT_RECOMPUTE_MISMATCH",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Exported dead-code report differs from independent exact-source recomputation.",
        ))
    return findings


def _dead_code_evidence_node_findings(
    data: dict[str, Any],
    archive: zipfile.ZipFile,
    checkout: Path,
) -> list[RuleFinding]:
    required_nodes: set[str] = set()
    for registry_path, collection_key in (
        ("reference/dead_code_entrypoints.json", "entrypoints"),
        ("reference/dead_code_allowlist.json", "entries"),
        ("reference/dead_code_public_api.json", "apis"),
    ):
        registry = json.loads((checkout / registry_path).read_text(encoding="utf-8-sig"))
        for item in registry.get(collection_key, []):
            required_nodes.update(evidence_test_nodes(item.get("evidence")))
    junit_outcomes: dict[str, dict[str, str]] = {}
    findings: list[RuleFinding] = []
    for step_id in ("direct_tests", "tests"):
        step = next((item for item in data.get("steps", []) if item.get("id") == step_id), {})
        rel = step.get("junit_xml")
        if not isinstance(rel, str):
            junit_outcomes[step_id] = {}
            findings.append(_finding(
                "PORTABLE_VERIFIER_JUNIT_FILE_MISSING",
                "APS-PORTABLE-VERIFIER-JUNIT-ERROR-001",
                f"Portable verifier JUnit binding is missing for {step_id}.",
                step_id=step_id,
            ))
            continue
        analysis, portable_findings = portable_junit_analysis(archive, rel, step_id=step_id)
        findings.extend(item for item in portable_findings if item.severity == "ERROR")
        junit_outcomes[step_id] = dict(analysis.node_outcomes) if analysis is not None else {}

    missing = sorted(
        node for node in required_nodes
        if node not in junit_outcomes.get("direct_tests", {})
        or node not in junit_outcomes.get("tests", {})
    )
    nonpassing = {
        step_id: {
            node: outcomes[node]
            for node in sorted(required_nodes & set(outcomes))
            if outcomes[node] != "passed"
        }
        for step_id, outcomes in junit_outcomes.items()
    }
    if missing:
        findings.append(_finding(
            "APS_DEAD_CODE_EVIDENCE_TEST_NODE_MISSING",
            "APS-DEAD-CODE-EVIDENCE-BINDING-001",
            "Typed evidence test nodes are absent from direct or segmented JUnit.",
            missing=missing,
        ))
    invalid_outcomes = {key: value for key, value in nonpassing.items() if value}
    if invalid_outcomes:
        findings.append(_finding(
            "APS_DEAD_CODE_EVIDENCE_INVALID",
            "APS-DEAD-CODE-EVIDENCE-BINDING-001",
            "Typed evidence test nodes did not pass in canonical JUnit.",
            outcomes=invalid_outcomes,
        ))
    return findings


@enforces_rule("APS-DEAD-CODE-REPORT-SCHEMA-001")
@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@enforces_rule("APS-PORTABLE-VERIFIER-JUNIT-ERROR-001")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_VALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_INVALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_RECOMPUTE_MISMATCH")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_TEST_NODE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_TEST_NODE_MISSING")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_dead_code_exported_evidence(
    data: dict[str, Any],
    archive: zipfile.ZipFile,
    identity: dict[str, Any],
) -> list[RuleFinding]:
    """Revalidate and independently recompute the exported dead-code report."""
    submitted, findings = _dead_code_report_findings(data, archive)
    if submitted is None:
        return findings
    try:
        with tempfile.TemporaryDirectory(prefix="aps_dead_code_verify_") as raw:
            temp = Path(raw)
            records = data.get("source", {}).get("records", [])
            checkout, checkout_findings = _checkout_dead_code_bundle(
                archive, identity, records, temp,
            )
            findings.extend(checkout_findings)
            if checkout is not None:
                findings.extend(_recompute_dead_code_report(checkout, submitted, temp))
                findings.extend(_dead_code_evidence_node_findings(data, archive, checkout))
    except (
        OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired,
        json.JSONDecodeError, KeyError, ValueError,
    ) as exc:
        findings.append(_finding(
            "APS_DEAD_CODE_REPORT_RECOMPUTE_MISMATCH",
            "APS-DEAD-CODE-REPORT-SCHEMA-001",
            "Portable dead-code recomputation failed closed.",
            error=type(exc).__name__,
        ))
    if not findings:
        findings.extend([
            RuleFinding(
                "APS_DEAD_CODE_REPORT_SCHEMA_VALID",
                "APS-DEAD-CODE-REPORT-SCHEMA-001",
                "Exported dead-code report passed schema and exact-source recomputation.",
                "INFO", {},
            ),
            RuleFinding(
                "APS_DEAD_CODE_EVIDENCE_TEST_NODE_VALID",
                "APS-DEAD-CODE-EVIDENCE-BINDING-001",
                "All typed evidence test nodes occur in direct and segmented JUnit.",
                "INFO", {},
            ),
        ])
    return findings


def verify_exported_evidence(
    data: dict[str, Any],
    *,
    artifact: Path | None = None,
    evidence_bundle: Path | None = None,
    source_root: Path | None = None,
) -> list[str]:
    """Independently recompute artifact, Git identity, evidence and JUnit claims."""
    findings: list[str] = []
    source = data.get("source", {})
    records = source.get("records", [])
    if not isinstance(records, list) or manifest_digest(records) != source.get("manifest_sha256"):
        findings.append("RECEIPT_SOURCE_MANIFEST_SHA_MISMATCH")

    artifact_data = data.get("artifact", {})
    if artifact is not None:
        if not artifact.exists():
            findings.append("RECEIPT_ARTIFACT_MISSING")
        else:
            if sha256_file(artifact) != artifact_data.get("sha256"):
                findings.append("RECEIPT_ARTIFACT_SHA_MISMATCH")
            actual_records, artifact_findings = read_artifact_records_safe(artifact)
            findings.extend(item.code for item in artifact_findings if item.severity == "ERROR")
            if actual_records is not None:
                if compare_records(records, actual_records):
                    findings.append("RECEIPT_ARTIFACT_RECORDS_MISMATCH")
                if artifact_data.get("file_count") != len(actual_records):
                    findings.append("RECEIPT_ARTIFACT_FILE_COUNT_MISMATCH")

    hashes = data.get("reproducibility", {}).get("hashes", {})
    if data.get("reproducibility", {}).get("all_passed"):
        expected = artifact_data.get("sha256")
        for name in ("artifact", "same_tree", "fresh_snapshot", "cross_extraction"):
            if hashes.get(name) != expected:
                findings.append(f"RECEIPT_REPRODUCIBILITY_HASH_MISMATCH:{name}")

    if source_root is not None:
        identity = identify_release_source(source_root)
        if identity.manifest_sha256 != source.get("manifest_sha256"):
            findings.append("RECEIPT_SOURCE_ROOT_MANIFEST_MISMATCH")
        if source.get("commit_sha") and identity.commit_sha != source.get("commit_sha"):
            findings.append("RECEIPT_SOURCE_COMMIT_MISMATCH")
        if source.get("tree_sha") and identity.tree_sha != source.get("tree_sha"):
            findings.append("RECEIPT_SOURCE_TREE_MISMATCH")

    bundle_data = data.get("evidence_bundle", {})
    if evidence_bundle is not None:
        if not evidence_bundle.exists():
            findings.append("RELEASE_EVIDENCE_BUNDLE_MISSING")
        else:
            if bundle_data.get("sha256") != sha256_file(evidence_bundle):
                findings.append("RELEASE_EVIDENCE_BUNDLE_SHA_MISMATCH")
            try:
                with zipfile.ZipFile(evidence_bundle) as archive:
                    infos = archive.infolist()
                    findings.extend(_zip_entry_findings(infos, "RELEASE_EVIDENCE"))
                    bad_entry = archive.testzip()
                    if bad_entry is not None:
                        findings.append(f"RELEASE_EVIDENCE_BUNDLE_CRC_FAILED:{bad_entry}")
                    names = [item.filename for item in infos]
                    manifest_payload = archive.read("manifest.json")
                    manifest = json.loads(manifest_payload)
                    if hashlib.sha256(manifest_payload).hexdigest() != bundle_data.get("manifest_sha256"):
                        findings.append("RELEASE_EVIDENCE_MANIFEST_SHA_MISMATCH")
                    findings.extend(item.code for item in validate_evidence_cardinality(bundle_data.get("file_count"), manifest, names) if item.severity == "ERROR")
                    for item in manifest.get("files", []):
                        path = item.get("path")
                        if path not in names:
                            findings.append(f"RELEASE_EVIDENCE_FILE_MISSING:{path}")
                            continue
                        payload = archive.read(path)
                        if hashlib.sha256(payload).hexdigest() != item.get("sha256") or len(payload) != item.get("size"):
                            findings.append(f"RELEASE_EVIDENCE_FILE_SHA_MISMATCH:{path}")
                    identity_path = data.get("identity_binding", {}).get("path")
                    if identity_path != "release_identity.json":
                        findings.append("RELEASE_IDENTITY_RECORD_PATH_MISMATCH")
                        identity = {}
                    else:
                        identity_payload = archive.read(identity_path)
                        identity_sha = hashlib.sha256(identity_payload).hexdigest()
                        if identity_sha != data.get("identity_binding", {}).get("sha256"):
                            findings.append("RELEASE_IDENTITY_RECORD_SHA_MISMATCH")
                        manifest_identity = manifest.get("identity_record", {})
                        if manifest_identity.get("path") != identity_path or manifest_identity.get("sha256") != identity_sha:
                            findings.append("RELEASE_IDENTITY_RECORD_MANIFEST_MISMATCH")
                        identity = json.loads(identity_payload)
                    identity_bundle_sha = identity.get("source", {}).get("git_bundle_sha256")
                    if data.get("identity_binding", {}).get("source_git_bundle_sha256") != identity_bundle_sha:
                        findings.append("RELEASE_SOURCE_GIT_BUNDLE_SHA_MISMATCH")
                    artifact_identity = identity.get("artifact", {})
                    manifest_artifact_identity = manifest.get("artifact_identity", {})
                    if artifact_identity != manifest_artifact_identity:
                        findings.append("RELEASE_ARTIFACT_IDENTITY_MISMATCH")
                    if artifact_identity.get("sha256") != artifact_data.get("sha256") or artifact_identity.get("file_count") != artifact_data.get("file_count"):
                        findings.append("RELEASE_ARTIFACT_IDENTITY_MISMATCH")
                    findings.extend(item.code for item in validate_release_identity_binding(data, manifest, identity) if item.severity == "ERROR")
                    git_bundle_findings = _verify_git_bundle(archive, identity, records)
                    findings.extend(git_bundle_findings)
                    findings.extend(item.code for item in validate_test_evidence_binding(data, archive, identity) if item.severity == "ERROR")
                    if not git_bundle_findings:
                        findings.extend(item.code for item in validate_dead_code_exported_evidence(data, archive, identity) if item.severity == "ERROR")
                    for step in data.get("steps", []):
                        for field, digest_field in (("stdout_log", "stdout_sha256"), ("stderr_log", "stderr_sha256")):
                            rel = step.get(field)
                            if not isinstance(rel, str) or Path(rel).is_absolute():
                                findings.append(f"RELEASE_EVIDENCE_LOG_PATH_NOT_PORTABLE:{step.get('id')}:{field}")
                                continue
                            if rel not in names:
                                findings.append(f"RELEASE_EVIDENCE_LOG_MISSING:{step.get('id')}:{rel}")
                            elif hashlib.sha256(archive.read(rel)).hexdigest() != step.get(digest_field):
                                findings.append(f"RELEASE_EVIDENCE_LOG_SHA_MISMATCH:{step.get('id')}:{rel}")
            except (OSError, zipfile.BadZipFile, KeyError, json.JSONDecodeError, ValueError) as exc:
                findings.append(f"RELEASE_EVIDENCE_BUNDLE_INVALID:{type(exc).__name__}")
    return sorted(set(findings))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--schema", default="schemas/release_receipt.schema.json")
    parser.add_argument("--profiles", default="reference/release_profiles.json")
    parser.add_argument("--profiles-schema", default="schemas/release_profiles.schema.json")
    parser.add_argument("--verify", action="store_true", help="independently recompute artifact/source/evidence/JUnit claims")
    parser.add_argument("--artifact")
    parser.add_argument("--evidence-bundle")
    parser.add_argument("--source-root")
    args = parser.parse_args()
    try:
        data = load_json(Path(args.receipt))
        schema = load_json(Path(args.schema))
        profiles = load_json(Path(args.profiles))
        profiles_schema = load_json(Path(args.profiles_schema))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"RECEIPT_READ_FAILED:{type(exc).__name__}", file=sys.stderr)
        return 2
    findings = validate_receipt(data, schema, profiles, profiles_schema)
    if args.verify:
        if data.get("status") == "PASS" and data.get("profile") == "release":
            if not args.artifact:
                findings.append("VERIFICATION_INPUT_REQUIRED:artifact")
            if not args.evidence_bundle:
                findings.append("VERIFICATION_INPUT_REQUIRED:evidence_bundle")
        try:
            findings.extend(verify_exported_evidence(
                data,
                artifact=Path(args.artifact) if args.artifact else None,
                evidence_bundle=Path(args.evidence_bundle) if args.evidence_bundle else None,
                source_root=Path(args.source_root) if args.source_root else None,
            ))
        except JUnitEvidenceError as exc:
            code = str(exc).split(":", 1)[0]
            finding = _finding(
                "PORTABLE_VERIFIER_JUNIT_XML_MALFORMED",
                "APS-PORTABLE-VERIFIER-JUNIT-ERROR-001",
                "Portable verifier rejected malformed JUnit at its outer CLI boundary.",
                parser_diagnostic=code,
            )
            findings.append(finding.legacy())
            print("APS_RULE_DIAGNOSTIC:" + json.dumps(finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    if findings:
        for finding in sorted(set(findings)):
            print(finding, file=sys.stderr)
        return 1
    print("Release receipt schema, policy and exported evidence are valid." if args.verify else "Release receipt schema and policy are valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
