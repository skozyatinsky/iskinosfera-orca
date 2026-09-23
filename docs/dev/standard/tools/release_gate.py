#!/usr/bin/env python3
# ======================================================================
# release_gate.py — версия 3.1
# Immutable release pipeline with portable independently verifiable evidence.
# ======================================================================

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_evidence import build_bundle, load_json, utc_now, write_portable_log  # noqa: E402
from junit_evidence import JUnitEvidenceError, node_ids_sha256, parse_junit  # noqa: E402
from release_integrity import (  # noqa: E402
    artifact_records, compare_records, copy_release_tree, extract_python,
    identify_source, perturb_metadata, prune_release_temp, remove_release_workspace, sha256_file, source_records,
    verify_artifact_matches_source,
)
from validate_release_receipt import validate_receipt, verify_exported_evidence  # noqa: E402
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule  # noqa: E402
from prompt_audit_contract import prompt_catalog_metrics  # noqa: E402
from release_external_controls import (  # noqa: E402
    artifact_prerequisites, final_receipt_status, release_block_state, requires_independent,
    run_certified_linux_suite, run_formal_external_trust_anchor, synthesize_blocked_release_steps,
)
from release_source_identity import committed_source_unchanged, copy_release_source, git_package_root_relative, identify_release_source, source_bundle_filter_arg  # noqa: E402

RECEIPT_SCHEMA_VERSION = "4.0.0"
RELEASE_SKIP_RULE_ID = "APS-RELEASE-SKIP-001"
RELEASE_SKIP_FINDING = "RELEASE_SKIP_TESTS_INCOMPLETE"
RELEASE_SKIP_RULE_REGISTERED = "RELEASE_SKIP_RULE_REGISTERED"
STATIC_FLAGS = [
    "--profile", "standard-package", "--root", ".",
    "--check-skills", "--check-agent-config", "--check-reference-data",
    "--check-spec-sync", "--check-manifest", "--check-skills-manifest",
    "--check-prompt-catalog", "--check-standard-overview", "--check-memory-governance",
    "--check-rag-action-governance", "--check-dead-code",
    "--check-tz-governance", "--check-audit-sequence",
    "--check-standard-capabilities", "--check-capability-evidence",
    "--check-hardcode", "--check-pattern-memory", "--check-markdown-links",
    "--check-data-in-code", "--check-test-coverage", "--check-knowledge-index",
    "--check-entitlements", "--check-dependency-policy",
    "--check-dependency-selection-policy", "--check-tooling-security-review",
    "--check-tool-candidates", "--check-approved-tools", "--check-verification-evidence",
    "--check-loop-safe-mutation",
    "--check-module-registry", "--check-code-ownership", "--check-module-boundaries",
    "--check-work-package-graph", "--check-work-package-overlap",
    "--check-parallel-ai-development", "--check-agent-workflow-integrity",
    "--check-control-plane-integrity", "--check-check-registry", "--check-sync-policy",
    "--check-encrypted-env", "--check-automation-jobs", "--check-git-agent-policy",
    "--check-code-audit-policy", "--check-license-integration-policy",
    "--check-qai-fabric-policy", "--check-git-workspace-hygiene",
    "--check-agent-results", "--check-agent-task-contracts",
    "--check-classical-engineering-foundations", "--check-golden-path-portability",
    "--check-file-size", "--check-version-sync", "--check-ci-security",
    "--check-release-hygiene", "--check-rule-traceability",
    "--check-rule-inventory", "--check-rule-semantic-continuity",
    "--check-rule-implementation-linkage", "--check-rule-diagnostics",
    "--check-rule-test-evidence", "--warnings-as-errors",
]
BUILD_STEP_IDS = ("build", "artifact", "artifact_source_integrity", "same_tree_rebuild", "fresh_snapshot_rebuild", "cross_extraction_rebuild")
# ======================================================================
# RELEASE-SKIP POLICY — APS-RELEASE-SKIP-001
# ======================================================================
@enforces_rule("APS-RELEASE-SKIP-001")
@emits_diagnostic("APS-RELEASE-SKIP-001", "RELEASE_SKIP_RULE_REGISTERED")
@emits_diagnostic("APS-RELEASE-SKIP-001", "RELEASE_SKIP_TESTS_INCOMPLETE")
@emits_diagnostic("APS-RELEASE-SKIP-001", "RELEASE_SKIP_PREEXISTING_ARTIFACT_REMOVED")
def validate_skip_tests_policy(skip_tests: bool, artifact_paths: list[Path]) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    for path in artifact_paths:
        if path.exists():
            path.unlink()
            findings.append(RuleFinding(
                "RELEASE_SKIP_PREEXISTING_ARTIFACT_REMOVED",
                RELEASE_SKIP_RULE_ID,
                "Pre-existing release artifact was removed before gate execution.",
                "INFO",
                {"path": path.name},
            ))
    if skip_tests:
        findings.append(RuleFinding(
            RELEASE_SKIP_FINDING,
            RELEASE_SKIP_RULE_ID,
            "Skipping mandatory tests makes the release incomplete and unpublished.",
            "ERROR",
            {},
        ))
    if not findings:
        findings.append(RuleFinding(
            RELEASE_SKIP_RULE_REGISTERED,
            RELEASE_SKIP_RULE_ID,
            "Release skip policy is registered in the production gate.",
            "INFO",
            {},
        ))
    return findings

def _portable(value: str, replacements: dict[str, str]) -> str:
    result = value
    for source, target in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if source:
            result = result.replace(source, target)
    return result

def _write_step_logs(stage: Path, step_id: str, stdout: str, stderr: str, replacements: dict[str, str]) -> tuple[str, str, str, str]:
    stdout_rel = f"logs/{step_id}.stdout.log"; stderr_rel = f"logs/{step_id}.stderr.log"
    stdout_sha = write_portable_log(stage, stdout_rel, stdout, replacements)
    stderr_sha = write_portable_log(stage, stderr_rel, stderr, replacements)
    return stdout_rel, stderr_rel, stdout_sha, stderr_sha


def command_step(
    step_id: str,
    command: list[str],
    cwd: Path,
    stage: Path,
    replacements: dict[str, str],
    *,
    env: dict[str, str] | None = None,
    input_hashes: dict[str, str] | None = None,
    output_hashes: dict[str, str] | None = None,
    test_summary_path: Path | None = None,
) -> dict[str, Any]:
    started_at = utc_now(); started = time.monotonic()
    effective_env = dict(os.environ)
    effective_env.update({
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
    })
    if env:
        effective_env.update(env)
    command_temp = stage.parent / "command_temp"; remove_release_workspace(command_temp, stage.parent); command_temp.mkdir()
    effective_env.update({"TMPDIR": str(command_temp), "TMP": str(command_temp), "TEMP": str(command_temp)})
    proc = subprocess.run(command, cwd=cwd, env=effective_env, capture_output=True, text=True)
    remove_release_workspace(command_temp, stage.parent)
    stdout_rel, stderr_rel, stdout_sha, stderr_sha = _write_step_logs(stage, step_id, proc.stdout, proc.stderr, replacements)
    result: dict[str, Any] = {
        "id": step_id,
        "command": [_portable(str(value), replacements) for value in command],
        "working_directory": _portable(str(cwd), replacements),
        "started_at": started_at,
        "duration_seconds": round(time.monotonic() - started, 3),
        "exit_code": proc.returncode,
        "status": "PASS" if proc.returncode == 0 else "FAIL",
        "stdout_sha256": stdout_sha,
        "stderr_sha256": stderr_sha,
        "stdout_log": stdout_rel,
        "stderr_log": stderr_rel,
        "input_hashes": input_hashes or {},
        "output_hashes": output_hashes or {},
    }
    if test_summary_path and test_summary_path.exists():
        result["test_summary"] = load_json(test_summary_path)
    return result


def bind_junit_evidence(step: dict[str, Any], junit_path: Path, stage: Path, summary_path: Path | None = None) -> None:
    """Bind a test step to exported JUnit and recompute its accounting."""
    if not junit_path.is_file():
        step.update({"status": "FAIL", "exit_code": 1, "findings": ["RELEASE_TEST_JUNIT_MISSING"]})
        return
    try:
        analysis = parse_junit(junit_path, require_node_ids=True)
    except (OSError, JUnitEvidenceError) as exc:
        step.update({
            "status": "FAIL",
            "exit_code": 1,
            "findings": [f"RELEASE_TEST_JUNIT_INVALID:{exc}"],
        })
        return
    recomputed = dict(analysis.summary)
    if summary_path and summary_path.is_file():
        declared = load_json(summary_path)
        accounting_keys = ("total", "completed", "accounted", "passed", "failed", "skipped", "xfailed", "xpassed", "errors", "unexpected_skipped", "status")
        if any(declared.get(key) != recomputed.get(key) for key in accounting_keys):
            step.update({"status": "FAIL", "exit_code": 1, "findings": ["RELEASE_TEST_SUMMARY_JUNIT_MISMATCH"]})
        recomputed["duration_seconds"] = declared.get("duration_seconds", 0.0)
    if analysis.missing_node_id_count or analysis.duplicate_node_ids or recomputed.get("status") != "PASS":
        step.update({"status": "FAIL", "exit_code": 1, "findings": sorted(set(step.get("findings", []) + ["RELEASE_TEST_JUNIT_ACCOUNTING_INVALID"]))})
    rel = junit_path.relative_to(stage).as_posix()
    step["test_summary"] = recomputed
    step["junit_xml"] = rel
    step["output_hashes"] = {
        **step.get("output_hashes", {}),
        "junit_xml_sha256": sha256_file(junit_path),
        "junit_node_ids_sha256": node_ids_sha256(analysis.node_ids),
    }


def run_source_identity_bundle(root: Path, stage: Path, replacements: dict[str, str], source_identity: Any) -> dict[str, Any]:
    """Export the exact Git commit/tree as portable source identity evidence."""
    bundle_path = stage / "source" / "source_repository.bundle"
    bundle_path.parent.mkdir(parents=True, exist_ok=True)
    step = command_step(
        "source_identity_bundle",
        ["git", "-c", "pack.threads=1", "-c", "pack.window=250", "-c", "pack.depth=50", "bundle", "create", "--version=3", str(bundle_path), f"--filter={source_bundle_filter_arg(source_identity.records)}", "HEAD"],
        root,
        stage,
        replacements,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    )
    if bundle_path.is_file():
        step["output_hashes"] = {"source_git_bundle_sha256": sha256_file(bundle_path)}
    else:
        step.update({"status": "FAIL", "exit_code": 1, "findings": ["RELEASE_SOURCE_GIT_BUNDLE_MISSING"]})
    return step


def synthetic_step(
    step_id: str,
    cwd: Path,
    stage: Path,
    replacements: dict[str, str],
    *,
    passed: bool,
    findings: list[str] | None = None,
    input_hashes: dict[str, str] | None = None,
    output_hashes: dict[str, str] | None = None,
    command: list[str] | None = None,
    skipped: bool = False,
    stdout_text: str | None = None,
) -> dict[str, Any]:
    findings = findings or []
    stdout = stdout_text if stdout_text is not None else ("" if findings else f"{step_id}: PASS\n")
    stderr = "\n".join(findings) + ("\n" if findings else "")
    stdout_rel, stderr_rel, stdout_sha, stderr_sha = _write_step_logs(stage, step_id, stdout, stderr, replacements)
    return {
        "id": step_id,
        "command": [_portable(str(value), replacements) for value in (command or ["internal", step_id])],
        "working_directory": _portable(str(cwd), replacements),
        "started_at": utc_now(),
        "duration_seconds": 0.0,
        "exit_code": 0 if passed else (2 if skipped else 1),
        "status": "SKIPPED" if skipped else ("PASS" if passed else "FAIL"),
        "stdout_sha256": stdout_sha,
        "stderr_sha256": stderr_sha,
        "stdout_log": stdout_rel,
        "stderr_log": stderr_rel,
        "input_hashes": input_hashes or {},
        "output_hashes": output_hashes or {},
        **({"findings": findings} if findings else {}),
    }


def _all_pass(steps: list[dict[str, Any]], required: list[str] | tuple[str, ...]) -> bool:
    by_id = {step["id"]: step for step in steps}
    return all(by_id.get(step_id, {}).get("status") == "PASS" and by_id[step_id].get("exit_code") == 0 for step_id in required)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--evidence-bundle")
    parser.add_argument("--profile", default="release")
    parser.add_argument("--skip-tests", action="store_true")
    return parser.parse_args()


def source_preflight(source_identity: Any, profile: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    if profile["requires_git_repository"] and not source_identity.git_repository:
        findings.append("RELEASE_GIT_REPOSITORY_REQUIRED")
    clean_policy = profile["requires_clean_working_tree"]
    if clean_policy == "always" and source_identity.git_clean is not True:
        findings.append("RELEASE_CLEAN_WORKING_TREE_REQUIRED")
    if clean_policy == "if_git" and source_identity.git_repository and source_identity.git_clean is not True:
        findings.append("RELEASE_CLEAN_WORKING_TREE_REQUIRED")
    findings.extend(f"RELEASE_SOURCE_SYMLINK_UNSUPPORTED:{item['path']}" for item in source_identity.records if item.get("type") == "symlink")
    for item in source_identity.git_mode_mismatches:
        findings.append(f"RELEASE_SOURCE_GIT_MODE_MISMATCH:{item['path']}:{item['git_mode']}:{item['artifact_mode']}")
    return findings


def workspace_integrity_step(step_id: str, workspace: Path, baseline: list[dict[str, Any]], manifest_sha: str, stage: Path, replacements: dict[str, str]) -> dict[str, Any]:
    current = source_records(workspace); findings = compare_records(baseline, current)
    if findings:
        code = {"static_source_integrity": "SOURCE_TREE_MUTATED_DURING_STATIC", "tests_source_integrity": "SOURCE_TREE_MUTATED_DURING_TESTS", "golden_source_integrity": "SOURCE_TREE_MUTATED_DURING_GOLDEN", "capability_source_integrity": "SOURCE_TREE_MUTATED_DURING_CAPABILITY_EVIDENCE", "agent_gate_source_integrity": "SOURCE_TREE_MUTATED_DURING_AGENT_GATE_EVIDENCE", "trust_boundary_source_integrity": "SOURCE_TREE_MUTATED_DURING_TRUST_BOUNDARY_EVIDENCE"}.get(step_id, "SOURCE_TREE_MUTATED_DURING_EXECUTION")
        findings = [code, *findings]
    return synthetic_step(step_id, workspace, stage, replacements, passed=not findings, findings=findings, input_hashes={"source_manifest_sha256": manifest_sha}, output_hashes={"workspace_manifest_sha256": identify_source(workspace).manifest_sha256})

def run_source_static(root: Path, pristine: Path, temp: Path, stage: Path, replacements: dict[str, str], source_identity: Any, profile: dict[str, Any]) -> tuple[Path, list[dict[str, Any]]]:
    if source_identity.git_repository and not any(item.get("type") == "symlink" for item in source_identity.records): copy_release_source(root, pristine, source_identity)
    else: copy_release_tree(root, pristine)
    pristine_id = identify_source(pristine)
    findings = source_preflight(source_identity, profile)
    diff = compare_records(source_identity.records, pristine_id.records)
    if diff: findings.extend(["SOURCE_SNAPSHOT_MISMATCH", *diff])
    steps = [synthetic_step("source_preflight", root, stage, replacements, passed=not findings, findings=findings, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}, output_hashes={"snapshot_manifest_sha256": pristine_id.manifest_sha256})]
    workspace = temp / "static_workspace"; copy_release_tree(pristine, workspace)
    steps.append(command_step("static", [sys.executable, "tools/validate_structure.py", *STATIC_FLAGS], workspace, stage, replacements, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("static_source_integrity", workspace, source_identity.records, source_identity.manifest_sha256, stage, replacements))
    return workspace, steps



def run_tests(
    pristine: Path,
    temp: Path,
    stage: Path,
    replacements: dict[str, str],
    source_identity: Any,
    skip: bool,
    *,
    skip_finding: str = "MANDATORY_TESTS_SKIPPED",
) -> list[dict[str, Any]]:
    test_ids = ("direct_tests", "direct_tests_source_integrity", "tests", "tests_source_integrity", "golden", "golden_source_integrity")
    if skip:
        return [synthetic_step(step_id, pristine, stage, replacements, passed=False, findings=[skip_finding], skipped=True) for step_id in test_ids]
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider"}
    steps: list[dict[str, Any]] = []

    direct = temp / "direct_tests_workspace"
    copy_release_tree(pristine, direct)
    direct_summary = temp / "direct_tests_summary.json"
    direct_junit = stage / "reports" / "direct_tests.junit.xml"
    direct_step = command_step(
        "direct_tests",
        [sys.executable, "tools/run_test_suite.py", "--chunk-size", "1000000", "--chunk-timeout-seconds", "3600", "--summary-json", str(direct_summary), "--junit-xml", str(direct_junit), "--", "-q"],
        direct, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    )
    bind_junit_evidence(direct_step, direct_junit, stage, direct_summary)
    steps.append(direct_step)
    steps.append(workspace_integrity_step("direct_tests_source_integrity", direct, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(direct, temp)

    tests = temp / "tests_workspace"
    copy_release_tree(pristine, tests)
    summary = temp / "tests_summary.json"
    tests_junit = stage / "reports" / "segmented_tests.junit.xml"
    tests_step = command_step(
        "tests",
        [sys.executable, "tools/run_test_suite.py", "--chunk-size", "25", "--chunk-timeout-seconds", "120", "--summary-json", str(summary), "--junit-xml", str(tests_junit), "--", "-q"],
        tests, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    )
    bind_junit_evidence(tests_step, tests_junit, stage, summary)
    steps.append(tests_step)
    steps.append(workspace_integrity_step("tests_source_integrity", tests, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(tests, temp)

    golden = temp / "golden_workspace"
    copy_release_tree(pristine, golden)
    gsummary = temp / "golden_summary.json"
    golden_junit = stage / "reports" / "golden.junit.xml"
    golden_step = command_step(
        "golden",
        [sys.executable, "tools/run_test_suite.py", "--chunk-size", "1", "--chunk-timeout-seconds", "240", "--summary-json", str(gsummary), "--junit-xml", str(golden_junit), "--", "tests/test_validate_structure.py::test_reference_project_exact_ci_strict_command_passes"],
        golden, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    )
    bind_junit_evidence(golden_step, golden_junit, stage, gsummary)
    steps.append(golden_step)
    steps.append(workspace_integrity_step("golden_source_integrity", golden, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(golden, temp)
    return steps



def run_prompt_audit_evidence(
    pristine: Path,
    temp: Path,
    stage: Path,
    replacements: dict[str, str],
    source_identity: Any,
) -> list[dict[str, Any]]:
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider"}
    steps: list[dict[str, Any]] = []

    catalog = temp / "prompt_catalog_workspace"; copy_release_tree(pristine, catalog)
    steps.append(command_step(
        "prompt_catalog_validation",
        [sys.executable, "tools/validate_structure.py", "--root", ".", "--profile", "standard-package", "--schemas-root", "schemas", "--check-prompt-catalog", "--warnings-as-errors"],
        catalog, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    ))

    integrity = temp / "prompt_content_workspace"; copy_release_tree(pristine, integrity)
    report = stage / "reports" / "prompt_catalog_validation.json"
    steps.append(command_step(
        "prompt_content_integrity",
        [sys.executable, "tools/prompt_audit_contract.py", "--root", ".", "--output", str(report)],
        integrity, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    ))

    wrapper = temp / "read_only_audit_wrapper_workspace"; copy_release_tree(pristine, wrapper)
    steps.append(command_step(
        "read_only_audit_wrapper_evidence",
        [sys.executable, "-m", "pytest", "-q", "-s",
         "tests/test_v2_9_139_audit_prompts.py::test_read_only_wrapper_detects_file_mutation",
         "tests/test_v2_9_139_audit_prompts.py::test_read_only_wrapper_detects_branch_switch",
         "tests/test_v2_9_139_audit_prompts.py::test_read_only_wrapper_detects_index_mutation",
         "tests/test_v2_9_139_audit_prompts.py::test_read_only_wrapper_detects_ref_mutation",
         "tests/test_v2_9_139_audit_prompts.py::test_read_only_wrapper_detects_untracked_file_creation",
         "tests/test_v2_9_139_audit_prompts.py::test_read_only_wrapper_preserves_input_artifacts"],
        wrapper, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    ))

    adversarial = temp / "audit_prompt_adversarial_workspace"; copy_release_tree(pristine, adversarial)
    steps.append(command_step(
        "audit_prompt_adversarial_evidence",
        [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_139_audit_prompts.py"],
        adversarial, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    ))
    for workspace in (catalog, integrity, wrapper, adversarial): remove_release_workspace(workspace, temp)
    return steps


RULE_TRACEABILITY_PHASES = (
    "rule_inventory",
    "rule_registry_validation",
    "rule_global_uniqueness",
    "rule_semantic_continuity",
    "rule_implementation_linkage",
    "rule_diagnostic_linkage",
    "rule_behavioral_test_evidence",
    "rule_capability_linkage",
    "rule_traceability_receipt",
)


def run_rule_traceability_evidence(
    pristine: Path,
    temp: Path,
    stage: Path,
    replacements: dict[str, str],
    source_identity: Any,
    env: dict[str, str],
) -> list[dict[str, Any]]:
    registry = load_json(pristine / "reference/rule_traceability_registry.json")
    previous = registry.get("previous_release", {})
    previous_path = str(previous.get("registry_path", ""))
    previous_sha = str(previous.get("registry_sha256", ""))
    steps: list[dict[str, Any]] = []
    for phase in RULE_TRACEABILITY_PHASES:
        workspace = temp / f"{phase}_workspace"
        copy_release_tree(pristine, workspace)
        report_path = stage / "reports" / f"{phase}.json"
        command = [
            sys.executable,
            "tools/rule_traceability.py",
            "--root", ".",
            "--previous-registry", previous_path,
            "--previous-registry-sha256", previous_sha,
            "--release-mode",
            "--output", str(report_path),
        ]
        if phase in {"rule_behavioral_test_evidence", "rule_traceability_receipt"}:
            command.append("--execute-tests")
        if phase == "rule_inventory":
            command.extend(["--inventory-output", str(stage / "reports/rule_inventory.json")])
        steps.append(command_step(
            phase, command, workspace, stage, replacements, env=env,
            input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
        ))
        steps.append(workspace_integrity_step(
            f"{phase}_source_integrity", workspace, source_identity.records,
            source_identity.manifest_sha256, stage, replacements,
        )); remove_release_workspace(workspace, temp)
    return steps

def run_dead_code_evidence(pristine: Path, temp: Path, stage: Path, replacements: dict[str, str], source_identity: Any, env: dict[str, str]) -> list[dict[str, Any]]:
    workspace = temp / "dead_code_workspace"
    copy_release_tree(pristine, workspace)
    report = stage / "reports" / "dead_code_report.json"
    step = command_step(
        "dead_code_audit",
        [
            sys.executable, "tools/dead_code_audit.py",
            "--root", ".",
            "--profile", "standard-package",
            "--output", str(report),
            "--require-evidence-execution",
            "--evidence-junit", f"direct_tests={stage / 'reports/direct_tests.junit.xml'}",
            "--evidence-junit", f"tests={stage / 'reports/segmented_tests.junit.xml'}",
        ],
        workspace, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    )
    if report.is_file():
        step.setdefault("output_hashes", {})["dead_code_report_sha256"] = sha256_file(report)
    return [
        step,
        workspace_integrity_step(
            "dead_code_audit_source_integrity", workspace, source_identity.records,
            source_identity.manifest_sha256, stage, replacements,
        ),
    ]


def run_v129_evidence(root: Path, pristine: Path, temp: Path, stage: Path, replacements: dict[str, str], source_identity: Any) -> list[dict[str, Any]]:
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider"}
    steps = run_rule_traceability_evidence(pristine, temp, stage, replacements, source_identity, env)
    steps.extend(run_dead_code_evidence(pristine, temp, stage, replacements, source_identity, env))
    cap = temp / "capability_workspace"; copy_release_tree(pristine, cap); report = stage / "reports" / "capability_evidence.json"
    steps.append(command_step("capability_evidence", [sys.executable, "tools/run_capability_evidence.py", "--root", ".", "--output", str(report)], cap, stage, replacements, env=env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}, output_hashes={}))
    steps.append(workspace_integrity_step("capability_source_integrity", cap, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(cap, temp)
    agent = temp / "agent_gate_workspace"; copy_release_tree(pristine, agent)
    trusted_manifest_path = pristine / "reference/trusted_tools_manifest.json"
    trusted_manifest_raw = trusted_manifest_path.read_bytes()
    trusted_manifest = json.loads(trusted_manifest_raw)
    trusted_manifest_sha = __import__("hashlib").sha256(trusted_manifest_raw).hexdigest()
    trusted_env = {
        **env,
        "APS_TRUSTED_ATTESTATION_KEY": "release-evidence-" + source_identity.manifest_sha256,
        "APS_TRUSTED_ATTESTATION_KEY_ID": "release-evidence-key",
        "APS_TRUSTED_SIGNER_IDENTITY": "release-evidence-signer",
        "APS_TRUSTED_ORCHESTRATOR": "1",
        "APS_TRUSTED_TOOL_MANIFEST_SHA256": trusted_manifest_sha,
        "APS_TRUSTED_TOOL_MANIFEST_PUBLIC_KEYS_JSON": json.dumps({
            trusted_manifest["signing_key_id"]: {"public_key": trusted_manifest["signing_public_key"]}
        }, sort_keys=True),
        "APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST": source_identity.manifest_sha256,
    }
    steps.append(command_step("agent_gate_evidence", [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_129_regressions.py::test_valid_signed_db_attestation_passes_merge_gate"], agent, stage, replacements, env=trusted_env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("agent_gate_source_integrity", agent, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(agent, temp)
    post_merge_workspace = temp / "post_merge_workspace"; copy_release_tree(pristine, post_merge_workspace)
    steps.append(command_step("trusted_post_merge_evidence", [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_129_regressions.py::test_post_merge_trusted_transaction_marks_done_and_closes_lease"], post_merge_workspace, stage, replacements, env=trusted_env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("post_merge_source_integrity", post_merge_workspace, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(post_merge_workspace, temp)
    trust_workspace = temp / "trust_boundary_workspace"; copy_release_tree(pristine, trust_workspace)
    steps.append(command_step("trust_boundary_evidence", [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_130_regressions.py"], trust_workspace, stage, replacements, env=trusted_env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("trust_boundary_source_integrity", trust_workspace, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(trust_workspace, temp)
    v131_workspace = temp / "v131_adversarial_workspace"; copy_release_tree(pristine, v131_workspace)
    steps.append(command_step("v131_adversarial_evidence", [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_131_adversarial.py"], v131_workspace, stage, replacements, env=trusted_env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("v131_adversarial_source_integrity", v131_workspace, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(v131_workspace, temp)
    v132_workspace = temp / "v132_adversarial_workspace"; copy_release_tree(pristine, v132_workspace)
    steps.append(command_step("v132_adversarial_evidence", [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_132_adversarial.py"], v132_workspace, stage, replacements, env=trusted_env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("v132_adversarial_source_integrity", v132_workspace, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(v132_workspace, temp)
    v133_workspace = temp / "v133_automatic_merge_workspace"; copy_release_tree(pristine, v133_workspace)
    steps.append(command_step("v133_automatic_merge_evidence", [sys.executable, "-m", "pytest", "-q", "tests/test_v2_9_133_automatic_merge.py"], v133_workspace, stage, replacements, env=trusted_env, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}))
    steps.append(workspace_integrity_step("v133_automatic_merge_source_integrity", v133_workspace, source_identity.records, source_identity.manifest_sha256, stage, replacements)); remove_release_workspace(v133_workspace, temp)
    health_report = stage / "reports" / "project_health_audit.json"
    health_records = temp / "project_health_source_records.json"
    health_records.write_text(json.dumps(source_identity.records, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    steps.append(command_step(
        "project_health_audit",
        [sys.executable, "tools/project_health_release.py", "--source-repo", str(root),
         "--expected-commit", str(source_identity.commit_sha), "--expected-tree", str(source_identity.tree_sha),
         "--source-records", str(health_records), "--output", str(health_report)],
        root, stage, replacements, env=env,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
    ))
    return steps



def _run_pre_artifact_steps(root: Path, pristine: Path, temp: Path, stage: Path, replacements: dict[str, str], source_identity: Any, profile: dict[str, Any], *, skip_tests: bool) -> tuple[Path, list[dict[str, Any]], bool]:
    static_workspace, steps = run_source_static(root, pristine, temp, stage, replacements, source_identity, profile)
    certified_step = run_certified_linux_suite(
        pristine, stage, replacements, source_identity, skip=skip_tests,
        synthetic_step_fn=synthetic_step, release_skip_finding=RELEASE_SKIP_FINDING,
        require_external=requires_independent(profile),
    )
    steps.append(certified_step)
    blocked, finding, missing_trust = release_block_state(
        certified_step, skip_tests=skip_tests, release_skip_finding=RELEASE_SKIP_FINDING,
        require_external=requires_independent(profile),
    )
    steps.extend(run_tests(pristine, temp, stage, replacements, source_identity, blocked, skip_finding=finding))
    if not blocked:
        steps.extend(run_prompt_audit_evidence(pristine, temp, stage, replacements, source_identity))
        steps.extend(run_v129_evidence(root, pristine, temp, stage, replacements, source_identity))
        steps.append(run_source_identity_bundle(root, stage, replacements, source_identity))
        return static_workspace, steps, blocked
    skip_ids = [
        "prompt_catalog_validation", "prompt_content_integrity", "read_only_audit_wrapper_evidence", "audit_prompt_adversarial_evidence",
        *tuple(item for phase in RULE_TRACEABILITY_PHASES for item in (phase, f"{phase}_source_integrity")),
        "capability_evidence", "capability_source_integrity", "agent_gate_evidence", "agent_gate_source_integrity",
        "trusted_post_merge_evidence", "post_merge_source_integrity", "trust_boundary_evidence", "trust_boundary_source_integrity",
        "v131_adversarial_evidence", "v131_adversarial_source_integrity", "v132_adversarial_evidence", "v132_adversarial_source_integrity",
        "v133_automatic_merge_evidence", "v133_automatic_merge_source_integrity", "dead_code_audit", "dead_code_audit_source_integrity",
        "project_health_audit", "formal_external_trust_anchor",
    ]
    steps.extend(synthesize_blocked_release_steps(
        skip_ids, pristine, stage, replacements, skip_tests=skip_tests, blocked_finding=finding,
        missing_formal_trust=missing_trust, synthetic_step_fn=synthetic_step,
    ))
    message = f"{RELEASE_SKIP_FINDING}:{RELEASE_SKIP_RULE_ID}" if skip_tests else "FORMAL_EXTERNAL_CONTROL_EVIDENCE_NOT_PROVIDED"
    print(message, file=sys.stderr)
    steps.append(run_source_identity_bundle(root, stage, replacements, source_identity))
    return static_workspace, steps, blocked

def empty_repro() -> dict[str, Any]:
    return {"same_tree_rebuild": False, "fresh_snapshot_rebuild": False, "cross_extraction_rebuild": False, "all_passed": False, "hashes": {"artifact": None, "same_tree": None, "fresh_snapshot": None, "cross_extraction": None}}


def rebuild_step(step_id: str, source: Path, target: Path, original: Path, stage: Path, replacements: dict[str, str], code: str) -> tuple[dict[str, Any], bool, str | None]:
    step = command_step(step_id, [sys.executable, "tools/build_release_zip.py", "--root", ".", "--output", str(target)], source, stage, replacements)
    original_hash = sha256_file(original) if original.exists() else None; target_hash = sha256_file(target) if target.exists() else None; matched = step["status"] == "PASS" and original_hash == target_hash
    if not matched:
        step.update({"status": "FAIL", "exit_code": 1, "findings": [code], "output_hashes": {"original_sha256": original_hash or "missing", "rebuilt_sha256": target_hash or "missing"}})
    else: step["output_hashes"] = {"rebuilt_sha256": target_hash or "missing"}
    return step, matched, target_hash


def run_artifact(pristine: Path, static_workspace: Path, temp: Path, stage: Path, replacements: dict[str, str], output: Path, source_identity: Any, prior_steps: list[dict[str, Any]], allowed: bool, require_external: bool = True) -> tuple[list[dict[str, Any]], bool, dict[str, Any]]:
    repro = empty_repro()
    if not allowed or not _all_pass(prior_steps, artifact_prerequisites(require_external, RULE_TRACEABILITY_PHASES)):
        return [synthetic_step(step, pristine, stage, replacements, passed=False, findings=["BUILD_PREREQUISITES_NOT_SATISFIED"], skipped=True) for step in BUILD_STEP_IDS], False, repro
    steps=[command_step("build", [sys.executable, "tools/build_release_zip.py", "--root", ".", "--output", str(output)], pristine, stage, replacements, input_hashes={"source_manifest_sha256": source_identity.manifest_sha256})]
    artifact_hash=sha256_file(output) if output.exists() else None; repro["hashes"]["artifact"]=artifact_hash
    steps.append(command_step("artifact", [sys.executable, "tools/validate_structure.py", "--root", ".", "--profile", "standard-package", "--artifact", str(output)], static_workspace, stage, replacements, input_hashes={"artifact_sha256": artifact_hash or "missing"}))
    findings=verify_artifact_matches_source(source_identity.records, output) if output.exists() else ["ARTIFACT_MISSING"]
    matches=not findings; steps.append(synthetic_step("artifact_source_integrity", pristine, stage, replacements, passed=matches, findings=["ARTIFACT_SOURCE_MANIFEST_MISMATCH", *findings] if findings else [], input_hashes={"source_manifest_sha256": source_identity.manifest_sha256}, output_hashes={"artifact_sha256": artifact_hash or "missing"}))
    rebuilds=(("same_tree_rebuild",pristine,temp/"same_tree.zip","REPRODUCIBILITY_SAME_TREE_MISMATCH"),("fresh_snapshot_rebuild",temp/"fresh_snapshot",temp/"fresh_snapshot.zip","REPRODUCIBILITY_FRESH_SNAPSHOT_MISMATCH"),("cross_extraction_rebuild",temp/"python_extractall",temp/"cross_extraction.zip","REPRODUCIBILITY_CROSS_EXTRACTION_MISMATCH"))
    copy_release_tree(pristine,rebuilds[1][1]);perturb_metadata(rebuilds[1][1]);extract_python(output,rebuilds[2][1]);perturb_metadata(rebuilds[2][1])
    for (step_id,source,target,code),key in zip(rebuilds,("same_tree","fresh_snapshot","cross_extraction"),strict=True):
        step,matched,target_hash=rebuild_step(step_id,source,target,output,stage,replacements,code);steps.append(step);repro[step_id]=matched;repro["hashes"][key]=target_hash
    repro["all_passed"]=all(repro[item[0]] for item in rebuilds)
    return steps,matches,repro


def compose(
    root: Path,
    output: Path,
    manifest: dict[str, Any],
    profile_name: str,
    profile: dict[str, Any],
    source_identity: Any,
    source_unchanged: bool,
    steps: list[dict[str, Any]],
    artifact_matches: bool,
    repro: dict[str, Any],
    status: str,
    evidence: dict[str, Any] | None,
    rule_traceability_counts: dict[str, int],
    prompt_metrics: dict[str, int],
) -> dict[str, Any]:
    mandatory = list(profile["mandatory_steps"])
    observed = [step["id"] for step in steps]
    return {
        "receipt_schema_version": RECEIPT_SCHEMA_VERSION,
        "standard_version": manifest["version"],
        "profile": profile_name,
        "status": status,
        "created_at": utc_now(),
        "environment": {
            "python": sys.version.split()[0],
            "platform": platform.platform(),
            "python_executable": "${PYTHON}",
            "pytest_plugin_autoload": "disabled",
            "working_directory": "${SOURCE_ROOT}",
        },
        "source": {
            "git_repository": source_identity.git_repository,
            "git_clean": source_identity.git_clean,
            "commit_sha": source_identity.commit_sha,
            "tree_sha": source_identity.tree_sha,
            "manifest_sha256": source_identity.manifest_sha256,
            "file_count": len(source_identity.records),
            "snapshot_method": "git_tree_plus_canonical_copy" if source_identity.git_repository else "canonical_copy",
            "source_unchanged": source_unchanged,
            "records": source_identity.records,
        },
        "steps": steps,
        "not_applicable_gates": [
            {"gate": "--check-active-task-diff", "reason": "standard-package release has no active implementation task"},
            {"gate": "--check-lease-expiry", "reason": "release health audit checks external leases when configured"},
        ],
        "artifact": {
            "path": output.name if output.exists() else None,
            "published": status in ("PASS", "SELF_ATTESTED") and output.exists(),
            "sha256": sha256_file(output) if output.exists() else None,
            "source_manifest_matches": artifact_matches,
            "file_count": len(artifact_records(output)) if output.exists() else 0,
        },
        "reproducibility": repro,
        "evidence_bundle": evidence,
        "rule_traceability": rule_traceability_counts,
        "prompt_catalog": prompt_metrics,
        "policy": {
            "mandatory_steps": mandatory,
            "observed_steps": observed,
            "missing_steps": sorted(set(mandatory) - set(observed)),
            "allowed_skips": profile["allowed_skips"],
            "external_controls": profile["external_controls"],
        },
    }



def main() -> int:
    args=parse_args();root=Path(args.root).resolve();output=Path(args.output).resolve();receipt=Path(args.receipt).resolve();evidence=Path(args.evidence_bundle).resolve() if args.evidence_bundle else receipt.with_name(receipt.stem.replace("RELEASE_RECEIPT","RELEASE_EVIDENCE")+".zip")
    profiles=load_json(root/"reference/release_profiles.json");profile=profiles.get("profiles",{}).get(args.profile)
    if not isinstance(profile,dict): print(f"EXECUTION_PROFILE_UNKNOWN:{args.profile}",file=sys.stderr);return 2
    if profile.get("entrypoint")!="tools/release_gate.py": print(f"EXECUTION_PROFILE_ENTRYPOINT_MISMATCH:{args.profile}:{profile.get('entrypoint')}",file=sys.stderr);return 2
    skip_policy_findings = validate_skip_tests_policy(args.skip_tests, [output, receipt, evidence])
    for finding in skip_policy_findings:
        if finding.code in {RELEASE_SKIP_FINDING, "RELEASE_SKIP_PREEXISTING_ARTIFACT_REMOVED"}:
            print(f"{finding.code}:{finding.rule_id}", file=sys.stderr)
    manifest=load_json(root/"manifest.json");schema=load_json(root/"schemas/release_receipt.schema.json");profiles_schema=load_json(root/"schemas/release_profiles.schema.json");source_identity=identify_release_source(root)
    with tempfile.TemporaryDirectory(prefix="aps_release_gate_") as raw:
        temp=Path(raw);stage=temp/"evidence";stage.mkdir();pristine=temp/"pristine_source"
        replacements={str(root):"${SOURCE_ROOT}",str(temp):"${RELEASE_TEMP}",str(output):"${ARTIFACT}",str(receipt):"${RECEIPT}",str(evidence):"${EVIDENCE_BUNDLE}"}
        static_workspace, steps, release_execution_blocked = _run_pre_artifact_steps(
            root, pristine, temp, stage, replacements, source_identity, profile,
            skip_tests=args.skip_tests,
        )
        source_bundle_path=stage/"source/source_repository.bundle";source_bundle_payload=source_bundle_path.read_bytes() if source_bundle_path.is_file() else None;source_bundle_path.unlink(missing_ok=True)
        artifact_steps,artifact_matches,repro=run_artifact(pristine,static_workspace,temp,stage,replacements,output,source_identity,steps,profile["artifact_allowed"],requires_independent(profile));steps.extend(artifact_steps)
        if not release_execution_blocked:
            steps.append(run_formal_external_trust_anchor(
                pristine, stage, replacements, output,
                synthetic_step_fn=synthetic_step,
            ))
        prompt_report_path = stage / "reports/prompt_catalog_validation.json"
        prompt_metrics = load_json(prompt_report_path).get("metrics", {}) if prompt_report_path.is_file() else prompt_catalog_metrics(pristine)
        prune_release_temp(temp, stage)
        source_unchanged=committed_source_unchanged(root,source_identity) and all(s["status"]=="PASS" for s in steps if s["id"].endswith("_source_integrity") and s["id"]!="artifact_source_integrity")
        pre_required=[s for s in profile["mandatory_steps"] if s not in {"evidence_bundle","receipt_validation"}]
        core_ok=_all_pass(steps,pre_required) and source_unchanged and (not profile["artifact_allowed"] or (artifact_matches and repro["all_passed"])) and not args.skip_tests
        evidence_step=synthetic_step("evidence_bundle",root,stage,replacements,passed=core_ok,findings=[] if core_ok else ["EVIDENCE_PREREQUISITES_NOT_SATISFIED"],stdout_text="Portable evidence bundle is content-addressed and excludes the receipt to avoid recursive hashing.\n");steps.append(evidence_step)
        validation_step=synthetic_step("receipt_validation",root,stage,replacements,passed=core_ok,findings=[] if core_ok else ["RECEIPT_PREREQUISITES_NOT_SATISFIED"],stdout_text="Receipt schema and policy validation is recomputed before publication.\n");steps.append(validation_step)
        (stage/"source_records.json").write_text(json.dumps(source_identity.records,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
        actual_artifact_records = artifact_records(output) if output.exists() else []
        if output.exists(): (stage/"artifact_records.json").write_text(json.dumps(actual_artifact_records,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
        (stage/"profile.json").write_text(json.dumps(profile,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
        test_bindings = {}
        for step_id in ("direct_tests", "tests", "golden"):
            step = next((item for item in steps if item.get("id") == step_id), {})
            test_bindings[step_id] = {
                "junit_xml": step.get("junit_xml"),
                "junit_xml_sha256": step.get("output_hashes", {}).get("junit_xml_sha256"),
                "junit_node_ids_sha256": step.get("output_hashes", {}).get("junit_node_ids_sha256"),
                "summary": step.get("test_summary"),
            }
        release_identity = {
            "schema_version": "1.0.0",
            "standard_version": manifest["version"],
            "source": {
                "commit_sha": source_identity.commit_sha,
                "tree_sha": source_identity.tree_sha,
                "manifest_sha256": source_identity.manifest_sha256,
                "file_count": len(source_identity.records),
                "package_root_relative": git_package_root_relative(root) if source_identity.git_repository else ".",
                "git_bundle": "source/source_repository.bundle",
                "git_bundle_sha256": next((item.get("output_hashes", {}).get("source_git_bundle_sha256") for item in steps if item.get("id") == "source_identity_bundle"), None),
            },
            "artifact": {
                "sha256": sha256_file(output) if output.exists() else None,
                "file_count": len(actual_artifact_records),
            },
            "tests": test_bindings,
        }
        identity_path = stage / "release_identity.json"
        identity_path.write_text(json.dumps(release_identity,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
        evidence_data=build_bundle(stage,evidence,release_identity,extra_files={"source/source_repository.bundle":source_bundle_payload} if source_bundle_payload is not None else {});del source_bundle_payload;evidence_data["path"]=evidence.name
        evidence_step["output_hashes"]={"evidence_bundle_sha256":evidence_data["sha256"],"evidence_manifest_sha256":evidence_data["manifest_sha256"]}
        status = final_receipt_status(
            core_ok=core_ok,
            steps=steps,
            mandatory_steps=profile["mandatory_steps"],
            skip_tests=args.skip_tests,
            profile_name=args.profile,
            independent_verification=requires_independent(profile),
        )
        rule_report_path = stage / "reports/rule_traceability_receipt.json"
        rule_counts = load_json(rule_report_path).get("counts", {}) if rule_report_path.is_file() else {
            "total_human_rule_blocks": 0, "total_registry_rules": 0, "implemented_rules": 0,
            "partially_implemented_rules": 0, "documented_rules": 0, "deprecated_rules": 0,
            "superseded_rules": 0, "external_control_required_rules": 0,
            "rules_with_passing_tests": 0, "rules_with_positive_tests": 0,
            "rules_with_negative_tests": 0, "rules_with_bypass_tests": 0,
            "rules_without_tests": 0, "behavioral_tests_required_rules": 0,
            "implemented_rules_with_complete_test_triad": 0, "untested_implemented_rules": 0,
            "rules_without_tests_by_design": 0, "nonimplemented_rules_with_tests": 0,
            "unregistered_human_rules": 0, "orphan_registry_rules": 0, "duplicate_rule_ids": 0,
            "unknown_implementation_symbols": 0, "missing_structured_diagnostics": 0,
            "semantic_drift_findings": 0, "removed_published_rules": 0, "reused_rule_ids": 0,
        }
        data=compose(root,output,manifest,args.profile,profile,source_identity,source_unchanged,steps,artifact_matches,repro,status,evidence_data,rule_counts,prompt_metrics)
        data["identity_binding"] = {"path": "release_identity.json", "sha256": sha256_file(identity_path), "source_git_bundle_sha256": release_identity["source"]["git_bundle_sha256"], "verified": core_ok}
        findings=validate_receipt(data,schema,profiles,profiles_schema)
        if not findings and core_ok:
            findings.extend(verify_exported_evidence(data, artifact=output, evidence_bundle=evidence, source_root=root))
        if findings:
            data["status"]="FAIL";validation_step.update({"status":"FAIL","exit_code":1,"findings":sorted(set(findings))});data["artifact"]["published"]=False
        data["policy"]["observed_steps"]=[s["id"] for s in steps];data["policy"]["missing_steps"]=sorted(set(profile["mandatory_steps"])-set(data["policy"]["observed_steps"]))
        final_findings=validate_receipt(data,schema,profiles,profiles_schema)
        if final_findings:
            data["status"]="FAIL";validation_step.update({"status":"FAIL","exit_code":1,"findings":sorted(set(validation_step.get("findings",[])+final_findings))});data["artifact"]["published"]=False
        if data["status"] not in ("PASS","SELF_ATTESTED") and output.exists(): output.unlink();data["artifact"].update({"published":False,"path":None})
        receipt.parent.mkdir(parents=True,exist_ok=True);receipt.write_text(json.dumps(data,ensure_ascii=False,indent=2,sort_keys=True)+"\n")
    return 0 if data["status"] in {"PASS","SELF_ATTESTED"} else (2 if data["status"] in {"INCOMPLETE","DIAGNOSTIC_ONLY"} else 1)

if __name__=="__main__":raise SystemExit(main())
