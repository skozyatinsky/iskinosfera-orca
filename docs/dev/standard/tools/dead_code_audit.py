#!/usr/bin/env python3
# ======================================================================
# dead_code_audit.py — версия 1.0
# Production validator: dead code, unreachable statements and reachability.
# ======================================================================
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import tempfile
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))

from dead_code_ast import SKIP_PARTS, build_module_index, detect_commented_code, detect_unreachable_statements, detect_unused_imports, is_excluded, iter_python_files
from dead_code_reachability import classify_reachability, detect_unknown_dynamic_references
from dead_code_evidence import (
    evidence_test_nodes,
    validate_evidence_binding_registry,
    validate_evidence_test_execution,
)
from dead_code_registry import apply_allowlist, load_json_if_exists, resolve_registry_paths, validate_allowlist, validate_entrypoints, validate_public_api_contracts, validate_public_api_targets, load_scan_scope_checked
from dead_code_report import build_report
from dead_code_report_validation import validate_dead_code_report
from dead_code_types import Finding, stable_finding_id
from rule_traceability_types import emits_diagnostic, enforces_rule


@enforces_rule("APS-DEAD-CODE-STRUCTURED-DIAGNOSTIC-001")
@enforces_rule("APS-DEAD-CODE-REPORT-SCHEMA-001")
@emits_diagnostic("APS-DEAD-CODE-STRUCTURED-DIAGNOSTIC-001", "APS_DEAD_CODE_REPORT_VALID")
@emits_diagnostic("APS-DEAD-CODE-STRUCTURED-DIAGNOSTIC-001", "APS_DEAD_CODE_REPORT_INVALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_VALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_INVALID")
def validate_report_shape(report: dict[str, Any]) -> list[str]:
    """Backward-compatible entrypoint for full executable report validation."""
    return validate_dead_code_report(report)


@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@enforces_rule("APS-DEAD-CODE-REPORT-SCHEMA-001")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_VALID")
@emits_diagnostic("APS-DEAD-CODE-REPORT-SCHEMA-001", "APS_DEAD_CODE_REPORT_SCHEMA_INVALID")
@enforces_rule("APS-DEAD-CODE-UNREACHABLE-STATEMENT-001")
@emits_diagnostic("APS-DEAD-CODE-UNREACHABLE-STATEMENT-001", "APS_DEAD_CODE_UNREACHABLE_SCAN_PASS")
@emits_diagnostic("APS-DEAD-CODE-UNREACHABLE-STATEMENT-001", "APS_DEAD_CODE_UNREACHABLE_STATEMENT")
@enforces_rule("APS-DEAD-CODE-DETECTION-001")
@enforces_rule("APS-DEAD-CODE-PRODUCTION-REACHABILITY-001")
@enforces_rule("APS-DEAD-CODE-PUBLIC-API-CONTRACT-001")
@enforces_rule("APS-DEAD-CODE-TEST-ONLY-REACHABILITY-001")
@enforces_rule("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001")
@enforces_rule("APS-DEAD-CODE-ALLOWLIST-001")
@enforces_rule("APS-DEAD-CODE-ALLOWLIST-EXPIRY-001")
@enforces_rule("APS-DEAD-CODE-NO-AUTOMATIC-DELETION-001")
@enforces_rule("APS-DEAD-CODE-RELEASE-GATE-001")
@emits_diagnostic("APS-DEAD-CODE-DETECTION-001", "APS_DEAD_CODE_UNUSED_IMPORT")
@emits_diagnostic("APS-DEAD-CODE-PRODUCTION-REACHABILITY-001", "APS_DEAD_CODE_PRODUCTION_UNREACHABLE")
@emits_diagnostic("APS-DEAD-CODE-PUBLIC-API-CONTRACT-001", "APS_DEAD_CODE_PUBLIC_API_CONTRACT_VALID")
@emits_diagnostic("APS-DEAD-CODE-PUBLIC-API-CONTRACT-001", "APS_DEAD_CODE_PUBLIC_API_CONTRACT_INVALID")
@emits_diagnostic("APS-DEAD-CODE-TEST-ONLY-REACHABILITY-001", "APS_DEAD_CODE_TEST_ONLY_REACHABLE")
@emits_diagnostic("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001", "APS_DEAD_CODE_UNKNOWN_DYNAMIC_ENTRYPOINT")
@emits_diagnostic("APS-DEAD-CODE-ALLOWLIST-001", "APS_DEAD_CODE_ALLOWLIST_INVALID")
@emits_diagnostic("APS-DEAD-CODE-ALLOWLIST-EXPIRY-001", "APS_DEAD_CODE_ALLOWLIST_EXPIRED")
@emits_diagnostic("APS-DEAD-CODE-NO-AUTOMATIC-DELETION-001", "APS_DEAD_CODE_READ_ONLY")
@emits_diagnostic("APS-DEAD-CODE-RELEASE-GATE-001", "APS_DEAD_CODE_RELEASE_GATE_PASS")
@emits_diagnostic("APS-DEAD-CODE-RELEASE-GATE-001", "APS_DEAD_CODE_RELEASE_BLOCKED")
def audit_project(
    root: Path,
    profile: str = "standard-package",
    *,
    evidence_junit_paths: dict[str, Path] | None = None,
    require_evidence_execution: bool = False,
) -> dict[str, Any]:
    root = root.resolve()
    manifest = load_json_if_exists(root / "manifest.json", {"version": "0.0.0"})
    entry_path, allow_path, api_path = resolve_registry_paths(root)
    entry_data = load_json_if_exists(entry_path, {"schema_version": "1.0.0", "entrypoints": []})
    allow_data = load_json_if_exists(allow_path, {"schema_version": "1.0.0", "entries": []})
    api_data = load_json_if_exists(api_path, {"schema_version": "1.0.0", "apis": []})
    binding_registry_path = root / "reference/dead_code_evidence_bindings.json"
    binding_problems = validate_evidence_binding_registry(root) if binding_registry_path.is_file() else []
    findings = [
        Finding(
            stable_finding_id("APS-DC-EVID-REG", "reference/dead_code_evidence_bindings.json", problem),
            "APS-DEAD-CODE-EVIDENCE-BINDING-001",
            "APS_DEAD_CODE_EVIDENCE_INVALID",
            "ERROR",
            "invalid_evidence",
            "HIGH",
            "reference/dead_code_evidence_bindings.json",
            0,
            "<registry>",
            "evidence_registry",
            False,
            False,
            [],
            {"problem": problem},
            problem,
            "Repair the typed evidence registry and its exact subject bindings.",
        )
        for index, problem in enumerate(binding_problems, 1)
    ]
    entrypoints, entry_findings = validate_entrypoints(root, entry_data)
    findings.extend(entry_findings)
    public_apis, api_findings = validate_public_api_contracts(root, api_data)
    findings.extend(api_findings)
    allowlist, allow_findings = validate_allowlist(root, allow_data, str(manifest.get("version", "0.0.0")))
    findings.extend(allow_findings)

    required_test_nodes: set[str] = set()
    for payload, key in ((entry_data, "entrypoints"), (api_data, "apis"), (allow_data, "entries")):
        for record in payload.get(key, []):
            if isinstance(record, dict):
                required_test_nodes.update(evidence_test_nodes(record.get("evidence")))
    execution_problems: list[str] = []
    if evidence_junit_paths is not None:
        execution_problems = validate_evidence_test_execution(required_test_nodes, evidence_junit_paths)
    elif require_evidence_execution:
        execution_problems = ["Formal evidence execution proof was required but no JUnit suites were supplied."]
    findings.extend(
        Finding(
            stable_finding_id("APS-DC-EVID-EXEC", "<junit>", problem),
            "APS-DEAD-CODE-EVIDENCE-BINDING-001",
            "APS_DEAD_CODE_EVIDENCE_INVALID",
            "ERROR",
            "invalid_evidence",
            "HIGH",
            "<junit>",
            0,
            "<behavioral-evidence>",
            "evidence_execution",
            False,
            False,
            [],
            {"problem": problem},
            problem,
            "Supply canonical passing direct and segmented JUnit for all exact evidence nodes.",
        )
        for index, problem in enumerate(execution_problems, 1)
    )

    scan_exclusions, scan_scope_findings = load_scan_scope_checked(root)
    findings.extend(scan_scope_findings)
    excluded_prefixes = [str(item.get("path", "")) for item in scan_exclusions]
    files_excluded = sum(1 for p in root.rglob("*.py")
                         if not any(part in SKIP_PARTS for part in p.relative_to(root).parts)
                         and excluded_prefixes and is_excluded(p.relative_to(root), excluded_prefixes))

    modules = {}
    parse_failures: list[Finding] = []
    for path in iter_python_files(root, excluded_prefixes):
        rel_parts = path.relative_to(root).parts
        if profile == "standard-package" and len(rel_parts) >= 2 and rel_parts[:2] == ("examples", "reference_python_project"):
            continue
        try:
            index = build_module_index(root, path); modules[index.path] = index
        except (SyntaxError, UnicodeDecodeError) as exc:
            rel = path.relative_to(root).as_posix()
            parse_failures.append(Finding(
                stable_finding_id("APS-DC-PARSE", rel, "parse_failure"), "APS-DEAD-CODE-DETECTION-001",
                "APS_DEAD_CODE_PARSE_FAILED", "ERROR", "parse_failure", "HIGH", rel,
                int(getattr(exc, "lineno", 0) or 0), "<module>", "module", False, False, [],
                {"error": str(exc)}, "Python source could not be parsed.", "Fix parsing before release.",
            ))
    findings.extend(parse_failures)
    public_apis, api_target_findings = validate_public_api_targets(public_apis, modules)
    findings.extend(api_target_findings)
    from dead_code_reachability import externally_reexported_names
    reexports = externally_reexported_names(modules)
    for module in modules.values():
        findings.extend(detect_unreachable_statements(module))
        findings.extend(detect_unused_imports(module, reexports.get(module.path, set())))
        findings.extend(detect_commented_code(root, module))
    production, _, reach_findings = classify_reachability(modules, entrypoints, public_apis, profile); findings.extend(reach_findings)
    findings.extend(detect_unknown_dynamic_references(modules, entrypoints, production))
    apply_allowlist(findings, allowlist)
    report = build_report(
        root=root, profile=profile, production_entrypoints=entrypoints, public_api_contracts=public_apis,
        files_scanned=len(modules), symbols_scanned=sum(len(m.symbols) for m in modules.values()), findings=findings,
        scan_exclusions=scan_exclusions, files_excluded=files_excluded,
    )
    shape = validate_report_shape(report)
    if shape:
        report["status"] = "FAIL"
        report.setdefault("diagnostics", []).extend(shape)
    return report


# ======================================================================
# ПРОИСХОЖДЕНИЕ НАХОДКИ — APS-DEAD-CODE-ORIGIN-001
# ======================================================================

@enforces_rule("APS-DEAD-CODE-ORIGIN-001")
@emits_diagnostic("APS-DEAD-CODE-ORIGIN-001", "APS_DEAD_CODE_ORIGIN_CLASSIFIED")
@emits_diagnostic("APS-DEAD-CODE-ORIGIN-001", "APS_DEAD_CODE_BASELINE_UNAVAILABLE")
def classify_origin(report: dict[str, Any], root: Path, baseline_ref: str | None) -> dict[str, Any]:
    """Размечает находки: появилась с этой правкой или была раньше.

    Отказ в безопасную сторону. Нет объявленной базовой ревизии, репозиторий не
    git, ссылка не разрешается — всё остаётся `pre_existing`. Обратное правило
    («не с чем сравнить, значит новое») повесило бы весь накопленный долг на
    того, кто первым запустил проверку.
    """
    findings = report.get("findings", [])
    if not baseline_ref:
        report["baseline"] = {"ref": None, "resolved_sha": None, "status": "NOT_DECLARED",
                              "reason": "No baseline was declared; every finding is pre_existing."}
        return report
    worktree = Path(tempfile.mkdtemp(prefix="aps-dc-baseline-"))
    try:
        sha = subprocess.run(["git", "-C", str(root), "rev-parse", f"{baseline_ref}^{{commit}}"],
                             capture_output=True, text=True, timeout=60)
        if sha.returncode != 0:
            raise RuntimeError(sha.stderr.strip() or f"cannot resolve {baseline_ref}")
        resolved = sha.stdout.strip()
        added = subprocess.run(["git", "-C", str(root), "worktree", "add", "--detach",
                                str(worktree), resolved],
                               capture_output=True, text=True, timeout=300)
        if added.returncode != 0:
            raise RuntimeError(added.stderr.strip() or "cannot create baseline worktree")
        before = audit_project(worktree, report.get("profile", "standard-package"))
        known = {item.get("finding_id") for item in before.get("findings", [])}
        for item in findings:
            item["origin"] = "pre_existing" if item.get("finding_id") in known else "introduced"
        report["baseline"] = {"ref": baseline_ref, "resolved_sha": resolved, "status": "APPLIED",
                              "reason": f"{len(known)} findings at baseline."}
    except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
        report["baseline"] = {"ref": baseline_ref, "resolved_sha": None, "status": "UNAVAILABLE",
                              "reason": str(exc)}
        report.setdefault("diagnostics", []).append(
            f"APS_DEAD_CODE_BASELINE_UNAVAILABLE:{baseline_ref}:"
            "baseline unavailable; every finding stays pre_existing"
        )
    finally:
        subprocess.run(["git", "-C", str(root), "worktree", "remove", "--force", str(worktree)],
                       capture_output=True, text=True, timeout=120)
        shutil.rmtree(worktree, ignore_errors=True)
    report["summary"]["introduced_findings"] = sum(1 for i in findings if i.get("origin") == "introduced")
    report["summary"]["pre_existing_findings"] = sum(1 for i in findings if i.get("origin") != "introduced")
    return report


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Dead-code and production reachability audit")
    parser.add_argument("--root", default=".")
    parser.add_argument("--profile", default="standard-package")
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--evidence-junit",
        action="append",
        default=[],
        metavar="SUITE=PATH",
        help="bind formal behavioral evidence to an already executed canonical JUnit suite",
    )
    parser.add_argument("--require-evidence-execution", action="store_true")
    parser.add_argument(
        "--baseline",
        default=None,
        metavar="GIT_REF",
        help="classify each finding as introduced by the change or pre-existing at this revision",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    junit_paths: dict[str, Path] = {}
    for raw in args.evidence_junit:
        if "=" not in raw:
            print(f"INVALID_EVIDENCE_JUNIT_ARGUMENT:{raw}", file=sys.stderr)
            return 2
        suite_id, raw_path = raw.split("=", 1)
        if not suite_id or not raw_path or suite_id in junit_paths:
            print(f"INVALID_EVIDENCE_JUNIT_ARGUMENT:{raw}", file=sys.stderr)
            return 2
        junit_paths[suite_id] = Path(raw_path).resolve()
    report = audit_project(
        Path(args.root),
        args.profile,
        evidence_junit_paths=junit_paths or None,
        require_evidence_execution=args.require_evidence_execution,
    )
    report = classify_origin(report, Path(args.root).resolve(), args.baseline)
    output = Path(args.output); output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "summary": report["summary"]}, ensure_ascii=False, sort_keys=True))
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
