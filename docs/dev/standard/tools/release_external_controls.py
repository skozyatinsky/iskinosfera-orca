#!/usr/bin/env python3
# ======================================================================
# release_external_controls.py — версия 1.0
# External-control orchestration for the formal release graph.
# ======================================================================
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

from rule_traceability_types import emits_diagnostic, enforces_rule

from certified_linux_suite import CertifiedLinuxSuiteError, verify_certified_linux_suite
from formal_trust_anchor import FormalTrustAnchorError, verify_formal_trust_anchor

StepFactory = Callable[..., dict[str, Any]]


CERTIFIED_LINUX_REQUIRED_ENVIRONMENT = (
    "APS_CERTIFIED_LINUX_SUITE_ATTESTATION",
    "APS_CERTIFIED_LINUX_SUITE_ATTESTATION_SHA256",
    "APS_CERTIFIED_LINUX_SUITE_PUBLIC_KEYS_JSON",
    "APS_CERTIFIED_LINUX_DIRECT_JUNIT",
    "APS_CERTIFIED_LINUX_SEGMENTED_JUNIT",
)

FORMAL_TRUST_REQUIRED_ENVIRONMENT = (
    "APS_TRUSTED_TOOL_MANIFEST_SHA256",
    "APS_TRUSTED_TOOL_MANIFEST_PUBLIC_KEYS_JSON",
)


def missing_environment(names: tuple[str, ...]) -> list[str]:
    return sorted(name for name in names if not os.environ.get(name, "").strip())


def certified_linux_evidence_not_provided(step: dict[str, Any]) -> bool:
    return "CERTIFIED_LINUX_SUITE_EVIDENCE_NOT_PROVIDED" in step.get("findings", [])


def formal_trust_evidence_not_provided() -> list[str]:
    return missing_environment(FORMAL_TRUST_REQUIRED_ENVIRONMENT)


def release_block_state(
    certified_step: dict[str, Any],
    *,
    skip_tests: bool,
    release_skip_finding: str,
    require_external: bool = True,
) -> tuple[bool, str, list[str]]:
    if not require_external:
        return skip_tests, release_skip_finding, []
    missing_formal_trust = formal_trust_evidence_not_provided() if not skip_tests else []
    external_missing = (
        not skip_tests
        and (certified_linux_evidence_not_provided(certified_step) or bool(missing_formal_trust))
    )
    blocked = skip_tests or external_missing
    finding = release_skip_finding if skip_tests else "FORMAL_EXTERNAL_CONTROL_EVIDENCE_NOT_PROVIDED"
    return blocked, finding, missing_formal_trust


def synthesize_blocked_release_steps(
    step_ids: list[str],
    pristine: Path,
    stage: Path,
    replacements: dict[str, str],
    *,
    skip_tests: bool,
    blocked_finding: str,
    missing_formal_trust: list[str],
    synthetic_step_fn: StepFactory,
) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    for step_id in step_ids:
        findings = [blocked_finding]
        if step_id == "formal_external_trust_anchor" and missing_formal_trust and not skip_tests:
            findings = [
                "FORMAL_EXTERNAL_TRUST_EVIDENCE_NOT_PROVIDED",
                *[f"MISSING_ENV:{name}" for name in missing_formal_trust],
            ]
        steps.append(synthetic_step_fn(
            step_id, pristine, stage, replacements, passed=False, findings=findings, skipped=True,
        ))
    return steps


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_certified_linux_suite(
    pristine: Path,
    stage: Path,
    replacements: dict[str, str],
    source_identity: Any,
    *,
    skip: bool,
    synthetic_step_fn: StepFactory,
    release_skip_finding: str,
    require_external: bool = True,
) -> dict[str, Any]:
    if not require_external:
        # Профиль без независимой проверки не притворяется, что она была:
        # шаг объявляется неприменимым по имени профиля, а не тихо пропускается.
        return synthetic_step_fn(
            "certified_linux_suite", pristine, stage, replacements,
            passed=False, findings=["CERTIFIED_LINUX_NOT_REQUIRED_BY_PROFILE"], skipped=True,
        )
    if skip:
        return synthetic_step_fn(
            "certified_linux_suite", pristine, stage, replacements,
            passed=False, findings=[release_skip_finding], skipped=True,
        )
    missing_external = missing_environment(CERTIFIED_LINUX_REQUIRED_ENVIRONMENT)
    if missing_external:
        return synthetic_step_fn(
            "certified_linux_suite", pristine, stage, replacements,
            passed=False,
            findings=["CERTIFIED_LINUX_SUITE_EVIDENCE_NOT_PROVIDED", *[f"MISSING_ENV:{name}" for name in missing_external]],
            skipped=True,
        )
    output = stage / "reports" / "certified_linux_suite.json"
    try:
        result = verify_certified_linux_suite(
            root=pristine,
            expected_commit=str(source_identity.commit_sha),
            expected_tree=str(source_identity.tree_sha),
            expected_source_manifest_sha256=str(source_identity.manifest_sha256),
        )
    except (OSError, CertifiedLinuxSuiteError) as exc:
        return synthetic_step_fn(
            "certified_linux_suite", pristine, stage, replacements,
            passed=False,
            findings=[str(exc).split(":", 1)[0]],
            input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return synthetic_step_fn(
        "certified_linux_suite", pristine, stage, replacements,
        passed=True,
        input_hashes={"source_manifest_sha256": source_identity.manifest_sha256},
        output_hashes={"certified_linux_suite_sha256": _sha256_file(output)},
        stdout_text=json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n",
    )


def run_formal_external_trust_anchor(
    pristine: Path,
    stage: Path,
    replacements: dict[str, str],
    output: Path,
    *,
    synthetic_step_fn: StepFactory,
) -> dict[str, Any]:
    report = stage / "reports" / "formal_external_trust_anchor.json"
    if not output.is_file():
        return synthetic_step_fn(
            "formal_external_trust_anchor", pristine, stage, replacements,
            passed=False, findings=["FORMAL_ARTIFACT_REQUIRED"], skipped=True,
        )
    missing_external = formal_trust_evidence_not_provided()
    if missing_external:
        return synthetic_step_fn(
            "formal_external_trust_anchor", pristine, stage, replacements,
            passed=False,
            findings=["FORMAL_EXTERNAL_TRUST_EVIDENCE_NOT_PROVIDED", *[f"MISSING_ENV:{name}" for name in missing_external]],
            skipped=True,
        )
    artifact_sha = _sha256_file(output)
    previous_runtime_digest = os.environ.get("APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST")
    os.environ["APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST"] = artifact_sha
    try:
        result = verify_formal_trust_anchor(root=pristine, artifact=output)
    except (OSError, FormalTrustAnchorError) as exc:
        return synthetic_step_fn(
            "formal_external_trust_anchor", pristine, stage, replacements,
            passed=False,
            findings=[str(exc).split(":", 1)[0]],
            input_hashes={"artifact_sha256": artifact_sha},
        )
    finally:
        if previous_runtime_digest is None:
            os.environ.pop("APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST", None)
        else:
            os.environ["APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST"] = previous_runtime_digest
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return synthetic_step_fn(
        "formal_external_trust_anchor", pristine, stage, replacements,
        passed=True,
        input_hashes={"artifact_sha256": artifact_sha},
        output_hashes={"formal_external_trust_anchor_sha256": _sha256_file(report)},
        stdout_text=json.dumps(result, ensure_ascii=False, sort_keys=True) + "\n",
    )


@enforces_rule("APS-RELEASE-SELF-ATTESTATION-001")
@emits_diagnostic("APS-RELEASE-SELF-ATTESTATION-001", "RELEASE_SELF_ATTESTATION_DECLARED")
@emits_diagnostic("APS-RELEASE-SELF-ATTESTATION-001", "RELEASE_SELF_ATTESTATION_PASS_FORBIDDEN")
def final_receipt_status(
    *,
    core_ok: bool,
    steps: list[dict[str, Any]],
    mandatory_steps: list[str],
    skip_tests: bool,
    profile_name: str,
    independent_verification: bool = True,
) -> str:
    by_id = {str(step.get("id")): step for step in steps}
    all_mandatory_pass = all(
        by_id.get(step_id, {}).get("status") == "PASS"
        and by_id.get(step_id, {}).get("exit_code") == 0
        for step_id in mandatory_steps
    )
    if core_ok and all_mandatory_pass:
        # PASS означает «подтверждено независимой стороной» и закреплён за
        # профилями, которые её требуют. Профиль без независимой проверки
        # получает собственный статус, который нельзя прочитать как релизный.
        return "PASS" if independent_verification else "SELF_ATTESTED"
    external_evidence_not_provided = any(
        finding in {
            "CERTIFIED_LINUX_SUITE_EVIDENCE_NOT_PROVIDED",
            "FORMAL_EXTERNAL_TRUST_EVIDENCE_NOT_PROVIDED",
        }
        for step in steps
        for finding in step.get("findings", [])
    )
    if skip_tests or external_evidence_not_provided:
        return "INCOMPLETE"
    if profile_name == "diagnostic" and core_ok:
        return "DIAGNOSTIC_ONLY"
    return "FAIL"


def requires_independent(profile: dict[str, Any]) -> bool:
    """Требует ли профиль подтверждения независимой стороной."""
    return bool(profile.get("independent_verification", True))


def artifact_prerequisites(require_external: bool, phases: tuple[str, ...]) -> tuple[str, ...]:
    """Шаги, которые обязаны пройти до публикации артефакта.

    Независимая аттестация входит сюда только для профиля, который её требует:
    иначе профиль, объявивший себя самозаверенным, всё равно не смог бы
    опубликовать архив, и объявление ничего бы не меняло.
    """
    return ("source_preflight", "source_identity_bundle", "static", "static_source_integrity",
        *(("certified_linux_suite",) if require_external else ()), "direct_tests", "direct_tests_source_integrity", "tests", "tests_source_integrity", "golden", "golden_source_integrity", "prompt_catalog_validation", "prompt_content_integrity", "read_only_audit_wrapper_evidence", "audit_prompt_adversarial_evidence", *tuple(item for phase in phases for item in (phase, f"{phase}_source_integrity")), "capability_evidence", "capability_source_integrity", "agent_gate_evidence", "agent_gate_source_integrity", "trusted_post_merge_evidence", "post_merge_source_integrity", "trust_boundary_evidence", "trust_boundary_source_integrity", "v131_adversarial_evidence", "v131_adversarial_source_integrity", "v132_adversarial_evidence", "v132_adversarial_source_integrity", "v133_automatic_merge_evidence", "v133_automatic_merge_source_integrity", "dead_code_audit", "dead_code_audit_source_integrity", "project_health_audit")
