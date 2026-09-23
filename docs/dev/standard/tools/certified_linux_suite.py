#!/usr/bin/env python3
# ======================================================================
# certified_linux_suite.py — версия 1.0
# Верификация внешне подписанного полного Linux test contour.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from external_trust import (  # noqa: E402
    ExternalTrustError,
    canonical_bytes,
    load_registry,
    load_signed_revocation_state,
    parse_utc,
    verify_ed25519_record,
)
from junit_evidence import JUnitEvidenceError, node_ids_sha256, parse_junit  # noqa: E402
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule, print_diagnostic  # noqa: E402

ATTESTATION_ENV = "APS_CERTIFIED_LINUX_SUITE_ATTESTATION"
ATTESTATION_PIN_ENV = "APS_CERTIFIED_LINUX_SUITE_ATTESTATION_SHA256"
KEYS_ENV = "APS_CERTIFIED_LINUX_SUITE_PUBLIC_KEYS_JSON"
REVOKED_KEYS_ENV = "APS_CERTIFIED_LINUX_SUITE_REVOKED_KEY_IDS"
REVOCATION_STATE_ENV = "APS_CERTIFIED_LINUX_SUITE_REVOCATION_STATE"
DIRECT_JUNIT_ENV = "APS_CERTIFIED_LINUX_DIRECT_JUNIT"
SEGMENTED_JUNIT_ENV = "APS_CERTIFIED_LINUX_SEGMENTED_JUNIT"
PROFILE_RELATIVE = Path("reference/certified_linux_suite_profile.json")
SCHEMA_RELATIVE = Path("schemas/certified_linux_suite_attestation.schema.json")
RULE_ID = "APS-CERTIFIED-LINUX-SUITE-001"
REQUIRED_CAPABILITIES = (
    "linux",
    "user_namespace",
    "mount_namespace",
    "pid_namespace",
    "pivot_root",
    "no_new_privs",
    "descendant_cleanup",
)


class CertifiedLinuxSuiteError(RuntimeError):
    """Fail-closed error for external full-suite evidence."""


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path, finding: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertifiedLinuxSuiteError(finding) from exc
    if not isinstance(value, dict):
        raise CertifiedLinuxSuiteError(finding)
    return value


def _validate_schema(root: Path, record: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:  # pragma: no cover
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_SCHEMA_VALIDATOR_REQUIRED") from exc
    schema = _load_json(root / SCHEMA_RELATIVE, "CERTIFIED_LINUX_SCHEMA_INVALID")
    errors = sorted(Draft202012Validator(schema).iter_errors(record), key=lambda item: list(item.absolute_path))
    if errors:
        location = "/".join(str(item) for item in errors[0].absolute_path) or "$"
        raise CertifiedLinuxSuiteError(f"CERTIFIED_LINUX_ATTESTATION_SCHEMA_INVALID:{location}:{errors[0].message}")


def _profile(root: Path) -> tuple[dict[str, Any], str]:
    profile = _load_json(root / PROFILE_RELATIVE, "CERTIFIED_LINUX_PROFILE_INVALID")
    return profile, hashlib.sha256(canonical_bytes(profile)).hexdigest()


def _require_sha256(value: Any, finding: str) -> str:
    text = str(value or "")
    if len(text) != 64 or any(ch not in "0123456789abcdef" for ch in text):
        raise CertifiedLinuxSuiteError(finding)
    return text


def _formal_summary(analysis: Any, label: str) -> None:
    summary = analysis.summary
    valid = (
        summary.get("total", 0) > 0
        and summary.get("completed") == summary.get("total")
        and summary.get("accounted") == summary.get("total")
        and summary.get("passed") == summary.get("total")
        and summary.get("failed") == 0
        and summary.get("errors") == 0
        and summary.get("unexpected_skipped") == 0
        and summary.get("xpassed") == 0
        and not analysis.duplicate_node_ids
        and analysis.missing_node_id_count == 0
        and summary.get("status") == "PASS"
    )
    if not valid:
        raise CertifiedLinuxSuiteError(f"CERTIFIED_LINUX_JUNIT_ACCOUNTING_INVALID:{label}")


def _finding(code: str, message: str, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, RULE_ID, message, severity, evidence)


def _artifact_signing_key(root: Path) -> str:
    """Открытый ключ, которым подписан манифест инструментов этой поставки.

    Он не может быть корнем доверия к ней же: иначе сборщик заверяет
    собственную работу.
    """
    try:
        manifest = json.loads((root / "reference/trusted_tools_manifest.json").read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_ARTIFACT_KEY_UNREADABLE") from exc
    key = manifest.get("signing_public_key")
    if not isinstance(key, str) or not key:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_ARTIFACT_KEY_UNREADABLE")
    return key


def _verify_attestation_trust(root: Path, record: dict[str, Any]) -> None:
    """Проверить подпись аттестации и независимость корня доверия.

    Ключ, которым подписан манифест инструментов поставки, не может заверять её
    же. Отзыв, подписанный самим издателем, ничего не доказывает — требуется
    третий ключ, отдельный и от сборщика, и от издателя.
    """
    artifact_key = _artifact_signing_key(root)
    issuer_entry = load_registry(KEYS_ENV, "CERTIFIED_LINUX_ISSUER_REGISTRY_REQUIRED").get(
        str(record.get("key_id", ""))
    )
    issuer_key = str(issuer_entry.get("public_key", "")) if isinstance(issuer_entry, dict) else ""
    revoked = load_signed_revocation_state(
        REVOCATION_STATE_ENV,
        registry_env=KEYS_ENV,
        finding_prefix="CERTIFIED_LINUX",
        forbidden_public_keys=(artifact_key, issuer_key),
    )
    if str(record.get("key_id")) in revoked:
        raise ExternalTrustError("CERTIFIED_LINUX_ISSUER_REVOKED")
    verify_ed25519_record(
        record,
        registry_env=KEYS_ENV,
        revoked_env=REVOKED_KEYS_ENV,
        missing_registry_finding="CERTIFIED_LINUX_ISSUER_REGISTRY_REQUIRED",
        unknown_key_finding="CERTIFIED_LINUX_ISSUER_UNTRUSTED",
        revoked_key_finding="CERTIFIED_LINUX_ISSUER_REVOKED",
        signature_finding="CERTIFIED_LINUX_ATTESTATION_SIGNATURE_INVALID",
        expected_service_identity=str(record["issuer"]),
        expected_deployment_identity=str(record["deployment_identity"]),
        denied_public_keys=(artifact_key,),
        denied_finding="CERTIFIED_LINUX_SELF_CERTIFICATION_FORBIDDEN",
    )


@enforces_rule("APS-CERTIFIED-LINUX-SUITE-001")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_SUITE_VERIFIED")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_SUITE_REQUIRED")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_ATTESTATION_INVALID")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_JUNIT_INVALID")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_TEST_BINDING_MISMATCH")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_NODE_SET_MISMATCH")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_SELF_CERTIFICATION_FORBIDDEN")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_REVOCATION_STATE_REQUIRED")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_REVOCATION_STATE_STALE")
@emits_diagnostic("APS-CERTIFIED-LINUX-SUITE-001", "CERTIFIED_LINUX_REVOCATION_NOT_INDEPENDENTLY_SIGNED")
def verify_certified_linux_suite(
    *,
    root: Path,
    expected_commit: str,
    expected_tree: str,
    expected_source_manifest_sha256: str,
    attestation_path: Path | None = None,
    direct_junit_path: Path | None = None,
    segmented_junit_path: Path | None = None,
) -> dict[str, Any]:
    root = root.resolve()
    attestation_path = attestation_path or Path(os.environ.get(ATTESTATION_ENV, ""))
    direct_junit_path = direct_junit_path or Path(os.environ.get(DIRECT_JUNIT_ENV, ""))
    segmented_junit_path = segmented_junit_path or Path(os.environ.get(SEGMENTED_JUNIT_ENV, ""))
    if not str(attestation_path) or not attestation_path.is_file():
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_SUITE_REQUIRED")
    if not str(direct_junit_path) or not direct_junit_path.is_file():
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_DIRECT_JUNIT_REQUIRED")
    if not str(segmented_junit_path) or not segmented_junit_path.is_file():
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_SEGMENTED_JUNIT_REQUIRED")

    record = _load_json(attestation_path, "CERTIFIED_LINUX_ATTESTATION_INVALID")
    _validate_schema(root, record)
    pinned = _require_sha256(os.environ.get(ATTESTATION_PIN_ENV), "CERTIFIED_LINUX_ATTESTATION_PIN_REQUIRED")
    actual_attestation_sha = _sha256_file(attestation_path)
    if pinned != actual_attestation_sha:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_ATTESTATION_PIN_MISMATCH")
    try:
        _verify_attestation_trust(root, record)
    except ExternalTrustError as exc:
        raise CertifiedLinuxSuiteError(str(exc)) from exc

    now = datetime.now(timezone.utc)
    try:
        issued = parse_utc(str(record["issued_at"]), "CERTIFIED_LINUX_ATTESTATION_TIMESTAMP_INVALID")
        expires = parse_utc(str(record["expires_at"]), "CERTIFIED_LINUX_ATTESTATION_TIMESTAMP_INVALID")
    except ExternalTrustError as exc:
        raise CertifiedLinuxSuiteError(str(exc)) from exc
    if issued > now or expires <= now:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_ATTESTATION_EXPIRED")

    profile, profile_sha = _profile(root)
    if record.get("profile_id") != profile.get("profile_id") or record.get("profile_sha256") != profile_sha:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_PROFILE_MISMATCH")
    bindings = {
        "commit_sha": expected_commit,
        "tree_sha": expected_tree,
        "source_manifest_sha256": expected_source_manifest_sha256,
    }
    for key, expected in bindings.items():
        if record.get("source", {}).get(key) != expected:
            raise CertifiedLinuxSuiteError(f"CERTIFIED_LINUX_SOURCE_BINDING_MISMATCH:{key}")

    capabilities = record.get("environment", {}).get("capabilities", {})
    missing_caps = sorted(key for key in REQUIRED_CAPABILITIES if capabilities.get(key) is not True)
    if record.get("environment", {}).get("os") != "Linux" or missing_caps:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_CAPABILITIES_INCOMPLETE:" + ",".join(missing_caps))
    _require_sha256(record.get("environment", {}).get("executor_image_digest"), "CERTIFIED_LINUX_EXECUTOR_IMAGE_DIGEST_INVALID")

    try:
        direct = parse_junit(direct_junit_path, require_node_ids=True)
        segmented = parse_junit(segmented_junit_path, require_node_ids=True)
    except (OSError, JUnitEvidenceError) as exc:
        raise CertifiedLinuxSuiteError(f"CERTIFIED_LINUX_JUNIT_INVALID:{exc}") from exc
    _formal_summary(direct, "direct")
    _formal_summary(segmented, "segmented")
    if direct.node_ids != segmented.node_ids:
        raise CertifiedLinuxSuiteError("CERTIFIED_LINUX_NODE_SET_MISMATCH")

    tests = record.get("tests", {})
    actual = {
        "collected": len(direct.node_ids),
        "direct_junit_sha256": _sha256_file(direct_junit_path),
        "segmented_junit_sha256": _sha256_file(segmented_junit_path),
        "node_ids_sha256": node_ids_sha256(direct.node_ids),
        "passed": int(direct.summary["passed"]),
        "failed": int(direct.summary["failed"]),
        "errors": int(direct.summary["errors"]),
        "unexpected_skipped": int(direct.summary["unexpected_skipped"]),
        "xpassed": int(direct.summary["xpassed"]),
    }
    for key, value in actual.items():
        if tests.get(key) != value:
            raise CertifiedLinuxSuiteError(f"CERTIFIED_LINUX_TEST_BINDING_MISMATCH:{key}")

    return {
        "status": "PASS",
        "attestation_id": record["attestation_id"],
        "attestation_sha256": actual_attestation_sha,
        "issuer": record["issuer"],
        "deployment_identity": record["deployment_identity"],
        "profile_id": record["profile_id"],
        "profile_sha256": profile_sha,
        "source": bindings,
        "tests": actual,
        "environment": record["environment"],
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--commit", required=True)
    parser.add_argument("--tree", required=True)
    parser.add_argument("--source-manifest-sha256", required=True)
    parser.add_argument("--attestation")
    parser.add_argument("--direct-junit")
    parser.add_argument("--segmented-junit")
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = verify_certified_linux_suite(
            root=Path(args.root),
            expected_commit=args.commit,
            expected_tree=args.tree,
            expected_source_manifest_sha256=args.source_manifest_sha256,
            attestation_path=Path(args.attestation) if args.attestation else None,
            direct_junit_path=Path(args.direct_junit) if args.direct_junit else None,
            segmented_junit_path=Path(args.segmented_junit) if args.segmented_junit else None,
        )
    except CertifiedLinuxSuiteError as exc:
        code = str(exc).split(":", 1)[0]
        print_diagnostic(_finding(code, str(exc)))
        print(str(exc), file=sys.stderr)
        return 1
    finding = _finding("CERTIFIED_LINUX_SUITE_VERIFIED", "External certified Linux full-suite evidence is valid.", "INFO", **result)
    print_diagnostic(finding)
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
