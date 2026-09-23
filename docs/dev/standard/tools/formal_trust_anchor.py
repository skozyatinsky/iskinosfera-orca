#!/usr/bin/env python3
# ======================================================================
# formal_trust_anchor.py — версия 1.0
# External trust-root gate for formal release and installation.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule, print_diagnostic  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402

RULE_ID = "APS-FORMAL-EXTERNAL-PIN-001"


class FormalTrustAnchorError(RuntimeError):
    """Fail-closed formal trust anchor error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _finding(code: str, message: str, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, RULE_ID, message, severity, evidence)


@enforces_rule("APS-FORMAL-EXTERNAL-PIN-001")
@emits_diagnostic("APS-FORMAL-EXTERNAL-PIN-001", "FORMAL_EXTERNAL_TRUST_ANCHOR_VERIFIED")
@emits_diagnostic("APS-FORMAL-EXTERNAL-PIN-001", "TRUSTED_TOOL_EXTERNAL_PIN_REQUIRED")
@emits_diagnostic("APS-FORMAL-EXTERNAL-PIN-001", "TRUSTED_TOOL_EXTERNAL_PIN_MISMATCH")
@emits_diagnostic("APS-FORMAL-EXTERNAL-PIN-001", "TRUSTED_RUNTIME_ARTIFACT_DIGEST_MISMATCH")
@emits_diagnostic("APS-FORMAL-EXTERNAL-PIN-001", "TRUSTED_TOOL_MANIFEST_SIGNING_KEY_UNKNOWN")
def verify_formal_trust_anchor(*, root: Path, artifact: Path) -> dict[str, Any]:
    if not artifact.is_file():
        raise FormalTrustAnchorError("FORMAL_ARTIFACT_REQUIRED")
    try:
        identity = verify_trusted_tools(root=root, require_external_pin=True)
    except TrustedToolIdentityError as exc:
        raise FormalTrustAnchorError(str(exc)) from exc
    artifact_sha = sha256_file(artifact)
    if identity.get("runtime_artifact_digest") != artifact_sha:
        raise FormalTrustAnchorError("TRUSTED_RUNTIME_ARTIFACT_DIGEST_MISMATCH")
    if identity.get("external_manifest_pin") != identity.get("manifest_sha256"):
        raise FormalTrustAnchorError("TRUSTED_TOOL_EXTERNAL_PIN_MISMATCH")
    return {
        "status": "PASS",
        "formal_external_trust_verified": True,
        "artifact_sha256": artifact_sha,
        "manifest_sha256": identity["manifest_sha256"],
        "external_manifest_pin": identity["external_manifest_pin"],
        "manifest_signing_key_id": identity["manifest_signing_key_id"],
        "runtime_artifact_digest": identity["runtime_artifact_digest"],
        "verified_tool_count": len(identity["verified_tools"]),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    try:
        result = verify_formal_trust_anchor(root=Path(args.root), artifact=Path(args.artifact))
    except (OSError, FormalTrustAnchorError) as exc:
        code = str(exc).split(":", 1)[0]
        print_diagnostic(_finding(code, str(exc)))
        print(str(exc), file=sys.stderr)
        return 1
    print_diagnostic(_finding("FORMAL_EXTERNAL_TRUST_ANCHOR_VERIFIED", "External manifest pin and artifact binding are valid.", "INFO", **result))
    text = json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
