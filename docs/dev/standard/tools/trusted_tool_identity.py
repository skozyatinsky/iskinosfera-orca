#!/usr/bin/env python3
# ======================================================================
# trusted_tool_identity.py — версия 2.0
# Trusted executable identity with mandatory external pin for trusted profiles.
# ======================================================================
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
from typing import Any, Iterable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
except ImportError as exc:  # pragma: no cover
    raise RuntimeError("TRUSTED_TOOL_CRYPTOGRAPHY_REQUIRED") from exc

TOOL_MANIFEST_RELATIVE = Path("reference/trusted_tools_manifest.json")
MANIFEST_PIN_ENV = "APS_TRUSTED_TOOL_MANIFEST_SHA256"
MANIFEST_KEYS_ENV = "APS_TRUSTED_TOOL_MANIFEST_PUBLIC_KEYS_JSON"
MANIFEST_REVOKED_KEYS_ENV = "APS_TRUSTED_TOOL_MANIFEST_REVOKED_KEY_IDS"
MANIFEST_BUILD_ENV = "APS_TRUSTED_TOOL_MANIFEST_BUILD"
MANIFEST_PRIVATE_KEY_ENV = "APS_TRUSTED_TOOL_MANIFEST_PRIVATE_KEY"
MANIFEST_SIGNING_KEY_ID_ENV = "APS_TRUSTED_TOOL_MANIFEST_SIGNING_KEY_ID"
RUNTIME_ARTIFACT_DIGEST_ENV = "APS_TRUSTED_RUNTIME_ARTIFACT_DIGEST"
TRUST_ENV = "APS_TRUSTED_ORCHESTRATOR"

TRUSTED_TOOL_PATHS = (
    "tools/trusted_signer.py",
    "tools/trusted_verifier.py",
    "tools/trusted_tool_identity.py",
    "tools/external_trust.py",
    "tools/sandbox_certification.py",
    "tools/merge_readiness_gate.py",
    "tools/post_merge_finalize.py",
    "tools/provider_protection_adapter.py",
    "tools/candidate_sandbox.py",
    "tools/trusted_execution.py",
    "tools/agent_gate.py",
    "tools/orchestrator_control_plane.py",
    "tools/orchestrator_trust_store.py",
    "tools/orchestrator_assurance_store.py",
    "tools/automatic_merge_gate.py",
    "tools/provider_merge_adapter.py",
    "tools/merge_transaction_store.py",
    "tools/verify_merge_result.py",
    "tools/recover_merge_operation.py",
)


class TrustedToolIdentityError(RuntimeError):
    """Fail-closed trusted executable identity error."""


def _sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _delivery_mode(path: Path) -> str:
    mode = stat.S_IMODE(path.lstat().st_mode)
    return f"{mode:04o}"


def _decode_b64(value: str, finding: str, expected_length: int | None = None) -> bytes:
    try:
        payload = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise TrustedToolIdentityError(finding) from exc
    if expected_length is not None and len(payload) != expected_length:
        raise TrustedToolIdentityError(finding)
    return payload


def _public_registry() -> dict[str, Any]:
    raw = os.environ.get(MANIFEST_KEYS_ENV, "").strip()
    if not raw:
        raise TrustedToolIdentityError("TRUSTED_TOOL_EXTERNAL_KEY_REGISTRY_REQUIRED")
    try:
        registry = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TrustedToolIdentityError("TRUSTED_TOOL_EXTERNAL_KEY_REGISTRY_INVALID") from exc
    if not isinstance(registry, dict):
        raise TrustedToolIdentityError("TRUSTED_TOOL_EXTERNAL_KEY_REGISTRY_INVALID")
    return registry


def _revoked_ids() -> set[str]:
    return {item.strip() for item in os.environ.get(MANIFEST_REVOKED_KEYS_ENV, "").split(",") if item.strip()}


def package_root() -> Path:
    return Path(__file__).resolve().parent.parent


def build_manifest(root: Path, *, version: str, build_provenance: str) -> dict[str, Any]:
    if os.environ.get(MANIFEST_BUILD_ENV) != "1":
        raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_RUNTIME_REGENERATION_FORBIDDEN")
    key_id = os.environ.get(MANIFEST_SIGNING_KEY_ID_ENV, "").strip()
    private_key_raw = _decode_b64(
        os.environ.get(MANIFEST_PRIVATE_KEY_ENV, ""),
        "TRUSTED_TOOL_MANIFEST_SIGNING_KEY_REQUIRED",
        32,
    )
    if not key_id:
        raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_SIGNING_KEY_ID_REQUIRED")
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_raw)
    public_key_raw = private_key.public_key().public_bytes_raw()

    root = root.resolve()
    tools: list[dict[str, Any]] = []
    for relative in TRUSTED_TOOL_PATHS:
        path = root / relative
        if not path.exists():
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_MISSING:{relative}")
        if path.is_symlink():
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_SYMLINK_FORBIDDEN:{relative}")
        payload = path.read_bytes()
        tools.append({
            "path": relative,
            "version": version,
            "build_provenance": build_provenance,
            "sha256": _sha256_bytes(payload),
            "size": len(payload),
            "mode": _delivery_mode(path),
        })
    base = {
        "schema_version": "2.0.0",
        "standard_version": version,
        "build_provenance": build_provenance,
        "execution_environment_identity": "python-reference-runtime-v2",
        "key_policy_version": "external-ed25519-policy-v1",
        "signature_algorithm": "ed25519",
        "signing_key_id": key_id,
        "signing_public_key": base64.b64encode(public_key_raw).decode("ascii"),
        "tools": tools,
    }
    signed = dict(base)
    signed["manifest_body_sha256"] = _sha256_bytes(_canonical_json(base))
    signed["manifest_signature"] = base64.b64encode(private_key.sign(_canonical_json(signed))).decode("ascii")
    return signed


def write_manifest(root: Path, *, version: str, build_provenance: str) -> Path:
    manifest = build_manifest(root, version=version, build_provenance=build_provenance)
    output = root.resolve() / TOOL_MANIFEST_RELATIVE
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def _verify_embedded_signature(data: dict[str, Any]) -> None:
    signature = _decode_b64(str(data.get("manifest_signature", "")), "TRUSTED_TOOL_MANIFEST_SIGNATURE_INVALID")
    public_key = _decode_b64(str(data.get("signing_public_key", "")), "TRUSTED_TOOL_MANIFEST_PUBLIC_KEY_INVALID", 32)
    signed = dict(data)
    signed.pop("manifest_signature", None)
    base = dict(signed)
    expected_body = base.pop("manifest_body_sha256", None)
    if expected_body != _sha256_bytes(_canonical_json(base)):
        raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_BODY_DIGEST_MISMATCH")
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, _canonical_json(signed))
    except (InvalidSignature, ValueError) as exc:
        raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_SIGNATURE_INVALID") from exc


def load_manifest(
    root: Path | None = None,
    *,
    require_external_pin: bool | None = None,
) -> tuple[dict[str, Any], Path, str, str | None]:
    root = (root or package_root()).resolve()
    path = root / TOOL_MANIFEST_RELATIVE
    try:
        raw = path.read_bytes()
        data = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise TrustedToolIdentityError(f"TRUSTED_TOOL_MANIFEST_INVALID:{exc}") from exc
    if not isinstance(data, dict) or not isinstance(data.get("tools"), list):
        raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_INVALID:shape")
    if data.get("schema_version") != "2.0.0" or data.get("signature_algorithm") != "ed25519":
        raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_INVALID:schema")
    _verify_embedded_signature(data)
    raw_digest = _sha256_bytes(raw)
    require_external = os.environ.get(TRUST_ENV) == "1" if require_external_pin is None else require_external_pin
    runtime_digest: str | None = None
    if require_external:
        pinned = os.environ.get(MANIFEST_PIN_ENV, "").strip()
        if not pinned:
            raise TrustedToolIdentityError("TRUSTED_TOOL_EXTERNAL_PIN_REQUIRED")
        if pinned != raw_digest:
            raise TrustedToolIdentityError("TRUSTED_TOOL_EXTERNAL_PIN_MISMATCH")
        key_id = str(data.get("signing_key_id", ""))
        if key_id in _revoked_ids():
            raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_SIGNING_KEY_REVOKED")
        registry = _public_registry()
        entry = registry.get(key_id)
        public_value = entry.get("public_key") if isinstance(entry, dict) else entry
        if not isinstance(public_value, str):
            raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_SIGNING_KEY_UNKNOWN")
        expected_public = _decode_b64(public_value, "TRUSTED_TOOL_MANIFEST_SIGNING_KEY_UNKNOWN", 32)
        actual_public = _decode_b64(str(data.get("signing_public_key", "")), "TRUSTED_TOOL_MANIFEST_PUBLIC_KEY_INVALID", 32)
        if expected_public != actual_public:
            raise TrustedToolIdentityError("TRUSTED_TOOL_MANIFEST_SIGNING_KEY_UNKNOWN")
        runtime_digest = os.environ.get(RUNTIME_ARTIFACT_DIGEST_ENV, "").strip()
        if len(runtime_digest) != 64 or any(ch not in "0123456789abcdef" for ch in runtime_digest):
            raise TrustedToolIdentityError("TRUSTED_RUNTIME_ARTIFACT_DIGEST_REQUIRED")
    return data, path, raw_digest, runtime_digest


def verify_trusted_tools(
    required_paths: Iterable[str] | None = None,
    *,
    root: Path | None = None,
    require_external_pin: bool | None = None,
) -> dict[str, Any]:
    root = (root or package_root()).resolve()
    manifest, manifest_path, manifest_digest, runtime_digest = load_manifest(
        root, require_external_pin=require_external_pin
    )
    entries = {item.get("path"): item for item in manifest["tools"] if isinstance(item, dict)}
    required = tuple(required_paths or TRUSTED_TOOL_PATHS)
    verified: list[dict[str, Any]] = []
    for relative in required:
        entry = entries.get(relative)
        if not isinstance(entry, dict):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_NOT_APPROVED:{relative}")
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_MISSING:{relative}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_SYMLINK_FORBIDDEN:{relative}")
        if not stat.S_ISREG(metadata.st_mode):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_NOT_REGULAR:{relative}")
        resolved = path.resolve(strict=True)
        if resolved != path.absolute():
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_PATH_REDIRECTED:{relative}")
        payload = path.read_bytes()
        actual = {"sha256": _sha256_bytes(payload), "size": len(payload), "mode": _delivery_mode(path)}
        if actual["sha256"] != entry.get("sha256"):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_DIGEST_MISMATCH:{relative}")
        if actual["size"] != entry.get("size"):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_SIZE_MISMATCH:{relative}")
        if actual["mode"] != entry.get("mode"):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_MODE_MISMATCH:{relative}")
        if entry.get("version") != manifest.get("standard_version"):
            raise TrustedToolIdentityError(f"TRUSTED_EXECUTABLE_VERSION_UNAPPROVED:{relative}")
        verified.append({"path": relative, **actual, "version": entry.get("version")})
    return {
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_digest,
        "manifest_body_sha256": manifest["manifest_body_sha256"],
        "manifest_signature": manifest["manifest_signature"],
        "manifest_signing_key_id": manifest["signing_key_id"],
        "external_manifest_pin": os.environ.get(MANIFEST_PIN_ENV) if runtime_digest else None,
        "runtime_artifact_digest": runtime_digest,
        "standard_version": manifest.get("standard_version"),
        "build_provenance": manifest.get("build_provenance"),
        "execution_environment_identity": manifest.get("execution_environment_identity"),
        "key_policy_version": manifest.get("key_policy_version"),
        "verified_tools": verified,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(package_root()))
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--version")
    parser.add_argument("--build-provenance", default="source-tree")
    parser.add_argument("--tool", action="append", default=[])
    parser.add_argument("--require-external-pin", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        root = Path(args.root).resolve()
        if args.write:
            if not args.version:
                raise TrustedToolIdentityError("TRUSTED_TOOL_VERSION_REQUIRED")
            output = write_manifest(root, version=args.version, build_provenance=args.build_provenance)
            print(output)
            return 0
        result = verify_trusted_tools(
            args.tool or None,
            root=root,
            require_external_pin=True if args.require_external_pin else None,
        )
    except (OSError, ValueError, TrustedToolIdentityError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
