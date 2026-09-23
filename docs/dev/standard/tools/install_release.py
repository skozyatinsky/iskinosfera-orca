#!/usr/bin/env python3
# ======================================================================
# install_release.py — версия 1.0
# Безопасная установка release ZIP с восстановлением canonical modes.
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
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_integrity import compare_records, manifest_digest, source_records  # noqa: E402
from trusted_tool_identity import TrustedToolIdentityError, verify_trusted_tools  # noqa: E402
from validate_release_receipt import (  # noqa: E402
    load_json,
    validate_receipt,
    verify_exported_evidence,
)


class InstallationError(RuntimeError):
    """Fail-closed release installation error."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_name(name: str) -> PurePosixPath:
    if not name or "\\" in name:
        raise InstallationError("INSTALL_ARCHIVE_PATH_INVALID")
    pure = PurePosixPath(name)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise InstallationError("INSTALL_ARCHIVE_PATH_TRAVERSAL")
    return pure


def inspect_archive(artifact: Path, records: list[dict[str, Any]]) -> list[tuple[zipfile.ZipInfo, dict[str, Any]]]:
    expected = {item["path"]: item for item in records}
    inspected: list[tuple[zipfile.ZipInfo, dict[str, Any]]] = []
    with zipfile.ZipFile(artifact) as archive:
        infos = [item for item in archive.infolist() if not item.is_dir()]
        names = [item.filename for item in infos]
        if len(names) != len(set(names)):
            raise InstallationError("INSTALL_ARCHIVE_DUPLICATE_ENTRY")
        for info in infos:
            pure = _safe_name(info.filename)
            record = expected.get(pure.as_posix())
            if not isinstance(record, dict):
                raise InstallationError(f"INSTALL_ARCHIVE_UNEXPECTED_ENTRY:{info.filename}")
            raw_mode = (info.external_attr >> 16) & 0xFFFF
            archive_type = "symlink" if stat.S_ISLNK(raw_mode) else "file"
            if archive_type != record.get("type"):
                raise InstallationError(f"INSTALL_ARCHIVE_TYPE_MISMATCH:{info.filename}")
            inspected.append((info, record))
    if {item.filename for item, _ in inspected} != set(expected):
        raise InstallationError("INSTALL_ARCHIVE_MANIFEST_MISMATCH")
    return inspected


def _extract(artifact: Path, destination: Path, inspected: list[tuple[zipfile.ZipInfo, dict[str, Any]]]) -> int:
    destination.mkdir(parents=True, exist_ok=False)
    restored = 0
    with zipfile.ZipFile(artifact) as archive:
        for info, record in inspected:
            target = destination.joinpath(*PurePosixPath(info.filename).parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            payload = archive.read(info)
            if hashlib.sha256(payload).hexdigest() != record.get("sha256") or len(payload) != record.get("size"):
                raise InstallationError(f"INSTALL_ARCHIVE_CONTENT_MISMATCH:{info.filename}")
            if record.get("type") == "symlink":
                link_target = payload.decode("utf-8")
                link_path = PurePosixPath(link_target)
                if link_path.is_absolute() or ".." in link_path.parts:
                    raise InstallationError(f"INSTALL_ARCHIVE_SYMLINK_UNSAFE:{info.filename}")
                target.symlink_to(link_target)
            else:
                target.write_bytes(payload)
                mode = int(str(record.get("mode")), 8)
                target.chmod(mode)
                restored += 1
    return restored


def install_release(
    *,
    artifact: Path,
    receipt_path: Path,
    evidence_bundle: Path,
    destination: Path,
    installation_receipt: Path | None = None,
    integrity_only: bool = False,
) -> dict[str, Any]:
    root = Path(__file__).resolve().parent.parent
    receipt = load_json(receipt_path)
    schema = load_json(root / "schemas/release_receipt.schema.json")
    profiles = load_json(root / "reference/release_profiles.json")
    profiles_schema = load_json(root / "schemas/release_profiles.schema.json")
    findings = validate_receipt(receipt, schema, profiles, profiles_schema)
    findings.extend(verify_exported_evidence(receipt, artifact=artifact, evidence_bundle=evidence_bundle))
    if findings:
        raise InstallationError("INSTALL_RELEASE_VERIFICATION_FAILED:" + ";".join(sorted(set(findings))))
    if receipt.get("status") != "PASS" or receipt.get("artifact", {}).get("published") is not True:
        raise InstallationError("INSTALL_RELEASE_NOT_PUBLISHED")
    if sha256_file(artifact) != receipt.get("artifact", {}).get("sha256"):
        raise InstallationError("INSTALL_ARCHIVE_HASH_MISMATCH")
    records = receipt.get("source", {}).get("records")
    if not isinstance(records, list) or manifest_digest(records) != receipt.get("source", {}).get("manifest_sha256"):
        raise InstallationError("INSTALL_SOURCE_MANIFEST_MISMATCH")
    inspected = inspect_archive(artifact, records)
    if destination.exists():
        raise InstallationError("INSTALL_DESTINATION_EXISTS")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="aps_install_", dir=str(destination.parent)) as raw:
        staged = Path(raw) / "staged"
        restored = _extract(artifact, staged, inspected)
        installed_records = source_records(staged)
        drift = compare_records(records, installed_records)
        if drift:
            raise InstallationError("INSTALL_SOURCE_MANIFEST_MISMATCH:" + ";".join(drift[:20]))
        try:
            tool_identity = verify_trusted_tools(
                root=staged,
                require_external_pin=not integrity_only,
            )
        except TrustedToolIdentityError as exc:
            raise InstallationError(str(exc)) from exc
        artifact_digest = sha256_file(artifact)
        if not integrity_only and tool_identity.get("runtime_artifact_digest") != artifact_digest:
            raise InstallationError("TRUSTED_RUNTIME_ARTIFACT_DIGEST_MISMATCH")
        static = subprocess.run(
            [sys.executable, str(staged / "tools/validate_structure.py"), "--root", str(staged),
             "--profile", "standard-package", "--schemas-root", str(staged / "schemas"), "--warnings-as-errors"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1"},
        )
        if static.returncode != 0:
            raise InstallationError("INSTALL_STATIC_VALIDATION_FAILED:" + (static.stderr or static.stdout).strip())
        staged.replace(destination)
    result = {
        "schema_version": "2.0.0",
        "status": "CONTRACT_READY" if integrity_only else "PASS",
        "assurance_level": "INTEGRITY_ONLY" if integrity_only else "AUTHENTICITY_AND_INTEGRITY",
        "formal_installation_verified": not integrity_only,
        "installed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "artifact_sha256": sha256_file(artifact),
        "release_receipt_sha256": sha256_file(receipt_path),
        "evidence_bundle_sha256": sha256_file(evidence_bundle),
        "destination": str(destination.resolve()),
        "source_manifest_sha256": receipt["source"]["manifest_sha256"],
        "installed_file_count": len(records),
        "regular_file_modes_restored": restored,
        "trusted_tool_identity": tool_identity,
        "static_validation_exit_code": 0,
    }
    output = installation_receipt or destination.parent / "INSTALLATION_RECEIPT.json"
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    result["installation_receipt"] = str(output.resolve())
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--evidence-bundle", required=True)
    parser.add_argument("--destination", required=True)
    parser.add_argument("--installation-receipt")
    parser.add_argument(
        "--integrity-only",
        action="store_true",
        help="explicit non-formal mode; verifies bytes/modes/static gate but not an external trust anchor",
    )
    args = parser.parse_args()
    try:
        result = install_release(
            artifact=Path(args.artifact),
            receipt_path=Path(args.receipt),
            evidence_bundle=Path(args.evidence_bundle),
            destination=Path(args.destination),
            installation_receipt=Path(args.installation_receipt) if args.installation_receipt else None,
            integrity_only=args.integrity_only,
        )
    except (InstallationError, OSError, ValueError, zipfile.BadZipFile, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
