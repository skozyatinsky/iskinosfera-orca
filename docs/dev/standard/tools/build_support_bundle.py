#!/usr/bin/env python3
# ======================================================================
# build_support_bundle.py — версия 1.0
# Детерминированная сборка support bundle с точной cardinality.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
import stat
import sys
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule, print_diagnostic  # noqa: E402

RULE_ID = "APS-SUPPORT-BUNDLE-CARDINALITY-001"
CHECKSUM_NAME = "SHA256SUMS.txt"
FIXED_DATE = (2020, 1, 1, 0, 0, 0)


class SupportBundleError(RuntimeError):
    """Fail-closed support bundle error."""


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _files(root: Path) -> list[Path]:
    result = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        if path.is_symlink():
            raise SupportBundleError(f"SUPPORT_BUNDLE_SYMLINK_FORBIDDEN:{path.relative_to(root).as_posix()}")
        if path.is_file():
            result.append(path)
    return result


def _zip_info(name: str, mode: int = 0o644) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_DATE)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def _checksum_payload(entries: list[tuple[str, bytes]]) -> bytes:
    return ("".join(f"{sha256_bytes(payload)}  {name}\n" for name, payload in entries)).encode("utf-8")


@enforces_rule("APS-SUPPORT-BUNDLE-CARDINALITY-001")
@emits_diagnostic("APS-SUPPORT-BUNDLE-CARDINALITY-001", "SUPPORT_BUNDLE_CARDINALITY_VALID")
@emits_diagnostic("APS-SUPPORT-BUNDLE-CARDINALITY-001", "SUPPORT_BUNDLE_ENTRY_COUNT_MISMATCH")
@emits_diagnostic("APS-SUPPORT-BUNDLE-CARDINALITY-001", "SUPPORT_BUNDLE_CHECKSUM_SET_MISMATCH")
@emits_diagnostic("APS-SUPPORT-BUNDLE-CARDINALITY-001", "SUPPORT_BUNDLE_SELF_HASH_FORBIDDEN")
def verify_support_bundle(path: Path, delivery: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = [item for item in archive.infolist() if not item.is_dir()]
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise SupportBundleError("SUPPORT_BUNDLE_DUPLICATE_ENTRY")
            if CHECKSUM_NAME not in names:
                raise SupportBundleError("SUPPORT_BUNDLE_CHECKSUMS_MISSING")
            for name in names:
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                    raise SupportBundleError(f"SUPPORT_BUNDLE_UNSAFE_PATH:{name}")
            bad = archive.testzip()
            if bad:
                raise SupportBundleError(f"SUPPORT_BUNDLE_CRC_FAILURE:{bad}")
            checksum_text = archive.read(CHECKSUM_NAME).decode("utf-8")
            declared: dict[str, str] = {}
            for raw in checksum_text.splitlines():
                digest, sep, name = raw.partition("  ")
                if not sep or len(digest) != 64 or name in declared:
                    raise SupportBundleError("SUPPORT_BUNDLE_CHECKSUMS_INVALID")
                declared[name] = digest
            expected_names = set(names) - {CHECKSUM_NAME}
            if set(declared) != expected_names:
                raise SupportBundleError("SUPPORT_BUNDLE_CHECKSUM_SET_MISMATCH")
            for name, digest in declared.items():
                if sha256_bytes(archive.read(name)) != digest:
                    raise SupportBundleError(f"SUPPORT_BUNDLE_CHECKSUM_MISMATCH:{name}")
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise SupportBundleError(f"SUPPORT_BUNDLE_INVALID:{type(exc).__name__}") from exc
    actual_count = len(names)
    if delivery is not None:
        support = delivery.get("support_bundle", {})
        if support.get("entry_count") != actual_count:
            raise SupportBundleError("SUPPORT_BUNDLE_ENTRY_COUNT_MISMATCH")
        if support.get("checksummed_entry_count") != actual_count - 1:
            raise SupportBundleError("SUPPORT_BUNDLE_ENTRY_COUNT_MISMATCH")
        if support.get("sha256") != sha256_file(path):
            raise SupportBundleError("SUPPORT_BUNDLE_DIGEST_MISMATCH")
        if support.get("self_hash_included") is not False:
            raise SupportBundleError("SUPPORT_BUNDLE_SELF_HASH_FORBIDDEN")
    return {
        "status": "PASS",
        "entry_count": actual_count,
        "checksummed_entry_count": actual_count - 1,
        "sha256": sha256_file(path),
        "self_hash_included": False,
    }


def build_support_bundle(*, input_dir: Path, output: Path, delivery_summary: Path, version: str) -> dict[str, Any]:
    input_dir = input_dir.resolve()
    entries = [(path.relative_to(input_dir).as_posix(), path.read_bytes()) for path in _files(input_dir)]
    if any(name == CHECKSUM_NAME for name, _ in entries):
        raise SupportBundleError("SUPPORT_BUNDLE_INPUT_CHECKSUMS_FORBIDDEN")
    checksum_payload = _checksum_payload(entries)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, payload in entries:
            archive.writestr(_zip_info(name), payload)
        archive.writestr(_zip_info(CHECKSUM_NAME), checksum_payload)
    result = verify_support_bundle(output)
    delivery = {
        "schema_version": "1.0.0",
        "version": version,
        "support_bundle": {
            "path": output.name,
            "entry_count": result["entry_count"],
            "checksummed_entry_count": result["checksummed_entry_count"],
            "sha256": result["sha256"],
            "self_hash_included": False,
            "hash_binding": "external_delivery_summary",
        },
    }
    delivery_summary.write_text(json.dumps(delivery, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    verify_support_bundle(output, delivery)
    return delivery


def _finding(code: str, message: str, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, RULE_ID, message, severity, evidence)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--delivery-summary", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    try:
        if args.verify_only:
            delivery = json.loads(Path(args.delivery_summary).read_text(encoding="utf-8-sig"))
            result = verify_support_bundle(Path(args.output), delivery)
        else:
            delivery = build_support_bundle(
                input_dir=Path(args.input_dir),
                output=Path(args.output),
                delivery_summary=Path(args.delivery_summary),
                version=args.version,
            )
            result = delivery["support_bundle"]
    except (OSError, json.JSONDecodeError, SupportBundleError) as exc:
        code = str(exc).split(":", 1)[0]
        print_diagnostic(_finding(code, str(exc)))
        print(str(exc), file=sys.stderr)
        return 1
    print_diagnostic(_finding("SUPPORT_BUNDLE_CARDINALITY_VALID", "Support bundle entry and checksum cardinality are exact.", "INFO", **result))
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
