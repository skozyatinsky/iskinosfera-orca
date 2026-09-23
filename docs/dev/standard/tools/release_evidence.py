#!/usr/bin/env python3
# ======================================================================
# release_evidence.py — версия 2.0
# Детерминированный portable evidence bundle с release identity binding.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import zipfile
import datetime as dt
from pathlib import Path
from typing import Any


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def _portable_extra_path(rel: str) -> Path:
    relative = Path(rel)
    if (
        not rel
        or "\x00" in rel
        or "\\" in rel
        or ":" in rel
        or relative.is_absolute()
        or ".." in relative.parts
        or relative.as_posix() != rel
        or rel == "manifest.json"
    ):
        raise ValueError("RELEASE_EVIDENCE_EXTRA_PATH_INVALID")
    return relative


def write_portable_log(stage: Path, relative: str, text: str, replacements: dict[str, str] | None = None) -> str:
    replacements = replacements or {}
    for source, target in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if source:
            text = text.replace(source, target)
    path = stage / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return sha(path.read_bytes())


def bundle_manifest(
    stage: Path,
    release_identity: dict[str, Any],
    extra_files: dict[str, bytes] | None = None,
) -> dict[str, Any]:
    extra_files = extra_files or {}
    files: list[dict[str, Any]] = []
    for path in sorted(item for item in stage.rglob("*") if item.is_file() and item.name != "manifest.json"):
        rel = path.relative_to(stage).as_posix()
        files.append({"path": rel, "sha256": sha(path.read_bytes()), "size": path.stat().st_size})
    for rel, payload in sorted(extra_files.items()):
        files.append({"path": rel, "sha256": sha(payload), "size": len(payload)})
    files.sort(key=lambda item: item["path"])
    return {
        "schema_version": "2.0.0",
        "standard_version": release_identity["standard_version"],
        "source_identity": release_identity["source"],
        "artifact_identity": release_identity["artifact"],
        "test_evidence": release_identity["tests"],
        "identity_record": {
            "path": "release_identity.json",
            "sha256": sha((stage / "release_identity.json").read_bytes()),
        },
        "file_count": len(files) + 1,
        "files": files,
    }


def build_bundle(
    stage: Path,
    output: Path,
    release_identity: dict[str, Any],
    *,
    extra_files: dict[str, bytes] | None = None,
    consume_files: tuple[str, ...] = (),
) -> dict[str, Any]:
    extra_files = dict(extra_files or {})
    stage_root = stage.resolve()
    for rel in extra_files:
        relative = _portable_extra_path(rel)
        if (stage / relative).exists():
            raise ValueError("RELEASE_EVIDENCE_DUPLICATE_EXTRA_PATH")
    for rel in sorted(set(consume_files)):
        relative = _portable_extra_path(rel)
        path = stage / relative
        try:
            path.resolve().relative_to(stage_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ValueError("RELEASE_EVIDENCE_CONSUMED_PATH_INVALID") from exc
        if path.is_symlink() or not path.is_file():
            raise FileNotFoundError(rel)
        if rel in extra_files:
            raise ValueError("RELEASE_EVIDENCE_DUPLICATE_EXTRA_PATH")
        extra_files[rel] = path.read_bytes()
        path.unlink()
    manifest = bundle_manifest(stage, release_identity, extra_files)
    manifest_path = stage / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        disk_files = {
            path.relative_to(stage).as_posix(): path
            for path in stage.rglob("*")
            if path.is_file()
        }
        for rel in sorted(set(disk_files) | set(extra_files)):
            info = zipfile.ZipInfo(rel, (2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            payload = extra_files.get(rel)
            archive.writestr(info, payload if payload is not None else disk_files[rel].read_bytes())
    return {
        "path": str(output),
        "sha256": sha(output.read_bytes()),
        "file_count": manifest["file_count"],
        "manifest_sha256": sha(manifest_path.read_bytes()),
        "published": True,
    }
