#!/usr/bin/env python3
# ======================================================================
# release_integrity.py — версия 1.0
# Каноническая идентификация release source и проверка artifact provenance.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from rule_traceability_types import emits_diagnostic, enforces_rule

CANONICAL_ZIP_TIMESTAMP = (2020, 1, 1, 0, 0, 0)
HYGIENE_DIRS = {
    ".git", ".hg", ".svn", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    "__pycache__", ".venv", "venv", "env", "node_modules", "dist", "build",
}
HYGIENE_FILES = {".DS_Store", "Thumbs.db", "desktop.ini"}
HYGIENE_SUFFIXES = (".egg-info", ".dist-info")


@dataclass(frozen=True)
class SourceIdentity:
    records: list[dict[str, Any]]
    manifest_sha256: str
    git_repository: bool
    git_clean: bool | None
    commit_sha: str | None
    tree_sha: str | None
    git_mode_mismatches: list[dict[str, str]]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _skip_part(name: str) -> bool:
    return name in HYGIENE_DIRS or name in HYGIENE_FILES or name.endswith(HYGIENE_SUFFIXES) or name.endswith(".pyc")


def collect_entries(root: Path) -> list[Path]:
    """Collect shipped paths without following directory symlinks."""
    root = root.resolve()
    entries: list[Path] = []
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        kept_dirs: list[str] = []
        for name in sorted(dirs):
            p = current_path / name
            if _skip_part(name):
                continue
            if p.is_symlink():
                entries.append(p)
            else:
                kept_dirs.append(name)
        dirs[:] = kept_dirs
        for name in sorted(files):
            if _skip_part(name):
                continue
            entries.append(current_path / name)
    return sorted(entries, key=lambda p: p.relative_to(root).as_posix())


def canonical_mode(relative_path: str, data: bytes, *, is_symlink: bool = False) -> int:
    """Infer stable POSIX mode independent of extraction tool and umask."""
    if is_symlink:
        return 0o777
    normalized = relative_path.replace("\\", "/")
    is_launcher = "/bin/" in f"/{normalized}" or normalized.startswith("bin/")
    has_shebang = data.startswith(b"#!")
    return 0o755 if is_launcher or has_shebang else 0o644


def source_records(root: Path) -> list[dict[str, Any]]:
    root = root.resolve()
    records: list[dict[str, Any]] = []
    for path in collect_entries(root):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            target = os.readlink(path)
            payload = target.encode("utf-8")
            records.append({
                "path": rel,
                "type": "symlink",
                "sha256": sha256_bytes(payload),
                "size": len(payload),
                "mode": "0777",
                "symlink_target": target,
            })
        else:
            payload = path.read_bytes()
            mode = canonical_mode(rel, payload)
            records.append({
                "path": rel,
                "type": "file",
                "sha256": sha256_bytes(payload),
                "size": len(payload),
                "mode": f"{mode:04o}",
                "symlink_target": None,
            })
    return records


def manifest_digest(records: Iterable[dict[str, Any]]) -> str:
    payload = json.dumps(list(records), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def _git_value(root: Path, *args: str) -> str | None:
    try:
        proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout.strip() if proc.returncode == 0 else None


def git_tree_modes(root: Path, ref: str = "HEAD") -> dict[str, str]:
    """Return exact Git tree modes keyed by shipped path."""
    try:
        proc = subprocess.run(
            ["git", "ls-tree", "-rz", ref], cwd=root, capture_output=True, check=False,
        )
    except OSError:
        return {}
    if proc.returncode != 0:
        return {}
    result: dict[str, str] = {}
    for raw in proc.stdout.split(b"\0"):
        if not raw:
            continue
        metadata, path = raw.split(b"\t", 1)
        mode = metadata.split(b" ", 1)[0].decode("ascii")
        result[path.decode("utf-8", errors="surrogateescape")] = mode
    return result


@enforces_rule("APS-RELEASE-GIT-MODE-IDENTITY-001")
@emits_diagnostic("APS-RELEASE-GIT-MODE-IDENTITY-001", "RELEASE_SOURCE_GIT_MODE_VALID")
@emits_diagnostic("APS-RELEASE-GIT-MODE-IDENTITY-001", "RELEASE_SOURCE_GIT_MODE_MISMATCH")
def git_mode_mismatches(root: Path, records: list[dict[str, Any]], ref: str = "HEAD") -> list[dict[str, str]]:
    """Compare exact Git modes with canonical source/artifact modes."""
    modes = git_tree_modes(root, ref)
    if not modes:
        inside = _git_value(root, "rev-parse", "--is-inside-work-tree") == "true"
        if inside and records:
            return [{"path": "<git-tree>", "git_mode": "UNAVAILABLE", "artifact_mode": "UNVERIFIED"}]
        return []
    record_map = {str(item["path"]): item for item in records}
    findings: list[dict[str, str]] = []
    expected_mode = {"100644": "0644", "100755": "0755", "120000": "0777"}
    for path, git_mode in sorted(modes.items()):
        record = record_map.get(path)
        if record is None:
            findings.append({"path": path, "git_mode": git_mode, "artifact_mode": "MISSING"})
            continue
        artifact_mode = str(record.get("mode"))
        expected = expected_mode.get(git_mode)
        if expected is None or artifact_mode != expected:
            findings.append({"path": path, "git_mode": git_mode, "artifact_mode": artifact_mode})
    for path in sorted(record_map.keys() - modes.keys()):
        findings.append({"path": path, "git_mode": "MISSING", "artifact_mode": str(record_map[path].get("mode"))})
    return findings


def identify_source(root: Path) -> SourceIdentity:
    records = source_records(root)
    inside = _git_value(root, "rev-parse", "--is-inside-work-tree") == "true"
    commit = _git_value(root, "rev-parse", "HEAD") if inside else None
    tree = _git_value(root, "rev-parse", "HEAD^{tree}") if inside else None
    clean: bool | None = None
    if inside:
        status_text = _git_value(root, "status", "--porcelain", "--untracked-files=all")
        clean = status_text == "" if status_text is not None else False
    return SourceIdentity(
        records=records,
        manifest_sha256=manifest_digest(records),
        git_repository=inside,
        git_clean=clean,
        commit_sha=commit,
        tree_sha=tree,
        git_mode_mismatches=git_mode_mismatches(root, records) if inside else [],
    )


def compare_records(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> list[str]:
    b = {item["path"]: item for item in before}
    a = {item["path"]: item for item in after}
    findings: list[str] = []
    for path in sorted(b.keys() - a.keys()):
        findings.append(f"removed:{path}")
    for path in sorted(a.keys() - b.keys()):
        findings.append(f"added:{path}")
    for path in sorted(a.keys() & b.keys()):
        if a[path] != b[path]:
            findings.append(f"changed:{path}")
    return findings


def remove_release_workspace(workspace: Path, temp_root: Path) -> None:
    """Remove one verified temporary workspace without escaping its release root."""
    root = temp_root.resolve()
    candidate = workspace.resolve()
    if candidate == root or root not in candidate.parents:
        raise ValueError("RELEASE_TEMP_WORKSPACE_OUTSIDE_ROOT")
    if candidate.exists():
        shutil.rmtree(candidate)


def prune_release_temp(temp_root: Path, keep: Path) -> None:
    """Remove completed release scratch data while preserving one evidence tree."""
    root = temp_root.resolve()
    kept = keep.resolve()
    if root not in kept.parents:
        raise ValueError("RELEASE_TEMP_KEEP_OUTSIDE_ROOT")
    for child in root.iterdir():
        if child.resolve() == kept:
            continue
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def copy_release_tree(source: Path, destination: Path) -> None:
    """Create a pristine canonical copy containing only shipped entries."""
    source = source.resolve()
    destination.mkdir(parents=True, exist_ok=False)
    for path in collect_entries(source):
        rel = path.relative_to(source)
        target = destination / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if path.is_symlink():
            target.symlink_to(os.readlink(path))
            continue
        data = path.read_bytes()
        target.write_bytes(data)
        target.chmod(canonical_mode(rel.as_posix(), data))


def artifact_records(zip_path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with zipfile.ZipFile(zip_path) as zf:
        for info in sorted(zf.infolist(), key=lambda item: item.filename):
            if info.is_dir():
                continue
            data = zf.read(info)
            raw_mode = (info.external_attr >> 16) & 0xFFFF
            is_symlink = stat.S_ISLNK(raw_mode)
            mode = raw_mode & 0o777
            records.append({
                "path": info.filename,
                "type": "symlink" if is_symlink else "file",
                "sha256": sha256_bytes(data),
                "size": len(data),
                "mode": f"{mode:04o}",
                "symlink_target": data.decode("utf-8") if is_symlink else None,
            })
    return records


def verify_artifact_matches_source(source: list[dict[str, Any]], zip_path: Path) -> list[str]:
    return compare_records(source, artifact_records(zip_path))


def extract_python(zip_path: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(destination)


def perturb_metadata(root: Path) -> None:
    """Change mtimes and regular-file permissions to test metadata independence."""
    for index, path in enumerate(collect_entries(root), start=1):
        if path.is_symlink():
            continue
        timestamp = 946684800 + index
        os.utime(path, (timestamp, timestamp))
        path.chmod(0o600)
