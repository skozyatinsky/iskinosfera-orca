"""Helpers for binding a release package to an enclosing Git repository."""

from __future__ import annotations

import hashlib
import io
import json
import shutil
import subprocess
import tempfile
import unicodedata
import zipfile
from dataclasses import replace
from pathlib import Path, PurePosixPath
from typing import Any

from release_integrity import (
    canonical_mode,
    compare_records,
    copy_release_tree,
    git_mode_mismatches,
    identify_source,
    manifest_digest,
)


_WINDOWS_RESERVED_NAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
}


def git_package_root_relative(root: Path) -> str:
    """Return the package path inside the enclosing Git repository."""
    proc = subprocess.run(
        ["git", "rev-parse", "--show-prefix"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError("RELEASE_SOURCE_GIT_PREFIX_UNAVAILABLE")
    raw = proc.stdout.strip().rstrip("/") or "."
    relative = package_root_relative({"source": {"package_root_relative": raw}})
    if relative is None:
        raise RuntimeError("RELEASE_SOURCE_GIT_PREFIX_INVALID")
    return relative.as_posix()


def source_bundle_filter_arg(records: list[dict[str, Any]]) -> str:
    """Include every package blob while omitting larger blobs outside it."""
    return f"blob:limit={_largest_blob_size(records) + 1}"


def _largest_blob_size(records: list[dict[str, Any]]) -> int:
    return max(
        (
            int(item.get("size", 0))
            for item in records
            if item.get("type") in {"file", "symlink"}
        ),
        default=0,
    )


def package_root_relative(identity: dict[str, Any]) -> PurePosixPath | None:
    raw = identity.get("source", {}).get("package_root_relative", ".")
    if (
        not isinstance(raw, str)
        or not raw
        or "\x00" in raw
        or "\\" in raw
        or ":" in raw
    ):
        return None
    try:
        relative = PurePosixPath(raw)
    except (TypeError, ValueError):
        return None
    if raw == ".":
        return relative
    try:
        _portable_tree_path(raw.encode("utf-8"))
    except (UnicodeEncodeError, ValueError):
        return None
    if (
        relative.is_absolute()
        or relative.as_posix() != raw
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        return None
    return relative


def package_tree_ref(identity: dict[str, Any], ref: str = "HEAD") -> str | None:
    relative = package_root_relative(identity)
    if relative is None:
        return None
    return ref if relative.as_posix() == "." else f"{ref}:{relative.as_posix()}"


def _portable_tree_path(raw_path: bytes) -> str:
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID") from exc
    relative = PurePosixPath(path)
    for part in relative.parts:
        stem = part.split(".", 1)[0].casefold()
        if (
            not part
            or part in {".", ".."}
            or part.casefold() == ".git"
            or part[-1:] in {" ", "."}
            or stem in _WINDOWS_RESERVED_NAMES
            or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
        ):
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
    if not path or "\\" in path or relative.is_absolute() or relative.as_posix() != path:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
    return path


def _register_portable_tree_path(
    path: str,
    files: set[str],
    directories: dict[str, str],
) -> None:
    portable = unicodedata.normalize("NFC", path).casefold()
    portable_parts = portable.split("/")
    raw_parts = path.split("/")
    prefixes = {
        "/".join(portable_parts[:index]): "/".join(raw_parts[:index])
        for index in range(1, len(portable_parts))
    }
    if portable in files or portable in directories or prefixes.keys() & files:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
    if any(key in directories and directories[key] != raw for key, raw in prefixes.items()):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
    files.add(portable)
    for key, raw in prefixes.items():
        directories.setdefault(key, raw)


def _filtered_pack(payload: bytes, records: list[dict[str, Any]]) -> bytes | None:
    boundary = payload.find(b"\n\n")
    if boundary < 0 or payload[boundary + 2 : boundary + 6] != b"PACK":
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_HEADER_INVALID")
    try:
        header = payload[:boundary].decode("ascii").splitlines()
    except UnicodeDecodeError as exc:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_HEADER_INVALID") from exc
    filters = [line.removeprefix("@filter=") for line in header if line.startswith("@filter=")]
    if not filters:
        return None
    if len(filters) != 1 or not filters[0].startswith("blob:limit="):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_FILTER_INVALID")
    raw_limit = filters[0].removeprefix("blob:limit=")
    if not raw_limit.isdigit():
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_FILTER_INVALID")
    limit = int(raw_limit)
    if limit <= _largest_blob_size(records):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_FILTER_INVALID")
    return payload[boundary + 2 :]


def _install_filtered_pack(checkout: Path, temp: Path, pack_payload: bytes) -> None:
    pack = temp / "source.pack"
    pack.write_bytes(pack_payload)
    indexed = subprocess.run(
        ["git", "index-pack", "--promisor", str(pack)],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )
    pack_hash = indexed.stdout.strip()
    if len(pack_hash) != 40 or any(char not in "0123456789abcdef" for char in pack_hash):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_PACK_INVALID")
    target = checkout / ".git" / "objects" / "pack"
    for suffix in (".pack", ".idx", ".promisor"):
        source = pack.with_suffix(suffix)
        if not source.is_file():
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_PACK_INVALID")
        shutil.move(str(source), target / f"pack-{pack_hash}{suffix}")


def _git_tree_blobs(
    checkout: Path,
    tree_ref: str,
) -> list[tuple[str, str, bytes]]:
    listed = subprocess.run(
        ["git", "ls-tree", "-rlz", tree_ref],
        cwd=checkout,
        check=True,
        capture_output=True,
    )
    metadata: list[tuple[str, str, bytes, int]] = []
    portable_files: set[str] = set()
    portable_directories: dict[str, str] = {}
    for raw in listed.stdout.split(b"\0"):
        if not raw:
            continue
        fields, raw_path = raw.split(b"\t", 1)
        parts = fields.split()
        if len(parts) != 4 or parts[1] != b"blob" or parts[0] not in {b"100644", b"100755", b"120000"}:
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
        path = _portable_tree_path(raw_path)
        relative = PurePosixPath(path)
        if (
            relative.is_absolute()
            or relative.as_posix() != path
        ):
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
        _register_portable_tree_path(path, portable_files, portable_directories)
        metadata.append((path, parts[0].decode("ascii"), parts[2], int(parts[3])))
    loaded = subprocess.run(
        ["git", "cat-file", "--batch"],
        cwd=checkout,
        input=b"".join(oid + b"\n" for _, _, oid, _ in metadata),
        capture_output=True,
    )
    if loaded.returncode != 0:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_PACK_INVALID")
    stream = io.BytesIO(loaded.stdout)
    result: list[tuple[str, str, bytes]] = []
    for path, mode, oid, declared_size in metadata:
        header = stream.readline().rstrip(b"\n").split()
        if len(header) != 3 or header[0] != oid or header[1] != b"blob":
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_PACK_INVALID")
        size = int(header[2])
        payload = stream.read(size)
        if size != declared_size or len(payload) != size or stream.read(1) != b"\n":
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_PACK_INVALID")
        result.append((path, mode, payload))
    if stream.read(1):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_PACK_INVALID")
    return result


def _git_blob_records(blobs: list[tuple[str, str, bytes]]) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path, git_mode, payload in blobs:
        is_symlink = git_mode == "120000"
        target = payload.decode("utf-8", errors="surrogateescape") if is_symlink else None
        mode = 0o777 if is_symlink else canonical_mode(path, payload)
        records.append({
            "path": path,
            "type": "symlink" if is_symlink else "file",
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
            "mode": f"{mode:04o}",
            "symlink_target": target,
        })
    return records


def _materialize_package(
    temp: Path,
    blobs: list[tuple[str, str, bytes]],
) -> Path:
    package = temp / "package_snapshot"
    return _write_package(package, blobs)


def _write_package(
    package: Path,
    blobs: list[tuple[str, str, bytes]],
) -> Path:
    package.mkdir()
    for path, git_mode, payload in blobs:
        if git_mode == "120000":
            raise ValueError("RELEASE_SOURCE_SYMLINK_UNSUPPORTED")
        destination = package.joinpath(*PurePosixPath(path).parts)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() or destination.is_symlink():
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_TREE_INVALID")
        destination.write_bytes(payload)
        destination.chmod(0o755 if git_mode == "100755" else 0o644)
    return package


def identify_release_source(root: Path) -> Any:
    """Bind a clean Git source to canonical blob bytes, not checkout filters."""
    identity = identify_source(root)
    if not identity.git_repository:
        return identity
    try:
        records = _git_blob_records(_git_tree_blobs(root, "HEAD"))
    except (OSError, ValueError, subprocess.CalledProcessError):
        unavailable = [{
            "path": "<git-objects>",
            "git_mode": "UNAVAILABLE",
            "artifact_mode": "UNVERIFIED",
        }]
        return replace(identity, git_mode_mismatches=unavailable)
    return replace(
        identity,
        records=records,
        manifest_sha256=manifest_digest(records),
        git_mode_mismatches=git_mode_mismatches(root, records),
    )


def copy_release_source(root: Path, destination: Path, identity: Any) -> None:
    """Create a deterministic source snapshot from Git blobs when available."""
    if not identity.git_repository:
        copy_release_tree(root, destination)
        return
    ref = identity.commit_sha or "HEAD"
    _write_package(destination, _git_tree_blobs(root, ref))


def committed_source_unchanged(root: Path, expected: Any) -> bool:
    current = identify_release_source(root)
    package_status = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=all", "--", "."],
        cwd=root, capture_output=True, text=True,
    ) if expected.git_repository else None
    return (
        not compare_records(expected.records, current.records)
        and current.commit_sha == expected.commit_sha
        and current.tree_sha == expected.tree_sha
        and (
            not expected.git_repository
            or package_status is not None
            and package_status.returncode == 0
            and package_status.stdout.strip() == ""
        )
    )


def checkout_git_bundle_package(
    payload: bytes,
    identity: dict[str, Any],
    records: list[dict[str, Any]],
    temp: Path,
) -> tuple[Path, Path, str, str]:
    """Restore only the governed package from a full or filtered bundle."""
    source = identity.get("source", {})
    if hashlib.sha256(payload).hexdigest() != source.get("git_bundle_sha256"):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_SHA_MISMATCH")
    filtered_pack = _filtered_pack(payload, records)
    bundle = temp / "source.bundle"
    checkout = temp / "checkout"
    bundle.write_bytes(payload)
    subprocess.run(["git", "init", "-q", str(checkout)], check=True, capture_output=True)
    verified = subprocess.run(
        ["git", "-C", str(checkout), "bundle", "verify", str(bundle)],
        capture_output=True,
        text=True,
    )
    if verified.returncode != 0:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_INVALID")
    listed = subprocess.run(
        ["git", "bundle", "list-heads", str(bundle), "HEAD"],
        cwd=checkout,
        capture_output=True,
        text=True,
    )
    head_lines = [line.split() for line in listed.stdout.splitlines() if line.strip()]
    if (
        listed.returncode != 0
        or len(head_lines) != 1
        or len(head_lines[0]) != 2
        or head_lines[0][1] != "HEAD"
        or len(head_lines[0][0]) != 40
        or any(char not in "0123456789abcdef" for char in head_lines[0][0])
    ):
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_HEAD_INVALID")
    advertised_head = head_lines[0][0]
    if filtered_pack is None:
        fetched = subprocess.run(
            ["git", "-C", str(checkout), "fetch", "-q", str(bundle), "HEAD"],
            capture_output=True,
            text=True,
        )
        if fetched.returncode != 0:
            raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_INVALID")
        commit_ref = advertised_head
        package_ref = package_tree_ref(identity, advertised_head)
    else:
        commit_ref = advertised_head
        _install_filtered_pack(checkout, temp, filtered_pack)
        package_ref = package_tree_ref(identity, advertised_head)
    if package_ref is None:
        raise ValueError("RELEASE_SOURCE_GIT_BUNDLE_RECORDS_MISMATCH")
    package = _materialize_package(temp, _git_tree_blobs(checkout, package_ref))
    return checkout, package, commit_ref, package_ref


def verify_git_bundle(
    archive: zipfile.ZipFile,
    identity: dict[str, Any],
    records: list[dict[str, Any]],
) -> list[str]:
    if not isinstance(records, list) or any(not isinstance(item, dict) for item in records):
        return ["RELEASE_SOURCE_GIT_BUNDLE_RECORDS_MISMATCH"]
    source = identity.get("source", {})
    bundle_path = source.get("git_bundle")
    if not isinstance(bundle_path, str):
        return ["RELEASE_SOURCE_GIT_BUNDLE_MISSING"]
    try:
        payload = archive.read(bundle_path)
    except KeyError:
        return ["RELEASE_SOURCE_GIT_BUNDLE_MISSING"]
    try:
        with tempfile.TemporaryDirectory(prefix="aps_receipt_git_") as raw:
            temp = Path(raw)
            checkout, package_checkout, commit_ref, package_ref = checkout_git_bundle_package(
                payload, identity, records, temp,
            )
            commit = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", f"{commit_ref}^{{commit}}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            tree = subprocess.run(
                ["git", "-C", str(checkout), "rev-parse", f"{commit_ref}^{{tree}}"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            findings: list[str] = []
            if commit != source.get("commit_sha"):
                findings.append("RELEASE_SOURCE_COMMIT_MISMATCH")
            if tree != source.get("tree_sha"):
                findings.append("RELEASE_SOURCE_TREE_MISMATCH")
            checked_records = _git_blob_records(_git_tree_blobs(checkout, package_ref))
            if compare_records(records, checked_records):
                findings.append("RELEASE_SOURCE_GIT_BUNDLE_RECORDS_MISMATCH")
            if manifest_digest(checked_records) != source.get("manifest_sha256"):
                findings.append("RELEASE_SOURCE_MANIFEST_MISMATCH")
            if git_mode_mismatches(checkout, records, ref=package_ref):
                findings.append("RELEASE_SOURCE_GIT_MODE_MISMATCH")
            try:
                manifest_path = package_checkout / "manifest.json"
                source_manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                findings.append("RELEASE_SOURCE_MANIFEST_INVALID")
            else:
                if source_manifest.get("version") != identity.get("standard_version"):
                    findings.append("RELEASE_STANDARD_VERSION_MISMATCH")
            return findings
    except ValueError as exc:
        code = str(exc)
        if code.startswith("RELEASE_SOURCE_"):
            return [code]
        return ["RELEASE_SOURCE_GIT_BUNDLE_VERIFICATION_FAILED"]
    except (OSError, RuntimeError, subprocess.CalledProcessError):
        return ["RELEASE_SOURCE_GIT_BUNDLE_VERIFICATION_FAILED"]
