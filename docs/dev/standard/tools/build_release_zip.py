#!/usr/bin/env python3
# ======================================================================
# build_release_zip.py — версия 2.0
# Tool-independent reproducible ZIP builder with canonical metadata.
# ======================================================================

from __future__ import annotations

import argparse
import os
import stat
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from release_integrity import (  # noqa: E402
    CANONICAL_ZIP_TIMESTAMP,
    canonical_mode,
    collect_entries,
)


def _zip_info(relative: str, *, mode: int, is_symlink: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(relative, date_time=CANONICAL_ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    file_type = stat.S_IFLNK if is_symlink else stat.S_IFREG
    info.external_attr = (file_type | mode) << 16
    info.flag_bits |= 0x800
    return info


def build_zip(root: Path, output: Path) -> int:
    root = root.resolve()
    output = output.resolve()
    try:
        output.relative_to(root)
    except ValueError:
        pass
    else:
        raise ValueError("release output must be outside source root")

    entries = collect_entries(root)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as zf:
        for path in entries:
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                payload = os.readlink(path).encode("utf-8")
                info = _zip_info(relative, mode=0o777, is_symlink=True)
            else:
                payload = path.read_bytes()
                info = _zip_info(relative, mode=canonical_mode(relative, payload), is_symlink=False)
            zf.writestr(info, payload, compress_type=zipfile.ZIP_STORED)
    return len(entries)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(args.root)
    if not root.is_dir():
        print(f"нет такого каталога: {root}", file=sys.stderr)
        return 1
    try:
        count = build_zip(root, Path(args.output))
    except (OSError, ValueError) as exc:
        print(f"release build failed: {exc}", file=sys.stderr)
        return 1
    print(f"Собрано {count} файлов -> {Path(args.output).resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
