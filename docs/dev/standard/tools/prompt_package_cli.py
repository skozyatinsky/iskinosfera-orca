#!/usr/bin/env python3
# ======================================================================
# prompt_package_cli.py — версия 1.0
# CLI для prompt package: generate, validate, package.
# ======================================================================
from __future__ import annotations

import argparse
import json
from pathlib import Path

from prompt_package import build_prompt_archive, generate_entrypoints, validate_package, write_lock


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("generate", "validate", "package"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--output")
    parser.add_argument("--refresh-lock", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if args.command == "generate":
        if args.refresh_lock:
            write_lock(root)
        paths = generate_entrypoints(root)
        print(json.dumps({"status": "PASS", "generated": [str(p.relative_to(root)) for p in paths]}, ensure_ascii=False, indent=2))
        return 0
    if args.command == "validate":
        findings = validate_package(root)
        errors = [item for item in findings if item.severity == "ERROR"]
        print(json.dumps({"status": "PASS" if not errors else "FAIL", "findings": [item.as_dict() for item in findings]}, ensure_ascii=False, indent=2))
        return 0 if not errors else 1
    if not args.output:
        parser.error("--output is required for package")
    result = build_prompt_archive(root, Path(args.output).resolve())
    print(json.dumps({"status": "PASS", **result}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
