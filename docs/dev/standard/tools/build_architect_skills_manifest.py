#!/usr/bin/env python3
# ======================================================================
# build_architect_skills_manifest.py — версия 1.0
# Deterministically inventories Architector skills without activating them.
# ======================================================================
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def load_quarantined_ids(profile_path: Path) -> set[str]:
    """Карантин объявляет профиль проекта, а не константа в инструменте.

    До v2.9.162 здесь лежало ``{"skill-the-humanizer"}`` — идентификатор с
    префиксом, которого не бывает: ``skill_id`` берётся из имени каталога.
    Константа не совпадала ни с чем и молча не работала с момента появления,
    а заодно держала данные одного проекта в общем инструменте.
    """
    if not profile_path.is_file():
        return set()
    try:
        data = json.loads(profile_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return set()
    declared = data.get("quarantined_skill_ids", []) if isinstance(data, dict) else []
    return {item for item in declared if isinstance(item, str)}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_license_ledger(path: Path | None) -> dict[str, dict[str, Any]]:
    if path is None or not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    entries = data.get("skills", []) if isinstance(data, dict) else []
    return {
        str(item.get("skill_id")): item
        for item in entries
        if isinstance(item, dict) and item.get("skill_id")
    }


def _entry(root: Path, skill_file: Path, skill_id: str, license_entry: dict[str, Any],
           quarantined_ids: set[str]) -> dict[str, Any]:
    quarantined = skill_id in quarantined_ids or license_entry.get("license_status") == "QUARANTINED"
    status = "QUARANTINED" if quarantined else license_entry.get("license_status", "UNKNOWN")
    return {
        "skill_id": skill_id,
        "canonical_path": skill_file.relative_to(root).as_posix(),
        "root_exposure_path": f".claude/skills/{skill_id}/SKILL.md",
        "source": str(license_entry.get("source", "UNRESOLVED")),
        "version": str(license_entry.get("version", "UNVERSIONED")),
        "license_status": status,
        "installable": bool(license_entry.get("installable", False)) and not quarantined,
        "client_distribution_allowed": bool(license_entry.get("client_distribution_allowed", False)) and not quarantined,
        "sha256": sha256(skill_file),
    }


def build_manifest(root: Path, source_root: Path, ledger: dict[str, dict[str, Any]],
                   quarantined_ids: set[str] | None = None) -> dict[str, Any]:
    quarantined_ids = quarantined_ids or set()
    skills: list[dict[str, Any]] = []
    seen: set[str] = set()
    for skill_file in sorted(source_root.rglob("SKILL.md")):
        skill_id = skill_file.parent.name
        skills.append(_entry(root, skill_file, skill_id, ledger.get(skill_id, {}), quarantined_ids))
        seen.add(skill_id)

    # Карантинный скил не выставлен в корне — иначе он не был бы в карантине.
    # Но в манифесте он обязан быть: именно там проверяющий убеждается, что он
    # не выставлен, не устанавливается и не уходит клиенту. Где он лежит,
    # объявляет реестр лицензий полем canonical_path.
    for skill_id, license_entry in sorted(ledger.items()):
        if skill_id in seen:
            continue
        if skill_id not in quarantined_ids and license_entry.get("license_status") != "QUARANTINED":
            continue
        declared = license_entry.get("canonical_path")
        if not isinstance(declared, str) or not declared:
            continue
        skill_file = root / declared
        if not skill_file.is_file():
            continue
        skills.append(_entry(root, skill_file, skill_id, license_entry, quarantined_ids))
        seen.add(skill_id)

    skills.sort(key=lambda item: item["skill_id"])
    return {"schema_version": 1, "skills": skills}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--source", default="_architect/.claude/skills")
    parser.add_argument("--license-ledger", default="docs/registry/architect_license_ledger.json")
    parser.add_argument("--profile", default="docs/registry/architect_library_profile.json")
    parser.add_argument("--output", default="docs/registry/architect_skills_manifest.json")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    source = root / args.source
    if not source.is_dir():
        print(f"skill source directory not found: {source}")
        return 1
    ledger = load_license_ledger(root / args.license_ledger)
    quarantined_ids = load_quarantined_ids(root / args.profile)
    data = build_manifest(root, source, ledger, quarantined_ids)
    output = root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": "PASS", "count": len(data["skills"]), "output": args.output}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
