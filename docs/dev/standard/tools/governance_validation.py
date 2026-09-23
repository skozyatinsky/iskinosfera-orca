#!/usr/bin/env python3
# ======================================================================
# governance_validation.py — версия 1.0
# Семантическая проверка trusted control plane для v2.9.128.
# ======================================================================
from __future__ import annotations

import fnmatch
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from jsonschema import Draft7Validator
except ImportError:  # pragma: no cover
    Draft7Validator = None


@dataclass(frozen=True)
class GovernanceClass:
    class_id: str
    required_all_of: tuple[str, ...]
    required_any_of: tuple[str, ...]
    allowed_patterns: tuple[str, ...]
    required_schema: str | None
    must_exist: bool
    must_resolve: bool
    minimum_resolved_files: int
    exclusive: bool
    allow_shared_paths_with: tuple[str, ...]
    read_by_validators: tuple[str, ...]


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def _safe(path: str) -> bool:
    return bool(path) and not Path(path).is_absolute() and ".." not in PurePosixPath(path.replace("\\", "/")).parts


def _base(root: Path, schemas_root: Path | None, rel: str) -> Path:
    if (root / rel).exists():
        return root
    if schemas_root is not None and rel.startswith(("schemas/", "reference/", "tools/")):
        return schemas_root.parent
    return root


def _resolve(root: Path, schemas_root: Path | None, pattern: str) -> list[Path]:
    base = _base(root, schemas_root, pattern)
    if any(char in pattern for char in "*?["):
        return sorted(path for path in base.glob(pattern) if path.exists())
    path = base / pattern
    return [path] if path.exists() else []


def _matches(path: str, pattern: str) -> bool:
    normalized = path.replace("\\", "/")
    return fnmatch.fnmatchcase(normalized, pattern) or PurePosixPath(normalized).match(pattern)


def _schema_findings(data: Any, schema_path: Path, prefix: str) -> list[str]:
    if Draft7Validator is None:
        return [f"GOVERNANCE_SCHEMA_VALIDATOR_UNAVAILABLE:{prefix}"]
    schema, error = _load_json(schema_path)
    if error or not isinstance(schema, dict):
        return [f"GOVERNANCE_SCHEMA_READ_FAILED:{prefix}:{error}"]
    findings: list[str] = []
    for issue in sorted(Draft7Validator(schema).iter_errors(data), key=lambda item: list(item.absolute_path)):
        location = "/".join(str(part) for part in issue.absolute_path) or "$"
        findings.append(f"GOVERNANCE_SCHEMA_MISMATCH:{prefix}:{location}:{issue.message}")
    return findings


def _load_registry(root: Path, schemas_root: Path | None) -> tuple[dict[str, Any] | None, list[str]]:
    standard_root = schemas_root.parent if schemas_root is not None else root
    path = standard_root / "reference/governance_class_registry.json"
    data, error = _load_json(path)
    if error or not isinstance(data, dict):
        return None, [f"CONTROL_PLANE_NOT_TRUSTED: governance class registry unavailable: {error}"]
    schema_path = standard_root / "schemas/governance_class_registry.schema.json"
    findings = _schema_findings(data, schema_path, "governance_class_registry") if schema_path.exists() else [
        "CONTROL_PLANE_NOT_TRUSTED: governance class registry schema missing"
    ]
    return data, findings


def _definitions(registry: dict[str, Any]) -> dict[str, GovernanceClass]:
    result: dict[str, GovernanceClass] = {}
    for raw in registry.get("classes", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("class_id"), str):
            continue
        item = GovernanceClass(
            class_id=raw["class_id"], required_all_of=tuple(raw.get("required_all_of", [])),
            required_any_of=tuple(raw.get("required_any_of", [])), allowed_patterns=tuple(raw.get("allowed_patterns", [])),
            required_schema=raw.get("required_schema") if isinstance(raw.get("required_schema"), str) else None,
            must_exist=raw.get("must_exist", True) is True, must_resolve=raw.get("must_resolve", True) is True,
            minimum_resolved_files=int(raw.get("minimum_resolved_files", 1)), exclusive=raw.get("exclusive", False) is True,
            allow_shared_paths_with=tuple(raw.get("allow_shared_paths_with", [])),
            read_by_validators=tuple(raw.get("read_by_validators", [])),
        )
        result[item.class_id] = item
    return result


def _validate_paths(
    root: Path, schemas_root: Path | None, prefix: str, class_id: str, definition: GovernanceClass,
    paths: list[str], protected: set[str], resolved: set[str], findings: list[str],
) -> None:
    for rel in paths:
        if not _safe(rel):
            findings.append(f"GOVERNANCE_CLASS_SEMANTIC_MISMATCH:{prefix}:{class_id}:unsafe path:{rel}")
            continue
        if rel not in protected:
            findings.append(f"GOVERNANCE_CLASS_SEMANTIC_MISMATCH:{prefix}:{class_id}:unprotected path:{rel}")
        if definition.allowed_patterns and not any(_matches(rel, pattern) for pattern in definition.allowed_patterns):
            findings.append(f"GOVERNANCE_CLASS_SEMANTIC_MISMATCH:{prefix}:{class_id}:path not allowed:{rel}")
        matches = _resolve(root, schemas_root, rel)
        if definition.must_resolve and not matches:
            findings.append(f"GOVERNANCE_PATH_NOT_RESOLVED:{prefix}:{class_id}:{rel}")
        for match in matches:
            base = _base(root, schemas_root, rel)
            try:
                match.resolve(strict=True).relative_to(base.resolve(strict=True))
            except (OSError, ValueError):
                findings.append(f"GOVERNANCE_PATH_SYMLINK_ESCAPE:{prefix}:{class_id}:{rel}")
                continue
            resolved.add(match.relative_to(base).as_posix())


def _validate_requirements(prefix: str, class_id: str, definition: GovernanceClass, paths: list[str], resolved: set[str], findings: list[str]) -> None:
    for required in definition.required_all_of:
        if required not in paths:
            findings.append(f"GOVERNANCE_REQUIRED_PATH_MISSING:{prefix}:{class_id}:{required}")
    if definition.required_any_of and not any(candidate in paths for candidate in definition.required_any_of):
        findings.append(f"GOVERNANCE_REQUIRED_PATH_MISSING:{prefix}:{class_id}:one-of:{list(definition.required_any_of)}")
    if definition.must_exist and len(resolved) < definition.minimum_resolved_files:
        findings.append(f"GOVERNANCE_PATH_NOT_RESOLVED:{prefix}:{class_id}:minimum={definition.minimum_resolved_files}:actual={len(resolved)}")


def _validate_schema_binding(root: Path, schemas_root: Path | None, prefix: str, class_id: str, definition: GovernanceClass, paths: list[str], findings: list[str]) -> None:
    standard_root = schemas_root.parent if schemas_root is not None else root
    if definition.required_schema:
        schema_path = standard_root / definition.required_schema
        if not schema_path.exists():
            findings.append(f"GOVERNANCE_SCHEMA_MISMATCH:{prefix}:{class_id}:schema missing:{definition.required_schema}")
        else:
            for rel in paths:
                if any(char in rel for char in "*?[") or not rel.endswith(".json"):
                    continue
                target = _base(root, schemas_root, rel) / rel
                if target.exists():
                    data, error = _load_json(target)
                    findings.extend([f"GOVERNANCE_SCHEMA_MISMATCH:{prefix}:{class_id}:{rel}:{error}"] if error else _schema_findings(data, schema_path, f"{class_id}:{rel}"))
    validator_candidates = [
        standard_root / "tools/validate_structure.py",
        Path(__file__).resolve().parent / "validate_structure.py",
    ]
    validator_text = "\n".join(
        candidate.read_text(encoding="utf-8", errors="ignore")
        for candidate in validator_candidates
        if candidate.exists()
    )
    for flag in definition.read_by_validators:
        if flag not in validator_text:
            findings.append(f"GOVERNANCE_VALIDATOR_BINDING_MISSING:{prefix}:{class_id}:{flag}")


def _collision_findings(prefix: str, definitions: dict[str, GovernanceClass], resolved: dict[str, set[str]]) -> list[str]:
    findings: list[str] = []
    class_ids = sorted(resolved)
    for index, left_id in enumerate(class_ids):
        left = definitions.get(left_id)
        if left is None or not left.exclusive:
            continue
        for right_id in class_ids[index + 1:]:
            right = definitions.get(right_id)
            if right is None or not right.exclusive or right_id in left.allow_shared_paths_with or left_id in right.allow_shared_paths_with:
                continue
            shared = sorted(resolved[left_id] & resolved[right_id])
            if shared:
                findings.append(f"GOVERNANCE_CLASS_COLLISION:{prefix}:{left_id}:{right_id}:{shared}")
    return findings


def semantic_control_plane_findings(root: Path, manifest: dict[str, Any], schemas_root: Path | None, *, prefix: str = "control-plane") -> list[str]:
    registry, findings = _load_registry(root, schemas_root)
    if registry is None:
        return findings
    classes = manifest.get("governance_classes")
    protected = manifest.get("governance_paths")
    if not isinstance(classes, dict) or not isinstance(protected, list):
        return [*findings, f"CONTROL_PLANE_NOT_TRUSTED:{prefix}:missing classes or paths"]
    definitions = _definitions(registry)
    mandatory = set(registry.get("mandatory_class_ids", []))
    missing = sorted(mandatory - set(classes))
    if missing:
        findings.append(f"CONTROL_PLANE_NOT_TRUSTED:{prefix}:mandatory classes missing:{missing}")
    resolved: dict[str, set[str]] = defaultdict(set)
    manifest_path = "docs/registry/control_plane_manifest.json"
    for class_id in sorted(mandatory & set(classes)):
        definition, values = definitions.get(class_id), classes.get(class_id)
        if definition is None or not isinstance(values, list) or not values or not all(isinstance(value, str) and value.strip() for value in values):
            findings.append(f"GOVERNANCE_CLASS_SEMANTIC_MISMATCH:{prefix}:{class_id}:undefined or empty mapping")
            continue
        paths = [value.replace("\\", "/") for value in values]
        if class_id != "control_plane_manifest" and set(paths) == {manifest_path}:
            findings.append(f"GOVERNANCE_CLASS_SELF_ALIAS:{prefix}:{class_id}:{manifest_path}")
        _validate_paths(root, schemas_root, prefix, class_id, definition, paths, {item for item in protected if isinstance(item, str)}, resolved[class_id], findings)
        _validate_requirements(prefix, class_id, definition, paths, resolved[class_id], findings)
        _validate_schema_binding(root, schemas_root, prefix, class_id, definition, paths, findings)
    findings.extend(_collision_findings(prefix, definitions, resolved))
    if mandatory and all(set(classes.get(class_id, [])) == {manifest_path} for class_id in mandatory):
        findings.append(f"GOVERNANCE_CLASS_SELF_ALIAS:{prefix}:all classes alias manifest")
    if findings:
        findings.append(f"CONTROL_PLANE_NOT_TRUSTED:{prefix}:semantic validation failed")
    return sorted(set(findings))
