#!/usr/bin/env python3
# ======================================================================
# dead_code_evidence.py — версия 1.0
# Typed evidence resolver for dead-code entrypoint, public API and
# bounded allowlist contracts.
# ======================================================================
from __future__ import annotations

# ======================================================================
# 1. IMPORTS
# ======================================================================
import ast
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from jsonschema import Draft202012Validator

from junit_evidence import parse_junit

from rule_traceability_types import emits_diagnostic, enforces_rule


# ======================================================================
# 2. CONSTANTS AND IN-PROCESS CACHE
# ======================================================================
PRIMARY_CONTRACT_TYPES = {"entrypoint", "public_api", "migration", "deprecation", "trusted_manifest"}
PRODUCTION_ROOT_CONTRACT_TYPES = {"entrypoint", "public_api", "migration", "deprecation"}
EVIDENCE_KINDS = {"json_pointer", "markdown_anchor", "test_node"}


# ======================================================================
# 3. SAFE PATH AND SELECTOR HELPERS
# ======================================================================
def _safe_relative_path(value: str) -> bool:
    path = PurePosixPath(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts and "\\" not in value


def _subject(item: dict[str, Any]) -> tuple[str, str]:
    subject = item.get("subject")
    if not isinstance(subject, dict):
        return "", ""
    return str(subject.get("path", "")), str(subject.get("symbol", ""))


def _resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must be empty or start with '/'.")
    current = document
    for raw in pointer.split("/")[1:]:
        token = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            if not token.isdigit():
                raise ValueError("JSON pointer list token must be an integer.")
            index = int(token)
            if index >= len(current):
                raise ValueError("JSON pointer list index is out of range.")
            current = current[index]
        elif isinstance(current, dict):
            if token not in current:
                raise ValueError("JSON pointer object key does not exist.")
            current = current[token]
        else:
            raise ValueError("JSON pointer traverses a scalar value.")
    return current


def _slugify_heading(value: str) -> str:
    normalized = value.strip().casefold()
    normalized = re.sub(r"[^\w\- ]+", "", normalized, flags=re.UNICODE)
    normalized = re.sub(r"[\s\-]+", "-", normalized)
    return normalized.strip("-")


def _markdown_section(text: str, anchor: str) -> str | None:
    lines = text.splitlines()
    start = None
    level = None
    for index, line in enumerate(lines):
        match = re.match(r"^(#{1,6})\s+(.+?)\s*$", line)
        if match and _slugify_heading(match.group(2)) == anchor:
            start = index
            level = len(match.group(1))
            break
    if start is None or level is None:
        return None
    end = len(lines)
    for index in range(start + 1, len(lines)):
        match = re.match(r"^(#{1,6})\s+", lines[index])
        if match and len(match.group(1)) <= level:
            end = index
            break
    return "\n".join(lines[start:end])


def _test_function_docstring(root: Path, node_id: str) -> str | None:
    try:
        parts = node_id.split("::")
        if len(parts) < 2:
            return None
        relative = parts[0]
        path = root / relative
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=relative)
    except (OSError, UnicodeDecodeError, SyntaxError):
        return None
    nodes: list[ast.AST] = list(tree.body)
    selected: ast.AST | None = None
    for name in parts[1:]:
        selected = next(
            (
                node
                for node in nodes
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name
            ),
            None,
        )
        if selected is None:
            return None
        nodes = list(selected.body) if isinstance(selected, ast.ClassDef) else []
    if not isinstance(selected, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    return ast.get_docstring(selected, clean=False) or ""


# ======================================================================
# 4. CANONICAL BINDING REGISTRY VALIDATION
# ======================================================================
def _binding_schema_path(root: Path) -> Path:
    candidate = root / "schemas/dead_code_evidence_bindings.schema.json"
    if candidate.is_file():
        return candidate
    return Path(__file__).resolve().parent.parent / "schemas/dead_code_evidence_bindings.schema.json"


@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_evidence_binding_registry(root: Path) -> list[str]:
    """Validate the canonical registry schema, version and exact binding identities."""
    registry_path = root / "reference/dead_code_evidence_bindings.json"
    schema_path = _binding_schema_path(root)
    try:
        registry_bytes = registry_path.read_bytes()
        schema_bytes = schema_path.read_bytes()
    except OSError as exc:
        return [f"Evidence binding registry/schema is unavailable: {type(exc).__name__}."]
    # Validation is intentionally recomputed on every call. Evidence registries are
    # small, while a cache could conceal an in-process substitution of the manifest
    # or a referenced contract.
    _ = hashlib.sha256(registry_bytes).hexdigest(), hashlib.sha256(schema_bytes).hexdigest()
    problems: list[str] = []
    try:
        registry = json.loads(registry_bytes)
        schema = json.loads(schema_bytes)
        Draft202012Validator.check_schema(schema)
    except (json.JSONDecodeError, ValueError) as exc:
        problems.append(f"Evidence binding registry/schema is invalid JSON Schema: {type(exc).__name__}.")
    else:
        for error in sorted(Draft202012Validator(schema).iter_errors(registry), key=lambda item: list(item.absolute_path)):
            location = "/".join(str(part) for part in error.absolute_path) or "$"
            problems.append(f"binding-registry/{location}: {error.message}")
        manifest_path = root / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            problems.append("manifest.json cannot be resolved for evidence-registry version binding.")
        else:
            if registry.get("standard_version") != manifest.get("version"):
                problems.append("Evidence binding registry standard_version must match manifest.version.")
        bindings = registry.get("bindings", {}) if isinstance(registry, dict) else {}
        seen_targets: set[tuple[str, str, str]] = set()
        if isinstance(bindings, dict):
            for key, binding in bindings.items():
                if not isinstance(binding, dict):
                    continue
                if binding.get("binding_id") != key:
                    problems.append(f"Binding map key {key!r} does not match binding_id.")
                target = (
                    str(binding.get("contract_type", "")),
                    str(binding.get("path", "")),
                    str(binding.get("symbol", "")),
                )
                if target in seen_targets:
                    problems.append(f"Duplicate exact evidence binding target: {target!r}.")
                seen_targets.add(target)
                for reference in binding.get("supporting_references", []):
                    if not isinstance(reference, str) or not reference:
                        continue
                    relative = reference.split("::", 1)[0].split("#", 1)[0]
                    if not _safe_relative_path(relative) or not (root / relative).is_file():
                        problems.append(f"Supporting reference does not resolve: {reference!r}.")
    return problems


# ======================================================================
# 5. TYPED EVIDENCE RESOLUTION
# ======================================================================
def _validate_json_pointer_evidence(
    root: Path,
    item: dict[str, Any],
    target_path: str,
    target_symbol: str,
) -> str | None:
    evidence_path = str(item.get("path", ""))
    pointer = str(item.get("pointer", ""))
    if not _safe_relative_path(evidence_path):
        return "JSON evidence path must be a safe relative path."
    path = root / evidence_path
    if not path.is_file():
        return "JSON evidence file does not exist."
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
        selected = _resolve_json_pointer(payload, pointer)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        return f"JSON evidence pointer cannot be resolved: {type(exc).__name__}."
    if not isinstance(selected, dict):
        return "JSON evidence pointer must resolve to an object contract."
    expected_type = str(item.get("contract_type", ""))
    if selected.get("contract_type") != expected_type:
        return "JSON evidence contract_type does not match the resolved contract."
    if selected.get("path") != target_path or selected.get("symbol") != target_symbol:
        return "JSON evidence is not bound to the exact target path and symbol."
    if selected.get("status", "ACTIVE") != "ACTIVE":
        return "JSON evidence contract is not ACTIVE."
    return None


def _validate_markdown_evidence(
    root: Path,
    item: dict[str, Any],
    target_path: str,
    target_symbol: str,
) -> str | None:
    evidence_path = str(item.get("path", ""))
    anchor = str(item.get("anchor", ""))
    if not _safe_relative_path(evidence_path) or not anchor:
        return "Markdown evidence requires a safe path and exact anchor."
    path = root / evidence_path
    if not path.is_file():
        return "Markdown evidence file does not exist."
    try:
        section = _markdown_section(path.read_text(encoding="utf-8"), anchor)
    except (OSError, UnicodeDecodeError):
        section = None
    if section is None:
        return "Markdown evidence anchor does not resolve."
    expected_type = f"dead-code-contract-type: {item.get('contract_type', '')}"
    expected_subject = f"dead-code-subject: {target_path}::{target_symbol}"
    if expected_type not in section or expected_subject not in section:
        return "Markdown evidence section is unrelated to the exact target contract."
    return None


def _validate_test_node_evidence(
    root: Path,
    item: dict[str, Any],
    target_path: str,
    target_symbol: str,
) -> str | None:
    node_id = str(item.get("node_id", ""))
    if not node_id or "[" in node_id:
        return "Test evidence requires a non-parametrized exact pytest node ID."
    test_path = node_id.split("::", 1)[0]
    if not _safe_relative_path(test_path) or not test_path.startswith("tests/"):
        return "Test evidence must resolve below tests/."
    path = root / test_path
    if not path.is_file():
        return "Test evidence file does not exist."
    docstring = _test_function_docstring(root, node_id)
    if docstring is None:
        return "Test evidence node does not resolve to an exact test function."
    expected_subject = f"dead-code-subject: {target_path}::{target_symbol}"
    expected_type = "dead-code-contract-type: behavioral_test"
    if expected_subject not in docstring or expected_type not in docstring:
        return "Test evidence node is not bound to the exact target path and symbol."
    return None


@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_evidence_set(
    root: Path,
    evidence: Any,
    *,
    target_path: str,
    target_symbol: str,
    required_primary_types: set[str],
    require_behavioral_test: bool = True,
) -> list[str]:
    """Validate typed evidence and exact subject binding for one registry record."""
    if not isinstance(evidence, list) or not evidence:
        return ["Typed evidence must be a non-empty array."]
    problems: list[str] = []
    seen: set[str] = set()
    observed_primary: set[str] = set()
    behavioral_tests = 0
    for index, raw in enumerate(evidence, 1):
        prefix = f"evidence[{index}]"
        if not isinstance(raw, dict):
            problems.append(f"{prefix}: legacy/untyped evidence strings are forbidden.")
            continue
        kind = str(raw.get("kind", ""))
        contract_type = str(raw.get("contract_type", ""))
        subject_path, subject_symbol = _subject(raw)
        if kind not in EVIDENCE_KINDS:
            problems.append(f"{prefix}: unsupported evidence kind.")
            continue
        if contract_type not in PRIMARY_CONTRACT_TYPES | {"behavioral_test"}:
            problems.append(f"{prefix}: unsupported contract_type.")
            continue
        if (subject_path, subject_symbol) != (target_path, target_symbol):
            problems.append(f"{prefix}: subject does not match the exact registry target.")
            continue
        identity = json.dumps(raw, ensure_ascii=False, sort_keys=True)
        if identity in seen:
            problems.append(f"{prefix}: duplicate evidence object.")
            continue
        seen.add(identity)
        if kind == "json_pointer":
            error = _validate_json_pointer_evidence(root, raw, target_path, target_symbol)
        elif kind == "markdown_anchor":
            error = _validate_markdown_evidence(root, raw, target_path, target_symbol)
        else:
            error = _validate_test_node_evidence(root, raw, target_path, target_symbol)
        if error:
            problems.append(f"{prefix}: {error}")
            continue
        if contract_type in PRIMARY_CONTRACT_TYPES:
            observed_primary.add(contract_type)
        if kind == "test_node" and contract_type == "behavioral_test":
            behavioral_tests += 1
    if required_primary_types and not (observed_primary & required_primary_types):
        required = ",".join(sorted(required_primary_types))
        problems.append(f"Typed primary contract evidence is required: {required}.")
    if require_behavioral_test and behavioral_tests == 0:
        problems.append("At least one exact collected behavioral test node is required.")
    return problems


def evidence_test_nodes(evidence: Any) -> set[str]:
    """Return exact collected test-node claims from a typed evidence array."""
    if not isinstance(evidence, list):
        return set()
    return {
        str(item.get("node_id"))
        for item in evidence
        if isinstance(item, dict)
        and item.get("kind") == "test_node"
        and item.get("contract_type") == "behavioral_test"
        and isinstance(item.get("node_id"), str)
    }

# ======================================================================
# 6. BATCH EXECUTION PROOF FROM CANONICAL JUNIT
# ======================================================================
@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_evidence_test_execution(
    required_nodes: set[str],
    junit_paths: dict[str, Path],
    *,
    required_suites: tuple[str, ...] = ("direct_tests", "tests"),
) -> list[str]:
    """Validate exact evidence nodes against already executed canonical JUnit.

    Structural dead-code validation deliberately does not launch nested pytest
    processes. Formal release supplies the direct and segmented full-suite JUnit
    files produced earlier in the immutable release graph. Every evidence node
    must exist in both suites and have the exact ``passed`` outcome.
    """
    problems: list[str] = []
    if not required_nodes:
        return ["No exact behavioral evidence test nodes were registered."]
    for suite_id in required_suites:
        path = junit_paths.get(suite_id)
        if path is None:
            problems.append(f"Required evidence execution suite is missing: {suite_id}.")
            continue
        if not path.is_file():
            problems.append(f"Evidence execution JUnit does not exist: {suite_id}.")
            continue
        try:
            analysis = parse_junit(path, require_node_ids=True)
        except (OSError, ValueError, SyntaxError) as exc:
            problems.append(f"Evidence execution JUnit is invalid for {suite_id}: {type(exc).__name__}.")
            continue
        if analysis.summary.get("status") != "PASS":
            problems.append(f"Evidence execution suite did not pass: {suite_id}.")
        if analysis.missing_node_id_count or analysis.duplicate_node_ids:
            problems.append(f"Evidence execution JUnit node accounting is invalid: {suite_id}.")
            continue
        outcomes = dict(analysis.node_outcomes)
        missing = sorted(required_nodes - set(outcomes))
        if missing:
            problems.append(f"Evidence test nodes are absent from {suite_id}: {missing!r}.")
        nonpassing = sorted(node for node in required_nodes if outcomes.get(node) not in {None, "passed"})
        if nonpassing:
            rendered = {node: outcomes[node] for node in nonpassing}
            problems.append(f"Evidence test nodes did not pass in {suite_id}: {rendered!r}.")
    return problems
