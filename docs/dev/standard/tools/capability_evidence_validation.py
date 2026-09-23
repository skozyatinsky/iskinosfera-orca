#!/usr/bin/env python3
# ======================================================================
# capability_evidence_validation.py — версия 1.0
# Static contract validation for executable capability evidence cases.
# ======================================================================

from __future__ import annotations

import ast
import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)


def _test_function_semantics(path: Path, function_name: str) -> tuple[bool, str]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return False, str(exc)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name:
            meaningful = False
            for child in ast.walk(node):
                if isinstance(child, ast.Assert):
                    meaningful = True
                elif isinstance(child, ast.Call):
                    target = ast.unparse(child.func)
                    if target.endswith(("raises", "run", "check")) or target.startswith("subprocess"):
                        meaningful = True
            if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                return False, "empty pass"
            return meaningful, "" if meaningful else "no assertion or executable verification"
    return False, "function not found"


def _asserts_finding_code(path: Path, function_name: str, expected_code: str) -> bool:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        function = next(
            node for node in tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == function_name
        )
    except (OSError, SyntaxError, StopIteration):
        return False
    literals = {
        child.value for child in ast.walk(function)
        if isinstance(child, ast.Constant) and isinstance(child.value, str)
    }
    return any(expected_code in literal for literal in literals)


def check_capability_evidence_contract(root: Path) -> list[str]:
    path = root / "reference" / "capability_evidence.json"
    data, error = _load_json(path)
    if error or not isinstance(data, dict):
        return [f"CAPABILITY_EVIDENCE_INVALID:{error}"]
    findings: list[str] = []
    seen: set[str] = set()
    for case in data.get("cases", []):
        if not isinstance(case, dict):
            continue
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            findings.append("CAPABILITY_EVIDENCE_INVALID:case_id")
            continue
        if case_id in seen:
            findings.append(f"CAPABILITY_EVIDENCE_DUPLICATE:{case_id}")
        seen.add(case_id)
        node_id = case.get("pytest_node_id")
        if not isinstance(node_id, str) or "::" not in node_id:
            findings.append(f"CAPABILITY_EVIDENCE_INVALID:{case_id}:pytest_node_id")
            continue
        file_name, function_name = node_id.rsplit("::", 1)
        test_path = root / file_name
        meaningful, reason = _test_function_semantics(test_path, function_name)
        if not meaningful:
            findings.append(f"CAPABILITY_EVIDENCE_MEANINGLESS:{case_id}:{reason}")
        polarity = case.get("polarity")
        expected_code = case.get("expected_finding_code")
        if polarity in {"negative", "bypass"}:
            if not isinstance(expected_code, str):
                findings.append(f"CAPABILITY_EVIDENCE_INVALID:{case_id}:expected_finding_code")
            elif not _asserts_finding_code(test_path, function_name, expected_code):
                findings.append(f"CAPABILITY_EVIDENCE_CODE_NOT_ASSERTED:{case_id}:{expected_code}")
        if not isinstance(case.get("expected_exit_code"), int):
            findings.append(f"CAPABILITY_EVIDENCE_INVALID:{case_id}:expected_exit_code")
    return sorted(set(findings))
