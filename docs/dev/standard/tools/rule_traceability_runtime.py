#!/usr/bin/env python3
# ======================================================================
# rule_traceability_runtime.py — версия 1.0
# Детерминированное выполнение связанных behavioral tests и сбор runtime evidence.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from rule_traceability_ast import test_entries
from rule_traceability_types import RuleFinding


# ======================================================================
# 1. БАЗОВЫЕ ОПЕРАЦИИ
# ======================================================================

def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _registry_rules(data: dict[str, Any]) -> list[dict[str, Any]]:
    rules = data.get("rules", [])
    return [item for item in rules if isinstance(item, dict)] if isinstance(rules, list) else []


def _rule_id(rule: dict[str, Any]) -> str:
    return str(rule.get("rule_id") or rule.get("id") or "")


def _finding(code: str, rule_id: str, message: str, **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, "ERROR", evidence)


def _git_value(root: Path, *args: str) -> str | None:
    proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    value = proc.stdout.strip()
    return value if proc.returncode == 0 and value else None


# ======================================================================
# 2. STRUCTURED DIAGNOSTIC PARSER
# ======================================================================

def _parse_runtime_diagnostics(text: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    prefix = "APS_RULE_DIAGNOSTIC:"
    decoder = json.JSONDecoder()
    for line in text.splitlines():
        offset = 0
        while True:
            index = line.find(prefix, offset)
            if index < 0:
                break
            payload = line[index + len(prefix):].lstrip()
            try:
                value, consumed = decoder.raw_decode(payload)
            except json.JSONDecodeError:
                break
            if isinstance(value, dict):
                result.append(value)
            offset = index + len(prefix) + consumed
    return result


# ======================================================================
# 3. BATCHED IMMUTABLE PYTEST EXECUTION
# ======================================================================

def execute_linked_tests(
    root: Path,
    data: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[RuleFinding]]:
    """Выполняет все linked tests одним immutable pytest invocation.

    Один процесс исключает стоимость повторной загрузки полного стандарта, но
    evidence остаётся по каждому node_id: exact rule ID, polarity, expected
    structured diagnostic, command/JUnit/stdout/stderr digests и source identity.
    """
    declared: list[tuple[str, str, dict[str, Any]]] = []
    for rule in _registry_rules(data):
        if rule.get("status") != "IMPLEMENTED":
            continue
        rule_id = _rule_id(rule)
        declared.extend((rule_id, polarity, test) for polarity, test in test_entries(rule))
    if not declared:
        return [], []

    env = {
        **os.environ,
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTEST_ADDOPTS": "-p no:cacheprovider",
    }
    commit_sha = _git_value(root, "rev-parse", "HEAD")
    tree_sha = _git_value(root, "rev-parse", "HEAD^{tree}")
    with tempfile.TemporaryDirectory(prefix="aps_rule_tests_") as raw:
        junit = Path(raw) / "junit.xml"
        node_ids = [str(test.get("node_id", "")) for _, _, test in declared]
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-s",
            f"--junitxml={junit}",
            *node_ids,
        ]
        proc = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True)
        combined = proc.stdout + "\n" + proc.stderr
        diagnostics = _parse_runtime_diagnostics(combined)
        junit_sha = _sha256_bytes(junit.read_bytes()) if junit.is_file() else None
        command_sha = _sha256_text(json.dumps(command, separators=(",", ":")))
        stdout_sha = _sha256_text(proc.stdout)
        stderr_sha = _sha256_text(proc.stderr)

    results: list[dict[str, Any]] = []
    findings: list[RuleFinding] = []
    for rule_id, polarity, test in declared:
        node_id = str(test.get("node_id", ""))
        expected_code = str(test.get("expected_diagnostic_code", ""))
        observed = next(
            (
                item for item in diagnostics
                if item.get("rule_id") == rule_id and item.get("code") == expected_code
            ),
            None,
        )
        passed = proc.returncode == 0 and observed is not None
        results.append({
            "rule_id": rule_id,
            "node_id": node_id,
            "polarity": polarity,
            "candidate_commit_sha": commit_sha,
            "candidate_tree_sha": tree_sha,
            "command": command,
            "command_sha256": command_sha,
            "exit_code": proc.returncode,
            "junit_sha256": junit_sha,
            "stdout_sha256": stdout_sha,
            "stderr_sha256": stderr_sha,
            "expected_diagnostic_code": expected_code,
            "observed_structured_diagnostic": observed,
            "status": "PASS" if passed else "FAIL",
        })
        if not passed:
            findings.append(_finding(
                "IMPLEMENTED_RULE_WITHOUT_BEHAVIORAL_EVIDENCE",
                rule_id,
                f"Linked behavioral test did not produce exact runtime evidence: {node_id}",
                node_id=node_id,
                expected_diagnostic_code=expected_code,
                exit_code=proc.returncode,
                detail=node_id,
            ))
    return results, sorted(set(findings))
