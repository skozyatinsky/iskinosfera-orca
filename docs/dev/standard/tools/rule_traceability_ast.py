#!/usr/bin/env python3
# ======================================================================
# rule_traceability_ast.py — версия 2.0
# AST-проверка implementation annotations, call path и behavioral tests.
# ======================================================================

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from rule_traceability_types import RuleFinding


@dataclass(frozen=True)
class SymbolInfo:
    module_path: Path
    module_name: str
    symbol_name: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    tree: ast.Module


# ======================================================================
# 1. РАЗРЕШЕНИЕ EXACT SYMBOL
# Формат registry: package.module:function_name.
# ======================================================================

def resolve_symbol(root: Path, symbol: str) -> SymbolInfo | None:
    module, separator, function_name = symbol.partition(":")
    if not separator or not module or not function_name or "." in function_name:
        return None
    module_path = root / (module.replace(".", "/") + ".py")
    if not module_path.is_file():
        return None
    try:
        tree = ast.parse(module_path.read_text(encoding="utf-8-sig"), filename=str(module_path))
    except (OSError, SyntaxError, UnicodeError):
        return None
    node = next(
        (
            item
            for item in tree.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == function_name
        ),
        None,
    )
    if node is None:
        return None
    return SymbolInfo(module_path, module, function_name, node, tree)


def _literal_string(node: ast.AST | None) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _decorator_call(node: ast.AST, name: str) -> ast.Call | None:
    if not isinstance(node, ast.Call):
        return None
    function = node.func
    current = function.id if isinstance(function, ast.Name) else (
        function.attr if isinstance(function, ast.Attribute) else ""
    )
    return node if current == name else None


def _has_enforces_annotation(node: ast.FunctionDef | ast.AsyncFunctionDef, rule_id: str) -> bool:
    for decorator in node.decorator_list:
        call = _decorator_call(decorator, "enforces_rule")
        if call and call.args and _literal_string(call.args[0]) == rule_id:
            return True
    return False


def _emitted_diagnostics(node: ast.FunctionDef | ast.AsyncFunctionDef, rule_id: str) -> set[str]:
    result: set[str] = set()
    for decorator in node.decorator_list:
        call = _decorator_call(decorator, "emits_diagnostic")
        if not call or len(call.args) < 2:
            continue
        if _literal_string(call.args[0]) == rule_id:
            code = _literal_string(call.args[1])
            if code:
                result.add(code)
    return result


def _is_nontrivial(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    statements = list(node.body)
    if statements and isinstance(statements[0], ast.Expr):
        value = statements[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            statements = statements[1:]
    if not statements:
        return False
    meaningful = []
    for statement in statements:
        if isinstance(statement, ast.Pass):
            continue
        if isinstance(statement, ast.Return) and (
            statement.value is None
            or isinstance(statement.value, ast.Constant)
        ):
            continue
        meaningful.append(statement)
    return bool(meaningful)


def _called_names(node: ast.AST) -> set[str]:
    result: set[str] = set()
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        function = child.func
        if isinstance(function, ast.Name):
            result.add(function.id)
        elif isinstance(function, ast.Attribute):
            result.add(function.attr)
    return result


# ======================================================================
# 2. IMPLEMENTATION LINKAGE
# Комментарий, docstring или неиспользуемый symbol не считается реализацией.
# ======================================================================

def validate_implementation_links(root: Path, rule: dict[str, Any]) -> list[RuleFinding]:
    rule_id = str(rule.get("rule_id", ""))
    findings: list[RuleFinding] = []
    implementations = rule.get("implementation", [])
    if not isinstance(implementations, list):
        return [RuleFinding(
            "RULE_IMPLEMENTATION_INVALID",
            rule_id,
            "implementation must be an array",
            evidence={"detail": rule_id},
        )]

    declared_codes = {
        str(item.get("code"))
        for item in rule.get("diagnostics", [])
        if isinstance(item, dict) and item.get("code")
    }
    observed_codes: set[str] = set()

    for item in implementations:
        if not isinstance(item, dict):
            findings.append(RuleFinding(
                "RULE_IMPLEMENTATION_INVALID",
                rule_id,
                "implementation item must be an object",
                evidence={"detail": rule_id},
            ))
            continue
        symbol = str(item.get("symbol", ""))
        info = resolve_symbol(root, symbol)
        if info is None:
            findings.append(RuleFinding(
                "UNKNOWN_IMPLEMENTATION_SYMBOL",
                rule_id,
                f"Unknown implementation symbol: {symbol}",
                evidence={"symbol": symbol, "detail": symbol},
            ))
            continue
        if not _has_enforces_annotation(info.node, rule_id):
            findings.append(RuleFinding(
                "RULE_IMPLEMENTATION_ANNOTATION_MISSING",
                rule_id,
                f"Exact enforces_rule annotation is missing on {symbol}",
                evidence={"symbol": symbol, "detail": symbol},
            ))
        if not _is_nontrivial(info.node):
            findings.append(RuleFinding(
                "RULE_IMPLEMENTATION_TRIVIAL",
                rule_id,
                f"Implementation symbol is empty/trivial: {symbol}",
                evidence={"symbol": symbol, "detail": symbol},
            ))
        observed_codes.update(_emitted_diagnostics(info.node, rule_id))

        gate_symbols = item.get("gate_symbols", [])
        if not isinstance(gate_symbols, list) or not gate_symbols:
            findings.append(RuleFinding(
                "RULE_IMPLEMENTATION_GATE_MISSING",
                rule_id,
                f"No gate_symbols declared for {symbol}",
                evidence={"symbol": symbol, "detail": symbol},
            ))
            continue
        reached = False
        for gate_symbol in gate_symbols:
            gate = resolve_symbol(root, str(gate_symbol))
            if gate is None:
                findings.append(RuleFinding(
                    "UNKNOWN_IMPLEMENTATION_GATE_SYMBOL",
                    rule_id,
                    f"Unknown gate symbol: {gate_symbol}",
                    evidence={"symbol": gate_symbol, "detail": str(gate_symbol)},
                ))
                continue
            if str(gate_symbol) == symbol or info.symbol_name in _called_names(gate.node):
                reached = True
        if not reached:
            findings.append(RuleFinding(
                "RULE_IMPLEMENTATION_NOT_REACHED_BY_GATE",
                rule_id,
                f"Implementation {symbol} is not called by a declared gate",
                evidence={"symbol": symbol, "gate_symbols": gate_symbols, "detail": symbol},
            ))

    for code in sorted(declared_codes - observed_codes):
        findings.append(RuleFinding(
            "RULE_DIAGNOSTIC_NOT_EMITTED_BY_IMPLEMENTATION",
            rule_id,
            f"Diagnostic is not declared by an implementation decorator: {code}",
            evidence={"diagnostic_code": code, "detail": code},
        ))
    for code in sorted(observed_codes - declared_codes):
        findings.append(RuleFinding(
            "RULE_IMPLEMENTATION_DIAGNOSTIC_UNREGISTERED",
            rule_id,
            f"Implementation emits unregistered diagnostic: {code}",
            evidence={"diagnostic_code": code, "detail": code},
        ))
    return findings


# ======================================================================
# 3. TEST LINKAGE
# Test должен иметь rule_test decorator и достигать production symbol.
# ======================================================================

def _find_test_node(root: Path, node_id: str) -> tuple[Path, ast.FunctionDef | ast.AsyncFunctionDef] | None:
    rel, separator, function_name = node_id.partition("::")
    if not separator or not function_name:
        return None
    path = root / rel
    if not path.is_file():
        return None
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return None
    node = next(
        (
            item
            for item in tree.body
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef))
            and item.name == function_name
        ),
        None,
    )
    return (path, node) if node is not None else None


def _test_annotation(node: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, str] | None:
    for decorator in node.decorator_list:
        call = _decorator_call(decorator, "rule_test")
        if not call or len(call.args) < 2:
            continue
        rule_id = _literal_string(call.args[0])
        polarity = _literal_string(call.args[1])
        expected = None
        for keyword in call.keywords:
            if keyword.arg == "expected_diagnostic":
                expected = _literal_string(keyword.value)
        if rule_id and polarity and expected:
            return {
                "rule_id": rule_id,
                "polarity": polarity,
                "expected_diagnostic": expected,
            }
    return None


def _contains_assert_true(node: ast.AST) -> bool:
    return any(
        isinstance(child, ast.Assert)
        and isinstance(child.test, ast.Constant)
        and child.test.value is True
        for child in ast.walk(node)
    )


def _only_prints_or_metadata(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    body = list(node.body)
    if body and isinstance(body[0], ast.Expr):
        value = body[0].value
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            body = body[1:]
    meaningful_calls = _called_names(node) - {
        "print",
        "print_diagnostic",
        "diagnostic_line",
        "rule_test",
    }
    has_assert = any(isinstance(item, ast.Assert) for item in ast.walk(node))
    return not meaningful_calls and not has_assert


def validate_test_links(root: Path, rule: dict[str, Any]) -> list[RuleFinding]:
    rule_id = str(rule.get("rule_id", ""))
    findings: list[RuleFinding] = []
    implementation_names = {
        str(item.get("symbol", "")).partition(":")[2]
        for item in rule.get("implementation", [])
        if isinstance(item, dict)
    }
    implementation_names.discard("")

    tests = rule.get("tests", {})
    if not isinstance(tests, dict):
        return [RuleFinding(
            "RULE_TESTS_INVALID",
            rule_id,
            "tests must be an object grouped by polarity",
            evidence={"detail": rule_id},
        )]

    for polarity in ("positive", "negative", "bypass"):
        entries = tests.get(polarity, [])
        if not isinstance(entries, list):
            findings.append(RuleFinding(
                "RULE_TESTS_INVALID",
                rule_id,
                f"tests.{polarity} must be an array",
                evidence={"detail": polarity},
            ))
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                findings.append(RuleFinding(
                    "RULE_TESTS_INVALID",
                    rule_id,
                    f"Invalid {polarity} test entry",
                    evidence={"detail": polarity},
                ))
                continue
            node_id = str(entry.get("node_id", ""))
            expected = str(entry.get("expected_diagnostic_code", ""))
            resolved = _find_test_node(root, node_id)
            if resolved is None:
                findings.append(RuleFinding(
                    "RULE_TEST_NODE_MISSING",
                    rule_id,
                    f"Unknown pytest node: {node_id}",
                    evidence={"node_id": node_id, "detail": node_id},
                ))
                continue
            _, node = resolved
            annotation = _test_annotation(node)
            if annotation is None:
                findings.append(RuleFinding(
                    "RULE_TEST_ANNOTATION_MISSING",
                    rule_id,
                    f"rule_test annotation is missing: {node_id}",
                    evidence={"node_id": node_id, "detail": node_id},
                ))
            else:
                if annotation["rule_id"] != rule_id:
                    findings.append(RuleFinding(
                        "RULE_TEST_RULE_ID_MISMATCH",
                        rule_id,
                        f"Test is bound to another rule ID: {node_id}",
                        evidence={
                            "node_id": node_id,
                            "observed_rule_id": annotation["rule_id"],
                            "detail": node_id,
                        },
                    ))
                if annotation["polarity"] != polarity:
                    findings.append(RuleFinding(
                        "RULE_TEST_POLARITY_MISMATCH",
                        rule_id,
                        f"Test polarity mismatch: {node_id}",
                        evidence={"node_id": node_id, "detail": node_id},
                    ))
                if annotation["expected_diagnostic"] != expected:
                    findings.append(RuleFinding(
                        "RULE_DIAGNOSTIC_RULE_ID_MISMATCH",
                        rule_id,
                        f"Expected diagnostic metadata mismatch: {node_id}",
                        evidence={"node_id": node_id, "detail": node_id},
                    ))
            if _contains_assert_true(node):
                findings.append(RuleFinding(
                    "RULE_TEST_TRIVIAL_ASSERTION",
                    rule_id,
                    f"assert True is not behavioral evidence: {node_id}",
                    evidence={"node_id": node_id, "detail": node_id},
                ))
            called = _called_names(node)
            if not (called & implementation_names):
                findings.append(RuleFinding(
                    "RULE_TEST_DOES_NOT_EXERCISE_IMPLEMENTATION",
                    rule_id,
                    f"Test does not call a registered production symbol: {node_id}",
                    evidence={
                        "node_id": node_id,
                        "implementation_names": sorted(implementation_names),
                        "detail": node_id,
                    },
                ))
            if _only_prints_or_metadata(node):
                findings.append(RuleFinding(
                    "RULE_TEST_ONLY_PRINTS_DIAGNOSTIC",
                    rule_id,
                    f"Test only prints/declares evidence: {node_id}",
                    evidence={"node_id": node_id, "detail": node_id},
                ))
    return findings


def test_entries(rule: dict[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    tests = rule.get("tests", {})
    if not isinstance(tests, dict):
        return []
    result: list[tuple[str, dict[str, Any]]] = []
    for polarity in ("positive", "negative", "bypass"):
        entries = tests.get(polarity, [])
        if isinstance(entries, list):
            result.extend((polarity, entry) for entry in entries if isinstance(entry, dict))
    return result
