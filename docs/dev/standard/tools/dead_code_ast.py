#!/usr/bin/env python3
# ======================================================================
# dead_code_ast.py — версия 1.0
# Детерминированный AST-индекс Python-кода и high-confidence проверки.
# ======================================================================
from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from dead_code_types import Finding, ImportRecord, SymbolId, SymbolRecord, stable_finding_id
from rule_traceability_types import emits_diagnostic, enforces_rule

SKIP_PARTS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "build", "dist"}
TERMINATORS = (ast.Return, ast.Raise, ast.Break, ast.Continue)


@dataclass
class ModuleIndex:
    path: str
    is_test: bool
    tree: ast.AST
    symbols: dict[str, SymbolRecord] = field(default_factory=dict)
    imports: list[ImportRecord] = field(default_factory=list)
    names: set[str] = field(default_factory=set)
    strings: set[str] = field(default_factory=set)
    dynamic_names: set[str] = field(default_factory=set)
    top_level_references: set[str] = field(default_factory=set)
    has_main_guard: bool = False
    exports: set[str] = field(default_factory=set)


def is_excluded(rel: Path, excluded_prefixes: Iterable[str]) -> bool:
    """Путь объявлен проектом вне области аудита (см. dead_code_scan_scope.json)."""
    posix = rel.as_posix()
    for prefix in excluded_prefixes:
        cleaned = prefix.strip("/")
        if cleaned and (posix == cleaned or posix.startswith(f"{cleaned}/")):
            return True
    return False


def iter_python_files(root: Path, excluded_prefixes: Iterable[str] = ()) -> Iterable[Path]:
    prefixes = tuple(excluded_prefixes)
    for path in sorted(root.rglob("*.py")):
        rel = path.relative_to(root)
        if any(part in SKIP_PARTS for part in rel.parts):
            continue
        if prefixes and is_excluded(rel, prefixes):
            continue
        yield path


def is_test_path(rel: Path) -> bool:
    return any(part in {"tests", "test", "fixtures"} for part in rel.parts) or rel.name.startswith("test_")


def _is_type_checking_test(node: ast.AST) -> bool:
    return isinstance(node, ast.Name) and node.id == "TYPE_CHECKING" or (
        isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
        and node.value.id == "typing" and node.attr == "TYPE_CHECKING"
    )


def _collect_imports(tree: ast.Module, rel: str) -> list[ImportRecord]:
    records: list[ImportRecord] = []

    def walk_statements(statements: list[ast.stmt], typing_only: bool = False) -> None:
        for stmt in statements:
            if isinstance(stmt, ast.If) and _is_type_checking_test(stmt.test):
                walk_statements(stmt.body, True)
                walk_statements(stmt.orelse, typing_only)
                continue
            if isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    records.append(ImportRecord(rel, stmt.lineno, alias.name, None, alias.asname or alias.name.split(".")[0], typing_only))
            elif isinstance(stmt, ast.ImportFrom):
                if stmt.module == "__future__":
                    continue
                for alias in stmt.names:
                    records.append(ImportRecord(rel, stmt.lineno, stmt.module or "", alias.name, alias.asname or alias.name, typing_only))
            for child_name in ("body", "orelse", "finalbody"):
                child = getattr(stmt, child_name, None)
                if isinstance(child, list) and not isinstance(stmt, ast.If):
                    walk_statements(child, typing_only)
            for handler in getattr(stmt, "handlers", []):
                walk_statements(handler.body, typing_only)
    walk_statements(tree.body)
    return records


class _ReferenceVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()
        self.strings: set[str] = set()
        self.dynamic_names: set[str] = set()

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load):
            self.names.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        self.names.add(node.attr)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            self.strings.add(node.value)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        if isinstance(node.func, ast.Name) and node.func.id in {"getattr", "setattr", "hasattr"} and len(node.args) >= 2:
            name = node.args[1]
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                self.dynamic_names.add(name.value)
        self.generic_visit(node)


def _function_references(node: ast.AST) -> set[str]:
    visitor = _ReferenceVisitor()
    visitor.visit(node)
    return visitor.names


def _is_main_guard(node: ast.If) -> bool:
    test = node.test
    return (
        isinstance(test, ast.Compare)
        and isinstance(test.left, ast.Name)
        and test.left.id == "__name__"
        and len(test.ops) == 1
        and isinstance(test.ops[0], ast.Eq)
        and len(test.comparators) == 1
        and isinstance(test.comparators[0], ast.Constant)
        and test.comparators[0].value == "__main__"
    )


def build_module_index(root: Path, path: Path) -> ModuleIndex:
    rel = path.relative_to(root).as_posix()
    tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=rel)
    index = ModuleIndex(rel, is_test_path(Path(rel)), tree)
    visitor = _ReferenceVisitor(); visitor.visit(tree)
    index.names = visitor.names; index.strings = visitor.strings; index.dynamic_names = visitor.dynamic_names
    index.imports = _collect_imports(tree, rel)
    for stmt in tree.body:
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            if any(isinstance(t, ast.Name) and t.id == "__all__" for t in targets):
                value = stmt.value
                if isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                    index.exports.update(
                        item.value for item in value.elts
                        if isinstance(item, ast.Constant) and isinstance(item.value, str)
                    )
    for stmt in tree.body:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            index.symbols[stmt.name] = SymbolRecord(SymbolId(rel, stmt.name), "async_function" if isinstance(stmt, ast.AsyncFunctionDef) else "function", stmt.lineno, stmt.name.startswith("_"), _function_references(stmt))
        elif isinstance(stmt, ast.ClassDef):
            index.symbols[stmt.name] = SymbolRecord(SymbolId(rel, stmt.name), "class", stmt.lineno, stmt.name.startswith("_"), _function_references(stmt))
            for child in stmt.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    qn = f"{stmt.name}.{child.name}"
                    index.symbols[qn] = SymbolRecord(SymbolId(rel, qn), "method", child.lineno, child.name.startswith("_"), _function_references(child))
        else:
            index.top_level_references.update(_function_references(stmt))
        if isinstance(stmt, ast.If) and _is_main_guard(stmt):
            index.has_main_guard = True
            for child in stmt.body:
                index.top_level_references.update(_function_references(child))
    return index


def _walk_blocks(node: ast.AST) -> Iterable[list[ast.stmt]]:
    for _, value in ast.iter_fields(node):
        if isinstance(value, list) and value and all(isinstance(item, ast.stmt) for item in value):
            yield value
            for item in value:
                yield from _walk_blocks(item)
        elif isinstance(value, ast.AST):
            yield from _walk_blocks(value)


@enforces_rule("APS-DEAD-CODE-UNREACHABLE-STATEMENT-001")
@emits_diagnostic("APS-DEAD-CODE-UNREACHABLE-STATEMENT-001", "APS_DEAD_CODE_UNREACHABLE_SCAN_PASS")
@emits_diagnostic("APS-DEAD-CODE-UNREACHABLE-STATEMENT-001", "APS_DEAD_CODE_UNREACHABLE_STATEMENT")
def detect_unreachable_statements(module: ModuleIndex) -> list[Finding]:
    findings: list[Finding] = []
    for block in _walk_blocks(module.tree):
        terminated: ast.stmt | None = None
        for stmt in block:
            if terminated is not None:
                findings.append(Finding(
                    stable_finding_id("APS-DC", module.path, stmt.lineno, type(stmt).__name__,
                                      "unreachable_statement"),
                    "APS-DEAD-CODE-UNREACHABLE-STATEMENT-001",
                    "APS_DEAD_CODE_UNREACHABLE_STATEMENT", "ERROR", "syntactically_unreachable",
                    "HIGH", module.path, stmt.lineno, "<statement>", type(stmt).__name__, False, False, [],
                    {"terminator_line": terminated.lineno, "terminator_kind": type(terminated).__name__},
                    "Statement follows an unconditional terminator in the same block.",
                    "Remove or restructure the unreachable statement after review and regression tests.",
                ))
            if isinstance(stmt, TERMINATORS):
                terminated = stmt
            elif terminated is not None:
                # All later statements in the same block remain unreachable.
                continue
    return findings


@enforces_rule("APS-DEAD-CODE-DETECTION-001")
@emits_diagnostic("APS-DEAD-CODE-DETECTION-001", "APS_DEAD_CODE_SCAN_PASS")
@emits_diagnostic("APS-DEAD-CODE-DETECTION-001", "APS_DEAD_CODE_UNUSED_IMPORT")
def detect_unused_imports(module: ModuleIndex, externally_reexported: set[str] | None = None) -> list[Finding]:
    if module.is_test:
        return []
    externally_reexported = externally_reexported or set()
    findings: list[Finding] = []
    for idx, record in enumerate(module.imports, 1):
        if record.typing_only or record.bound_name in module.names or record.bound_name in module.exports or record.bound_name in externally_reexported:
            continue
        severity = "WARNING" if record.imported_name is None else "ERROR"
        confidence = "MEDIUM" if record.imported_name is None else "HIGH"
        findings.append(Finding(
            stable_finding_id("APS-DC-IMP", module.path, record.bound_name, "unused_import"), "APS-DEAD-CODE-DETECTION-001",
            "APS_DEAD_CODE_UNUSED_IMPORT", severity, "unused_import", confidence,
            module.path, record.line, record.bound_name, "import", False, False, [],
            {"module": record.module, "imported_name": record.imported_name, "typing_only": record.typing_only},
            "Imported binding is not referenced by the parsed module.",
            "Remove it, prove a side-effect/registration contract, or add a bounded allowlist record.",
        ))
    return findings


@enforces_rule("APS-DEAD-CODE-DETECTION-001")
@emits_diagnostic("APS-DEAD-CODE-DETECTION-001", "APS_DEAD_CODE_COMMENTED_BLOCK_REVIEW")
def detect_commented_code(root: Path, module: ModuleIndex) -> list[Finding]:
    """Detect only large, parseable comment blocks that look like Python code."""
    path = root / module.path
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    groups: list[tuple[int, list[str]]] = []
    start = 0; current: list[str] = []
    for number, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#") and not stripped.startswith(("#!", "# ====", "# ----")):
            if not current:
                start = number
            payload = stripped[1:]
            if payload.startswith(" "):
                payload = payload[1:]
            current.append(payload)
        else:
            if len(current) >= 4:
                groups.append((start, current))
            current = []
    if len(current) >= 4:
        groups.append((start, current))
    findings: list[Finding] = []
    for idx, (line, group) in enumerate(groups, 1):
        text = "\n".join(group)
        if not any(token in text for token in ("def ", "class ", "import ", "return ", "raise ")):
            continue
        try:
            parsed = ast.parse(text)
        except SyntaxError:
            continue
        if not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom)) for node in ast.walk(parsed)):
            continue
        findings.append(Finding(
            stable_finding_id("APS-DC-COMMENT", module.path, line), "APS-DEAD-CODE-DETECTION-001",
            "APS_DEAD_CODE_COMMENTED_BLOCK_REVIEW", "WARNING", "commented_code", "MEDIUM",
            module.path, line, "<commented-block>", "comment", False, False, [],
            {"line_count": len(group)}, "Large parseable commented Python block requires review.",
            "Remove historical code or preserve rationale in documentation, not executable-looking comments.",
        ))
    return findings
