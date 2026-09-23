#!/usr/bin/env python3
# ======================================================================
# dead_code_reachability.py — версия 1.1
# Ограниченный production/test reachability graph для Python.
# ======================================================================
from __future__ import annotations

from collections import deque

from dead_code_ast import ModuleIndex
from dead_code_types import Finding, stable_finding_id
from rule_traceability_types import emits_diagnostic, enforces_rule


def _module_name(path: str) -> str:
    value = path[:-3] if path.endswith(".py") else path
    if value.endswith("/__init__"):
        value = value[:-9]
    parts = value.split("/")
    if "src" in parts:
        parts = parts[parts.index("src") + 1:]
    return ".".join(parts)


def _module_lookup(modules: dict[str, ModuleIndex]) -> dict[str, str]:
    result: dict[str, str] = {}
    for path in modules:
        name = _module_name(path)
        result[name] = path
        result.setdefault(name.rsplit(".", 1)[-1], path)
        if name.startswith("tools."):
            result.setdefault(name.removeprefix("tools."), path)
    return result


def _name_map(modules: dict[str, ModuleIndex]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for module in modules.values():
        for qn, record in module.symbols.items():
            result.setdefault(qn.split(".")[-1], []).append(record.symbol_id.key)
    return result


def _import_aliases(module: ModuleIndex, modules: dict[str, ModuleIndex]) -> dict[str, set[str]]:
    lookup = _module_lookup(modules); aliases: dict[str, set[str]] = {}
    for item in module.imports:
        if not item.imported_name:
            continue
        target_path = lookup.get(item.module)
        if target_path and item.imported_name in modules[target_path].symbols:
            aliases.setdefault(item.bound_name, set()).add(modules[target_path].symbols[item.imported_name].symbol_id.key)
    return aliases


def externally_reexported_names(modules: dict[str, ModuleIndex]) -> dict[str, set[str]]:
    lookup = _module_lookup(modules); result = {path: set() for path in modules}
    for module in modules.values():
        for item in module.imports:
            target = lookup.get(item.module)
            if target and item.imported_name:
                result[target].add(item.imported_name)
    return result


def _symbol_graph(modules: dict[str, ModuleIndex]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    names = _name_map(modules); graph: dict[str, set[str]] = {}; module_roots: dict[str, set[str]] = {}
    for module in modules.values():
        aliases = _import_aliases(module, modules)
        module_roots[module.path] = set()
        for ref in module.top_level_references:
            if ref in aliases:
                module_roots[module.path].update(aliases[ref]); continue
            candidates = names.get(ref, [])
            local = [item for item in candidates if item.startswith(module.path + ":")]
            module_roots[module.path].update(local or (candidates if len(candidates) == 1 else []))
        for record in module.symbols.values():
            edges: set[str] = set()
            for ref in record.references:
                if ref in aliases:
                    edges.update(aliases[ref]); continue
                candidates = names.get(ref, [])
                local = [item for item in candidates if item.startswith(module.path + ":")]
                edges.update(local or (candidates if len(candidates) == 1 else []))
            graph[record.symbol_id.key] = edges
    return graph, module_roots


def _walk(graph: dict[str, set[str]], roots: set[str]) -> set[str]:
    visited: set[str] = set(); queue = deque(sorted(roots))
    while queue:
        node = queue.popleft()
        if node in visited:
            continue
        visited.add(node); queue.extend(sorted(graph.get(node, set()) - visited))
    return visited


def _public_contract_roots(modules: dict[str, ModuleIndex], public_apis: list[dict]) -> tuple[set[str], dict[str, list[str]]]:
    roots: set[str] = set()
    evidence: dict[str, list[str]] = {}
    for module in modules.values():
        aliases = _import_aliases(module, modules)
        for export in module.exports:
            if export in module.symbols:
                key = module.symbols[export].symbol_id.key
                roots.add(key)
                evidence.setdefault(key, []).append(f"{module.path}:__all__")
            for key in aliases.get(export, set()):
                roots.add(key)
                evidence.setdefault(key, []).append(f"{module.path}:__all__:{export}")
    for item in public_apis:
        key = f"{item['path']}:{item['symbol']}"
        roots.add(key)
        evidence.setdefault(key, []).append(f"public_api:{item['api_id']}")
    return roots, evidence


@enforces_rule("APS-DEAD-CODE-PRODUCTION-REACHABILITY-001")
@enforces_rule("APS-DEAD-CODE-TEST-ONLY-REACHABILITY-001")
@emits_diagnostic("APS-DEAD-CODE-PRODUCTION-REACHABILITY-001", "APS_DEAD_CODE_PRODUCTION_REACHABILITY_VALID")
@emits_diagnostic("APS-DEAD-CODE-PRODUCTION-REACHABILITY-001", "APS_DEAD_CODE_PRODUCTION_UNREACHABLE")
@emits_diagnostic("APS-DEAD-CODE-TEST-ONLY-REACHABILITY-001", "APS_DEAD_CODE_TEST_REACHABILITY_SEPARATED")
@emits_diagnostic("APS-DEAD-CODE-TEST-ONLY-REACHABILITY-001", "APS_DEAD_CODE_TEST_ONLY_REACHABLE")
def classify_reachability(modules: dict[str, ModuleIndex], entrypoints: list[dict], public_apis: list[dict] | None = None, profile: str = "standard-package") -> tuple[set[str], set[str], list[Finding]]:
    graph, module_roots = _symbol_graph(modules)
    public_apis = public_apis or []
    contract_roots, contract_evidence = _public_contract_roots(modules, public_apis)
    production_roots: set[str] = set(contract_roots); test_roots: set[str] = set(); entrypoint_paths: dict[str, list[str]] = {}
    for module in modules.values():
        roots = module_roots.get(module.path, set())
        if module.is_test:
            test_roots.update(roots)
            test_roots.update(record.symbol_id.key for record in module.symbols.values())
        elif module.has_main_guard or module.path.endswith("/__main__.py"):
            production_roots.update(roots)
            if "main" in module.symbols:
                production_roots.add(module.symbols["main"].symbol_id.key)
    for item in entrypoints:
        key = f"{item['path']}:{item['symbol']}"
        production_roots.add(key); entrypoint_paths.setdefault(key, []).append(str(item["path"]))
    production = _walk(graph, production_roots); tests = _walk(graph, test_roots)

    findings: list[Finding] = []
    for module in modules.values():
        if module.is_test:
            continue
        for qn, record in module.symbols.items():
            key = record.symbol_id.key; prod = key in production; test = key in tests
            if prod or record.kind == "method":
                continue
            if test:
                category, code, rule, severity, confidence = "test_only_reachable", "APS_DEAD_CODE_TEST_ONLY_REACHABLE", "APS-DEAD-CODE-TEST-ONLY-REACHABILITY-001", "ERROR", "HIGH"
            elif record.private:
                category, code, rule, severity, confidence = "production_unreachable", "APS_DEAD_CODE_PRODUCTION_UNREACHABLE", "APS-DEAD-CODE-PRODUCTION-REACHABILITY-001", "ERROR", "HIGH"
            else:
                category, code, rule, severity, confidence = "production_unreachable", "APS_DEAD_CODE_PRODUCTION_UNREACHABLE", "APS-DEAD-CODE-PRODUCTION-REACHABILITY-001", "WARNING", "MEDIUM"
            findings.append(Finding(
                stable_finding_id("APS-DC-REACH", module.path, qn, record.kind, category), rule, code, severity, category, confidence,
                module.path, record.line, qn, record.kind, prod, test, entrypoint_paths.get(key, []),
                {"graph_node": key, "registered_entrypoint": key in {f"{item['path']}:{item['symbol']}" for item in entrypoints}, "public_contract_evidence": contract_evidence.get(key, [])},
                "Symbol is reachable from tests but not production roots." if test else "Symbol is not reachable from registered production roots.",
                "Register a real external/dynamic entrypoint, remove with regression proof, or use a bounded evidence-backed allowlist.",
            ))
    return production, tests, findings


@enforces_rule("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001")
@emits_diagnostic("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001", "APS_DEAD_CODE_DYNAMIC_ENTRYPOINT_VALID")
@emits_diagnostic("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001", "APS_DEAD_CODE_UNKNOWN_DYNAMIC_ENTRYPOINT")
def detect_unknown_dynamic_references(modules: dict[str, ModuleIndex], entrypoints: list[dict], production: set[str] | None = None) -> list[Finding]:
    registered = {str(item["symbol"]).split(".")[-1] for item in entrypoints}
    production = production or set()
    production_names = {item.split(":", 1)[1].split(".")[-1] for item in production}
    findings: list[Finding] = []
    known_symbols = {qn.split(".")[-1] for module in modules.values() for qn in module.symbols}
    for module in modules.values():
        if module.is_test:
            continue
        for name in sorted(module.dynamic_names & known_symbols):
            if name in registered or name in production_names:
                continue
            findings.append(Finding(
                stable_finding_id("APS-DC-DYN", module.path, name, "dynamic_entrypoint"), "APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001",
                "APS_DEAD_CODE_UNKNOWN_DYNAMIC_ENTRYPOINT", "WARNING", "dynamic_entrypoint", "MEDIUM",
                module.path, 0, name, "dynamic_reference", False, False, [],
                {"mechanism": "getattr/setattr/hasattr", "name": name},
                "String-based dynamic reference exists without an exact registered entrypoint.",
                "Register the dynamic entrypoint with evidence or remove the reflective reference.",
            ))
    return findings
