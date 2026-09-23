#!/usr/bin/env python3
# ======================================================================
# v128_validation.py — версия 1.0
# Семантические validators v2.9.128: trusted control plane, реестры
# функций, lifecycle, journal и capability evidence.
# ======================================================================

from __future__ import annotations

import ast
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

# Support both normal CLI imports and direct importlib loading in tests/tools.
sys.path.insert(0, str(Path(__file__).resolve().parent))
# Ре-экспорт: тесты зовут его как v128.semantic_control_plane_findings(...),
# то есть через этот модуль. Удаление ломает импорт test_v2_9_128_regressions.
from governance_validation import semantic_control_plane_findings  # noqa: F401,E402


# ======================================================================
# 1. ОБЩИЕ УТИЛИТЫ
# ======================================================================


def load_json(path: Path) -> tuple[Any | None, str | None]:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except (OSError, json.JSONDecodeError) as exc:
        return None, str(exc)



def _normal(text: Any) -> str:
    value = str(text or "").casefold().strip()
    value = re.sub(r"[^\wа-яё]+", " ", value, flags=re.IGNORECASE)
    return " ".join(value.split())


def _safe_repo_path(path: str) -> bool:
    if not path or Path(path).is_absolute():
        return False
    return ".." not in PurePosixPath(path.replace("\\", "/")).parts


def _git_output(root: Path, args: list[str]) -> tuple[str | None, str | None]:
    try:
        proc = subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if proc.returncode != 0:
        return None, (proc.stderr or proc.stdout).strip()
    return proc.stdout.strip(), None


def _json_at_ref(root: Path, ref: str, path: str) -> Any | None:
    text, error = _git_output(root, ["show", f"{ref}:{path}"])
    if error or text is None:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


def _parse_iso(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


# ======================================================================
# 2. SEMANTIC TRUSTED CONTROL PLANE
# Реализован в governance_validation.py и реэкспортирован выше.
# ======================================================================


# ======================================================================
# 3. FUNCTION INVENTORY, DUPLICATION И AST COVERAGE
# ======================================================================


LIFECYCLE_ORDER = [
    "PLANNED", "APPROVED", "WIP", "IMPLEMENTED", "TESTED_TARGETED",
    "TESTED_AFFECTED", "TESTED_FULL", "READY_FOR_REVIEW", "READY_FOR_MERGE",
    "MERGED", "DONE", "BLOCKED", "FAILED", "DEPRECATED", "REMOVED",
]

ALLOWED_TRANSITIONS = {
    "PLANNED": {"APPROVED", "WIP", "BLOCKED", "FAILED"},
    "APPROVED": {"WIP", "BLOCKED", "FAILED"},
    "WIP": {"IMPLEMENTED", "BLOCKED", "FAILED"},
    "IMPLEMENTED": {"TESTED_TARGETED", "MERGED", "WIP", "BLOCKED", "FAILED"},
    "TESTED_TARGETED": {"TESTED_AFFECTED", "WIP", "BLOCKED", "FAILED"},
    "TESTED_AFFECTED": {"TESTED_FULL", "WIP", "BLOCKED", "FAILED"},
    "TESTED_FULL": {"READY_FOR_REVIEW", "WIP", "BLOCKED", "FAILED"},
    "READY_FOR_REVIEW": {"READY_FOR_MERGE", "WIP", "BLOCKED", "FAILED"},
    "READY_FOR_MERGE": {"MERGED", "WIP", "BLOCKED", "FAILED"},
    "MERGED": {"DONE", "ROLLED_BACK", "FAILED"},
    "DONE": {"DEPRECATED"},
    "BLOCKED": {"WIP", "FAILED"},
    "FAILED": {"WIP", "REMOVED"},
    "DEPRECATED": {"REMOVED"},
    "REMOVED": set(),
}


def _registry_dir(root: Path) -> Path:
    return root / "docs" / "registry"


def _read_array(path: Path, label: str, findings: list[str]) -> list[dict[str, Any]]:
    if not path.exists():
        findings.append(f"{label.upper()}_MISSING:{path.relative_to(path.parents[2]) if len(path.parents) > 2 else path}")
        return []
    data, error = load_json(path)
    if error or not isinstance(data, list):
        findings.append(f"{label.upper()}_INVALID:{error or 'root is not array'}")
        return []
    return [item for item in data if isinstance(item, dict)]


def _entry_id(entry: dict[str, Any]) -> str | None:
    for key in ("function_id", "id"):
        if isinstance(entry.get(key), str) and entry[key].strip():
            return entry[key].strip()
    return None


def _user_entrypoints(entry: dict[str, Any]) -> tuple[set[str], set[str]]:
    routes: set[str] = set()
    commands: set[str] = set()
    for item in entry.get("public_entrypoints", entry.get("entry_points", [])) or []:
        if isinstance(item, str):
            if item.startswith("/"):
                routes.add(item)
            elif " " in item or item.startswith("python"):
                commands.add(item)
        elif isinstance(item, dict):
            route = item.get("route") or item.get("path")
            command = item.get("command") or item.get("cmd")
            if isinstance(route, str):
                routes.add(route)
            if isinstance(command, str):
                commands.add(command)
    return routes, commands


def _semantic_tokens(value: Any) -> set[str]:
    normalized = _normal(value)
    return {token for token in normalized.replace("_", " ").split() if len(token) >= 3}


def _overlap_score(left: dict[str, Any], right: dict[str, Any]) -> float:
    left_tokens = set().union(*(_semantic_tokens(left.get(field)) for field in ("title", "description", "summary", "inputs", "outputs")))
    right_tokens = set().union(*(_semantic_tokens(right.get(field)) for field in ("title", "description", "summary", "inputs", "outputs")))
    if len(left_tokens) < 3 or len(right_tokens) < 3:
        return 0.0
    union = left_tokens | right_tokens
    return len(left_tokens & right_tokens) / len(union) if union else 0.0


def check_function_duplication(root: Path) -> list[str]:
    findings: list[str] = []
    users = _read_array(_registry_dir(root) / "user_functions.json", "user_function_registry", findings)
    technical = _read_array(_registry_dir(root) / "functions.json", "function_registry", findings)

    def approved(entry: dict[str, Any]) -> bool:
        kind = entry.get("duplicate_class")
        return kind in {"INTENTIONAL_ALIAS", "APPROVED_REPLACEMENT"} and all(
            isinstance(entry.get(field), str) and entry[field].strip()
            for field in ("duplicate_rationale", "duplicate_owner", "task_id", "architectural_decision", "approved_reviewer")
        ) and isinstance(entry.get("migration_plan"), str) and entry["migration_plan"].strip()

    seen_user_ids: dict[str, dict[str, Any]] = {}
    seen_titles: dict[str, dict[str, Any]] = {}
    seen_routes: dict[str, dict[str, Any]] = {}
    seen_commands: dict[str, dict[str, Any]] = {}
    seen_semantics: dict[str, dict[str, Any]] = {}
    for entry in users:
        identity = _entry_id(entry)
        if identity:
            if identity in seen_user_ids:
                findings.append(f"EXACT_DUPLICATE:user_function:{identity}")
            seen_user_ids[identity] = entry
        title_key = _normal(entry.get("title"))
        if title_key:
            if title_key in seen_titles and not (approved(entry) or approved(seen_titles[title_key])):
                findings.append(f"SEMANTIC_DUPLICATE:user_function:title:{identity}:{_entry_id(seen_titles[title_key])}")
            seen_titles[title_key] = entry
        semantic_key = "|".join(
            part for part in (
                _normal(entry.get("description") or entry.get("summary")),
                _normal(entry.get("inputs")),
                _normal(entry.get("outputs")),
            ) if part
        )
        if semantic_key:
            if semantic_key in seen_semantics and not (approved(entry) or approved(seen_semantics[semantic_key])):
                findings.append(f"SEMANTIC_DUPLICATE:user_function:intent:{identity}:{_entry_id(seen_semantics[semantic_key])}")
            seen_semantics[semantic_key] = entry
        routes, commands = _user_entrypoints(entry)
        for route in routes:
            if route in seen_routes and not approved(entry):
                findings.append(f"ROUTE_DUPLICATE:{route}:{identity}:{_entry_id(seen_routes[route])}")
            seen_routes[route] = entry
        for command in commands:
            if command in seen_commands and not approved(entry):
                findings.append(f"CLI_DUPLICATE:{command}:{identity}:{_entry_id(seen_commands[command])}")
            seen_commands[command] = entry

    for index, left in enumerate(users):
        for right in users[index + 1:]:
            if approved(left) or approved(right):
                continue
            left_id = _entry_id(left) or "<unknown>"
            right_id = _entry_id(right) or "<unknown>"
            score = _overlap_score(left, right)
            if score >= 0.55:
                findings.append(f"POSSIBLE_OVERLAP:user_function:{left_id}:{right_id}:score={score:.3f}")

    maps: dict[str, dict[str, dict[str, Any]]] = {
        "id": {}, "qualified": {}, "signature": {}, "route": {}, "cli": {},
    }
    for entry in technical:
        identity = _entry_id(entry) or "<unknown>"
        keys = {
            "id": _entry_id(entry),
            "qualified": entry.get("qualified_symbol") or entry.get("qualified_name"),
            "signature": _normal(entry.get("signature")),
            "route": entry.get("route"),
            "cli": entry.get("cli_command"),
        }
        codes = {
            "id": "EXACT_DUPLICATE", "qualified": "SYMBOL_DUPLICATE",
            "signature": "SIGNATURE_DUPLICATE", "route": "ROUTE_DUPLICATE", "cli": "CLI_DUPLICATE",
        }
        for kind, raw in keys.items():
            if not isinstance(raw, str) or not raw.strip():
                continue
            key = raw.strip()
            if key in maps[kind] and not (approved(entry) or approved(maps[kind][key])):
                findings.append(f"{codes[kind]}:technical_function:{key}:{identity}:{_entry_id(maps[kind][key])}")
            maps[kind][key] = entry
    return sorted(set(findings))


def _ast_symbols(path: Path) -> tuple[dict[str, ast.AST], str | None]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
    except (OSError, SyntaxError) as exc:
        return {}, str(exc)
    symbols: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols[node.name] = node
            if isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        symbols[f"{node.name}.{child.name}"] = child
    return symbols, None


def _canonical_signature(node: ast.AST) -> str | None:
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
    positional = [*node.args.posonlyargs, *node.args.args]
    defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
    rendered: list[str] = []
    for index, (arg, default) in enumerate(zip(positional, defaults, strict=True)):
        value = arg.arg + (f": {ast.unparse(arg.annotation)}" if arg.annotation else "")
        if default is not None:
            value += f" = {ast.unparse(default)}"
        rendered.append(value)
        if node.args.posonlyargs and index + 1 == len(node.args.posonlyargs):
            rendered.append("/")
    if node.args.vararg:
        value = "*" + node.args.vararg.arg
        if node.args.vararg.annotation:
            value += f": {ast.unparse(node.args.vararg.annotation)}"
        rendered.append(value)
    elif node.args.kwonlyargs:
        rendered.append("*")
    for arg, default in zip(node.args.kwonlyargs, node.args.kw_defaults, strict=True):
        value = arg.arg + (f": {ast.unparse(arg.annotation)}" if arg.annotation else "")
        if default is not None:
            value += f" = {ast.unparse(default)}"
        rendered.append(value)
    if node.args.kwarg:
        value = "**" + node.args.kwarg.arg
        if node.args.kwarg.annotation:
            value += f": {ast.unparse(node.args.kwarg.annotation)}"
        rendered.append(value)
    result = ast.unparse(node.returns) if node.returns else None
    return f"{prefix}{node.name}({', '.join(rendered)})" + (f" -> {result}" if result else "")


def _signature_from_ast(node: ast.AST) -> str | None:
    return _canonical_signature(node)


def _canonical_declared_signature(value: str) -> str | None:
    text = value.strip()
    try:
        tree = ast.parse(f"def {text}:\n    pass\n")
    except SyntaxError:
        try:
            tree = ast.parse(f"{text}:\n    pass\n")
        except SyntaxError:
            return None
    node = tree.body[0] if tree.body else None
    return _canonical_signature(node) if node is not None else None


def check_function_registry(root: Path, *, public_symbol_coverage: bool = False, base_ref: str | None = None) -> list[str]:
    findings: list[str] = []
    technical = _read_array(_registry_dir(root) / "functions.json", "function_registry", findings)
    intents = _read_array(_registry_dir(root) / "function_intents.json", "function_intents", findings)
    intent_by_id = {_entry_id(entry): entry for entry in intents if _entry_id(entry)}
    base_ids: set[str] = set()
    base_intents: dict[str, dict[str, Any]] = {}
    if base_ref:
        base_functions = _json_at_ref(root, base_ref, "docs/registry/functions.json")
        if isinstance(base_functions, list):
            base_ids = {_entry_id(entry) for entry in base_functions if isinstance(entry, dict) and _entry_id(entry)}
        base_intent_data = _json_at_ref(root, base_ref, "docs/registry/function_intents.json")
        if isinstance(base_intent_data, list):
            base_intents = {_entry_id(entry): entry for entry in base_intent_data if isinstance(entry, dict) and _entry_id(entry)}
    registered: set[tuple[str, str]] = set()
    for entry in technical:
        identity = _entry_id(entry) or "<unknown>"
        path_value = entry.get("path")
        symbol = entry.get("symbol")
        if base_ref and identity not in base_ids:
            intent = base_intents.get(identity)
            if not isinstance(intent, dict) or intent.get("status") not in {"APPROVED", "ACTIVATED"}:
                findings.append(f"FUNCTION_INTENT_NOT_APPROVED:{identity}")
            else:
                for field in ("task_id", "path", "symbol", "kind"):
                    if intent.get(field) != entry.get(field):
                        findings.append(f"FUNCTION_INTENT_ACTIVATION_MISMATCH:{identity}:{field}")
        if identity in intent_by_id and intent_by_id[identity].get("status") == "CANCELLED":
            findings.append(f"FUNCTION_INTENT_CANCELLED:{identity}")
        if not isinstance(path_value, str) or not isinstance(symbol, str):
            findings.append(f"FUNCTION_REGISTRY_INVALID:{identity}:path/symbol required")
            continue
        if not _safe_repo_path(path_value):
            findings.append(f"FUNCTION_REGISTRY_INVALID:{identity}:unsafe path:{path_value}")
            continue
        target = root / path_value
        if not target.exists():
            findings.append(f"REGISTERED_SYMBOL_NOT_FOUND:{identity}:file:{path_value}")
            continue
        symbols, error = _ast_symbols(target)
        if error:
            findings.append(f"REGISTERED_SYMBOL_NOT_FOUND:{identity}:parse:{error}")
            continue
        lookup = symbol
        qualified = entry.get("qualified_symbol") or entry.get("qualified_name")
        if isinstance(qualified, str) and "." in qualified:
            tail = ".".join(qualified.split(".")[-2:])
            if tail in symbols:
                lookup = tail
        if lookup not in symbols:
            findings.append(f"REGISTERED_SYMBOL_NOT_FOUND:{identity}:{path_value}::{lookup}")
            continue
        registered.add((path_value, lookup.split(".")[-1]))
        declared = entry.get("signature")
        actual = _signature_from_ast(symbols[lookup])
        if isinstance(declared, str) and actual:
            canonical_declared = _canonical_declared_signature(declared)
            if canonical_declared is None or canonical_declared != actual:
                findings.append(f"FUNCTION_SIGNATURE_DRIFT:{identity}:declared={declared}:actual={actual}")

    if public_symbol_coverage:
        for path in sorted(root.glob("src/**/*.py")):
            rel = path.relative_to(root).as_posix()
            symbols, error = _ast_symbols(path)
            if error:
                continue
            for symbol, node in symbols.items():
                if "." in symbol or symbol.startswith("_"):
                    continue
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and (rel, symbol) not in registered:
                    findings.append(f"PUBLIC_SYMBOL_NOT_REGISTERED:{rel}::{symbol}")
    return sorted(set(findings))


def check_function_intents(root: Path) -> list[str]:
    findings: list[str] = []
    intents = _read_array(_registry_dir(root) / "function_intents.json", "function_intents", findings)
    seen: set[str] = set()
    for entry in intents:
        identity = _entry_id(entry)
        if not identity:
            findings.append("FUNCTION_INTENT_INVALID:missing function_id")
            continue
        if identity in seen:
            findings.append(f"FUNCTION_INTENT_DUPLICATE:{identity}")
        seen.add(identity)
        for field in ("task_id", "path", "symbol", "kind", "approved_by", "approved_at"):
            if not isinstance(entry.get(field), str) or not entry[field]:
                findings.append(f"FUNCTION_INTENT_INVALID:{identity}:{field}")
        if entry.get("status") not in {"APPROVED", "ACTIVATED", "CANCELLED"}:
            findings.append(f"FUNCTION_INTENT_INVALID:{identity}:status")
        if isinstance(entry.get("path"), str) and not _safe_repo_path(entry["path"]):
            findings.append(f"FUNCTION_INTENT_INVALID:{identity}:unsafe path")
    return sorted(set(findings))


def check_user_function_registry(root: Path) -> list[str]:
    findings: list[str] = []
    users = _read_array(_registry_dir(root) / "user_functions.json", "user_function_registry", findings)
    seen: set[str] = set()
    for entry in users:
        identity = _entry_id(entry)
        if not identity:
            findings.append("USER_FUNCTION_REGISTRY_INVALID:missing function_id/id")
            continue
        if identity in seen:
            findings.append(f"EXACT_DUPLICATE:user_function:{identity}")
        seen.add(identity)
        state = entry.get("lifecycle_state") or entry.get("status")
        if state in {"PLANNED", "APPROVED", "WIP", "IMPLEMENTED", "TESTED_TARGETED", "TESTED_AFFECTED", "TESTED_FULL", "READY_FOR_REVIEW", "READY_FOR_MERGE", "MERGED", "DONE"}:
            if not isinstance(entry.get("task_id") or entry.get("introduced_by_task"), str):
                findings.append(f"FUNCTION_TASK_LINK_MISSING:{identity}")
            if state in {"WIP", "IMPLEMENTED", "TESTED_TARGETED", "TESTED_AFFECTED", "TESTED_FULL", "READY_FOR_REVIEW", "READY_FOR_MERGE"} and not isinstance(entry.get("lease_id"), str):
                findings.append(f"FUNCTION_LEASE_MISSING:{identity}:{state}")
            if state == "READY_FOR_MERGE" and not isinstance(entry.get("verified_attestation"), str):
                findings.append(f"FUNCTION_ATTESTATION_MISSING:{identity}")
            if state in {"MERGED", "DONE"} and not isinstance(entry.get("merged_commit"), str):
                findings.append(f"FUNCTION_NOT_IN_PROTECTED_MAIN:{identity}:merge commit missing")
        criteria = entry.get("acceptance_criteria")
        if state in {"PLANNED", "APPROVED", "WIP"} and (not isinstance(criteria, list) or not criteria):
            findings.append(f"USER_FUNCTION_REGISTRY_INVALID:{identity}:acceptance_criteria required")
    return sorted(set(findings))


def _task_documents(root: Path) -> dict[str, dict[str, Any]]:
    tasks: dict[str, dict[str, Any]] = {}
    task_dir = _registry_dir(root) / "agent_tasks"
    candidates = list(task_dir.glob("*.json")) if task_dir.exists() else []
    candidates.extend((_registry_dir(root) / "agent_tasks.example").glob("*.json") if (_registry_dir(root) / "agent_tasks.example").exists() else [])
    for path in candidates:
        data, error = load_json(path)
        if not error and isinstance(data, dict):
            identity = data.get("task_id") or data.get("id")
            if isinstance(identity, str):
                tasks[identity] = data
    return tasks


def _active_lease_entries(root: Path) -> list[dict[str, Any]]:
    path = _registry_dir(root) / "active_work_packages.json"
    data, error = load_json(path)
    if error or not isinstance(data, dict):
        return []
    raw = data.get("active", data.get("leases", []))
    return [item for item in raw if isinstance(item, dict)] if isinstance(raw, list) else []


def check_registry_task_linkage(root: Path) -> list[str]:
    findings: list[str] = []
    users = _read_array(_registry_dir(root) / "user_functions.json", "user_function_registry", findings)
    technical = _read_array(_registry_dir(root) / "functions.json", "function_registry", findings)
    intents = _read_array(_registry_dir(root) / "function_intents.json", "function_intents", findings)
    tasks = _task_documents(root)
    leases = _active_lease_entries(root)
    user_ids = {_entry_id(entry) for entry in users if _entry_id(entry)}
    technical_ids = {_entry_id(entry) for entry in technical if _entry_id(entry)}
    intent_ids = {_entry_id(entry) for entry in intents if _entry_id(entry) and entry.get("status") in {"APPROVED", "ACTIVATED"}}
    lease_by_task = {entry.get("task_id"): entry for entry in leases if isinstance(entry.get("task_id"), str)}

    for entry in [*users, *technical]:
        identity = _entry_id(entry) or "<unknown>"
        task_id = entry.get("task_id") or entry.get("introduced_by_task")
        if isinstance(task_id, str) and task_id not in tasks:
            findings.append(f"FUNCTION_TASK_LINK_MISSING:{identity}:{task_id}")
        state = entry.get("lifecycle_state") or entry.get("status")
        if state == "WIP" and task_id not in lease_by_task:
            findings.append(f"FUNCTION_LEASE_MISSING:{identity}:{task_id}")
        if state == "WIP" and isinstance(entry.get("lease_id"), str) and task_id in lease_by_task:
            if entry["lease_id"] != lease_by_task[task_id].get("lease_id", entry["lease_id"]):
                findings.append(f"FUNCTION_LEASE_MISMATCH:{identity}:{entry['lease_id']}")

    for task_id, task in tasks.items():
        for field, known, code in (
            ("creates_user_functions", user_ids, "USER_FUNCTION_REGISTRY_UPDATE_MISSING"),
            ("modifies_user_functions", user_ids, "USER_FUNCTION_REGISTRY_UPDATE_MISSING"),
            ("creates_technical_functions", technical_ids | intent_ids, "FUNCTION_INTENT_OR_REGISTRY_MISSING"),
            ("modifies_technical_functions", technical_ids, "FUNCTION_REGISTRY_UPDATE_MISSING"),
            ("deprecates_functions", technical_ids | user_ids, "FUNCTION_REGISTRY_UPDATE_MISSING"),
        ):
            for identity in task.get(field, []) or []:
                if isinstance(identity, str) and identity not in known:
                    findings.append(f"{code}:{task_id}:{identity}")
    return sorted(set(findings))


def check_function_lifecycle(root: Path) -> list[str]:
    findings: list[str] = []
    users = _read_array(_registry_dir(root) / "user_functions.json", "user_function_registry", findings)
    technical = _read_array(_registry_dir(root) / "functions.json", "function_registry", findings)
    for entry in [*users, *technical]:
        identity = _entry_id(entry) or "<unknown>"
        state = entry.get("lifecycle_state")
        legacy_status = entry.get("status")
        if state is None:
            continue
        compatible_status = {
            "PLANNED": {"PLANNED"}, "APPROVED": {"PLANNED", "WIP"}, "WIP": {"WIP"},
            "IMPLEMENTED": {"WIP", "ACTIVE"}, "TESTED_TARGETED": {"WIP", "ACTIVE"},
            "TESTED_AFFECTED": {"WIP", "ACTIVE"}, "TESTED_FULL": {"WIP", "ACTIVE"},
            "READY_FOR_REVIEW": {"WIP", "ACTIVE"}, "READY_FOR_MERGE": {"WIP", "ACTIVE"},
            "MERGED": {"ACTIVE"}, "DONE": {"DONE", "ACTIVE"}, "BLOCKED": {"WIP"},
            "FAILED": {"WIP"}, "DEPRECATED": {"DEPRECATED"}, "REMOVED": {"REMOVED"},
        }.get(state, set())
        if isinstance(legacy_status, str) and compatible_status and legacy_status not in compatible_status:
            findings.append(f"FUNCTION_STATUS_LIFECYCLE_CONFLICT:{identity}:{legacy_status}:{state}")
        if state not in LIFECYCLE_ORDER:
            findings.append(f"FUNCTION_LIFECYCLE_INVALID:{identity}:{state}")
            continue
        previous = entry.get("previous_lifecycle_state")
        if isinstance(previous, str) and previous != state and state not in ALLOWED_TRANSITIONS.get(previous, set()):
            findings.append(f"FUNCTION_LIFECYCLE_TRANSITION_INVALID:{identity}:{previous}->{state}")
        if state == "DONE" and entry.get("post_merge_validation") != "PASS":
            findings.append(f"FUNCTION_NOT_IN_PROTECTED_MAIN:{identity}:post_merge_validation")
    return sorted(set(findings))


def check_change_journal_v128(root: Path, base_ref: str | None = None) -> list[str]:
    path = _registry_dir(root) / "change_journal.jsonl"
    if not path.exists():
        return ["CHANGE_JOURNAL_MISSING:docs/registry/change_journal.jsonl"]
    findings: list[str] = []
    seen: set[str] = set()
    last_time: dict[tuple[str, str], datetime] = {}
    previous_state: dict[tuple[str, str], str] = {}
    actions = {
        "PLANNED", "IMPLEMENTATION_STARTED", "ADDED", "MODIFIED", "RENAMED", "DEPRECATED",
        "REPLACED", "REMOVED", "TESTED_TARGETED", "TESTED_AFFECTED", "TESTED_FULL",
        "READY_FOR_REVIEW", "READY_FOR_MERGE", "MERGED", "DONE", "ROLLED_BACK",
    }
    lines = path.read_text(encoding="utf-8").splitlines()
    for number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            entry = json.loads(raw)
        except json.JSONDecodeError as exc:
            findings.append(f"CHANGE_JOURNAL_INVALID:line={number}:{exc}")
            continue
        if not isinstance(entry, dict):
            findings.append(f"CHANGE_JOURNAL_INVALID:line={number}:not object")
            continue
        # Legacy v2.9.127 lines remain readable but new lifecycle enforcement applies to v128 dialect.
        if "event_id" not in entry:
            continue
        event_id = entry.get("event_id")
        if not isinstance(event_id, str) or not event_id:
            findings.append(f"CHANGE_JOURNAL_INVALID:line={number}:event_id")
            continue
        if event_id in seen:
            findings.append(f"CHANGE_JOURNAL_EVENT_DUPLICATE:{event_id}")
        seen.add(event_id)
        action = entry.get("action")
        if action not in actions:
            findings.append(f"CHANGE_JOURNAL_ACTION_INVALID:{event_id}:{action}")
        entity = (str(entry.get("entity_type")), str(entry.get("entity_id")))
        timestamp = _parse_iso(entry.get("timestamp"))
        if timestamp is None:
            findings.append(f"CHANGE_JOURNAL_INVALID:{event_id}:timestamp")
        elif entity in last_time and timestamp < last_time[entity]:
            findings.append(f"CHANGE_JOURNAL_TIME_REVERSED:{event_id}")
        elif timestamp is not None:
            last_time[entity] = timestamp
        from_state = entry.get("from_state")
        to_state = entry.get("to_state")
        if isinstance(from_state, str) and isinstance(to_state, str):
            if to_state not in ALLOWED_TRANSITIONS.get(from_state, set()) and from_state != to_state:
                findings.append(f"FUNCTION_LIFECYCLE_TRANSITION_INVALID:{event_id}:{from_state}->{to_state}")
            expected = previous_state.get(entity)
            if expected is not None and expected != from_state:
                findings.append(f"CHANGE_JOURNAL_STATE_CHAIN_INVALID:{event_id}:{expected}!={from_state}")
            previous_state[entity] = to_state
        if action == "MERGED" and not isinstance(entry.get("commit_sha"), str):
            findings.append(f"CHANGE_JOURNAL_MERGE_COMMIT_MISSING:{event_id}")
        if action == "DONE" and (not isinstance(entry.get("commit_sha"), str) or not isinstance(entry.get("attestation_id"), str)):
            findings.append(f"CHANGE_JOURNAL_DONE_EVIDENCE_MISSING:{event_id}")

    if base_ref:
        base_text, error = _git_output(root, ["show", f"{base_ref}:docs/registry/change_journal.jsonl"])
        if error is None and base_text is not None:
            current = path.read_text(encoding="utf-8")
            normalized_base = base_text + ("\n" if base_text and not base_text.endswith("\n") else "")
            if not current.startswith(normalized_base):
                findings.append("CHANGE_JOURNAL_NOT_APPEND_ONLY")
    return sorted(set(findings))


def check_function_test_evidence(root: Path) -> list[str]:
    findings: list[str] = []
    users = _read_array(_registry_dir(root) / "user_functions.json", "user_function_registry", findings)
    required_for_state = {
        "TESTED_TARGETED": ("targeted_tests",),
        "TESTED_AFFECTED": ("targeted_tests", "affected_tests"),
        "TESTED_FULL": ("targeted_tests", "affected_tests", "full_regression"),
        "READY_FOR_REVIEW": ("targeted_tests", "affected_tests", "full_regression"),
        "READY_FOR_MERGE": ("targeted_tests", "affected_tests", "full_regression"),
        "MERGED": ("targeted_tests", "affected_tests", "full_regression"),
        "DONE": ("targeted_tests", "affected_tests", "full_regression", "post_merge_validation"),
    }
    db_path = __import__("os").environ.get("APS_ORCHESTRATOR_DB")
    db = None
    if db_path:
        try:
            from orchestrator_control_plane import OrchestratorDB
            db = OrchestratorDB(db_path)
        except Exception as exc:
            findings.append(f"TRUSTED_TEST_EVIDENCE_DB_UNAVAILABLE:{exc}")
    try:
        for entry in users:
            identity = _entry_id(entry) or "<unknown>"
            state = entry.get("lifecycle_state")
            ids = entry.get("trusted_test_evidence_ids", {})
            if entry.get("trusted_test_evidence"):
                findings.append(f"FUNCTION_TEST_EVIDENCE_UNTRUSTED_INLINE:{identity}")
            for field in required_for_state.get(state, ()):
                evidence_id = ids.get(field) if isinstance(ids, dict) else None
                if not isinstance(evidence_id, str) or not evidence_id:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_MISSING:{identity}:{field}")
                    continue
                if db is None:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_NOT_VERIFIED:{identity}:{field}:{evidence_id}")
                    continue
                try:
                    evidence = db.get_test_evidence(evidence_id)
                except Exception as exc:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_NOT_VERIFIED:{identity}:{field}:{exc}")
                    continue
                expected_commit = entry.get("implementation_commit") or entry.get("merged_commit")
                if expected_commit and evidence.get("head_sha") != expected_commit:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_STALE:{identity}:{field}")
                if evidence.get("task_id") != (entry.get("task_id") or entry.get("introduced_by_task")):
                    findings.append(f"FUNCTION_TEST_EVIDENCE_TASK_MISMATCH:{identity}:{field}")
                if evidence.get("test_role") != field:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_ROLE_MISMATCH:{identity}:{field}")
                if evidence.get("issuer") not in {"trusted-candidate-runner", "trusted-post-merge-runner"}:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_ISSUER_INVALID:{identity}:{field}")
                if not isinstance(evidence.get("signer_identity"), str) or not evidence.get("signer_identity"):
                    findings.append(f"FUNCTION_TEST_EVIDENCE_SIGNER_MISSING:{identity}:{field}")
                if not isinstance(evidence.get("key_id"), str) or not evidence.get("key_id"):
                    findings.append(f"FUNCTION_TEST_EVIDENCE_KEY_ID_MISSING:{identity}:{field}")
                if not isinstance(evidence.get("run_id"), str) or not evidence.get("run_id"):
                    findings.append(f"FUNCTION_TEST_EVIDENCE_RUN_ID_MISSING:{identity}:{field}")
                if evidence.get("status") != "PASS" or evidence.get("exit_code") != 0:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_FAILED:{identity}:{field}")
                total = evidence.get("collected")
                if not isinstance(total, int) or evidence.get("completed") != total or evidence.get("accounted") != total:
                    findings.append(f"FUNCTION_TEST_EVIDENCE_ACCOUNTING_INVALID:{identity}:{field}")
                if evidence.get("failed") or evidence.get("errors"):
                    findings.append(f"FUNCTION_TEST_EVIDENCE_FAILED:{identity}:{field}")
                for digest_field in ("report_sha256", "stdout_sha256", "stderr_sha256", "tree_sha"):
                    if not isinstance(evidence.get(digest_field), str) or not evidence[digest_field]:
                        findings.append(f"FUNCTION_TEST_EVIDENCE_INCOMPLETE:{identity}:{field}:{digest_field}")
    finally:
        if db is not None:
            db.close()
    return sorted(set(findings))


def check_function_merge_status(root: Path, protected_ref: str = "HEAD") -> list[str]:
    findings: list[str] = []
    users = _read_array(_registry_dir(root) / "user_functions.json", "user_function_registry", findings)
    for entry in users:
        if entry.get("lifecycle_state") not in {"MERGED", "DONE"}:
            continue
        identity = _entry_id(entry) or "<unknown>"
        commit = entry.get("merged_commit")
        if not isinstance(commit, str):
            findings.append(f"FUNCTION_NOT_IN_PROTECTED_MAIN:{identity}:missing commit")
            continue
        _, error = _git_output(root, ["merge-base", "--is-ancestor", commit, protected_ref])
        if error:
            findings.append(f"FUNCTION_NOT_IN_PROTECTED_MAIN:{identity}:{commit}:{protected_ref}")
    return sorted(set(findings))


# Ре-экспорт: тесты зовут его как v128.check_capability_evidence_contract(...).
from capability_evidence_validation import check_capability_evidence_contract  # noqa: F401,E402


def all_function_findings(
    root: Path,
    *,
    base_ref: str | None = None,
    protected_ref: str = "HEAD",
    public_symbol_coverage: bool = False,
) -> list[str]:
    findings: list[str] = []
    findings.extend(check_function_intents(root))
    findings.extend(check_user_function_registry(root))
    findings.extend(check_function_registry(root, public_symbol_coverage=public_symbol_coverage, base_ref=base_ref))
    findings.extend(check_function_duplication(root))
    findings.extend(check_registry_task_linkage(root))
    findings.extend(check_function_lifecycle(root))
    findings.extend(check_change_journal_v128(root, base_ref))
    findings.extend(check_function_test_evidence(root))
    findings.extend(check_function_merge_status(root, protected_ref))
    return sorted(set(findings))
