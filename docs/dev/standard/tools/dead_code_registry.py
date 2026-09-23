#!/usr/bin/env python3
# ======================================================================
# dead_code_registry.py — версия 1.0
# Проверка registered entrypoints и ограниченного allowlist.
# ======================================================================
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from dead_code_evidence import PRODUCTION_ROOT_CONTRACT_TYPES, validate_evidence_set
from dead_code_types import Finding, stable_finding_id
from rule_traceability_types import emits_diagnostic, enforces_rule


def _version_tuple(value: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in value.split("."))
    except ValueError:
        return (0,)


def load_json_if_exists(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return default
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON object required: {path}")
    return data


def resolve_scan_scope_path(root: Path) -> Path:
    candidates = [root / "docs/registry/dead_code_scan_scope.json", root / "reference/dead_code_scan_scope.json"]
    return next((p for p in candidates if p.is_file()), candidates[-1])


SCAN_SCOPE_CATEGORIES = frozenset(
    {"vendored_tooling", "archived", "delivered_artifact", "generated", "third_party"}
)
SCAN_SCOPE_REQUIRED = ("exclusion_id", "path", "category", "reason", "owner")


def _scan_scope_entry_problem(entry: dict[str, Any]) -> str | None:
    """Причина, по которой запись не может сузить область, либо None."""
    missing = [f for f in SCAN_SCOPE_REQUIRED if not str(entry.get(f, "")).strip()]
    if missing:
        return f"Scan scope entry is missing required fields: {', '.join(missing)}."
    if entry.get("category") not in SCAN_SCOPE_CATEGORIES:
        return "Scan scope category is unknown."
    if len(str(entry.get("reason", ""))) < 10:
        return "Scan scope reason is too short to explain the exclusion."
    return None


@enforces_rule("APS-SCAN-SCOPE-UNIFORM-001")
@emits_diagnostic("APS-SCAN-SCOPE-UNIFORM-001", "SCAN_SCOPE_ENTRY_VALID")
@emits_diagnostic("APS-SCAN-SCOPE-UNIFORM-001", "SCAN_SCOPE_ENTRY_INVALID")
def validate_scan_scope(root: Path, entries: list[Any]) -> tuple[list[dict[str, Any]], list[Finding]]:
    """Отделяет применимые записи области от негодных.

    Негодная запись не сужает область и порождает блокирующую находку.
    Иначе объявленное сужение аудита можно было бы сделать анонимно — без
    причины, владельца и следа в отчёте, — а это ровно то, что запрещает
    `APS-SCAN-SCOPE-UNIFORM-001`.
    """
    valid: list[dict[str, Any]] = []
    findings: list[Finding] = []
    rel = resolve_scan_scope_path(root)
    try:
        rel_path = rel.relative_to(root).as_posix()
    except ValueError:
        rel_path = rel.as_posix()
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            problem = "Scan scope entry is not an object."
            entry = {}
        else:
            problem = _scan_scope_entry_problem(entry)
        if problem is None:
            valid.append(entry)
            continue
        eid = str(entry.get("exclusion_id", "")) or f"<index {index}>"
        findings.append(Finding(
            stable_finding_id("APS-SCAN-SCOPE", rel_path, eid),
            "APS-SCAN-SCOPE-UNIFORM-001", "SCAN_SCOPE_ENTRY_INVALID", "ERROR",
            "invalid_scan_scope", "HIGH", rel_path, 0, eid, "scan_scope",
            False, False, [], {"entry": entry}, problem,
            "Declare exclusion_id, path, category, reason and owner, or remove the entry.",
        ))
    return valid, findings


def load_scan_scope(root: Path) -> list[dict[str, Any]]:
    """Объявленные проектом каталоги вне области аудита.

    Аудит по умолчанию считает своим весь Python в дереве. Это неверно для
    проекта, куда внедрена чужая машинерия — плагины среды разработки,
    поставленные артефакты, архив. Без объявления такие каталоги дают счёт
    находок, к проекту не относящийся, и обесценивают стадию.

    Исключение — не молчаливое сужение: каждая запись несёт причину и
    владельца, а отчёт перечисляет применённые исключения и число
    пропущенных файлов. Запись без них не сужает область: возвращаются
    только валидные, а негодные отдаются находками через
    `validate_scan_scope`.
    """
    valid, _ = load_scan_scope_checked(root)
    return valid


def load_scan_scope_checked(root: Path) -> tuple[list[dict[str, Any]], list[Finding]]:
    """`load_scan_scope` вместе с находками по негодным записям."""
    path = resolve_scan_scope_path(root)
    if not path.is_file():
        return [], []
    data = load_json_if_exists(path, {})
    entries = data.get("exclusions")
    if not isinstance(entries, list):
        return [], []
    return validate_scan_scope(root, entries)


def resolve_registry_paths(root: Path) -> tuple[Path, Path, Path]:
    entry_candidates = [root / "docs/registry/dead_code_entrypoints.json", root / "reference/dead_code_entrypoints.json"]
    allow_candidates = [root / "docs/registry/dead_code_allowlist.json", root / "reference/dead_code_allowlist.json"]
    api_candidates = [root / "docs/registry/dead_code_public_api.json", root / "reference/dead_code_public_api.json"]
    return (
        next((p for p in entry_candidates if p.is_file()), entry_candidates[-1]),
        next((p for p in allow_candidates if p.is_file()), allow_candidates[-1]),
        next((p for p in api_candidates if p.is_file()), api_candidates[-1]),
    )


@enforces_rule("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001")
@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@emits_diagnostic("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001", "APS_DEAD_CODE_DYNAMIC_ENTRYPOINT_VALID")
@emits_diagnostic("APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001", "APS_DEAD_CODE_UNKNOWN_DYNAMIC_ENTRYPOINT")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_entrypoints(root: Path, data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[Finding]]:
    valid: list[dict[str, Any]] = []
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for idx, item in enumerate(data.get("entrypoints", []), 1):
        path = str(item.get("path", ""))
        symbol = str(item.get("symbol", ""))
        evidence = item.get("evidence", [])
        key = (path, symbol)
        reason = None
        code = "APS_DEAD_CODE_UNKNOWN_DYNAMIC_ENTRYPOINT"
        rule = "APS-DEAD-CODE-DYNAMIC-ENTRYPOINT-001"
        category = "unknown_dynamic_entrypoint"
        if not path or not symbol or "*" in path or "*" in symbol:
            reason = "Entrypoint requires exact path and symbol without wildcards."
        elif key in seen:
            reason = "Duplicate registered entrypoint."
        elif not (root / path).is_file():
            reason = "Entrypoint path does not exist."
        else:
            evidence_problems = validate_evidence_set(
                root,
                evidence,
                target_path=path,
                target_symbol=symbol,
                required_primary_types={"entrypoint"},
            )
            if evidence_problems:
                reason = "; ".join(evidence_problems)
                code = "APS_DEAD_CODE_EVIDENCE_INVALID"
                rule = "APS-DEAD-CODE-EVIDENCE-BINDING-001"
                category = "invalid_evidence"
        if reason:
            findings.append(Finding(
                stable_finding_id("APS-DC-ENTRY", path, symbol, reason), rule,
                code, "ERROR", category, "HIGH",
                path or "<missing>", 0, symbol or "<missing>", "entrypoint", False, False, [],
                {"entrypoint": item}, reason, "Register an exact typed and evidence-backed production entrypoint.",
            ))
        else:
            seen.add(key)
            valid.append(item)
    return valid, findings


@enforces_rule("APS-DEAD-CODE-PUBLIC-API-CONTRACT-001")
@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@emits_diagnostic("APS-DEAD-CODE-PUBLIC-API-CONTRACT-001", "APS_DEAD_CODE_PUBLIC_API_CONTRACT_VALID")
@emits_diagnostic("APS-DEAD-CODE-PUBLIC-API-CONTRACT-001", "APS_DEAD_CODE_PUBLIC_API_CONTRACT_INVALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_public_api_contracts(root: Path, data: dict[str, Any]) -> tuple[list[dict[str, Any]], list[Finding]]:
    valid: list[dict[str, Any]] = []
    findings: list[Finding] = []
    seen_ids: set[str] = set()
    seen_targets: set[tuple[str, str]] = set()
    allowed_kinds = {"compatibility_api", "plugin_hook", "library_api", "external_contract"}
    manifest_version = str(load_json_if_exists(root / "manifest.json", {"version": "0.0.0"}).get("version", "0.0.0"))
    registry_version = str(data.get("standard_version", ""))
    for idx, item in enumerate(data.get("apis", []), 1):
        api_id = str(item.get("api_id", ""))
        path = str(item.get("path", ""))
        symbol = str(item.get("symbol", ""))
        kind = str(item.get("contract_kind", ""))
        owner = str(item.get("owner", "")).strip()
        evidence = item.get("evidence", [])
        target = (path, symbol)
        reason = None
        code = "APS_DEAD_CODE_PUBLIC_API_CONTRACT_INVALID"
        rule = "APS-DEAD-CODE-PUBLIC-API-CONTRACT-001"
        category = "invalid_public_api_contract"
        if registry_version != manifest_version:
            reason = "Public API registry standard_version must match manifest.version."
        elif not re.fullmatch(r"APS-DC-API-[A-Z0-9-]+", api_id) or api_id in seen_ids:
            reason = "Public API contract requires a unique canonical api_id."
        elif not path or not symbol or "*" in path or "*" in symbol:
            reason = "Public API contract requires exact path and symbol without wildcards."
        elif target in seen_targets:
            reason = "Duplicate public API contract target."
        elif kind not in allowed_kinds:
            reason = "Public API contract_kind is not recognized."
        elif not owner:
            reason = "Public API contract requires an owner."
        elif not (root / path).is_file():
            reason = "Public API contract path does not exist."
        else:
            evidence_problems = validate_evidence_set(
                root,
                evidence,
                target_path=path,
                target_symbol=symbol,
                required_primary_types={"public_api", "migration", "deprecation"},
            )
            if evidence_problems:
                reason = "; ".join(evidence_problems)
                code = "APS_DEAD_CODE_EVIDENCE_INVALID"
                rule = "APS-DEAD-CODE-EVIDENCE-BINDING-001"
                category = "invalid_evidence"
        if reason:
            findings.append(Finding(
                stable_finding_id("APS-DC-API", api_id, path, symbol, reason), rule,
                code, "ERROR", category, "HIGH",
                path or "<missing>", 0, symbol or "<missing>", "public_api_contract", False, False, [],
                {"contract": item}, reason, "Register an exact typed public API contract or remove the stale declaration.",
            ))
        else:
            seen_ids.add(api_id)
            seen_targets.add(target)
            valid.append(item)
    return valid, findings


def validate_public_api_targets(public_apis: list[dict[str, Any]], modules: dict[str, Any]) -> tuple[list[dict[str, Any]], list[Finding]]:
    valid: list[dict[str, Any]] = []
    findings: list[Finding] = []
    for idx, item in enumerate(public_apis, 1):
        path = str(item["path"])
        symbol = str(item["symbol"])
        module = modules.get(path)
        if module is None or symbol not in module.symbols:
            findings.append(Finding(
                stable_finding_id("APS-DC-API-TARGET", path, symbol), "APS-DEAD-CODE-PUBLIC-API-CONTRACT-001",
                "APS_DEAD_CODE_PUBLIC_API_CONTRACT_INVALID", "ERROR", "invalid_public_api_contract", "HIGH",
                path, 0, symbol, "public_api_contract", False, False, [],
                {"contract": item}, "Public API contract target does not resolve to a top-level symbol.",
                "Correct the exact target or remove the stale contract.",
            ))
        else:
            valid.append(item)
    return valid, findings


@enforces_rule("APS-DEAD-CODE-ALLOWLIST-001")
@enforces_rule("APS-DEAD-CODE-ALLOWLIST-EXPIRY-001")
@enforces_rule("APS-DEAD-CODE-EVIDENCE-BINDING-001")
@emits_diagnostic("APS-DEAD-CODE-ALLOWLIST-001", "APS_DEAD_CODE_ALLOWLIST_VALID")
@emits_diagnostic("APS-DEAD-CODE-ALLOWLIST-001", "APS_DEAD_CODE_ALLOWLIST_INVALID")
@emits_diagnostic("APS-DEAD-CODE-ALLOWLIST-EXPIRY-001", "APS_DEAD_CODE_ALLOWLIST_CURRENT")
@emits_diagnostic("APS-DEAD-CODE-ALLOWLIST-EXPIRY-001", "APS_DEAD_CODE_ALLOWLIST_EXPIRED")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_VALID")
@emits_diagnostic("APS-DEAD-CODE-EVIDENCE-BINDING-001", "APS_DEAD_CODE_EVIDENCE_INVALID")
def validate_allowlist(root: Path, data: dict[str, Any], current_version: str) -> tuple[list[dict[str, Any]], list[Finding]]:
    valid: list[dict[str, Any]] = []
    findings: list[Finding] = []
    seen: set[str] = set()
    category_contracts = {
        "dynamic_entrypoint": {"entrypoint"},
        "production_unreachable": set(PRODUCTION_ROOT_CONTRACT_TYPES),
        "test_only_reachable": {"public_api", "migration", "deprecation"},
        "unused_import": {"trusted_manifest", "migration", "deprecation"},
        "commented_code": {"migration", "deprecation"},
    }
    for idx, item in enumerate(data.get("entries", []), 1):
        aid = str(item.get("allowlist_id", ""))
        path = str(item.get("path", ""))
        symbol = str(item.get("symbol", ""))
        reason = str(item.get("reason", "")).strip()
        owner = str(item.get("owner", "")).strip()
        review = str(item.get("review_version", ""))
        evidence = item.get("evidence", [])
        category = str(item.get("category", ""))
        code = None
        message = None
        rule = "APS-DEAD-CODE-ALLOWLIST-001"
        finding_category = "invalid_allowlist"
        if not aid or aid in seen or not path or not symbol or "*" in path or "*" in symbol:
            code, message = "APS_DEAD_CODE_ALLOWLIST_INVALID", "Allowlist IDs and path/symbol targets must be unique and exact."
        elif not reason or not owner:
            code, message = "APS_DEAD_CODE_ALLOWLIST_INVALID", "Allowlist requires reason and owner."
        elif category == "syntactically_unreachable" or category not in category_contracts:
            code, message = "APS_DEAD_CODE_ALLOWLIST_INVALID", "Allowlist category is forbidden or unknown."
        elif not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", review) or _version_tuple(review) <= _version_tuple(current_version):
            code, message = "APS_DEAD_CODE_ALLOWLIST_EXPIRED", "Allowlist review_version must be later than the current standard version."
            rule = "APS-DEAD-CODE-ALLOWLIST-EXPIRY-001"
        elif not (root / path).is_file():
            code, message = "APS_DEAD_CODE_ALLOWLIST_INVALID", "Allowlisted path does not exist."
        else:
            evidence_problems = validate_evidence_set(
                root,
                evidence,
                target_path=path,
                target_symbol=symbol,
                required_primary_types=category_contracts[category],
            )
            if evidence_problems:
                code = "APS_DEAD_CODE_EVIDENCE_INVALID"
                message = "; ".join(evidence_problems)
                rule = "APS-DEAD-CODE-EVIDENCE-BINDING-001"
                finding_category = "invalid_evidence"
        if code:
            findings.append(Finding(
                stable_finding_id("APS-DC-ALLOW", aid, path, symbol, message), rule, code, "ERROR", finding_category, "HIGH",
                path or "<missing>", 0, symbol or "<missing>", "allowlist", False, False, [],
                {"allowlist_id": aid, "entry": item}, message or "Invalid allowlist.", "Fix or remove the bounded allowlist record.",
            ))
        else:
            seen.add(aid)
            valid.append(item)
    return valid, findings


def apply_allowlist(findings: list[Finding], entries: list[dict[str, Any]]) -> None:
    by_key = {(str(x["path"]), str(x["symbol"]), str(x["category"])): x for x in entries}
    for finding in findings:
        item = by_key.get((finding.path, finding.symbol, finding.category))
        if item:
            finding.disposition = "ALLOWLISTED"
            finding.allowlist_id = str(item["allowlist_id"])
