#!/usr/bin/env python3
# ======================================================================
# tz_governance.py — версия 1.0.0
# Fail-closed проверка жизненного цикла ТЗ и порядка аудитов APS v2.9.157.
# ======================================================================

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from rule_traceability_types import RuleFinding, emits_diagnostic, enforces_rule  # noqa: E402

VALID_STATUSES = {"DRAFT", "TODO", "WIP", "REVIEW", "BLOCKED", "DONE", "ARCHIVE", "CONFLICT"}
STATUS_FOLDER_TOKENS = {
    "реализовано", "для реализации", "сделано", "выполнено",
    "done", "todo", "wip", "review", "blocked", "archive",
}
INDEX_FILE_NAMES = {"readme.md"}
STRONG_EVIDENCE = {"TEST", "RUNTIME"}
MEDIUM_EVIDENCE = {"CODE", "CONFIG", "API", "DB", "CI", "UI", "REPORT"}
WEAK_EVIDENCE = {"DOC", "GIT"}
ALL_EVIDENCE = STRONG_EVIDENCE | MEDIUM_EVIDENCE | WEAK_EVIDENCE
HEADER_RE = re.compile(
    r"^\s*-\s*(?P<key>ID|Status|Priority|Owner|Updated|Verified|Blocked-by|Conflicts-with)\s*:\s*(?P<value>.*)$",
    re.IGNORECASE,
)
ITEM_RE = re.compile(r"^\s*-\s*\[(?P<mark>[ xX])\]\s*\((?P<priority>must|should|may)\)\s*(?P<text>.+)$")
EVIDENCE_RE = re.compile(r"\b(?P<kind>" + "|".join(sorted(ALL_EVIDENCE)) + r")\b\s+`(?P<ref>[^`]+)`")
STATUS_SUFFIX_RE = re.compile(r"__(?P<status>[A-Z_]+)$")
LINE_SUFFIX_RE = re.compile(r"^(?P<path>.+?):(?P<lines>\d+(?:[-,]\d+)*)$")
NUMERIC_PREFIX_RE = re.compile(r"^\d+[._ -]*")
BRACKET_STATUS_RE = re.compile(r"\s*\[(?:DONE|TODO|WIP|REVIEW|BLOCKED|ARCHIVE|DRAFT|CONFLICT)[^\]]*\]\s*", re.I)


@dataclass
class Evidence:
    kind: str
    ref: str


@dataclass
class Criterion:
    checked: bool
    priority: str
    text: str
    evidence: list[Evidence] = field(default_factory=list)


def _finding(code: str, rule_id: str, message: str, *, severity: str = "ERROR", **evidence: Any) -> RuleFinding:
    return RuleFinding(code, rule_id, message, severity, evidence)


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, check=False)


def _relative_safe_path(value: str) -> str | None:
    raw = value.strip().replace("\\", "/")
    if not raw or raw.startswith("/") or re.match(r"^[A-Za-z]:/", raw):
        return None
    path = Path(raw)
    if any(part in {"", ".", ".."} for part in path.parts):
        return None
    return path.as_posix()


def parse_header(text: str) -> dict[str, str]:
    header: dict[str, str] = {}
    canonical = {
        "id": "ID", "status": "Status", "priority": "Priority", "owner": "Owner",
        "updated": "Updated", "verified": "Verified", "blocked-by": "Blocked-by",
        "conflicts-with": "Conflicts-with",
    }
    for line in text.splitlines():
        match = HEADER_RE.match(line)
        if match:
            header.setdefault(canonical[match.group("key").lower()], match.group("value").strip())
    return header


def parse_criteria(text: str) -> list[Criterion]:
    result: list[Criterion] = []
    current: Criterion | None = None
    for line in text.splitlines():
        item = ITEM_RE.match(line)
        if item:
            current = Criterion(
                checked=item.group("mark").lower() == "x",
                priority=item.group("priority"),
                text=item.group("text").strip(),
            )
            result.append(current)
            continue
        if current is not None and "→" in line:
            for match in EVIDENCE_RE.finditer(line):
                current.evidence.append(Evidence(match.group("kind"), match.group("ref").strip()))
            continue
        if line.strip() and not line.startswith((" ", "\t")):
            current = None
    return result


def filename_status(path: Path) -> str | None:
    match = STATUS_SUFFIX_RE.search(path.stem)
    return match.group("status") if match else None


def normalized_spec_name(path: Path) -> str:
    stem = BRACKET_STATUS_RE.sub(" ", path.stem)
    stem = NUMERIC_PREFIX_RE.sub("", stem)
    stem = STATUS_SUFFIX_RE.sub("", stem)
    stem = re.sub(r"[\W_]+", " ", stem, flags=re.UNICODE).strip().casefold()
    return stem


def _active_spec_paths(root: Path, docs_root: Path) -> list[Path]:
    if not docs_root.is_dir():
        return []
    result: list[Path] = []
    for path in docs_root.rglob("*.md"):
        rel_parts = [part.casefold() for part in path.relative_to(docs_root).parts[:-1]]
        if any(part in {"_черновики", "_архив"} for part in rel_parts):
            continue
        if _is_directory_index(path):
            continue
        result.append(path)
    return sorted(result)


def _is_directory_index(path: Path) -> bool:
    """Индекс каталога — навигация по заданиям, а не задание.

    До v2.9.157 техническим заданием считался любой `.md` в корне ТЗ, поэтому
    `README.md` обязан был нести статус в имени файла и чек-лист приёмки —
    требование, которое индекс выполнить не может по смыслу (находка 30-04).
    Ограничение: исключается ровно одно имя и только оно.
    """
    return path.name.casefold() in INDEX_FILE_NAMES


@enforces_rule("APS-TZ-LAYOUT-001")
@emits_diagnostic("APS-TZ-LAYOUT-001", "TZ_LAYOUT_VALID")
@emits_diagnostic("APS-TZ-LAYOUT-001", "TZ_ROOT_DUPLICATED")
@emits_diagnostic("APS-TZ-LAYOUT-001", "TZ_STATUS_FOLDER_FORBIDDEN")
@emits_diagnostic("APS-TZ-LAYOUT-001", "TZ_DUPLICATE_SPECIFICATION")
def validate_layout(root: Path, docs_relative: str = "docs/ТЗ") -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    docs_root = root / docs_relative
    docs_parent = root / "docs"
    if docs_parent.is_dir():
        for candidate in docs_parent.iterdir():
            if not candidate.is_dir() or candidate == docs_root:
                continue
            folded = re.sub(r"[\s_-]+", "", candidate.name.casefold())
            if folded.startswith("тз") or folded.startswith("tz"):
                findings.append(_finding(
                    "TZ_ROOT_DUPLICATED", "APS-TZ-LAYOUT-001",
                    "A second technical-specification root is forbidden.", path=candidate.relative_to(root).as_posix(),
                ))
    specs = _active_spec_paths(root, docs_root)
    duplicates: dict[str, list[str]] = {}
    for path in specs:
        for part in path.relative_to(docs_root).parts[:-1]:
            token = re.sub(r"[_-]+", " ", part.casefold()).strip()
            if token in STATUS_FOLDER_TOKENS:
                findings.append(_finding(
                    "TZ_STATUS_FOLDER_FORBIDDEN", "APS-TZ-LAYOUT-001",
                    "Technical-specification folders must describe topic, not status.",
                    path=path.relative_to(root).as_posix(), folder=part,
                ))
        key = normalized_spec_name(path)
        if key:
            duplicates.setdefault(key, []).append(path.relative_to(root).as_posix())
    for key, paths in sorted(duplicates.items()):
        if len(paths) > 1:
            findings.append(_finding(
                "TZ_DUPLICATE_SPECIFICATION", "APS-TZ-LAYOUT-001",
                "Multiple specification files normalize to the same logical identity.",
                normalized_name=key, paths=paths,
            ))
    if not findings:
        findings.append(_finding("TZ_LAYOUT_VALID", "APS-TZ-LAYOUT-001", "Technical-specification layout is valid.", severity="INFO"))
    return findings


@enforces_rule("APS-TZ-STATUS-AUTHORITY-001")
@emits_diagnostic("APS-TZ-STATUS-AUTHORITY-001", "TZ_STATUS_AUTHORITY_VALID")
@emits_diagnostic("APS-TZ-STATUS-AUTHORITY-001", "TZ_STATUS_MISSING")
@emits_diagnostic("APS-TZ-STATUS-AUTHORITY-001", "TZ_STATUS_CONFLICT")
@emits_diagnostic("APS-TZ-STATUS-AUTHORITY-001", "TZ_BLOCK_REASON_MISSING")
@emits_diagnostic("APS-TZ-STATUS-AUTHORITY-001", "TZ_CONFLICT_REFERENCE_MISSING")
@emits_diagnostic("APS-TZ-STATUS-AUTHORITY-001", "TZ_CONDITIONAL_DONE_FORBIDDEN")
def validate_status_authority(path: Path, text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    header = parse_header(text)
    status = header.get("Status", "").upper()
    suffix = filename_status(path)
    if status not in VALID_STATUSES or suffix not in VALID_STATUSES:
        findings.append(_finding(
            "TZ_STATUS_MISSING", "APS-TZ-STATUS-AUTHORITY-001",
            "Status must exist both in the header and in the __STATUS filename suffix.",
            header_status=status or None, filename_status=suffix, path=path.as_posix(),
        ))
    elif status != suffix:
        findings.append(_finding(
            "TZ_STATUS_CONFLICT", "APS-TZ-STATUS-AUTHORITY-001",
            "Header status is canonical and must match the filename suffix.",
            header_status=status, filename_status=suffix, path=path.as_posix(),
        ))
    if status == "BLOCKED" and not header.get("Blocked-by"):
        findings.append(_finding(
            "TZ_BLOCK_REASON_MISSING", "APS-TZ-STATUS-AUTHORITY-001",
            "BLOCKED requires Blocked-by.", path=path.as_posix(),
        ))
    if status == "CONFLICT" and not header.get("Conflicts-with"):
        findings.append(_finding(
            "TZ_CONFLICT_REFERENCE_MISSING", "APS-TZ-STATUS-AUTHORITY-001",
            "CONFLICT requires Conflicts-with.", path=path.as_posix(),
        ))
    if status == "DONE" and re.search(r"(?:кроме|основн(?:ой|ая)\s+контур|poc|частич)", text, re.I):
        findings.append(_finding(
            "TZ_CONDITIONAL_DONE_FORBIDDEN", "APS-TZ-STATUS-AUTHORITY-001",
            "Conditional DONE wording is forbidden.", path=path.as_posix(),
        ))
    if not findings:
        findings.append(_finding("TZ_STATUS_AUTHORITY_VALID", "APS-TZ-STATUS-AUTHORITY-001", "Status authority is consistent.", severity="INFO"))
    return findings


def _resolve_evidence(root: Path, evidence: Evidence) -> tuple[bool, str, str | None]:
    # RUNTIME разрешается так же, как REPORT: машина проверяет существование
    # записи исполнения, соответствие содержимого контракту — ревью человеком.
    # До v2.9.157 этот вид отвергался безусловно, хотя два документа ядра
    # объявляли его допустимым: код расходился с текстом (находка 30-05).
    raw = evidence.ref.strip()
    if "::" in raw:
        raw_path, node = raw.split("::", 1)
    else:
        raw_path, node = raw, None
    line_match = LINE_SUFFIX_RE.match(raw_path)
    max_line: int | None = None
    if line_match:
        raw_path = line_match.group("path")
        max_line = max(int(value) for value in re.split(r"[-,]", line_match.group("lines")))
    safe = _relative_safe_path(raw_path)
    if safe is None:
        return False, "Evidence path is absolute, empty, or contains traversal.", None
    target = root / safe
    if not target.is_file():
        return False, "Evidence file does not exist.", safe
    text = target.read_text(encoding="utf-8", errors="replace")
    if max_line is not None and max_line > text.count("\n") + 1:
        return False, "Evidence line range does not exist.", safe
    if node:
        symbol = node.split("[")[0].split("::")[-1]
        if not re.search(rf"^(?:async\s+def|def|class)\s+{re.escape(symbol)}\b", text, re.M):
            return False, "Exact test node is absent from the referenced file.", safe
    return True, "resolved", safe


@enforces_rule("APS-TZ-DONE-EVIDENCE-001")
@emits_diagnostic("APS-TZ-DONE-EVIDENCE-001", "TZ_DONE_EVIDENCE_VALID")
@emits_diagnostic("APS-TZ-DONE-EVIDENCE-001", "TZ_ACCEPTANCE_CHECKLIST_MISSING")
@emits_diagnostic("APS-TZ-DONE-EVIDENCE-001", "TZ_MUST_UNCHECKED")
@emits_diagnostic("APS-TZ-DONE-EVIDENCE-001", "TZ_EVIDENCE_MISSING")
@emits_diagnostic("APS-TZ-DONE-EVIDENCE-001", "TZ_EVIDENCE_UNRESOLVED")
@emits_diagnostic("APS-TZ-DONE-EVIDENCE-001", "TZ_DOC_ONLY_MUST")
def validate_acceptance_evidence(root: Path, path: Path, text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    header = parse_header(text)
    status = header.get("Status", "").upper()
    criteria = parse_criteria(text)
    if not criteria:
        return [_finding(
            "TZ_ACCEPTANCE_CHECKLIST_MISSING", "APS-TZ-DONE-EVIDENCE-001",
            "An active technical specification requires atomic acceptance criteria.", path=path.as_posix(),
        )]
    for index, criterion in enumerate(criteria, 1):
        if status == "DONE" and criterion.priority == "must" and not criterion.checked:
            findings.append(_finding(
                "TZ_MUST_UNCHECKED", "APS-TZ-DONE-EVIDENCE-001",
                "DONE cannot contain an unchecked must criterion.", path=path.as_posix(), criterion=index,
            ))
        if criterion.checked and not criterion.evidence:
            findings.append(_finding(
                "TZ_EVIDENCE_MISSING", "APS-TZ-DONE-EVIDENCE-001",
                "A checked criterion requires typed evidence.", path=path.as_posix(), criterion=index,
            ))
            continue
        if status == "DONE" and criterion.priority == "must" and criterion.checked:
            if not any(e.kind in STRONG_EVIDENCE | MEDIUM_EVIDENCE for e in criterion.evidence):
                findings.append(_finding(
                    "TZ_DOC_ONLY_MUST", "APS-TZ-DONE-EVIDENCE-001",
                    "DOC/GIT-only evidence cannot close a must criterion.", path=path.as_posix(), criterion=index,
                ))
        for evidence in criterion.evidence:
            ok, note, _ = _resolve_evidence(root, evidence)
            if not ok:
                findings.append(_finding(
                    "TZ_EVIDENCE_UNRESOLVED", "APS-TZ-DONE-EVIDENCE-001",
                    "Evidence reference cannot be resolved.", path=path.as_posix(), criterion=index,
                    evidence_kind=evidence.kind, evidence_ref=evidence.ref, detail=note,
                ))
    if not findings:
        findings.append(_finding("TZ_DONE_EVIDENCE_VALID", "APS-TZ-DONE-EVIDENCE-001", "Acceptance evidence is valid.", severity="INFO"))
    return findings


def _verified_parts(value: str) -> tuple[str, str, str, str] | None:
    parts = [part.strip() for part in value.split("/")]
    if len(parts) < 3 or not all(parts[:3]):
        return None
    return parts[0], parts[1], parts[2], "/".join(parts[3:]).strip()


@enforces_rule("APS-TZ-DONE-INDEPENDENCE-001")
@emits_diagnostic("APS-TZ-DONE-INDEPENDENCE-001", "TZ_DONE_INDEPENDENTLY_VERIFIED")
@emits_diagnostic("APS-TZ-DONE-INDEPENDENCE-001", "TZ_VERIFICATION_MISSING")
@emits_diagnostic("APS-TZ-DONE-INDEPENDENCE-001", "TZ_DONE_SELF_VERIFIED")
@emits_diagnostic("APS-TZ-DONE-INDEPENDENCE-001", "TZ_VERIFIED_COMMIT_INVALID")
@emits_diagnostic("APS-TZ-DONE-INDEPENDENCE-001", "TZ_EVIDENCE_STALE")
def validate_independence(root: Path, path: Path, text: str) -> list[RuleFinding]:
    findings: list[RuleFinding] = []
    header = parse_header(text)
    status = header.get("Status", "").upper()
    if status not in {"DONE", "REVIEW"}:
        return [_finding("TZ_DONE_INDEPENDENTLY_VERIFIED", "APS-TZ-DONE-INDEPENDENCE-001", "Verification is not required for this status.", severity="INFO")]
    parsed = _verified_parts(header.get("Verified", ""))
    if parsed is None:
        return [_finding(
            "TZ_VERIFICATION_MISSING", "APS-TZ-DONE-INDEPENDENCE-001",
            "REVIEW and DONE require date/verifier/commit in Verified.", path=path.as_posix(),
        )]
    _, verifier, commit, _ = parsed
    owner = header.get("Owner", "").strip().casefold()
    verifier_folded = verifier.casefold()
    trusted_ci = verifier_folded in {"ci", "trusted ci", "release ci", "github actions", "gitlab ci"}
    if owner and owner == verifier_folded and not trusted_ci:
        findings.append(_finding(
            "TZ_DONE_SELF_VERIFIED", "APS-TZ-DONE-INDEPENDENCE-001",
            "The implementer/owner cannot independently verify their own DONE claim.", path=path.as_posix(), owner=owner,
        ))
    # Репозиторий ищется от каталога проекта вверх, а не требуется буквально
    # в его корне: проект может быть вложенным (пример внутри пакета,
    # подкаталог монорепозитория). Если репозитория нет вовсе или коммит в нём
    # не резолвится, git вернёт ненулевой код и находка останется та же.
    if _git(root, "cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        findings.append(_finding(
            "TZ_VERIFIED_COMMIT_INVALID", "APS-TZ-DONE-INDEPENDENCE-001",
            "Verified commit must resolve in the audited repository.", path=path.as_posix(), commit=commit,
        ))
        return findings
    for criterion in parse_criteria(text):
        for evidence in criterion.evidence:
            ok, _, safe = _resolve_evidence(root, evidence)
            if not ok or safe is None:
                continue
            node = evidence.ref.split("::", 1)[1] if "::" in evidence.ref else None
            changed_node = _evidence_changed(root, commit, safe, node)
            if changed_node:
                findings.append(_finding(
                    "TZ_EVIDENCE_STALE", "APS-TZ-DONE-INDEPENDENCE-001",
                    "Evidence changed after the Verified commit; DONE must degrade to REVIEW.",
                    path=path.as_posix(), evidence_path=safe, verified_commit=commit,
                    granularity="node" if node else "file",
                ))
            elif changed_node is None:
                findings.append(_finding(
                    "TZ_VERIFIED_COMMIT_INVALID", "APS-TZ-DONE-INDEPENDENCE-001",
                    "Git could not compare evidence freshness.", path=path.as_posix(), commit=commit, evidence_path=safe,
                ))
    if not findings:
        findings.append(_finding("TZ_DONE_INDEPENDENTLY_VERIFIED", "APS-TZ-DONE-INDEPENDENCE-001", "DONE/REVIEW verification is independent and current.", severity="INFO"))
    return findings


def _node_source(text: str, symbol: str) -> str | None:
    """Исходник именованного узла: `def`, `async def` или `class`.

    Возвращает `None`, если файл не разбирается или узла в нём нет — тогда
    вызывающий обязан вернуться к сравнению файла целиком, а не считать
    доказательство свежим.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) \
                and node.name == symbol:
            return ast.dump(node, include_attributes=False)
    return None


@enforces_rule("APS-TZ-EVIDENCE-GRANULARITY-001")
@emits_diagnostic("APS-TZ-EVIDENCE-GRANULARITY-001", "TZ_EVIDENCE_NODE_UNCHANGED")
def _evidence_changed(root: Path, commit: str, safe: str, node: str | None) -> bool | None:
    """Изменилось ли доказательство между `commit` и `HEAD`.

    Если доказательство называет точный узел (`file::node`), сравнивается
    **узел**, а не файл: добавление соседнего теста отметку `Verified` не
    трогает, правка самого узла — трогает.

    До v2.9.159 сравнивался файл целиком. Направление отказа было безопасным,
    но правило срабатывало на изменениях, не касающихся ТЗ, и приучало
    переставлять отметку механически — `Verified` терял смысл ровно там, где
    должен работать.

    `None` означает «сравнить не удалось»: вызывающий сообщает об этом
    отдельным диагностическим кодом, а не считает доказательство свежим.
    """
    changed = _git(root, "diff", "--quiet", f"{commit}..HEAD", "--", safe)
    if changed.returncode not in {0, 1}:
        return None
    if changed.returncode == 0:
        return False
    if not node:
        return True
    symbol = node.split("[")[0].split("::")[-1]
    old = _git(root, "show", f"{commit}:{safe}")
    if old.returncode != 0:
        return True
    current = (root / safe)
    if not current.is_file():
        return True
    old_node = _node_source(old.stdout, symbol)
    new_node = _node_source(current.read_text(encoding="utf-8", errors="replace"), symbol)
    if old_node is None or new_node is None:
        return True
    return old_node != new_node


def _prompt_ids(root: Path) -> set[str]:
    path = root / "prompts/registry.json"
    if not path.is_file():
        return set()
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    return {
        str(item.get("prompt_id") or item.get("id"))
        for item in data.get("prompts", []) if isinstance(item, dict)
    }


@enforces_rule("APS-TZ-AUDIT-SEQUENCE-001")
@emits_diagnostic("APS-TZ-AUDIT-SEQUENCE-001", "TZ_AUDIT_SEQUENCE_VALID")
@emits_diagnostic("APS-TZ-AUDIT-SEQUENCE-001", "TZ_AUDIT_SEQUENCE_INVALID")
@emits_diagnostic("APS-TZ-AUDIT-SEQUENCE-001", "TZ_AUDIT_MUTATION_MODE")
@emits_diagnostic("APS-TZ-AUDIT-SEQUENCE-001", "TZ_AUDIT_PROMPT_MISSING")
def validate_audit_sequence(root: Path, relative: str = "reference/audit_sequence.json") -> list[RuleFinding]:
    path = root / relative
    if not path.is_file():
        return [_finding("TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001", "Audit sequence registry is missing.", path=relative)]
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        return [_finding("TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001", "Audit sequence registry is not valid JSON.", detail=str(exc))]
    stages = data.get("stages")
    if not isinstance(stages, list) or not stages:
        return [_finding("TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001", "stages must be a non-empty list.")]
    findings: list[RuleFinding] = []
    by_id: dict[str, dict[str, Any]] = {}
    for item in stages:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] in by_id:
            findings.append(_finding("TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001", "Stage IDs must be unique strings."))
            continue
        by_id[item["id"]] = item
    expected = {"00", "10", "20", "25", "30", "40", "90"}
    if set(by_id) != expected:
        findings.append(_finding(
            "TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001",
            "Audit sequence must contain the canonical stage set.", expected=sorted(expected), actual=sorted(by_id),
        ))
    prompt_ids = _prompt_ids(root)
    for stage_id, item in by_id.items():
        mode = item.get("mode")
        if stage_id != "90" and mode != "READ_ONLY":
            findings.append(_finding(
                "TZ_AUDIT_MUTATION_MODE", "APS-TZ-AUDIT-SEQUENCE-001",
                "Audit stages must be READ_ONLY.", stage_id=stage_id, mode=mode,
            ))
        dependencies = item.get("depends_on")
        if not isinstance(dependencies, list) or any(dep not in by_id for dep in dependencies):
            findings.append(_finding(
                "TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001",
                "Every dependency must reference a known stage.", stage_id=stage_id, depends_on=dependencies,
            ))
        for prompt_id in [item.get("prompt_id"), *(item.get("extension_prompt_ids") or [])]:
            if prompt_id is not None and prompt_id not in prompt_ids:
                findings.append(_finding(
                    "TZ_AUDIT_PROMPT_MISSING", "APS-TZ-AUDIT-SEQUENCE-001",
                    "Audit stage references an unknown prompt ID.", stage_id=stage_id, prompt_id=prompt_id,
                ))
    required_edges = {"10": {"00"}, "20": {"10"}, "25": {"10"}, "30": {"00", "10", "20", "25"}, "40": {"00"}, "90": {"30", "40"}}
    for stage_id, required in required_edges.items():
        actual = set(by_id.get(stage_id, {}).get("depends_on") or [])
        if not required.issubset(actual):
            findings.append(_finding(
                "TZ_AUDIT_SEQUENCE_INVALID", "APS-TZ-AUDIT-SEQUENCE-001",
                "Mandatory audit dependency is missing.", stage_id=stage_id, required=sorted(required), actual=sorted(actual),
            ))
    if data.get("audit_mutation_forbidden") is not True:
        findings.append(_finding("TZ_AUDIT_MUTATION_MODE", "APS-TZ-AUDIT-SEQUENCE-001", "audit_mutation_forbidden must be true."))
    if not findings:
        findings.append(_finding("TZ_AUDIT_SEQUENCE_VALID", "APS-TZ-AUDIT-SEQUENCE-001", "Audit sequence and prompt bindings are valid.", severity="INFO"))
    return findings


@enforces_rule("APS-TZ-LAYOUT-001")
@enforces_rule("APS-TZ-STATUS-AUTHORITY-001")
@enforces_rule("APS-TZ-DONE-EVIDENCE-001")
@enforces_rule("APS-TZ-DONE-INDEPENDENCE-001")
@enforces_rule("APS-TZ-AUDIT-SEQUENCE-001")
@enforces_rule("APS-TZ-SECURITY-PROFILE-001")
@emits_diagnostic("APS-TZ-SECURITY-PROFILE-001", "AUDIT_STAGE_PROFILE_VALID")
@emits_diagnostic("APS-TZ-SECURITY-PROFILE-001", "AUDIT_STAGE_PROFILE_UNDECLARED")
@emits_diagnostic("APS-TZ-SECURITY-PROFILE-001", "AUDIT_STAGE_PROFILE_CONFLICT")
@emits_diagnostic("APS-TZ-SECURITY-PROFILE-001", "AUDIT_STAGE_PROFILE_ABSENT")
def validate_security_stage_profile(root: Path, relative: str = "reference/audit_sequence.json") -> list[RuleFinding]:
    """Стадия, отданная внешнему профилю, обязана объявить контракт.

    До v2.9.157 стадия `40` несла `prompt_id: null` и флаг
    `external_profile_required: true`, который нигде не описан и ничем не
    проверялся. Стадия была обязательной зависимостью `90`, но объявить её
    исполненной было нечем — полный вердикт готовности оставался недостижим
    для любого проекта (находка 40-03).

    Ошибкой считается несвязный контракт — это дефект самого стандарта.

    Отсутствие профиля у проекта не является ни ошибкой, ни предупреждением:
    для большинства проектов это законное и постоянное состояние — внешнего
    аудита безопасности у них просто нет. Сообщать о нём как о нарушении
    значит либо давать вечный шум, либо толкать к тому, чтобы объявить
    несуществующий профиль. Факт записывается уровнем `INFO`, остаётся
    машинно-читаемым и учитывается тем, кто считает вердикт стадии `90`.

    Первая редакция этого правила ставила здесь `WARNING` — и сломала
    собственный релизный гейт стандарта, который запускает проверку с
    `--warnings-as-errors`. Обойти можно было только объявив профиль, которого
    нет; это и показало, что уровень выбран неверно.
    """
    path = root / relative
    if not path.is_file():
        return [_finding("AUDIT_STAGE_PROFILE_VALID", "APS-TZ-SECURITY-PROFILE-001",
                         "No audit sequence registry to inspect.", severity="INFO")]
    try:
        stages = json.loads(path.read_text(encoding="utf-8-sig")).get("stages") or []
    except (OSError, json.JSONDecodeError):
        return [_finding("AUDIT_STAGE_PROFILE_UNDECLARED", "APS-TZ-SECURITY-PROFILE-001",
                         "Audit sequence registry is unreadable.", path=relative)]
    findings: list[RuleFinding] = []
    for stage in stages:
        if not isinstance(stage, dict) or not stage.get("external_profile_required"):
            continue
        stage_id = str(stage.get("id"))
        if stage.get("prompt_id") is not None:
            findings.append(_finding(
                "AUDIT_STAGE_PROFILE_CONFLICT", "APS-TZ-SECURITY-PROFILE-001",
                "A stage cannot be both prompt-driven and delegated to an external profile.",
                stage_id=stage_id, prompt_id=stage.get("prompt_id"),
            ))
            continue
        contract = stage.get("external_profile_contract")
        registry_path = contract.get("registry_path") if isinstance(contract, dict) else None
        satisfied_when = contract.get("satisfied_when") if isinstance(contract, dict) else None
        if not isinstance(registry_path, str) or not registry_path or not isinstance(satisfied_when, str) or not satisfied_when:
            findings.append(_finding(
                "AUDIT_STAGE_PROFILE_UNDECLARED", "APS-TZ-SECURITY-PROFILE-001",
                "An externally delegated stage must declare registry_path and satisfied_when.",
                stage_id=stage_id,
            ))
            continue
        safe = _relative_safe_path(registry_path)
        if safe is None:
            findings.append(_finding(
                "AUDIT_STAGE_PROFILE_UNDECLARED", "APS-TZ-SECURITY-PROFILE-001",
                "external_profile_contract.registry_path must be a safe relative path.",
                stage_id=stage_id, registry_path=registry_path,
            ))
        elif not (root / safe).is_file():
            findings.append(_finding(
                "AUDIT_STAGE_PROFILE_ABSENT", "APS-TZ-SECURITY-PROFILE-001",
                "Stage is declared but its external profile is absent; stage 90 verdict stays partial.",
                severity="INFO", stage_id=stage_id, registry_path=registry_path,
            ))
    if not any(item.severity == "ERROR" for item in findings):
        findings.append(_finding("AUDIT_STAGE_PROFILE_VALID", "APS-TZ-SECURITY-PROFILE-001",
                                 "Externally delegated audit stages declare a coherent contract.", severity="INFO"))
    return findings


@enforces_rule("APS-TZ-RUNTIME-EVIDENCE-001")
@emits_diagnostic("APS-TZ-RUNTIME-EVIDENCE-001", "TZ_RUNTIME_EVIDENCE_VALID")
@emits_diagnostic("APS-TZ-RUNTIME-EVIDENCE-001", "TZ_RUNTIME_RECORD_MISSING")
def validate_runtime_evidence(root: Path, path: Path, text: str) -> list[RuleFinding]:
    """Запись исполнения обязана лежать в репозитории и открываться.

    Машинно проверяется только существование файла. Соответствие содержимого
    контракту `APS-TZ-RUNTIME-EVIDENCE-001` остаётся предметом ревью человеком,
    и это ограничение объявляется явно — иначе `RUNTIME` становится лазейкой
    «файл есть, значит закрыто», ровно как предупреждает контракт `REPORT`.
    """
    findings: list[RuleFinding] = []
    for index, criterion in enumerate(parse_criteria(text), 1):
        for evidence in criterion.evidence:
            if evidence.kind != "RUNTIME":
                continue
            safe = _relative_safe_path(evidence.ref.strip().split("::", 1)[0])
            if safe is None or not (root / safe).is_file():
                findings.append(_finding(
                    "TZ_RUNTIME_RECORD_MISSING", "APS-TZ-RUNTIME-EVIDENCE-001",
                    "RUNTIME evidence must point to an execution record committed to the repository.",
                    path=path.as_posix(), criterion=index, evidence_ref=evidence.ref,
                ))
    if not findings:
        findings.append(_finding(
            "TZ_RUNTIME_EVIDENCE_VALID", "APS-TZ-RUNTIME-EVIDENCE-001",
            "RUNTIME evidence resolves to a committed execution record.", severity="INFO",
        ))
    return findings


@enforces_rule("APS-TZ-INDEX-EXEMPTION-001")
@emits_diagnostic("APS-TZ-INDEX-EXEMPTION-001", "TZ_INDEX_EXEMPTED")
@emits_diagnostic("APS-TZ-INDEX-EXEMPTION-001", "TZ_INDEX_CLAIMS_SPEC_STATUS")
def validate_index_exemption(root: Path, docs_root: Path) -> list[RuleFinding]:
    """Индекс каталога исключён — но не может маскировать под собой ТЗ.

    Исключение узкое по построению: освобождается ровно имя `README.md`.
    Если индекс объявляет собственный `ID:` или `Status:`, он перестаёт быть
    навигацией и обязан стать полноценным ТЗ с именем по конвенции.
    """
    findings: list[RuleFinding] = []
    if not docs_root.is_dir():
        return [_finding("TZ_INDEX_EXEMPTED", "APS-TZ-INDEX-EXEMPTION-001",
                         "No specification root to inspect.", severity="INFO")]
    for path in sorted(docs_root.rglob("*.md")):
        if not _is_directory_index(path):
            continue
        header = parse_header(path.read_text(encoding="utf-8", errors="replace"))
        if header.get("ID") or header.get("Status"):
            findings.append(_finding(
                "TZ_INDEX_CLAIMS_SPEC_STATUS", "APS-TZ-INDEX-EXEMPTION-001",
                "A directory index must not declare specification ID or Status.",
                path=path.relative_to(root).as_posix(),
            ))
    if not findings:
        findings.append(_finding("TZ_INDEX_EXEMPTED", "APS-TZ-INDEX-EXEMPTION-001",
                                 "Directory index is exempt and claims no specification status.", severity="INFO"))
    return findings


def run_all_checks(root: Path, docs_relative: str = "docs/ТЗ") -> list[RuleFinding]:
    findings = validate_layout(root, docs_relative)
    docs_root = root / docs_relative
    findings.extend(validate_index_exemption(root, docs_root))
    for path in _active_spec_paths(root, docs_root):
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(root)
        findings.extend(validate_status_authority(relative, text))
        findings.extend(validate_acceptance_evidence(root, relative, text))
        findings.extend(validate_runtime_evidence(root, relative, text))
        findings.extend(validate_independence(root, relative, text))
    findings.extend(validate_audit_sequence(root))
    findings.extend(validate_security_stage_profile(root))
    return findings


def _print_findings(findings: Iterable[RuleFinding]) -> None:
    for finding in findings:
        print("APS_TZ_DIAGNOSTIC:" + json.dumps(finding.as_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate technical-specification lifecycle and audit ordering.")
    parser.add_argument("--root", default=".")
    parser.add_argument("--docs-root", default="docs/ТЗ")
    parser.add_argument("--check-audit-sequence-only", action="store_true")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    findings = validate_audit_sequence(root) if args.check_audit_sequence_only else run_all_checks(root, args.docs_root)
    _print_findings(findings)
    return 1 if any(item.severity == "ERROR" for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
