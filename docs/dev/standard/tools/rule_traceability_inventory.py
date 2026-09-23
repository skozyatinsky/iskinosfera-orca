#!/usr/bin/env python3
# ======================================================================
# rule_traceability_inventory.py — версия 2.0
# Извлечение canonical human rule blocks из Markdown и JSON Schema.
# ======================================================================

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from rule_traceability_types import RuleFinding

DOCUMENT_RE = re.compile(
    r"<!--\s*aps-document\s*\n(?P<body>.*?)\n\s*-->", re.IGNORECASE | re.DOTALL
)
RULE_RE = re.compile(
    r"<!--\s*aps-rule\s*\n(?P<body>.*?)\n\s*-->", re.IGNORECASE | re.DOTALL
)
HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
RULE_ID_RE = re.compile(r"^APS-[A-Z0-9]+(?:-[A-Z0-9]+)+$")
NORMATIVE_RE = re.compile(
    r"\b(?:MUST(?:\s+NOT)?|SHALL(?:\s+NOT)?|REQUIRED|"
    r"обязан(?:а|о|ы)?|должен(?:на|но|ны)?|необходимо|требуется|"
    r"запрещен(?:о|а|ы)?|нельзя|обязательн(?:о|ая|ые|ый)|"
    r"допускается\s+только|не\s+допускается)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class HumanRule:
    rule_id: str
    title: str
    status: str
    semantic_contract_version: int
    path: str
    kind: str
    anchor: str | None
    json_pointer: str | None
    text: str
    digest: str
    line: int | None

    def source_key(self) -> tuple[str, str, str]:
        return (self.kind, self.path, self.anchor or self.json_pointer or "")


# ======================================================================
# 1. НОРМАЛИЗАЦИЯ И СЛУЖЕБНЫЙ ПАРСИНГ
# ======================================================================

def normalize_rule_text(text: str) -> str:
    """Нормализует смысловой текст, игнорируя Markdown-форматирование/пробелы."""
    text = unicodedata.normalize("NFKC", text)
    text = re.sub(r"<!--.*?-->", " ", text, flags=re.DOTALL)
    text = re.sub(r"^```.*?$|^~~~.*?$", " ", text, flags=re.MULTILINE)
    text = re.sub(r"^#{1,6}\s+", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*(?:[-*+] |\d+[.)]\s+)", "", text, flags=re.MULTILINE)
    text = re.sub(r"[`*_~]+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def rule_text_sha256(text: str) -> str:
    return hashlib.sha256(normalize_rule_text(text).encode("utf-8")).hexdigest()


def slugify_heading(value: str) -> str:
    value = re.sub(r"<[^>]+>", "", value)
    value = value.strip().lower().replace("ё", "е")
    value = re.sub(r"[^a-z0-9а-я]+", "-", value, flags=re.IGNORECASE)
    return value.strip("-") or "rule"


def _parse_scalar_block(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        result[key.strip()] = value.strip().strip('"\'')
    return result


def _line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _code_fence_lines(lines: list[str]) -> set[int]:
    fenced: set[int] = set()
    open_token: str | None = None
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        token = "```" if stripped.startswith("```") else ("~~~" if stripped.startswith("~~~") else None)
        if token:
            fenced.add(index)
            if open_token is None:
                open_token = token
            elif open_token == token:
                open_token = None
            continue
        if open_token is not None:
            fenced.add(index)
    return fenced


# ======================================================================
# 2. MARKDOWN INVENTORY
# Rule block начинается у heading и действует до heading того же/старшего уровня.
# ======================================================================

def _document_contract(text: str, rel: str) -> tuple[str | None, list[RuleFinding]]:
    findings: list[RuleFinding] = []
    match = DOCUMENT_RE.search(text)
    if not match:
        return None, [RuleFinding(
            "HUMAN_DOCUMENT_TYPE_MISSING",
            "APS-RULE-ID-001",
            f"Missing aps-document metadata in {rel}",
            evidence={"path": rel, "detail": rel},
        )]
    doc_type = _parse_scalar_block(match.group("body")).get("type")
    if doc_type not in {"normative", "non_normative", "mixed"}:
        findings.append(RuleFinding(
            "HUMAN_DOCUMENT_TYPE_INVALID",
            "APS-RULE-ID-001",
            f"Invalid aps-document type in {rel}",
            evidence={"path": rel, "detail": doc_type or "missing"},
        ))
    return doc_type, findings


def _markdown_headings(lines: list[str]) -> list[tuple[int, int, str]]:
    result: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        match = HEADING_RE.match(line)
        if match:
            result.append((index, len(match.group(1)), match.group(2).strip()))
    return result


def _parse_rule_marker(
    marker: re.Match[str],
    *,
    rel: str,
    text: str,
    lines: list[str],
    headings: list[tuple[int, int, str]],
) -> tuple[HumanRule | None, list[RuleFinding], tuple[int, int] | None]:
    findings: list[RuleFinding] = []
    meta = _parse_scalar_block(marker.group("body"))
    rule_id = meta.get("id", "")
    status = meta.get("status", "")
    version_raw = meta.get("semantic_contract_version", "")
    marker_line = _line_number(text, marker.start()) - 1
    candidates = [item for item in headings if item[0] < marker_line]
    if not candidates:
        findings.append(RuleFinding(
            "HUMAN_RULE_HEADING_MISSING",
            rule_id or "APS-RULE-ID-001",
            f"aps-rule marker has no preceding heading in {rel}",
            evidence={"path": rel, "line": marker_line + 1, "detail": rel},
        ))
        return None, findings, None

    heading_line, heading_level, title = candidates[-1]
    if any(heading_line < other[0] < marker_line for other in headings):
        findings.append(RuleFinding(
            "HUMAN_RULE_MARKER_NOT_ADJACENT",
            rule_id or "APS-RULE-ID-001",
            f"aps-rule marker is not attached to the nearest heading in {rel}",
            evidence={"path": rel, "line": marker_line + 1, "detail": title},
        ))
        return None, findings, None

    end_line = next(
        (line for line, level, _ in headings if line > heading_line and level <= heading_level),
        len(lines),
    )
    body_start = marker_line + marker.group(0).count("\n") + 1
    body_text = "\n".join(lines[body_start:end_line]).strip()
    span = (heading_line, end_line)
    if not rule_id:
        findings.append(RuleFinding(
            "HUMAN_RULE_ID_MISSING",
            "APS-RULE-ID-001",
            f"Rule block without ID in {rel}",
            evidence={"path": rel, "line": marker_line + 1, "detail": title},
        ))
        return None, findings, span
    if not RULE_ID_RE.fullmatch(rule_id):
        findings.append(RuleFinding(
            "RULE_ID_FORMAT_INVALID",
            rule_id,
            f"Invalid rule ID format in {rel}",
            evidence={"path": rel, "line": marker_line + 1, "detail": rule_id},
        ))
    try:
        semantic_version = int(version_raw)
    except ValueError:
        semantic_version = 0
        findings.append(RuleFinding(
            "RULE_SEMANTIC_VERSION_INVALID",
            rule_id,
            f"Invalid semantic_contract_version in {rel}",
            evidence={"path": rel, "line": marker_line + 1, "detail": version_raw or "missing"},
        ))
    rule = HumanRule(
        rule_id=rule_id,
        title=re.sub(r"^APS-[A-Z0-9-]+\s*[—-]\s*", "", title).strip(),
        status=status,
        semantic_contract_version=semantic_version,
        path=rel,
        kind="markdown",
        anchor=slugify_heading(title),
        json_pointer=None,
        text=body_text,
        digest=rule_text_sha256(body_text),
        line=heading_line + 1,
    )
    return rule, findings, span


# Пункт чек-листа приёмки ТЗ обязан нести маркер приоритета `(must)` по
# APS-TZ-DONE-EVIDENCE-001. Это проектное требование к продукту, а не
# нормативное утверждение стандарта, поэтому из проверки оно исключается —
# иначе два правила пакета противоречат друг другу и корректно оформленное ТЗ
# невозможно положить в репозиторий.
ACCEPTANCE_ITEM_RE = re.compile(r"^\s*-\s*\[[ xX]\]\s*\((?:must|should|may)\)\s")


def _uncovered_normative_lines(lines: list[str], spans: list[tuple[int, int]]) -> list[int]:
    fenced = _code_fence_lines(lines)
    uncovered: list[int] = []
    for index, line in enumerate(lines):
        if index in fenced or line.lstrip().startswith(">") or not NORMATIVE_RE.search(line):
            continue
        if ACCEPTANCE_ITEM_RE.match(line):
            continue
        if any(start <= index < end for start, end in spans):
            continue
        if "aps-rule" not in line and "aps-document" not in line:
            uncovered.append(index + 1)
    return uncovered


def parse_markdown_rules(path: Path, root: Path) -> tuple[list[HumanRule], list[RuleFinding], str | None]:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8", errors="strict")
    lines = text.splitlines()
    doc_type, findings = _document_contract(text, rel)
    headings = _markdown_headings(lines)
    rules: list[HumanRule] = []
    spans: list[tuple[int, int]] = []
    for marker in RULE_RE.finditer(text):
        rule, local, span = _parse_rule_marker(
            marker, rel=rel, text=text, lines=lines, headings=headings,
        )
        findings.extend(local)
        if span is not None:
            spans.append(span)
        if rule is not None:
            rules.append(rule)

    uncovered = _uncovered_normative_lines(lines, spans)
    if uncovered:
        findings.extend([
            RuleFinding(
                "HUMAN_RULE_ID_MISSING",
                "APS-RULE-ID-001",
                f"Normative statement outside aps-rule block in {rel}",
                evidence={"path": rel, "line": uncovered[0], "detail": f"{rel}:{uncovered[0]}"},
            ),
            RuleFinding(
                "UNMARKED_NORMATIVE_STATEMENT",
                "APS-RULE-ID-001",
                f"Unmarked normative statement in {rel}",
                evidence={"path": rel, "lines": uncovered, "detail": f"{rel}:{uncovered[0]}"},
            ),
        ])
    if doc_type == "non_normative" and (rules or uncovered):
        findings.append(RuleFinding(
            "NON_NORMATIVE_DOCUMENT_CONTAINS_RULE",
            rules[0].rule_id if rules else "APS-RULE-ID-001",
            f"non_normative document contains normative content: {rel}",
            evidence={"path": rel, "detail": rel},
        ))
    if doc_type in {"normative", "mixed"} and not rules and not uncovered:
        findings.append(RuleFinding(
            "NORMATIVE_DOCUMENT_WITHOUT_RULES",
            "APS-RULE-ID-001",
            f"Document declares {doc_type} but contains no aps-rule blocks: {rel}",
            severity="WARNING",
            evidence={"path": rel, "detail": rel},
        ))
    return rules, findings, doc_type


# ======================================================================
# 3. JSON SCHEMA DESCRIPTION INVENTORY
# x-aps-rule является canonical metadata для нормативного description.
# ======================================================================

def _json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def parse_schema_rules(path: Path, root: Path) -> tuple[list[HumanRule], list[RuleFinding]]:
    rel = path.relative_to(root).as_posix()
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    rules: list[HumanRule] = []
    findings: list[RuleFinding] = []

    def walk(value: Any, pointer: str) -> None:
        if isinstance(value, dict):
            description = value.get("description")
            annotation = value.get("x-aps-rule")
            if isinstance(description, str) and NORMATIVE_RE.search(description):
                if not isinstance(annotation, dict):
                    findings.append(RuleFinding(
                        "SCHEMA_RULE_ID_MISSING",
                        "APS-RULE-ID-001",
                        f"Normative schema description lacks x-aps-rule in {rel}",
                        evidence={"path": rel, "json_pointer": pointer, "detail": f"{rel}:{pointer}"},
                    ))
                else:
                    rule_id = str(annotation.get("id", ""))
                    status = str(annotation.get("status", ""))
                    try:
                        semantic_version = int(annotation.get("semantic_contract_version", 0))
                    except (TypeError, ValueError):
                        semantic_version = 0
                    if not rule_id:
                        findings.append(RuleFinding(
                            "HUMAN_RULE_ID_MISSING",
                            "APS-RULE-ID-001",
                            f"Schema rule annotation lacks ID in {rel}",
                            evidence={"path": rel, "json_pointer": pointer, "detail": f"{rel}:{pointer}"},
                        ))
                    else:
                        rules.append(HumanRule(
                            rule_id=rule_id,
                            title=str(annotation.get("title") or value.get("title") or pointer),
                            status=status,
                            semantic_contract_version=semantic_version,
                            path=rel,
                            kind="schema_description",
                            anchor=None,
                            json_pointer=pointer + "/description",
                            text=description,
                            digest=rule_text_sha256(description),
                            line=None,
                        ))
            for key, child in value.items():
                walk(child, pointer + "/" + _json_pointer_escape(str(key)))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, pointer + f"/{index}")

    walk(data, "")
    return rules, findings


# ======================================================================
# 4. DECLARED ROOTS
# Новые файлы автоматически входят в inventory и не требуют ручной регистрации пути.
# ======================================================================

def iter_declared_files(root: Path, normative_roots: Iterable[dict[str, str]]) -> tuple[list[Path], list[Path]]:
    markdown: set[Path] = set()
    schemas: set[Path] = set()
    for item in normative_roots:
        raw_path = item.get("path", "")
        kind = item.get("kind", "")
        target = (root / raw_path).resolve()
        try:
            target.relative_to(root.resolve())
        except ValueError:
            continue
        if kind == "markdown":
            if target.is_file() and target.suffix.lower() == ".md":
                markdown.add(target)
        elif kind == "markdown_tree" and target.is_dir():
            markdown.update(path for path in target.rglob("*.md") if path.is_file())
        elif kind == "json_schema_tree" and target.is_dir():
            schemas.update(path for path in target.rglob("*.json") if path.is_file())
    return sorted(markdown), sorted(schemas)


def build_inventory(root: Path, normative_roots: Iterable[dict[str, str]]) -> tuple[list[HumanRule], list[RuleFinding], dict[str, Any]]:
    markdown_files, schema_files = iter_declared_files(root, normative_roots)
    all_rules: list[HumanRule] = []
    findings: list[RuleFinding] = []
    document_types: dict[str, str | None] = {}
    for path in markdown_files:
        rules, local, doc_type = parse_markdown_rules(path, root)
        all_rules.extend(rules)
        findings.extend(local)
        document_types[path.relative_to(root).as_posix()] = doc_type
    for path in schema_files:
        rules, local = parse_schema_rules(path, root)
        all_rules.extend(rules)
        findings.extend(local)

    by_id: dict[str, list[HumanRule]] = {}
    for rule in all_rules:
        by_id.setdefault(rule.rule_id, []).append(rule)
    for rule_id, occurrences in by_id.items():
        if len(occurrences) > 1:
            findings.append(RuleFinding(
                "RULE_ID_DUPLICATE_GLOBAL",
                rule_id,
                f"Rule ID has {len(occurrences)} canonical human blocks",
                evidence={
                    "sources": [item.source_key() for item in occurrences],
                    "detail": ",".join(item.path for item in occurrences),
                },
            ))

    summary = {
        "markdown_documents": len(markdown_files),
        "schema_documents": len(schema_files),
        "documents_total": len(markdown_files) + len(schema_files),
        "human_rule_blocks": len(all_rules),
        "document_types": {
            "normative": sum(value == "normative" for value in document_types.values()),
            "mixed": sum(value == "mixed" for value in document_types.values()),
            "non_normative": sum(value == "non_normative" for value in document_types.values()),
            "missing": sum(value is None for value in document_types.values()),
        },
    }
    return sorted(all_rules, key=lambda item: (item.rule_id, item.path)), sorted(set(findings)), summary
