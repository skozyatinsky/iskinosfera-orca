#!/usr/bin/env python3
# ======================================================================
# junit_evidence.py — версия 1.0
# Каноническое объединение и независимый пересчёт JUnit evidence.
# ======================================================================

from __future__ import annotations

import copy
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from rule_traceability_types import emits_diagnostic, enforces_rule


class JUnitEvidenceError(RuntimeError):
    """Structured fail-closed JUnit evidence error."""



@dataclass(frozen=True)
class JUnitAnalysis:
    summary: dict[str, int | float | str]
    node_ids: tuple[str, ...]
    duplicate_node_ids: tuple[str, ...]
    missing_node_id_count: int
    node_outcomes: tuple[tuple[str, str], ...]


def _property(case: ET.Element, name: str) -> str | None:
    properties = case.find("properties")
    if properties is None:
        return None
    for item in properties.findall("property"):
        if item.get("name") == name:
            return item.get("value")
    return None


def _node_id(case: ET.Element) -> str | None:
    return case.get("node_id") or _property(case, "node_id")


OUTCOMES = {"passed", "failed", "error", "skipped", "xfailed", "xpassed"}
ALLOWED_JUNIT_ROOTS = {"testsuite", "testsuites"}

# `aps_outcome` уточняет нативное свидетельство, но НИКОГДА не ослабляет его.
# Ключ — исход, выведенный из нативных элементов; значение — что свойству
# позволено объявить дополнительно. Всё остальное — противоречие: побеждает
# нативный исход, а факт противоречия учитывается и роняет статус в FAIL.
ALLOWED_OUTCOME_REFINEMENTS = {
    "passed": {"passed", "xpassed", "skipped", "xfailed", "failed", "error"},
    "failed": {"failed", "error", "xpassed"},
    "error": {"error", "failed", "xpassed"},
    "skipped": {"skipped", "failed", "error"},
    "xfailed": {"xfailed", "skipped", "failed", "error"},
}


def _native_outcome(case: ET.Element) -> str:
    """Исход по нативным элементам JUnit — единственный источник, которому доверяем."""
    if case.find("failure") is not None:
        return "failed"
    if case.find("error") is not None:
        return "error"
    skipped = case.find("skipped")
    if skipped is not None:
        marker = " ".join(filter(None, [skipped.get("type"), skipped.get("message"), skipped.text])).lower()
        return "xfailed" if "xfail" in marker else "skipped"
    return "passed"


def _outcome(case: ET.Element) -> tuple[str, bool]:
    """Вернуть (исход, признак противоречия).

    Нативные <failure>/<error>/<skipped> имеют безусловный приоритет. Свойство
    `aps_outcome` может лишь уточнить исход в пределах допустимого набора или
    ужесточить его; попытка смягчить (например, объявить passed при
    физически присутствующем <failure>) отбрасывается и помечается.
    """
    native = _native_outcome(case)
    explicit = _property(case, "aps_outcome")
    if explicit not in OUTCOMES:
        return native, False
    if explicit not in ALLOWED_OUTCOME_REFINEMENTS[native]:
        return native, True
    return explicit, False


def testcase_elements(root: ET.Element) -> list[ET.Element]:
    """Собрать testcase, проверив корень и иерархию suite.

    root.iter() обходит дерево независимо от корня, из-за чего произвольный
    документ с вложенным <testcase> принимался за корректный JUnit. Допускаются
    только корни testsuite/testsuites, а каждый testcase обязан лежать
    непосредственно в testsuite.
    """
    if root.tag not in ALLOWED_JUNIT_ROOTS:
        raise JUnitEvidenceError(f"JUNIT_XML_MALFORMED:unexpected_root={root.tag}")
    parents = {child: parent for parent in root.iter() for child in parent}
    cases: list[ET.Element] = []
    for case in root.iter("testcase"):
        parent = parents.get(case)
        if parent is None or parent.tag != "testsuite":
            raise JUnitEvidenceError(
                f"JUNIT_XML_MALFORMED:testcase_outside_testsuite={'' if parent is None else parent.tag}"
            )
        cases.append(case)
    return cases


@enforces_rule("APS-JUNIT-STRUCTURED-ERROR-001")
@emits_diagnostic("APS-JUNIT-STRUCTURED-ERROR-001", "JUNIT_EVIDENCE_VALID")
@emits_diagnostic("APS-JUNIT-STRUCTURED-ERROR-001", "JUNIT_XML_MALFORMED")
@emits_diagnostic("APS-JUNIT-STRUCTURED-ERROR-001", "JUNIT_XML_UNREADABLE")
def parse_junit_bytes(payload: bytes, *, require_node_ids: bool = True) -> JUnitAnalysis:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise JUnitEvidenceError("JUNIT_XML_MALFORMED") from exc
    cases = testcase_elements(root)
    counts = {
        "total": len(cases),
        "completed": len(cases),
        "passed": 0,
        "failed": 0,
        "errors": 0,
        "skipped": 0,
        "xfailed": 0,
        "xpassed": 0,
        "unexpected_skipped": 0,
        "outcome_contradictions": 0,
    }
    node_ids: list[str] = []
    node_outcomes: list[tuple[str, str]] = []
    missing = 0
    for case in cases:
        node_id = _node_id(case)
        if node_id:
            node_ids.append(node_id)
        else:
            missing += 1
        outcome, contradiction = _outcome(case)
        if contradiction:
            counts["outcome_contradictions"] += 1
        if node_id:
            node_outcomes.append((node_id, outcome))
        if outcome == "error":
            counts["errors"] += 1
        else:
            counts[outcome] += 1
        if outcome == "skipped":
            counts["unexpected_skipped"] += 1
    counts["accounted"] = sum(counts[key] for key in ("passed", "failed", "errors", "skipped", "xfailed", "xpassed"))
    duplicates = sorted({node_id for node_id in node_ids if node_ids.count(node_id) > 1})
    counts["status"] = "PASS" if (
        counts["total"] > 0
        and counts["completed"] == counts["total"]
        and counts["accounted"] == counts["total"]
        and counts["failed"] == 0
        and counts["errors"] == 0
        and counts["xpassed"] == 0
        and counts["unexpected_skipped"] == 0
        and counts["outcome_contradictions"] == 0
        and not duplicates
        and (not require_node_ids or missing == 0)
    ) else "FAIL"
    counts["duration_seconds"] = 0.0
    return JUnitAnalysis(
        summary=counts,
        node_ids=tuple(node_ids),
        duplicate_node_ids=tuple(duplicates),
        missing_node_id_count=missing,
        node_outcomes=tuple(node_outcomes),
    )


def parse_junit(path: Path, *, require_node_ids: bool = True) -> JUnitAnalysis:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise JUnitEvidenceError("JUNIT_XML_UNREADABLE") from exc
    return parse_junit_bytes(payload, require_node_ids=require_node_ids)


def node_ids_sha256(node_ids: Iterable[str]) -> str:
    payload = "\n".join(sorted(node_ids)).encode("utf-8") + b"\n"
    return hashlib.sha256(payload).hexdigest()


def clone_testcases(path: Path) -> list[ET.Element]:
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise JUnitEvidenceError("JUNIT_XML_MALFORMED") from exc
    return [copy.deepcopy(case) for case in testcase_elements(root)]


def write_canonical_junit(cases: list[ET.Element], output: Path, *, suite_name: str = "agent_project_standard") -> None:
    analysis_root = ET.Element("testsuites", {"name": suite_name})
    suite = ET.SubElement(analysis_root, "testsuite", {"name": suite_name})
    for case in cases:
        suite.append(case)
    analysis = parse_junit_bytes(ET.tostring(analysis_root, encoding="utf-8", xml_declaration=True))
    summary = analysis.summary
    suite.set("tests", str(summary["total"]))
    suite.set("failures", str(summary["failed"]))
    suite.set("errors", str(summary["errors"]))
    suite.set("skipped", str(int(summary["skipped"]) + int(summary["xfailed"])))
    analysis_root.set("tests", str(summary["total"]))
    analysis_root.set("failures", str(summary["failed"]))
    analysis_root.set("errors", str(summary["errors"]))
    analysis_root.set("skipped", str(int(summary["skipped"]) + int(summary["xfailed"])))
    output.parent.mkdir(parents=True, exist_ok=True)
    ET.ElementTree(analysis_root).write(output, encoding="utf-8", xml_declaration=True)
