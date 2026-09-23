#!/usr/bin/env python3
# ======================================================================
# dead_code_types.py — версия 1.0
# Общие типы системного анализа мёртвого кода и достижимости.
# ======================================================================
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


def stable_finding_id(prefix: str, *parts: object) -> str:
    """Идентификатор находки из её содержания, а не из порядка обхода.

    Порядковый номер делает два отчёта одного проекта несравнимыми: добавили
    файл — сдвинулись все последующие номера, и вопрос «что появилось с
    прошлого прогона» перестаёт иметь ответ. Отпечаток от того, что находку
    определяет, переживает и перестановку файлов, и правку соседей.
    """
    payload = "\x1f".join("" if part is None else str(part) for part in parts)
    return f"{prefix}-{hashlib.sha256(payload.encode('utf-8')).hexdigest()[:12]}"


@dataclass(frozen=True)
class SymbolId:
    path: str
    qualname: str

    @property
    def key(self) -> str:
        return f"{self.path}:{self.qualname}"


@dataclass
class SymbolRecord:
    symbol_id: SymbolId
    kind: str
    line: int
    private: bool
    references: set[str] = field(default_factory=set)


@dataclass
class ImportRecord:
    path: str
    line: int
    module: str
    imported_name: str | None
    bound_name: str
    typing_only: bool


@dataclass
class Finding:
    finding_id: str
    rule_id: str
    diagnostic_code: str
    severity: str
    category: str
    confidence: str
    path: str
    line: int
    symbol: str
    symbol_kind: str
    production_reachable: bool
    test_reachable: bool
    entrypoint_paths: list[str]
    evidence: dict[str, Any]
    reason: str
    recommended_action: str
    disposition: str = "OPEN"
    allowlist_id: str | None = None
    # Появилась ли находка вместе с рассматриваемой правкой. Без объявленной
    # базовой ревизии — pre_existing: старый долг не вешается на текущую правку.
    origin: str = "pre_existing"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
