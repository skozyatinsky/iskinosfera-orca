#!/usr/bin/env python3
# ======================================================================
# peer_registry_adapter.py — версия 1.0 (для стандарта v2.9.33)
# Конвертер реестра «парного» стандарта (qai-fabric/RAG) → наш формат.
# Роль: tool. Один файл, без внешних зависимостей.
# ======================================================================
"""Читает docs/registry/ проекта в ПАРНОМ формате (envelope {version, purpose,
entries}) и раскладывает в НАШ формат (см. REGISTRY_CONTRACT). Всегда DRY-RUN:
пишет только в --out и печатает отчёт о потерях. Исходный репозиторий не трогает.

Парный формат (qai-fabric/RAG):
  functions.json      {version, purpose, entries:[{symbol_id,name,kind,qualified_name,
                       file_path,module,owner_module,status,summary}]}
  variables.json      entries:[{var_id,name,kind,file_path,owner_module,status,summary,...}]
  test_coverage.json  entries:[{symbol_id,coverage_status,summary,test_refs:[...]}]

Наш формат (надмножество v2.9.35 — ингест без потерь):
  functions.json      [ {id,symbol,kind,native_kind,path,public,status,summary,
                       qualified_name,module,owner_module} ]  (kind нормализован в 4,
                       гранулярный вид сохраняется в native_kind)
  env_vars.json       [ {variable,required,used_in,description} ]
  config_fields.json  [ {field,source,type,required,description,default,allowed_values} ]
  constants.json      [ {name,kind,path,value,owner_module,summary} ]  (код-константы)
  test_coverage.json  [ {symbol_id,coverage_status,summary,test_refs} ] (без envelope)

Использование:
  python tools/peer_registry_adapter.py --src /path/to/repo --out /tmp/converted
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# наш узкий kind-enum functions.json
# protocol добавлен по уроку пилота qai: plugin_protocol — это class X(Protocol)
_CLASS_MARKERS = ("class", "exception", "dataclass", "enum", "error", "protocol")


def map_kind(k: str) -> str:
    """Богатую парную таксономию (adapter_class, rag_core_function, service_method,
    tool_function, …) сворачиваем в наши четыре значения. Возвращает (наш_kind)."""
    lk = (k or "").lower()
    if "method" in lk:
        return "method"
    if any(m in lk for m in _CLASS_MARKERS):
        return "class"
    if "constant" in lk:
        return "constant"
    return "function"


def map_status(s: str) -> str:
    m = {"active": "ACTIVE", "removed": "REMOVED"}
    return m.get((s or "").lower(), "NEEDS_CONFIRMATION")


def _load_entries(path: Path) -> list:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if isinstance(data, dict):
        return data.get("entries", []) or []
    if isinstance(data, list):
        return data
    return []


def convert_functions(entries: list, loss: list) -> list:
    """Non-lossy (v2.9.35): kind нормализуется в 4 значения, но гранулярный вид и
    описательные поля СОХРАНЯЮТСЯ (native_kind/summary/qualified_name/module/owner_module)."""
    out = []
    for e in entries:
        item = {
            "id": e.get("symbol_id"),
            "symbol": e.get("name"),
            "kind": map_kind(e.get("kind", "")),
            "path": e.get("file_path"),
            "public": True,  # functions.json парного стандарта = публичная поверхность
            "status": map_status(e.get("status", "")),
        }
        # сохраняем сигнал парка (надмножество нашей схемы)
        native = e.get("kind")
        if native and native.lower() not in ("function", "class", "method", "constant"):
            item["native_kind"] = native
        for src, dst in (("summary", "summary"), ("qualified_name", "qualified_name"),
                         ("module", "module"), ("owner_module", "owner_module")):
            if e.get(src):
                item[dst] = e[src]
        out.append(item)
    return out


def convert_variables(entries: list, loss: list) -> tuple[list, list, list]:
    """Разводит variables на env_vars / config_fields / constants (v2.9.35 — код-
    константы больше не теряются, уходят в constants.json)."""
    env_out, cfg_out, const_out = [], [], []
    for e in entries:
        kind = (e.get("kind") or "").lower()
        # их status=active значит «запись актуальна», НЕ «поле обязательно»;
        # честная эвристика обязательности — отсутствие default (урок пилота qai)
        required = e.get("default") is None
        desc = e.get("summary")
        if kind == "env_var":
            item = {"variable": e.get("name"), "required": required}
            if e.get("default") is not None:
                item["default"] = e["default"]
            if e.get("file_path"):
                item["used_in"] = [e["file_path"]]
            if desc:
                item["description"] = desc
            env_out.append(item)
        elif kind in ("config_field", "manifest_field"):
            item = {
                "field": e.get("name"),
                "source": "manifest" if kind == "manifest_field" else "config",
                "type": "string",  # парный формат не несёт тип — синтезируем, проверить вручную
                "required": required,
            }
            if e.get("default") is not None:
                item["default"] = e["default"]
            if e.get("allowed_values"):
                item["allowed_values"] = e["allowed_values"]
            if desc:
                item["description"] = desc
            cfg_out.append(item)
        else:  # *_constant и прочее — код-константы (v2.9.35: свой реестр, не потеря)
            item = {"name": e.get("name"),
                    "kind": (e.get("kind") or "constant").replace("_constant", ""),
                    "path": e.get("file_path") or "UNKNOWN"}
            if e.get("default") is not None:
                item["value"] = e["default"]
            if e.get("owner_module"):
                item["owner_module"] = e["owner_module"]
            if desc:
                item["summary"] = desc
            const_out.append(item)
    if cfg_out:
        loss.append("config_fields: поле 'type' синтезировано как 'string' "
                    "(парный формат не хранит тип) — проверить вручную")
    return env_out, cfg_out, const_out


def convert_coverage(entries: list) -> list:
    # item-схема идентична нашей (перенята в v2.9.28) — только снять envelope
    return entries


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True, help="корень проекта в парном формате")
    ap.add_argument("--out", required=True, help="куда писать наш формат (DRY-RUN, не в src)")
    args = ap.parse_args()
    src = Path(args.src).resolve()
    out = Path(args.out).resolve()
    reg = src / "docs" / "registry"
    if not reg.is_dir():
        print(f"нет {reg}", file=sys.stderr)
        return 2
    out.mkdir(parents=True, exist_ok=True)

    loss: list[str] = []
    funcs = convert_functions(_load_entries(reg / "functions.json"), loss)
    env, cfg, consts = convert_variables(_load_entries(reg / "variables.json"), loss)
    cov = convert_coverage(_load_entries(reg / "test_coverage.json"))

    emitted = {
        "functions.json": funcs,
        "env_vars.json": env,
        "config_fields.json": cfg,
        "constants.json": consts,
        "test_coverage.json": cov,
    }
    for name, payload in emitted.items():
        (out / name).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"DRY-RUN: {src.name} → {out}")
    for name, payload in emitted.items():
        print(f"  {name}: {len(payload)} записей")
    print(f"\nОтчёт о потерях ({len(loss)}):")
    for m in loss:
        print("  ~", m)
    if not loss:
        print("  (без потерь)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
