#!/usr/bin/env python3
# ======================================================================
# audit_tz_implementation.py — версия 1.0
# Deterministic read-only inventory/traceability baseline for docs/**.
# It never upgrades a requirement to DONE without executable evidence.
# ======================================================================
from __future__ import annotations
import argparse, hashlib, json, re, subprocess, uuid, zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

SKIP={".git",".venv","venv","node_modules","dist","build","coverage","__pycache__",".pytest_cache",".mypy_cache",".ruff_cache"}
REQ=re.compile(r"^(?:\s*[-*+]\s+|\s*\d+[.)]\s+|\s*#{1,6}\s+)?(.{12,})$")
KEYWORDS=("должен","должна","должно","обязан","необходимо","требуется","shall","must","acceptance","критер")

def now(): return datetime.now(timezone.utc).isoformat().replace("+00:00","Z")
def git(root,*args):
    p=subprocess.run(["git",*args],cwd=root,capture_output=True,text=True); return p.stdout.strip() if p.returncode==0 else None

def read_doc(path:Path)->tuple[str,str|None]:
    try:
        if path.suffix.lower() in {".md",".txt",".rst",".yaml",".yml",".json",".toml"}: return path.read_text(encoding="utf-8",errors="ignore"),None
        if path.suffix.lower()==".docx":
            with zipfile.ZipFile(path) as z: xml=z.read("word/document.xml")
            root=ElementTree.fromstring(xml); return "\n".join("".join(node.itertext()) for node in root.iter() if node.tag.endswith("}p")),None
        return "",f"UNSUPPORTED_FORMAT:{path.suffix}"
    except Exception as exc: return "",str(exc)

def classify(path:Path,text:str)->str:
    name=path.name.casefold(); head=text[:3000].casefold(); parent_parts={part.casefold() for part in path.parts}
    if any(k in name for k in ("audit","аудит","report","отчет","отчёт")): return "REPORT"
    if any(k in name for k in ("adr","decision","решение")): return "ADR"
    if any(k in name for k in ("roadmap","plan","план")): return "PLAN"
    if parent_parts & {"тз", "spec", "specs", "requirements"} or any(k in name for k in ("тз","tz_","spec","technical")) or any(k in head for k in ("техническ","requirements","требован")): return "TECHNICAL_SPEC"
    return "REFERENCE"

def code_evidence(root:Path,phrase:str)->list[str]:
    tokens=[t for t in re.findall(r"[a-zA-Zа-яА-ЯёЁ0-9_]{5,}",phrase) if t.casefold() not in {"система","должна","должен","необходимо","требуется"}][:3]
    if not tokens:return []
    evidence=[]
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP or part=="docs" for part in path.relative_to(root).parts):continue
        if path.suffix.lower() not in {".py",".js",".ts",".tsx",".java",".go",".rs",".yml",".yaml",".json",".toml"}:continue
        text=path.read_text(encoding="utf-8",errors="ignore").casefold()
        if sum(token.casefold() in text for token in tokens)>=2:evidence.append(path.relative_to(root).as_posix())
        if len(evidence)>=5:break
    return evidence

def main():
    p=argparse.ArgumentParser();p.add_argument("--root",default=".");p.add_argument("--audit-type",choices=["MANUAL","SCHEDULED"],default="MANUAL");p.add_argument("--output",required=True);p.add_argument("--markdown-output");a=p.parse_args();root=Path(a.root).resolve();docs=root/"docs";documents=[];requirements=[]
    for path in sorted(docs.rglob("*")) if docs.exists() else []:
        if not path.is_file() or any(part in SKIP for part in path.relative_to(root).parts):continue
        text,error=read_doc(path); kind=classify(path,text); rel=path.relative_to(root).as_posix(); digest=hashlib.sha256(path.read_bytes()).hexdigest()
        documents.append({"path":rel,"type":kind,"readable":error is None,"error":error,"sha256":digest,"suggested_name":None})
        if kind!="TECHNICAL_SPEC" or error:continue
        idx=0
        for line_no,line in enumerate(text.splitlines(),1):
            cleaned=line.strip()
            if len(cleaned)>500 or not any(k in cleaned.casefold() for k in KEYWORDS):continue
            m=REQ.match(cleaned)
            if not m:continue
            idx+=1;rid=f"REQ-{re.sub(r'[^A-Z0-9]+','-',path.stem.upper())[:32]}-{idx:03d}";evidence=code_evidence(root,cleaned)
            status="ФОРМАЛЬНО ЗАЯВЛЕНО" if evidence else "НЕ ПРОВЕРЕНО"
            requirements.append({"id":rid,"requirement":cleaned,"source":rel,"line":line_no,"status":status,"evidence":evidence,"acceptance_criterion":"Критерий приёмки в ТЗ отсутствует."})
    counts={};
    for item in requirements:counts[item["status"]]=counts.get(item["status"],0)+1
    completed=counts.get("ВЫПОЛНЕНО",0);strict=round(100*completed/len(requirements),2) if requirements else 0.0
    final="АУДИТ НЕ МОЖЕТ БЫТЬ ЗАВЕРШЁН" if not requirements else ("НЕ ГОТОВ К ПРИЁМКЕ" if completed<len(requirements) else "ГОТОВ К ПРИЁМКЕ")
    report={"schema_version":"1.0.0","audit_id":f"tz-audit-{uuid.uuid4().hex}","audit_type":a.audit_type,"source":{"commit_sha":git(root,"rev-parse","HEAD"),"tree_sha":git(root,"rev-parse","HEAD^{tree}"),"branch":git(root,"branch","--show-current"),"working_tree_clean":not bool(git(root,"status","--porcelain")),"document_inventory_sha256":hashlib.sha256(json.dumps(documents,sort_keys=True).encode()).hexdigest()},"documents":documents,"requirements":requirements,"summary":{"document_count":len(documents),"technical_spec_count":sum(d["type"]=="TECHNICAL_SPEC" for d in documents),"requirement_count":len(requirements),"status_counts":counts,"strict_completion_percent":strict,"generated_at":now()},"status":final}
    out=Path(a.output);out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    if a.markdown_output:
        lines=["# Аудит выполнения технических заданий","",f"Статус: **{final}**",f"Строгий процент: **{strict}%**","","## Документы",""]+[f"- `{d['path']}` — {d['type']}" for d in documents]+["","## Требования",""]+[f"- **{r['id']}** — {r['status']}: {r['requirement']} (`{r['source']}:{r['line']}`)" for r in requirements]
        Path(a.markdown_output).write_text("\n".join(lines)+"\n",encoding="utf-8")
    print(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True));return 0 if final.startswith("ГОТОВ") else 1
if __name__=="__main__":raise SystemExit(main())
