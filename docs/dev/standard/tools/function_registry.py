#!/usr/bin/env python3
# ======================================================================
# function_registry.py — версия 1.0
# Discovery and validation entrypoint for user/technical function inventory.
# ======================================================================
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from v128_validation import all_function_findings, load_json  # noqa: E402


def main() -> int:
    p=argparse.ArgumentParser(); p.add_argument("--root",default="."); p.add_argument("--query"); p.add_argument("--validate",action="store_true"); p.add_argument("--base-ref"); p.add_argument("--protected-ref",default="HEAD"); a=p.parse_args(); root=Path(a.root).resolve()
    if a.validate:
        findings=all_function_findings(root,base_ref=a.base_ref,protected_ref=a.protected_ref,public_symbol_coverage=True)
        if findings:
            print("\n".join(findings),file=sys.stderr); return 1
        print("FUNCTION_REGISTRIES_VALID"); return 0
    users,_=load_json(root/"docs/registry/user_functions.json"); technical,_=load_json(root/"docs/registry/functions.json")
    q=(a.query or "").casefold(); result={"query":a.query,"user_functions":[],"technical_functions":[]}
    for key, items in (("user_functions",users or []),("technical_functions",technical or [])):
        for item in items:
            if not isinstance(item,dict): continue
            hay=json.dumps(item,ensure_ascii=False).casefold()
            if not q or q in hay: result[key].append(item)
    result["can_start_new_development"] = not result["user_functions"] and not result["technical_functions"]
    print(json.dumps(result,ensure_ascii=False,indent=2,sort_keys=True)); return 0
if __name__=="__main__": raise SystemExit(main())
