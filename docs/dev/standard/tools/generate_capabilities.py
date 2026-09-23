#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path

def render(root: Path) -> str:
    data=json.loads((root/'reference/standard_capabilities.json').read_text(encoding='utf-8'))
    intro=(root/'reference/CAPABILITIES_INTRO.md').read_text(encoding='utf-8').rstrip()
    appendix=(root/'reference/CAPABILITIES_APPENDIX.md').read_text(encoding='utf-8').lstrip('\n').rstrip()
    lines=[intro,'','| Слой | Что даёт | Флаг валидатора |','|---|---|---|']
    for c in data['capabilities']:
        lines.append(f"| **{c['name']}** | {c['description']} | {c['enforcement']} |")
    if appendix: lines += ['', appendix]
    return '\n'.join(lines).rstrip()+'\n'

def main():
    p=argparse.ArgumentParser(); p.add_argument('--root',default='.'); p.add_argument('--check',action='store_true')
    a=p.parse_args(); root=Path(a.root).resolve(); out=root/'CAPABILITIES.md'; rendered=render(root)
    if a.check:
        if not out.exists() or out.read_text(encoding='utf-8')!=rendered:
            print('CAPABILITIES.md устарел; запусти tools/generate_capabilities.py --root .'); return 1
        return 0
    out.write_text(rendered,encoding='utf-8'); return 0
if __name__=='__main__': raise SystemExit(main())
