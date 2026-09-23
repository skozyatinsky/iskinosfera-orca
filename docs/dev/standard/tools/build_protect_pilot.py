#!/usr/bin/env python3
# ======================================================================
# build_protect_pilot.py — пилот: Cython vs Nuitka (module-режим)
# Сравнивает защищённую компиляцию одного .py в нативный модуль по осям:
#   build time · размер артефакта · runtime · остаточная читаемость исходника.
# Требует установленных cython и nuitka; C-компилятор в PATH.
# Всегда работает в --workdir (артефакты сборки туда, не в проект).
# ======================================================================
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

# Подопытный модуль: горячий цикл (perf) + строковые константы (обфускация).
PAYLOAD = '''\
SECRET_TABLE = {"alpha_key": 1013, "bravo_key": 2027, "charlie_key": 3041}
LICENSE_SALT = "Zm9vYmFyLXNlY3JldC1zYWx0LT12"


def hot(n):
    s = 0
    for i in range(n):
        s = (s * 1103515245 + 12345) & 0x7FFFFFFF
    return s


def lookup(key):
    return SECRET_TABLE.get(key, -1)
'''

# строки/идентификаторы, наличие которых в бинарнике = утечка исходника
LEAK_MARKERS = ["SECRET_TABLE", "LICENSE_SALT", "alpha_key", "Zm9vYmFy", "lookup"]


def sh(cmd: list[str], cwd: Path) -> tuple[float, bool, str]:
    t0 = time.perf_counter()
    p = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True)
    return time.perf_counter() - t0, p.returncode == 0, (p.stderr or p.stdout)[-400:]


def find_so(d: Path) -> Path | None:
    cands = sorted([*d.glob("*.so"), *d.glob("**/*.so")], key=lambda f: len(str(f)))
    return cands[0] if cands else None


def leak_count(so: Path) -> int:
    """Сколько маркеров исходника видно сырым `strings` (proxy обфускации)."""
    try:
        out = subprocess.run(["strings", str(so)], capture_output=True, text=True).stdout
    except Exception:
        out = so.read_bytes().decode("latin-1", "ignore")
    return sum(1 for m in LEAK_MARKERS if m in out)


def run_perf(so: Path, iters: int) -> float | None:
    """Импортировать собранный модуль в отдельном процессе и замерить hot()."""
    mod = so.name.split(".")[0]
    code = (f"import sys,time; sys.path.insert(0,{str(so.parent)!r}); import {mod} as m;"
            f"t=time.perf_counter();\n"
            f"[m.hot(2_000_000) for _ in range({iters})];"
            f"print(time.perf_counter()-t)")
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    try:
        return float(p.stdout.strip())
    except ValueError:
        sys.stderr.write(f"[perf {mod}] {p.stderr[-300:]}\n")
        return None


def build_cython(work: Path) -> dict:
    d = work / "cython_build"
    d.mkdir(parents=True, exist_ok=True)
    (d / "payload.py").write_text(PAYLOAD)
    bt, ok, err = sh([sys.executable, "-m", "cython", "-3", "--embed=no", "payload.py"], d)
    # cythonize -i компилирует в .so на месте
    bt2, ok2, err2 = sh([sys.executable, "-m", "Cython.Build.Cythonize", "-i", "-3", "payload.py"], d)
    return _measure("Cython", d, bt + bt2, ok2, err2)


def build_nuitka(work: Path) -> dict:
    d = work / "nuitka_build"
    d.mkdir(parents=True, exist_ok=True)
    (d / "payload.py").write_text(PAYLOAD)
    bt, ok, err = sh([sys.executable, "-m", "nuitka", "--module", "payload.py",
                      f"--output-dir={d}", "--remove-output", "--quiet",
                      "--no-progressbar"], d)
    return _measure("Nuitka", d, bt, ok, err)


def _measure(name: str, d: Path, build_s: float, ok: bool, err: str) -> dict:
    so = find_so(d)
    if not ok or so is None:
        return {"tool": name, "ok": False, "err": err}
    return {"tool": name, "ok": True, "build_s": build_s,
            "size_kb": so.stat().st_size / 1024, "leaks": leak_count(so),
            "so": so}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--perf-iters", type=int, default=5)
    args = ap.parse_args()
    work = Path(args.workdir).resolve()
    work.mkdir(parents=True, exist_ok=True)

    results = [build_cython(work), build_nuitka(work)]
    for r in results:
        if r["ok"]:
            r["perf_s"] = run_perf(r["so"], args.perf_iters)

    print(f"\n{'tool':8} {'build,s':>9} {'size,KB':>9} {'perf,s':>9} {'leaks':>6} / {len(LEAK_MARKERS)}")
    print("-" * 52)
    for r in results:
        if not r["ok"]:
            print(f"{r['tool']:8} FAILED: {r['err'][:120]}")
            continue
        perf = f"{r['perf_s']:.3f}" if r.get("perf_s") is not None else "  n/a"
        print(f"{r['tool']:8} {r['build_s']:9.2f} {r['size_kb']:9.1f} {perf:>9} {r['leaks']:6} / {len(LEAK_MARKERS)}")
    print("\nleaks = сколько строк/идентификаторов исходника видно сырым `strings` "
          "(меньше = сильнее защита).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
