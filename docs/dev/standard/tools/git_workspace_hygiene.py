#!/usr/bin/env python3
# ======================================================================
# git_workspace_hygiene.py — версия 1.0 (для стандарта v2.9.89)
# Runtime-инвентаризация веток/worktree. Роль: tool. READ-ONLY.
# ======================================================================
"""Дополняет статический --check-git-workspace-hygiene (validate_structure.py):
тот проверяет только структуру docs/registry/git_workspace_hygiene.json,
этот инструмент смотрит на реальное состояние репозитория — на какой ветке
сейчас основная папка, какие ветки/worktree есть, что можно было бы убрать.

Только READ-ONLY режимы. Ни один режим не удаляет ветки или worktree —
это намеренное ограничение первой версии слоя (см. GIT_WORKSPACE_HYGIENE_
STANDARD.md §5): риск необратимой операции выше выгоды от автоматизации,
пока нет отдельного подтверждения человека на уровне самого инструмента.

Использование:
  python tools/git_workspace_hygiene.py --check-current-workspace
  python tools/git_workspace_hygiene.py --inventory
  python tools/git_workspace_hygiene.py --cleanup-dry-run
  (опционально --root <path>, по умолчанию текущая директория)
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

_DEFAULT_PROTECTED = {"main", "master", "release"}


def _git(root: Path, args: list[str]) -> tuple[int, str]:
    proc = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True, text=True,
    )
    return proc.returncode, (proc.stdout or proc.stderr).strip()


def _load_policy(root: Path) -> dict:
    """Читает docs/registry/git_workspace_hygiene.json, если есть. Не валится,
    если файла нет или он битый — тогда используются дефолты этого инструмента."""
    path = root / "docs" / "registry" / "git_workspace_hygiene.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}


def _protected_branches(policy: dict) -> set[str]:
    patterns = policy.get("branch_policy", {}).get("protected_branch_patterns")
    if isinstance(patterns, list) and patterns:
        return {p for p in patterns if isinstance(p, str) and "*" not in p} or _DEFAULT_PROTECTED
    return _DEFAULT_PROTECTED


def _primary_branch(policy: dict) -> str:
    branch = policy.get("primary_workspace", {}).get("branch")
    return branch if isinstance(branch, str) and branch else "main"


def cmd_check_current_workspace(root: Path, policy: dict) -> int:
    primary = _primary_branch(policy)
    problems: list[str] = []

    rc, current = _git(root, ["rev-parse", "--abbrev-ref", "HEAD"])
    if rc != 0:
        print(f"не удалось определить текущую ветку: {current}", file=sys.stderr)
        return 2
    detached = current == "HEAD"

    rc, status = _git(root, ["status", "--porcelain"])
    dirty = bool(status.strip())

    print(f"текущая ветка: {'(detached HEAD)' if detached else current}")
    print(f"рабочая копия: {'dirty' if dirty else 'clean'}")

    if detached:
        problems.append("основная папка в detached HEAD — должна быть на "
                         f"'{primary}'")
    elif current != primary:
        problems.append(f"основная папка на ветке '{current}', ожидается '{primary}' — "
                         f"похоже на незавершённую feature-разработку в основной папке")

    # v2.9.90 (P1 внешнего ревью v2.9.89): dirty основная папка раньше не
    # проверялась вообще — allow_dirty_status=false (дефолт) должен ловить это,
    # а не считать dirty main "ОК". Независимо от ветки — dirty сама по себе
    # нарушение "стабильной базы", отдельное от "не на той ветке".
    allow_dirty = bool(policy.get("primary_workspace", {}).get("allow_dirty_status", False))
    if dirty and not allow_dirty:
        problems.append("основная папка dirty — должна оставаться стабильной чистой базой "
                         "(allow_dirty_status=false)")

    if problems:
        print("\nНарушения:")
        for p in problems:
            print(f"  ! {p}")
        print("\nНичего не удаляю и не переключаю автоматически. Безопасное "
              "действие: проверить git status, при готовности — "
              f"git switch {primary} вручную (после коммита/stash текущих изменений).")
        return 1

    print("\nОК: основная папка на защищённой ветке, без нарушений.")
    return 0


def _branch_list(root: Path) -> list[str]:
    rc, out = _git(root, ["branch", "--format=%(refname:short)"])
    if rc != 0 or not out:
        return []
    return [b.strip() for b in out.splitlines() if b.strip()]


def _merged_branches(root: Path, primary: str) -> set[str]:
    rc, out = _git(root, ["branch", "--merged", primary, "--format=%(refname:short)"])
    if rc != 0:
        return set()
    return {b.strip() for b in out.splitlines() if b.strip()}


def _worktree_list(root: Path) -> list[dict]:
    rc, out = _git(root, ["worktree", "list", "--porcelain"])
    if rc != 0 or not out:
        return []
    entries: list[dict] = []
    cur: dict = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        if line.startswith("worktree "):
            if cur:
                entries.append(cur)
            cur = {"path": line[len("worktree "):].strip()}
        elif line.startswith("branch "):
            cur["branch"] = line[len("branch "):].strip().replace("refs/heads/", "")
        elif line == "detached":
            cur["branch"] = "(detached)"
    if cur:
        entries.append(cur)
    return entries


def _worktree_dirty(path: str) -> bool:
    p = Path(path)
    if not p.is_dir():
        return False
    rc, out = _git(p, ["status", "--porcelain"])
    return rc == 0 and bool(out.strip())


def cmd_inventory(root: Path, policy: dict) -> int:
    primary = _primary_branch(policy)
    protected = _protected_branches(policy)
    branches = _branch_list(root)
    merged = _merged_branches(root, primary)
    worktrees = _worktree_list(root)
    worktree_branches = {w.get("branch") for w in worktrees if w.get("branch")}

    print(f"локальные ветки ({len(branches)}):")
    for b in branches:
        flags = []
        if b in protected:
            flags.append("protected")
        if b == primary:
            flags.append("primary")
        if b in merged and b != primary:
            flags.append("merged")
        elif b != primary:
            flags.append("unmerged")
        if b in worktree_branches:
            flags.append("has-worktree")
        print(f"  {b}  [{', '.join(flags) if flags else '-'}]")

    print(f"\nworktree ({len(worktrees)}):")
    for w in worktrees:
        dirty = _worktree_dirty(w["path"])
        branch = w.get("branch", "?")
        state = "dirty" if dirty else "clean"
        merged_flag = "merged" if branch in merged else "unmerged"
        print(f"  {w['path']}  branch={branch}  {state}  {merged_flag}")

    return 0


def cmd_cleanup_dry_run(root: Path, policy: dict) -> int:
    primary = _primary_branch(policy)
    protected = _protected_branches(policy)
    branches = _branch_list(root)
    merged = _merged_branches(root, primary)
    worktrees = _worktree_list(root)
    worktree_branches = {w.get("branch"): w for w in worktrees if w.get("branch")}

    print("DRY-RUN — ничего не удаляется. Отчёт о кандидатах на уборку:\n")

    branch_candidates = [
        b for b in branches
        if b != primary and b not in protected and b in merged and b not in worktree_branches
    ]
    print(f"ветки-кандидаты на удаление (merged, без активного worktree, {len(branch_candidates)}):")
    for b in branch_candidates:
        print(f"  git branch -d {b}   # safe: merged в {primary}, worktree нет")
    if not branch_candidates:
        print("  (нет)")

    print("\nworktree-кандидаты на удаление (clean + merged):")
    wt_count = 0
    for w in worktrees:
        branch = w.get("branch")
        if branch in (None, primary, "(detached)"):
            continue
        if branch not in merged:
            continue
        if _worktree_dirty(w["path"]):
            print(f"  {w['path']}  branch={branch}   # ПРОПУЩЕН: dirty, не трогать без "
                  f"подтверждения человека")
            continue
        print(f"  git worktree remove {w['path']}   # safe: branch={branch} merged, clean")
        wt_count += 1
    if wt_count == 0 and not any(w.get("branch") not in (None, primary, "(detached)")
                                  and w.get("branch") in merged for w in worktrees):
        print("  (нет)")

    unmerged_dirty = [
        w for w in worktrees
        if w.get("branch") not in (None, primary) and w.get("branch") not in merged
    ]
    if unmerged_dirty:
        print("\nunmerged worktree (НЕ кандидаты — unmerged ветка не удаляется автоматически):")
        for w in unmerged_dirty:
            print(f"  {w['path']}  branch={w.get('branch')}")

    # v2.9.90 (P2 внешнего ревью v2.9.89): §2.4 стандарта явно называет stale
    # remote refs частью cleanup — раньше dry-run отчёт их не показывал.
    print("\nstale remote refs (git remote prune origin --dry-run):")
    rc, prune_out = _git(root, ["remote", "prune", "origin", "--dry-run"])
    if rc != 0:
        print(f"  (не удалось получить: {prune_out})")
    elif prune_out.strip():
        for line in prune_out.strip().splitlines():
            print(f"  {line}")
    else:
        print("  (нет)")

    print("\nНапоминание: force-delete/force-remove запрещены без подтверждения "
          "человека (branch_policy.force_delete_requires_human_confirmation, "
          "worktree_policy.force_remove_requires_human_confirmation).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="корень репозитория (по умолчанию '.')")
    ap.add_argument("--check-current-workspace", action="store_true",
                     help="на какой ветке основная папка сейчас, dirty/detached ли она")
    ap.add_argument("--inventory", action="store_true",
                     help="список локальных веток и worktree с merged/dirty статусом")
    ap.add_argument("--cleanup-dry-run", action="store_true",
                     help="кандидаты на безопасную уборку (ничего не удаляет)")
    args = ap.parse_args()

    if not (args.check_current_workspace or args.inventory or args.cleanup_dry_run):
        ap.print_help()
        return 2

    root = Path(args.root).resolve()
    rc, _ = _git(root, ["rev-parse", "--git-dir"])
    if rc != 0:
        print(f"{root} — не git-репозиторий", file=sys.stderr)
        return 2

    policy = _load_policy(root)
    exit_code = 0
    if args.check_current_workspace:
        exit_code = cmd_check_current_workspace(root, policy) or exit_code
    if args.inventory:
        if exit_code == 0:
            print()
        cmd_inventory(root, policy)
    if args.cleanup_dry_run:
        print()
        cmd_cleanup_dry_run(root, policy)
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
