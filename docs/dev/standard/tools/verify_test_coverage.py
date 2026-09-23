#!/usr/bin/env python3
# ======================================================================
# verify_test_coverage.py — версия 1.9 (для стандарта v2.9.103)
# Runtime-подтверждение test_coverage.json. Роль: tool.
# ======================================================================
"""Дополняет статический --check-test-coverage (validate_structure.py): тот
проверяет, что путь существует и "похож на тест" (test_*.py/*_test.py под
tests/); этот инструмент реально спрашивает pytest, собирается ли заявленный
узел — доказывает связь "символ -> тест", а не просто "путь на диске есть"
(P1 внешнего ревью v2.9.90, подтверждено репродукцией: test_refs[].path=
README.md проходил статическую проверку молча).

Безопасность test_ref (v2.9.101, P1 внешнего ревью v2.9.100, репродуцировано
для run_user_function_tests.py — тот же класс уязвимости здесь): `path`
обязан оставаться внутри `--root` (запрещены абсолютные пути и `..`-эскейп)
и не должен начинаться с `-` (иначе pytest интерпретирует его как свою
CLI-опцию — например, `--collect-only` даёт ложный успех без выполнения
теста). `--` перед путём в вызове pytest — вторая линия защиты.

Использование:
  python tools/verify_test_coverage.py --root . --collect-only
  python tools/verify_test_coverage.py --root . --run
  python tools/verify_test_coverage.py --root . --collect-only --allow-missing-registry
  python tools/verify_test_coverage.py --root . --run --pytest-timeout-seconds 60

Registry-файл (v2.9.97, P2 внешнего ревью v2.9.96): по умолчанию
`docs/registry/test_coverage.json` ОБЯЗАН существовать, если инструмент
вызван явно — отсутствие файла теперь `exit=2`, не тихое "нечего проверять"
(случайно удалённый реестр неотличим от проекта, который осознанно не
использует этот контракт). Для проектов без контракта — явный
`--allow-missing-registry` возвращает старое поведение (exit=0).

Timeout (v2.9.97, P1 внешнего ревью v2.9.96): каждый вложенный вызов pytest
ограничен `--pytest-timeout-seconds` (по умолчанию 300) — зависший тест не
должен блокировать gate навсегда; таймаут трактуется как FAIL, не как
необработанное исключение. v2.9.98 (P2 внешнего ревью v2.9.97,
репродуцировано): значение обязано быть конечным положительным числом —
`nan`/`inf` роняли необработанный `ValueError`/`OverflowError` внутри
`subprocess`; теперь argparse отклоняет некорректное значение сам
(`exit=2`, без traceback).

Malformed test_refs (v2.9.102, P1 внешнего ревью v2.9.101, репродуцировано):
нераспознанный/опечатанный `kind` (например "pytests" вместо "pytest") или
`path` нестрокового типа при `kind=pytest` раньше молча пропускались —
тот же "нет kind=pytest test_refs — нечего проверять", `exit=0`, что и для
проекта, где pytest test_refs ДЕЙСТВИТЕЛЬНО отсутствуют. Теперь это
явная ошибка конфигурации (`exit=2`), не тихий пропуск. Редакция секретов
(v2.9.102, P2 внешнего ревью v2.9.101): та же правка, что в
run_user_function_tests.py — CLI-флаг вида `--api-key VALUE` и голый
`Bearer VALUE` теперь тоже редактируются.

Коды выхода: 0 — все test_refs подтверждены (либо нечего проверять); 1 —
хотя бы один test_ref не собрался/не прошёл/не уложился в таймаут; 2 —
test_coverage.json битый, не массив, отсутствует без
`--allow-missing-registry`, test_refs содержит нераспознанный/опечатанный
kind или нестроковый path при kind=pytest, ИЛИ `--pytest-timeout-seconds`
не является конечным положительным числом (fail-closed, v2.9.96/97/98/102).

Timeout убивает всё дерево процессов, не только сам pytest (v2.9.99, P1
внешнего ревью v2.9.98, репродуцировано): `subprocess.run(timeout=...)`
останавливал только прямой дочерний процесс — тест, который успел
породить и отсоединить собственный процесс (`start_new_session=True`/
демонизация), продолжал жить после timeout. См. `run_user_function_tests.py`
для той же логики и подробного объяснения.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import signal
import subprocess
import sys
from pathlib import Path


class UnsafeTestRefError(RuntimeError):
    """test_ref небезопасен: выходит за пределы проекта или выглядит как
    pytest-опция, не путь к тесту."""


def _reject_path_escaping_project(root: Path, rel_path: str, what: str) -> None:
    if not rel_path or "\x00" in rel_path:
        raise UnsafeTestRefError(f"{what}: путь пуст или содержит NUL: {rel_path!r}")
    candidate = Path(rel_path.replace("\\", "/"))
    if candidate.is_absolute():
        raise UnsafeTestRefError(f"{what}: абсолютный путь запрещён: {rel_path!r}")
    resolved_root = root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        raise UnsafeTestRefError(
            f"{what}: путь выходит за пределы проекта ({resolved_root}): {rel_path!r}") from None


def _validate_test_ref(root: Path, node: str) -> None:
    if node.startswith("-"):
        raise UnsafeTestRefError(
            f"test_ref {node!r} начинается с '-' — выглядит как pytest-опция, не путь к тесту")
    path_part = node.split("::", 1)[0]
    _reject_path_escaping_project(root, path_part, f"test_ref {node!r}")


def _positive_finite_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"ожидалось число: {value!r}") from exc
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError(
            f"значение должно быть конечным числом больше 0, получено {value!r}")
    return parsed


class RegistryMissingError(RuntimeError):
    """test_coverage.json отсутствует, а --allow-missing-registry не передан."""


class RegistryLoadError(RuntimeError):
    """test_coverage.json битый или не массив — не то же самое, что "файла нет"."""


def _load(path: Path, allow_missing: bool) -> list:
    if not path.exists():
        if allow_missing:
            return []
        raise RegistryMissingError(
            f"{path} отсутствует — если проект осознанно не использует "
            f"TEST_COVERAGE_CONTRACT, передай --allow-missing-registry")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryLoadError(f"битый {path}: {exc}") from exc
    if not isinstance(data, list):
        raise RegistryLoadError(f"{path}: ожидался массив, получено {type(data).__name__}")
    return data


# kind-значения из schemas/test_coverage.schema.json (§test_refs[].kind).
_KNOWN_TEST_REF_KINDS = {"pytest", "cli", "manual", "integration", "e2e"}


class TestCoverageEntryError(RuntimeError):
    """test_refs содержит структурно некорректную или нераспознанную запись.

    P1 внешнего ревью v2.9.101, репродуцировано: ref с нераспознанным/
    опечатанным `kind` (например "pytests" вместо "pytest") или с kind=
    "pytest", но нестроковым `path`, раньше молча пропускался — тот же
    "нет kind=pytest test_refs — нечего проверять", `exit=0`, что и для
    проекта, где pytest test_refs ДЕЙСТВИТЕЛЬНО отсутствуют намеренно.
    Различаем: неизвестный kind — ошибка конфигурации (`exit=2`), не тихий
    пропуск; kind=="pytest" с нестроковым path — тоже ошибка конфигурации."""


def _pytest_refs(data: list) -> list[tuple[str, str]]:
    """[(symbol_id, path_с_node_id)] для всех kind=pytest test_refs."""
    out: list[tuple[str, str]] = []
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            # v2.9.103 (P1 внешнего ревью v2.9.102, репродуцировано): `[42]`
            # (top-level элемент не объект) раньше молча пропускался — реестр
            # из одних "мусорных" записей выглядел как "нет kind=pytest
            # test_refs, нечего проверять", exit=0. Повреждённый элемент — не
            # то же самое, что пустой реестр.
            raise TestCoverageEntryError(
                f"элемент [{i}] должен быть объектом, получено {type(entry).__name__}")
        sid = entry.get("symbol_id", "?")
        for ref in entry.get("test_refs") or []:
            if not isinstance(ref, dict):
                raise TestCoverageEntryError(
                    f"{sid}: test_refs содержит элемент, не являющийся объектом: {ref!r}")
            kind = ref.get("kind")
            if kind not in _KNOWN_TEST_REF_KINDS:
                raise TestCoverageEntryError(
                    f"{sid}: test_refs[].kind={kind!r} не распознан (ожидался один из "
                    f"{sorted(_KNOWN_TEST_REF_KINDS)}) — похоже на опечатку, а не "
                    f"намеренно другой вид проверки")
            if kind != "pytest":
                continue
            path = ref.get("path")
            if not isinstance(path, str):
                raise TestCoverageEntryError(
                    f"{sid}: test_refs[].path должен быть строкой при kind=pytest, "
                    f"получено {path!r}")
            out.append((sid, path))
    return out


def _popen_kwargs() -> dict:
    """Платформенные kwargs для запуска в отдельной группе процессов."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _descendant_pids(root_pid: int) -> list[int]:
    """Снимок PID всех потомков root_pid ПРЯМО СЕЙЧАС, через `ps` — ловит
    процессы, которые сами вызвали свой `start_new_session` (заводят
    отдельную группу, killpg их не достанет). См. подробное объяснение в
    `run_user_function_tests.py`.

    Если `ps` недоступен (v2.9.100, P2 внешнего ревью v2.9.99) — явное
    предупреждение в stderr вместо тихого возврата []."""
    try:
        proc = subprocess.run(["ps", "-e", "-o", "pid=,ppid="], capture_output=True, text=True)
    except FileNotFoundError:
        print("предупреждение: команда 'ps' недоступна — cleanup дерева процессов "
              "при timeout не гарантирован", file=sys.stderr)
        return []
    if proc.returncode != 0:
        print("предупреждение: 'ps' завершился с ошибкой — cleanup дерева процессов "
              "при timeout не гарантирован", file=sys.stderr)
        return []
    children: dict[int, list[int]] = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        try:
            pid, ppid = int(parts[0]), int(parts[1])
        except ValueError:
            continue
        children.setdefault(ppid, []).append(pid)
    result: list[int] = []
    seen = {root_pid}
    frontier = [root_pid]
    while frontier:
        next_frontier = []
        for p in frontier:
            for c in children.get(p, []):
                if c not in seen:
                    seen.add(c)
                    result.append(c)
                    next_frontier.append(c)
        frontier = next_frontier
    return result


def _terminate_process_tree(proc: subprocess.Popen) -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True)
        return
    descendants = _descendant_pids(proc.pid)
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    for pid in descendants:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass


# Тот же класс уязвимости, что в run_user_function_tests.py (см. там
# подробный комментарий): первая версия редакции ловила только первое
# "слово" после разделителя, оставляя сам секрет на виду для многословных
# значений вида "Bearer <token>". Теперь редактируется до конца строки, плюс
# отдельный паттерн для credentials в connection string (user:pass@host).
_SECRET_KEY_LINE_RE = re.compile(
    r'(?im)(\b[A-Za-z0-9_.-]*(?:TOKEN|SECRET|PASSWORD|PASSPHRASE|API[_-]?KEY|'
    r'AUTHORIZATION|COOKIE|PRIVATE[_-]?KEY)[A-Za-z0-9_.-]*\b\s*[\'"]?\s*[:=]\s*[\'"]?)'
    r'(.+?)([\'"]?\s*[,}]?\s*)$'
)
_URL_CREDENTIAL_RE = re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@')
# v2.9.102 (P2 внешнего ревью v2.9.101, репродуцировано): CLI-флаг вида
# `--api-key VALUE` (разделитель — пробел, не `:`/`=`) и голый `Bearer VALUE`
# без предшествующего `Authorization:` уходили в лог нередактированными.
_CLI_FLAG_SECRET_RE = re.compile(
    r'(?im)(--[A-Za-z0-9_-]*(?:token|secret|password|passphrase|api[_-]?key|'
    r'authorization|cookie|private[_-]?key)[A-Za-z0-9_-]*(?:[=\s]+))(\S+)'
)
_BEARER_TOKEN_RE = re.compile(r'(?i)(\bBearer\s+)(\S+)')


def _redact_secrets(text: str) -> str:
    text = _SECRET_KEY_LINE_RE.sub(lambda m: f"{m.group(1)}[REDACTED]{m.group(3)}", text)
    text = _URL_CREDENTIAL_RE.sub(lambda m: f"{m.group(1)}{m.group(2)}:[REDACTED]@", text)
    text = _CLI_FLAG_SECRET_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    text = _BEARER_TOKEN_RE.sub(lambda m: f"{m.group(1)}[REDACTED]", text)
    return text


def _run_pytest(root: Path, node: str, collect_only: bool, timeout_seconds: float) -> tuple[bool, str]:
    # sys.executable, не "python3" (P2 внешнего ревью v2.9.94): на Windows
    # команда python3 часто отсутствует, а сам стандарт продвигает
    # переносимый запуск (python -m pytest / GOLDEN_PATH_STANDARD). "--"
    # перед node (v2.9.101) — вторая линия защиты от option injection поверх
    # _validate_test_ref, вызванной в main() до этой функции.
    args = [sys.executable, "-m", "pytest", "-q"]
    if collect_only:
        args.append("--collect-only")
    args.append("--")
    args.append(node)
    proc = subprocess.Popen(args, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, **_popen_kwargs())
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        # v2.9.97, P1 внешнего ревью v2.9.96: зависший сбор/тест раньше
        # блокировал gate навсегда. v2.9.99, P1 внешнего ревью v2.9.98:
        # убиваем всё дерево процессов, не только сам pytest.
        _terminate_process_tree(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return False, f"timeout после {timeout_seconds:.0f}с"
    tail_source = _redact_secrets((stdout or "") + (stderr or "")).strip()
    tail = tail_source.splitlines()[-1] if tail_source else ""
    return proc.returncode == 0, tail


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="корень проекта (по умолчанию '.')")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--collect-only", action="store_true",
                       help="только собрать узлы (pytest --collect-only) — не выполняет тесты")
    mode.add_argument("--run", action="store_true", help="реально выполнить каждый заявленный тест")
    ap.add_argument("--allow-missing-registry", action="store_true",
                     help="не считать отсутствие test_coverage.json ошибкой — для проектов, "
                          "которые осознанно не используют TEST_COVERAGE_CONTRACT")
    ap.add_argument("--pytest-timeout-seconds", type=_positive_finite_float, default=300.0,
                     help="таймаут на каждый вложенный вызов pytest (по умолчанию 300с; "
                          "конечное число > 0)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    try:
        data = _load(root / "docs" / "registry" / "test_coverage.json", args.allow_missing_registry)
    except (RegistryLoadError, RegistryMissingError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    try:
        refs = _pytest_refs(data)
    except TestCoverageEntryError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if not refs:
        print("нет kind=pytest test_refs в test_coverage.json — нечего проверять")
        return 0

    # v2.9.101, P1 внешнего ревью v2.9.100: та же уязвимость, что в
    # run_user_function_tests.py — валидируем ВСЕ refs до запуска первого.
    for sid, node in refs:
        try:
            _validate_test_ref(root, node)
        except UnsafeTestRefError as exc:
            print(f"{sid}: {exc}", file=sys.stderr)
            return 2

    failed = 0
    for sid, node in refs:
        ok, tail = _run_pytest(root, node, collect_only=args.collect_only,
                              timeout_seconds=args.pytest_timeout_seconds)
        status = "OK" if ok else "FAIL"
        print(f"  [{status}] {sid} -> {node}" + (f"  ({tail})" if not ok else ""))
        if not ok:
            failed += 1

    print(f"\n{len(refs) - failed}/{len(refs)} test_refs подтверждены "
          f"({'collect-only' if args.collect_only else 'run'})")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
