#!/usr/bin/env python3
# ======================================================================
# run_user_function_tests.py — версия 1.11 (для стандарта v2.9.114)
# Исполняемый раннер user_functions.json по affected-режиму. Роль: tool.
#
# Документированное исключение из лимита размера файла (SOURCE_FILE_
# STANDARD §1, v2.9.114, P2 внешнего ревью v2.9.113): единый дистрибутивный
# tool без внешних зависимостей, который проект «кладёт одним файлом» —
# тот же класс, что tools/validate_structure.py. Разбиение на несколько
# файлов сломало бы just-copy-this-file распространение. См. --check-
# file-size exemption в validate_structure.py и README.md.
# ======================================================================
"""Дополняет статический --check-user-functions: тот проверяет форму
реестра (пути существуют, related_registry ссылается на реальные записи);
этот инструмент реально ЗАПУСКАЕТ связанные проверки для затронутых
пользовательских функций — раздел §4.13 внешнего предложения по автономной
разработке (`01_agent_project_standard_autonomous_development.md`), принята
только сама идея affected-раннера, не вся предложенная там оркестрация.

ВАЖНО (v2.9.100): `automation.test_refs` — ТОЛЬКО pytest path/node id
(строка вида `tests/test_x.py` или `tests/test_x.py::test_name`). Этот
инструмент не универсальный test-раннер: он не выполняет Playwright/
Postman/shell-сценарии. Такие проверки описываются в `automation.tool`/
`automation.command` информационно (для человека/другого инструмента), но
НЕ должны попадать в `test_refs` — этот раннер передаст любую строку
оттуда напрямую в `python -m pytest`, и структурный (не строковый) элемент
там теперь явная ошибка конфигурации (`exit=2`), а не крах.

Использование:
  python tools/run_user_function_tests.py --mode all
  python tools/run_user_function_tests.py --mode affected --changed-from origin/main
  python tools/run_user_function_tests.py --mode affected --changed-from origin/main --committed-only
  python tools/run_user_function_tests.py --mode all --allow-missing-registry
  python tools/run_user_function_tests.py --mode all --pytest-timeout-seconds 60

--mode affected определяет изменённые файлы и находит user_functions,
затронутые изменением, чтобы запустить только их automation.test_refs.
Функция без automation.test_refs, но затронутая изменением — это находка
(evidence отсутствует), не тихий пропуск.

Источник паттернов "что считается затронутым" (v2.9.96, P1 внешнего ревью
v2.9.95): `regression_policy.affected_by` (glob-пути из
`USER_FUNCTION_REGISTRY_CONTRACT.md §4`), ОБЪЕДИНЁННЫЙ с `related_code` и
файлами из `automation.test_refs` (v2.9.98, P1 внешнего ревью v2.9.97 —
раньше изменение самого файла теста не делало функцию affected, хотя
test_refs явно на него ссылается; node id вида `path::test_x` обрезается до
пути файла). Не fallback ("одно ИЛИ другое") — именно объединение: владелец
мог не включить в ручной `affected_by` файл, который и так уже перечислен
в `related_code`/`test_refs`. Поддерживаются `*` (любые символы кроме `/`),
`**` (любая глубина путей, включая `/`), `**/` (ноль или более каталогов —
так `src/**/*.py` матчит и `src/module.py`, и `src/pkg/module.py`, v2.9.97)
и точные пути.

Сам реестр как источник изменений (v2.9.98, P1 внешнего ревью v2.9.97,
репродуцировано): если изменён `docs/registry/user_functions.json` —
новая запись, смена `status`, правка `automation.test_refs`/
`regression_policy` и т.п. — код мог не измениться вообще, но факт
реестра изменился. Консервативно (не diff записей — это отдельная,
более точная, но более сложная задача): при изменении самого файла
реестра ВСЕ ACTIVE функции считаются affected. Переход ACTIVE -> не-ACTIVE
(или удаление записи целиком) — отдельный случай, см. ниже "Удаление и
деактивация".

`--registry <path>` / `docs/registry/test_runner.json.registry` (v2.9.99):
можно переопределить канонический путь реестра — явный `--registry` >
`test_runner.json.registry` > `docs/registry/user_functions.json`.
v2.9.100 (P1 внешнего ревью v2.9.99, репродуцировано): переключение самого
`test_runner.json.registry` на другой путь (оба файла уже существовали и
не менялись) раньше не считалось изменением источника правды — теперь
раннер сравнивает resolved-путь на текущем HEAD и на merge-base; при
расхождении это трактуется как полная смена реестра (все ACTIVE affected
+ removal-check по старому файлу). `test_runner.json`, если существует,
теперь читается fail-closed: битый JSON/не-объект/`registry` не строка ->
`exit=2`, не тихий откат на канонический путь (было воспроизведено:
проект с двумя валидными реестрами и битым `test_runner.json` между ними
проверял пустой канонический файл, думая, что "нечего проверять").

Удаление и деактивация (v2.9.99, P1 внешнего ревью v2.9.98, репродуцировано):
"все ACTIVE affected при правке реестра" (v2.9.98) безопасно только для
записей, ОСТАЮЩИХСЯ ACTIVE — сама фильтрация по status=ACTIVE делала
переход ACTIVE->REMOVED/DEPRECATED (или удаление записи) невидимым,
функция просто исчезала из рассмотрения. Раннер сравнивает текущий реестр
со старым (на merge-base — см. ниже) через `git show <ref>:<path>`; ACTIVE
на базе, но не ACTIVE (или отсутствующая) сейчас -> `[REMOVAL REVIEW
REQUIRED]`, `exit=1` — обычный affected-прогон не имеет права
самостоятельно сертифицировать удаление пользовательской возможности.
v2.9.100 (P2 внешнего ревью v2.9.99, репродуцировано): старый реестр,
который СУЩЕСТВОВАЛ на базовом ref, но был битым/не массивом, раньше
трактовался так же, как "реестра там не было" — removal-check молча
пропускался. Теперь это разные случаи: "не было" — ок (проект только
завёл первый реестр), "был, но нечитаем" — `exit=2` (fail-closed, не
тихий пропуск removal-контроля).

Merge-base, не буквальный `--changed-from` (v2.9.100, P1 внешнего ревью
v2.9.99, репродуцировано): affected-файлы считаются как `git diff
<changed-from>...HEAD` — тройная точка уже сравнивает от merge-base. Но
старый реестр раньше грузился буквально с `git show <changed-from>:...` —
ТЕКУЩЕЙ вершины ветки `changed-from`, а не точки, где feature-ветка от неё
отделилась. Если `changed-from` (например, `main`) успел уйти вперёд после
разделения веток, эта рассинхронизация baseline давала ложные "removal
review required" для функций, добавленных на `main` уже ПОСЛЕ разделения
и никогда не существовавших на самой feature-ветке — блокируя корректный
PR. Теперь `git merge-base <changed-from> HEAD` вычисляется один раз и
используется и для removal-check, и для сравнения registry-path (test_runner
switch).

Изменённые файлы (v2.9.96, P1 внешнего ревью v2.9.95): по умолчанию —
объединение закоммиченного диапазона (`git diff --name-only
<changed-from>...HEAD`), незакоммиченных изменений (staged и unstaged) и
untracked-файлов — иначе gate перед commit (см. GIT_AGENT_WORKFLOW_STANDARD:
изменить -> проверить -> закоммитить) не видит именно те правки, которые
должен проверять. `--committed-only` возвращает старое поведение (только
закоммиченный диапазон). v2.9.97 (P1 внешнего ревью v2.9.96, репродуцировано):
все git-вызовы теперь используют `-z --no-renames` — без этого переименование
файла показывало ТОЛЬКО новый путь (старый путь, который реально перестал
существовать по старому адресу, был невидим affected-анализу), а не-ASCII
имена файлов git quote'ит в octal-escape форму (`"src/\\320\\274..."`),
которая не совпадает ни с одним реальным паттерном. v2.9.98 (P2 внешнего
ревью v2.9.97): git-вывод декодируется явным `encoding="utf-8",
errors="surrogateescape"` — раньше `text=True` без явной кодировки
полагался на `locale.getpreferredencoding()`, который на Windows не всегда
UTF-8.

Registry-файл (v2.9.95/96/97): по умолчанию `docs/registry/
user_functions.json` ОБЯЗАН существовать, если инструмент вызван явно —
отсутствие файла теперь `exit=2`, не тихий "0 ACTIVE, нечего проверять"
(P2 внешнего ревью v2.9.96: иначе случайно удалённый реестр неотличим от
проекта, который осознанно не использует этот контракт). Для проектов без
контракта — явный `--allow-missing-registry` возвращает старое поведение.

Timeout (v2.9.97, P1 внешнего ревью v2.9.96): каждый вложенный вызов pytest
ограничен `--pytest-timeout-seconds` (по умолчанию 300) — зависший тест или
plugin не должен блокировать gate навсегда; таймаут трактуется как FAIL, не
как исключение. v2.9.98 (P2 внешнего ревью v2.9.97, репродуцировано):
значение обязано быть конечным положительным числом — `nan`/`inf` роняли
необработанный `ValueError`/`OverflowError` внутри `subprocess`, отрицательное
давало формально успешный, но бессмысленный результат; теперь argparse сам
отклоняет некорректное значение с понятной ошибкой (`exit=2`, без traceback).
v2.9.99 (P1 внешнего ревью v2.9.98, репродуцировано): `subprocess.run(timeout=)`
останавливал только сам pytest — процесс, которого тест успел породить и
отсоединить (`start_new_session=True`/демонизация), переживал timeout.
Теперь при timeout снимается снимок всего дерева потомков (`ps`) и все они
завершаются SIGTERM->SIGKILL (POSIX) / `taskkill /T /F` (Windows). v2.9.100
(P2 внешнего ревью v2.9.99): если `ps` недоступен (минимальный контейнер) —
предупреждение в stderr, что гарантированный cleanup невозможен, а не
тихий пропуск.

`automation.test_refs` (v2.9.99/100): элементы обязаны быть строками
(pytest path/node id). Нестроковый элемент (например, структурный
`{"kind": "command", ...}` для будущего non-pytest раннера) — явная
ошибка конфигурации (`exit=2`), не крах (`TypeError: unhashable type`,
воспроизведено с dict-элементом). Несколько функций, ссылающихся на один и
тот же test_ref (общий E2E-сценарий и т.п.), выполняют его один раз, не
повторно на каждую функцию (v2.9.99); итоговый "функций задето" считается
по уникальным id, не по сумме длин списков (v2.9.100, P2 внешнего ревью
v2.9.99, репродуцировано: функция с двумя упавшими refs считалась дважды).

Диагностика при падении (v2.9.99): полный stdout+stderr печатается при
FAIL, не только последняя строка — иначе кодовый агент вынужден
перезапускать тест ради диагностики. v2.9.100 (P1 внешнего ревью v2.9.99,
репродуцировано: тест, печатающий `API_TOKEN=...`, отправлял секрет прямо
в лог): перед печатью применяется эвристическая редакция значений у ключей
вида `*TOKEN*`/`*SECRET*`/`*PASSWORD*`/`*API_KEY*`/`*AUTHORIZATION*`/
`*COOKIE*`/`*PRIVATE_KEY*` (regex по имени переменной, не по списку
конкретных секретов проекта) — это эвристика, не гарантия: нестандартно
названная или замаскированная тайна не будет поймана, вывод по-прежнему
не предназначен для публикации без ревью. v2.9.102 (P2 внешнего ревью
v2.9.101, репродуцировано): редакция ловила только `KEY: VALUE`/`KEY=VALUE`
— CLI-флаг вида `--api-key VALUE` (разделитель — пробел) и голый
`Bearer VALUE` без `Authorization:` уходили нередактированными; добавлены
отдельные паттерны для обоих случаев.

`--committed-only` и `.gitignore` (v2.9.102, P1 внешнего ревью v2.9.101,
репродуцировано): проверка чистоты worktree (`git status --porcelain`)
не видит файлы, перечисленные в `.gitignore`, — такой файл никогда не
"грязный", он невидим git полностью. test_ref, указывающий на такой файл,
исполнялся и сертифицировался как committed-evidence, хотя ни разу не
существовал в истории коммитов. Теперь каждый test_ref в режиме
`--committed-only` дополнительно проверяется через `git ls-files
--error-unmatch` — должен быть отслеживаемым файлом, не просто
существующим на диске. Полностью корректное решение (прогон в чистом
temporary checkout HEAD) — значительно более крупное изменение; реализовано
в v2.9.103 (детали ниже) и расширено в v2.9.112.

Типобезопасность реестра (v2.9.102, P1 внешнего ревью v2.9.101,
репродуцировано): `automation`/`regression_policy` нестрокового-не-dict
типа (например, строка вместо объекта) роняли необработанный
`AttributeError` при `.get(...)` — теперь явная ошибка конфигурации
(`exit=2`) до первого обращения к полям.

Историческая строгость test_runner.json (v2.9.102, P1 внешнего ревью
v2.9.101): `_resolve_registry_rel_path_at_ref` проверял строго только
JSON-парсинг и тип top-level объекта, а само поле `registry` внутри тихо
проходило через терпимый fallback-to-canonical для нестрокового/пустого
значения — асимметрично строгости текущего состояния
(`_resolve_registry_rel_path` для тех же значений бросает
TestRunnerConfigError). Теперь одинаково строго и для исторического ref.

`--committed-only`: усиление изоляции (v2.9.112, P1/P2 внешнего ревью
v2.9.103, реконструировано и репродуцировано заново). Четыре смежных
пробела в worktree-изоляции, добавленной в v2.9.103: (1) реестр (`id`/
`status`/`automation`/`test_refs` и т.д.) читался из `root` (рабочая
копия на диске), а не из самого worktree — dirty-check в начале защищает
только от УЖЕ имеющейся грязи на момент запуска, не от TOCTOU (файл может
измениться МЕЖДУ dirty-check и фактическим чтением реестра, пока считается
git diff/merge-base). Теперь temporary worktree создаётся сразу после
dirty-check, и реестр читается из него; git-операции (diff/show/merge-base/
ls-files) по-прежнему используют `root` — они сравнивают REFS, а не
рабочую копию, TOCTOU-окна не имеют. (2) Вложенный pytest наследовал ПОЛНОЕ
окружение родителя, включая `PYTHONPATH` — унаследованный путь мог
указывать на локальный/незакоммиченный модуль ВНЕ worktree, обходя саму
идею изоляции; теперь `PYTHONPATH` снимается явно для запусков внутри
worktree (остальное окружение сохраняется — иначе pytest может не
найтись). (3) Один и тот же worktree переиспользовался для ВСЕХ test_refs
одного прогона без сброса между ними — файл, сгенерированный/изменённый
одним тестом, мог просочиться в исполнение следующего; теперь worktree
сбрасывается (`git reset --hard` + `git clean -fdx`) перед каждым
test_ref. (4) Нестроковый `id` доходил до `', '.join(fids)` при печати
результата и ронял `TypeError`; нестроковый `status` тихо исключал запись
из ACTIVE-фильтра без единого сообщения — обе проверки типа теперь явные,
`exit=2`, ДО фильтрации (тот же паттерн, что automation/regression_policy/
related_code/test_refs).

Коды выхода: 0 — всё прошло (либо нечего проверять); 1 — тесты упали,
evidence отсутствует, сам pytest не уложился в таймаут, ИЛИ требуется
`[REMOVAL REVIEW REQUIRED]`; 2 — раннер не смог определить входные данные:
git diff/merge-base не удалось получить (недостающий ref, запуск вне
git-репозитория), docs/registry/user_functions.json битый/неверного типа,
файл отсутствует без `--allow-missing-registry`, docs/registry/
test_runner.json битый/неверной формы (включая историческую версию на
merge-base), старый реестр на merge-base существовал, но нечитаем,
automation/regression_policy неверного типа, automation.test_refs
содержит нестроковый/небезопасный/(при --committed-only) неотслеживаемый
git элемент, ИЛИ `--pytest-timeout-seconds` не является конечным
положительным числом.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


USER_FUNCTIONS_REGISTRY_REL_PATH = "docs/registry/user_functions.json"
TEST_RUNNER_REL_PATH = "docs/registry/test_runner.json"


class PathEscapesProjectError(RuntimeError):
    """Путь (registry-путь или test_ref) выходит за пределы --root.

    P1 внешнего ревью v2.9.100, репродуцировано: `"../outside_test.py"` в
    automation.test_refs реально исполнялся раннером — pytest получал
    относительный путь и `cwd=root` его резолвил наружу. Для автономного
    контура это обход lease/worktree-границ: агент, который может писать в
    registry, мог бы заставить gate выполнить код за пределами
    разрешённого scope."""


def _reject_path_escaping_project(root: Path, rel_path: str, what: str) -> None:
    """Бросает PathEscapesProjectError, если `rel_path` (после разрешения
    относительно `root`) не является потомком `root`. Ловит абсолютные пути,
    `..`-эскейп и (через `resolve()`) symlink, ведущий наружу."""
    if not rel_path or "\x00" in rel_path:
        raise PathEscapesProjectError(f"{what}: путь пуст или содержит NUL: {rel_path!r}")
    candidate = Path(rel_path.replace("\\", "/"))
    if candidate.is_absolute():
        raise PathEscapesProjectError(f"{what}: абсолютный путь запрещён: {rel_path!r}")
    resolved_root = root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(resolved_root)
    except ValueError:
        raise PathEscapesProjectError(
            f"{what}: путь выходит за пределы проекта ({resolved_root}): {rel_path!r}") from None


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
    """user_functions.json отсутствует, а --allow-missing-registry не передан.

    P2 внешнего ревью v2.9.96, репродуцировано: явный вызов инструмента на
    проекте без этого файла молча давал "0 ACTIVE, нечего проверять" ->
    exit=0 — неотличимо от случайно удалённого реестра. Файл обязателен по
    умолчанию, если инструмент вызван явно; opt-in для проектов, которые
    осознанно не используют этот контракт."""


class RegistryLoadError(RuntimeError):
    """user_functions.json битый или не массив — не то же самое, что "файла нет".

    Раньше (P2 внешнего ревью v2.9.95, репродуцировано) битый JSON печатал
    сообщение в stderr, но возвращал [] — "0 ACTIVE user_functions, нечего
    проверять", exit=0. Повреждённый реестр — не пустой реестр, раннер не
    имеет права молча решить, что проверять нечего."""


class TestRunnerConfigError(RuntimeError):
    """docs/registry/test_runner.json существует, но битый/неверной формы.

    P1 внешнего ревью v2.9.99, репродуцировано: раньше это молча трактовалось
    как "в test_runner.json нет поля registry" и раннер тихо откатывался на
    канонический путь — проект с двумя валидными реестрами и битым
    test_runner.json между ними проверял пустой канонический файл вместо
    настоящего, думая, что "нечего проверять"."""


class BaseTestRunnerUnreadableError(RuntimeError):
    """Исторический test_runner.json на merge-base СУЩЕСТВОВАЛ, но битый —
    не то же самое, что "его там не было".

    P1 внешнего ревью v2.9.100, репродуцировано: `_resolve_registry_rel_path_
    at_ref` раньше возвращала None для этого случая, а вызывающий код
    трактовал None как "путь не сменился" (`registry_switched = old_path is
    not None and old_path != registry_rel_path` — с `None` даёт `False`).
    Смена test_runner.json.registry на новый (уже существующий) путь при
    исторически нечитаемом test_runner.json проходила молча, `exit=0`."""


def _resolve_registry_rel_path_from_data(data, explicit: str | None) -> str:
    """Общая логика приоритета: явный --registry > test_runner.json.registry
    > канонический путь. `data` — уже распарсенный JSON test_runner.json
    (или None, если файла не было)."""
    if explicit:
        return explicit.replace("\\", "/")
    if isinstance(data, dict):
        registry = data.get("registry")
        if isinstance(registry, str) and registry:
            return registry.replace("\\", "/")
    return USER_FUNCTIONS_REGISTRY_REL_PATH


def _resolve_registry_rel_path(root: Path, explicit: str | None) -> str:
    """Приоритет (v2.9.99, P2 внешнего ревью v2.9.98 — по слову владельца,
    это не починка нарушенного контракта, а новая фича): явный --registry >
    docs/registry/test_runner.json.registry > канонический путь по
    умолчанию. v2.9.100 (P1 внешнего ревью v2.9.99, репродуцировано):
    test_runner.json, если существует, читается fail-closed — битый JSON
    или неверная форма (`registry` не строка, top-level не объект) бросает
    TestRunnerConfigError, не тихий откат на канонический путь. v2.9.101
    (P2 внешнего ревью v2.9.100, репродуцировано): пустая строка `registry`
    тоже неверная форма — раньше молча трактовалась как "поле не задано" и
    откатывалась на канонический путь."""
    if explicit:
        return explicit.replace("\\", "/")
    test_runner_path = root / TEST_RUNNER_REL_PATH
    if not test_runner_path.exists():
        return USER_FUNCTIONS_REGISTRY_REL_PATH
    try:
        data = json.loads(test_runner_path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TestRunnerConfigError(f"битый {test_runner_path}: {exc}") from exc
    if not isinstance(data, dict):
        raise TestRunnerConfigError(
            f"{test_runner_path}: ожидался объект, получено {type(data).__name__}")
    registry = data.get("registry")
    if registry is not None and not isinstance(registry, str):
        raise TestRunnerConfigError(f"{test_runner_path}: поле registry должно быть строкой")
    if registry == "":
        raise TestRunnerConfigError(
            f"{test_runner_path}: поле registry — пустая строка, а не отсутствует; "
            f"убери поле совсем, если хочешь канонический путь")
    return _resolve_registry_rel_path_from_data(data, None)


def _resolve_registry_rel_path_at_ref(root: Path, ref: str, explicit: str | None) -> str:
    """Тот же resolve, но по историческому test_runner.json на `ref` (через
    `git show`). Используется только для сравнения "сменился ли источник
    правды". v2.9.101 (P1 внешнего ревью v2.9.100, репродуцировано): раньше
    битый исторический файл трактовался терпимо (возврат None), а вызывающий
    код читал None как "не сменилось" — теперь это BaseTestRunnerUnreadableError,
    fail-closed: не можем надёжно сравнить baseline, не имеем права молча
    решить, что реестр не менялся."""
    if explicit:
        return explicit.replace("\\", "/")
    proc = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{TEST_RUNNER_REL_PATH}"],
                          capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        return USER_FUNCTIONS_REGISTRY_REL_PATH  # файла там не было -> канонический путь
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise BaseTestRunnerUnreadableError(
            f"{TEST_RUNNER_REL_PATH} на {ref} существует, но битый JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise BaseTestRunnerUnreadableError(
            f"{TEST_RUNNER_REL_PATH} на {ref}: ожидался объект, получено {type(data).__name__}")
    # v2.9.102 (P1 внешнего ревью v2.9.101): раньше только JSON-парсинг/тип
    # top-level объекта проверялись строго (fail-closed), а само поле
    # `registry` внутри проходило через терпимый `_resolve_registry_rel_path_
    # from_data`, который молча трактует нестроковое/пустое значение как
    # "поле не задано" -> канонический путь. Для ТЕКУЩЕГО состояния те же
    # значения — TestRunnerConfigError (см. `_resolve_registry_rel_path`).
    # Асимметрия: одна и та же поломка конфигурации на историческом ref
    # тихо резолвилась в "всё в порядке", хотя на текущем HEAD с тем же
    # содержимым инструмент отказался бы работать. Здесь — та же строгость.
    registry = data.get("registry")
    if registry is not None and not isinstance(registry, str):
        raise BaseTestRunnerUnreadableError(
            f"{TEST_RUNNER_REL_PATH} на {ref}: поле registry должно быть строкой")
    if registry == "":
        raise BaseTestRunnerUnreadableError(
            f"{TEST_RUNNER_REL_PATH} на {ref}: поле registry — пустая строка, а не отсутствует")
    return _resolve_registry_rel_path_from_data(data, None)


def _load(path: Path, allow_missing: bool) -> list:
    if not path.exists():
        if allow_missing:
            return []
        raise RegistryMissingError(
            f"{path} отсутствует — если проект осознанно не использует "
            f"USER_FUNCTION_REGISTRY_CONTRACT, передай --allow-missing-registry")
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RegistryLoadError(f"битый {path}: {exc}") from exc
    if not isinstance(data, list):
        raise RegistryLoadError(f"{path}: ожидался массив, получено {type(data).__name__}")
    # v2.9.103 (P1 внешнего ревью v2.9.102, репродуцировано): `[42]` (массив
    # с нестроковым/нестроковым элементом) раньше проходил эту проверку (это
    # массив), а дальнейший фильтр `isinstance(f, dict)` молча выбрасывал
    # такие элементы — реестр из одних "мусорных" записей выглядел как
    # "0 ACTIVE user_functions, нечего проверять", exit=0. Повреждённый
    # элемент — не то же самое, что пустой реестр.
    for i, entry in enumerate(data):
        if not isinstance(entry, dict):
            raise RegistryLoadError(
                f"{path}: элемент [{i}] должен быть объектом, получено {type(entry).__name__}")
    return data


class GitDiffError(RuntimeError):
    """git diff не удалось получить — недостающий ref/не git-репозиторий/др.

    Раньше эта ошибка молча трактовалась как "0 изменённых файлов" -> exit=0
    (P1 внешнего ревью v2.9.94, репродуцировано: --changed-from заведомо
    несуществующего ref давал зелёный результат). Ошибка diff — не "ничего
    не изменилось", это невозможность определить входные данные; раннер не
    имеет права молча решить, что проверять нечего."""


def _run_git_paths(root: Path, args: list[str]) -> set[str]:
    # -z: NUL-разделённый вывод — не quote'ит не-ASCII имена в octal-escape
    # и корректно передаёт пробелы/переводы строк в имени файла.
    # encoding="utf-8" явно, не text=True (P2 внешнего ревью v2.9.97): без
    # явной кодировки Python декодирует через locale.getpreferredencoding(),
    # который на Windows не всегда UTF-8 — git сам всегда пишет байты в UTF-8.
    proc = subprocess.run(["git", "-C", str(root)] + args, capture_output=True,
                          encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        raise GitDiffError(f"git {' '.join(args)} упал: {proc.stderr.strip()}")
    return {p for p in proc.stdout.split("\0") if p}


def _merge_base(root: Path, changed_from: str) -> str:
    """`git merge-base <changed_from> HEAD` — точка, где текущая ветка
    разошлась с `changed_from`, а не буквальная (возможно, ушедшая вперёд)
    вершина `changed_from` (P1 внешнего ревью v2.9.99, репродуцировано:
    `git show <changed_from>:...` брал ТЕКУЩУЮ вершину, а `git diff
    <changed_from>...HEAD` уже сравнивал от merge-base — рассинхронизация
    baseline давала ложные "removal review required" для записей,
    появившихся на `changed_from` уже ПОСЛЕ разделения веток и никогда не
    существовавших на самой feature-ветке)."""
    proc = subprocess.run(["git", "-C", str(root), "merge-base", changed_from, "HEAD"],
                          capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        raise GitDiffError(f"git merge-base {changed_from} HEAD упал: {proc.stderr.strip()}")
    return proc.stdout.strip()


class BaseRegistryUnreadableError(RuntimeError):
    """Старый реестр СУЩЕСТВОВАЛ на merge-base, но битый/не массив.

    P2 внешнего ревью v2.9.99, репродуцировано: раньше это трактовалось так
    же, как "файла там не было" — removal-check молча пропускался, будто
    сравнивать не с чем. "Не было" (проект только завёл первый реестр) и
    "был, но нечитаем" — разные случаи; второй не должен тихо отключать
    защиту от удаления."""


def _load_registry_at_ref(root: Path, ref: str, registry_rel_path: str) -> list | None:
    """Реестр на указанном ref через `git show <ref>:<path>`.

    None означает "файла там не было" (новый реестр — легитимно, ничего
    сравнивать) — не поднимает исключение. Если файл БЫЛ, но JSON битый или
    не массив — BaseRegistryUnreadableError (fail-closed, v2.9.100): это не
    то же самое, что отсутствие файла, и не должно молча отключать
    removal-check."""
    proc = subprocess.run(["git", "-C", str(root), "show", f"{ref}:{registry_rel_path}"],
                          capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        return None
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise BaseRegistryUnreadableError(
            f"{registry_rel_path} на {ref} существует, но битый JSON: {exc}") from exc
    if not isinstance(data, list):
        raise BaseRegistryUnreadableError(
            f"{registry_rel_path} на {ref}: ожидался массив, получено {type(data).__name__}")
    return data


def _detect_removed_or_deactivated(base_functions: list, current_functions: list) -> list[str]:
    """id'ы, ACTIVE на базовом ref, но не ACTIVE (или вовсе исчезнувшие) сейчас.

    P1 внешнего ревью v2.9.98, репродуцировано: "все ACTIVE affected при
    правке реестра" (v2.9.98) безопасно только для записей, ОСТАЮЩИХСЯ
    ACTIVE — сама фильтрация по status=ACTIVE делает переход ACTIVE->
    REMOVED/DEPRECATED (или полное удаление записи) невидимым: функция
    просто исчезает из рассмотрения, ноль проверок. Полный registry-diff
    (какие поля именно изменились) — отдельная, более сложная задача, не
    сделана; здесь только факт "была ACTIVE, перестала быть"."""
    base_active_ids = {f.get("id") for f in base_functions
                       if isinstance(f, dict) and f.get("status") == "ACTIVE" and f.get("id")}
    current_by_id = {f.get("id"): f for f in current_functions
                     if isinstance(f, dict) and f.get("id")}
    removed = []
    for fid in base_active_ids:
        cur = current_by_id.get(fid)
        if cur is None or cur.get("status") != "ACTIVE":
            removed.append(fid)
    return sorted(removed)


def _popen_kwargs() -> dict:
    """Платформенные kwargs для запуска в отдельной группе процессов —
    нужно, чтобы уметь убить дерево потомков теста целиком, не только сам
    pytest (см. _terminate_process_tree)."""
    if sys.platform == "win32":
        return {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
    return {"start_new_session": True}


def _descendant_pids(root_pid: int) -> list[int]:
    """Снимок PID всех потомков root_pid ПРЯМО СЕЙЧАС, через `ps`.

    Нужен отдельно от `killpg`: процесс, который сам вызвал свой
    `start_new_session`/`setsid()` (демонизация), заводит НОВУЮ сессию и
    pgid, отличный от родительского — `killpg(pytest_pid, ...)` его не
    достаёт, хотя PPID на этот момент ещё указывает на pytest (реальный
    reparent на init произойдёт только когда pytest умрёт). Снимок дерева
    ДО убийства ловит такие процессы по PID, а не по группе.

    Если `ps` недоступен (минимальный контейнер, v2.9.100, P2 внешнего
    ревью v2.9.99) — явное предупреждение в stderr вместо тихого возврата
    [], чтобы оператор знал: гарантированный cleanup дерева процессов при
    timeout здесь невозможен, а не притворялся, что всё чисто."""
    try:
        proc = subprocess.run(["ps", "-e", "-o", "pid=,ppid="], capture_output=True, text=True)
    except FileNotFoundError:
        print("предупреждение: команда 'ps' недоступна — cleanup дерева процессов "
              "при timeout не гарантирован (снимаются только сам pytest и его прямая "
              "группа, отсоединённые потомки могут пережить timeout)", file=sys.stderr)
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
    """SIGTERM -> (после паузы) SIGKILL всей группе процессов + отдельно
    снятым по PID потомкам на POSIX; `taskkill /T /F` на Windows.

    P1 внешнего ревью v2.9.98, репродуцировано: `subprocess.run(timeout=...)`
    останавливает только сам pytest — процесс, которого тест успел породить
    и отсоединить (`start_new_session=True` в самом тесте / демон), остаётся
    жить после timeout. Для автономного gate это критично: сервер/worker/
    браузер/контейнер/временная БД могут продолжать работать в фоне после
    того, как gate уже объявил проверку остановленной. Первая версия этого
    фикса убивала только `killpg(pytest_pid, ...)` — это НЕ ловит потомка,
    который сам вызвал `start_new_session`/сделал double-fork (заводит
    собственную группу процессов) — воспроизведено репродукцией ревьюера.
    Снимок дерева по PID через `ps` (см. `_descendant_pids`) ловит и такие
    процессы."""
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                       capture_output=True)
        return
    descendants = _descendant_pids(proc.pid)  # снимок ДО убийства чего-либо
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


def _worktree_is_dirty(root: Path) -> bool:
    proc = subprocess.run(["git", "-C", str(root), "status", "--porcelain"],
                          capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        raise GitDiffError(f"git status --porcelain упал: {proc.stderr.strip()}")
    return bool(proc.stdout.strip())


def _changed_files(root: Path, changed_from: str, committed_only: bool) -> set[str]:
    # --no-renames: без этого git схлопывает rename в один "новый путь" —
    # старый путь (реально переставший существовать по старому адресу)
    # был бы невидим affected-анализу. С --no-renames rename виден как
    # удаление старого пути + добавление нового — оба ловятся.
    changed = _run_git_paths(root, ["diff", "--no-renames", "--name-only", "-z",
                                    f"{changed_from}...HEAD"])
    if committed_only:
        return changed
    # рабочая директория: staged, unstaged, untracked — иначе gate перед
    # commit не видит правки, которые должен проверять (P1 внешнего ревью
    # v2.9.95: "изменить -> gate -> commit" из GIT_AGENT_WORKFLOW_STANDARD)
    changed |= _run_git_paths(root, ["diff", "--no-renames", "--name-only", "-z"])
    changed |= _run_git_paths(root, ["diff", "--no-renames", "--name-only", "-z", "--cached"])
    changed |= _run_git_paths(root, ["ls-files", "-z", "--others", "--exclude-standard"])
    return changed


def _pattern_to_regex(pattern: str) -> re.Pattern:
    """glob -> regex: `*` = любые символы кроме `/`, `**/` = ноль или более
    каталогов (включая завершающий `/`), `**` (не перед `/`) = любая глубина
    путей, остальное — точное совпадение после экранирования."""
    pattern = pattern.replace("\\", "/")
    out: list[str] = []
    i, n = 0, len(pattern)
    while i < n:
        if pattern[i:i + 3] == "**/":
            # "ноль или более каталогов": src/**/*.py матчит и src/x.py
            # (v2.9.97, P1 внешнего ревью v2.9.96 — раньше требовало ровно
            # одну промежуточную директорию)
            out.append("(?:.*/)?")
            i += 3
            continue
        c = pattern[i]
        if c == "*":
            if pattern[i:i + 2] == "**":
                out.append(".*")
                i += 2
            else:
                out.append("[^/]*")
                i += 1
        elif c == "?":
            out.append("[^/]")
            i += 1
        else:
            out.append(re.escape(c))
            i += 1
    return re.compile("^" + "".join(out) + "$")


def _is_affected(patterns: list, changed: set[str]) -> bool:
    compiled = [_pattern_to_regex(p) for p in patterns if isinstance(p, str)]
    normalized = {c.replace("\\", "/") for c in changed}
    return any(rx.match(path) for rx in compiled for path in normalized)


def _function_patterns(fn: dict) -> list[str]:
    """Объединение (не fallback) affected_by + related_code + test_refs.

    P1 внешнего ревью v2.9.97, репродуцировано: изменение файла из
    automation.test_refs (например, ослабили сам тест) не делало функцию
    affected, если путь не был отдельно продублирован в affected_by/
    related_code. test_refs — тот же самый источник истины "что защищает
    эту функцию", он обязан участвовать в детекции. Node id
    (`path::test_x`) обрезается до пути файла."""
    policy = fn.get("regression_policy") or {}
    automation = fn.get("automation") or {}
    affected_by = [p for p in (policy.get("affected_by") or []) if isinstance(p, str)]
    related_code = [p for p in (fn.get("related_code") or []) if isinstance(p, str)]
    test_refs = [ref.split("::", 1)[0] for ref in (automation.get("test_refs") or [])
                 if isinstance(ref, str)]
    seen: set[str] = set()
    out: list[str] = []
    for p in affected_by + related_code + test_refs:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _affected_functions(functions: list, changed: set[str], registry_rel_path: str,
                        force_all: bool = False) -> list:
    if force_all or registry_rel_path in changed:
        # P1 внешнего ревью v2.9.97, репродуцировано: правка самого реестра
        # (новая запись, смена status, test_refs, affected_by...) не меняет
        # код и раньше не задевала ни одну функцию. Консервативно: реестр
        # изменился -> все ACTIVE функции affected (точный registry-diff —
        # отдельная, более сложная задача, не сделана). Работает и для
        # кастомного пути реестра (v2.9.99, --registry) — сравнение по тому
        # же resolved-пути, что и загрузка. `force_all` (v2.9.100) —
        # вызывающий код уже определил переключение test_runner.json.registry
        # (сам файл на новом resolved-пути мог не измениться, поэтому
        # `registry_rel_path in changed` его не поймает).
        return list(functions)
    affected = []
    for fn in functions:
        if _is_affected(_function_patterns(fn), changed):
            affected.append(fn)
    return affected


# P1 внешнего ревью v2.9.99, репродуцировано: тест, печатающий
# "API_TOKEN=super-secret-value", отправлял значение прямо в лог CI.
# Эвристика по ИМЕНИ переменной (regex), не по конкретным значениям
# проекта — не гарантия: нестандартно названная или иначе замаскированная
# тайна не будет поймана. Полный вывод по-прежнему не предназначен для
# публикации без ревью, это снижение риска для типового случая, не защита.
#
# v2.9.101 (P1 внешнего ревью v2.9.100, репродуцировано): первая версия
# капturировала только `\S+` — одно "слово" после разделителя. На
# "Authorization: Bearer XYZ" это редактировало ТОЛЬКО "Bearer", оставляя
# сам токен XYZ на виду — хуже, чем не редактировать вовсе (создаёт
# ложное чувство безопасности). Теперь ключ-значение редактируется до
# конца строки (`.+?` с учётом кавычек/скобок JSON), плюс отдельный паттерн
# для credentials внутри connection string (`user:pass@host`).
_SECRET_KEY_LINE_RE = re.compile(
    r'(?im)(\b[A-Za-z0-9_.-]*(?:TOKEN|SECRET|PASSWORD|PASSPHRASE|API[_-]?KEY|'
    r'AUTHORIZATION|COOKIE|PRIVATE[_-]?KEY)[A-Za-z0-9_.-]*\b\s*[\'"]?\s*[:=]\s*[\'"]?)'
    r'(.+?)([\'"]?\s*[,}]?\s*)$'
)
_URL_CREDENTIAL_RE = re.compile(r'([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@]+):([^/\s@]+)@')
# v2.9.102 (P2 внешнего ревью v2.9.101, репродуцировано): `_SECRET_KEY_LINE_RE`
# требует разделитель `:`/`=` — CLI-флаг вида `--api-key VALUE` (разделитель —
# пробел) и голый `Bearer VALUE` без предшествующего `Authorization:` уходили
# в лог нередактированными.
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


class UnsafeTestRefError(RuntimeError):
    """test_ref небезопасен для передачи pytest как есть.

    P1 внешнего ревью v2.9.100, репродуцировано: test_ref="--collect-only"
    интерпретировался pytest как CLI-флаг, а не путь к тесту — pytest
    переходил в collect-only режим (ничего не выполняя) и всегда возвращал
    успех, даже при реально падающих тестах в проекте. Любой ref, начинающийся
    с "-", отклоняется; "--" перед ref в вызове pytest — вторая линия
    защиты (см. _run_test_ref)."""


class UntrackedTestRefError(RuntimeError):
    """--committed-only запрошен, но test_ref указывает на файл, не отслеживаемый git.

    P1 внешнего ревью v2.9.101, репродуцировано: `_worktree_is_dirty` проверяет
    `git status --porcelain`, но файл, перечисленный в `.gitignore`, НИКОГДА не
    появляется в этом выводе — он не "грязный", он невидим git полностью. Такой
    файл, ни разу не существовавший в истории коммитов, тем не менее исполнялся
    pytest и сертифицировался как "committed evidence" для --committed-only.
    Дешёвая проверка отслеживаемости самого test_ref (см. `_is_tracked_by_git`)
    ловит прямую подмену; транзитивные зависимости (импорт gitignored-модуля
    из отслеживаемого теста) она не ловит — см. `WorktreeError` и
    `_create_detached_worktree` ниже, это и есть полное решение той же
    проблемы."""


class WorktreeError(RuntimeError):
    """Не удалось создать/удалить временный detached worktree для --committed-only.

    P1 внешнего ревью v2.9.102, репродуцировано: тест, ОТСЛЕЖИВАЕМЫЙ git
    (проходит `_is_tracked_by_git`), но импортирующий gitignored-модуль (или
    читающий gitignored fixture/conftest.py/локальный .env), был зелёным
    локально, хотя в чистом checkout HEAD упал бы на этапе сборки/импорта —
    gitignored-файл физически существует на диске рядом с отслеживаемым
    тестом, но никогда не существовал в истории коммитов. Единственная
    надёжная семантика "--committed-only" — реально выполнять pytest не
    против рабочей копии на диске, а против временного detached worktree на
    HEAD (`git worktree add --detach`), где gitignored-файлы физически
    отсутствуют. Решение владельца (после явного вопроса о компромиссе
    "производительность и риск сломать сценарии, где тесты сейчас случайно
    зависят от gitignored-файлов" против "семантическая корректность") —
    полный корректный вариант, не более лёгкая частичная альтернатива."""


def _is_tracked_by_git(root: Path, rel_path: str) -> bool:
    proc = subprocess.run(
        ["git", "-C", str(root), "ls-files", "--error-unmatch", "--", rel_path],
        capture_output=True, encoding="utf-8", errors="surrogateescape")
    return proc.returncode == 0


def _create_detached_worktree(root: Path) -> tuple[Path, Path]:
    """Временный detached checkout HEAD — только отслеживаемые git файлы,
    без staged/unstaged/untracked/gitignored. `pytest`, запущенный здесь,
    видит РЕАЛЬНОЕ committed-состояние, а не рабочую копию на диске.

    Возвращает (worktree_root, exec_dir). `--root` инструмента не обязан
    совпадать с корнем git-репозитория (например, target-project — это
    подкаталог монорепо) — `git worktree add` всегда чекаутит ВЕСЬ
    репозиторий целиком в `worktree_root`; `exec_dir` — тот же
    относительный подкаталог внутри нового worktree, где реально нужно
    запускать pytest (cwd). Если бы `exec_dir` был равен `worktree_root`
    в таком случае, pytest запускался бы не в том каталоге и не находил
    бы тесты/конфиг вовсе."""
    proc_top = subprocess.run(
        ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
        capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc_top.returncode != 0:
        raise WorktreeError(
            f"не удалось определить корень git-репозитория для {root}: "
            f"{proc_top.stderr.strip()}")
    git_root = Path(proc_top.stdout.strip())
    tmp_dir = Path(tempfile.mkdtemp(prefix="committed_only_worktree_"))
    proc = subprocess.run(
        ["git", "-C", str(root), "worktree", "add", "--detach", str(tmp_dir), "HEAD"],
        capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        shutil.rmtree(tmp_dir, ignore_errors=True)
        raise WorktreeError(
            f"не удалось создать временный worktree на HEAD для --committed-only: "
            f"{proc.stderr.strip()}")
    try:
        rel = root.resolve().relative_to(git_root.resolve())
    except ValueError:
        rel = Path(".")
    return tmp_dir, (tmp_dir / rel)


def _remove_worktree(root: Path, worktree_path: Path) -> None:
    proc = subprocess.run(
        ["git", "-C", str(root), "worktree", "remove", "--force", str(worktree_path)],
        capture_output=True, encoding="utf-8", errors="surrogateescape")
    if proc.returncode != 0:
        # запасной путь: ручное удаление + prune, чтобы не оставлять мусор
        # на диске и не блокировать `git worktree add` будущими запусками
        # (git иначе помнит "занятый" путь в .git/worktrees/).
        shutil.rmtree(worktree_path, ignore_errors=True)
        subprocess.run(["git", "-C", str(root), "worktree", "prune"], capture_output=True)


def _reset_worktree(worktree_root: Path) -> None:
    """Возвращает detached worktree к чистому состоянию HEAD.

    v2.9.112 (P2 внешнего ревью v2.9.103, репродуцировано): один и тот же
    worktree раньше переиспользовался для ВСЕХ test_refs одного прогона без
    сброса между ними — файл, сгенерированный/изменённый одним тестом
    (__pycache__, кэш, побочная запись на диск), мог просочиться в
    исполнение следующего test_ref, ослабляя --committed-only изоляцию
    после первого запуска. Вызывается перед КАЖДЫМ test_ref (включая
    первый — сразу после создания worktree это no-op, но так не нужно
    отдельно обрабатывать первую итерацию)."""
    subprocess.run(["git", "-C", str(worktree_root), "reset", "--hard", "HEAD"],
                    capture_output=True, encoding="utf-8", errors="surrogateescape")
    subprocess.run(["git", "-C", str(worktree_root), "clean", "-fdx"],
                    capture_output=True, encoding="utf-8", errors="surrogateescape")


def _validate_test_ref(root: Path, ref: str, committed_only: bool = False) -> None:
    if ref.startswith("-"):
        raise UnsafeTestRefError(
            f"test_ref {ref!r} начинается с '-' — выглядит как pytest-опция, не путь к тесту")
    path_part = ref.split("::", 1)[0]
    _reject_path_escaping_project(root, path_part, f"test_ref {ref!r}")
    if committed_only and not _is_tracked_by_git(root, path_part):
        raise UntrackedTestRefError(
            f"test_ref {ref!r}: файл {path_part!r} не отслеживается git (untracked или "
            f".gitignore'нут) — --committed-only требует, чтобы evidence существовал в "
            f"истории коммитов, а не только на диске")


def _run_test_ref(root: Path, ref: str, timeout_seconds: float,
                  exec_root: Path | None = None) -> tuple[bool, str, str]:
    # sys.executable, не "python3" (P2 внешнего ревью v2.9.94): на Windows
    # команда python3 часто отсутствует. Popen (не subprocess.run) в
    # отдельной группе процессов (v2.9.99, P1 внешнего ревью v2.9.98) — при
    # timeout убиваем всю группу, не только сам pytest (см.
    # _terminate_process_tree). "--" перед ref (v2.9.101) — вторая линия
    # защиты от option injection поверх _validate_test_ref. `exec_root`
    # (v2.9.103) — для --committed-only это временный detached worktree на
    # HEAD (см. _create_detached_worktree), не рабочая копия на диске.
    env = None
    if exec_root is not None:
        # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано): изоляция
        # через detached worktree ловит файлы на диске, но unsanitized
        # окружение всё равно её обходит — унаследованный PYTHONPATH может
        # указывать на локальный/незакоммиченный код вне worktree, и pytest
        # внутри "изолированного" запуска молча импортирует его вместо
        # committed-версии. Полное окружение сохраняем (proxy/PATH/venv и
        # т.п. нужны, чтобы pytest вообще нашёлся и запустился) — снимаем
        # только PYTHONPATH.
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
    proc = subprocess.Popen([sys.executable, "-m", "pytest", "-q", "--", ref],
                            cwd=(exec_root or root), env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, **_popen_kwargs())
    try:
        stdout, stderr = proc.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        # v2.9.97, P1 внешнего ревью v2.9.96: зависший тест раньше блокировал
        # gate навсегда — таймаут теперь FAIL с понятным сообщением, не
        # необработанное исключение
        _terminate_process_tree(proc)
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        return False, f"timeout после {timeout_seconds:.0f}с", ""
    ok = proc.returncode == 0
    combined = _redact_secrets((stdout or "") + (stderr or ""))
    stripped = combined.strip()
    tail = stripped.splitlines()[-1] if stripped else ""
    # полный вывод возвращается только при падении (v2.9.99, P2 внешнего
    # ревью v2.9.98: раньше сохранялась только последняя строка — traceback/
    # assertion diff/captured logs терялись, кодовому агенту приходилось
    # перезапускать тест ради диагностики). Редакция секретов (v2.9.100)
    # применена ДО возврата — и tail, и full_output уже очищены.
    return ok, tail, ("" if ok else combined)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--root", default=".", help="корень проекта (по умолчанию '.')")
    ap.add_argument("--mode", choices=["all", "affected"], required=True)
    ap.add_argument("--changed-from", help="git ref для --mode affected (напр. origin/main)")
    ap.add_argument("--committed-only", action="store_true",
                     help="учитывать только закоммиченный диапазон (changed-from...HEAD), "
                          "игнорировать staged/unstaged/untracked — старое поведение до v2.9.96")
    ap.add_argument("--allow-missing-registry", action="store_true",
                     help="не считать отсутствие user_functions.json ошибкой — для проектов, "
                          "которые осознанно не используют USER_FUNCTION_REGISTRY_CONTRACT")
    ap.add_argument("--pytest-timeout-seconds", type=_positive_finite_float, default=300.0,
                     help="таймаут на каждый вложенный вызов pytest (по умолчанию 300с; "
                          "конечное число > 0)")
    ap.add_argument("--registry", default=None,
                     help="путь к реестру (относительно --root); по умолчанию — "
                          "docs/registry/test_runner.json.registry, если задан, иначе "
                          "docs/registry/user_functions.json (v2.9.99)")
    args = ap.parse_args()

    if args.mode == "affected" and not args.changed_from:
        print("--mode affected требует --changed-from", file=sys.stderr)
        return 2

    root = Path(args.root).resolve()
    committed_only_active = args.mode == "affected" and args.committed_only

    if committed_only_active:
        try:
            if _worktree_is_dirty(root):
                print("--committed-only запрошен, но рабочая директория не чиста (git status "
                      "--porcelain непуст) — pytest всё равно исполняется против реальной "
                      "рабочей копии на диске, незакоммиченная правка теста/кода может "
                      "сертифицировать committed-изменение, которого в истории нет", file=sys.stderr)
                return 2
        except GitDiffError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано): worktree раньше
    # создавался прямо перед исполнением тестов — реестр и все его
    # производные (id/automation/test_refs/regression_policy) читались из
    # `root` (рабочая копия на диске), а не из изолированного HEAD-снимка.
    # dirty-check выше защищает только от УЖЕ имеющейся грязи на момент
    # запуска, не от TOCTOU: параллельный процесс может тронуть отслеживаемый
    # файл МЕЖДУ dirty-check и фактическим чтением реестра (git diff/
    # merge-base ниже — не мгновенные на большом репозитории). Создаём
    # worktree сразу после dirty-check; `content_root` — этот worktree при
    # --committed-only, иначе сам `root` (обычный режим, поведение не
    # меняется). Весь остаток функции обёрнут в try/finally, чтобы каждый
    # существующий early-return всё равно чистил worktree.
    worktree_root: Path | None = None
    content_root = root
    if committed_only_active:
        try:
            worktree_root, content_root = _create_detached_worktree(root)
        except WorktreeError as exc:
            print(str(exc), file=sys.stderr)
            return 2

    try:
        try:
            registry_rel_path = _resolve_registry_rel_path(content_root, args.registry)
            _reject_path_escaping_project(content_root, registry_rel_path, "registry")
        except (TestRunnerConfigError, PathEscapesProjectError) as exc:
            print(str(exc), file=sys.stderr)
            return 2
        try:
            raw_functions = _load(content_root / registry_rel_path, args.allow_missing_registry)
        except (RegistryLoadError, RegistryMissingError) as exc:
            print(str(exc), file=sys.stderr)
            return 2

        # v2.9.112 (P1 внешнего ревью v2.9.103, репродуцировано): нестроковый
        # id ронял `', '.join(fids)` в TypeError ниже при печати результата
        # теста. Нестроковый status тихо исключал запись из ACTIVE-фильтра
        # без единого диагностического сообщения — неверно сконфигурированная
        # запись просто никогда не тестировалась, молча. Обе проверки — ДО
        # фильтрации, тем же явным exit=2 паттерном, что automation/
        # regression_policy/related_code/affected_by/test_refs ниже.
        for i, f in enumerate(raw_functions):
            if not isinstance(f, dict):
                continue
            fid_raw = f.get("id")
            if fid_raw is not None and not isinstance(fid_raw, str):
                print(f"{registry_rel_path}: id элемента [{i}] должен быть строкой, "
                      f"получено {type(fid_raw).__name__}", file=sys.stderr)
                return 2
            status_raw = f.get("status")
            if status_raw is not None and not isinstance(status_raw, str):
                print(f"{registry_rel_path}: status элемента [{i}] ({fid_raw!r}) должен быть "
                      f"строкой, получено {type(status_raw).__name__}", file=sys.stderr)
                return 2
        functions = [f for f in raw_functions if isinstance(f, dict) and f.get("status") == "ACTIVE"]

        # v2.9.100, P1 внешнего ревью v2.9.99, репродуцировано: dict-элемент в
        # automation.test_refs ронял `TypeError: unhashable type` при построении
        # ref_to_fids. test_refs — ТОЛЬКО pytest path/node id строки (см. docstring
        # модуля); нестроковый элемент — ошибка конфигурации, не крах. v2.9.101:
        # каждая строка дополнительно проверяется на option-injection ("-"
        # в начале) и path traversal (см. _validate_test_ref).
        for fn in functions:
            fid = fn.get("id", "?")
            automation = fn.get("automation")
            if automation is not None and not isinstance(automation, dict):
                print(f"{registry_rel_path}: automation у {fid!r} должен быть объектом, "
                      f"получено {type(automation).__name__}", file=sys.stderr)
                return 2
            policy = fn.get("regression_policy")
            if policy is not None and not isinstance(policy, dict):
                print(f"{registry_rel_path}: regression_policy у {fid!r} должен быть объектом, "
                      f"получено {type(policy).__name__}", file=sys.stderr)
                return 2
            # v2.9.103 (P1 внешнего ревью v2.9.102, репродуцировано): `related_code`
            # строкой (не списком) итерировался посимвольно в _function_patterns
            # (`for p in "src/feature.py" if isinstance(p, str)` — каждый символ
            # тоже строка) — glob-паттерны из одного символа практически никогда
            # не матчат реальные пути, affected-детекция тихо отключалась для
            # функции, exit=0 вместо честного "затронута". Аналогично для
            # regression_policy.affected_by.
            related_code = fn.get("related_code")
            if related_code is not None and (not isinstance(related_code, list)
                                              or not all(isinstance(p, str) for p in related_code)):
                print(f"{registry_rel_path}: related_code у {fid!r} должен быть списком строк, "
                      f"получено {related_code!r}", file=sys.stderr)
                return 2
            affected_by = (policy or {}).get("affected_by")
            if affected_by is not None and (not isinstance(affected_by, list)
                                             or not all(isinstance(p, str) for p in affected_by)):
                print(f"{registry_rel_path}: regression_policy.affected_by у {fid!r} должен быть "
                      f"списком строк, получено {affected_by!r}", file=sys.stderr)
                return 2
            refs = (automation or {}).get("test_refs")
            if refs is not None and (not isinstance(refs, list)
                                      or not all(isinstance(r, str) for r in refs)):
                print(f"{registry_rel_path}: automation.test_refs у {fid!r} должен быть списком "
                      f"строк (pytest path/node id, напр. \"tests/test_x.py::test_y\") — "
                      f"получено {refs!r}", file=sys.stderr)
                return 2
            for ref in refs or []:
                try:
                    _validate_test_ref(root, ref, committed_only=committed_only_active)
                except (UnsafeTestRefError, PathEscapesProjectError, UntrackedTestRefError) as exc:
                    print(f"{registry_rel_path}: {fid!r}: {exc}", file=sys.stderr)
                    return 2

        removal_review = False
        if args.mode == "affected":
            try:
                changed = _changed_files(root, args.changed_from, args.committed_only)
                merge_base = _merge_base(root, args.changed_from)
            except GitDiffError as exc:
                print(str(exc), file=sys.stderr)
                print("не удалось определить изменённые файлы — это не "
                      "\"0 изменённых файлов\", раннер не может решить, что "
                      "проверять нечего", file=sys.stderr)
                return 2

            # v2.9.100, P1 внешнего ревью v2.9.99, репродуцировано: смена самого
            # test_runner.json.registry (оба файла уже существовали, не менялись)
            # раньше не считалась изменением источника правды. Сравниваем
            # resolved-путь на merge-base с текущим. v2.9.101: битый исторический
            # test_runner.json теперь fail-closed (BaseTestRunnerUnreadableError),
            # не тихий None, который раньше читался как "не сменилось".
            try:
                old_registry_rel_path = _resolve_registry_rel_path_at_ref(root, merge_base, args.registry)
            except BaseTestRunnerUnreadableError as exc:
                print(str(exc), file=sys.stderr)
                print("исторический test_runner.json существовал на базовом ref, но нечитаем — "
                      "невозможно надёжно определить, сменился ли источник правды реестра",
                      file=sys.stderr)
                return 2
            registry_switched = old_registry_rel_path != registry_rel_path
            registry_source_changed = registry_switched or registry_rel_path in changed
            base_registry_rel_path = old_registry_rel_path if registry_switched else registry_rel_path

            if registry_source_changed:
                try:
                    # merge-base, не буквальный --changed-from (P1 внешнего
                    # ревью v2.9.99, репродуцировано: рассинхронизация baseline
                    # между git diff (уже merge-base через "...") и git show
                    # (буквальная вершина changed-from) давала ложные "removal
                    # review required" для записей, добавленных на changed-from
                    # уже ПОСЛЕ разделения веток).
                    base_functions = _load_registry_at_ref(root, merge_base, base_registry_rel_path)
                except BaseRegistryUnreadableError as exc:
                    print(str(exc), file=sys.stderr)
                    print("старый реестр существовал на базовом ref, но нечитаем — "
                          "removal-check не может быть тихо пропущен", file=sys.stderr)
                    return 2
                if base_functions is not None:
                    removed_ids = _detect_removed_or_deactivated(base_functions, raw_functions)
                    for fid in removed_ids:
                        print(f"  [REMOVAL REVIEW REQUIRED] {fid} — ACTIVE-функция удалена или "
                              f"деактивирована; автоматическая affected-проверка не может "
                              f"сертифицировать удаление")
                    if removed_ids:
                        removal_review = True

            targets = _affected_functions(functions, changed, registry_rel_path,
                                          force_all=registry_source_changed)
            print(f"изменённых файлов: {len(changed)} | затронутых user_functions: {len(targets)}")
        else:
            targets = functions
            print(f"всего ACTIVE user_functions: {len(targets)}")

        if not targets:
            if removal_review:
                print("нечего запускать, но требуется ручной review удаления/деактивации выше")
            else:
                print("нечего проверять")
            return 1 if removal_review else 0

        # v2.9.99, P2 внешнего ревью v2.9.98: несколько функций могут ссылаться
        # на один и тот же test_ref (общий E2E-сценарий и т.п.) — раньше он
        # запускался повторно для каждой, увеличивая время/стоимость и риск
        # flaky. Строим test_ref -> [function_id] и выполняем каждый уникальный
        # ref один раз, результат распространяем на все связанные функции.
        ref_to_fids: dict[str, list[str]] = {}
        missing_evidence = 0
        for fn in targets:
            fid = fn.get("id", "?")
            refs = (fn.get("automation") or {}).get("test_refs") or []
            if not refs:
                print(f"  [NO EVIDENCE] {fid} — automation.test_refs пуст, затронут изменением")
                missing_evidence += 1
                continue
            for ref in refs:
                ref_to_fids.setdefault(ref, []).append(fid)

        # v2.9.103 (P1 внешнего ревью v2.9.102, репродуцировано): проверка
        # отслеживаемости самого test_ref (_is_tracked_by_git) не ловит
        # транзитивные зависимости (тест импортирует gitignored-модуль) — pytest
        # для --committed-only исполняется против временного detached worktree
        # на HEAD (создан выше), не против рабочей копии на диске.
        failed_refs: set[str] = set()
        for ref, fids in ref_to_fids.items():
            if committed_only_active:
                # v2.9.112 (P2 внешнего ревью v2.9.103, репродуцировано): один
                # и тот же worktree переиспользовался для ВСЕХ test_refs одного
                # прогона без сброса между ними — файл, сгенерированный/
                # изменённый одним тестом (__pycache__, побочная запись на
                # диск), мог просочиться в исполнение следующего test_ref.
                _reset_worktree(worktree_root)
            ok, tail, full_output = _run_test_ref(
                root, ref, args.pytest_timeout_seconds,
                exec_root=(content_root if committed_only_active else None))
            status = "OK" if ok else "FAIL"
            print(f"  [{status}] {ref} -> {', '.join(fids)}" + (f"  ({tail})" if not ok else ""))
            if not ok:
                failed_refs.add(ref)
                # v2.9.99, P2 внешнего ревью v2.9.98: раньше сохранялась только
                # последняя строка вывода — traceback/assertion diff/captured
                # logs терялись, кодовому агенту приходилось перезапускать тест
                # ради диагностики. Печатаем полный stdout+stderr при падении
                # (уже редактированный от секретов — см. _run_test_ref).
                if full_output.strip():
                    print("    --- полный вывод ---")
                    for line in full_output.strip().splitlines():
                        print(f"    {line}")
                    print("    --------------------")

        # v2.9.100, P2 внешнего ревью v2.9.99, репродуцировано: функция с двумя
        # упавшими test_refs считалась дважды (sum длин списков) — теперь
        # уникальные id, не сумма.
        impacted_ids = {fid for ref in failed_refs for fid in ref_to_fids[ref]}
        functions_impacted = len(impacted_ids)
        print(f"\n{len(targets)} функций, {len(ref_to_fids)} уникальных test_refs "
              f"({len(failed_refs)} упавших, {functions_impacted} функций задето), "
              f"{missing_evidence} без evidence (automation.test_refs пуст)")
        return 1 if (failed_refs or missing_evidence or removal_review) else 0
    finally:
        if worktree_root is not None:
            _remove_worktree(root, worktree_root)


if __name__ == "__main__":
    sys.exit(main())
