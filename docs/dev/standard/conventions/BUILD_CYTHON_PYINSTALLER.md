# Шаблон: Защищённая сборка Python → бинарник (Cython + PyInstaller)

> Переносимый шаблон. Применяется к любому Python-проекту, который нужно
> передать заказчику без исходного кода.
>
> Источники:
> - `License-hub/BUILD_GUIDE.md` — схема PyInstaller-поставки
> - `FNS_Checker/PYTHON_IP_PROTECTION.md` — боевые грабли + уровни защиты + Rust

---

## Зачем

- `.pyc` декомпилируется (`uncompyle6`) — не защищает
- `.pyd/.so` (Cython) — нативный C-код, практически не декомпилируется
- Strip убирает символы — усложняет реверс, −20-50% размер
- PyInstaller упаковывает в один `.exe`/ELF без Python на машине заказчика

```
.py ──Cython──► .c ──gcc──► .pyd/.so ──strip──► ──PyInstaller──► app.exe
```

---

## Минимальный setup.py

```python
from setuptools import setup, Extension
from Cython.Build import cythonize

extensions = [Extension(name="mymod", sources=["mymod.pyx"])]
setup(
    ext_modules=cythonize(extensions, compiler_directives={
        "language_level": "3",
        "embedsignature": True,   # нужно FastAPI / inspect.signature
        "binding": True,          # корректная работа декораторов
        "linetrace": False,       # защита: без трассировки
        "boundscheck": False,
        "wraparound": False,
        "cdivision": True,
    }, nthreads=1),               # ⚠️ >1 вызывает баг сортировки в Cython
    script_args=["build_ext", "--inplace"],
)
```

---

## Файлы-образцы

```
License-hub/setup_cython.py   ← компиляция .py → .pyd/.so
License-hub/build_exe.py      ← упаковка PyInstaller
License-hub/build.bat         ← one-click сборка (Windows)

optimus-service/setup_client.py    ← Cython + strip + scope-флаги
scripts/build_client.py            ← сборка dist (бинарники + точки входа)
```

---

## Что компилировать, что оставлять .py

| Модуль | Компилировать? | Почему |
|--------|---------------|--------|
| Бизнес-логика, криптография | ✅ да | Чувствительный IP |
| FastAPI-роуты (`*_api.py`) | ❌ нет | FastAPI через `inspect.signature()` ломается в .so |
| Entry-point (`main.py`) | ❌ нет | PyInstaller/загрузчик требует .py |
| `build_exe.py`, `setup_cython.py` | ❌ нет | Инструменты сборки |
| Обучающие утилиты (`train_*.py`) | ❌ нет | Клиенту не нужны, раздувают поставку |

---

## Strip символов

Убрать symbol table и debug info после компиляции:

```bash
find build_client -name "*.so" -exec strip --strip-all {} \;
```

- **Быстродействие:** не влияет. CPU исполняет тот же код.
- **Что теряется:** gdb/perf видят адреса вместо имён. Python traceback работает нормально.
- **Windows .pyd:** MinGW strip или MSVC без `/DEBUG`.

---

## Грабли (проверено болью)

| Проблема | Решение |
|---------|---------|
| `nthreads>1` в cythonize — баг сортировки | Всегда `nthreads=1` |
| `from __future__ import annotations` не первой строкой | Должна быть ПЕРВОЙ, до `__version__` и assignments |
| FastAPI ломается в скомпилированном роуте | Исключать `*_api.py` из компиляции |
| `.so` привязан к версии CPython | Собирать на той же Python, что в PyInstaller |
| Кросс-компиляция | Не работает. Собирать на целевой платформе |
| Пакеты (`common/`) попадают не туда | Нужна staging-папка с `__init__.py` |

---

## Перенос в новый проект

1. Скопировать `setup_cython.py` / `setup_client.py`, `build_exe.py`, `build.bat`
2. В setup: `MODULES` = список модулей с чувствительной логикой (без роутов и entry-points)
3. В `build_exe.py`:
   - `APP_NAME` — имя бинарника
   - `CYTHON_MODULES` — совпадает с `MODULES`
   - Entry-point → свой
   - `HIDDEN_IMPORTS` — то, что PyInstaller не находит статически (uvicorn, fastapi, jwt...)
   - `DATA_FILES` — статические ресурсы (UI, конфиги, ключи)
4. `requirements-build.txt`:
   ```
   pyinstaller>=6.0
   Cython>=3.0
   setuptools>=70.0
   ```

---

## Уровни защиты

| Уровень | Инструмент | Стоимость | Защита от |
|---------|-----------|-----------|-----------|
| 1 | Cython .so + strip | Бесплатно | Чтения глазами, casual reverse |
| 2 | Nuitka (`--module --no-docstrings`) | Бесплатно | Больше метаданных убрано |
| 3 | PyArmor Pro | ~$100/год | Шифрованный байткод + привязка к железу |
| 4 | Критическое ядро на Rust/PyO3 | 2-4 нед | Native binary, реверс = ассемблер |
| 5 | Rust + VMProtect/Themida | $500+ | Виртуализация кода, реверс — месяцы |
| 6 | SaaS / Confidential Computing | Архитектурное | Код не покидает сервер вообще |

**Рекомендация для большинства проектов:** Уровень 1 + License Hub = достаточно.

---

## Когда добавлять Rust (PyO3)

Профилировать сначала: `py-spy record -o prof.svg -- python main.py`

**Имеет смысл:**
- CPU-bound Python-циклы (10-30x ускорение)
- Параллелизм без GIL (`py.allow_threads` + rayon)
- Критический IP: Rust binary — чистый ассемблер, кратно сложнее Cython

**Не имеет смысла:**
- Всё, что уже в numpy/torch/onnxruntime (99% времени в C++)
- IO-bound (HTTP, БД) — Python не bottleneck
- Мелкие редко вызываемые функции — FFI overhead 10-100 нс/вызов

**Деплой Rust-модуля:** на сервере заказчика ничего дополнительного не нужно (статическая линковка). Собирать в manylinux-контейнере:
```bash
docker run --rm -v $(pwd):/io ghcr.io/pyo3/maturin build --release
```

---

## Что защищает / не защищает

| | Защищает? |
|---|---|
| Чтение исходника `.py` | ✅ да |
| Декомпиляция `.pyd/.so` | ✅ практически нет |
| Привязка к машине | ✅ через License Hub `machine_fingerprint` |
| Рантайм-дамп памяти реверсером | ❌ нет (нужен Уровень 4+) |
| Приватный RSA-ключ в дистрибутиве | ❌ НИКОГДА не класть |

---

## Чек-лист перед передачей заказчику

- [ ] В `dist/` нет ни одного `.py` из `CYTHON_MODULES`
- [ ] В `dist/keys/` только **публичные** ключи (`*_public_*.pem`)
- [ ] FastAPI-роуты не скомпилированы (проверить руками)
- [ ] `.env` не содержит production-секретов соседних систем
- [ ] Бинарник запускается на чистой машине без Python
- [ ] `.pyd/.so` собран под ту же версию CPython, что в PyInstaller

---

## Связанное

- Лицензирование: `_library/prompts/development/LICENSE_HUB_PATTERN.md`
- Скил клиента: `_library/skills/license-client/SKILL.md`
- Образцы файлов: `optimus-service/setup_client.py`, `License-hub/build_exe.py`
