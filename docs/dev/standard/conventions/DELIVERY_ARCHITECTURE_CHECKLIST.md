# Delivery Architecture Checklist

> Архитектурный профиль проекта, который будет поставляться клиенту
> как защищённый бинарь (Cython + PyInstaller + License Hub).
>
> **Применять С САМОГО НАЧАЛА проекта**, даже если до сборки ещё далеко.
> Ретрофит на существующий код — кратно дороже.
>
> Источник: практика доработки server-проекта под клиентскую поставку
> (перенесено в Архитектора 2026-04-18).

---

## Отношения с другими документами

| Документ | Что там | Связь |
|---|---|---|
| `IP_PROTECTION_GUIDE.md` | **Что и зачем** защищать (концепция, слои) | Этот чек-лист — **как архитектурно подготовиться** |
| `BUILD_PROTECTED_BINARY.md` | **Как собирать** (Cython → PyInstaller, команды) | Этот чек-лист — что должно существовать **до** сборки |
| `LICENSE_HUB_INTEGRATION.md` | **Как подключиться** к серверу лицензий (API) | Этот чек-лист — где разместить boundary и как интегрировать |

---

## 1. Двенадцать требований к архитектуре

### 1.1. Отдельный delivery-profile

Защищённая поставка — **отдельный профиль**, а не вариация основного
runtime. Не меняет поведение dev/prod.

```
configs/
└── profiles/
    ├── dev.yaml
    ├── prod.yaml
    └── delivery.yaml      ← профиль клиентской поставки
```

Селектор профиля — env `APP_PROFILE=delivery` или флаг `--profile delivery`.

### 1.2. Тонкие точки входа

`app/main.py`, `dashboard/app.py` — максимум bootstrap + wiring.
Бизнес-логика в `core/`, `orchestrator/`, `plugins/`.

**Почему:** entry points хуже всего переживают Cython/PyInstaller
(dynamic discovery, imports, side-effects). Чем тоньше — тем меньше
проблем при сборке.

### 1.3. Чувствительная логика — в модулях с ясной границей

Концентрируется в: `core/`, `orchestrator/`, `llm/`, `plugins/`, `browser/`.

Это **будущие кандидаты на Cython-компиляцию**, не entry points.

Антипаттерн: «утилитка» в `utils/` с критичным алгоритмом — либо
перенести в `core/`, либо явно пометить как `_internal/` с комментарием
«компилируется».

### 1.4. License Hub — один integration boundary

**Один** модуль — `adapters/license/` или `plugins/license_client/` —
с единственным публичным интерфейсом:

```python
class LicenseGate:
    def verify(self, feature: str) -> LicenseState: ...
    def activate(self, key: str) -> None: ...
```

Все остальные модули обращаются **только через него**. Никаких
`if license.valid:` в бизнес-логике напрямую.

**Почему:** при ротации SDK, смене протокола, breaking-change Hub'а —
правим один файл, а не 40.

### 1.5. Конфиг как контракт

Всё настраиваемое — через `models/config_schema.py` (pydantic).
FAIL-FAST: невалидный конфиг → отказ при bootstrap.

**Запрещено** в коде защищённого модуля:
- Хардкоды URL, таймаутов, лимитов
- Чтение env напрямую (только через config loader)
- `getattr(config, "x", default)` — используй строгую схему

### 1.6. Компилируемое vs runtime-ресурсы

Явное разделение:

| Что компилируется | Остаётся внешним |
|---|---|
| `core/`, `orchestrator/`, `llm/`, `plugins/`, `browser/` | `configs/*.yaml` |
| `adapters/` (кроме интерфейсов, доступных для расширения) | `data/` (БД, артефакты) |
| `models/` (схемы) | `logs/` |
| `utils/doctor.py` | `docs/user/` (если в поставку) |
| | UI-статика (`dashboard/static/`) |
| | Публичные ключи (`keys/public/*.pem`) |
| | Лицензионный файл клиента |

### 1.7. Никакого `inspect` / динамического self-reflection

Критичная логика **не должна** зависеть от:
- `inspect.getsource()` / `inspect.getfile()`
- `__file__` для чтения соседних файлов как исходников
- Динамической генерации кода через `exec()` / `eval()`
- Late imports через строковые имена классов

**Почему:** после Cython-компиляции это ломается. PyInstaller onefile —
ломает ещё больше (`__file__` указывает на временный каталог).

Заменители:
- `inspect` → явные метаданные в модуле (`__registry__ = {...}`)
- `__file__` → `importlib.resources` / `pkg_resources`
- `exec` → плагин-интерфейс с явной регистрацией

### 1.8. Никаких секретов в поставке

В клиентский бинарь попадают **только**:
- Публичные ключи (для verify JWT от License Hub)
- Runtime-конфиг (URL Hub'а, таймауты)
- Код приложения (скомпилированный)

**Не попадают:**
- Приватные ключи
- Серверные секреты (API keys к LLM-провайдерам клиент подключает свои)
- Dev-конфиги, пароли от БД разработки
- `.env` файлы

Проверка — скрипт `tools/audit_delivery_bundle.py` перед релизом
(генерируется `/generate-project`).

### 1.9. Doctor знает про поставку

`utils/doctor.py` должен уметь в режиме `--profile delivery`:

- [ ] Проверить наличие всех обязательных runtime-файлов
- [ ] Проверить целостность bundle (хэши `.pyd`/`.so`)
- [ ] Проверить validity лицензии + срок
- [ ] Проверить связь с License Hub
- [ ] Проверить наличие публичных ключей
- [ ] Проверить, что mutable state каталоги (data/, logs/) writable
- [ ] Проверить, что все env-переменные из схемы заполнены

### 1.10. Mutable state — снаружи бинаря

Никогда не внутри PyInstaller-бандла:

- `data/automation.db` (SQLite)
- `logs/`
- `artifacts/` (сгенерированные файлы)
- `configs/runtime/` (клиентские настройки)
- Кеши (`data/cache/`)

Пути берутся из конфига или env, default — рядом с бинарём:

```python
# models/config_schema.py
class Paths(BaseModel):
    data_dir: Path = Field(default_factory=lambda: Path("./data"))
    logs_dir: Path = Field(default_factory=lambda: Path("./logs"))
```

### 1.11. Build-логика — отдельным слоем

`BUILD_PROTECTED_BINARY.md` — это external pipeline, не часть приложения.

Жить должно в:
```
build/
├── cython/
│   ├── build.sh
│   └── setup.py
├── pyinstaller/
│   ├── build.sh
│   └── <project>.spec
└── audit/
    └── audit_delivery_bundle.py
```

В runtime-коде — никаких упоминаний Cython / PyInstaller.

### 1.12. Feature-to-entitlement map

Явный реестр: **какие фичи лицензируются, какие базовые**.

Файл: `configs/entitlements.yaml` (в git, публичный):

```yaml
features:
  - name: basic_automation
    tier: base              # base | pro | enterprise
    requires_license: false
  - name: multi_tenant
    tier: enterprise
    requires_license: true
  - name: llm_bring_your_own
    tier: base
    requires_license: false
  - name: license_hub_offline_grace_days
    tier: pro
    value: 7
```

Клиентский код проверяет:

```python
if license_gate.has_feature("multi_tenant"):
    enable_multi_tenant()
else:
    raise FeatureNotLicensedError("multi_tenant")
```

Не спрашивать каждый раз Hub — feature-check **кешируется** в
`LicenseGate` на TTL из конфига.

---

## 2. Что проверить на своём проекте (TO VERIFY)

Эти вопросы **нужно закрыть в ТЗ** до начала реализации:

### 2.1. Какие модули чувствительны для компиляции?

Составить список конкретных пакетов проекта, которые **обязательно**
попадают в Cython:

- [ ] `core/` (всегда)
- [ ] `orchestrator/` (всегда)
- [ ] `llm/`
- [ ] `plugins/<x>/` (точечно)
- [ ] `browser/`
- [ ] что-то специфическое для домена?

Что **не компилируется**: `models/` (нужно для deserialization),
`configs/`, `tests/`, `scripts/`.

### 2.2. Защищённая поставка нужна для backend-only или для web/UI тоже?

- **Backend-only** — компилируем Python, UI (если есть) остаётся
  обычной статикой в `dashboard/static/`. Проще, быстрее, меньше рисков.
- **Backend + UI** — нужно решить: обфускация JS? bundling через
  закрытый webpack? Electron-обёртка? Это кратно усложняет pipeline.

### 2.3. Какой формат поставки?

| Формат | Когда | Плюсы | Минусы |
|---|---|---|---|
| **onedir** | default | Быстрый старт, легко апдейтить точечно | Клиент видит структуру |
| **onefile** | один exe клиенту | Нечего разбирать на куски | Медленный старт, проблемы с `__file__`, сложнее обновлять |
| **Docker bundle** | Linux server appliance | Изолированное окружение, любые зависимости | Требует Docker у клиента |
| **Appliance** (полный image) | On-premise turnkey | Zero-install | Огромный размер, OS-lock |

Решение фиксируется в `docs/dev/adr/NNNN-delivery-format.md`.

### 2.4. Что из `docs/` уезжает клиенту?

Состав `docs/` в бандле выбирается перечнем, а не вычитанием: перечисляется
то, что клиенту нужно, остальное не попадает. Обратный порядок ошибается
молча — новый раздел `docs/` уезжает вместе со сборкой, и узнают об этом у
клиента.

Клиенту нужны `Инструкции_пользователя/` и, если он сопровождает решение
сам, `Инструкции_разработчика/`.

Клиенту не отдаются:

| Раздел | Почему |
|--------|--------|
| `Презентации/` | материалы для инвесторов и партнёров: цифры, планы, позиционирование — не для заказчика решения |
| `Отчеты/`, `audits/` | аудиты и находки, включая незакрытые: список слабых мест продукта |
| `memory/` | решения, уроки и тупики — внутренняя кухня |
| `БТ/`, `ТЗ/` | требования и контракты: по ним воспроизводится продукт |
| `Архив/` | устаревшее, которое никто не перечитывал перед отдачей |

`Дизайн/` и `registry/` решаются по проекту: первый бывает нужен при передаче
интерфейса, второй — при интеграции.

Раздел `Презентации/` заведён в `DOCUMENTATION_STANDARD.md` §2.1 выпуском
2.9.174, и до этого пункта состав `docs/` в бандле не оговаривался нигде.

---

## 3. Ретрофит на существующий код

Если проект уже в разработке, а пункты чек-листа не соблюдены:

1. **Аудит** — пройти по 12 пунктам, составить список отклонений
2. **Расставить приоритеты** — сначала 1.4 (License boundary), 1.8
   (секреты), 1.7 (inspect), потом остальное
3. **Завести ADR** на каждую крупную переделку
4. **Не откладывать до сборки** — чем ближе к релизу, тем дороже

---

## 4. Автоматизация

`/generate-project` при типе `client-delivery`:

1. Добавляет в `docs/agents/PROJECT_CONTEXT.md` блок про поставку
2. Копирует `configs/profiles/delivery.yaml.tpl`
3. Копирует `build/` pipeline из `_workspace/_template/build/`
4. Копирует `tools/audit_delivery_bundle.py`
5. Копирует `configs/entitlements.yaml.tpl`
6. В `models/config_schema.py` добавляет `DeliveryConfig` секцию
7. В `utils/doctor.py` добавляет `DeliveryDoctorChecks`
8. Автоподключает `_library/delivery/*.md` в docs/dev/
9. Добавляет ADR-шаблоны: `NNNN-delivery-format.md`, `NNNN-license-boundary.md`

---

## 5. Связанные документы

- `IP_PROTECTION_GUIDE.md` — зачем защищать, что именно
- `BUILD_PROTECTED_BINARY.md` — как собирать
- `LICENSE_HUB_INTEGRATION.md` — интеграция с сервером лицензий
- `_library/agent_configs/global/ISKINOSPHERE_INTEGRATION_STANDARD.md` — подключение к панели управления (часто идёт в паре с защищённой поставкой)
- `_library/prompts/development/LICENSE_HUB_PATTERN.md` — паттерн (подробности API)
