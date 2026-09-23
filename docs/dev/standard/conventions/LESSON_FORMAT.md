# Формат урока

> Канонический формат урока, который пишется в конце разработки модуля
> или фичи и потом обрабатывается Учителем (`/teach`).
>
> Читается скилом `/finish-module` и `/teach`. Машиночитаемый
> frontmatter позволяет Учителю отслеживать распространение опыта.

---

## 1. Где живёт урок

Два параллельных артефакта:

| Где | Формат | Аудитория |
|---|---|---|
| **В проекте:** `docs/Отчеты/NN_Отчет_ретро_<slug>__DONE.md` + `docs/Инструкции_разработчика/NN_Инструкция_<module>_подводные_камни__DONE.md` | человеко-ориентированные retrospective и pitfalls | разработчики проекта |
| **В Архитекторе:** `docs/memory/lessons/{date}-{slug}.md` | машиночитаемый урок с frontmatter | Учитель и другие проекты |

`/finish-module` создаёт оба. Архитекторный вариант — это «экстракт» для
переноса в другие проекты.

---

## 2. Структура `docs/memory/lessons/{date}-{slug}.md`

```markdown
---
id: lesson-2026-04-18-cython-inspect-trap
source_project: RSD
source_module: src/<package>/use_cases

category: gotcha              # gotcha | pattern | anti-pattern | optimization | process
severity: warn                # info | warn | blocker
promote: true                 # вручную поднять приоритет для Учителя

tags:                         # свободные теги, поверх category
  - python
  - cython
  - static-compilation

context:
  stack: ["python-3.11", "cython-3.0", "pyinstaller-6.x"]
  domain: ["client-delivery"]
  trigger: "подготовка модуля к Cython-компиляции"

teaches: []                   # заполняется Учителем при обобщении
  # - target: _library/delivery/DELIVERY_ARCHITECTURE_CHECKLIST.md
  #   action: add_rule
  #   rule_id: "1.7.inspect-ban"

applied_to: []                # след применения Учителем
  # - path: _library/delivery/DELIVERY_ARCHITECTURE_CHECKLIST.md
  #   commit: abc1234
  #   date: 2026-04-18

propagation: []               # кто из проектов уже получил обновление
  # - project: Architector
  #   notified: true
  #   applied: true
  #   applied_at: 2026-04-18

related_lessons: []           # ссылки на смежные уроки по id
superseded_by: null           # id урока, который заменил этот
---

# Урок: <короткое название — что именно узнали>

## TL;DR

Одно-два предложения: что узнали и как применять.

## Что произошло

Факты. Без интерпретаций. «Модуль X при сборке через Cython перестал
работать, ошибка — Y, на строке Z».

## Почему

Корневая причина. «Cython компилирует в .c/.so, теряется доступ к
исходному .py через `inspect.getsource()`. Наш код использовал его
в `src/<package>/core/introspect.py` для динамической регистрации handlers».

## Как избегать

Рекомендация — это то, что потом переносится в стандарты Учителем.
Формулируется как правило, не как нарратив:

> В модулях, которые будут компилироваться через Cython, не использовать
> `inspect.getsource()`, `inspect.getfile()`, `__file__` для чтения кода
> как текста. Заменять на явные метаданные (`__registry__`) или
> `importlib.resources`.

## Как нашли

Опционально: процесс обнаружения. Полезно Учителю, чтобы понять,
какого рода проверки добавить в Doctor или стандарт.

## Примечания

Опционально: ссылки на PR, commits, issues, релевантные обсуждения.

## Ссылки

- PR проекта: [URL]
- Обсуждение: [URL]
- Смежная документация: [path]
```

---

## 3. Обязательные vs опциональные поля

| Поле | Обяз. | Заполняет |
|---|:---:|---|
| `id` | ✅ | `/finish-module` (формат `lesson-{date}-{slug}`) |
| `source_project` | ✅ | `/finish-module` |
| `source_module` | ✅ | `/finish-module` |
| `category` | ✅ | `/finish-module` (через вопрос пользователю) |
| `severity` | ✅ | `/finish-module` (через вопрос) |
| `promote` | ✅ | `/finish-module` (default false) |
| `tags` | — | `/finish-module` + автоизвлечение из контекста |
| `context` | — | `/finish-module` (stack и структура из `docs/README.md`, `docs/ТЗ/README.md`, `structure.txt`) |
| `teaches` | — | `/teach` |
| `applied_to` | — | `/teach` |
| `propagation` | — | `/teach` + `/sync-standards` |
| `related_lessons` | — | `/teach` (поиск похожих) |
| `superseded_by` | — | Учитель при замене урока новым |

---

## 4. Категории

| `category` | Когда использовать | Пример |
|---|---|---|
| **gotcha** | Неожиданная проблема, подводный камень | «inspect ломается после Cython» |
| **pattern** | Решение, повторяемое в разных местах | «License Hub через один boundary» |
| **anti-pattern** | Что нельзя делать и почему | «конфиг через getattr(config, x, default)» |
| **optimization** | Как сделать быстрее/дешевле | «batch embeddings по 32, не по 1» |
| **process** | Про методологию/процесс разработки | «reindex после update-library — автоматизировать» |

---

## 5. Severity

| `severity` | Значение |
|---|---|
| `info` | Полезно знать, не критично |
| `warn` | Стоит избегать, могут быть проблемы |
| `blocker` | Блокирует цель (сборку, релиз, основной сценарий) |

Учитель обобщает только уроки с `severity ≥ warn` ИЛИ `promote: true`.

---

## 6. Критерии обобщения Учителем

Урок повышается до правила в стандарте, если:

- **Повторяемость:** ≥2 проектов с тем же gotcha ИЛИ универсальная
  технология (Python, Cython, FastAPI — автоматически переносимо)
- **Переносимость:** не привязан к бизнес-домену
- **Действенность:** формулируется как правило, а не нарратив
- **Важность:** severity ≥ warn ИЛИ `promote: true`

При принятии решения «не обобщать» — Учитель пишет `teaches: [{target: "local-only"}]`,
чтобы урок не анализировался повторно.

---

## 7. Жизненный цикл урока

```
[модуль готов]
     │
     ▼
 /finish-module → docs/Отчеты/*_Отчет_ретро_*__DONE.md
     │           + docs/Инструкции_разработчика/*_подводные_камни__DONE.md
     │           + docs/memory/lessons/{id}.md в Архитекторе (teaches: [])
     ▼
[раз в неделю / после вехи]
     │
     ▼
 /teach сканирует lessons с пустым teaches
     │
     ▼
 По критериям: обобщить? → Edit в _library/* → заполнить teaches + applied_to
     │
     ▼
 /sync-standards в проектах подхватывает изменения → propagation заполняется
     │
     ▼
[новый модуль в новом проекте автоматически соблюдает новое правило]
```

---

## 8. Пример: урок → правило

### До (`docs/memory/lessons/2026-04-18-cython-inspect-trap.md`):

```yaml
---
id: lesson-2026-04-18-cython-inspect-trap
source_project: RSD
source_module: src/<package>/use_cases
category: gotcha
severity: blocker
promote: true
teaches: []
applied_to: []
---

# inspect.getsource() ломается после Cython
```

### После `/teach`:

```yaml
---
# ... то же ...
teaches:
  - target: _library/delivery/DELIVERY_ARCHITECTURE_CHECKLIST.md
    action: add_rule
    rule_id: "1.7.inspect-ban"
applied_to:
  - path: _library/delivery/DELIVERY_ARCHITECTURE_CHECKLIST.md
    commit: abc1234
    date: 2026-04-18
---
```

+ в `DELIVERY_ARCHITECTURE_CHECKLIST.md` §1.7 появилось правило со
ссылкой обратно на урок:

```
### 1.7. Никакого inspect / динамического self-reflection

...

> Правило добавлено из урока `lesson-2026-04-18-cython-inspect-trap`
> (source: RSD/src/<package>/use_cases).
```

---

## 9. Связанные документы

- `_architect/SELF_LEARNING_SYSTEM.md` — концепция 4 ролей
- Скил `/finish-module` — создаёт урок
- Скил `/teach` — обобщает урок в правило
- Скил `/sync-standards` — распространяет правило в проекты
