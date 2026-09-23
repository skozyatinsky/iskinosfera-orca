# Оркестрация: субагенты, команды, Codex

> Как оркестратор (Claude Code lead) распределяет задачи, контролирует исполнение
> и координирует работу нескольких агентов.

---

## Четыре уровня параллельности

```
Уровень 1: Субагенты       Уровень 2: Agent Teams     Уровень 3: Managed Agents  Уровень 4: Локальный Оркестратор
(внутри одной сессии)       (несколько сессий)          (облако Anthropic)          (automation_server v3)

Claude Code (lead)          Claude Code (lead)          API                         Ralph Loop
  ├── Explore (Haiku)         ├── Teammate: Front         ├── Session 1               ├── ClaudeCodeRunner
  ├── Plan (Sonnet)           ├── Teammate: Back          ├── Session 2               ├── CodexRunner
  ├── code-reviewer           ├── Teammate: Tests         └── Session 3               ├── QwenRunner
  ├── codex-rescue            └── Shared task list                                    └── + новые Runner'ы
  └── результат → lead         └── общаются между собой

Быстро, дёшево              Мощно, дороже               Фоново, облачно             Автономно, пакетно
Результат → в контекст      Каждый — полная сессия       Через API                   Очередь задач + бюджет
Не общаются между собой     Общаются через mailbox       Независимые контейнеры      Детерминированный цикл
```

### Когда какой уровень

| Задача | Уровень | Почему |
|--------|:-------:|--------|
| Быстрый поиск по коду | 1 — Субагент (Explore) | Секунды, дёшево |
| Ревью + тесты | 1 — Субагенты | Параллельно внутри сессии |
| Исследование 3 вариантов | 2 — Agent Teams | Каждый копает своё |
| Фоновый аудит безопасности | 3 — Managed Agents | Часы, не блокирует |
| 5 задач на ночь разным агентам | **4 — Оркестратор** | Автономно, с бюджетом |
| Nightly regression suite | **4 — Оркестратор** | Пакетно, по расписанию |

### Связь: Архитектор → Оркестратор

```
Архитектор (/generate-project)
    │
    ├─→ AGENTS.md, CLAUDE.md, settings.json    (правила для агентов)
    ├─→ .claude/agents/*.md                     (определения субагентов)
    ├─→ skills/, MCP configs                    (инструменты)
    │
    ▼
Человек декомпозирует задачу → список микроТЗ
    │
    ▼
automation_server v3 (POST /api/v3/tasks)
    │
    ├─→ Ralph Loop: приоритет → зависимости → бюджет → агент
    ├─→ Runner запускает агента ИЗ ДИРЕКТОРИИ ПРОЕКТА (подхватывает CLAUDE.md)
    ├─→ JSONL transcript → детекция статуса
    ├─→ Acceptance criteria → done / retry / escalate
    └─→ Telegram: результат
```

> **Этап C (будущее):** Архитектор сам генерирует микроТЗ из бизнес-требования → отправляет в оркестратор.

---

## 1. Субагенты (основной инструмент)

### Что это
Субагент — это отдельный контекст внутри твоей сессии Claude Code. У него свой промт, свои инструменты, своя модель. Сделал работу — вернул результат в основной контекст.

### Встроенные субагенты

| Субагент | Модель | Инструменты | Когда используется |
|----------|--------|-------------|-------------------|
| **Explore** | Haiku (быстро, дёшево) | Только чтение | Поиск по коду, анализ структуры |
| **Plan** | Наследует от lead | Только чтение | Исследование перед планом |
| **General-purpose** | Наследует от lead | Все | Сложные многошаговые задачи |

### Как создать свой субагент

Файл `.claude/agents/my-agent.md`:

```yaml
---
name: my-agent
description: Что делает и когда использовать (Claude решает по описанию)
model: sonnet                    # sonnet, haiku, opus
tools:
  - Read
  - Grep
  - Glob
  - Bash
# model: haiku                   # дешевле и быстрее для простых задач
# allowedTools: Read Grep Glob   # ограничить инструменты
---

Ты — [роль]. Твоя задача — [что делать].

## Алгоритм
1. ...
2. ...

## Формат ответа
...
```

### Области видимости субагентов

| Расположение | Область | Приоритет |
|-------------|---------|:---------:|
| Managed settings | Вся организация | 1 (высший) |
| `--agents` (CLI флаг) | Текущая сессия | 2 |
| `.claude/agents/` | Текущий проект | 3 |
| `~/.claude/agents/` | Все проекты пользователя | 4 |
| Plugin `agents/` | Где плагин включён | 5 |

### Создание через UI

```
/agents → Library → Create new agent → Personal или Project
```

Claude сам сгенерирует промт, инструменты, модель по твоему описанию.

---

## 2. Codex внутри Claude Code

### Codex как субагент

Codex CLI (`@openai/codex`) можно запускать прямо из Claude Code. Есть два способа:

#### Способ 1: Через Bash (простой)

Оркестратор вызывает Codex через терминал:

```bash
codex --approval-mode suggest "Найди и исправь баг в auth.py"
```

#### Способ 2: Через codex-plugin-cc (интеграция)

Установка:
```bash
npm install -g @openai/codex
npx skills add codex-plugin-cc
```

Доступные команды:
| Команда | Что делает |
|---------|-----------|
| `/codex:review` | Ревью кода через Codex |
| `/codex:adversarial-review` | Жёсткое ревью: давление на решения |
| `/codex:rescue` | Передать задачу Codex целиком (как субагент) |

`/codex:rescue` — самое полезное: Claude застрял на баге → запускает Codex → Codex исследует → возвращает результат.

### Codex как субагент-определение

Можно создать `.claude/agents/codex-engineer.md`:

```yaml
---
name: codex-engineer
description: OpenAI Codex engineer для багфиксов, тестов и локальных правок. Использовать когда нужен второй взгляд или Claude застрял.
tools:
  - Bash
  - Read
  - Write
  - Edit
  - Grep
  - Glob
model: sonnet
---

Ты — инженер-исполнитель. Работаешь через Codex CLI.

## Алгоритм
1. Получи задачу от lead-агента
2. Запусти: `codex --approval-mode auto-edit "задача"`
3. Проверь результат
4. Верни отчёт: что сделано, что изменено, какие тесты прошли
```

---

## 3. Agent Teams (экспериментальное)

### Что это
Несколько полноценных сессий Claude Code, работающих параллельно. У каждого свой контекст, свои инструменты. Общаются через shared task list и mailbox.

### Включение
```json
// settings.json
{
  "env": {
    "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1"
  }
}
```

### Запуск команды
```
Создай команду агентов для рефакторинга модуля auth:
- Один на безопасность
- Один на тесты
- Один на производительность
```

### Когда использовать Agent Teams vs Субагенты

| | Субагенты | Agent Teams |
|---|---|---|
| **Общение** | Только с lead | Между собой напрямую |
| **Контекст** | Внутри сессии lead | Каждый — отдельная сессия |
| **Стоимость** | Низкая | Высокая (×N сессий) |
| **Лучше для** | Быстрые задачи, результат важнее процесса | Исследование, дебаты, параллельные гипотезы |
| **Координация** | Lead управляет всем | Shared task list + self-coordination |

### Ограничения (beta)
- Нет восстановления сессий в in-process режиме
- Один тим на сессию
- Нет вложенных команд (teammate не может создать свою команду)
- Split panes требуют tmux или iTerm2

---

## 4. Схема оркестрации для Архитектора

### Как оркестратор распределяет задачи

```
Входящая задача
    │
    ▼
Оркестратор (Claude Code lead)
    │
    ├── Класс A (архитектура) ─────────── Делает сам
    │
    ├── Класс B (инженерная) ─────────── Субагент: codex-engineer
    │                                     или /codex:rescue
    │
    ├── Класс C (прототип/boilerplate) ── Субагент: qwen-executor
    │                                     (через Bash: qwen-code ...)
    │
    ├── Класс D (баги/тесты) ─────────── Субагент: codex-engineer
    │
    └── Класс E (сравнение) ──────────── Agent Team:
                                           - Teammate 1: вариант A
                                           - Teammate 2: вариант B
                                           - Teammate 3: devil's advocate
```

### Контроль исполнения

Оркестратор контролирует через:

1. **Описание субагента** — чёткие границы: что можно, что нельзя
2. **Ограничение инструментов** — `tools: [Read, Grep]` = только чтение
3. **Модель** — Haiku для простых задач (дешевле), Sonnet/Opus для сложных
4. **Definition of Done** — в промте субагента: «верни отчёт в формате...»
5. **Hooks** (для Agent Teams):
   - `TeammateIdle` — что делать когда teammate закончил
   - `TaskCompleted` — проверка перед отметкой "готово"
6. **Plan approval** — teammate планирует → lead одобряет → только потом работает

### Формат ТЗ для субагента

Оркестратор формулирует задачу так:

```markdown
## Задача
[Что сделать — конкретно]

## Контекст
[Какие файлы смотреть, какой модуль]

## Ограничения
[Что НЕ трогать, какие файлы не менять]

## Ожидаемый результат
[Формат: изменённые файлы / отчёт / PR]

## Проверка
[Какие тесты запустить, что считать успехом]
```

---

## 5. Набор субагентов для типового проекта

### Обязательные (создаёт Архитектор при `/generate-project`)

| Субагент | Файл | Модель | Инструменты | Назначение |
|----------|------|--------|-------------|-----------|
| `code-reviewer` | `.claude/agents/code-reviewer.md` | Sonnet | Read, Grep, Glob | Ревью кода перед коммитом |
| `test-runner` | `.claude/agents/test-runner.md` | Haiku | Bash, Read, Grep | Запуск тестов, анализ падений |
| `codex-engineer` | `.claude/agents/codex-engineer.md` | Sonnet | Все | Делегирование задач Codex CLI |

### По необходимости

| Субагент | Когда добавлять |
|----------|----------------|
| `security-auditor` | Проекты с auth, платежами, PII |
| `db-migrator` | Проекты с БД, миграциями |
| `frontend-reviewer` | Проекты с фронтендом |
| `qwen-executor` | Если используется Qwen Code |
| `doc-writer` | Проекты с обязательной документацией |

---

## 6. Быстрая установка

```bash
# 1. Codex CLI
npm install -g @openai/codex

# 2. Codex плагин для Claude Code
npx skills add codex-plugin-cc

# 3. Superpowers (субагентные скилы)
npx superpowers@latest install
# Включает: subagent-driven-development, dispatching-parallel-agents

# 4. Agent Teams (экспериментальное)
# В settings.json:
# "env": { "CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS": "1" }
```

---

## Ссылки

- [Субагенты (офиц. документация)](https://code.claude.com/docs/en/sub-agents)
- [Agent Teams (офиц. документация)](https://code.claude.com/docs/en/agent-teams)
- [Superpowers: subagent-driven-development](https://github.com/obra/superpowers)
- [Codex Plugin для Claude Code](https://github.com/openai/codex-plugin-cc)
- [Managed Agents](https://platform.claude.com/docs/en/managed-agents/overview)
