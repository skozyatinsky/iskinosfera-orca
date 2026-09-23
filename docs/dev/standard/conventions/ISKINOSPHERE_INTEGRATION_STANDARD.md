# Стандарт интеграции с Искиносферой

> Единый протокол подключения любого проекта Архитектора к **серверу
> управления Искиносферы** (hub).
>
> Читается при генерации проекта, если проект должен:
> - быть видим в панели управления Искиносферы,
> - принимать удалённые команды,
> - отправлять телеметрию/статус,
> - или сообщать о лицензионных событиях.
>
> Цель: подключить новый сервис за **5 минут** — скопировать
> `src/<package>/plugins/iskinosphere_client/`, заполнить `configs/iskinosphere.yaml`,
> выставить env `ISKINOSPHERE_TOKEN` → готово.

---

## 1. Модель отношений

```
┌─────────────────────────┐        ┌───────────────────────────┐
│  Iskinosphere Hub       │◄──────►│  Проект (сервис / агент)  │
│  (сервер управления)    │  HTTPS │  src/<package>/plugins/   │
│                         │  +mTLS │        client/            │
└─────────────────────────┘        └───────────────────────────┘
         ▲                                      │
         │ heartbeat, events, telemetry         │
         └──────────────────────────────────────┘
         ▼
      commands (control plane): restart, update_config,
      pause, resume, run_task, rotate_license, …
```

**Роли:**
- **Hub** — источник правды о составе парка проектов, центральная панель,
  команды оператору, сбор телеметрии.
- **Project** — клиент. Сам регистрируется, шлёт heartbeat, принимает команды.

**Hub никогда не ходит в проект первым.** Все соединения инициирует
проект (`outbound-only`). Это снимает требование публичного IP с проектов
и упрощает firewall-политику.

---

## 2. Модель подключения

Два транспорта — выбирается при регистрации:

| Транспорт | Когда | Протокол |
|---|---|---|
| **Long-polling** | default, дешёвый, работает через любой firewall | HTTPS: `POST /api/v1/poll` с long-timeout |
| **WebSocket** | для низкой задержки команд (> 1/сек) | `wss://hub/api/v1/ws` с bearer-токеном |

Оба дают одинаковый логический контракт (§4). Проект не знает, какой
транспорт у него — это детерминируется конфигом hub'а.

---

## 3. Идентификация и аутентификация

### 3.1. Регистрация (onboarding — один раз)

1. Оператор в панели Hub создаёт запись о проекте → получает
   **registration token** (короткоживущий, 24h).
2. Этот токен попадает в проект через:
   - env `ISKINOSPHERE_REGISTRATION_TOKEN` (предпочтительно, one-shot), **или**
   - `configs/iskinosphere.yaml: registration_token:` (если автоматизация CI).
3. При первом старте клиент делает:
   ```
   POST /api/v1/register
   Body: {
     "registration_token": "...",
     "project_name": "...",
     "version": "...",
     "machine_fingerprint": "..."   # см. LICENSE_HUB_PATTERN
   }
   Response: {
     "project_id": "uuid",
     "access_token": "long-lived JWT",
     "refresh_token": "...",
     "ca_cert": "PEM"              # для mTLS, если включен
   }
   ```
4. Клиент сохраняет `access_token` + `refresh_token` в
   `data/iskinosphere/credentials.enc` (шифровка по `machine_fingerprint`),
   **удаляет** `registration_token` из конфига и env.
5. `registration_token` на Hub'е помечается использованным.

### 3.2. Работа (каждая сессия)

- Все запросы содержат `Authorization: Bearer <access_token>`.
- При `401` клиент делает `POST /api/v1/token/refresh` с `refresh_token`.
- При `403 permanent` — клиент переходит в режим «деградации»
  (см. §7), уведомляет оператора через локальный канал (Telegram-bot,
  лог, Doctor), **не ломает основную функциональность**.

### 3.3. mTLS (опционально, для appliance-поставок)

- Hub выдаёт клиенту сертификат при регистрации (`ca_cert` в ответе +
  клиентский серт через отдельный эндпоинт `/api/v1/cert/issue`).
- Ротация — автоматически через `/api/v1/cert/renew` за 30 дней до
  истечения.

---

## 4. Логический контракт

Все эндпоинты относительно `https://{hub_url}/api/v1/`.

### 4.1. Heartbeat (клиент → hub)

```
POST /heartbeat
Headers: Authorization: Bearer <token>
Body: {
  "project_id": "uuid",
  "timestamp": "2026-04-18T12:00:00Z",
  "status": "ok" | "degraded" | "error",
  "version": "x.y.z",
  "uptime_sec": 12345,
  "load": { "cpu": 0.12, "mem_mb": 512, "active_tasks": 3 },
  "flags": {
    "license_valid": true,
    "dry_run": false,
    "security_verdict": "PASS" | "BLOCKED" | "PASS-WITH-WAIVERS" | "unknown",
    "security_reviewed_at": "2026-06-24T10:00:00Z",
    "security_stale": false          # true, если последняя проверка старше порога (см. §11)
  }
}
Response: {
  "commands": [ ... ],            # pending команды, см. §4.3
  "next_heartbeat_sec": 60,
  "config_version": "sha256:..."  # если изменился — клиент делает GET /config
}
```

**Частота:** default 60 сек. Hub может менять через `next_heartbeat_sec`.

### 4.2. Health-check (hub → клиент, опц)

Если клиент поддерживает inbound (редко):
```
GET /healthz → 200 OK
GET /readyz  → 200 OK / 503
```

Обычно здоровье определяется по heartbeat, inbound не требуется.

### 4.3. Команды (hub → клиент через ответ на heartbeat/poll)

```json
{
  "command_id": "uuid",
  "type": "restart" | "update_config" | "pause" | "resume"
        | "run_task" | "rotate_license" | "fetch_logs"
        | "security_review" | "custom",
  "params": { ... },
  "issued_at": "...",
  "expires_at": "...",
  "ack_required": true
}
```

**Гарантия:** клиент отвечает на команду в течение
`expires_at - issued_at` (default 5 мин):

```
POST /commands/{command_id}/ack
Body: { "status": "accepted" | "rejected" | "done" | "failed",
        "result": {...},
        "error": "..." }
```

Без ack — Hub помечает команду stale, повторяет на следующем heartbeat
до 3 раз, потом — эскалация оператору.

### 4.4. Конфиг (pull-модель)

```
GET /config
Response: {
  "version": "sha256:...",
  "body": { ... }                 # валидируется через src/<package>/models/config_schema.py
}
```

Клиент применяет конфиг через `src/<package>/models/config_schema.py` (FAIL-FAST:
невалидный конфиг → отказ, не silent fallback). Старый конфиг
остаётся активным при провале валидации.

### 4.5. Телеметрия и события

```
POST /events
Body: {
  "events": [
    { "type": "task_completed", "ts": "...", "payload": {...} },
    { "type": "license_warning", "ts": "...", "payload": {...} },
    { "type": "security_review", "ts": "...", "payload": {   # см. §11
        "verdict": "BLOCKED", "scope": "full",
        "counts": { "critical": 0, "high": 4, "medium": 5, "low": 5, "info": 2 },
        "top_findings": [ { "level": "high", "domain": 7, "title": "MCP без аутентификации" } ],
        "report_path": "docs/Audit/security_review_2026-06-24.md" } },
    { "type": "error", "ts": "...", "payload": {...} }
  ]
}
```

Батчится: default 100 событий или 10 сек.

### 4.6. Логи (pull по команде `fetch_logs`)

Не push — только pull по явному запросу Hub'а. Иначе канал захлёбывается.

---

## 5. Клиентский модуль (канонический путь)

```
src/<package>/plugins/iskinosphere_client/
├── README.md                   # как подключить к проекту
├── __init__.py
├── client.py                   # HTTP+WS реализация
├── commands.py                 # диспатчер входящих команд
├── heartbeat.py                # фоновая задача heartbeat
├── events.py                   # батч-отправка событий
├── config_sync.py              # pull конфига + валидация
├── schema.py                   # pydantic-модели запросов/ответов
└── registration.py             # one-shot регистрация
```

Интеграция с проектом:
- `src/<package>/app/main.py` — один `await iskinosphere_client.start()` при bootstrap.
- `src/<package>/models/config_schema.py` — блок `iskinosphere:` (см. §6).
- `src/<package>/utils/doctor.py` — проверка связи с Hub (`IskinosphereDoctorCheck`).

---

## 6. Конфигурация

`configs/iskinosphere.yaml`:

```yaml
iskinosphere:
  enabled: true
  hub_url: https://hub.iskinosphere.com
  transport: long-polling        # long-polling | websocket
  heartbeat_interval_sec: 60
  mtls: false                    # включается Hub'ом при onboarding
  events:
    batch_size: 100
    flush_interval_sec: 10
  degraded_mode:
    max_offline_hours: 24        # после этого проект входит в read-only
    on_license_invalid: block    # block | degrade | continue
```

`registration_token` и `access_token` **никогда** не в yaml — только env
или зашифрованный `data/iskinosphere/credentials.enc`.

---

## 7. Деградация и автономность

**Инвариант:** проект должен работать, когда Hub недоступен. Hub —
панель управления, не критичная зависимость.

| Состояние | Поведение клиента |
|---|---|
| Hub недоступен < `max_offline_hours` | Работа штатно, events буферизуются локально |
| Hub недоступен ≥ `max_offline_hours` | Режим `degraded`: отключаются фичи, помеченные `requires_hub: true` в feature-map |
| Лицензия недействительна | По `on_license_invalid`: `block` (стоп), `degrade` (read-only), `continue` (warning + работа) |

Feature-to-entitlement map — в
`_library/delivery/DELIVERY_ARCHITECTURE_CHECKLIST.md#feature-to-entitlement-map`.

---

## 8. Безопасность

1. **Секреты никогда в коде/git.** Только env или зашифрованное хранилище.
2. **Токены привязаны к `machine_fingerprint`.** Скопировать на другой
   сервер без re-activation нельзя.
3. **Логи не содержат токены.** Маскирование — в `src/<package>/plugins/iskinosphere_client/client.py`
   на уровне httpx-logging-hook.
4. **`registration_token` — одноразовый.** После успешной регистрации —
   удаляется из env и конфига.
5. **mTLS для appliance:** сертификаты ротируются автоматически.
6. **Audit trail:** все входящие команды пишутся в `logs/iskinosphere_audit.log`
   с timestamp + command_id + результат. Этот лог не удаляется скриптами
   очистки.

---

## 9. Тестирование

Обязательные контракт-тесты в проекте (`tests/contract/iskinosphere/`):

1. `test_registration.py` — успех + отказ (token expired, token reused)
2. `test_heartbeat.py` — корректный payload, обработка commands
3. `test_command_dispatch.py` — каждый тип команды → корректный ack
4. `test_degraded_mode.py` — Hub down → работа штатно < N часов
5. `test_config_sync.py` — невалидный конфиг не применяется

Mock-Hub для локальной разработки:
`_library/agent_configs/examples/iskinosphere_mock_hub/` (TODO — отдельная задача).

---

## 10. Чек-лист подключения проекта

- [ ] `src/<package>/plugins/iskinosphere_client/` скопирован в проект
- [ ] `configs/iskinosphere.yaml` создан, `hub_url` заполнен
- [ ] `src/<package>/models/config_schema.py` содержит блок `IskinosphereConfig`
- [ ] `src/<package>/app/main.py` запускает `iskinosphere_client.start()`
- [ ] `src/<package>/utils/doctor.py` включает `IskinosphereDoctorCheck`
- [ ] В панели Hub создан проект, получен `registration_token`
- [ ] Первый старт прошёл: project_id выдан, heartbeat виден в панели
- [ ] `registration_token` удалён из env
- [ ] Контракт-тесты прогнаны

---

## 11. Управляемая проверка ИБ (профиль ИБ-специалиста)

ИБ-специалист (`SECURITY_STANDARD.md` + `AGENTS_SECURITY.md` + скил
`/security-review`) — не локальная самодеятельность проекта, а **управляемая
из Hub возможность**. Hub видит безопасность всего парка, запускает проверки
удалённо и не даёт релизить проект с непройденным гейтом.

### 11.1. Что добавляет профиль ИБ к протоколу

| Канал | Что несёт |
|-------|-----------|
| Heartbeat `flags.security_*` (§4.1) | Текущий вердикт, дата последней проверки, признак устаревания. Hub рисует столбец «ИБ» в панели парка |
| Команда `security_review` (§4.3) | Hub приказывает проекту прогнать `/security-review` |
| Событие `security_review` (§4.5) | Проект сам шлёт результат после каждой проверки (по команде или по расписанию) |

### 11.2. Команда `security_review`

```json
{
  "command_id": "uuid",
  "type": "security_review",
  "params": {
    "scope": "diff" | "full",       // default diff; "full" — весь проект
    "ref": "main",                  // база для diff (optional)
    "fix": false                    // Hub НЕ инициирует авто-правки по умолчанию
  },
  "ack_required": true
}
```

Диспатчер команд проекта (`plugins/iskinosphere_client/commands.py`) запускает
скил `/security-review` и отвечает ack:

```json
POST /commands/{command_id}/ack
{
  "status": "done" | "failed",
  "result": {
    "verdict": "PASS" | "BLOCKED" | "PASS-WITH-WAIVERS",
    "counts": { "critical": 0, "high": 0, "medium": 2, "low": 3, "info": 1 },
    "report_path": "docs/Отчеты/security_review_<дата>.md",
    "gate": "pass" | "blocked"
  }
}
```

После проверки проект дублирует итог событием `security_review` (§4.5) —
чтобы Hub зафиксировал результат, даже если ack потерялся.

### 11.3. Парковая сводка и гейт на релиз

Hub агрегирует вердикты по всем проектам в **карту безопасности парка**:

- 🔴 хотя бы один проект `BLOCKED` → виден оператору как требующий внимания;
- ⚠️ `security_stale: true` → проверка устарела, Hub планирует новую;
- ✅ все `PASS` → парк здоров.

**Гейт на релиз (ключевой инвариант):** пока последний вердикт проекта —
`BLOCKED`, Hub **отказывается выдавать команды поставки/деплоя** для этого
проекта (`run_task: deploy`, связка с `/deploy-module` и
`/audit-delivery-bundle`). Релиз разблокируется, когда вердикт стал `PASS`
или `PASS-WITH-WAIVERS` с оформленными исключениями.

### 11.4. Периодические проверки парка

Hub может ставить `security_review` на расписание (например, еженедельно для
всего парка или после каждого `task_completed` сборки). Так гейт не
обходится «один раз прошли и забыли»: устаревший вердикт помечается
`security_stale` и требует повторного прогона.

### 11.5. Граница: гейт релиза, не убийца рантайма

Профиль ИБ **не нарушает инвариант автономности (§7)**. `BLOCKED` не
останавливает уже работающий сервис и не переводит его в degraded — это
**гейт поставки**, а не runtime-kill. Hub блокирует *выпуск новой версии*,
но не *работу текущей*. Реальное реагирование на инцидент ИБ в рантайме —
отдельная команда оператора (`pause`/`restart`), осознанное действие, а не
автоматическое следствие находки.

### 11.6. Клиентский модуль и Doctor

- `plugins/iskinosphere_client/commands.py` — хендлер `security_review`.
- `utils/doctor.py` — `SecurityReviewDoctorCheck`: помечает проблему, если
  последняя проверка `BLOCKED` или старше порога. Включается в общий Doctor.
- Аудит: входящая команда `security_review` пишется в
  `logs/iskinosphere_audit.log` (§8.6), как любая команда Hub.

### 11.7. Безопасность самого канала

- Отчёты ИБ могут содержать чувствительные детали (пути, фрагменты находок).
  В событие `security_review` идут **counts + заголовки + путь к отчёту**,
  не полные тела находок. Полный отчёт остаётся в проекте (`docs/Отчеты/`),
  Hub тянет его только по явной команде `fetch_logs`/`fetch_report`.
- Вердикт и counts — не секрет, но `top_findings` не должны раскрывать
  эксплойт целиком в телеметрии.

---

## 12. Версия стандарта

- **v1.1** (2026-06-24) — добавлен профиль ИБ как управляемая возможность:
  команда `security_review`, событие `security_review`, флаги
  `flags.security_*` в heartbeat, парковая карта безопасности и гейт на релиз
  (§11). Обратная совместимость с v1.0 сохранена — поля опциональны.
- **v1.0** (2026-04-18) — первая редакция. Long-polling + WS,
  heartbeat/commands/config/events, опциональный mTLS.

При breaking-change стандарта — новая мажорная версия + ADR в
`docs/memory/decisions/`, старые проекты продолжают работать по своей версии.

---

## Связанные документы

- `_library/prompts/development/SERVER_CONTROL_ARCHITECTURE.md` — архитектура серверного управления через Telegram (комплементарно, не замещает)
- `_library/prompts/development/LICENSE_HUB_PATTERN.md` — лицензирование (комплементарно, использует тот же `machine_fingerprint`)
- `_library/delivery/DELIVERY_ARCHITECTURE_CHECKLIST.md` — если проект поставляется клиенту
- `_library/agent_configs/global/FILE_AND_FOLDER_STANDARD.md` — куда класть клиентский модуль
