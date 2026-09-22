# kosatka

Ответвление (fork) [Orca](https://github.com/stablyai/orca) — агентной IDE для
параллельной работы с AI-агентами. Лицензия MIT (см. [LICENSE](LICENSE)).

## Происхождение

| Параметр | Значение |
|---|---|
| Исходный проект | [stablyai/orca](https://github.com/stablyai/orca) (MIT) |
| База ответвления | `627cde33d58910b6422b63aacb88d035a3ba0582` |
| Удалённый источник | `upstream` → `git@github.com:stablyai/orca.git` |

## Дельта

### Добавлено

- **Русский язык** — полный каталог `src/renderer/src/i18n/locales/ru.json`
  (11 160 ключей)
- **Турецкий язык** — полный каталог `src/renderer/src/i18n/locales/tr.json`
  (11 160 ключей)
- **Мобильная «Косатка»** — локализация React Native-приложения (`mobile/`):
  русский и турецкий интерфейсы, видимое имя «Косатка»
- **i18n-инфраструктура** — `mobile/src/i18n/` (i18next + expo-localization)

### Изменено

- Отключена телеметрия (PostHog): `TELEMETRY_ENABLED = false`
- Обновлённые ссылки автообновлений: `github.com/skozyatinsky/kosatka`
- Конфигурация сборки: `electron-builder.config.cjs`, `dev-app-update.yml`

### Не изменено

- `orca://` схема и протокол сопряжения
- Идентификаторы пакетов (iOS: `com.stably.orca.mobile`, Android: `com.stably.orca.mobile`)
- `appId` десктопного приложения (`com.stablyai.orca`)
- `productName` десктопного приложения (Orca)
- SSH relay (не зависит от stablyai)
- Лицензия MIT

## Обновления из upstream

```bash
git fetch upstream && git rebase upstream/main
```

При конфликтах — разрешить в пользу своего кода (локализация не должна
перезаписываться).