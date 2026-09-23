# PROJECT_SNAPSHOT.md — iskinosfera-orca

> Машинная карта проекта.
> Обновление: 2026-09-23 (onboarding к agent_project_standard v3.1.3 baseline)

---

## Идентификация

| Поле | Значение |
|------|----------|
| project_id | iskinosfera_orca |
| Название | iskinosfera-orca |
| Статус | active |
| Язык документации | mixed |
| Директория ТЗ | docs/specs |

## Описание

Десктопная среда разработки и клиент параллельной агентной разработки Искиносферы.
Форк проекта `stablyai/orca` (TypeScript, React, Electron).

## Точки входа

| Тип | Команда | Назначение |
|-----|---------|------------|
| CLI | `pnpm run dev` | Запуск dev-окружения |
| CLI | `python docs/dev/standard/tools/validate_structure.py --root . --profile target-project --check-paths --check-registry --check-schemas --check-project-snapshot` | Проверка стандарта |
