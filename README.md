# Discord API Security Research Lab

Локальная лаборатория для исследования безопасности Discord API. Проект помогает
проверять собственные приложения и конфигурации: структуру REST API, Gateway,
OAuth2, права доступа и утечки токенов в файлах.

Проект **не** подключается к Discord, **не** использует чужие токены и **не** обходит
ограничения API. Все сетевые проверки идут только на собственный mock-сервер
`127.0.0.1`. Все данные в примерах синтетические.

## Что внутри

| Модуль | Что делает |
| --- | --- |
| Core Engine | общий JSON, модели, конфиг, риски, логи без секретов |
| REST API Analyzer | проверка endpoint: авторизация, rate limit, коды ошибок |
| OAuth2 Analyzer | redirect URI, scopes, PKCE, state, способ аутентификации клиента |
| Permission Analyzer | декодирование битов прав и поиск избыточных разрешений |
| Gateway Analyzer | heartbeat, intents, resume, события, версия протокола |
| Token Leak Detector | локальный поиск Discord Bot Token в ENV/JSON/YAML/PY/JS/TS/TXT |
| Exploit Research Lab | описание сценариев и проверка исправлений на mock-сервере |
| Reporting Engine | отчёты TXT, JSON, Markdown |
| Configuration Manager | загрузка, проверка и создание конфигурации |
| CLI Interface | команды `scan`, `analyze`, `gateway`, `permissions`, `oauth`, `exploit-lab`, `report`, `config`, `version`, `help` |

## Стек

- **Rust 1.77+** — ядро и все анализаторы (`dscore`).
- **Go 1.22+** — параллельный сканер токенов (`dstoken`) и локальный REST/WebSocket
  mock-сервер (`dsmock`).
- **Python 3.12+** — CLI, конфигурация, отчёты, HTTP/WebSocket-клиент, интеграция.

Внешних библиотек нет: только стандартные `std`, `net/http`, `argparse`, `socket`
и другие модули стандартной библиотеки.

## Быстрый старт

```bash
make build
make test
make demo
```

`make demo` сканирует синтетический каталог `examples/corpus`, анализирует
`examples/bundle.json`, поднимает локальный mock и пишет отчёты в `examples/`.

## Примеры команд

```bash
# Поиск утечек токенов и отчёт
PYTHONPATH=python python3 -m dsrlab scan examples/corpus \
  --config configs/default.json --out examples/token-report.md

# Анализ описания API
PYTHONPATH=python python3 -m dsrlab analyze examples/bundle.json \
  --config configs/default.json --out examples/analysis.json

# Только права / только OAuth2
PYTHONPATH=python python3 -m dsrlab permissions examples/bundle.json
PYTHONPATH=python python3 -m dsrlab oauth examples/bundle.json

# Локальный Gateway и лаборатория сценариев
PYTHONPATH=python python3 -m dsrlab gateway --out examples/gateway-trace.json
PYTHONPATH=python python3 -m dsrlab exploit-lab examples/bundle.json --out examples/lab-results.json

# Отчёты и служебные команды
PYTHONPATH=python python3 -m dsrlab report examples/analysis.json --format all --out examples/report
PYTHONPATH=python python3 -m dsrlab config show
PYTHONPATH=python python3 -m dsrlab version
```

Подробности — в [USAGE.md](USAGE.md). Установка — в [INSTALL.md](INSTALL.md).

## Безопасность

- Секреты наружу не уходят: RAW содержит только SHA-256, длину, энтропию и координаты.
- Отчёты и логи содержат маски вида `<discord_bot_token:27:masked>`.
- Mock-сервер слушает только `127.0.0.1` и не делает исходящих запросов.
- Лаборатория воспроизводит сценарии только на локальном mock и проверяет исправления.
- Запрещены кража токенов, захват аккаунтов, обход авторизации и чужие серверы.

## Тесты

```bash
make test
```

Проверяются JSON, конфиг, анализаторы, дедупликация, сортировка, REST, WebSocket,
OAuth2, сценарии лаборатории, отчёты, маскирование и производительность сканера.

## Документация

- [SPEC.md](SPEC.md) — контракты модулей и форматы данных.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — архитектура и выбор стека.
- [docs/EXAMPLE_REPORT.md](docs/EXAMPLE_REPORT.md) — пример отчёта на синтетических данных.
- [USAGE.md](USAGE.md) — запуск и настройка.
