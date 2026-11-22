# Использование

Все команды запускаются из корня проекта после `make build`.

## scan — поиск утечек Discord Bot Token

```bash
PYTHONPATH=python python3 -m dsrlab scan examples/corpus \
  --config configs/default.json --out examples/token-report.md
```

Сканер `dstoken` обходит каталог параллельно, находит токены вида
`<17-20 цифр>.<6 символов>.<27 символов>` и пишет `token-raw.json` с отпечатками
SHA-256, длиной, энтропией и координатами. Ядро `dscore` оценивает риск, находит
дубликаты и собирает группы. Python сохраняет Markdown-отчёт в `--out`
(по умолчанию `token-report.md`).

Поддерживаются `.env`, `.json`, `.yaml`, `.yml`, `.py`, `.js`, `.ts`, `.txt`.
Маркеры `DUMMY`, `FAKE`, `EXAMPLE`, `SAMPLE`, `REDACTED`, `PLACEHOLDER`, `TESTKEY`
помечают находку как ложное срабатывание.

## analyze — анализ описания API

```bash
PYTHONPATH=python python3 -m dsrlab analyze examples/bundle.json \
  --config configs/default.json --out examples/analysis.json
```

Напрямую через ядро:

```bash
target/debug/dscore analyze examples/bundle.json configs/default.json > examples/analysis.json
```

## permissions и oauth

```bash
PYTHONPATH=python python3 -m dsrlab permissions examples/bundle.json
PYTHONPATH=python python3 -m dsrlab oauth examples/bundle.json
```

Команды показывают только находки соответствующего модуля. Биты прав
декодируются по таблице Discord; права `ADMINISTRATOR`, `BAN_MEMBERS`,
`MANAGE_ROLES`, `MANAGE_WEBHOOKS` и другие считаются избыточными.

## gateway — локальный WebSocket

```bash
PYTHONPATH=python python3 -m dsrlab gateway --out examples/gateway-trace.json
```

Поднимается `dsmock` на `127.0.0.1`, клиент подключается к `/gateway`, получает
`HELLO`, отправляет `IDENTIFY`, принимает `READY` и `MESSAGE_CREATE`, отправляет
`HEARTBEAT` и ждёт `HEARTBEAT_ACK`. Результат — JSON со списком op-кодов, событий
и числом подтверждений. Сервер закрывается автоматически.

## exploit-lab — сценарии и проверка исправлений

```bash
PYTHONPATH=python python3 -m dsrlab exploit-lab examples/bundle.json \
  --config configs/default.json --out examples/lab-results.json
```

Каждый сценарий из `scenarios` выполняется только на локальном mock-сервере.
Проверяется код ответа, заголовок `Retry-After` для 429 и поле `fixed`.
Результаты пишутся в `LAB_RESULTS.json`, затем запускается обычный анализ bundle.

Пример сценария:

```json
{
  "id": "ratelimit-001",
  "type": "rate_limit",
  "title": "Ответ 429 без Retry-After",
  "endpoint": "/api/v10/rate-limited",
  "mock_response": 429,
  "expected": "Retry-After и код 429",
  "fix_check": "заголовок присутствует",
  "impact": "medium",
  "fixed": false
}
```

## report — отчёты

```bash
PYTHONPATH=python python3 -m dsrlab report examples/analysis.json --format all --out examples/report
PYTHONPATH=python python3 -m dsrlab report examples/analysis.json --format md --out report.md
```

Форматы: `txt`, `json`, `md`, `all`. Во всех форматах секреты заменены масками.

## config и служебные команды

```bash
PYTHONPATH=python python3 -m dsrlab config show
PYTHONPATH=python python3 -m dsrlab config init --path my-config.json
PYTHONPATH=python python3 -m dsrlab config validate --path configs/default.json
PYTHONPATH=python python3 -m dsrlab version
PYTHONPATH=python python3 -m dsrlab help
```

Основные поля `configs/default.json`: лимиты файлов и строк, число воркеров,
исключённые каталоги и расширения, regex-паттерны, маркеры ложных срабатываний,
пороги риска, публичные пути, опасные scopes и права, параметры Gateway.

## Что нельзя делать

- отправлять найденные значения куда-либо внешним сервисам;
- использовать реальные или чужие токены;
- делать запросы к Discord и обходить ограничения API;
- проверять чужие серверы и аккаунты.
