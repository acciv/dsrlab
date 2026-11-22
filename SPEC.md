# Discord API Security Research Lab — контракты модулей

## Общие правила

Проект работает локально. Он не делает запросов к Discord, не использует чужие токены,
не обходит авторизацию, не обходит rate limits и не получает доступ к чужим аккаунтам.
Все сетевые проверки идут только на собственный mock-сервер `127.0.0.1`.

Все тестовые значения синтетические: Discord ID из диапазона `100000000000000000`,
секреты содержат `DUMMY`, `FAKE` или `EXAMPLE`. Реальные токены в коде, тестах и примерах
запрещены.

Принцип маскирования: наружу уходит только SHA-256 отпечаток, длина, энтропия, файл
и номер строки. Полное значение секрета не попадает ни в RAW, ни в ANALYZED, ни в отчёты,
ни в логи.

## Стек

- Rust 1.77+ — Core Engine: JSON, модель, REST/OAuth2/Permission/Gateway/Lab анализаторы,
  риски, статистика, логирование, CLI `dscore`.
- Go 1.22+ — `dstoken` (параллельный локальный сканер токенов) и `dsmock` (локальный
  REST + WebSocket mock-сервер).
- Python 3.12+ — CLI Interface, Config Manager, Report Generator, mock-клиент, интеграция.

Внешних зависимостей нет: только std Rust, std Go и std Python.

## Структура потоков

```
CLI (Python)
  scan PATH        -> Go dstoken -> TOKEN_RAW.json -> Rust dscore analyze-tokens -> TOKEN_ANALYSIS.json
  analyze BUNDLE   -> Rust dscore analyze -> ANALYSIS.json
  gateway          -> Go dsmock + Python WebSocket-клиент -> GATEWAY_TRACE.json
  permissions      -> Rust dscore analyze -> decode permission bits
  oauth            -> Rust dscore analyze -> oauth findings
  exploit-lab      -> Go dsmock + Python HTTP-клиент -> LAB_RESULTS.json -> Rust analyze
  report           -> TXT / JSON / Markdown из ANALYSIS.json
```

## Входной BUNDLE.json

```json
{
  "version": "1.0",
  "endpoints": [
    {"method":"GET","path":"/users/@me","auth":"bearer","rate_limit":"per-route",
     "scopes":["identify"],"errors":[401,403],"description":"текущий пользователь"}
  ],
  "oauth": {
    "client_id":"100000000000000001",
    "redirect_uris":["http://localhost:8080/callback"],
    "scopes":["identify","email"],
    "pkce":true,
    "state":true,
    "token_endpoint_auth_method":"client_secret_basic"
  },
  "permissions": [
    {"role":"reader","bits":1024,"scope":"guild"},
    {"role":"bot","bits":8,"scope":"guild"}
  ],
  "gateway": {
    "version":10,
    "heartbeat_interval":41250,
    "intents":["GUILDS","GUILD_MESSAGES"],
    "events":["READY","MESSAGE_CREATE"],
    "reconnect":"exponential-backoff",
    "resume":true
  },
  "scenarios": [
    {"id":"ratelimit-001","type":"rate_limit","title":"Ответ 429 без Retry-After",
     "endpoint":"/users/@me","mock_response":429,"expected":"Retry-After обработан",
     "fix_check":"заголовок Retry-After присутствует","impact":"medium","fixed":false}
  ]
}
```

## RAW токен-сканера (выход Go `dstoken`)

```json
{
  "scanned_files": 3,
  "skipped_files": 0,
  "findings": [
    {"file":"config.py","line":4,"column":9,"fingerprint":"sha256:ab12...",
     "id_length":18,"timestamp_length":6,"secret_length":27,"entropy":4.12,
     "context":"bot_token","false_positive":false}
  ]
}
```

Полного значения в RAW нет. Поля строго эти. `findings` сортируются по `file`, `line`,
`column`. Пустой массив пишется `[]`.

## Выход Rust `ANALYSIS.json`

```json
{
  "version": "1.0",
  "summary": {
    "endpoints": 1, "scenarios": 1, "findings": 4,
    "by_module": {"rest":1,"oauth":2,"gateway":0,"permissions":1,"lab":0},
    "by_severity": {"critical":0,"high":1,"medium":2,"low":1}
  },
  "findings": [
    {"module":"oauth","id":"oauth-pkce-disabled","title":"PKCE отключён",
     "severity":"medium","evidence":"pkce=false","recommendation":"Включить PKCE"}
  ],
  "permission_bits": [
    {"role":"bot","bits":8,"names":["ADMINISTRATOR"],"excessive":true}
  ],
  "scenario_results": [
    {"id":"ratelimit-001","status":"reproduced","severity":"medium","notes":"mock 429"}
  ]
}
```

## Правила анализа (Rust, детерминированные)

### REST
- endpoint без `rate_limit` → `rest-rate-limit-missing`, medium;
- `auth == "none"` для пути вне публичного списка (`/gateway`, `/oauth2/token`) →
  `rest-auth-missing`, high;
- `auth != "none"` и в `errors` нет `401` → `rest-401-not-documented`, low;
- `method == "POST"` и пустой `errors` → `rest-errors-not-documented`, low.

### OAuth2
- redirect URI содержит `*` или `http://` и не является `localhost` / `127.0.0.1` →
  `oauth-redirect-insecure`, high;
- scopes содержат любой из `guilds.join`, `webhook.incoming`,
  `applications.commands.update` → `oauth-dangerous-scope`, high;
- `pkce == false` → `oauth-pkce-disabled`, medium;
- `state == false` → `oauth-state-disabled`, medium;
- `token_endpoint_auth_method == "none"` → `oauth-token-auth-none`, high.

### Permissions
Таблица битов (имя → бит): CREATE_INSTANT_INVITE 0, KICK_MEMBERS 1, BAN_MEMBERS 2,
ADMINISTRATOR 3, MANAGE_CHANNELS 4, MANAGE_GUILD 5, ADD_REACTIONS 6, VIEW_AUDIT_LOG 7,
VIEW_CHANNEL 10, SEND_MESSAGES 11, MANAGE_MESSAGES 13, MENTION_EVERYONE 17,
CONNECT 20, SPEAK 21, MANAGE_NICKNAMES 27, MANAGE_ROLES 28, MANAGE_WEBHOOKS 29,
USE_APPLICATION_COMMANDS 31, MANAGE_THREADS 34, MODERATE_MEMBERS 40,
SEND_VOICE_MESSAGES 46, SEND_POLLS 49.
Опасные: ADMINISTRATOR, BAN_MEMBERS, KICK_MEMBERS, MANAGE_GUILD, MANAGE_CHANNELS,
MANAGE_ROLES, MANAGE_WEBHOOKS, MANAGE_MESSAGES.
- ADMINISTRATOR → `perm-admin-granted`, critical;
- любой другой опасный бит → `perm-excessive`, high;
- `scope == "global"` и опасный бит → additional `perm-global-scope`, medium.

### Gateway
- `heartbeat_interval` вне 1000..60000 → `gateway-heartbeat-range`, medium;
- `resume == false` → `gateway-resume-disabled`, low;
- в `events` нет `READY` → `gateway-ready-missing`, low;
- `intents` пуст → `gateway-intents-empty`, low;
- `version < 10` → `gateway-old-version`, low.

### Exploit Lab
- сценарий без `id`, `type`, `endpoint` или `fix_check` → `lab-invalid-scenario`, low;
- `fixed == true` → статус `fixed`; иначе `reproduced` (только симуляция на mock);
- `severity` сценария по умолчанию `medium`, допустимые значения `low/medium/high/critical`.

Findings сортируются по убыванию тяжести (`critical, high, medium, low`), затем по `id`.
`by_module` и `by_severity` — детерминированные отсортированные объекты, все ключи
присутствуют даже с нулями.

## Контракт Rust `dscore`

Модули в `rust/crates/core/src/`: `json.rs`, `model.rs`, `config.rs`, `mask.rs`,
`logging.rs`, `risk.rs`, `rest.rs`, `oauth.rs`, `permissions.rs`, `gateway.rs`,
`lab.rs`, `tokens.rs`, `analyzer.rs`, `lib.rs`, `main.rs`.

Публичный фасад:
- `analyze_json(bundle_json: &str, config_json: &str) -> Result<String,String>`
- `analyze_tokens_json(raw_json: &str, config_json: &str) -> Result<String,String>`
- `validate_config_json(config_json: &str) -> Result<(),String>`
- `version() -> &'static str` = `dscore 1.0.0`

CLI:
```
dscore analyze <bundle.json> <config.json>
dscore analyze-tokens <token_raw.json> <config.json>
dscore validate-config <config.json>
dscore version
dscore help
```

Минимум 12 тестов: JSON, конфиг, маски, REST, OAuth2, permission bits, gateway,
lab, token analysis, дедупликация, логи без секретов, сортировка findings.

## Контракт Go

### `dstoken`
```
dstoken --path DIR --config CONFIG --out TOKEN_RAW.json
```
Правила: Discord Bot Token вида `<17-20 цифр>.<6 символов>.<27 символов>`, graceful
детекция ENV/JSON/YAML/PY/JS/TS/TXT, границы, SHA-256 отпечаток, энтропия, маркеры
`DUMMY/FAKE/EXAMPLE/SAMPLE/REDACTED/PLACEHOLDER` → false positive. Параллельный обход,
limits из конфига, детерминированная сортировка. В выводе нет секретов.

### `dsmock`
```
dsmock --port 0 --config CONFIG
```
Привязка только к `127.0.0.1`. Первой строкой stdout печатает `PORT:<number>`, затем
работает до SIGINT/SIGTERM. Endpoints:
- `GET /api/v10/gateway` → `{"url":"ws://127.0.0.1:<port>/gateway","shards":1}`
- `GET /api/v10/users/@me` → синтетический JSON пользователя `DUMMY_USER`
- `GET /api/v10/guilds/100000000000000002` → синтетический guild JSON
- `POST /api/v10/channels/100000000000000003/messages` → 201 с синтетическим message JSON
- `GET /api/v10/rate-limited` → 429 + `Retry-After: 1` + `X-RateLimit-*` headers
- `POST /api/v10/oauth2/token` → синтетический OAuth2 ответ с `DUMMY_ACCESS_TOKEN`
- `POST /api/v10/webhooks/100000000000000004/DUMMYWEBHOOK` → 204
- `GET /api/v10/forbidden` → 403 JSON
- `GET /health` → `{"ok":true}`
- WebSocket `/gateway`: handshake, `HELLO` op 10, ждёт `IDENTIFY` op 2, шлёт `READY`
  op 0, отвечает на `HEARTBEAT` op 1 → `HEARTBEAT_ACK` op 11, шлёт `MESSAGE_CREATE`
  op 0 с синтетическим сообщением, опционально `RECONNECT` op 7.

Любой запрос с заголовком `Authorization` логируется только как `[REDACTED]`.
Никаких запросов наружу. Минимум 8 тестов Go: REST endpoints, 429 headers, OAuth mock,
webhook, forbidden, WebSocket handshake/events/heartbeat, token scanner типы/границы/
false positives/большая директория, запись RAW.

## Контракт Python

Пакет `dsrlab`: `cli.py`, `config.py`, `report.py`, `integration.py`, `logging.py`,
`mockclient.py`, `__main__.py`.

CLI команды: `scan`, `analyze`, `gateway`, `permissions`, `oauth`, `exploit-lab`,
`report`, `config`, `version`, `help`.

- `scan PATH [--config] [--out]` — dstoken + analyze-tokens + отчёт.
- `analyze BUNDLE [--config] [--out]` — dscore analyze.
- `gateway [--port] [--out]` — поднять dsmock, подключиться WebSocket вручную
  (socket + base64 key, без внешних библиотек), собрать `GATEWAY_TRACE.json`:
  `connected`, `ops`, `events`, `heartbeat_acks`, `disconnected`.
- `permissions BUNDLE` / `oauth BUNDLE` — печать соответствующих finding-ов из ANALYSIS.
- `exploit-lab BUNDLE [--config] [--out]` — поднять dsmock, для каждого сценария сделать
  локальный HTTP-запрос к mock endpoint, сверить код ответа/заголовки с `expected`,
  записать `LAB_RESULTS.json`, затем вызвать dscore analyze и напечатать сводку.
- `report ANALYSIS [--format txt|json|md|all] [--out]`
- `config show|init|validate [--path]`
- `version`, `help`.

Отчёты содержат заголовок, сводку, статистику по модулям и тяжести, таблицу findings,
раздел permission bits, раздел сценариев лаборатории, рекомендации и пометку, что данные
синтетические. Ни одного полного секрета.

Минимум 14 unittest-тестов: CLI, config, отчёты, маскирование, отсутствие секретов,
поиск бинарников, REST mock, WebSocket mock, OAuth mock, permission decode, сценарии
лаборатории, интеграция (skip если бинарников нет), версия/help.

## Тестовые данные

`examples/corpus/` — ENV/JSON/YAML/PY/JS/TS/TXT с синтетическими Discord-токенами
(префикс `DUMMY`) и отдельный файл ложных срабатываний.
`examples/bundle.json` — вход для analyze/permissions/oauth/lab.

## Документация

`README.md`, `INSTALL.md`, `USAGE.md`, `docs/ARCHITECTURE.md`, `docs/EXAMPLE_REPORT.md`,
`SPEC.md`.

## Запрещено

- запросы к discord.com и любым внешним адресам;
- реальные токены и чужие аккаунты;
- brute force, обход авторизации и rate limits;
- кража токенов, захват серверов;
- TODO и заглушки вместо реализации.
