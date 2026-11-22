# Архитектура Discord API Security Research Lab

## Выбор стека

| Слой | Язык | Причина |
| --- | --- | --- |
| Core Engine, REST/OAuth2/permissions/gateway/lab анализаторы | Rust 1.77+ | детерминированные правила, строгие модели, безопасная работа с секретами |
| Token scanner, локальный REST/Gateway mock | Go 1.22+ | горутины для обхода файлов, стандартные `net/http` и WebSocket-фреймы |
| CLI, конфиг, отчёты, mock-клиент, интеграция | Python 3.12+ | удобные команды, быстрые отчёты, простой HTTP/WebSocket-клиент без зависимостей |

C++ и Node.js не используются: они не дают выигрыша в этой задаче и только добавляют дублирование.

## Модули

1. **Core Engine** (`rust/.../lib.rs`) — фасад, JSON, модель, конфиг, риски, логирование.
2. **REST API Analyzer** (`rust/.../rest.rs`) — проверка endpoint-каталога: авторизация,
   rate limit, documented errors.
3. **OAuth2 Analyzer** (`rust/.../oauth.rs`) — redirect URI, scopes, PKCE, state,
   token endpoint auth.
4. **Permission Analyzer** (`rust/.../permissions.rs`) — декодирование битов Discord,
   поиск избыточных прав и global scope.
5. **Gateway Analyzer** (`rust/.../gateway.rs`) — heartbeat, intents, resume, события,
   версия протокола.
6. **Exploit Research Lab** (`rust/.../lab.rs`) — описание сценариев, симуляция на mock,
   проверка исправлений, статусы `reproduced` / `fixed`.
7. **Token Leak Detector** (`go/internal/token`) — локальный поиск Discord Bot Tokens,
   SHA-256 отпечатки и маскирование.
8. **Reporting Engine** (`python/dsrlab/report.py`) — TXT, JSON, Markdown.
9. **Configuration Manager** (`rust/.../config.rs` + `python/dsrlab/config.py`) —
   загрузка, проверка, создание конфига.
10. **CLI Interface** (`python/dsrlab/cli.py`) — все команды из спецификации.
11. **Testing Framework** — тесты Rust, Go, Python,包括 mock HTTP и WebSocket.

## Потоки данных

```
dsrlab scan PATH
  -> Go dstoken  -> TOKEN_RAW.json -> Rust dscore analyze-tokens -> TOKEN_ANALYSIS.json

dsrlab analyze BUNDLE
  -> Rust dscore analyze -> ANALYSIS.json -> Python report

dsrlab gateway
  -> Go dsmock (127.0.0.1) <-> Python WebSocket client -> GATEWAY_TRACE.json

dsrlab exploit-lab BUNDLE
  -> Go dsmock (127.0.0.1) <-> Python HTTP client -> LAB_RESULTS.json
  -> Rust dscore analyze -> ANALYSIS.json
```

Секрет живёт только в памяти Go-сканера во время сопоставления regex. Наружу уходит
SHA-256, длина, энтропия и координаты. Rust и Python не получают полных значений.

## Mock-сервер

`dsmock` слушает только `127.0.0.1`, порт по умолчанию выделяется ОС (`--port 0`).
Он отдаёт синтетические JSON-ответы, 429 с `Retry-After`, 403, OAuth2-ответ и WebSocket
события `HELLO`, `READY`, `MESSAGE_CREATE`, `HEARTBEAT_ACK`. Заголовки `Authorization`
никогда не пишутся в логи.

Лаборатория не выполняет реальную эксплуатацию: она проверяет, что локальный mock
возвращает ожидаемый ответ и что описанное исправление меняет результат.

## Точки расширения

- новый endpoint-проверка: функция в `rest.rs` + pattern в конфиге;
- новый маркер ложного срабатывания: `false_positive_markers` в конфиге;
- новый сценарий лаборатории: объект в `scenarios` BUNDLE.json;
- новый формат отчёта: функция в `report.py` + опция `--format`.

## Зависимости

Только стандартные библиотеки: Rust `std`, Go `net/http`, `crypto/sha256`, `regexp`,
`encoding/json`, `sync`; Python `argparse`, `json`, `socket`, `base64`, `hashlib`,
`urllib.request`, `subprocess`, `unittest`.
