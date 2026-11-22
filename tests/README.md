# Тестирование

Тесты распределены по слоям:

- `cargo test --manifest-path Cargo.toml` — Rust: JSON, конфиг, маски, анализаторы,
  дедупликация, сортировка, логи без секретов.
- `cd go && go test -count=1 ./...` — Go: REST и WebSocket mock, 429, OAuth, webhook,
  токен-сканер, границы, ложные срабатывания, большая директория.
- `cd python && python3 -m unittest discover -s tests -v` — Python: CLI, конфиг,
  отчёты, HTTP/WebSocket-клиент, сценарии лаборатории, интеграция.

Все тесты используют только синтетические значения и `127.0.0.1`. Общий запуск:
`make test`.
