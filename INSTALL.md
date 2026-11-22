# Установка

## Требования

- Rust 1.77+ (`cargo`, `rustc`)
- Go 1.22+ (`go`)
- Python 3.12+ (`python3`)
- `make` (необязательно, но рекомендуется)

Внешние пакеты и библиотеки не нужны.

## Сборка

Из корня проекта:

```bash
make build
```

Команда собирает:

- `target/debug/dscore` — Rust-ядро;
- `go/bin/dstoken` — сканер токенов;
- `go/bin/dsmock` — локальный mock-сервер.

Эквивалентно вручную:

```bash
cargo build --manifest-path Cargo.toml
mkdir -p go/bin
cd go && go build -o bin/dstoken ./cmd/dstoken && go build -o bin/dsmock ./cmd/dsmock
```

## Проверка

```bash
make test
target/debug/dscore version
go/bin/dstoken --help
go/bin/dsmock --help
PYTHONPATH=python python3 -m dsrlab version
```

## Запуск без установки в систему

Достаточно `PYTHONPATH=python` для CLI. Бинарники ищутся автоматически в
`target/debug/`, `go/bin/` и через `PATH`. Явно задать их можно переменными:

```bash
export TGSEC_CORE=/path/to/dscore
export TGSEC_DSTOKEN=/path/to/dstoken
export TGSEC_DSMOCK=/path/to/dsmock
```

## Docker

```bash
docker build -t dsrlab .
docker run --rm -v "$PWD:/work" -w /work dsrlab make demo
```

Контейнер не требует сети для самого анализа; сетевые проверки остаются внутри
`127.0.0.1`.

## Устранение проблем

- `ToolNotFoundError` — выполните `make build` или задайте переменные `TGSEC_*`.
- `connection refused` при работе с mock — убедитесь, что команда `gateway` или
  `exploit-lab` ещё выполняется; сервер живёт только внутри этой команды.
- Ошибка конфига — проверьте `configs/default.json` командой
  `PYTHONPATH=python python3 -m dsrlab config validate`.
