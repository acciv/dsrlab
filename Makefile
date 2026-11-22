PYTHON ?= python3
PYRUN := PYTHONPATH=python $(PYTHON)
PY := $(PYRUN) -m dsrlab

.PHONY: build test demo lint clean help

help:
	@echo "Доступные цели: build, test, demo, lint, clean"

build:
	cargo build --manifest-path Cargo.toml
	mkdir -p go/bin
	cd go && go build -o bin/dstoken ./cmd/dstoken
	cd go && go build -o bin/dsmock ./cmd/dsmock

lint:
	cd go && gofmt -l . && go vet ./...

test: build
	cargo test --manifest-path Cargo.toml
	cd go && go vet ./... && go test -count=1 ./...
	$(PYRUN) -m unittest discover -s python/tests -v

demo: build
	$(PY) scan examples/corpus --config configs/default.json --out examples/token-report.md
	$(PY) analyze examples/bundle.json --config configs/default.json --out examples/analysis.json
	$(PY) gateway --out examples/gateway-trace.json
	$(PY) exploit-lab examples/bundle.json --config configs/default.json --out examples/lab-results.json
	$(PY) report examples/analysis.json --format all --out examples/report
	cp examples/report.md docs/EXAMPLE_REPORT.md
	@echo "Демо готово: examples/token-report.md, examples/analysis.json, docs/EXAMPLE_REPORT.md"

clean:
	rm -rf target go/bin
	rm -f token-raw.json token-analysis.json token-report.md analysis.json
	rm -f gateway-trace.json lab-results.json
	rm -f examples/token-raw.json examples/token-analysis.json examples/token-report.md
	rm -f examples/analysis.json examples/gateway-trace.json examples/lab-results.json
	rm -f examples/report.txt examples/report.json examples/report.md
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
