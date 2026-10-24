# solsentry developer commands. `make check` is the single gate used locally and in CI.
UV ?= uv
SRC := src tests scripts
COV_MIN := 90
export SOLCX_BINARY_PATH ?= $(CURDIR)/.solcx

.PHONY: help install check format-check fmt lint typecheck test demo eval bench fixtures fixtures-verify integration clean

help:
	@echo "make check            format-check + lint + mypy --strict + tests with coverage >= $(COV_MIN)%"
	@echo "make demo             offline end-to-end demo over the bundled fixtures"
	@echo "make eval             precision/recall on the dev and holdout splits"
	@echo "make bench            throughput and scaling benchmark"
	@echo "make fixtures         recompile fixture ASTs with the pinned solc (network on first run)"
	@echo "make fixtures-verify  recompile and check committed ASTs reproduce byte-for-byte"

install:
	$(UV) sync

format-check:
	$(UV) run ruff format --check $(SRC)

fmt:
	$(UV) run ruff format $(SRC)
	$(UV) run ruff check --fix $(SRC)

lint:
	$(UV) run ruff check $(SRC)

typecheck:
	$(UV) run mypy

test:
	$(UV) run pytest --cov=solsentry --cov-report=term --cov-fail-under=$(COV_MIN)

check: format-check lint typecheck test

demo:
	$(UV) run python -u scripts/demo.py

eval:
	$(UV) run solsentry eval fixtures/ast/dev --name dev
	@echo
	$(UV) run solsentry eval fixtures/ast/holdout --name holdout

bench:
	$(UV) run python -u scripts/bench.py

fixtures:
	$(UV) run --extra compile python -u scripts/compile_fixtures.py

fixtures-verify:
	$(UV) run --extra compile python -u scripts/compile_fixtures.py --verify

# solsentry has no Docker-based tests; kept so every P50 repo answers `make integration`.
integration:
	@echo "no integration targets: all tests run offline in 'make test'"

clean:
	rm -rf out .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
