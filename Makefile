.PHONY: help install lint fmt fmt-check typecheck test check build pyz clean

RUN := uv run

help:
	@grep -E '^[a-z-]+:' Makefile | cut -d: -f1

install:
	uv sync

lint:
	$(RUN) ruff check .

fmt:
	$(RUN) ruff check --fix .
	$(RUN) ruff format .

fmt-check:
	$(RUN) ruff format --check .

typecheck:
	$(RUN) mypy

test:
	$(RUN) pytest --cov=joker_dmapi --cov-report=term-missing

check: lint fmt-check typecheck test

build:
	uv build

# Single-file executable (zipapp) with dependencies bundled; needs only a python3 >= 3.11.
pyz:
	mkdir -p dist
	$(RUN) shiv -c joker-dmapi -o dist/joker-dmapi.pyz --python '/usr/bin/env python3' .

clean:
	rm -rf build dist .pytest_cache .mypy_cache .ruff_cache .coverage src/*.egg-info
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
