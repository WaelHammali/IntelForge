.PHONY: install lint fmt type test check

install:
	pip install -e ".[dev]"
	pre-commit install

lint:
	ruff check src tests

fmt:
	ruff format src tests

type:
	mypy src

test:
	pytest -q

check: lint type test
	ruff format --check src tests
