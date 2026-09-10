# Contributing

## Setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Before opening a PR

Run the same checks CI runs:

```bash
ruff check src tests
ruff format --check src tests
mypy src
pytest -q
```

## Guidelines

- Keep the pipeline stages (`graph/nodes.py`) thin — real logic belongs in
  `tools/` (external commands) or `agents/` (LLM roles).
- Every new tool wrapper goes through `tools.base.run_command` so its output is
  recorded and cleaned like the others.
- Prompts live in `src/intelforge/prompts/*.txt`, loaded via
  `agents.prompts.load_prompt`.
- Add or update tests under `tests/`; LLM behaviour is tested with
  `langchain_core` fakes, never live calls.
- Conventional-commit style messages (`feat:`, `fix:`, `docs:`, `ci:`, …).
