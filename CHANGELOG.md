# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.1.0] — 2026-09-10

### Added
- `ScanTarget` / `validate_target()` — every target is validated and classified
  (IP · hostname · URL) before it can reach a subprocess.
- Shared hardened HTTP client (`intelforge.tools.http`): stable User-Agent,
  one place where TLS verification is disabled, `InsecureRequestWarning`
  silenced once.
- Per-role LLM sampling temperature (`INTELFORGE_LLM_TEMPERATURE_RESEARCHER`,
  default `0.6`) so the reasoning model does not loop at near-zero temperature.
- `CHANGELOG.md`.

### Changed
- Prompts rewritten per model: rigid skeletons for the 8B cleaner, evidence
  discipline for the 70B analyst, reasoning-model framing and anti-hallucination
  rules for the DeepSeek-R1 researcher.
- The interactive console and the Click subcommands now share one `_cmd_*`
  handler layer — the two front-ends can no longer diverge.
- Nmap XML is parsed with `defusedxml`; non-numeric `portid` values are skipped.
- Web-fuzz IP detection uses `ipaddress` instead of a digit-count heuristic.

### Fixed
- Argument injection: a target such as `-oX` or `--script=…` is rejected, and
  `--` terminates the Nmap argv.
- Invalid input (bad target, unknown state field) fails with a clean message and
  a non-zero exit code instead of a traceback.
- `_page_urls()` no longer produces `http://http://…` when the target is a URL.

## [3.0.0]

- Restructured into a `src/` package orchestrated by a LangGraph `StateGraph`.
- Unified Click CLI plus interactive console over the graph.
- Provider-agnostic LLM roles via LangChain `init_chat_model`.
- Typed Nmap / FinalRecon / web-fuzz wrappers; Rich console theme, banner and
  result tables.
- CI (ruff, mypy, pytest on Python 3.11–3.13), Dependabot, PEP 561 `py.typed`.
