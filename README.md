# IntelForge ⚡
### Autonomous Penetration Testing & Reconnaissance AI Engine
> **Keystone Groupe, Tunisia · AI and CyberSecurity Project 2026**
> *Passive OSINT, multi-threaded network & web discovery, and a collaborative AI
> analysis pipeline — orchestrated end to end with LangGraph.*

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Orchestration](https://img.shields.io/badge/Orchestration-LangGraph-orange.svg)](https://langchain-ai.github.io/langgraph/)
[![OSINT](https://img.shields.io/badge/OSINT-FinalRecon-red.svg)](https://github.com/thewhiteh4t/FinalRecon)

---

## Overview

IntelForge removes the manual enumeration bottleneck in security assessments, CTFs
and Red Team operations. It runs the recon collectors, condenses every tool's raw
output with an LLM, and then walks a fixed chain of AI "members" — **Cleaner →
Analyst → Researcher → Analyst (synthesis)** — to turn discovery into a structured,
prioritised exploit-intelligence report.

The whole flow is a compiled **LangGraph `StateGraph`**: every step is an explicit
node, the shared `TargetState` is the bus between them, and the diagram below is
generated from the running graph (`intelforge graph`).

```mermaid
graph TD;
	__start__([start]):::first
	recon(recon · nmap + FinalRecon + web fuzz, parallel)
	clean_commands(clean_commands · LLM condenses every command)
	fetch_pages(fetch_pages · HTTP GET discovered URLs)
	clean_html(clean_html · Stage 1 Cleaner)
	analyst(analyst · Stage 2 attack surface)
	research(research · Stage 3 CVE research + Stage 4 synthesis)
	report(report · JSON + tables)
	__end__([end]):::last
	__start__ --> recon;
	recon --> clean_commands;
	clean_commands -.->|"--no-llm"| report;
	clean_commands -.-> fetch_pages;
	fetch_pages --> clean_html;
	clean_html --> analyst;
	analyst --> research;
	research --> report;
	report --> __end__;
	classDef first fill-opacity:0
	classDef last fill:#bfb6fc
```

---

## Capabilities

- **Passive OSINT (FinalRecon)** — headers, SSL/TLS, DNS, WHOIS, subdomains,
  directories, Wayback endpoints, emails.
- **Active recon (Nmap)** — configurable TCP/UDP profiles, service/version
  detection, XML parsed into typed `Port` / `Service` records.
- **Web fuzzing** — directories (threaded HTTP), subdomains (`dig`), vhosts (Host
  header); skipped automatically for a bare IP.
- **Command Output Cleaner** — the second cleaner, pointed at CLI output. Each
  Nmap sweep becomes one row; FinalRecon is fanned into per-section rows. Produces
  the `Purpose | Command | Cleaned Findings` table and a digest fed to the Analyst.
- **AI members**
  - *Cleaner* — strips HTML noise to structured text.
  - *Analyst (Stage 2)* — maps upload points, injectable params, bypass paths,
    auth pages and suspicious keywords.
  - *Researcher (Stage 3)* — a reasoning model researches CVEs, techniques and
    tools per finding and per Nmap service version.
  - *Analyst (Stage 4)* — synthesises the research tuples + command digest into a
    final report with an open-services table and an access map
    (`register_required` vs `bypass_candidates`).
- **Provider-agnostic LLMs** — each role is a `provider:model` string
  (`groq:…`, `openai:…`, `google_genai:…`, or any OpenAI-compatible gateway) via
  LangChain's `init_chat_model`.

---

## Install

Linux (Kali / Parrot / Debian / Ubuntu). Requires **Python 3.11–3.13**, plus
`nmap` (`sudo apt install -y nmap`) and, optionally, `figlet` and a FinalRecon
checkout.

```bash
git clone https://github.com/WaelHammali/Pentest_Command_DAGDIG.git intelforge
cd intelforge
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"          # drop [dev] for a runtime-only install
cp .env.example .env             # then set GROQ_API_KEY (or another provider)
```

---

## Usage

```bash
intelforge                       # interactive console
intelforge scan 10.10.11.20      # full pipeline
intelforge scan 10.10.11.20 --no-web --no-osint --no-llm
intelforge osint example.com     # passive OSINT only (FinalRecon + cleaner)
intelforge webanalyze http://10.10.11.20/   # AI web analysis, no recon
intelforge show                  # render the stored state
intelforge export report.json
intelforge graph                 # print the pipeline diagram
```

Interactive console commands mirror the subcommands: `use`, `scan`, `osint`,
`webanalyze`, `show`, `set`, `export`, `graph`, `clear`, `banner`, `help`, `exit`.

### Configuration (`.env` / environment, prefix `INTELFORGE_`)

| Setting | Purpose | Default |
| --- | --- | --- |
| `INTELFORGE_LLM_CLEANER` / `_ANALYST` / `_RESEARCHER` | model per role | `groq:…` |
| `INTELFORGE_LLM_BASE_URL` | OpenAI-compatible gateway | – |
| `GROQ_API_KEY` / `OPENAI_API_KEY` / … | provider credentials | – |
| `INTELFORGE_FINALRECON_PATH` | path to `finalrecon.py` | see `.env.example` |
| `INTELFORGE_REQUEST_TIMEOUT` / `_FUZZ_THREADS` / `_SCAN_TIMEOUT` | tuning | `10` / `20` / `600` |
| `INTELFORGE_DATA_DIR` / `_WORDLIST_DIR` | output & wordlist roots | `data` / `wordlists` |

Legacy `GROQ_MODEL` / `GROQ_MODEL_2` / `GROQ_MODEL_3` are still honoured when the
matching `INTELFORGE_LLM_*` variable is unset.

---

## Project layout

```
pyproject.toml                 # packaging, deps, ruff / mypy / pytest config
src/intelforge/
├── cli.py                     # click subcommands + interactive console
├── config.py                  # pydantic-settings Settings
├── console/                   # Rich theme, banner, result tables
├── domain/                    # models.py (Pydantic) + state.py (TargetState)
├── tools/                     # nmap · finalrecon · webfuzz + run_command
├── agents/                    # llm · html_cleaner · command_cleaner · analyst · researcher
├── graph/                     # state · nodes · pipeline (the LangGraph StateGraph)
├── reporting/                 # JSON report writer
└── prompts/                   # system-prompt templates
tests/                         # models, state, config, tools, agents, graph, cli
```

---

## Development

```bash
ruff check src tests
mypy src
pytest
```

---

## Disclaimer

For authorised security assessments, education, CTFs and penetration testing with
explicit written consent only. Unauthorised scanning of third-party infrastructure
is illegal.
