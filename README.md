# DAGDIG ⚡
### Domain & Gateway Discovery Intelligence Gathering
> **An autonomous reconnaissance engine and AI-driven attack surface analyzer tailored for Hack The Box (HTB) machines, CTFs, and penetration testing.**

---

## 📌 Overview

**DAGDIG** is a reconnaissance and attack-path discovery tool designed to eliminate manual enumeration bottlenecks during penetration tests and CTF challenges.

By integrating multi-threaded port discovery, web fuzzing, and a **Triple Groq LLM Intelligence Pipeline**, DAGDIG transitions seamlessly from raw port scans to actionable, high-priority exploitation avenues.

```
+-------------------------------------------------------------------------------+
|                                  DAGDIG WORKFLOW                              |
+-------------------------------------------------------------------------------+
|  1. RECON          Nmap TCP/UDP Scans + Directory / Subdomain / Vhost Fuzzing |
|        |                                                                      |
|  2. STAGE 1 AI     Reconnaissance Synthesizer (Llama-3.3-70B via Groq)        |
|        |                                                                      |
|  3. STAGE 2 AI     Deep Web Surface Parser & Parameter / Keyword Discovery   |
|        |           - Bypass Paths (admin portals, unauthenticated endpoints)   |
|        |           - Upload Points (webshell injection, mime-type bypasses)   |
|        |           - Injectable Parameters (?id=, ?page=, LFI, SQLi, IDOR)    |
|        |           - Keyword Indications & Version Fingerprints (e.g. chameleon)|
|        |           - LLM Recon Paragraph for downstream AI agents             |
|        |                                                                      |
|  4. STAGE 3 AI     Automated Exploit & CVE Research (Actionable Attack Plan)  |
|        |           - Exact CVE IDs, PoC payloads, tools & attack execution order|
|        V                                                                      |
|  5. OUTPUT         State JSON + Exploit Intelligence Plan (`data/exploit_*.json`)|
+-------------------------------------------------------------------------------+
```

---

## 🚀 Key Capabilities

- 🎯 **Network Reconnaissance**: Fast TCP & UDP port discovery using `nmap`, service banner grabbing, and OS fingerprinting.
- 🔍 **Web Surface Discovery**: Parallel directory fuzzing, virtual host identification, and endpoint mapping.
- 🧠 **Triple Groq LLM Intelligence**:
  - **Stage 1 — Recon Synthesis**: Summarizes open ports, service versions, and vulnerabilities.
  - **Stage 2 — Attack Surface & Keyword Fingerprinting**: Fetches and cleans target pages (stripping noise), maps bypass paths, authentication portals, file upload vectors, query parameters susceptible to manipulation, and subtle page hints (e.g. internal keywords, themes, specific technologies).
  - **Stage 3 — Actionable Exploit Planner**: Cross-references findings against CVE databases and known exploits, recommends exact tools (`sqlmap`, `hydra`, `metasploit`, custom PoCs), payloads, and prioritizes the attack sequence.
- 📊 **Dynamic State Management**: Centralized tracking across scans, instant tabular status display, and structured JSON export ready for hand-off to other tools or LLMs.

---

## 🛠️ Prerequisites

DAGDIG is designed for Linux environments (Kali Linux, Parrot OS, Ubuntu/Debian):

- **Python**: 3.10 or higher
- **Nmap**: `sudo apt install -y nmap`
- **Figlet**: `sudo apt install -y figlet` (for dynamic colored ASCII banners)
- **Wordlists**: `seclists`, `dirb`, or `wordlists` package (optional, built-in fallbacks provided)
- **Groq API Key**: Free API key from [Groq Console](https://console.groq.com) (provides ultra-low-latency Llama-3.3-70B inferences)

---

## 📦 Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/WaelHammali/Pentest_Command_DAGDIG.git
cd Pentest_Command_DAGDIG
```

### 2. Install System Tools & Wordlists (Recommended for Kali / Ubuntu)
```bash
sudo apt update
sudo apt install -y nmap figlet seclists dirb wordlists
```

### 3. Run Automated Setup
Run the setup script to create a virtual environment, install Python dependencies, and symlink local wordlists:
```bash
chmod +x dagdig/scripts/setup.sh
./dagdig/scripts/setup.sh
```

*(Alternatively, manual setup:)*
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r dagdig/requirements.txt
```

### 4. Configure Your API Key
Copy the example environment file and add your Groq API key:
```bash
cp dagdig/.env.example dagdig/.env
nano dagdig/.env
```
Add your key:
```ini
GROQ_API_KEY=gsk_your_groq_api_key_here
```

---

## 📖 How to Run DAGDIG

You can run commands directly using the root launcher:

### 1. Full Target Scan & AI Analysis (Recon -> Fuzzing -> AI)
Run complete port scanning, directory fuzzing, and AI synthesis on a target IP or domain:
```bash
python dagdig.py scan 10.10.11.x
```
*Options:*
- `--ports 1-1000` / `-p 80,443,8080`: Custom port ranges
- `--udp / -u`: Include UDP scanning
- `--no-ai`: Skip AI analysis

### 2. Web Attack Surface & Exploit Advisor (`webanalyze`)
Directly analyze a web application URL through the 3-stage LLM pipeline to discover bypass paths, injection points, and attack vectors:
```bash
python dagdig.py webanalyze http://10.10.11.x/
```
*What this outputs:*
- Discovered bypass endpoints & authentication portals
- Upload forms with payload recommendations (webshell injection, extension bypasses)
- Manipulable URL parameters (`id`, `page`, `file`, etc.)
- Specific page keywords and clues
- Comprehensive **Exploit Intelligence Report** saved to `dagdig/data/exploit_<target>_<timestamp>.json`

### 3. Inspect Current Reconnaissance State
View discovered services, open ports, directories, and vulnerabilities in a clean CLI table:
```bash
python dagdig.py show
```

### 4. Re-run AI Analysis on Discovered State
Re-analyze existing scan data stored in state without re-running network scans:
```bash
python dagdig.py analyze
```

### 5. Export Scan Data
Export the structured state to a JSON file:
```bash
python dagdig.py export scan_results.json
```

---

## 📂 Project Architecture

```
Pentest_Command_DAGDIG/
├── dagdig.py                     # Root CLI launcher
├── README.md                     # Project documentation
└── dagdig/                       # Main package
    ├── dagdig.py                 # Core CLI entrypoint & commands
    ├── core/                     # State management, data schemas, banners
    │   ├── schema.py             # TargetData & PageAnalysis data models
    │   └── state.py              # Persistent scan state manager
    ├── exec/                     # Execution engines
    │   ├── nmap.py               # TCP/UDP port scanner
    │   └── web.py                # Directory & vhost fuzzer
    ├── llm/                      # LLM Integration & Orchestration
    │   ├── client.py             # Groq API client
    │   └── llm_bridge.py         # DualGroqAnalyzer & TripleGroqAnalyzer (Stages 1-3)
    ├── attack/                   # Attack planning & tracking
    │   ├── tracker.py            # Attack vector tracking & logging
    │   └── advisor.py            # WebAttackAdvisor orchestration
    ├── prompts/                  # Stage 1, 2, and 3 prompt templates
    ├── scripts/
    │   └── setup.sh              # Automated installation & environment setup
    └── wordlists/                # Symlinked system wordlists (.gitignored)
```

---

## 🛡️ Wordlists Information

To keep the repository lightweight, large wordlist files (such as SecLists and rockyou) are **not** bundled directly in Git. 

- When `./dagdig/scripts/setup.sh` runs, it automatically detects and creates symbolic links to your system's wordlists in `/usr/share/wordlists` and `/usr/share/seclists`.
- If no system wordlists are found, DAGDIG seamlessly falls back to embedded, high-signal wordlists for directory and parameter fuzzing.

---

## ⚖️ Disclaimer

DAGDIG is intended strictly for authorized security assessments, educational purposes, CTF competitions, and Hack The Box machines. Unauthorized testing of systems without explicit consent is illegal.
