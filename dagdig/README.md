# DAGDIG ⚡
### Domain & Gateway Discovery Intelligence Gathering
> **An autonomous reconnaissance engine and AI-driven attack surface analyzer tailored for Hack The Box (HTB) machines, CTFs, and penetration testing.**

---

## 📌 Overview

**DAGDIG** is a reconnaissance and attack-path discovery tool designed to eliminate manual enumeration bottlenecks during penetration tests and CTF challenges.

By integrating multi-threaded port discovery, web fuzzing, and a **Triple Groq LLM Intelligence Pipeline**, DAGDIG transitions seamlessly from raw port scans to actionable, high-priority exploitation avenues.

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

## 📦 Installation & Setup

### 1. Install System Tools & Wordlists (Kali / Ubuntu)
```bash
sudo apt update
sudo apt install -y nmap seclists dirb wordlists
```

### 2. Run Automated Setup
Run the setup script to initialize the virtual environment, install Python dependencies, and symlink local wordlists:
```bash
chmod +x scripts/setup.sh
./scripts/setup.sh
```

### 3. Configure Your API Key
Add your Groq API key to `.env`:
```bash
cp .env.example .env
nano .env
```
```ini
GROQ_API_KEY=gsk_your_groq_api_key_here
```

---

## 📖 Usage

```bash
# 1. Full Target Scan & AI Analysis
python dagdig.py scan 10.10.11.x

# 2. Web Attack Surface & Exploit Advisor
python dagdig.py webanalyze http://10.10.11.x/

# 3. View Discovered State
python dagdig.py show

# 4. Re-run AI Analysis
python dagdig.py analyze

# 5. Export State to JSON
python dagdig.py export scan_results.json
```
