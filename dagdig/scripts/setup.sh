#!/bin/bash
# DAGDIG Setup Script

set -e

echo "====================================="
echo "  DAGDIG - Setup"
echo "====================================="

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "[!] Python3 not found"
    exit 1
fi

# Create virtual environment
if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

# Activate
source venv/bin/activate

# Upgrade pip
echo "[*] Upgrading pip..."
pip install --upgrade pip

# Install dependencies
echo "[*] Installing dependencies..."
pip install -r requirements.txt

# Check system dependencies
if ! command -v nmap &> /dev/null; then
    echo "[!] Warning: 'nmap' is not installed or not in PATH."
    echo "    Install with: sudo apt install -y nmap"
fi

if ! command -v figlet &> /dev/null; then
    echo "[!] Warning: 'figlet' is not installed or not in PATH."
    echo "    Install with: sudo apt install -y figlet"
fi

# Create directories
mkdir -p data/raw wordlists

# Link system wordlists if available (saves disk space & keeps them updated)
if [ -d /usr/share/wordlists ]; then
    echo "[*] Symlinking system wordlists (/usr/share/wordlists)..."
    ln -sfn /usr/share/wordlists/* wordlists/ 2>/dev/null || true
fi

if [ -d /usr/share/seclists ]; then
    echo "[*] Symlinking SecLists (/usr/share/seclists)..."
    ln -sfn /usr/share/seclists wordlists/seclists 2>/dev/null || true
fi

if [ ! -d /usr/share/wordlists ] && [ ! -d /usr/share/seclists ]; then
    echo "[i] System wordlists not found. Built-in fallbacks will be used."
    echo "    For comprehensive wordlists, install via:"
    echo "    sudo apt install -y seclists wordlists"
fi

# Create .env from example
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo "[!] Please edit .env with your Groq API key (GROQ_API_KEY=gsk_...)"
fi

echo ""
echo "[+] Setup complete!"
echo ""
echo "Quick Start:"
echo "  1. Set your Groq API key in .env"
echo "  2. python dagdig.py scan <target_ip>"
echo "  3. python dagdig.py webanalyze <url>"

