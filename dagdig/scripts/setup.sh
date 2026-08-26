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

# Create directories
mkdir -p data/raw wordlists

# Copy wordlists if they exist in /usr/share/wordlists/
if [ -d /usr/share/wordlists ]; then
    echo "[*] Copying wordlists from /usr/share/wordlists/..."
    cp -rn /usr/share/wordlists/* wordlists/ 2>/dev/null || true
fi

# Copy from seclists if exists
if [ -d /usr/share/seclists ]; then
    echo "[*] Copying from /usr/share/seclists/..."
    cp -rn /usr/share/seclists/* wordlists/ 2>/dev/null || true
fi

# Create .env from example
if [ ! -f .env ] && [ -f .env.example ]; then
    cp .env.example .env
    echo "[!] Please edit .env with your API keys"
fi

echo ""
echo "[+] Setup complete!"
echo ""
echo "Run: python test.py"
echo "Or:  python dagdig.py scan example.com"
