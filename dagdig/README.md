# DAGDIG - Domain & Gateway Discovery Intelligence Gathering

DAGDIG is an advanced reconnaissance tool designed for domain and gateway discovery. It automates network scanning (using `nmap`) and web fuzzing (for directories, subdomains, and vhosts) in parallel, persisting discovered information into a structured state.

## Features

- **Network Scanning**: Handles TCP and UDP scans (both full and lightweight) using `nmap`.
- **Web Fuzzing**: Discovers directories, subdomains, and virtual hosts in parallel.
- **State Management**: Consolidates results, tracks progress, exports reports to JSON, and prints pretty status tables.
- **Multi-threading**: Runs scans and web discovery tasks concurrently.

## Setup

Run the setup script to initialize the virtual environment and install dependencies:
```bash
./scripts/setup.sh
```

## Usage

### Perform a Scan
```bash
python dagdig.py scan <target>
```

### View Results
```bash
python dagdig.py show
```

### Export Results
```bash
python dagdig.py export [filename]
```
