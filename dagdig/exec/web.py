#!/usr/bin/env python3
"""
Web fuzzing (directories, subdomains, vhosts)
"""
import os
import requests
import concurrent.futures
import subprocess as sp
from urllib.parse import urlparse
from pathlib import Path
from core.state import StateManager

class WebFuzzer:
    def __init__(self, state: StateManager):
        self.state = state
        self.session = requests.Session()
        self.session.verify = False
        self.session.timeout = 5

    def _base_url(self, target: str) -> str:
        if not target.startswith('http'):
            return f"http://{target}"
        return target

    def _find_wordlist_file(self, name: str) -> Path:
        """Search recursively for a wordlist by filename"""
        for root, dirs, files in os.walk('wordlists'):
            for file in files:
                if name in file and file.endswith('.txt'):
                    return Path(root) / file
        return None

    def _load_wordlist(self, name: str) -> list:
        """Load wordlist from file or fallback to built-in list"""
        # Common filenames for each type
        candidates = {
            'directories': ['common.txt', 'directory-list-2.3-medium.txt', 'dirb/common.txt', 'directories.txt'],
            'subdomains': ['subdomains-top1million-5000.txt', 'dnsmap.txt', 'subdomains.txt'],
            'vhosts': ['vhosts.txt', 'vhosts-common.txt'],
            'parameters': ['parameters.txt'],
            'extensions': ['web-extensions.txt', 'extensions.txt'],
        }
        for candidate in candidates.get(name, [name]):
            filepath = self._find_wordlist_file(candidate)
            if filepath:
                print(f"[+] Using wordlist: {filepath}")
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        return [line.strip() for line in f if line.strip() and not line.startswith('#')]
                except:
                    pass
        
        # Built-in fallback lists
        print(f"[!] No wordlist found for {name}, using fallback")
        fallbacks = {
            'directories': ['admin', 'api', 'assets', 'css', 'js', 'images', 'uploads', 'config', 'backup', 'test', 'dev'],
            'subdomains': ['www', 'mail', 'ftp', 'webmail', 'blog', 'dev', 'admin', 'forum', 'news', 'vpn', 'mysql'],
            'vhosts': ['www', 'dev', 'test', 'staging', 'admin', 'api', 'app'],
            'parameters': ['id', 'page', 'action', 'user', 'password', 'email', 'name', 'token'],
            'extensions': ['php', 'html', 'txt', 'js', 'css', 'json', 'xml', 'bak', 'old', 'backup'],
        }
        return fallbacks.get(name, [])

    # ---------- Directory Fuzzing ----------
    def fuzz_directories(self, target: str):
        """Fuzz directories using wordlist"""
        print("[*] Fuzzing directories...")
        base = self._base_url(target)
        wordlist = self._load_wordlist('directories')
        found = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(self._check_dir, base, word): word for word in wordlist}
            for future in concurrent.futures.as_completed(futures):
                word = futures[future]
                try:
                    if future.result():
                        found.append(word)
                        self.state.data.add_directory(word)
                        print(f"[+] Found directory: {word}")
                except:
                    pass
        self.state.save()
        return found

    def _check_dir(self, base, word):
        url = f"{base}/{word}"
        try:
            resp = self.session.get(url, allow_redirects=False)
            if resp.status_code in (200, 301, 302, 403):
                return True
        except:
            pass
        return False

    # ---------- Subdomain Discovery ----------
    def fuzz_subdomains(self, target: str):
        """Discover subdomains via DNS (dig/nslookup)"""
        print("[*] Fuzzing subdomains...")
        domain = target
        if '://' in domain:
            domain = urlparse(domain).netloc
        wordlist = self._load_wordlist('subdomains')
        found = []
        
        for sub in wordlist:
            full = f"{sub}.{domain}"
            try:
                result = sp.run(['dig', '+short', full], capture_output=True, text=True, timeout=3)
                if result.stdout.strip():
                    found.append(full)
                    self.state.data.add_subdomain(full)
                    print(f"[+] Found subdomain: {full}")
            except:
                pass
        self.state.save()
        return found

    # ---------- VHost Discovery ----------
    def fuzz_vhosts(self, target: str):
        """Discover virtual hosts by checking Host header"""
        print("[*] Fuzzing vhosts...")
        domain = target
        if '://' in domain:
            domain = urlparse(domain).netloc
        base = self._base_url(target)
        wordlist = self._load_wordlist('vhosts')
        found = []
        
        for vhost in wordlist:
            full = f"{vhost}.{domain}"
            try:
                resp = self.session.get(base, headers={'Host': full}, allow_redirects=False)
                if resp.status_code in (200, 301, 302, 403):
                    found.append(full)
                    self.state.data.add_vhost(full)
                    print(f"[+] Found vhost: {full}")
            except:
                pass
        self.state.save()
        return found
