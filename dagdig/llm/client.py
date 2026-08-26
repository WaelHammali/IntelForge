#!/usr/bin/env python3
"""
Groq API Client for DAGDIG Dual-AI Analysis Pipeline
Each client uses a dedicated API key and model, with 429 retry logic.
"""
import os
import time
import re
import requests
from pathlib import Path


class GroqClient:
    def __init__(self, api_key: str = None, model: str = None):
        self._load_dotenv()

        self.api_key = api_key or os.environ.get('GROQ_API_KEY', '').strip().strip('"').strip("'")
        self.model = model or os.environ.get('GROQ_MODEL') or 'qwen/qwen3.8-27b'
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"

    def _load_dotenv(self):
        """Parse local .env file if vars are not already in os.environ"""
        env_path = Path('.env')
        if not env_path.exists():
            env_path = Path(__file__).parent.parent / '.env'
        if env_path.exists():
            try:
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            k, v = line.split('=', 1)
                            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
            except Exception:
                pass

    def is_configured(self) -> bool:
        return bool(self.api_key and self.api_key != 'your-groq-api-key-here')

    def chat_completion(self, system_prompt: str, user_prompt: str, temperature: float = 0.2) -> str:
        """Send completion request to Groq API, retrying on 429."""
        if not self.is_configured():
            raise ValueError("GROQ_API_KEY is missing or unconfigured. Please set GROQ_API_KEY in .env or environment.")

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": temperature
        }

        max_attempts = 10
        for attempt in range(max_attempts):
            resp = requests.post(self.api_url, json=payload, headers=headers, timeout=60)

            if resp.status_code == 200:
                data = resp.json()
                try:
                    return data['choices'][0]['message']['content']
                except (KeyError, IndexError) as e:
                    raise RuntimeError(f"Unexpected response structure from Groq API: {data}") from e

            elif resp.status_code == 429:
                wait = 30.0
                err_msg = "Unknown 429 error"
                try:
                    err_msg = resp.json().get('error', {}).get('message', str(resp.text))
                    m = re.search(r'try again in ([\d.]+)s', err_msg)
                    if m:
                        wait = float(m.group(1)) + 1
                except Exception:
                    pass
                print(f"[!] Rate limit on {self.model} (attempt {attempt + 1}/{max_attempts}). Msg: {err_msg[:80]}... Waiting {wait:.1f}s...")
                time.sleep(wait)

            else:
                raise RuntimeError(f"Groq API call failed (HTTP {resp.status_code}): {resp.text}")

        raise RuntimeError(f"Groq API rate limit exceeded after {max_attempts} attempts.")
