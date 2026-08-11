"""LLM provider wiring. Derivation and the optional agent loop use Gemini.

API key resolution (first hit wins):

  GEMINI_API_KEY
  GOOGLE_API_KEY
  GOOGLE_API_KEY_APIKEY   (some Google client setups)

Never commit a key. Prefer a gitignored `.env` or the process environment.
"""

from __future__ import annotations

import os
from pathlib import Path

from google import genai

_ENV_LOADED = False


def load_dotenv(path: Path | None = None) -> None:
    """Load a gitignored .env into os.environ if present (does not override)."""
    global _ENV_LOADED
    if _ENV_LOADED:
        return
    _ENV_LOADED = True
    env_path = path or Path(__file__).resolve().parent.parent / ".env"
    if not env_path.is_file():
        return
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


class LLMConfigError(RuntimeError):
    """No usable Gemini API key in the environment."""


def api_key() -> str:
    load_dotenv()
    for name in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_API_KEY_APIKEY"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    raise LLMConfigError(
        "No Gemini API key found. Set GEMINI_API_KEY (or GOOGLE_API_KEY) in the "
        "environment or a gitignored warrant/.env file, then retry."
    )


def has_api_key() -> bool:
    try:
        api_key()
        return True
    except LLMConfigError:
        return False


def client() -> genai.Client:
    return genai.Client(api_key=api_key())


def model_name() -> str:
    load_dotenv()
    return os.environ.get("WARRANT_LLM_MODEL", "gemini-flash-latest")
