import json
import logging
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional

from dotenv import load_dotenv

logger = logging.getLogger(__name__)

ENV_PATH = Path(__file__).parent / '.env'
if ENV_PATH.exists():
    load_dotenv(str(ENV_PATH))

# Single key (backward compat)
OPENROUTER_API_KEY: str = os.getenv("OPENROUTER_API_KEY", "")

# Multi-key rotation (OPENROUTER_API_KEYS = "key1,key2,key3,...")
_raw_keys = os.getenv("OPENROUTER_API_KEYS", "")
OPENROUTER_API_KEYS: List[str] = [k.strip() for k in _raw_keys.split(",") if k.strip()]
if OPENROUTER_API_KEY and OPENROUTER_API_KEY not in OPENROUTER_API_KEYS:
    OPENROUTER_API_KEYS.insert(0, OPENROUTER_API_KEY)

if not OPENROUTER_API_KEYS:
    logger.warning("OPENROUTER_API_KEY not set in environment or .env")
    logger.warning("   Set it via Render Environment Variables or create .env file")
    logger.warning("   OPENROUTER_API_KEY=sk-...")

def get_api_key() -> str:
    """Return a random API key from the rotation pool."""
    if not OPENROUTER_API_KEYS:
        return ""
    return random.choice(OPENROUTER_API_KEYS)
OPENROUTER_BASE_URL: str = "https://openrouter.ai/api/v1"
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = "llama-3.3-70b-versatile"
API_PROVIDER: str = os.getenv("API_PROVIDER", "openrouter")

OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_API_KEY: str = os.getenv("OLLAMA_API_KEY", "")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "gpt-oss:120b")
OLLAMA_TIMEOUT: int = int(os.getenv("OLLAMA_TIMEOUT", "90"))

GITHUB_TOKEN: str = os.getenv("GITHUB_TOKEN", "")
_secret_key = os.getenv("SECRET_KEY")
if not _secret_key:
    import secrets
    if os.path.isdir("/data"):
        raise RuntimeError("SECRET_KEY must be set in production environment variables")
    _key_file = Path(__file__).parent / ".secret_key"
    if _key_file.exists():
        _secret_key = _key_file.read_text().strip()
    else:
        _secret_key = secrets.token_hex(32)
        _key_file.write_text(_secret_key)
SECRET_KEY: str = _secret_key

CONFIG_FILE = Path(__file__).parent / 'config.json'

DEFAULT_CONFIG = {
    "temperature": 0.3,
    "timeout": 300,
    "max_retries": 3,
    "initial_backoff": 2.0,
    "max_code_chars": 500_000,
    "cache_enabled": True,
    "cache_db": "cache.db",
    "parallel": True,
    "parallel_max_workers": 4,
    "active_model": "openrouter-free",
    "model_fallback_chain": [
        "openrouter-free", "qwen3-coder",
        "llama-3.3-70b", "hermes-3-405b",
        "deepseek-r1", "nemotron-3-ultra",
    ],
}

def load_config() -> Dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                cfg.update(json.load(f))
            logger.info(f"Loading config from {CONFIG_FILE}")
        except Exception as e:
            logger.warning(f"Failed to load {CONFIG_FILE}: {e}")
    return cfg

_config = load_config()

FREE_MODELS: Dict[str, Dict] = {
    "openrouter-free":   {"id": "openrouter/free",                              "context": 200_000},
    "qwen3-coder":       {"id": "qwen/qwen3-coder:free",                         "context": 1_048_576},
    "llama-3.3-70b":     {"id": "meta-llama/llama-3.3-70b-instruct:free",        "context": 131_072},
    "gemma-4-26b":       {"id": "google/gemma-4-26b-a4b-it:free",                "context": 262_144},
    "hermes-3-405b":     {"id": "nousresearch/hermes-3-llama-3.1-405b:free",     "context": 131_072},
    "nemotron-3-ultra":  {"id": "nvidia/nemotron-3-ultra-550b-a55b:free",        "context": 1_000_000},
    "nemotron-3-nano":   {"id": "nvidia/nemotron-3-nano-30b-a3b:free",            "context": 256_000},
    "deepseek-r1":       {"id": "deepseek/deepseek-r1:free",                       "context": 1_000_000},
    "deepseek-chat":     {"id": "deepseek/deepseek-chat:free",                    "context": 1_000_000},
    "deepseek-r1-llama": {"id": "deepseek/deepseek-r1-distill-llama-70b:free",    "context": 131_072},
    "qwen-2.5-coder":    {"id": "qwen/qwen-2.5-coder-32b-instruct:free",          "context": 32_768},
    "gemma-2-27b":       {"id": "google/gemma-2-27b-it:free",                     "context": 8_192},
}

ACTIVE_MODEL: str = _config["active_model"]
MODEL_FALLBACK_CHAIN: List[str] = _config["model_fallback_chain"]
OPENROUTER_MODEL: str = FREE_MODELS.get(ACTIVE_MODEL, {}).get("id", "openrouter/free")
MAX_CODE_CHARS: int = min(
    FREE_MODELS.get(ACTIVE_MODEL, {}).get("context", 200_000) // 2,
    _config["max_code_chars"]
)
TEMPERATURE: float = _config["temperature"]
TIMEOUT: int = _config["timeout"]
MAX_RETRIES: int = _config["max_retries"]
INITIAL_BACKOFF: float = _config["initial_backoff"]
CACHE_ENABLED: bool = _config["cache_enabled"]
CACHE_DB_PATH: str = f"/data/{_config['cache_db']}" if os.path.isdir("/data") else os.path.join(os.path.dirname(__file__), "instance", _config["cache_db"])
os.makedirs(os.path.dirname(CACHE_DB_PATH), exist_ok=True)
PARALLEL: bool = _config["parallel"]
PARALLEL_MAX_WORKERS: int = _config["parallel_max_workers"]
REPORT_DIR: str = "/data/reports" if os.path.isdir("/data") else os.path.join(os.path.dirname(__file__), "reports")
PROGRESS_FILE: str = os.path.join(REPORT_DIR, "_progress.json")

KB_ENABLED: bool = _config.get("kb_enabled", True)
_kb_file = _config.get("kb_db", "knowledge.db")
_kb_local = os.path.join(os.path.dirname(__file__), "instance", _kb_file)
_kb_data = f"/data/{_kb_file}"
KB_DB_PATH: str = _kb_data if os.path.isdir("/data") else _kb_local
KB_RAG_ENABLED: bool = _config.get("kb_rag_enabled", True)
KB_MAX_CONTEXT: int = _config.get("kb_max_context", 2000)
KB_AUTO_LEARN: bool = _config.get("kb_auto_learn", True)

if API_PROVIDER == "openrouter" and not OPENROUTER_API_KEY:
    logger.warning("OPENROUTER_API_KEY is missing — AI analysis will fail.\n"
                   "   Local analysis (Opcodes, Storage) works without API.")
