from pathlib import Path
import os
from dotenv import load_dotenv

# Base paths
BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = BASE_DIR / "data"
PROFILES_DIR = DATA_DIR / "profiles"
MEMORY_DIR = DATA_DIR / "memory"
SESSIONS_DIR = DATA_DIR / "sessions"
LOGS_DIR = DATA_DIR / "logs"

for d in (DATA_DIR, PROFILES_DIR, MEMORY_DIR, SESSIONS_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Env file
env_path = BASE_DIR / ".env"
if env_path.exists():
    load_dotenv(env_path)

# LLM config
LLM_API_KEY = os.getenv("LLM_API_KEY") or ""
LLM_API_BASE = os.getenv("LLM_API_BASE", "https://api.deepseek.com")
LLM_MODEL = os.getenv("LLM_MODEL", "deepseek-chat")

LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.4"))
LLM_TOP_P = float(os.getenv("LLM_TOP_P", "0.9"))
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "2048"))

# UI and memory config
TYPEWRITER_DELAY = float(os.getenv("TYPEWRITER_DELAY", "0.004"))
MEMORY_MAX_CHARS = int(os.getenv("MEMORY_MAX_CHARS", "2000"))
