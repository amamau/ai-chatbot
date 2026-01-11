import json
import secrets
import string
from pathlib import Path
from typing import Dict, Optional

from config import DATA_DIR

TOKENS_FILE = DATA_DIR / "tokens.json"

# URL-safe alphabet: letters + digits + a few special characters
TOKEN_ALPHABET = string.ascii_letters + string.digits + "-_~"


def load_tokens() -> Dict[str, Dict]:
    """
    Load token configuration from data/tokens.json.

    File format example:
    {
      "hahqj8iuwuaj19Z": {
        "profile_id": "thita",
        "label": "THITA beta tester 1"
      }
    }
    """
    if not TOKENS_FILE.exists():
        return {}
    try:
        with TOKENS_FILE.open(encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def save_tokens(tokens: Dict[str, Dict]) -> None:
    TOKENS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with TOKENS_FILE.open("w", encoding="utf-8") as f:
        json.dump(tokens, f, ensure_ascii=False, indent=2)


def generate_token(length: int = 50) -> str:
    """
    Generate a random token with given length using URL-safe characters.
    """
    return "".join(secrets.choice(TOKEN_ALPHABET) for _ in range(length))


def create_token(profile_id: str, label: str = "") -> str:
    """
    Create a new token mapped to a profile_id, store it in tokens.json
    and return the token string.
    """
    tokens = load_tokens()

    # ensure uniqueness
    while True:
        token = generate_token(50)
        if token not in tokens:
            break

    tokens[token] = {
        "profile_id": profile_id,
        "label": label,
    }
    save_tokens(tokens)
    return token


def get_profile_for_token(token: str) -> Optional[Dict]:
    """
    Return token info dict if token exists, else None.
    """
    tokens = load_tokens()
    return tokens.get(token)


def list_tokens() -> Dict[str, Dict]:
    """
    Return all tokens mapping.
    """
    return load_tokens()


def delete_token(token: str) -> bool:
    """
    Delete a token from tokens.json. Returns True if removed, False if not found.
    """
    tokens = load_tokens()
    if token not in tokens:
        return False
    tokens.pop(token)
    save_tokens(tokens)
    return True
