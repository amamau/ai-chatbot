import json
from pathlib import Path
from typing import List, Dict, Optional

import bcrypt

# Cartella del progetto (dove sta questo file)
BASE_DIR = Path(__file__).resolve().parent

# 1) percorso classico: ./data/users.json
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)
USERS_FILE_MAIN = DATA_DIR / "users.json"

# 2) fallback: ./users.json (nel caso tu l'abbia lì)
USERS_FILE_FALLBACK = BASE_DIR / "users.json"


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _load_users() -> List[Dict]:
    """
    Carica la lista utenti.
    Prova prima data/users.json, poi ./users.json.
    Logga da dove legge, così vedi nei log cosa succede.
    """
    paths = []
    if USERS_FILE_MAIN.exists():
        paths.append(USERS_FILE_MAIN)
    if USERS_FILE_FALLBACK.exists() and USERS_FILE_FALLBACK != USERS_FILE_MAIN:
        paths.append(USERS_FILE_FALLBACK)

    for p in paths:
        try:
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                print(f"[accounts] loaded {len(data)} users from {p}")
                return data
            else:
                print(f"[accounts] file {p} does not contain a list, ignored")
        except Exception as e:
            print(f"[accounts] error loading {p}: {e}")

    print("[accounts] no valid users.json found, returning empty list")
    return []


def list_users() -> List[Dict]:
    return _load_users()


def get_user_by_email(email: str) -> Optional[Dict]:
    email_norm = _normalize_email(email)
    for u in _load_users():
        if _normalize_email(str(u.get("email", ""))) == email_norm:
            return u
    return None


def verify_password(password: str, password_hash: str) -> bool:
    """
    Verifica password in chiaro contro hash bcrypt.
    """
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except Exception as e:
        print(f"[accounts] password verification failed: {e}")
        return False


# alias nel caso qualche codice usi questo nome
def check_password(password: str, password_hash: str) -> bool:
    return verify_password(password, password_hash)


def authenticate(email: str, password: str) -> Optional[Dict]:
    """
    Autentica un utente:
      - trova per email
      - controlla is_active
      - verifica la password
    NON blocca più se profile_id è vuoto.
    """
    user = get_user_by_email(email)
    if not user:
        print(f"[accounts] authenticate: user not found for {email!r}")
        return None

    if not user.get("is_active", False):
        print(f"[accounts] authenticate: user {email!r} inactive")
        return None

    if not verify_password(password, user.get("password_hash", "")):
        print(f"[accounts] authenticate: wrong password for {email!r}")
        return None

    print(f"[accounts] authenticate: success for {email!r}")
    return user
