
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _default_audit_path() -> Path:
    """Default: data/logs/audit.jsonl"""
    try:
        from config import DATA_DIR  # type: ignore

        base = Path(DATA_DIR)
    except Exception:
        base = Path(__file__).resolve().parent / "data"
    return base / "logs" / "audit.jsonl"


# audit.py
from pathlib import Path
from datetime import datetime, timezone
import json

AUDIT_LOG = Path(__file__).resolve().parent / "data" / "audit.log"
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

def audit_event(*args, **kwargs):
    """
    Compat:
      - audit_event("evt", "user@email", {"k":"v"})
      - audit_event(event="evt", user_email="...", meta={...}, user_id=..., ip=..., ua=...)
    Best-effort: non deve MAI rompere le API.
    """
    try:
        if args:
            # mappa i 3 posizionali storici
            if len(args) >= 1 and "event" not in kwargs:
                kwargs["event"] = args[0]
            if len(args) >= 2 and "user_email" not in kwargs:
                kwargs["user_email"] = args[1]
            if len(args) >= 3 and "meta" not in kwargs:
                kwargs["meta"] = args[2]

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": str(kwargs.get("event") or ""),
            "user_email": (kwargs.get("user_email") or None),
            "user_id": (kwargs.get("user_id") or None),
            "ip": (kwargs.get("ip") or None),
            "ua": (kwargs.get("ua") or None),
            "meta": (kwargs.get("meta") or None),
        }

        with AUDIT_LOG.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception:
        # audit non deve mai bloccare il servizio
        return

