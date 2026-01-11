from datetime import datetime
from pathlib import Path

from config import MEMORY_DIR, MEMORY_MAX_CHARS


def memory_file(profile_id: str) -> Path:
    return MEMORY_DIR / f"{profile_id}.md"


def append_memory(profile_id: str, note: str) -> None:
    if not note:
        return
    fpath = memory_file(profile_id)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    line = f"- [{timestamp}] {note.strip()}\n"
    with fpath.open("a", encoding="utf-8") as f:
        f.write(line)


def get_memory_excerpt(profile_id: str) -> str:
    fpath = memory_file(profile_id)
    if not fpath.exists():
        return ""
    text = fpath.read_text(encoding="utf-8")
    if len(text) <= MEMORY_MAX_CHARS:
        return text
    return text[-MEMORY_MAX_CHARS:]


def load_full_memory(profile_id: str) -> str:
    fpath = memory_file(profile_id)
    if not fpath.exists():
        return ""
    return fpath.read_text(encoding="utf-8")


def clear_memory(profile_id: str) -> None:
    fpath = memory_file(profile_id)
    if fpath.exists():
        fpath.unlink()
