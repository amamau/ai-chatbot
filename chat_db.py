# -*- coding: utf-8 -*-
"""chat_db.py

SQLite persistence for:
- sessions (+ csrf_token)
- conversations / messages (private + workspace scope)
- projects (workspace scope)

No external dependencies.

Goals:
- Idempotent schema migrations
- Backward compatible public functions (private scope)
- Add ws_* APIs for workspace collaboration

Notes on scope separation:
- Private conversations: scope='private' and user_email is the owner.
- Workspace conversations: scope='workspace', workspace_id is set; user_email stores creator email for non-null constraint, but access is enforced by filtering workspace_id + scope.
"""

from __future__ import annotations

import os
import sqlite3
import secrets
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------
# DB location
# ---------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "chat.db"


# ---------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------


def _utc_now_iso() -> str:
    return datetime.utcnow().isoformat(timespec="seconds") + "Z"


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _table_exists(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (name,))
    return cur.fetchone() is not None


def _has_column(conn: sqlite3.Connection, table: str, col: str) -> bool:
    try:
        cur = conn.execute(f"PRAGMA table_info({table})")
        rows = cur.fetchall()
        for r in rows:
            if str(r[1]) == col:
                return True
    except Exception:
        return False
    return False


def _ensure_index(conn: sqlite3.Connection, ddl: str) -> None:
    try:
        conn.execute(ddl)
    except Exception:
        pass


def _random_csrf() -> str:
    # 32 bytes => 64 hex chars
    return secrets.token_hex(32)


# ---------------------------------------------------------------------
# Schema + migrations (idempotent)
# ---------------------------------------------------------------------


def init_chat_db() -> None:
    """Create the DB and tables if missing; apply safe migrations."""
    conn = _connect()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _migrate_schema(conn)
        conn.commit()
    finally:
        conn.close()


def _migrate_schema(conn: sqlite3.Connection) -> None:

    # sessions (backward-compatible migration from V4: sessions.id -> sessions.session_id)
    if _table_exists(conn, "sessions"):
        has_id = _has_column(conn, "sessions", "id")
        has_session_id = _has_column(conn, "sessions", "session_id")
        if has_id and not has_session_id:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions_new (
                  session_id TEXT PRIMARY KEY,
                  user_email TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  expires_at TEXT NOT NULL,
                  csrf_token TEXT
                )
                """
            )
            if _has_column(conn, "sessions", "csrf_token"):
                conn.execute(
                    "INSERT OR REPLACE INTO sessions_new(session_id, user_email, created_at, expires_at, csrf_token) "
                    "SELECT id, user_email, created_at, expires_at, COALESCE(csrf_token,'') FROM sessions"
                )
            else:
                conn.execute(
                    "INSERT OR REPLACE INTO sessions_new(session_id, user_email, created_at, expires_at, csrf_token) "
                    "SELECT id, user_email, created_at, expires_at, '' FROM sessions"
                )
            conn.execute("DROP TABLE sessions")
            conn.execute("ALTER TABLE sessions_new RENAME TO sessions")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,
          user_email TEXT NOT NULL,
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL
        )
        """
    )
    if not _has_column(conn, "sessions", "csrf_token"):
        conn.execute("ALTER TABLE sessions ADD COLUMN csrf_token TEXT")
        conn.execute("UPDATE sessions SET csrf_token='' WHERE csrf_token IS NULL")

    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_sessions_user_email ON sessions(user_email)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")


    # conversations
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS conversations (
          id TEXT PRIMARY KEY,
          user_email TEXT NOT NULL,
          profile_id TEXT NOT NULL,
          title TEXT NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          archived INTEGER DEFAULT 0,
          deleted INTEGER DEFAULT 0,
          deleted_at TEXT
        )
        """
    )

    # new columns for scope / workspace / attribution
    if not _has_column(conn, "conversations", "scope"):
        conn.execute("ALTER TABLE conversations ADD COLUMN scope TEXT")
        conn.execute("UPDATE conversations SET scope='private' WHERE scope IS NULL OR scope='' ")
    if not _has_column(conn, "conversations", "workspace_id"):
        conn.execute("ALTER TABLE conversations ADD COLUMN workspace_id TEXT")
    if not _has_column(conn, "conversations", "created_by_email"):
        conn.execute("ALTER TABLE conversations ADD COLUMN created_by_email TEXT")
        conn.execute("UPDATE conversations SET created_by_email=user_email WHERE created_by_email IS NULL OR created_by_email='' ")
    if not _has_column(conn, "conversations", "project_id"):
        conn.execute("ALTER TABLE conversations ADD COLUMN project_id TEXT")

    # ensure defaults
    conn.execute("UPDATE conversations SET scope='private' WHERE scope IS NULL OR scope='' ")

    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_conversations_user_email ON conversations(user_email)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_conversations_profile_id ON conversations(profile_id)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_conversations_updated_at ON conversations(updated_at)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_conversations_scope_ws ON conversations(scope, workspace_id)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_conversations_project ON conversations(project_id)")

    # messages
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS messages (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          conversation_id TEXT NOT NULL,
          role TEXT NOT NULL,
          content TEXT NOT NULL,
          created_at TEXT NOT NULL,
          FOREIGN KEY (conversation_id) REFERENCES conversations(id)
        )
        """
    )
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_messages_conversation_id ON messages(conversation_id)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_messages_created_at ON messages(created_at)")

    # projects (workspace scope)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS projects (
          id TEXT PRIMARY KEY,
          workspace_id TEXT NOT NULL,
          name TEXT NOT NULL,
          description TEXT,
          created_by_email TEXT,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          archived INTEGER DEFAULT 0,
          deleted INTEGER DEFAULT 0,
          deleted_at TEXT
        )
        """
    )
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_projects_ws ON projects(workspace_id)")
    _ensure_index(conn, "CREATE INDEX IF NOT EXISTS idx_projects_updated ON projects(updated_at)")


# ---------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------


def create_session(user_email: str, ttl_hours: int = 4, ttl_seconds: Optional[int] = None) -> Tuple[str, str]:
    """Create a new session and return (session_id, csrf_token)."""
    user_email = (user_email or "").strip().lower()
    if not user_email:
        raise ValueError("user_email is required")

    if ttl_seconds is not None:
        try:
            ts = int(ttl_seconds)
            if ts > 0:
                ttl_hours = max(1, int((ts + 3599) // 3600))
        except Exception:
            pass

    now = _utc_now_iso()
    exp_ts = datetime.utcnow().timestamp() + (max(1, int(ttl_hours)) * 3600)
    exp = datetime.utcfromtimestamp(exp_ts).isoformat(timespec="seconds") + "Z"

    sid = uuid.uuid4().hex
    csrf = _random_csrf()

    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            "INSERT INTO sessions(session_id, user_email, created_at, expires_at, csrf_token) VALUES(?,?,?,?,?)",
            (sid, user_email, now, exp, csrf),
        )
        conn.commit()
    finally:
        conn.close()

    return sid, csrf


# Backward-compat alias (old code expected a string)
def create_session_id(user_email: str, ttl_hours: int = 4) -> str:
    sid, _csrf = create_session(user_email=user_email, ttl_hours=ttl_hours)
    return sid


def get_session_email(session_id: str) -> Optional[str]:
    """Return user_email for a valid, non-expired session_id."""
    sid = (session_id or "").strip()
    if not sid:
        return None

    conn = _connect()
    try:
        _migrate_schema(conn)
        # delete expired
        now = _utc_now_iso()
        conn.execute("DELETE FROM sessions WHERE expires_at < ?", (now,))
        row = conn.execute("SELECT user_email FROM sessions WHERE session_id=?", (sid,)).fetchone()
        conn.commit()
        return str(row[0]) if row else None
    finally:
        conn.close()


def get_session_csrf(session_id: str) -> Optional[str]:
    """Return csrf_token for a session. If missing/empty, auto-generate and persist."""
    sid = (session_id or "").strip()
    if not sid:
        return None

    conn = _connect()
    try:
        _migrate_schema(conn)
        row = conn.execute("SELECT csrf_token FROM sessions WHERE session_id=?", (sid,)).fetchone()
        if not row:
            return None
        csrf = str(row[0] or "")
        if not csrf:
            csrf = _random_csrf()
            conn.execute("UPDATE sessions SET csrf_token=? WHERE session_id=?", (csrf, sid))
            conn.commit()
        return csrf
    finally:
        conn.close()


def delete_session(session_id: str) -> bool:
    sid = (session_id or "").strip()
    if not sid:
        return False
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute("DELETE FROM sessions WHERE session_id=?", (sid,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_sessions_by_email(user_email: str) -> int:
    email = (user_email or "").strip().lower()
    if not email:
        return 0
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute("DELETE FROM sessions WHERE user_email=?", (email,))
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Conversations (private)
# ---------------------------------------------------------------------


def create_conversation(conv_id: str, user_email: str, profile_id: str, title: str) -> Dict:
    """Create a private conversation (backward-compatible)."""
    conv_id = (conv_id or "").strip()
    user_email = (user_email or "").strip().lower()
    profile_id = (profile_id or "").strip()
    title = (title or "").strip() or "New chat"

    if not conv_id or not user_email or not profile_id:
        raise ValueError("conv_id, user_email and profile_id are required")

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            """
            INSERT INTO conversations(
              id, user_email, profile_id, title, created_at, updated_at,
              archived, deleted, deleted_at,
              scope, workspace_id, created_by_email, project_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (conv_id, user_email, profile_id, title, now, now, 0, 0, None, "private", None, user_email, None),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "id": conv_id,
        "user_email": user_email,
        "profile_id": profile_id,
        "title": title,
        "created_at": now,
        "updated_at": now,
        "archived": 0,
        "deleted": 0,
        "deleted_at": None,
        "scope": "private",
        "workspace_id": None,
        "created_by_email": user_email,
        "project_id": None,
    }


def list_conversations(
    user_email: str,
    profile_id: Optional[str] = None,
    limit: int = 80,
    status: str = "active",
) -> List[Dict]:
    """List private conversations for a user."""
    email = (user_email or "").strip().lower()
    if not email:
        return []

    profile_id = (profile_id or "").strip() or None
    lim = max(1, min(500, int(limit or 80)))
    st = (status or "active").strip().lower()
    if st not in ("active", "archived", "deleted"):
        st = "active"

    where = ["scope='private'", "user_email=?"]
    params: List[Any] = [email]

    if profile_id:
        where.append("profile_id=?")
        params.append(profile_id)

    if st == "active":
        where.append("archived=0")
        where.append("deleted=0")
    elif st == "archived":
        where.append("archived=1")
        where.append("deleted=0")
    elif st == "deleted":
        where.append("deleted=1")

    sql = (
        "SELECT id, user_email, profile_id, title, created_at, updated_at, archived, deleted, deleted_at, "
        "scope, workspace_id, created_by_email, project_id "
        "FROM conversations WHERE " + " AND ".join(where) + " ORDER BY updated_at DESC LIMIT ?"
    )
    params.append(lim)

    conn = _connect()
    try:
        _migrate_schema(conn)
        rows = conn.execute(sql, tuple(params)).fetchall()
        out = []
        for r in rows:
            out.append({k: r[k] for k in r.keys()})
        return out
    finally:
        conn.close()


def get_conversation(user_email: str, conversation_id: str) -> Optional[Dict]:
    """Get a private conversation by id (must belong to user)."""
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    if not email or not cid:
        return None

    conn = _connect()
    try:
        _migrate_schema(conn)
        row = conn.execute(
            """
            SELECT id, user_email, profile_id, title, created_at, updated_at, archived, deleted, deleted_at,
                   scope, workspace_id, created_by_email, project_id
            FROM conversations
            WHERE id=? AND user_email=? AND scope='private'
            """,
            (cid, email),
        ).fetchone()
        if not row:
            return None
        return {k: row[k] for k in row.keys()}
    finally:
        conn.close()


def update_conversation_title(user_email: str, conversation_id: str, title: str) -> bool:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    title = (title or "").strip()
    if not email or not cid or not title:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            "UPDATE conversations SET title=?, updated_at=? WHERE id=? AND user_email=? AND scope='private'",
            (title, now, cid, email),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def add_message(user_email: str, conversation_id: str, role: str, content: str) -> bool:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    role = (role or "").strip()
    content = (content or "").strip()
    if not email or not cid or not role or not content:
        return False

    # ensure conv exists and is private
    if not get_conversation(email, cid):
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            "INSERT INTO messages(conversation_id, role, content, created_at) VALUES(?,?,?,?)",
            (cid, role, content, now),
        )
        conn.execute(
            "UPDATE conversations SET updated_at=? WHERE id=? AND user_email=? AND scope='private'",
            (now, cid, email),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def list_messages(user_email: str, conversation_id: str, limit: int = 400) -> List[Dict]:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    if not email or not cid:
        return []

    if not get_conversation(email, cid):
        return []

    lim = max(1, min(2000, int(limit or 400)))
    conn = _connect()
    try:
        _migrate_schema(conn)
        rows = conn.execute(
            "SELECT id, conversation_id, role, content, created_at FROM messages WHERE conversation_id=? ORDER BY id ASC LIMIT ?",
            (cid, lim),
        ).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
    finally:
        conn.close()


def set_conversation_archived(user_email: str, conversation_id: str, archived: bool) -> bool:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    if not email or not cid:
        return False

    now = _utc_now_iso()
    val = 1 if archived else 0

    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            "UPDATE conversations SET archived=?, updated_at=? WHERE id=? AND user_email=? AND scope='private' AND deleted=0",
            (val, now, cid, email),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def soft_delete_conversation(user_email: str, conversation_id: str) -> bool:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    if not email or not cid:
        return False

    now = _utc_now_iso()

    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            """
            UPDATE conversations
            SET deleted=1, deleted_at=?, updated_at=?
            WHERE id=? AND user_email=? AND scope='private' AND deleted=0
            """,
            (now, now, cid, email),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def restore_conversation(user_email: str, conversation_id: str) -> bool:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    if not email or not cid:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            """
            UPDATE conversations
            SET deleted=0, deleted_at=NULL, archived=0, updated_at=?
            WHERE id=? AND user_email=? AND scope='private' AND deleted=1
            """,
            (now, cid, email),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def hard_delete_conversation(user_email: str, conversation_id: str) -> bool:
    email = (user_email or "").strip().lower()
    cid = (conversation_id or "").strip()
    if not email or not cid:
        return False

    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            "DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE id=? AND user_email=? AND scope='private')",
            (cid, email),
        )
        cur = conn.execute("DELETE FROM conversations WHERE id=? AND user_email=? AND scope='private'", (cid, email))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Workspace conversations (ws_*)
# ---------------------------------------------------------------------


def ws_create_conversation(
    conv_id: str,
    workspace_id: str,
    profile_id: str,
    created_by_email: str,
    title: str,
    project_id: Optional[str] = None,
) -> Dict:
    conv_id = (conv_id or "").strip()
    workspace_id = (workspace_id or "").strip()
    profile_id = (profile_id or "").strip()
    created_by_email = (created_by_email or "").strip().lower()
    title = (title or "").strip() or "New chat"
    project_id = (project_id or "").strip() or None

    if not conv_id or not workspace_id or not profile_id or not created_by_email:
        raise ValueError("conv_id, workspace_id, profile_id, created_by_email are required")

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            """
            INSERT INTO conversations(
              id, user_email, profile_id, title, created_at, updated_at,
              archived, deleted, deleted_at,
              scope, workspace_id, created_by_email, project_id
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (conv_id, created_by_email, profile_id, title, now, now, 0, 0, None, "workspace", workspace_id, created_by_email, project_id),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "id": conv_id,
        "user_email": created_by_email,
        "profile_id": profile_id,
        "title": title,
        "created_at": now,
        "updated_at": now,
        "archived": 0,
        "deleted": 0,
        "deleted_at": None,
        "scope": "workspace",
        "workspace_id": workspace_id,
        "created_by_email": created_by_email,
        "project_id": project_id,
    }


def ws_list_conversations(
    workspace_id: str,
    limit: int = 80,
    status: str = "active",
    project_id: str = "",
) -> List[Dict]:
    wsid = (workspace_id or "").strip()
    if not wsid:
        return []
    lim = max(1, min(500, int(limit or 80)))
    st = (status or "active").strip().lower()
    if st not in ("active", "archived", "deleted"):
        st = "active"

    where = ["scope='workspace'", "workspace_id=?"]
    params: List[Any] = [wsid]

    if st == "active":
        where += ["archived=0", "deleted=0"]
    elif st == "archived":
        where += ["archived=1", "deleted=0"]
    else:
        where += ["deleted=1"]

    pid = (project_id or "").strip()
    if pid:
        if pid == "none":
            where.append("(project_id IS NULL OR project_id='')")
        else:
            where.append("project_id=?")
            params.append(pid)

    sql = (
        "SELECT id, user_email, profile_id, title, created_at, updated_at, archived, deleted, deleted_at, "
        "scope, workspace_id, created_by_email, project_id "
        "FROM conversations WHERE " + " AND ".join(where) + " ORDER BY updated_at DESC LIMIT ?"
    )
    params.append(lim)

    conn = _connect()
    try:
        _migrate_schema(conn)
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
    finally:
        conn.close()


def ws_get_conversation(workspace_id: str, conversation_id: str) -> Optional[Dict]:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    if not wsid or not cid:
        return None

    conn = _connect()
    try:
        _migrate_schema(conn)
        row = conn.execute(
            """
            SELECT id, user_email, profile_id, title, created_at, updated_at, archived, deleted, deleted_at,
                   scope, workspace_id, created_by_email, project_id
            FROM conversations
            WHERE id=? AND workspace_id=? AND scope='workspace'
            """,
            (cid, wsid),
        ).fetchone()
        if not row:
            return None
        return {k: row[k] for k in row.keys()}
    finally:
        conn.close()


def ws_rename_conversation(workspace_id: str, conversation_id: str, title: str) -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    title = (title or "").strip()
    if not wsid or not cid or not title:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            "UPDATE conversations SET title=?, updated_at=? WHERE id=? AND workspace_id=? AND scope='workspace'",
            (title, now, cid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()

def ws_set_conversation_project(workspace_id: str, conversation_id: str, project_id: str = "") -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    pid = (project_id or "").strip()

    if not wsid or not cid:
        return False

    # empty => detach from project
    pid_db = pid if pid else None

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)

        # conversation must exist and be workspace-scoped
        row = conn.execute(
            "SELECT id FROM conversations WHERE id=? AND workspace_id=? AND scope='workspace' AND deleted=0",
            (cid, wsid),
        ).fetchone()
        if not row:
            return False

        # if setting a project, it must exist in the same workspace and not be deleted
        if pid_db:
            prow = conn.execute(
                "SELECT id FROM projects WHERE id=? AND workspace_id=? AND deleted=0",
                (pid_db, wsid),
            ).fetchone()
            if not prow:
                return False

        cur = conn.execute(
            "UPDATE conversations SET project_id=?, updated_at=? WHERE id=? AND workspace_id=? AND scope='workspace' AND deleted=0",
            (pid_db, now, cid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()



def ws_add_message(workspace_id: str, conversation_id: str, role: str, content: str) -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    role = (role or "").strip()
    content = (content or "").strip()
    if not wsid or not cid or not role or not content:
        return False

    if not ws_get_conversation(wsid, cid):
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            "INSERT INTO messages(conversation_id, role, content, created_at) VALUES(?,?,?,?)",
            (cid, role, content, now),
        )
        conn.execute(
            "UPDATE conversations SET updated_at=? WHERE id=? AND workspace_id=? AND scope='workspace'",
            (now, cid, wsid),
        )
        conn.commit()
        return True
    finally:
        conn.close()


def ws_list_messages(workspace_id: str, conversation_id: str, limit: int = 400) -> List[Dict]:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    if not wsid or not cid:
        return []

    if not ws_get_conversation(wsid, cid):
        return []

    lim = max(1, min(2000, int(limit or 400)))
    conn = _connect()
    try:
        _migrate_schema(conn)
        rows = conn.execute(
            "SELECT id, conversation_id, role, content, created_at FROM messages WHERE conversation_id=? ORDER BY id ASC LIMIT ?",
            (cid, lim),
        ).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
    finally:
        conn.close()


def ws_archive_conversation(workspace_id: str, conversation_id: str, archived: bool) -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    if not wsid or not cid:
        return False

    now = _utc_now_iso()
    val = 1 if archived else 0

    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            "UPDATE conversations SET archived=?, updated_at=? WHERE id=? AND workspace_id=? AND scope='workspace' AND deleted=0",
            (val, now, cid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ws_soft_delete_conversation(workspace_id: str, conversation_id: str) -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    if not wsid or not cid:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            """
            UPDATE conversations
            SET deleted=1, deleted_at=?, updated_at=?
            WHERE id=? AND workspace_id=? AND scope='workspace' AND deleted=0
            """,
            (now, now, cid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ws_restore_conversation(workspace_id: str, conversation_id: str) -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    if not wsid or not cid:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            """
            UPDATE conversations
            SET deleted=0, deleted_at=NULL, archived=0, updated_at=?
            WHERE id=? AND workspace_id=? AND scope='workspace' AND deleted=1
            """,
            (now, cid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ws_hard_delete_conversation(workspace_id: str, conversation_id: str) -> bool:
    wsid = (workspace_id or "").strip()
    cid = (conversation_id or "").strip()
    if not wsid or not cid:
        return False

    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            "DELETE FROM messages WHERE conversation_id IN (SELECT id FROM conversations WHERE id=? AND workspace_id=? AND scope='workspace')",
            (cid, wsid),
        )
        cur = conn.execute("DELETE FROM conversations WHERE id=? AND workspace_id=? AND scope='workspace'", (cid, wsid))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Projects (workspace)
# ---------------------------------------------------------------------


def ws_create_project(
    project_id: str,
    workspace_id: str,
    name: str,
    description: str = "",
    created_by_email: str = "",
) -> Dict:
    pid = (project_id or "").strip() or uuid.uuid4().hex
    wsid = (workspace_id or "").strip()
    name = (name or "").strip()
    description = (description or "").strip()
    created_by_email = (created_by_email or "").strip().lower()

    if not wsid or not name:
        raise ValueError("workspace_id and name are required")

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        conn.execute(
            """
            INSERT INTO projects(id, workspace_id, name, description, created_by_email, created_at, updated_at, archived, deleted, deleted_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (pid, wsid, name, description or None, created_by_email or None, now, now, 0, 0, None),
        )
        conn.commit()
    finally:
        conn.close()

    return {
        "id": pid,
        "workspace_id": wsid,
        "name": name,
        "description": description,
        "created_by_email": created_by_email,
        "created_at": now,
        "updated_at": now,
        "archived": 0,
        "deleted": 0,
        "deleted_at": None,
    }


def ws_list_projects(workspace_id: str, limit: int = 200, status: str = "active") -> List[Dict]:
    wsid = (workspace_id or "").strip()
    if not wsid:
        return []

    lim = max(1, min(1000, int(limit or 200)))
    st = (status or "active").strip().lower()
    if st not in ("active", "archived", "deleted"):
        st = "active"

    where = ["workspace_id=?"]
    params: List[Any] = [wsid]

    if st == "active":
        where += ["archived=0", "deleted=0"]
    elif st == "archived":
        where += ["archived=1", "deleted=0"]
    else:
        where += ["deleted=1"]

    sql = (
        "SELECT id, workspace_id, name, description, created_by_email, created_at, updated_at, archived, deleted, deleted_at "
        "FROM projects WHERE " + " AND ".join(where) + " ORDER BY updated_at DESC LIMIT ?"
    )
    params.append(lim)

    conn = _connect()
    try:
        _migrate_schema(conn)
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [{k: r[k] for k in r.keys()} for r in rows]
    finally:
        conn.close()

def ws_get_project(workspace_id: str, project_id: str):
    wsid = (workspace_id or "").strip()
    pid = (project_id or "").strip()
    if not wsid or not pid:
        return None

    conn = _connect()
    try:
        _migrate_schema(conn)
        row = conn.execute(
            """
            SELECT id, workspace_id, name, description, created_by_email, created_at, updated_at, archived, deleted, deleted_at
            FROM projects
            WHERE id=? AND workspace_id=?
            """,
            (pid, wsid),
        ).fetchone()
        if not row:
            return None
        return {k: row[k] for k in row.keys()}
    finally:
        conn.close()


def ws_update_project(workspace_id: str, project_id: str, name: str = '', description: str = '') -> bool:
    wsid = (workspace_id or "").strip()
    pid = (project_id or "").strip()
    if not wsid or not pid:
        return False

    # allow empty description, but not empty name if provided
    name = (name or '').strip()
    description = (description or '').strip()

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        # ensure exists and not deleted
        row = conn.execute(
            "SELECT id FROM projects WHERE id=? AND workspace_id=? AND deleted=0",
            (pid, wsid),
        ).fetchone()
        if not row:
            return False

        sets = []
        params = []
        if name:
            sets.append('name=?')
            params.append(name)
        sets.append('description=?')
        params.append(description or None)
        sets.append('updated_at=?')
        params.append(now)
        params += [pid, wsid]

        sql = 'UPDATE projects SET ' + ', '.join(sets) + ' WHERE id=? AND workspace_id=? AND deleted=0'
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()



def ws_set_project_archived(workspace_id: str, project_id: str, archived: bool) -> bool:
    wsid = (workspace_id or "").strip()
    pid = (project_id or "").strip()
    if not wsid or not pid:
        return False

    now = _utc_now_iso()
    val = 1 if archived else 0
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            "UPDATE projects SET archived=?, updated_at=? WHERE id=? AND workspace_id=? AND deleted=0",
            (val, now, pid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ws_soft_delete_project(workspace_id: str, project_id: str) -> bool:
    wsid = (workspace_id or "").strip()
    pid = (project_id or "").strip()
    if not wsid or not pid:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            """
            UPDATE projects
            SET deleted=1, deleted_at=?, updated_at=?
            WHERE id=? AND workspace_id=? AND deleted=0
            """,
            (now, now, pid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ws_restore_project(workspace_id: str, project_id: str) -> bool:
    wsid = (workspace_id or "").strip()
    pid = (project_id or "").strip()
    if not wsid or not pid:
        return False

    now = _utc_now_iso()
    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute(
            "UPDATE projects SET deleted=0, deleted_at=NULL, archived=0, updated_at=? WHERE id=? AND workspace_id=? AND deleted=1",
            (now, pid, wsid),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def ws_hard_delete_project(workspace_id: str, project_id: str) -> bool:
    wsid = (workspace_id or "").strip()
    pid = (project_id or "").strip()
    if not wsid or not pid:
        return False

    conn = _connect()
    try:
        _migrate_schema(conn)
        cur = conn.execute("DELETE FROM projects WHERE id=? AND workspace_id=?", (pid, wsid))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


# ---------------------------------------------------------------------
# Helpers / history pairs (unchanged)
# ---------------------------------------------------------------------


def build_history_pairs(messages: List[Dict], max_pairs: int = 6) -> List[Tuple[str, str]]:
    """Build (user, assistant) pairs from message list."""
    max_pairs = max(1, int(max_pairs or 6))
    pairs: List[Tuple[str, str]] = []

    user_buf: Optional[str] = None
    for m in messages:
        role = str(m.get("role") or "")
        content = str(m.get("content") or "")
        if role == "user":
            user_buf = content
        elif role == "assistant" and user_buf is not None:
            pairs.append((user_buf, content))
            user_buf = None

    return pairs[-max_pairs:]


# ---------------------------------------------------------------------
# Backward-compatible names (used in web_app.py)
# ---------------------------------------------------------------------

# conversation wrappers
create_conversation_db = create_conversation
list_conversations_db = list_conversations
get_conversation_db = get_conversation
update_conversation_title_db = update_conversation_title
add_message_db = add_message
list_messages_db = list_messages

# session wrappers
get_session_email_db = get_session_email


if __name__ == "__main__":
    init_chat_db()
    print("OK - chat_db ready at", DB_PATH)


# ---------------------------------------------------------------------
# Backward compatibility
# ---------------------------------------------------------------------

def init_db(*args, **kwargs):
    """Backward-compatible alias (web_app imports init_db)."""
    return init_chat_db()

def update_session_email(session_id: str, new_user_email: str) -> None:
    """Update the email attached to an existing session."""
    sid = (session_id or "").strip()
    newe = (new_user_email or "").strip().lower()
    if not sid or not newe:
        return
    conn = _connect()
    try:
        conn.execute("UPDATE sessions SET user_email=? WHERE session_id=?", (newe, sid))
        conn.commit()
    finally:
        conn.close()


def migrate_user_email(old_email: str, new_email: str) -> None:
    """Migrate ownership/attribution fields from old_email to new_email."""
    olde = (old_email or "").strip().lower()
    newe = (new_email or "").strip().lower()
    if not olde or not newe or olde == newe:
        return
    conn = _connect()
    try:
        # sessions (per non slogare gli altri device automaticamente)
        conn.execute("UPDATE sessions SET user_email=? WHERE user_email=?", (newe, olde))

        # conversations ownership + attribution
        conn.execute("UPDATE conversations SET user_email=? WHERE user_email=?", (newe, olde))
        if _has_column(conn, "conversations", "created_by_email"):
            conn.execute("UPDATE conversations SET created_by_email=? WHERE created_by_email=?", (newe, olde))

        # projects attribution (se esiste colonna)
        if _table_exists(conn, "projects") and _has_column(conn, "projects", "created_by_email"):
            conn.execute("UPDATE projects SET created_by_email=? WHERE created_by_email=?", (newe, olde))

        conn.commit()
    finally:
        conn.close()


def ws_set_conversation_project(*args, **kwargs):
    # V6.2 expects this for workspace conversation -> project binding
    return False

