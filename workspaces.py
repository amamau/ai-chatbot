# -*- coding: utf-8 -*-
"""workspaces.py

File-backed workspace + membership + invite tokens (MVP).

No external dependencies.

Storage: data/workspaces.json

Schema (v2):
{
  "version": 2,
  "workspaces": [
    {
      "id": "ws__...",
      "name": "Tobia",
      "owner_user_id": "u__1",
      "profile_id": "tobia",
      "status": "active"|"archived"|"deleted",
      "created_at": "...Z",
      "updated_at": "...Z",
      "archived_at": "...Z"|null,
      "deleted_at": "...Z"|null,
      "members": [
        {"user_id": "u__1", "role": "owner", "added_at": "...Z"}
      ]
    }
  ],
  "invites": [...]
}

Compatibility:
- Functions from the earlier MVP are preserved:
  ensure_default_workspaces, list_user_workspaces, list_members,
  create_workspace, create_invite, get_invite, accept_invite, remove_member

This file is intentionally conservative: no hard-delete; "deleted" is a status.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

WORKSPACES_FILE = DATA_DIR / "workspaces.json"


def _now_utc_iso() -> str:
    return datetime.utcnow().replace(tzinfo=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _load_store(path: Optional[Path] = None) -> Dict[str, Any]:
    p = path or WORKSPACES_FILE
    if not p.exists():
        return {"version": 2, "workspaces": [], "invites": []}
    try:
        with p.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {"version": 2, "workspaces": [], "invites": []}
        # normalize
        data.setdefault("version", 2)
        data.setdefault("workspaces", [])
        data.setdefault("invites", [])
        if not isinstance(data.get("workspaces"), list):
            data["workspaces"] = []
        if not isinstance(data.get("invites"), list):
            data["invites"] = []
        return data
    except Exception:
        return {"version": 2, "workspaces": [], "invites": []}


def _save_store(data: Dict[str, Any], path: Optional[Path] = None) -> None:
    p = path or WORKSPACES_FILE
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    tmp.replace(p)


def _find_ws(store: Dict[str, Any], workspace_id: str) -> Optional[Dict[str, Any]]:
    wid = str(workspace_id or "").strip()
    if not wid:
        return None
    for ws in store.get("workspaces", []) or []:
        if str(ws.get("id") or "") == wid:
            return ws
    return None


def _user_role_in_ws(ws: Dict[str, Any], user_id: str) -> Optional[str]:
    uid = str(user_id or "").strip()
    for m in ws.get("members", []) or []:
        if str(m.get("user_id") or "") == uid:
            return str(m.get("role") or "member")
    return None


def _cleanup_expired_invites(store: Dict[str, Any]) -> None:
    invites = store.get("invites", []) or []
    out = []
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    for inv in invites:
        exp = str(inv.get("expires_at") or "")
        if not exp:
            continue
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except Exception:
            continue
        if exp_dt > now:
            out.append(inv)
    store["invites"] = out


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def ensure_default_workspaces(users: List[Dict[str, Any]], path: Optional[Path] = None) -> None:
    """Idempotent: ensure each user has a default workspace."""
    store = _load_store(path)
    changed = False

    # legacy support: if file was version 1, upgrade shape
    if store.get("version") != 2:
        store["version"] = 2
        store.setdefault("workspaces", [])
        store.setdefault("invites", [])
        changed = True

    existing_by_owner: Dict[str, Dict[str, Any]] = {}
    for ws in store.get("workspaces", []) or []:
        oid = str(ws.get("owner_user_id") or "")
        if oid and oid not in existing_by_owner:
            existing_by_owner[oid] = ws

        # normalize workspace fields
        if "status" not in ws:
            ws["status"] = "active"
            changed = True
        if "profile_id" not in ws:
            ws["profile_id"] = ""
            changed = True
        ws.setdefault("created_at", _now_utc_iso())
        ws.setdefault("updated_at", ws.get("created_at"))
        ws.setdefault("archived_at", None)
        ws.setdefault("deleted_at", None)
        ws.setdefault("members", [])

    for u in (users or []):
        uid = str(u.get("id") or "").strip()
        if not uid:
            continue
        if uid in existing_by_owner:
            # ensure owner membership exists
            ws = existing_by_owner[uid]
            if not _user_role_in_ws(ws, uid):
                ws.setdefault("members", []).append({"user_id": uid, "role": "owner", "added_at": _now_utc_iso()})
                ws["updated_at"] = _now_utc_iso()
                changed = True
            # ensure profile_id (best-effort)
            if not str(ws.get("profile_id") or "").strip():
                pid = str(u.get("profile_id") or "").strip()
                if pid:
                    ws["profile_id"] = pid
                    ws["updated_at"] = _now_utc_iso()
                    changed = True
            # backfill profile_id for ALL workspaces owned by this user (legacy workspaces)
            pid = str(u.get("profile_id") or "").strip()
            if pid:
                for ws_any in store.get("workspaces", []) or []:
                    if str(ws_any.get("owner_user_id") or "") == uid and not str(ws_any.get("profile_id") or "").strip():
                        ws_any["profile_id"] = pid
                        ws_any["updated_at"] = _now_utc_iso()
                        changed = True

            continue

        # create default workspace
        name = str(u.get("name") or "Workspace").strip() or "Workspace"
        pid = str(u.get("profile_id") or "").strip()
        ws_id = "ws__" + secrets.token_hex(8)
        now = _now_utc_iso()
        ws = {
            "id": ws_id,
            "name": name,
            "owner_user_id": uid,
            "profile_id": pid,
            "status": "active",
            "created_at": now,
            "updated_at": now,
            "archived_at": None,
            "deleted_at": None,
            "members": [{"user_id": uid, "role": "owner", "added_at": now}],
        }
        store.setdefault("workspaces", []).append(ws)
        existing_by_owner[uid] = ws
        changed = True

    _cleanup_expired_invites(store)
    if changed:
        _save_store(store, path)


def get_workspace(workspace_id: str, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    store = _load_store(path)
    return _find_ws(store, workspace_id)


def list_user_workspaces(user_id: str, path: Optional[Path] = None, *, include_archived: bool = True, include_deleted: bool = False) -> List[Tuple[Dict[str, Any], str]]:
    """Return list of (workspace, role) for a given user.

    Backward compatible: older callers only passed (user_id).

    Defaults:
    - include_archived=True (so user can see archived workspaces in UI)
    - include_deleted=False
    """
    uid = str(user_id or "").strip()
    if not uid:
        return []

    store = _load_store(path)
    out: List[Tuple[Dict[str, Any], str]] = []
    for ws in store.get("workspaces", []) or []:
        status = str(ws.get("status") or "active").lower().strip()
        if status == "deleted" and not include_deleted:
            continue
        if status == "archived" and not include_archived:
            continue
        role = _user_role_in_ws(ws, uid)
        if role:
            out.append((ws, role))
    # stable sort: active first, then archived, then deleted
    prio = {"active": 0, "archived": 1, "deleted": 2}
    out.sort(key=lambda t: (prio.get(str(t[0].get("status") or "active"), 9), str(t[0].get("name") or "")))
    return out


def list_members(workspace_id: str, path: Optional[Path] = None) -> List[Dict[str, Any]]:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return []
    return list(ws.get("members", []) or [])


def get_user_role(workspace_id: str, user_id: str, path: Optional[Path] = None) -> Optional[str]:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return None
    return _user_role_in_ws(ws, user_id)


def create_workspace(name: str, owner_user_id: str, path: Optional[Path] = None, profile_id: str = "") -> Dict[str, Any]:
    store = _load_store(path)
    ws_id = "ws__" + secrets.token_hex(8)
    now = _now_utc_iso()
    ws = {
        "id": ws_id,
        "name": str(name or "Workspace").strip() or "Workspace",
        "owner_user_id": str(owner_user_id or "").strip(),
        "profile_id": str(profile_id or "").strip(),
        "status": "active",
        "created_at": now,
        "updated_at": now,
        "archived_at": None,
        "deleted_at": None,
        "members": [{"user_id": str(owner_user_id or "").strip(), "role": "owner", "added_at": now}],
    }
    store.setdefault("workspaces", []).append(ws)
    _save_store(store, path)
    return ws


def update_workspace_name(workspace_id: str, new_name: str, actor_user_id: str = "", path=None) -> bool:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return False

    nn = str(new_name or "").strip()
    if not nn:
        return False

    if actor_user_id:
        if str(ws.get("owner_user_id") or "") != str(actor_user_id or ""):
            return False

    ws["name"] = nn
    ws["updated_at"] = _now_utc_iso()
    _save_store(store, path)
    return True


def set_workspace_profile_id(workspace_id: str, profile_id: str, actor_user_id: str = "", path: Optional[Path] = None) -> bool:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return False

    pid = str(profile_id or "").strip()
    if not pid:
        return False

    # owner-only if actor provided
    if actor_user_id:
        if str(ws.get("owner_user_id") or "") != str(actor_user_id or ""):
            return False

    ws["profile_id"] = pid
    ws["updated_at"] = _now_utc_iso()
    _save_store(store, path)
    return True



def archive_workspace(workspace_id: str, actor_user_id: str, path: Optional[Path] = None) -> bool:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return False
    if str(ws.get("owner_user_id") or "") != str(actor_user_id or ""):
        return False
    if str(ws.get("status") or "active") == "deleted":
        return False
    ws["status"] = "archived"
    ws["archived_at"] = _now_utc_iso()
    ws["updated_at"] = _now_utc_iso()
    _save_store(store, path)
    return True


def restore_workspace(workspace_id: str, actor_user_id: str, path: Optional[Path] = None) -> bool:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return False
    if str(ws.get("owner_user_id") or "") != str(actor_user_id or ""):
        return False
    if str(ws.get("status") or "active") == "deleted":
        return False
    ws["status"] = "active"
    ws["archived_at"] = None
    ws["updated_at"] = _now_utc_iso()
    _save_store(store, path)
    return True


def delete_workspace(workspace_id: str, actor_user_id: str, path: Optional[Path] = None) -> bool:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return False
    if str(ws.get("owner_user_id") or "") != str(actor_user_id or ""):
        return False
    ws["status"] = "deleted"
    ws["deleted_at"] = _now_utc_iso()
    ws["updated_at"] = _now_utc_iso()
    _save_store(store, path)
    return True


def create_invite(
    workspace_id: str,
    email: str,
    invited_by_user_id: str,
    ttl_hours: int = 48,
    path: Optional[Path] = None,
) -> str:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        raise ValueError("Workspace not found")
    if str(ws.get("status") or "active") != "active":
        raise ValueError("Workspace is not active")

    # only owner can invite
    if str(ws.get("owner_user_id") or "") != str(invited_by_user_id or ""):
        raise PermissionError("Only owner can invite")

    token = secrets.token_urlsafe(24)
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    exp = now + timedelta(hours=int(ttl_hours or 48))
    inv = {
        "token": token,
        "workspace_id": str(workspace_id or "").strip(),
        "email": str(email or "").strip().lower(),
        "invited_by_user_id": str(invited_by_user_id or "").strip(),
        "created_at": now.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "expires_at": exp.isoformat(timespec="seconds").replace("+00:00", "Z"),
        "used": False,
        "used_at": None,
        "accepted_by_user_id": None,
        "accepted_by_email": None,
    }
    store.setdefault("invites", []).append(inv)
    _cleanup_expired_invites(store)
    _save_store(store, path)
    return token


def get_invite(token: str, path: Optional[Path] = None) -> Optional[Dict[str, Any]]:
    store = _load_store(path)
    _cleanup_expired_invites(store)
    tok = str(token or "").strip()
    if not tok:
        return None
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    for inv in store.get("invites", []) or []:
        if str(inv.get("token") or "") != tok:
            continue
        if bool(inv.get("used")):
            return None
        exp = str(inv.get("expires_at") or "")
        try:
            exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
        except Exception:
            return None
        if exp_dt <= now:
            return None
        return inv
    return None

def list_pending_invites(workspace_id: str, path: Optional[Path] = None) -> List[Dict[str, Any]]:
    """Return non-expired, non-used invites for a workspace (owner view)."""
    wsid = str(workspace_id or '').strip()
    if not wsid:
        return []
    store = _load_store(path)
    _cleanup_expired_invites(store)
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    out = []
    for inv in store.get('invites', []) or []:
        if str(inv.get('workspace_id') or '') != wsid:
            continue
        if bool(inv.get('used')):
            continue
        exp = str(inv.get('expires_at') or '')
        try:
            exp_dt = datetime.fromisoformat(exp.replace('Z', '+00:00'))
        except Exception:
            continue
        if exp_dt <= now:
            continue
        out.append(inv)
    # soonest-expiring first
    def _key(i):
        try:
            return datetime.fromisoformat(str(i.get('expires_at') or '').replace('Z', '+00:00'))
        except Exception:
            return now
    out.sort(key=_key)
    return out


def revoke_invite(token: str, actor_user_id: str, path: Optional[Path] = None) -> bool:
    """Revoke a pending invite (owner only)."""
    tok = str(token or '').strip()
    uid = str(actor_user_id or '').strip()
    if not tok or not uid:
        return False

    store = _load_store(path)
    _cleanup_expired_invites(store)

    inv = None
    for it in store.get('invites', []) or []:
        if str(it.get('token') or '') == tok:
            inv = it
            break
    if not inv:
        return False

    # must be workspace owner
    wsid = str(inv.get('workspace_id') or '').strip()
    ws = _find_ws(store, wsid)
    if not ws:
        return False
    if str(ws.get('owner_user_id') or '') != uid:
        return False

    if bool(inv.get('used')):
        return False

    inv['used'] = True
    inv['used_at'] = _now_utc_iso()
    inv['accepted_by_user_id'] = 'revoked'
    inv['accepted_by_email'] = None
    inv['revoked_by_user_id'] = uid
    inv['revoked_at'] = _now_utc_iso()

    _save_store(store, path)
    return True

def accept_invite(token: str, user_id: str, user_email: str, path: Optional[Path] = None) -> str:
    store = _load_store(path)
    _cleanup_expired_invites(store)

    inv = None
    for it in store.get("invites", []) or []:
        if str(it.get("token") or "") == str(token or "").strip():
            inv = it
            break
    if not inv:
        raise ValueError("Invite not found")

    if bool(inv.get("used")):
        raise ValueError("Invite already used")

    # validate expiration
    now = datetime.utcnow().replace(tzinfo=timezone.utc)
    exp = str(inv.get("expires_at") or "")
    exp_dt = datetime.fromisoformat(exp.replace("Z", "+00:00"))
    if exp_dt <= now:
        raise ValueError("Invite expired")

    ws_id = str(inv.get("workspace_id") or "").strip()
    ws = _find_ws(store, ws_id)
    if not ws:
        raise ValueError("Workspace not found")
    if str(ws.get("status") or "active") != "active":
        raise ValueError("Workspace is not active")

    uid = str(user_id or "").strip()
    if not uid:
        raise ValueError("Invalid user")

    # already a member? => just mark used
    role = _user_role_in_ws(ws, uid)
    if not role:
        ws.setdefault("members", []).append({"user_id": uid, "role": "member", "added_at": _now_utc_iso()})
        ws["updated_at"] = _now_utc_iso()

    inv["used"] = True
    inv["used_at"] = _now_utc_iso()
    inv["accepted_by_user_id"] = uid
    inv["accepted_by_email"] = str(user_email or "").strip().lower()

    _save_store(store, path)
    return ws_id


def remove_member(workspace_id: str, user_id: str, path: Optional[Path] = None) -> bool:
    store = _load_store(path)
    ws = _find_ws(store, workspace_id)
    if not ws:
        return False
    uid = str(user_id or "").strip()
    if not uid:
        return False
    # cannot remove owner
    if str(ws.get("owner_user_id") or "") == uid:
        return False
    members = ws.get("members", []) or []
    before = len(members)
    ws["members"] = [m for m in members if str(m.get("user_id") or "") != uid]
    if len(ws["members"]) == before:
        return False
    ws["updated_at"] = _now_utc_iso()
    _save_store(store, path)
    return True
