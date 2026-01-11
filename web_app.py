# -*- coding: utf-8 -*-
from __future__ import annotations

import html as html_escape
import json
import secrets
import subprocess
import textwrap
import uuid
import traceback
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Optional, List, Tuple
from email.message import EmailMessage
from urllib.parse import parse_qs



from fastapi import FastAPI, Form, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from chat_db import (
    init_db as init_chat_db,
    create_conversation as db_create_conversation,
    list_conversations as db_list_conversations,
    get_conversation as db_get_conversation,
    list_messages as db_list_messages,
    add_message as db_add_message,
    build_history_pairs as db_build_history_pairs,
    create_session as db_create_session,
    get_session_email as db_get_session_email,
    delete_session as db_delete_session,
    update_conversation_title as db_update_conversation_title,
    set_conversation_archived,
    soft_delete_conversation,
    restore_conversation,
    hard_delete_conversation,

    # session management
    delete_sessions_by_email as db_delete_sessions_by_email,
    update_session_email as db_update_session_email,
    migrate_user_email as db_migrate_user_email,

    get_session_csrf as db_get_session_csrf,

    # workspace conversations + projects
    ws_create_conversation,
    ws_list_conversations,
    ws_get_conversation,
    ws_rename_conversation,
    ws_set_conversation_project,
    ws_list_messages,
    ws_add_message,
    ws_archive_conversation,
    ws_soft_delete_conversation,
    ws_restore_conversation,
    ws_hard_delete_conversation,

    ws_create_project,
    ws_list_projects,
    ws_get_project,
    ws_update_project,
    ws_set_project_archived,
    ws_soft_delete_project,
    ws_restore_project,
    ws_hard_delete_project,

)

from audit import audit_event
from workspaces import (
    ensure_default_workspaces,
    list_user_workspaces,
    create_workspace,
    create_invite,
    get_invite,
    accept_invite,
    remove_member,
    list_members,
    get_workspace,
    get_user_role,
    update_workspace_name,
    archive_workspace,
    delete_workspace,
    restore_workspace,
    list_pending_invites,
    revoke_invite,
    set_workspace_profile_id,

)

from two_factor import (
    generate_base32_secret,
    otpauth_uri,
    generate_backup_codes,
    backup_codes_to_hashes,
    verify_2fa_code,
)



# -------------------------------------------------------------------
# Paths / config
# -------------------------------------------------------------------

try:
    from config import PROFILES_DIR, MEMORY_DIR, USERS_FILE  # type: ignore
    try:
        from config import DATA_DIR  # type: ignore
    except Exception:
        # Derive DATA_DIR from USERS_FILE if config does not export it
        DATA_DIR = Path(USERS_FILE).resolve().parent
except Exception:  # fallback if config does not expose them
    BASE_DIR = Path(__file__).resolve().parent
    DATA_DIR = BASE_DIR / "data"
    PROFILES_DIR = DATA_DIR / "profiles"
    MEMORY_DIR = DATA_DIR / "memory"
    USERS_FILE = DATA_DIR / "users.json"


CHAT_HISTORY_DIR = DATA_DIR / "chat_history"
CHAT_HISTORY_DIR.mkdir(parents=True, exist_ok=True)

from tokens import list_tokens  # we reuse the same JSON structure as owner_console
from accounts import get_user_by_email, verify_password
from profiles import load_profile
from memory import get_memory_excerpt, append_memory


# -------------------------------------------------------------------
# Simple user store helpers (web layer uses accounts.py)
# -------------------------------------------------------------------
# (tutta la logica reale sta in accounts.py: _load_users, save_users,
#  create_user, get_user_by_email, verify_password, ecc.)

# -------------------------------------------------------------------
# OTP + session in-memory stores
# -------------------------------------------------------------------


@dataclass
class PendingOTP:
    email: str
    code: str
    expires_at: datetime


OTP_STORE: Dict[str, PendingOTP] = {}
SESSION_STORE: Dict[str, Dict] = {}  # session_id -> {"email": ..., "created_at": ...}
@dataclass
class AccountOTP:
    email: str           # email attuale
    new_email: str       # nuova email proposta
    purpose: str         # "email_change"
    code: str
    expires_at: datetime


ACCOUNT_OTP_STORE: Dict[str, AccountOTP] = {}



def create_otp_for_email(email: str) -> str:
    code = f"{secrets.randbelow(1_000_000):06d}"
    otp_id = secrets.token_urlsafe(16)
    normalized_email = email.strip().lower()

    OTP_STORE[otp_id] = PendingOTP(
        email=normalized_email,
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )

    # Log interno per debug / sviluppo
    print(f"[auth] OTP for {normalized_email} is {code}")

    send_access_otp_email(normalized_email, code)
    return otp_id


def consume_otp(otp_id: str, code: str) -> Optional[str]:
    entry = OTP_STORE.get(otp_id)
    if not entry:
        return None
    if datetime.utcnow() > entry.expires_at:
        OTP_STORE.pop(otp_id, None)
        return None
    if code.strip() != entry.code:
        return None
    OTP_STORE.pop(otp_id, None)
    return entry.email

def create_account_email_change_otp(current_email: str, new_email: str) -> Tuple[str, str]:
    f"""
    Genera un OTP dedicato al cambio email dell'account.
    Ritorna (otp_id, code) per poter inviare la mail.
    """
    code = f"{secrets.randbelow(1_000_000):06d}"
    otp_id = secrets.token_urlsafe(16)
    entry = AccountOTP(
        email=current_email.strip().lower(),
        new_email=new_email.strip().lower(),
        purpose="email_change",
        code=code,
        expires_at=datetime.utcnow() + timedelta(minutes=10),
    )
    ACCOUNT_OTP_STORE[otp_id] = entry
    print(f"[account] OTP email change {entry.email} -> {entry.new_email} = {code}")
    return otp_id, code


def consume_account_email_change_otp(otp_id: str, code: str) -> Optional[Tuple[str, str]]:
    entry = ACCOUNT_OTP_STORE.get(otp_id)
    if not entry:
        return None
    if entry.purpose != "email_change":
        return None
    if datetime.utcnow() > entry.expires_at:
        ACCOUNT_OTP_STORE.pop(otp_id, None)
        return None
    if code.strip() != entry.code:
        return None
    ACCOUNT_OTP_STORE.pop(otp_id, None)
    return entry.email, entry.new_email



def create_session(email: str) -> Tuple[str, str]:
    """Create session and return (session_id, csrf_token).
    Back-compat for different db_create_session signatures/return types.
    """
    email_clean = (email or "").strip().lower()
    if not email_clean:
        raise ValueError("email is required")

    # 1) call DB helper with signature compatibility
    try:
        res = db_create_session(user_email=email_clean, ttl_hours=4)  # NEW (chat_db.py V5)
    except TypeError:
        res = db_create_session(user_email=email_clean, ttl_seconds=4 * 60 * 60)  # OLD fallback

    # 2) return type compatibility
    if isinstance(res, (tuple, list)) and len(res) == 2:
        sid, csrf = res[0], res[1]
        return str(sid), str(csrf)

    sid = str(res)
    csrf = _random_csrf_cookie()
    return sid, csrf

def get_email_from_request(request: Request) -> Optional[str]:
    sid = request.cookies.get("ai_session")
    if not sid:
        return None
    return db_get_session_email(session_id=sid)

def _normalize_email_addr(email: str) -> str:
    return (email or "").strip().lower()


def _email_slug(email: str) -> str:
    return _normalize_email_addr(email).replace("@", "_at_").replace(".", "_")


def _safe_next_url(next_url: str) -> str:
    """Allow only internal redirects."""
    n = (next_url or "").strip()
    if not n:
        return ""
    if not n.startswith("/"):
        return ""
    if n.startswith("//"):
        return ""
    if "://" in n:
        return ""
    return n


def _load_users_for_web() -> List[Dict]:
    """
    Carica users.json usando i path definiti in accounts.py.
    Non tocca la logica di accounts.
    """
    try:
        import accounts as acc_mod  # type: ignore
        path = getattr(acc_mod, "USERS_FILE_MAIN", None)
        if path is None or not path.exists():
            path = getattr(acc_mod, "USERS_FILE_FALLBACK", None)
        if not path or not path.exists():
            return []
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print("[account] _load_users_for_web error:", e)
        return []


def _save_users_for_web(users: List[Dict]) -> None:
    """
    Salva users.json usando gli stessi path di accounts.py.
    """
    try:
        import accounts as acc_mod  # type: ignore
        path = getattr(acc_mod, "USERS_FILE_MAIN", None)
        if path is None:
            path = getattr(acc_mod, "USERS_FILE_FALLBACK", None)
        if not path:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            json.dump(users, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print("[account] _save_users_for_web error:", e)


# -------------------------------------------------------------------
# Workspace bootstrap (idempotente)
# -------------------------------------------------------------------

try:
    ensure_default_workspaces(_load_users_for_web())
except Exception as _exc:
    print("[workspace] ensure_default_workspaces failed:", _exc)


def append_chat_history(email: str, role: str, text: str, profile_id: str) -> None:
    """
    Appende un messaggio (user/assistant) alla history JSONL dell'utente.
    """
    if not email or not text:
        return
    try:
        CHAT_HISTORY_DIR.mkdir(parents=True, exist_ok=True)
        slug = _email_slug(email)
        path = CHAT_HISTORY_DIR / f"{slug}.jsonl"
        rec = {
            "ts": datetime.utcnow().isoformat(timespec="seconds") + "Z",
            "role": role,
            "text": text,
            "profile_id": profile_id,
        }
        with path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        print("[history] append_chat_history error:", e)


def load_chat_history(email: str, limit: int = 80) -> List[Dict]:
    """
    Ritorna gli ultimi N record di history per l'utente.
    """
    slug = _email_slug(email)
    path = CHAT_HISTORY_DIR / f"{slug}.jsonl"
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        lines = lines[-limit:]
        out: List[Dict] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        return out
    except Exception as e:
        print("[history] load_chat_history error:", e)
        return []

def _title_from_msg(text: str) -> str:
    t = " ".join((text or "").strip().split())
    if not t:
        return "New chat"
    return t if len(t) <= 60 else (t[:59].rstrip() + "...")




# -------------------------------------------------------------------
# Email helpers (using msmtp "default" profile)
# -------------------------------------------------------------------


MSMTP_PATH = "/usr/bin/msmtp"  # percorso assoluto al binario


def _send_email(to_email: str, subject: str, html_body: str, text_body: Optional[str] = None) -> None:
    """
    Invia una mail via msmtp, con:
    - subject corretto
    - body HTML + fallback testo
    """

    if text_body is None:
        # fallback testo semplice se non lo passiamo
        text_body = "Open this email in an HTML-capable client."

    msg = EmailMessage()
    msg["From"] = "amamau Insight AI <noreply@amamau.com>"
    msg["To"] = to_email
    msg["Subject"] = subject

    # Parte testuale
    msg.set_content(text_body)

    # Parte HTML
    msg.add_alternative(html_body, subtype="html")

    print(f"[email] Sending to: {to_email} | subject={subject!r}")

    try:
        proc = subprocess.Popen(
            [MSMTP_PATH, "-a", "default", to_email],
            stdin=subprocess.PIPE,
            text=True,
        )
        stdout, stderr = proc.communicate(msg.as_string())

        print(f"[email] msmtp exit code: {proc.returncode}")
        if stdout:
            print("[email] msmtp stdout:", stdout)
        if stderr:
            print("[email] msmtp stderr:", stderr)

    except FileNotFoundError as e:
        print("[email] ERROR: msmtp not found (check MSMTP_PATH):", e)
    except Exception as e:
        print("[email] ERROR sending email:", repr(e))


def send_access_otp_email(email: str, code: str) -> None:
    subject = "Your amamau Insight AI access code"

    text_body = f"""Hi,

here is your one-time access code for amamau Insight AI:

    {code}

The code expires in 10 minutes.

If you didn't request this login, you can safely ignore this email.

- amamau Insight AI
"""

    html_body = f"""\
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>Your amamau Insight AI access code</title>
    <style>
      body {{
        margin: 0;
        padding: 0;
        background-color: #f5f5f7;
        font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", Arial, sans-serif;
        color: #111111;
      }}
      .wrapper {{
        padding: 32px 16px;
      }}
      .card {{
        max-width: 520px;
        margin: 0 auto;
        background-color: #ffffff;
        border-radius: 18px;
        padding: 28px 26px 24px;
        box-shadow: 0 18px 45px rgba(0, 0, 0, 0.06);
      }}
      .brand-row {{
        display: flex;
        align-items: center;
        gap: 10px;
        margin-bottom: 18px;
      }}
      .brand-dot {{
        width: 14px;
        height: 14px;
        border-radius: 999px;
        background: #111111;
      }}
      .brand-name {{
        font-size: 14px;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: #444;
      }}
      h1 {{
        margin: 0 0 8px;
        font-size: 20px;
        font-weight: 600;
      }}
      .subtitle {{
        font-size: 13px;
        color: #666;
        margin-bottom: 24px;
      }}
      .code-box {{
        border-radius: 14px;
        background-color: #111111;
        color: #ffffff;
        text-align: center;
        padding: 18px 12px;
        margin-bottom: 18px;
        letter-spacing: 0.32em;
        font-size: 22px;
        font-weight: 600;
      }}
      .meta {{
        font-size: 12px;
        color: #777;
        margin-bottom: 6px;
      }}
      .link {{
        font-size: 12px;
        color: #111111;
        text-decoration: none;
      }}
      .footer {{
        margin-top: 24px;
        font-size: 11px;
        color: #999;
      }}
      .footer a {{
        color: #999;
        text-decoration: none;
      }}
    </style>
  </head>
  <body>
    <div class="wrapper">
      <div class="card">
        <div class="brand-row">
          <div class="brand-dot"></div>
          <div class="brand-name">amamau &bull; insight ai</div>
        </div>

        <h1>Your access code</h1>
        <p class="subtitle">
          Use this one-time code to continue your session on
          <strong>amamau Insight AI</strong>.
        </p>

        <div class="code-box">
          {code}
        </div>

        <p class="meta">
          The code expires in <strong>10 minutes</strong> and works on this login only.
        </p>
        <p class="meta">
          If this wasn't you, you can safely ignore this email - no changes will be made.
        </p>

        <p class="meta">
          Open console: <a class="link" href="https://ai.amamau.com/console">ai.amamau.com/console</a>
        </p>

        <div class="footer">
          Sent by amamau Insight AI &bull; <a href="https://amamau.com">amamau.com</a><br />
          Access sent to: {email}
        </div>
      </div>
    </div>
  </body>
</html>
"""

    _send_email(email, subject, html_body, text_body=text_body)



# -------------------------------------------------------------------
# Profile loader
# -------------------------------------------------------------------


def load_profile(profile_id: str) -> Optional[Dict]:
    path = PROFILES_DIR / f"{profile_id}.json"
    if not path.exists():
        return None
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data.setdefault("id", profile_id)
            return data
    except Exception:
        return None
    return None


# -------------------------------------------------------------------
# LLM bridge
# -------------------------------------------------------------------


def run_llm_for_profile(profile_id: str, user_message: str) -> str:
    """
    Entrypoint usato dalla console web.

    - Carica il profilo business
    - Recupera un estratto di memoria di lungo periodo
    - (Per ora) NON usa history multi-turn, cosi il backend resta stateless
    - Chiama llm_client.generate_business_reply(...)
    - Ritorna solo la stringa di reply
    f"""
    try:
        import llm_client  # type: ignore
    except Exception:
        return f"(LLM client missing) You said: {{user_message}}"

    try:
        profile = load_profile(profile_id)
    except Exception as exc:
        return f"(Profile error: {{exc}}) You said: {{user_message}}"

    # Nessuna history per ora (puoi estenderla piu avanti con sessioni)
    history: List[Tuple[str, str]] = []

    try:
        memory_excerpt = get_memory_excerpt(profile_id)
    except Exception:
        memory_excerpt = ""

    try:
        result = llm_client.generate_business_reply(  # type: ignore[attr-defined]
            profile,
            history,
            memory_excerpt,
            user_message,
        )
    except Exception as exc:
        return f"(LLM error: {{exc}}) You said: {{user_message}}"

    # Salva eventuale memoria di lungo periodo
    try:
        if result.get("should_write_memory") and result.get("memory_note"):
            append_memory(profile_id, str(result["memory_note"]))
    except Exception:
        # la chat non deve mai crashare per problemi di memoria
        pass

    reply = result.get("reply") or "I wasn't able to generate a valid reply."
    return reply

def run_llm_for_profile_with_history(
    profile_id: str,
    user_message: str,
    history_pairs: List[Tuple[str, str]],
) -> str:
    try:
        import llm_client  # type: ignore
    except Exception:
        return f"(LLM client missing) You said: {{user_message}}"

    try:
        profile = load_profile(profile_id)
    except Exception as exc:
        return f"(Profile error: {{exc}}) You said: {{user_message}}"

    try:
        memory_excerpt = get_memory_excerpt(profile_id)
    except Exception:
        memory_excerpt = ""

    try:
        result = llm_client.generate_business_reply(  # type: ignore[attr-defined]
            profile,
            history_pairs or [],
            memory_excerpt,
            user_message,
        )
    except Exception as exc:
        return f"(LLM error: {{exc}}) You said: {{user_message}}"

    try:
        if result.get("should_write_memory") and result.get("memory_note"):
            append_memory(profile_id, str(result["memory_note"]))
    except Exception:
        pass

    return result.get("reply") or "I wasn't able to generate a valid reply."



# -------------------------------------------------------------------
# FastAPI app
# -------------------------------------------------------------------

app = FastAPI(title="amamau Insight AI")

try:
    init_chat_db()
except Exception as _exc:
    print("[chat_db] init failed:", _exc)


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------------
# HTML layout / templates
# -------------------------------------------------------------------


def render_layout(
    body_html: str,
    title: str,
    current_page: str = "home",
    session_email: Optional[str] = None,
) -> str:
    home_current = 'aria-current="page"' if current_page == "home" else ""
    console_current = 'aria-current="page"' if current_page == "console" else ""

    account_current = 'aria-current="page"' if current_page == "account" else ""
    workspace_current = 'aria-current="page"' if current_page == "workspace" else ""

    console_link_html = ""
    account_link_html = ""
    workspace_link_html = ""
    user_chip_html = ""
    logout_html = ""

    if session_email:
        console_link_html = f'<a href="/console" class="nav-link" {console_current}>Console</a>'
        account_link_html = f'<a href="/account" class="nav-link" {account_current}>Account</a>'
        ws_home = "/workspace"
        try:
            u = get_user_by_email(str(session_email)) if session_email else None
            uid = str((u or {}).get("id") or "").strip()
            if uid:
                wss = list_user_workspaces(uid)
                if wss:
                    ws_home = f"/w/{str((wss[0][0] or {}).get('id') or '').strip()}"
        except Exception:
            pass

        workspace_link_html = f'<a href="{ws_home}" class="nav-link" {workspace_current}>Workspace</a>'
        user_chip_html = (
            '<div class="user-chip">'
            f'<span class="user-name">{html_escape.escape(session_email)}</span>'
            '</div>'
        )
        logout_html = """
          <form method="post" action="/logout" style="margin:0;">
            <button type="submit" class="nav-pill" style="padding:0.35rem 0.9rem; font-size:0.75rem;">
              Logout
            </button>
          </form>
        """

    global_js = r"""
  <script>
  // Global helpers (used by /account, /workspace, ...)
  window.modalPrompt = window.modalPrompt || function modalPrompt(title, value, placeholder, confirmText) {
    return new Promise((resolve) => {
      const backdrop = document.createElement("div");
      backdrop.className = "am-modal-backdrop";
      backdrop.style.display = "flex";

      const modal = document.createElement("div");
      modal.className = "am-modal";

      const head = document.createElement("header");
      head.textContent = title || "Edit";

      const body = document.createElement("div");
      body.className = "am-modal-body";

      const inputEl = document.createElement("input");
      inputEl.type = "text";
      inputEl.placeholder = placeholder || "";
      inputEl.value = value || "";
      inputEl.style.width = "100%";
      inputEl.style.padding = "12px 12px";
      inputEl.style.borderRadius = "12px";
      inputEl.style.border = "1px solid rgba(0,0,0,0.12)";
      inputEl.style.background = "rgba(255,255,255,0.9)";
      body.appendChild(inputEl);

      const actions = document.createElement("div");
      actions.className = "am-modal-actions";

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "am-btn";
      cancelBtn.textContent = "Cancel";

      const okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = "am-btn primary";
      okBtn.textContent = confirmText || "Save";

      actions.appendChild(cancelBtn);
      actions.appendChild(okBtn);

      modal.appendChild(head);
      modal.appendChild(body);
      modal.appendChild(actions);

      backdrop.appendChild(modal);
      document.body.appendChild(backdrop);

      function close(v) { backdrop.remove(); resolve(v); }

      cancelBtn.onclick = () => close(null);
      okBtn.onclick = () => {
        const v = (inputEl.value || "").trim();
        if (!v) return;
        close(v);
      };

      backdrop.addEventListener("click", (ev) => { if (ev.target === backdrop) close(null); });
      inputEl.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") okBtn.click();
        if (ev.key === "Escape") cancelBtn.click();
      });

      setTimeout(() => inputEl.focus(), 0);
    });
  };

  window.modalConfirm = window.modalConfirm || function modalConfirm(title, message, confirmText) {
    return new Promise((resolve) => {
      const backdrop = document.createElement("div");
      backdrop.className = "am-modal-backdrop";
      backdrop.style.display = "flex";

      const modal = document.createElement("div");
      modal.className = "am-modal";

      const head = document.createElement("header");
      head.textContent = title || "Confirm";

      const body = document.createElement("div");
      body.className = "am-modal-body";
      const p = document.createElement("div");
      p.style.lineHeight = "1.55";
      p.style.fontSize = "0.9rem";
      p.textContent = message || "";
      body.appendChild(p);

      const actions = document.createElement("div");
      actions.className = "am-modal-actions";

      const cancelBtn = document.createElement("button");
      cancelBtn.type = "button";
      cancelBtn.className = "am-btn";
      cancelBtn.textContent = "Cancel";

      const okBtn = document.createElement("button");
      okBtn.type = "button";
      okBtn.className = "am-btn primary";
      okBtn.textContent = confirmText || "Confirm";

      actions.appendChild(cancelBtn);
      actions.appendChild(okBtn);

      modal.appendChild(head);
      modal.appendChild(body);
      modal.appendChild(actions);

      backdrop.appendChild(modal);
      document.body.appendChild(backdrop);

      function close(v) { backdrop.remove(); resolve(v); }

      cancelBtn.onclick = () => close(false);
      okBtn.onclick = () => close(true);
      backdrop.addEventListener("click", (ev) => { if (ev.target === backdrop) close(false); });
      document.addEventListener("keydown", function esc(ev) {
        if (ev.key === "Escape") { document.removeEventListener("keydown", esc); close(false); }
      });
    });
  };

  // IMPORTANT: always set the CSRF-aware helper.
  // Some pages previously defined a fetchJSON without CSRF; using "||" would keep the broken one.
  window.fetchJSON = async function fetchJSON(url, opts = {}) {
    function getCookie(name) {
      const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()\[\]\\/+^]/g, '\$&') + '=([^;]*)'));
      return m ? decodeURIComponent(m[1]) : '';
    }

    const headers = Object.assign({ "Accept": "application/json" }, (opts.headers || {}));
    const method = String(opts.method || "GET").toUpperCase();

    // CSRF: double-submit via X-CSRF-Token header (and optional JSON body field as a fallback)
    if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
      const csrf = getCookie('csrf_token');
      if (csrf && !headers['X-CSRF-Token']) headers['X-CSRF-Token'] = csrf;

      // Fallback: if the server ever reads CSRF from JSON body, inject it.
      try {
        const ct = String(headers["Content-Type"] || headers["content-type"] || "").toLowerCase();
        if (csrf && ct.includes("application/json") && typeof opts.body === "string") {
          const obj = JSON.parse(opts.body);
          if (obj && typeof obj === "object" && !("csrf" in obj)) {
            obj.csrf = csrf;
            opts.body = JSON.stringify(obj);
          }
        }
      } catch (e) {}
    }

    const res = await fetch(url, Object.assign({ credentials: "same-origin", headers }, opts));
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const msg = data?.detail || data?.error || ("HTTP " + res.status);
      throw new Error(msg);
    }
    return data;
  };

  // Auto-inject hidden CSRF input on all mutating forms
  (function () {
    function getCookie(name) {
      const m = document.cookie.match(new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()\[\]\\/+^]/g, '\$&') + '=([^;]*)'));
      return m ? decodeURIComponent(m[1]) : '';
    }
    function inject() {
      const csrf = getCookie('csrf_token');
      if (!csrf) return;
      document.querySelectorAll('form').forEach((f) => {
        const m = String(f.getAttribute('method') || 'GET').toUpperCase();
        if (!["POST", "PUT", "PATCH", "DELETE"].includes(m)) return;
        let inp = f.querySelector('input[name="csrf"]');
        if (!inp) {
          inp = document.createElement('input');
          inp.type = 'hidden';
          inp.name = 'csrf';
          f.appendChild(inp);
        }
        inp.value = csrf;
      });
    }
    document.addEventListener('DOMContentLoaded', inject);
  })();
  </script>
"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>{html_escape.escape(title)}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <meta name="description" content="amamau Insight AI - private business assistant console." />
  <link rel="icon" href="https://ai.amamau.com/favicon.ico" />
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600&display=swap" rel="stylesheet" />
  <style>
    :root {{
      --bg-page: #f5f5f7;
      --bg-card: #ffffff;
      --bg-soft: #fafafb;

      --border-subtle: #e2e2e7;
      --border-strong: #c8c8d0;

      --text-main: #111118;
      --text-soft: #4c4c57;
      --text-mute: #8d8d99;

      --accent: #111111;

      --radius-lg: 26px;
      --radius-md: 18px;
      --radius-pill: 999px;

      --shadow-soft: 0 18px 40px rgba(0, 0, 0, 0.04);
      --shadow-card: 0 14px 36px rgba(0, 0, 0, 0.07);

      --transition: 0.22s ease-out;
      --content-width: 1120px;
    }}

    * {{
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }}

    html, body {{
      font-family: 'Outfit', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-page);
      color: var(--text-main);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      min-height: 100vh;
    }}

    body {{
      display: flex;
      flex-direction: column;
    }}

    main {{
      flex: 1;
    }}

    .shell {{
      max-width: var(--content-width);
      margin: 0 auto;
      padding: 0 1.4rem 3.2rem;
    }}

    @media (min-width: 960px) {{
      .shell {{
        padding: 0 2rem 4rem;
      }}
    }}

    header {{
      position: sticky;
      top: 0;
      z-index: 1000;
      backdrop-filter: blur(18px);
      background: rgba(245, 245, 247, 0.96);
      border-bottom: 1px solid rgba(0, 0, 0, 0.04);
    }}

    .nav-inner {{
      max-width: var(--content-width);
      margin: 0 auto;
      padding: 0.85rem 1.4rem 0.75rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 1rem;
    }}

    @media (min-width: 960px) {{
      .nav-inner {{
        padding: 0.9rem 2rem 0.8rem;
      }}
    }}

    .logo-mark {{
      width: 26px;
      height: 26px;
      border-radius: 999px;
      background: #111111;
      margin-right: 0.6rem;
      flex-shrink: 0;
    }}

    .brand {{
      display: flex;
      align-items: center;
      gap: 0.35rem;
      text-decoration: none;
      color: var(--text-main);
      font-size: 0.95rem;
      font-weight: 600;
      letter-spacing: 0.18em;
      text-transform: uppercase;
    }}

    .brand span.small {{
      font-size: 0.78rem;
      letter-spacing: 0.28em;
      text-transform: uppercase;
      color: var(--text-mute);
      margin-left: 0.2rem;
    }}

    .nav-right {{
      display: flex;
      align-items: center;
      gap: 0.8rem;
      flex-wrap: wrap;
      justify-content: flex-end;
    }}

    .user-chip {{
      font-size: 0.78rem;
      padding: 0.32rem 0.9rem;
      border-radius: 999px;
      background: rgba(0, 0, 0, 0.03);
      color: var(--text-soft);
      display: inline-flex;
      align-items: center;
      max-width: 220px;
      border: 1px solid rgba(0, 0, 0, 0.04);
    }}

    .user-chip .user-name {{
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      font-weight: 500;
      color: var(--accent);
    }}

    .nav-link {{
      position: relative;
      color: var(--text-soft);
      text-decoration: none;
      font-size: 0.8rem;
      font-weight: 500;
      padding-bottom: 0.12rem;
      text-transform: uppercase;
      letter-spacing: 0.18em;
    }}

    .nav-link::after {{
      content: "";
      position: absolute;
      left: 0;
      bottom: 0;
      width: 0;
      height: 2px;
      background: #111111;
      border-radius: 999px;
      transition: width var(--transition);
    }}

    .nav-link:hover::after,
    .nav-link[aria-current="page"]::after {{
      width: 100%;
    }}

    .nav-pill {{
      padding: 0.45rem 1.2rem;
      border-radius: 999px;
      border: 1px solid var(--border-subtle);
      background: #ffffff;
      font-size: 0.78rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      text-decoration: none;
      color: var(--text-soft);
      box-shadow: 0 12px 26px rgba(0, 0, 0, 0.06);
      cursor: pointer;
    }}

    .nav-pill:hover {{
      border-color: var(--border-strong);
      color: var(--accent);
    }}

    .hero-wrap {{
      padding: 3.1rem 0 2.7rem;
    }}

    .hero {{
      display: flex;
      flex-direction: column;
      gap: 2.2rem;
    }}

    @media (min-width: 960px) {{
      .hero-wrap {{
        padding: 4rem 0 3.4rem;
      }}
      .hero {{
        flex-direction: row;
        align-items: stretch;
        gap: 3rem;
      }}
      .hero-main,
      .hero-side {{
        flex: 1;
      }}
    }}

    .hero-eyebrow {{
      font-size: 0.78rem;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--text-mute);
      margin-bottom: 0.7rem;
    }}

    .hero-title {{
      font-size: 2.2rem;
      line-height: 1.08;
      letter-spacing: -0.03em;
      margin-bottom: 1rem;
    }}

    .hero-title span.subtle {{
      color: var(--text-soft);
      font-weight: 500;
    }}

    @media (min-width: 768px) {{
      .hero-title {{
        font-size: 2.7rem;
      }}
    }}

    .hero-sub {{
      font-size: 0.98rem;
      color: var(--text-soft);
      line-height: 1.8;
      max-width: 520px;
    }}

    .hero-sub strong {{
      color: var(--accent);
      font-weight: 500;
    }}

    .hero-meta-row {{
      margin-top: 1.3rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.5rem 1rem;
      font-size: 0.83rem;
      color: var(--text-mute);
    }}

    .hero-actions {{
      margin-top: 1.9rem;
      display: flex;
      flex-wrap: wrap;
      gap: 0.8rem;
    }}

    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 0.85rem 1.7rem;
      border-radius: var(--radius-pill);
      font-size: 0.82rem;
      font-weight: 600;
      letter-spacing: 0.16em;
      text-transform: uppercase;
      border: 1px solid transparent;
      text-decoration: none;
      cursor: pointer;
      user-select: none;
      transition: background var(--transition),
                  color var(--transition),
                  border-color var(--transition),
                  box-shadow var(--transition),
                  transform var(--transition);
    }}

    .btn-primary {{
      background: #111111;
      color: #ffffff;
      box-shadow: 0 14px 32px rgba(0, 0, 0, 0.2);
    }}

    .btn-primary:hover {{
      transform: translateY(-1px);
      box-shadow: 0 20px 46px rgba(0, 0, 0, 0.28);
    }}

    .btn-ghost {{
      background: #ffffff;
      color: var(--text-soft);
      border-color: #d6d6de;
    }}

    .btn-ghost:hover {{
      color: var(--accent);
      border-color: var(--border-strong);
      box-shadow: 0 10px 26px rgba(0, 0, 0, 0.08);
    }}

    .hero-side {{
      background: var(--bg-card);
      border-radius: var(--radius-lg);
      border: 1px solid var(--border-subtle);
      box-shadow: var(--shadow-card);
      padding: 1.6rem 1.5rem 1.8rem;
    }}

.conv-item{{
  position: relative;
  padding-right: 54px; /* spazio per la ? */
}}

.conv-rename{{
  position: absolute;
  top: 10px;
  right: 10px;
  width: 34px;
  height: 34px;
  border-radius: 999px;
  border: 1px solid rgba(0,0,0,0.10);
  background: rgba(255,255,255,0.90);
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  opacity: 1 !important;
  z-index: 5;
}}


    @media (min-width: 960px) {{
      .hero-side {{
        padding: 1.9rem 1.9rem 2rem;
      }}
    }}

    .hero-side-label {{
      font-size: 0.78rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--text-mute);
      margin-bottom: 0.8rem;
    }}

    .hero-side-title {{
      font-size: 1.08rem;
      margin-bottom: 0.6rem;
    }}

    .hero-side p {{
      font-size: 0.9rem;
      color: var(--text-soft);
      line-height: 1.6;
      margin-bottom: 0.6rem;
    }}

    .small-note {{
      font-size: 0.78rem;
      color: var(--text-mute);
      line-height: 1.6;
    }}

    .form-field {{
      margin-bottom: 0.65rem;
    }}

    .form-field label {{
      display: block;
      font-size: 0.8rem;
      margin-bottom: 0.25rem;
      color: var(--text-soft);
    }}

    .form-field input {{
      width: 100%;
      border-radius: 999px;
      border: 1px solid #d6d6de;
      padding: 0.65rem 0.9rem;
      font-size: 0.88rem;
      outline: none;
      background: #fafafa;
      transition: border-color var(--transition),
                  box-shadow var(--transition),
                  background var(--transition);
    }}

    .form-field input:focus {{
      border-color: #111111;
      background: #ffffff;
      box-shadow: 0 0 0 1px #11111111;
    }}

    .alert {{
      border-radius: 12px;
      padding: 0.55rem 0.75rem;
      font-size: 0.8rem;
      margin-bottom: 0.55rem;
    }}

    .alert-info {{
      background: #eef5ff;
      border: 1px solid #c7d7ff;
      color: #1a3c8a;
    }}

    .alert-error {{
      background: #ffecec;
      border: 1px solid #f4b4b4;
      color: #7f1515;
    }}

    .token-help {{
      margin-top: 0.9rem;
      padding-top: 0.8rem;
      border-top: 1px dashed #e0e0ea;
      font-size: 0.8rem;
      color: var(--text-mute);
    }}

    .token-inline-form {{
      display: flex;
      gap: 0.45rem;
      margin-top: 0.5rem;
    }}

    .token-inline-form input {{
      flex: 1;
    }}

    .token-inline-form button {{
      white-space: nowrap;
      padding: 0.55rem 1.1rem;
      font-size: 0.78rem;
    }}

    .console-wrap {{
      margin-top: 2.6rem;
    }}

    .console-card {{
      background: var(--bg-card);
      border-radius: 30px;
      border: 1px solid var(--border-subtle);
      box-shadow: var(--shadow-card);
      padding: 1.7rem 1.6rem 1.4rem;
    }}

    @media (min-width: 960px) {{
      .console-card {{
        padding: 1.9rem 1.9rem 1.6rem;
      }}
    }}

    .console-header-top {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 0.8rem;
      margin-bottom: 0.6rem;
    }}

    .console-eyebrow {{
      font-size: 0.78rem;
      letter-spacing: 0.22em;
      text-transform: uppercase;
      color: var(--text-mute);
      margin-bottom: 0.35rem;
    }}

    .console-title {{
      font-size: 1.45rem;
      letter-spacing: -0.02em;
      margin-bottom: 0.1rem;
    }}

    .console-sub {{
      font-size: 0.9rem;
      color: var(--text-soft);
    }}

    .token-pill {{
      padding: 0.4rem 0.9rem;
      border-radius: 999px;
      border: 1px solid #dedee7;
      background: #f9f9fb;
      font-size: 0.78rem;
      color: var(--text-mute);
      white-space: nowrap;
    }}

    .token-pill strong {{
      color: var(--text-main);
      font-weight: 600;
    }}

    .chat-shell {{
      margin-top: 1.3rem;
      border-radius: 24px;
      border: 1px solid #e1e1ea;
      background: #fafafb;
      padding: 1.1rem 1rem 0.9rem;
    }}

/* ---- Conversations sidebar (ChatGPT-like) ---- */
.console-grid{{
  display:flex;
  gap:1rem;
  align-items:stretch;
}}

@media (max-width: 960px){{
  .console-grid{{ flex-direction:column; }}
}}

.conv-sidebar{{
  width: 320px;
  min-width: 260px;
  background:#ffffff;
  border:1px solid var(--border-subtle);
  border-radius: 24px;
  box-shadow: var(--shadow-soft);
  padding: 0.9rem;
  display:flex;
  flex-direction:column;
  gap:0.7rem;
}}

@media (max-width: 960px){{
  .conv-sidebar{{ width:100%; min-width:unset; }}
}}

.conv-sidebar-top{{
  display:flex;
  gap:0.6rem;
  align-items:center;
}}

.conv-new{{
  flex:1;
  border-radius: 999px;
  border: 1px solid #d6d6de;
  background:#111111;
  color:#fff;
  padding:0.55rem 0.9rem;
  font-size:0.78rem;
  font-weight:600;
  letter-spacing:0.16em;
  text-transform:uppercase;
  cursor:pointer;
}}

.conv-new:hover{{ opacity:0.95; }}

.conv-search{{
  width:100%;
  border-radius: 999px;
  border:1px solid #d6d6de;
  padding:0.55rem 0.85rem;
  font-size:0.82rem;
  outline:none;
  background:#fafafa;
}}

.conv-search:focus{{
  border-color:#111111;
  background:#fff;
}}

.conv-list{{
  flex:1;
  overflow:auto;
  padding-right: 0.15rem;
  display:flex;
  flex-direction:column;
  gap:0.45rem;
}}

.conv-item{{
  border:1px solid rgba(0,0,0,0.06);
  background:#fafafb;
  border-radius:18px;
  padding:0.65rem 0.75rem;
  cursor:pointer;
  transition: transform var(--transition), box-shadow var(--transition), background var(--transition), border-color var(--transition);
}}

.conv-item:hover{{
  transform: translateY(-1px);
  border-color: rgba(0,0,0,0.10);
  box-shadow: 0 10px 22px rgba(0,0,0,0.06);
  background:#ffffff;
}}

.conv-item.active{{
  background:#111111;
  color:#ffffff;
  border-color:#111111;
}}

.conv-title{{
  font-size:0.86rem;
  font-weight:600;
  line-height:1.25;
  margin-bottom:0.25rem;
}}

.conv-preview{{
  font-size:0.78rem;
  line-height:1.35;
  opacity:0.75;
}}

.conv-locked{{
  font-size:0.8rem;
  color: var(--text-mute);
  line-height:1.55;
  padding:0.55rem 0.65rem;
  border:1px dashed #e0e0ea;
  border-radius: 18px;
  background:#fafafb;
}}

.console-main{{
  flex:1;
  min-width: 0;
}}


    .chat-thread {{
      max-height: 420px;
      overflow-y: auto;
      padding-right: 0.2rem;
      margin-bottom: 0.9rem;
    }}

    .bubble {{
      max-width: 88%;
      margin-bottom: 0.6rem;
      padding: 0.75rem 0.9rem;
      border-radius: 18px;
      font-size: 0.9rem;
      line-height: 1.6;
      word-wrap: break-word;
      white-space: pre-wrap;
    }}

    .bubble-user {{
      margin-left: auto;
      border-bottom-right-radius: 4px;
      background: #111111;
      color: #ffffff;
    }}

    .bubble-ai {{
      margin-right: auto;
      border-bottom-left-radius: 4px;
      background: #ffffff;
      border: 1px solid #e1e1ea;
      color: var(--text-main);
    }}

    .bubble-label {{
      font-size: 0.72rem;
      text-transform: uppercase;
      letter-spacing: 0.18em;
      margin-bottom: 0.25rem;
      color: var(--text-mute);
    }}

    .chat-form {{
      display: flex;
      gap: 0.6rem;
      align-items: center;
    }}

    .chat-input {{
      flex: 1;
      border-radius: 999px;
      border: 1px solid #d3d3dd;
      padding: 0.65rem 0.9rem;
      font-size: 0.88rem;
      background: #ffffff;
      outline: none;
      transition: border-color var(--transition), box-shadow var(--transition);
    }}

    .chat-input:focus {{
      border-color: #111111;
      box-shadow: 0 0 0 1px #11111111;
    }}

    .chat-send-btn {{
      border-radius: 999px;
      border: none;
      background: #111111;
      color: #ffffff;
      padding: 0.62rem 1.2rem;
      font-size: 0.8rem;
      font-weight: 600;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      cursor: pointer;
      white-space: nowrap;
    }}

    .chat-send-btn[disabled] {{
      opacity: 0.6;
      cursor: default;
    }}

    .console-meta {{
      margin-top: 0.75rem;
      font-size: 0.78rem;
      color: var(--text-mute);
      display: flex;
      flex-wrap: wrap;
      gap: 0.8rem;
      justify-content: space-between;
    }}

.conv-rename{{
  opacity: 1 !important;
  margin-left:auto;
  width: 34px;
  height: 34px;
  border-radius: 999px;
  border: 1px solid rgba(0,0,0,0.08);
  background: rgba(255,255,255,0.7);
  cursor: pointer;
  font-size: 14px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  opacity: 0;
  transition: opacity var(--transition), transform var(--transition);
}}
.conv-item:hover .conv-rename{{
  opacity: 1;
  transform: translateY(-1px);
}}
.conv-item.active .conv-rename{{
  background: rgba(255,255,255,0.12);
  border-color: rgba(255,255,255,0.20);
  color: #fff;
  opacity: 1;
}}

/* menu + filtri conversazioni (F-STRING SAFE) */
.conv-menu {{
  display: flex;
  gap: 8px;
  margin: 12px 0 10px;
}}

.conv-menu button {{
  flex: 1;
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid rgba(0,0,0,0.10);
  background: rgba(255,255,255,0.8);
  cursor: pointer;
  font-weight: 600;
}}

.conv-menu button:hover {{
  background: rgba(255,255,255,1);
}}

.conv-filters {{
  display: flex;
  gap: 8px;
  margin: 8px 0 8px;
}}

.conv-filter {{
  flex: 1;
  padding: 9px 10px;
  border-radius: 999px;
  border: 1px solid rgba(0,0,0,0.10);
  background: rgba(255,255,255,0.7);
  cursor: pointer;
  font-size: 13px;
  font-weight: 700;
}}

.conv-filter.is-active {{
  background: rgba(0,0,0,0.06);
  border-color: rgba(0,0,0,0.18);
}}

/* modal (F-STRING SAFE) */
.am-modal-backdrop {{
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.35);
  display: none;
  align-items: center;
  justify-content: center;
  z-index: 9999;
}}

.am-modal {{
  width: min(520px, calc(100vw - 28px));
  background: rgba(255,255,255,0.92);
  border: 1px solid rgba(0,0,0,0.10);
  border-radius: 18px;
  box-shadow: 0 22px 70px rgba(0,0,0,0.18);
  overflow: hidden;
}}

.am-modal header {{
  padding: 14px 16px;
  border-bottom: 1px solid rgba(0,0,0,0.08);
  font-weight: 800;
}}

.am-modal .am-modal-body {{
  padding: 14px 16px;
}}

.am-modal .am-modal-actions {{
  padding: 12px 16px;
  display: flex;
  gap: 10px;
  justify-content: flex-end;
  border-top: 1px solid rgba(0,0,0,0.08);
}}

.am-btn {{
  padding: 10px 12px;
  border-radius: 12px;
  border: 1px solid rgba(0,0,0,0.12);
  background: rgba(255,255,255,0.85);
  cursor: pointer;
  font-weight: 700;
}}

.am-btn.primary {{
  background: rgba(0,0,0,0.92);
  color: #fff;
  border-color: rgba(0,0,0,0.92);
}}



    footer {{
      border-top: 1px solid #dfdfe6;
      padding: 1.6rem 1.4rem 2rem;
      font-size: 0.8rem;
      color: var(--text-mute);
      text-align: center;
    }}

    @media (min-width: 960px) {{
      footer {{
        padding: 2rem 2rem 2.4rem;
      }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="nav-inner">
      <a href="/" class="brand">
        <div class="logo-mark"></div>
        <div>
          <div>AMAMAU</div>
          <span class="small">Insight AI</span>
        </div>
      </a>
      <div class="nav-right">
        <a href="/" class="nav-link" {home_current}>Home</a>
        {console_link_html}
        {workspace_link_html}
        {account_link_html}
        {user_chip_html}
        {logout_html}
        <a href="mailto:hello@amamau.com?subject=Insight%20AI%20beta" class="nav-pill">Request beta</a>
      </div>
    </div>
  </header>
  <main>
    <div class="shell">
      {body_html}
    </div>
  </main>
  <footer>
    &copy; 2025 amamau - Insight AI console (private beta).
  </footer>

  {global_js}
</body>
</html>
"""




def render_index_page(
    info: str = "",
    error: str = "",
    otp_phase: bool = False,
    email_prefill: str = "",
    otp_id: str = "",
    session_email: Optional[str] = None,
    next_url: str = "",
    csrf_token: str = "",   # <-- AGGIUNGI
) -> str:
    info_html = ""
    error_html = ""
    if info:
        info_html = f'<div class="alert alert-info">{html_escape.escape(info)}</div>'
    if error:
        error_html = f'<div class="alert alert-error">{html_escape.escape(error)}</div>'

    email_prefill_escaped = html_escape.escape(email_prefill or "")
    next_url_safe = _safe_next_url(next_url)
    next_url_escaped = html_escape.escape(next_url_safe)
    csrf_token_escaped = html_escape.escape(csrf_token or "")


    if not otp_phase:
        # fase 1: email + password
        form_html = f"""
          <form method="post" action="/login">
          <input type="hidden" name="csrf" value="{csrf_token_escaped}" />
            <input type="hidden" name="next" value="{next_url_escaped}" />
            <div class="form-field">
              <label for="email">Work email</label>
              <input type="email" id="email" name="email" value="{email_prefill_escaped}" required autocomplete="email" />
            </div>
            <div class="form-field">
              <label for="password">Password</label>
              <input type="password" id="password" name="password" required autocomplete="current-password" />
            </div>
            <button class="btn btn-primary" type="submit" style="width:100%; margin-top:0.4rem;">
              Sign in
            </button>
          </form>
          <p class="small-note" style="margin-top:0.7rem;">
            Beta access is by invitation. If you don't have an account yet, email
            <a href="mailto:hello@amamau.com">hello@amamau.com</a>.
          </p>
          <p class="small-note">
            Have an invite URL with a token? You can also use it directly:
            <code>/t/&lt;token&gt;</code>.
          </p>
        """
    else:
        # fase 2: OTP
        form_html = f"""
          <form method="post" action="/login/verify">
          <input type="hidden" name="csrf" value="{csrf_token_escaped}" />
            <input type="hidden" name="otp_id" value="{html_escape.escape(otp_id)}" />
            <input type="hidden" name="next" value="{next_url_escaped}" />
            <div class="form-field">
              <label for="otp_code">6 digit code</label>
              <input type="text" id="otp_code" name="otp_code" required maxlength="6" pattern="\\d{{6}}" />
            </div>
            <button class="btn btn-primary" type="submit" style="width:100%; margin-top:0.4rem;">
              Verify code
            </button>
          </form>
          <p class="small-note" style="margin-top:0.7rem;">
            Check your inbox for a mail from <strong>noreply@amamau.com</strong>.
          </p>
        """

    body = f"""
      <section class="hero-wrap">
        <div class="hero">
          <div class="hero-main">
            <div class="hero-eyebrow">amamau &bull; small-team digital tools</div>
            <h1 class="hero-title">
              A private AI layer<br>for serious small teams.
            </h1>
            <p class="hero-sub">
              amamau Insight AI is a business-focused assistant tuned for naming,
              domains, pricing and small-brand decisions. No screenshots, no gimmicks,
              just outputs you can paste into docs and decks.
            </p>
            <div class="hero-meta-row">
              <span>Business-first answers</span>
              <span>Profile-based memory</span>
              <span>AI  under the hood</span>
            </div>
            <div class="hero-actions">
              <a href="#login" class="btn btn-primary">Access beta</a>
              <a href="mailto:hello@amamau.com?subject=amamau%20Insight%20AI" class="btn btn-ghost">
                Discuss a use case
              </a>
            </div>
          </div>

          <aside class="hero-side" id="login">
            <div class="hero-side-label">Sign in</div>
            <div class="hero-side-title">Email, password and one-time code.</div>
            {info_html}
            {error_html}
            {form_html}
          </aside>
        </div>
      </section>
    """
    return render_layout(body, "amamau Insight AI - access", current_page="home", session_email=session_email)

def render_index_page_safe(request: Request, info: str, error: str, otp_phase: bool, csrf_token: str = ""):
    token = csrf_token
    if not token and request is not None:
        try:
            token = str(getattr(request.state, "_csrf_token", "") or request.cookies.get("csrf_token") or "")
        except Exception:
            token = csrf_token
    try:
        return render_index_page(request=request, info=info, error=error, otp_phase=otp_phase, csrf_token=token)
    except TypeError:
        return render_index_page(info=info, error=error, otp_phase=otp_phase, csrf_token=token)


def render_console_page(profile: Dict, token: Optional[str], session_email: Optional[str]) -> str:
    profile_name = profile.get("name") or "Business profile"
    profile_id = profile.get("id") or ""
    token_label = token[:8] + "..." if token else "session"
    email_label = session_email or "invite link"

    authed = "1" if session_email else "0"

    # JS separato (NON f-string) => niente problemi con { } e niente crash in pagina
    script = r"""
(() => {
  const root = document.getElementById("console-root");
  if (!root) return;

  const profileId = root.dataset.profileId || "";
  const token = root.dataset.token || "";
  const authed = (root.dataset.authed || "0") === "1";

  const thread = document.getElementById("chat-thread");
  const form = document.getElementById("chat-form");
  const input = document.getElementById("chat-input");
  const sendBtn = document.getElementById("chat-send");

  const convList = document.getElementById("conv-list");
  const convNewBtn = document.getElementById("conv-new");
  const convSearch = document.getElementById("conv-search");
  const convLocked = document.getElementById("conv-locked");
  const filterWrap = document.getElementById("conv-filters");

  let sending = false;
  let activeConversationId = null;
  let conversationsCache = [];
  let currentStatus = "active";

  // Optional deep-link: /console?c=<conversation_id>
  // NOTE: previously this variable was referenced but never defined, breaking history + sending.
  const openFromUrl = (() => {
    try {
      return (new URL(window.location.href)).searchParams.get('c') || '';
    } catch (e) {
      return '';
    }
  })();

function wireFilters() {
  if (!filterWrap) return;
  const buttons = filterWrap.querySelectorAll(".conv-filter");
  buttons.forEach(btn => {
    btn.addEventListener("click", async () => {
      const next = (btn.dataset.status || "active").toLowerCase();
      if (next === currentStatus) return;

      currentStatus = next;
      buttons.forEach(b => b.classList.toggle("is-active", b === btn));

      activeConversationId = null;
      if (convSearch) convSearch.value = "";
      await loadConversations();
    });
  });
}


  function setSending(on) {
    sending = !!on;
    if (sendBtn) sendBtn.toggleAttribute("disabled", sending);
  }

  function appendGreeting() {
    const div = document.createElement("div");
    div.className = "bubble bubble-ai";
    const label = document.createElement("div");
    label.className = "bubble-label";
    label.textContent = "AI";
    const body = document.createElement("div");
    body.textContent =
      "Hi - I'm tuned for strategy, pricing, funnels and positioning. Give me short context + numbers and I'll stay decision-focused.";
    div.appendChild(label);
    div.appendChild(body);
    thread.appendChild(div);
    thread.scrollTop = thread.scrollHeight;
  }

  function resetThread() {
    thread.innerHTML = "";
    appendGreeting();
  }

function escapeHtml(s) {
  return (s || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function renderMarkdown(md) {
  let s = escapeHtml(md || "");

  // code blocks ``` ```
  s = s.replace(/```(\w+)?\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<pre class="md-pre"><code class="md-code">${code}</code></pre>`;
  });

  // inline code ``
  s = s.replace(/`([^`]+)`/g, `<code class="md-inline">$1</code>`);

  // bold ** **
  s = s.replace(/\*\*([^*]+)\*\*/g, `<strong>$1</strong>`);

  // simple lists (- / *)
  const lines = s.split("\n");
  let out = [];
  let inUl = false;

  for (const line of lines) {
    const m = line.match(/^(\s*[-*])\s+(.*)$/);
    if (m) {
      if (!inUl) { out.push("<ul class='md-ul'>"); inUl = true; }
      out.push(`<li>${m[2]}</li>`);
    } else {
      if (inUl) { out.push("</ul>"); inUl = false; }
      out.push(line === "" ? "<br/>" : `${line}<br/>`);
    }
  }
  if (inUl) out.push("</ul>");

  return out.join("");
}


  function appendBubble(role, text) {
    const div = document.createElement("div");
    div.className = "bubble " + (role === "user" ? "bubble-user" : "bubble-ai");

    const label = document.createElement("div");
    label.className = "bubble-label";
    label.textContent = role === "user" ? "You" : "AI";

    const body = document.createElement("div");
    body.className = "bubble-content";
    body.innerHTML = renderMarkdown(text || "");

    div.appendChild(label);
    div.appendChild(body);
    thread.appendChild(div);
    thread.scrollTop = thread.scrollHeight;
  }

function getCookie(name) {
  const m = document.cookie.match(
    new RegExp('(?:^|; )' + name.replace(/[.$?*|{}()\[\]\\/+^]/g, "\\$&") + '=([^;]*)')
  );
  return m ? decodeURIComponent(m[1]) : "";
}

async function fetchJSON(url, opts = {}) {
  const method = (opts.method || "GET").toUpperCase();

  // clone headers
  const headers = Object.assign({ "Accept": "application/json" }, (opts.headers || {}));

  // attach CSRF on mutating requests
  if (method !== "GET" && method !== "HEAD") {
    const csrf = getCookie("csrf_token") || "";
    if (csrf) headers["X-CSRF-Token"] = csrf;

    // extra safety: inject csrf into JSON body too (in case server reads body)
    const ct = (headers["Content-Type"] || headers["content-type"] || "").toLowerCase();
    if (ct.includes("application/json") && typeof opts.body === "string" && csrf) {
      try {
        const obj = JSON.parse(opts.body);
        if (obj && typeof obj === "object" && !("csrf" in obj)) {
          obj.csrf = csrf;
          opts.body = JSON.stringify(obj);
        }
      } catch (_) {}
    }
  }

  opts.headers = headers;

  // IMPORTANT: even if window.fetchJSON exists, call it AFTER injecting headers/body
  if (window.fetchJSON) return window.fetchJSON(url, opts);

  const res = await fetch(url, Object.assign({ credentials: "same-origin" }, opts));
  const data = await res.json().catch(() => ({}));

  if (!res.ok) {
    const msg = data?.detail || data?.error || ("HTTP " + res.status);
    throw new Error(msg);
  }
  return data;
}


  function setActiveConversation(id) {
    activeConversationId = id;
    const items = convList.querySelectorAll(".conv-item");
    items.forEach(it => it.classList.toggle("active", it.dataset.id === id));
  }

  function titleFromFirstMessage(text) {
    const t = (text || "").trim().replace(/\\s+/g, " ");
    if (!t) return "New chat";
    return t.length <= 60 ? t : (t.slice(0, 59).trim() + "...");
  }

function modalPrompt(title, value, placeholder, confirmText) {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "am-modal-backdrop";
    backdrop.style.display = "flex";

    const modal = document.createElement("div");
    modal.className = "am-modal";

    const head = document.createElement("header");
    head.textContent = title || "Edit";

    const body = document.createElement("div");
    body.className = "am-modal-body";

    const inputEl = document.createElement("input");
    inputEl.type = "text";
    inputEl.placeholder = placeholder || "";
    inputEl.value = value || "";
    inputEl.style.width = "100%";
    inputEl.style.padding = "12px 12px";
    inputEl.style.borderRadius = "12px";
    inputEl.style.border = "1px solid rgba(0,0,0,0.12)";
    inputEl.style.background = "rgba(255,255,255,0.9)";
    body.appendChild(inputEl);

    const actions = document.createElement("div");
    actions.className = "am-modal-actions";

    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "am-btn";
    cancelBtn.textContent = "Cancel";

    const okBtn = document.createElement("button");
    okBtn.type = "button";
    okBtn.className = "am-btn primary";
    okBtn.textContent = confirmText || "Save";

    actions.appendChild(cancelBtn);
    actions.appendChild(okBtn);

    modal.appendChild(head);
    modal.appendChild(body);
    modal.appendChild(actions);

    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);

    function close(v) { backdrop.remove(); resolve(v); }

    cancelBtn.onclick = () => close(null);
    okBtn.onclick = () => {
      const v = (inputEl.value || "").trim();
      if (!v) return;
      close(v);
    };

    backdrop.addEventListener("click", (ev) => { if (ev.target === backdrop) close(null); });
    inputEl.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") okBtn.click();
      if (ev.key === "Escape") cancelBtn.click();
    });

    setTimeout(() => inputEl.focus(), 0);
  });
}

function modalConfirm(title, message, confirmText) {
  return new Promise((resolve) => {
    const backdrop = document.createElement("div");
    backdrop.className = "am-modal-backdrop";
    backdrop.style.display = "flex";

    const modal = document.createElement("div");
    modal.className = "am-modal";

    const head = document.createElement("header");
    head.textContent = title || "Confirm";

    const body = document.createElement("div");
    body.className = "am-modal-body";
    const p = document.createElement("div");
    p.style.lineHeight = "1.55";
    p.style.fontSize = "0.9rem";
    p.textContent = message || "";
    body.appendChild(p);

    const actions = document.createElement("div");
    actions.className = "am-modal-actions";

    const cancelBtn = document.createElement("button");
    cancelBtn.type = "button";
    cancelBtn.className = "am-btn";
    cancelBtn.textContent = "Cancel";

    const okBtn = document.createElement("button");
    okBtn.type = "button";
    okBtn.className = "am-btn primary";
    okBtn.textContent = confirmText || "Confirm";

    actions.appendChild(cancelBtn);
    actions.appendChild(okBtn);

    modal.appendChild(head);
    modal.appendChild(body);
    modal.appendChild(actions);

    backdrop.appendChild(modal);
    document.body.appendChild(backdrop);

    function close(v) { backdrop.remove(); resolve(v); }

    cancelBtn.onclick = () => close(false);
    okBtn.onclick = () => close(true);
    backdrop.addEventListener("click", (ev) => { if (ev.target === backdrop) close(false); });
    document.addEventListener("keydown", function esc(ev) {
      if (ev.key === "Escape") { document.removeEventListener("keydown", esc); close(false); }
    });
  });
}

async function apiPost(url) {
  try {
    // Use global helper (includes CSRF) if available
    return await fetchJSON(url, { method: "POST" });
  } catch (e) {
    console.error(e);
    const msg = (e && e.message) ? e.message : "Request failed.";
    await modalConfirm("Request failed", msg, "OK");
    throw e;
  }
}
async function apiDelete(url) {
  try {
    // Use global helper (includes CSRF) if available
    return await fetchJSON(url, { method: "DELETE" });
  } catch (e) {
    console.error(e);
    const msg = (e && e.message) ? e.message : "Request failed.";
    await modalConfirm("Request failed", msg, "OK");
    throw e;
  }
}

const ICONS = {
  rename: `<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/>
  </svg>`,
  archive:`<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M21 8v13H3V8"/><path d="M1 3h22v5H1z"/><path d="M10 12h4"/>
  </svg>`,
  trash:`<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 16h10l1-16"/>
  </svg>`,
  restore:`<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 12a9 9 0 1 0 3-6.7"/><path d="M3 4v6h6"/>
  </svg>`,
  kill:`<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
    <path d="M3 6h18"/><path d="M8 6V4h8v2"/><path d="M6 6l1 16h10l1-16"/><path d="M10 11v6"/><path d="M14 11v6"/>
  </svg>`
};

function makeIconBtn(iconKey, title, fn, fallbackText) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "conv-action";
  b.title = title;

  const svg = ICONS[iconKey];
  b.innerHTML = svg ? svg : (fallbackText || "?");

  b.addEventListener("click", async (ev) => {
    ev.preventDefault();
    ev.stopPropagation();
    try { await fn(); } catch (e) { console.error(e); }
  });
  return b;
}


  function renderConversations(list) {
    convList.innerHTML = "";

    if (!authed) {
      if (convLocked) {
        convLocked.style.display = "block";
        convList.appendChild(convLocked);
      }
      return;
    }

    const q = (convSearch?.value || "").trim().toLowerCase();
    const filtered = !q ? list : list.filter(c => {
      const t = (c.title || "").toLowerCase();
      const p = (c.last_preview || "").toLowerCase();
      return t.includes(q) || p.includes(q);
    });

    if (!filtered.length) {
      const empty = document.createElement("div");
      empty.className = "conv-locked";
      empty.textContent = "No chats here.";
      convList.appendChild(empty);
      return;
    }

    const onListMutation = async (affectedId) => {
      if (activeConversationId === affectedId) {
        activeConversationId = null;
        resetThread();
      }
      await loadConversations();
    };

    const makeBtn = (txt, title, fn) => {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "conv-action";
      b.textContent = txt;
      b.title = title;
      b.addEventListener("click", async (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
        await fn();
      });
      return b;
    };

    filtered.forEach(c => {
      const item = document.createElement("div");
      item.className = "conv-item" + (c.id === activeConversationId ? " active" : "");
      item.dataset.id = c.id;

      const title = document.createElement("div");
      title.className = "conv-title";
      title.textContent = c.title || "New chat";

      const prev = document.createElement("div");
      prev.className = "conv-preview";
      prev.textContent = c.last_preview || "";

      const actions = document.createElement("div");
      actions.className = "conv-actions";

            // Rename
      actions.appendChild(makeIconBtn("rename", "Rename", async () => {
        const currentTitle = (c.title || "New chat");
        const nextTitle = await modalPrompt("Rename chat", currentTitle, "Enter a new title", "Save");
        if (nextTitle === null) return;

        const clean = (nextTitle || "").trim();
        if (!clean) return;

        try {
          await fetchJSON("/api/conversations/" + encodeURIComponent(c.id), {
            method: "PATCH",
            headers: { "Content-Type": "application/json", "Accept": "application/json" },
            body: JSON.stringify({ title: clean })
          });
          await loadConversations();
          setActiveConversation(c.id);
        } catch (e) {
          await modalConfirm("Rename failed", e.message || "Error", "OK");
        }
      }));

      if (currentStatus === "active") {
        actions.appendChild(makeIconBtn("archive", "Archive", async () => {
          const ok = await modalConfirm("Archive chat?", "You can restore it from Archived.", "Archive");
          if (!ok) return;
          await apiPost("/api/conversations/" + encodeURIComponent(c.id) + "/archive");
          await onListMutation(c.id);
        }));

        actions.appendChild(makeIconBtn("trash", "Move to Trash", async () => {
          const ok = await modalConfirm("Move to Trash?", "You can restore it from Trash.", "Trash");
          if (!ok) return;
          await apiPost("/api/conversations/" + encodeURIComponent(c.id) + "/trash");
          await onListMutation(c.id);
        }));
      } else if (currentStatus === "archived") {
        actions.appendChild(makeIconBtn("restore", "Unarchive", async () => {
          await apiPost("/api/conversations/" + encodeURIComponent(c.id) + "/unarchive");
          await onListMutation(c.id);
        }));

        actions.appendChild(makeIconBtn("trash", "Move to Trash", async () => {
          const ok = await modalConfirm("Move to Trash?", "You can restore it from Trash.", "Trash");
          if (!ok) return;
          await apiPost("/api/conversations/" + encodeURIComponent(c.id) + "/trash");
          await onListMutation(c.id);
        }));
      } else if (currentStatus === "deleted") {
        actions.appendChild(makeIconBtn("restore", "Restore", async () => {
          await apiPost("/api/conversations/" + encodeURIComponent(c.id) + "/restore");
          await onListMutation(c.id);
        }));

        actions.appendChild(makeIconBtn("kill", "Delete permanently", async () => {
          const ok = await modalConfirm("Delete permanently?", "This cannot be undone.", "Delete");
          if (!ok) return;
          await apiDelete("/api/conversations/" + encodeURIComponent(c.id));
          await onListMutation(c.id);
        }));
      }

      item.addEventListener("click", () => openConversation(c.id));

      item.appendChild(title);
      item.appendChild(prev);
      item.appendChild(actions);
      convList.appendChild(item);
    });

    if (!activeConversationId && openFromUrl) {

      openConversation(openFromUrl).catch(e => console.error(e));
    }
  }

  async function loadConversations() {
    if (!authed) return;

    try {
      const data = await fetchJSON(
        "/api/conversations?profile_id=" + encodeURIComponent(profileId) +
        "&status=" + encodeURIComponent(currentStatus)
      );

      conversationsCache = data?.conversations || [];
      renderConversations(conversationsCache);

      // se non c'ÃÂ¨ una chat attiva, apri la prima
      if (!activeConversationId && conversationsCache.length) {
        await openConversation(conversationsCache[0].id);
      } else if (!activeConversationId) {
        resetThread();
      }
    } catch (e) {
      convList.innerHTML = "";
      const err = document.createElement("div");
      err.className = "conv-locked";
      err.textContent = "Could not load conversations: " + e.message;
      convList.appendChild(err);
      resetThread();
    }
  }

  async function openConversation(convId) {
    if (!authed || !convId) return;

    try {
      const data = await fetchJSON("/api/conversations/" + encodeURIComponent(convId));
      setActiveConversation(convId);
      thread.innerHTML = "";

      const msgs = data?.messages || [];
      if (!msgs.length) {
        appendGreeting();
      } else {
        msgs.forEach(m => {
          const role = (m.role === "user") ? "user" : "ai";
          appendBubble(role, m.content || "");
        });
      }
    } catch (e) {
      resetThread();
      appendBubble("ai", "Error loading this chat. Try again.");
    }
  }

  async function createConversationWithTitle(title) {
    const data = await fetchJSON("/api/conversations", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ profile_id: profileId, title: title || "New chat" })
    });
    return data?.conversation || null;
  }

function makeIconBtn(icon, title, onClick) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "conv-action";
  b.title = title;
  b.innerHTML = ICONS[icon] || "";
  b.addEventListener("click", (ev) => { ev.preventDefault(); ev.stopPropagation(); onClick(); });
  return b;
}


  function wireFilters() {
    if (!filterWrap) return;
    const buttons = filterWrap.querySelectorAll(".conv-filter");
    buttons.forEach(btn => {
      btn.addEventListener("click", async () => {
        const next = (btn.dataset.status || "active").toLowerCase();
        if (next === currentStatus) return;

        currentStatus = next;
        buttons.forEach(b => b.classList.toggle("is-active", b === btn));

        // reset selection quando cambio tab
        activeConversationId = null;
        convSearch.value = "";
        await loadConversations();
      });
    });
  }

  // --- MODE B (token / no login) => /api/chat ---
  if (!authed) {
    if (convLocked) convLocked.style.display = "block";
    if (filterWrap) filterWrap.style.display = "none";
    resetThread();

    convNewBtn?.addEventListener("click", () => {
      resetThread();
      input?.focus();
    });

    form?.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      if (sending) return;

      const value = (input?.value || "").trim();
      if (!value) return;

      appendBubble("user", value);
      input.value = "";
      setSending(true);

      try {
        const csrf = getCookie("csrf_token") || "";

        const data = await fetchJSON("/api/chat", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: value, token, profile_id: profileId, csrf })
        });

        appendBubble("ai", data?.reply || "No reply.");
      } catch (e) {
        appendBubble("ai", "Error sending message. Please try again.");
      } finally {
        setSending(false);
        input?.focus();
      }
    });

    return;
  }

  // --- MODE A (logged in) => conversations DB ---
  if (convLocked) convLocked.style.display = "none";
  resetThread();
  wireFilters();
  loadConversations();

  convSearch?.addEventListener("input", () => renderConversations(conversationsCache));

  convNewBtn?.addEventListener("click", () => {
    activeConversationId = null;
    renderConversations(conversationsCache);
    resetThread();
    input?.focus();
  });

  form?.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (sending) return;

    const value = (input?.value || "").trim();
    if (!value) return;

    appendBubble("user", value);
    input.value = "";
    setSending(true);

    try {
      // se non c'ÃÂ¨ una chat attiva, creala (titolo dal primo messaggio)
      if (!activeConversationId) {
        const created = await createConversationWithTitle(titleFromFirstMessage(value));
        if (!created?.id) throw new Error("Conversation create failed");
        activeConversationId = created.id;
        await loadConversations();
        setActiveConversation(activeConversationId);
      }

      const data = await fetchJSON(
        "/api/conversations/" + encodeURIComponent(activeConversationId) + "/message",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ message: value })
        }
      );

      appendBubble("ai", data?.reply || "No reply.");
      await loadConversations();
      setActiveConversation(activeConversationId);
    } catch (e) {
      appendBubble("ai", "Error sending message: " + e.message);
    } finally {
      setSending(false);
      input?.focus();
    }
  });
})();
    """.strip()

    body = f"""
      <section class="hero-wrap console-wrap">
        <div class="console-card" id="console-root"
             data-profile-id="{html_escape.escape(profile_id)}"
             data-token="{html_escape.escape(token or '')}"
             data-authed="{authed}">
          <div class="console-header-top">
            <div>
              <div class="console-eyebrow">amamau / insight AI console</div>
              <div class="console-title">Business assistant on brief.</div>
              <div class="console-sub">
                Profile: <strong>{html_escape.escape(profile_name)}</strong>
                &nbsp;&middot;&nbsp;
                Access: <span>{html_escape.escape(email_label)}</span>
                &nbsp;&middot;&nbsp;
                <a href="/account">Account</a>
                &nbsp;&middot;&nbsp;
                <a href="/workspace">Workspace</a>
              </div>
            </div>
            <div class="token-pill">
              Token / session: <strong>{html_escape.escape(token_label)}</strong>
            </div>
          </div>

          <div class="console-grid">
            <aside class="conv-sidebar" id="conv-sidebar">
              <div class="conv-sidebar-top">
                <button class="conv-new" id="conv-new" type="button">New chat</button>
              </div>

              <input class="conv-search" id="conv-search" type="text" placeholder="Search chats..." autocomplete="off"/>

              <div class="conv-filters" id="conv-filters">
                <button class="conv-filter is-active" type="button" data-status="active">Chats</button>
                <button class="conv-filter" type="button" data-status="archived">Archived</button>
                <button class="conv-filter" type="button" data-status="deleted">Trash</button>
              </div>

              <div class="conv-list" id="conv-list">
                <div class="conv-locked" id="conv-locked" style="display:none;">
                  History is available only for logged-in sessions (cookie-based).<br/>
                  Open <strong>/</strong> and sign in to see your chats.
                </div>
              </div>
            </aside>

            <div class="console-main">
              <div class="chat-shell">
                <div class="chat-thread" id="chat-thread"></div>

                <form class="chat-form" id="chat-form" onsubmit="return false;">
                  <input type="text"
                         id="chat-input"
                         class="chat-input"
                         placeholder="Ask something about your business, pricing or offers..."
                         autocomplete="off" />
                  <button class="chat-send-btn" type="submit" id="chat-send">Send</button>
                </form>

                <div class="console-meta">
                  <span>amamau AI</span>
                  <span>Enter = send, Shift + Enter = new line.</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

<style>
  /* sidebar quick actions */
  .conv-item {{ position: relative; padding-right: 132px; }}
  .conv-actions{{
    position:absolute; top:10px; right:10px;
    display:flex; gap:6px;
    opacity:0; transform: translateY(0);
    transition: opacity var(--transition), transform var(--transition);
    z-index: 6;
  }}
  .conv-item:hover .conv-actions{{ opacity:1; transform: translateY(-1px); }}
  .conv-item.active .conv-actions{{ opacity:1; }}
  .conv-action{{
    width:34px; height:34px;
    border-radius:999px;
    border:1px solid rgba(0,0,0,0.08);
    background: rgba(255,255,255,0.7);
    cursor:pointer;
    display:flex; align-items:center; justify-content:center;
    font-size:14px; user-select:none;
  }}
  .conv-action:hover{{ background: rgba(255,255,255,0.95); }}
  .conv-item.active .conv-action{{
    background: rgba(255,255,255,0.12);
    border-color: rgba(255,255,255,0.20);
    color:#fff;
  }}

 .bubble-content {{ white-space: normal; }}
  .bubble-content .md-pre {{ margin: .5rem 0; padding: .6rem .7rem; border-radius: 12px; overflow-x:auto; background: rgba(0,0,0,0.06); }}
  .bubble-content .md-inline {{ padding: 0.1rem 0.35rem; border-radius: 8px; background: rgba(0,0,0,0.08); }}
  .bubble-content .md-ul {{ margin: .35rem 0 .35rem 1.1rem; padding: 0; }}
  .conv-action svg {{ width: 16px; height: 16px; }}

.conv-action {{ color: #111; }}
.conv-item.active .conv-action {{ color:#fff; }}

.conv-action svg {{
  display:block;
  width:16px;
  height:16px;
  pointer-events:none;
}}


</style>


      <script>{script}</script>
    """
    return render_layout(body, "amamau Insight AI - Console", current_page="console", session_email=session_email)

def render_account_page(
    user: dict,
    info: str = "",
    error: str = "",
    email_otp_id: str = "",
    pending_new_email: str = "",
) -> str:
    name = html_escape.escape(str(user.get("name") or ""))
    email = html_escape.escape(str(user.get("email") or ""))
    profile_id = html_escape.escape(str(user.get("profile_id") or ""))

    info_html = f'<div class="alert ok">{html_escape.escape(info)}</div>' if info else ""
    error_html = f'<div class="alert err">{html_escape.escape(error)}</div>' if error else ""

    otp_block = ""
    if email_otp_id:
        otp_block = f"""
          <div class="console-card" style="margin-top:16px;">
            <div class="card-title">Confirm email change</div>
            <div class="muted" style="margin-top:6px;">
              We sent a 6 digit code to <strong>{html_escape.escape(pending_new_email)}</strong>.
            </div>

            <form method="POST" action="/account/email/verify" style="margin-top:12px;">
              <input type="hidden" name="otp_id" value="{html_escape.escape(email_otp_id)}" />
              <div class="form-field">
                <label>6 digit code</label>
                <input name="otp_code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456" required />
              </div>
              <div class="form-actions">
                <button class="btn primary" type="submit">Verify</button>
              </div>
            </form>
          </div>
        """

    # workspace summary (best-effort)
    ws_html = ""
    try:
        ws_list = list_user_workspaces(str(user.get("id") or ""))
        ws_count = len(ws_list)
        ws_label = f"{ws_count} workspace" + ("s" if ws_count != 1 else "")
        ws_html = f"""
          <div class="console-card" style="margin-top:16px;">
            <div class="card-title">Workspace</div>
            <div class="muted" style="margin-top:8px;">
              {html_escape.escape(ws_label)} linked to this account.
            </div>
            <div class="form-actions" style="margin-top:12px;">
              <a class="btn primary" href="/workspace">Open workspace</a>
            </div>
          </div>
        """
    except Exception:
        ws_html = ""

    logout_all_js = """
    <script>
    (function(){
      const btn = document.getElementById("logoutAllBtn");
      if (!btn) return;
      btn.addEventListener("click", async () => {
        const ok = await window.modalConfirm(
          "Logout from all devices",
          "This will invalidate all active sessions. You will need to sign in again.",
          "Logout all"
        );
        if (!ok) return;
        btn.disabled = true;
        try {
          await window.fetchJSON("/logout_all", { method: "POST" });
          await window.modalConfirm("Done", "All sessions were invalidated.", "OK");
          window.location.href = "/";
        } catch (e) {
          await window.modalConfirm("Error", (e && e.message) ? e.message : "Request failed", "OK");
          btn.disabled = false;
        }
      });
    })();
    </script>
    """

    body = f"""
    <div class="hero-wrap">
      <div class="hero-grid">
        <div>
          <div class="kicker">ACCOUNT</div>
          <h1 class="hero-title">Account settings</h1>
          <p class="hero-sub">
            Manage your profile, email and password.
          </p>

          {info_html}
          {error_html}

          <div class="console-card" style="margin-top:16px;">
            <div class="card-title">Current</div>
            <div class="muted" style="margin-top:8px;">
              <div><strong>Name:</strong> {name or "-"}</div>
              <div><strong>Email:</strong> {email or "-"}</div>
              <div><strong>Profile:</strong> {profile_id or "-"}</div>
            </div>
          </div>
        </div>

        <div class="hero-side">
          <div class="console-card">
            <div class="card-title">Change display name</div>
            <form method="POST" action="/account/name" style="margin-top:12px;">
              <div class="form-field">
                <label>New name</label>
                <input name="new_name" value="{name}" placeholder="Your name" required />
              </div>
              <div class="form-actions">
                <button class="btn primary" type="submit">Save</button>
              </div>
            </form>
          </div>

          <div class="console-card" style="margin-top:16px;">
            <div class="card-title">Change email</div>
            <form method="POST" action="/account/email/start" style="margin-top:12px;">
              <div class="form-field">
                <label>New email</label>
                <input name="new_email" type="email" placeholder="new@email.com" required />
              </div>
              <div class="form-field">
                <label>Current password</label>
                <input name="current_password" type="password" autocomplete="current-password" required />
              </div>
              <div class="form-actions">
                <button class="btn primary" type="submit">Send code</button>
              </div>
            </form>
          </div>

          {otp_block}

          <div class="console-card" style="margin-top:16px;">
            <div class="card-title">Change password</div>
            <div class="muted" style="margin-top:8px;">Minimum: 10 characters, at least 1 number.</div>
            <form method="POST" action="/account/password" style="margin-top:12px;">
              <div class="form-field">
                <label>Current password</label>
                <input name="current_password" type="password" autocomplete="current-password" required />
              </div>
              <div class="form-field">
                <label>New password</label>
                <input name="new_password" type="password" autocomplete="new-password" required />
              </div>
              <div class="form-field">
                <label>Confirm new password</label>
                <input name="new_password_confirm" type="password" autocomplete="new-password" required />
              </div>
              <div class="form-actions">
                <button class="btn primary" type="submit">Update password</button>
              </div>
            </form>
          </div>

          <div class="console-card" style="margin-top:16px;">
            <div class="card-title">Security</div>
            <div class="muted" style="margin-top:8px;">
              Logout from all devices invalidates every active session for this account.
            </div>
            <div class="form-actions" style="margin-top:12px;">
              <button class="btn primary" id="logoutAllBtn" type="button">Logout from all devices</button>
            </div>
          </div>

          {ws_html}

        </div>
      </div>
    </div>

    {logout_all_js}
    """

    # NB: current_page lo metto "account" anche se la navbar evidenzia solo home/console
    return render_layout(body, title="Account", current_page="account", session_email=user.get("email"))


def _get_user_by_id(uid: str) -> Optional[Dict]:
    uid = str(uid or "").strip()
    if not uid:
        return None
    try:
        users = _load_users_for_web()
        for u in users:
            if str(u.get("id") or "") == uid:
                return u
    except Exception:
        return None
    return None


def render_workspace_page(
    user: dict,
    info: str = "",
    error: str = "",
) -> str:
    user_id = str(user.get("id") or "")
    info_html = f'<div class="alert ok">{html_escape.escape(info)}</div>' if info else ""
    error_html = f'<div class="alert err">{html_escape.escape(error)}</div>' if error else ""

    ws_list = []
    try:
        ws_list = list_user_workspaces(user_id)
    except Exception:
        ws_list = []

    ws_cards = []
    if not ws_list:
        ws_cards.append(
            '<div class="console-card"><div class="muted">No workspace found. (This should be rare; refresh or contact support.)</div></div>'
        )
    else:
        for ws, role in ws_list:
            ws_id = str(ws.get("id") or "")
            ws_name = html_escape.escape(str(ws.get("name") or "Workspace"))
            role_label = html_escape.escape(str(role or "member"))

            # members table
            members = []
            try:
                members = list_members(ws_id)
            except Exception:
                members = []

            rows = []
            for m in members:
                mid = str(m.get("user_id") or "")
                mrole = str(m.get("role") or "member")
                mu = _get_user_by_id(mid) or {}
                mem_email = html_escape.escape(str(mu.get("email") or mid))
                mem_name = html_escape.escape(str(mu.get("name") or ""))
                label = mem_email if not mem_name else f"{mem_name} &middot; {mem_email}"
                actions = ""
                if role == "owner" and mrole != "owner":
                    actions = f"""
                      <form method=\"POST\" action=\"/workspace/member/remove\" class=\"ws-remove-form\" style=\"margin:0;\">
                        <input type=\"hidden\" name=\"workspace_id\" value=\"{html_escape.escape(ws_id)}\" />
                        <input type=\"hidden\" name=\"member_user_id\" value=\"{html_escape.escape(mid)}\" />
                        <button class=\"btn\" type=\"submit\">Remove</button>
                      </form>
                    """
                rows.append(
                    f"<tr><td>{label}</td><td><span class='muted'>{html_escape.escape(mrole)}</span></td><td style='text-align:right'>{actions}</td></tr>"
                )

            members_html = (
                "<div class='muted' style='margin-top:8px;'>Members</div>"
                + "<div style='overflow-x:auto; margin-top:8px;'><table style='width:100%; border-collapse:collapse;'>"
                + "<thead><tr><th style='text-align:left; padding:8px 0; border-bottom:1px solid rgba(0,0,0,0.08);'>User</th><th style='text-align:left; padding:8px 0; border-bottom:1px solid rgba(0,0,0,0.08);'>Role</th><th style='padding:8px 0; border-bottom:1px solid rgba(0,0,0,0.08);'></th></tr></thead>"
                + "<tbody>" + "".join(rows) + "</tbody></table></div>"
            )

            invite_html = ""
            if role == "owner":
                invite_html = f"""
                  <div class=\"muted\" style=\"margin-top:14px;\">Invite member</div>
                  <form method=\"POST\" action=\"/workspace/invite\" style=\"margin-top:10px;\">
                    <input type=\"hidden\" name=\"workspace_id\" value=\"{html_escape.escape(ws_id)}\" />
                    <div class=\"form-field\">
                      <label>Email</label>
                      <input name=\"email\" type=\"email\" placeholder=\"member@email.com\" required />
                    </div>
                    <div class=\"form-actions\">
                      <button class=\"btn primary\" type=\"submit\">Send invite</button>
                    </div>
                  </form>
                """

            ws_cards.append(
                f"""
                <div class=\"console-card\" style=\"margin-top:16px;\">
                  <div class=\"card-title\">{ws_name}</div>
                  <div class=\"muted\" style=\"margin-top:8px;\">
                    <div><strong>Workspace ID:</strong> {html_escape.escape(ws_id)}</div>
                    <div><strong>Your role:</strong> {role_label}</div>
                  </div>
                  <div class=\"form-actions\" style=\"margin-top:12px; display:flex; gap:10px; flex-wrap:wrap;\">
                    <a class=\"btn primary\" href=\"/w/{html_escape.escape(ws_id)}\">Open chat</a>
                    <a class=\"btn\" href=\"/w/{html_escape.escape(ws_id)}/projects\">Projects</a>
                  </div>
                  {members_html}
                  {invite_html}
                </div>
                """
            )

    remove_member_js = """
    <script>
    // Confirm remove member using existing modal
    (function(){
      document.querySelectorAll('.ws-remove-form').forEach((form) => {
        form.addEventListener('submit', async (ev) => {
          ev.preventDefault();
          const ok = await window.modalConfirm('Remove member', 'Remove this member from the workspace?', 'Remove');
          if (!ok) return;
          form.submit();
        });
      });
    })();
    </script>
    """

    body = f"""
    <div class=\"hero-wrap\">
      <div class=\"hero-grid\">
        <div>
          <div class=\"kicker\">WORKSPACE</div>
          <h1 class=\"hero-title\">Team & workspace</h1>
          <p class=\"hero-sub\">Create workspaces, invite members, manage roles.</p>

          {info_html}
          {error_html}

          <div class=\"console-card\" style=\"margin-top:16px;\">
            <div class=\"card-title\">Create workspace</div>
            <form method=\"POST\" action=\"/workspace/create\" style=\"margin-top:12px;\">
              <div class=\"form-field\">
                <label>Name</label>
                <input name=\"name\" placeholder=\"My workspace\" required />
              </div>
              <div class=\"form-actions\">
                <button class=\"btn primary\" type=\"submit\">Create</button>
              </div>
            </form>
          </div>
        </div>

        <div class=\"hero-side\">
          <div class=\"console-card\">
            <div class=\"card-title\">Your workspaces</div>
            <div class=\"muted\" style=\"margin-top:8px;\">Account: <strong>{html_escape.escape(str(user.get('email') or ''))}</strong></div>
          </div>
          {''.join(ws_cards)}
        </div>
      </div>
    </div>
    {remove_member_js}
    """

    return render_layout(body, title="Workspace", current_page="workspace", session_email=user.get("email"))


def render_workspace_invite_page(token: str, invite: Optional[Dict[str, Any]], session_email: Optional[str]) -> str:
    token_esc = html_escape.escape(token or "")
    if not invite:
        body = f"""
        <div class=\"hero-wrap\">
          <div class=\"console-card\">
            <div class=\"card-title\">Invite not valid</div>
            <div class=\"muted\" style=\"margin-top:8px;\">This invite link is invalid or expired.</div>
            <div class=\"form-actions\" style=\"margin-top:12px;\"><a class=\"btn primary\" href=\"/\">Go home</a></div>
          </div>
        </div>
        """
        return render_layout(body, title="Invite", current_page="workspace", session_email=session_email)

    ws_id = str(invite.get("workspace_id") or "")
    invited_email = html_escape.escape(str(invite.get("email") or ""))
    exp = html_escape.escape(str(invite.get("expires_at") or ""))

    if not session_email:
        body = f"""
        <div class=\"hero-wrap\">
          <div class=\"console-card\">
            <div class=\"card-title\">Workspace invite</div>
            <div class=\"muted\" style=\"margin-top:8px;\">Invite for <strong>{invited_email}</strong>. Expires: {exp}</div>
            <div class=\"form-actions\" style=\"margin-top:12px;\">
              <a class=\"btn primary\" href=\"/?next=/workspace/invite/{token_esc}\">Sign in to accept</a>
            </div>
          </div>
        </div>
        """
        return render_layout(body, title="Invite", current_page="workspace", session_email=session_email)

    # logged in
    body = f"""
    <div class=\"hero-wrap\">
      <div class=\"console-card\">
        <div class=\"card-title\">Workspace invite</div>
        <div class=\"muted\" style=\"margin-top:8px;\">Invite for <strong>{invited_email}</strong>. Expires: {exp}</div>
        <form method=\"POST\" action=\"/workspace/invite/accept\" style=\"margin-top:12px;\">
          <input type=\"hidden\" name=\"token\" value=\"{token_esc}\" />
          <div class=\"form-actions\">
            <button class=\"btn primary\" type=\"submit\">Accept invite</button>
            <a class=\"btn\" href=\"/workspace\">Back to workspace</a>
          </div>
        </form>
      </div>
    </div>
    """
    return render_layout(body, title="Invite", current_page="workspace", session_email=session_email)


# -------------------------------------------------------------------
# Routes
# -------------------------------------------------------------------


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    email = get_email_from_request(request)
    next_url = _safe_next_url(str(request.query_params.get("next") or ""))
    if email and next_url:
        return RedirectResponse(url=next_url, status_code=302)
    info = ""
    if email:
        info = f"You are logged in as {email} - you can open the console from the menu."
    html = render_index_page(info=info, session_email=email, next_url=next_url)
    return HTMLResponse(html)


@app.get("/token", response_class=HTMLResponse)
async def open_token(token: str = ""):
    token_clean = token.strip()
    if not token_clean:
        return RedirectResponse(url="/", status_code=302)
    return RedirectResponse(url=f"/t/{token_clean}", status_code=302)

@app.get("/account", response_class=HTMLResponse)
async def account_page(request: Request) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page_safe(request, info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(
            info="",
            error="Account not active.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=403)

    html = render_account_page(user, info="", error="")
    return HTMLResponse(html)

from fastapi import Request
from fastapi.responses import RedirectResponse, HTMLResponse

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    err = (request.query_params.get("err") or "").strip()
    msg = ""
    if err in ("missing", "1"):
        msg = "Missing credentials."
    elif err == "csrf":
        msg = "Session expired, please retry."
    elif err:
        msg = "Login error. Please retry."
    csrf_cookie = str(request.cookies.get("csrf_token") or "") or _random_csrf_cookie()
    html = render_index_page_safe(request, info="", error=msg, otp_phase=False, csrf_token=csrf_cookie)
    resp = HTMLResponse(html)
    if not request.cookies.get("csrf_token"):
        resp.set_cookie(
            "csrf_token",
            csrf_cookie,
            httponly=False,
            secure=_cookie_secure(request),
            samesite="lax",
            max_age=6 * 60 * 60,
        )
    return resp

from fastapi import Request

# @app.post("/login")
# async def login_submit(request: Request):
#     ct = (request.headers.get("content-type") or "").lower()
# 
#     if "application/json" in ct:
#         data = await request.json()
#     else:
#         form = await request.form()
#         data = dict(form)
# 
#     email = (data.get("email") or "").strip().lower()
#     password = (data.get("password") or "")
# 
#     if not email or not password:
#         return RedirectResponse("/login?err=1", status_code=303)
# 
    # qui richiami la tua logica esistente di login (create session + set cookie)
#     resp = RedirectResponse("/console", status_code=303)
    # set_session_cookie(resp, session_id, ...)
#     return resp
# 
#     user = get_user_by_email(email)
#     if not user or not verify_password(password, user["password_hash"]):
#         return RedirectResponse("/login?err=badcreds", status_code=303)
# 
#     session_id = create_session(email=email, user_agent=request.headers.get("user-agent",""), ip=request.client.host if request.client else "")
#     resp = RedirectResponse("/console", status_code=303)
#     set_session_cookie(resp, session_id)  # <- questa è fondamentale
#     return resp
# 
# 
# 
@app.get("/api/conversations")
async def api_list_conversations(request: Request) -> JSONResponse:
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Not authenticated."}, status_code=401)

    profile_id = (request.query_params.get("profile_id") or "").strip()
    status = (request.query_params.get("status") or "active").strip().lower()

    # active | archived | deleted
    if status not in ("active", "archived", "deleted"):
        status = "active"

    convs = db_list_conversations(
        user_email=email,
        profile_id=profile_id or None,
        limit=80,
        status=status,            # <-- QUI
    )
    return JSONResponse({"conversations": convs, "status": status})


@app.post("/api/conversations")
async def api_create_conversation(request: Request) -> JSONResponse:
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Not authenticated."}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        data = {}

    profile_id = str((data or {}).get("profile_id") or "").strip()
    if not profile_id:
        user = get_user_by_email(email)
        if user:
            profile_id = str(user.get("profile_id") or "").strip()

    if not profile_id:
        return JSONResponse({"error": "No profile linked to this user."}, status_code=400)

    title = str((data or {}).get("title") or "").strip() or "New chat"
    conv_id = uuid.uuid4().hex
    conv = db_create_conversation(conv_id=conv_id, user_email=email, profile_id=profile_id, title=title)
    return JSONResponse({"conversation": conv})


@app.get("/api/conversations/{conversation_id}")
async def api_get_conversation(request: Request, conversation_id: str) -> JSONResponse:
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Not authenticated."}, status_code=401)

    conversation_id = (conversation_id or "").strip()
    conv = db_get_conversation(user_email=email, conversation_id=conversation_id)
    if not conv:
        return JSONResponse({"error": "Conversation not found."}, status_code=404)

    messages = db_list_messages(user_email=email, conversation_id=conversation_id, limit=400)
    return JSONResponse({"conversation": conv, "messages": messages})

@app.patch("/api/conversations/{conversation_id}")
async def api_update_conversation(request: Request, conversation_id: str) -> JSONResponse:
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Not authenticated."}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    title = str((data or {}).get("title") or "").strip()
    if not title:
        return JSONResponse({"error": "Missing title."}, status_code=400)

    conversation_id = (conversation_id or "").strip()
    if not conversation_id:
        return JSONResponse({"error": "Invalid conversation id."}, status_code=400)

    conv = db_get_conversation(user_email=email, conversation_id=conversation_id)
    if not conv:
        return JSONResponse({"error": "Conversation not found."}, status_code=404)

    ok = db_update_conversation_title(
        user_email=email,
        conversation_id=conversation_id,
        title=title,
    )
    if not ok:
        return JSONResponse({"error": "Unable to update title."}, status_code=500)

    conv2 = db_get_conversation(user_email=email, conversation_id=conversation_id) or conv
    return JSONResponse({"conversation": conv2})


@app.post("/api/conversations/{conversation_id}/message")
async def api_send_message(request: Request, conversation_id: str) -> JSONResponse:
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Not authenticated."}, status_code=401)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    message = str((data or {}).get("message") or "").strip()
    if not message:
        return JSONResponse({"error": "Empty message."}, status_code=400)

    conversation_id = (conversation_id or "").strip()
    conv = db_get_conversation(user_email=email, conversation_id=conversation_id)
    if not conv:
        return JSONResponse({"error": "Conversation not found."}, status_code=404)

    profile_id = str(conv.get("profile_id") or "").strip()
    if not profile_id:
        return JSONResponse({"error": "Conversation has no profile."}, status_code=400)

    # Auto-title (solo se ? ancora "New chat")
    try:
        current_title = str(conv.get("title") or "").strip().lower()
        if current_title in ("", "new chat"):
            db_update_conversation_title(
                user_email=email,
                conversation_id=conversation_id,
                title=_title_from_msg(message),
            )
    except Exception:
        pass

    prev = db_list_messages(user_email=email, conversation_id=conversation_id, limit=400)
    history_pairs = db_build_history_pairs(prev, max_pairs=6)

    db_add_message(user_email=email, conversation_id=conversation_id, role="user", content=message)

    reply = run_llm_for_profile_with_history(profile_id, message, history_pairs)

    db_add_message(user_email=email, conversation_id=conversation_id, role="assistant", content=reply)

    return JSONResponse({"reply": reply})



@app.post("/account/name", response_class=HTMLResponse)
async def account_update_name(request: Request, new_name: str = Form(...)) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page_safe(request, info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    new_name = new_name.strip()
    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(
            info="",
            error="Account not active.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=403)

    if not new_name:
        html = render_account_page(user, info="", error="Name cannot be empty.")
        return HTMLResponse(html, status_code=400)

    users = _load_users_for_web()
    email_norm = _normalize_email_addr(email)
    updated = False
    for u in users:
        if _normalize_email_addr(str(u.get("email", ""))) == email_norm:
            u["name"] = new_name
            updated = True
            break
    if updated:
        _save_users_for_web(users)
        user = get_user_by_email(email) or user
        html = render_account_page(user, info="Name updated.", error="")
        return HTMLResponse(html)
    else:
        html = render_account_page(user, info="", error="User not found while saving.")
        return HTMLResponse(html, status_code=500)


@app.post("/account/email/start", response_class=HTMLResponse)
async def account_email_start(
    request: Request,
    new_email: str = Form(...),
    current_password: str = Form(...),
) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page_safe(request, info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(
            info="",
            error="Account not active.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=403)

    new_email_norm = _normalize_email_addr(new_email)
    if not new_email_norm or "@" not in new_email_norm:
        html = render_account_page(user, info="", error="Please enter a valid email address.")
        return HTMLResponse(html, status_code=400)

    if new_email_norm == _normalize_email_addr(email):
        html = render_account_page(user, info="", error="New email must be different from current one.")
        return HTMLResponse(html, status_code=400)

    # password check
    stored_hash = user.get("password_hash") or ""
    if not verify_password(current_password, stored_hash):
        html = render_account_page(user, info="", error="Current password is not correct.")
        return HTMLResponse(html, status_code=400)

    # email already in use?
    other = get_user_by_email(new_email_norm)
    if other and _normalize_email_addr(other.get("email", "")) != _normalize_email_addr(email):
        html = render_account_page(user, info="", error="This email is already used by another account.")
        return HTMLResponse(html, status_code=400)

    otp_id, otp_code = create_account_email_change_otp(email, new_email_norm)

    # invia mail OTP alla nuova email
    subject = "amamau Insight AI - confirm email change"
    html_body = f"""
      <p>We received a request to change your login email for amamau Insight AI.</p>
      <p>New email: <strong>{html_escape.escape(new_email_norm)}</strong></p>
      <p>Your one-time code is:</p>
      <p style="font-size:24px; font-weight:600; letter-spacing:0.25em;">{otp_code}</p>
      <p>This code expires in 10 minutes. If you did not request this, you can ignore this email.</p>
    """
    _send_email(new_email_norm, subject, html_body)

    html = render_account_page(
        user,
        info=f"We sent a 6 digit code to {new_email_norm}.",
        error="",
        email_otp_id=otp_id,
        pending_new_email=new_email_norm,
    )
    return HTMLResponse(html)


@app.post("/account/email/verify", response_class=HTMLResponse)
async def account_email_verify(
    request: Request,
    otp_id: str = Form(...),
    otp_code: str = Form(...),
) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page_safe(request, info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(
            info="",
            error="Account not active.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=403)

    result = consume_account_email_change_otp(otp_id.strip(), otp_code.strip())
    if not result:
        html = render_account_page(user, info="", error="Code not valid or expired.")
        return HTMLResponse(html, status_code=400)

    current_email_norm, new_email_norm = result

    if _normalize_email_addr(email) != current_email_norm:
        html = render_account_page(user, info="", error="OTP does not match current session.")
        return HTMLResponse(html, status_code=400)

    # aggiorna users.json (con rollback in caso di errori)
    users = _load_users_for_web()
    if any(_normalize_email_addr(str(u.get("email", ""))) == new_email_norm for u in users):
        html = render_account_page(user, info="", error="Email already in use.")
        return HTMLResponse(html, status_code=400)

    updated = False
    user_id = str(user.get("id") or "")
    for u in users:
        if _normalize_email_addr(str(u.get("email", ""))) == current_email_norm:
            u["email"] = new_email_norm
            user_id = str(u.get("id") or user_id)
            updated = True
            break
    if not updated:
        html = render_account_page(user, info="", error="User not found while saving.")
        return HTMLResponse(html, status_code=500)

    _save_users_for_web(users)

    # migrate data in DB (con rollback file se fallisce)
    try:
        db_migrate_user_email(old_email=current_email_norm, new_email=new_email_norm)
        sid = request.cookies.get("ai_session")
        if sid:
            db_update_session_email(session_id=sid, new_user_email=new_email_norm)
    except Exception as exc:
        # rollback users.json
        try:
            users_rb = _load_users_for_web()
            for u in users_rb:
                if _normalize_email_addr(str(u.get("email", ""))) == new_email_norm and str(u.get("id") or "") == user_id:
                    u["email"] = current_email_norm
                    break
            _save_users_for_web(users_rb)
        except Exception:
            pass
        html = render_account_page(user, info="", error=f"Failed to migrate data: {exc}")
        return HTMLResponse(html, status_code=500)

    # rename chat history file (best-effort)
    try:
        old_path = CHAT_HISTORY_DIR / f"{_email_slug(current_email_norm)}.jsonl"
        new_path = CHAT_HISTORY_DIR / f"{_email_slug(new_email_norm)}.jsonl"
        if old_path.exists() and not new_path.exists():
            old_path.replace(new_path)
    except Exception:
        pass

    # audit (best-effort)
    try:
        audit_event(
            event="change_email",
            user_email=new_email_norm,
            user_id=user_id or None,
            ip=str(getattr(request.client, "host", "") or "") or None,
            ua=str(request.headers.get("user-agent") or "") or None,
            meta={"from": current_email_norm, "to": new_email_norm},
        )
    except Exception:
        pass

    # ricarica user aggiornato
    updated_user = get_user_by_email(new_email_norm) or {**user, "email": new_email_norm}
    html = render_account_page(updated_user, info="Email updated.", error="")
    return HTMLResponse(html)


@app.post("/account/password", response_class=HTMLResponse)
async def account_update_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    new_password_confirm: str = Form(...),
) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page_safe(request, info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(
            info="",
            error="Account not active.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=403)

    stored_hash = user.get("password_hash") or ""
    if not verify_password(current_password, stored_hash):
        html = render_account_page(user, info="", error="Current password is not correct.")
        return HTMLResponse(html, status_code=400)

    if new_password != new_password_confirm:
        html = render_account_page(user, info="", error="New passwords do not match.")
        return HTMLResponse(html, status_code=400)

    if len(new_password) < 10:
        html = render_account_page(user, info="", error="Password must be at least 10 characters.")
        return HTMLResponse(html, status_code=400)

    if not any(ch.isdigit() for ch in new_password):
        html = render_account_page(user, info="", error="Password must contain at least 1 number.")
        return HTMLResponse(html, status_code=400)

    # genera nuovo hash usando accounts.verify_password / bcrypt
    import bcrypt  # type: ignore

    new_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    users = _load_users_for_web()
    email_norm = _normalize_email_addr(email)
    updated = False
    for u in users:
        if _normalize_email_addr(str(u.get("email", ""))) == email_norm:
            u["password_hash"] = new_hash
            updated = True
            break
    if not updated:
        html = render_account_page(user, info="", error="User not found while saving.")
        return HTMLResponse(html, status_code=500)

    _save_users_for_web(users)

    # audit (best-effort)
    try:
        audit_event(
            event="change_password",
            user_email=_normalize_email_addr(email),
            user_id=str(user.get("id") or "") or None,
            ip=str(getattr(request.client, "host", "") or "") or None,
            ua=str(request.headers.get("user-agent") or "") or None,
        )
    except Exception:
        pass

    html = render_account_page(user, info="Password updated.", error="")
    return HTMLResponse(html)


@app.get("/workspace", response_class=HTMLResponse)
async def workspace_home(request: Request) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        return RedirectResponse(url="/?next=/workspace", status_code=302)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(info="", error="Account not active.", otp_phase=False)
        return HTMLResponse(html, status_code=403)

    html = render_workspace_page(user)
    return HTMLResponse(html)


@app.post("/workspace/create", response_class=HTMLResponse)
async def workspace_create(request: Request, name: str = Form(...)) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        return RedirectResponse(url="/?next=/workspace", status_code=302)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(info="", error="Account not active.", otp_phase=False)
        return HTMLResponse(html, status_code=403)

    name = (name or "").strip()
    if not name:
        html = render_workspace_page(user, info="", error="Workspace name is required.")
        return HTMLResponse(html, status_code=400)

    try:
        ws = create_workspace(name=name, owner_user_id=str(user.get("id") or ""))
    except Exception as exc:
        html = render_workspace_page(user, info="", error=f"Failed to create workspace: {exc}")
        return HTMLResponse(html, status_code=500)

    html = render_workspace_page(user, info=f"Workspace created: {ws.get('name')}", error="")
    return HTMLResponse(html)


@app.post("/workspace/invite", response_class=HTMLResponse)
async def workspace_invite_member(
    request: Request,
    workspace_id: str = Form(...),
    email: str = Form(...),
) -> HTMLResponse:
    session_email = get_email_from_request(request)
    if not session_email:
        return RedirectResponse(url=f"/?next=/workspace", status_code=302)

    user = get_user_by_email(session_email)
    if not user or not user.get("is_active", True):
        html = render_index_page(info="", error="Account not active.", otp_phase=False)
        return HTMLResponse(html, status_code=403)

    user_id = str(user.get("id") or "")
    workspace_id = str(workspace_id or "").strip()
    invite_email = _normalize_email_addr(email)
    if not invite_email:
        html = render_workspace_page(user, info="", error="Invite email is required.")
        return HTMLResponse(html, status_code=400)

    # authorization: must be owner
    role = None
    try:
        for ws, r in list_user_workspaces(user_id):
            if str(ws.get("id") or "") == workspace_id:
                role = r
                break
    except Exception:
        role = None
    if role != "owner":
        html = render_workspace_page(user, info="", error="Only the workspace owner can invite members.")
        return HTMLResponse(html, status_code=403)

    invited_user = get_user_by_email(invite_email)
    if not invited_user or not invited_user.get("is_active", True):
        html = render_workspace_page(
            user,
            info="",
            error="This email does not match an active account yet. (MVP: invite existing users only.)",
        )
        return HTMLResponse(html, status_code=400)

    try:
        token = create_invite(workspace_id=workspace_id, email=invite_email, invited_by_user_id=user_id, ttl_hours=48)
    except Exception as exc:
        html = render_workspace_page(user, info="", error=f"Failed to create invite: {exc}")
        return HTMLResponse(html, status_code=500)

    base = str(request.base_url).rstrip("/")
    link = f"{base}/workspace/invite/{token}"

    # send email
    try:
        subject = "amamau Insight AI - workspace invite"
        html_body = f"""
          <p>You have been invited to join a workspace on amamau Insight AI.</p>
          <p>Invite for: <strong>{html_escape.escape(invite_email)}</strong></p>
          <p><a href=\"{html_escape.escape(link)}\">Accept invite</a></p>
          <p>This link expires in 48 hours.</p>
        """
        _send_email(invite_email, subject, html_body)
    except Exception:
        # even if email fails, the token exists and can be copied from UI
        pass

    html = render_workspace_page(
        user,
        info=f"Invite created for {invite_email}. Link (for support): {link}",
        error="",
    )
    return HTMLResponse(html)


@app.get("/workspace/invite/{token}", response_class=HTMLResponse)
async def workspace_invite_view(request: Request, token: str) -> HTMLResponse:
    session_email = get_email_from_request(request)
    inv = None
    try:
        inv = get_invite(token)
    except Exception:
        inv = None
    html = render_workspace_invite_page(token, inv, session_email)
    return HTMLResponse(html)


@app.post("/workspace/invite/accept", response_class=HTMLResponse)
async def workspace_invite_accept(request: Request, token: str = Form(...)) -> HTMLResponse:
    session_email = get_email_from_request(request)
    token = (token or "").strip()
    if not session_email:
        return RedirectResponse(url=f"/?next=/workspace/invite/{token}", status_code=302)

    user = get_user_by_email(session_email)
    if not user or not user.get("is_active", True):
        html = render_index_page(info="", error="Account not active.", otp_phase=False)
        return HTMLResponse(html, status_code=403)

    inv = None
    try:
        inv = get_invite(token)
    except Exception:
        inv = None
    if not inv:
        html = render_workspace_invite_page(token, None, session_email)
        return HTMLResponse(html, status_code=400)

    invited_email = _normalize_email_addr(str(inv.get("email") or ""))
    if _normalize_email_addr(session_email) != invited_email:
        html = render_workspace_invite_page(token, inv, session_email)
        # show mismatch message on workspace page instead
        return HTMLResponse(html, status_code=403)

    try:
        ws_id = accept_invite(token=token, user_id=str(user.get("id") or ""), user_email=session_email)
    except Exception as exc:
        html = render_workspace_invite_page(token, inv, session_email)
        return HTMLResponse(html, status_code=500)

    html = render_workspace_page(user, info=f"Invite accepted. You joined workspace {ws_id}.", error="")
    return HTMLResponse(html)


@app.post("/workspace/member/remove", response_class=HTMLResponse)
async def workspace_remove_member(
    request: Request,
    workspace_id: str = Form(...),
    member_user_id: str = Form(...),
) -> HTMLResponse:
    session_email = get_email_from_request(request)
    if not session_email:
        return RedirectResponse(url="/?next=/workspace", status_code=302)

    user = get_user_by_email(session_email)
    if not user or not user.get("is_active", True):
        html = render_index_page(info="", error="Account not active.", otp_phase=False)
        return HTMLResponse(html, status_code=403)

    user_id = str(user.get("id") or "")
    workspace_id = str(workspace_id or "").strip()
    member_user_id = str(member_user_id or "").strip()

    # authorization: must be owner
    role = None
    try:
        for ws, r in list_user_workspaces(user_id):
            if str(ws.get("id") or "") == workspace_id:
                role = r
                break
    except Exception:
        role = None
    if role != "owner":
        html = render_workspace_page(user, info="", error="Only the workspace owner can remove members.")
        return HTMLResponse(html, status_code=403)

    ok = False
    try:
        ok = remove_member(workspace_id=workspace_id, user_id=member_user_id)
    except Exception:
        ok = False

    if not ok:
        html = render_workspace_page(user, info="", error="Could not remove member (maybe owner or not found).")
        return HTMLResponse(html, status_code=400)

    html = render_workspace_page(user, info="Member removed.", error="")
    return HTMLResponse(html)

def render_history_page(email: str, records: List[Dict]) -> str:
    email_val = html_escape.escape(email or "")

    if not records:
        thread_html = '<p class="small-note">No messages yet.</p>'
    else:
        bubbles = []
        for rec in records:
            role = rec.get("role", "")
            text = str(rec.get("text", "") or "")
            label = "You" if role == "user" else "AI"
            bubble_class = "bubble-user" if role == "user" else "bubble-ai"
            bubbles.append(
                f'''
                <div class="bubble {bubble_class}">
                  <div class="bubble-label">{label}</div>
                  <div>{html_escape.escape(text)}</div>
                </div>
                '''
            )
        thread_html = "\n".join(bubbles)

    body = f"""
      <section class="hero-wrap console-wrap">
        <div class="console-card">
          <div class="console-header-top">
            <div>
              <div class="console-eyebrow">History</div>
              <div class="console-title">Recent messages.</div>
              <div class="console-sub">
                Account: <strong>{email_val}</strong>
              </div>
            </div>
          </div>
          <div class="chat-shell">
            <div class="chat-thread">
              {thread_html}
            </div>
          </div>
        </div>
      </section>
    """

    body += """
    <script>
    (function(){
      const btn = document.getElementById('logoutAllBtn');
      if (!btn) return;
      btn.addEventListener('click', async () => {
        const ok = await window.modalConfirm(
          'Logout from all devices',
          'This will sign out all active sessions for your account, including this one.',
          'Logout all'
        );
        if (!ok) return;
        btn.disabled = true;
        try {
          await window.fetchJSON('/logout_all', { method: 'POST' });
          await window.modalConfirm('Done', 'All sessions were invalidated. You will be redirected to sign in again.', 'OK');
          window.location.href = '/';
        } catch (e) {
          await window.modalConfirm('Error', (e && e.message) ? e.message : 'Request failed.', 'OK');
          btn.disabled = false;
        }
      });
    })();
    </script>
    """
    return render_layout(body, "amamau Insight AI - History", current_page="home")


@app.get("/history", response_class=HTMLResponse)
async def history_page(request: Request) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page(
            info="",
            error="Please log in first.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=401)

    records = load_chat_history(email, limit=80)
    html = render_history_page(email, records)
    return HTMLResponse(html)

@app.post("/login", response_class=HTMLResponse)
async def login(
    request: Request,
    email: str = Form(""),
    password: str = Form(""),
    next: str = Form(""),
    csrf: str = Form(""),
) -> HTMLResponse:
    email = (email or "").strip().lower()
    password = (password or "")
    next_url = _safe_next_url(next)
    csrf_body = (csrf or "").strip()
    req_csrf = _csrf_from_request(request, csrf_body)
    csrf_cookie = str(request.cookies.get("csrf_token") or "")

    if not email or not password:
        print("[login] missing credentials")
        return RedirectResponse("/login?err=missing", status_code=303)
    if not req_csrf or not csrf_cookie or req_csrf != csrf_cookie:
        print("[login] csrf check failed (have_cookie=%s, have_token=%s)" % (bool(csrf_cookie), bool(req_csrf)))
        return RedirectResponse("/login?err=csrf", status_code=303)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        print("[login] invalid or inactive account")
        html = render_index_page(
            info="",
            error="Invalid email or inactive account.",
            otp_phase=False,
            email_prefill=email,
            next_url=next_url,
            csrf_token=csrf_cookie,
        )
        return HTMLResponse(html, status_code=400)

    stored_hash = user.get("password_hash") or ""
    if not verify_password(password, stored_hash):
        print("[login] bad password")
        html = render_index_page(
            info="",
            error="Invalid email or password.",
            otp_phase=False,
            email_prefill=email,
            next_url=next_url,
            csrf_token=csrf_cookie,
        )
        return HTMLResponse(html, status_code=400)

    try:
        otp_id = create_otp_for_email(email)
    except Exception as exc:
        print("[login] exception during OTP creation:", exc)
        print(traceback.format_exc())
        html = render_index_page(
            info="",
            error="Temporary error while sending code. Please retry.",
            otp_phase=False,
            email_prefill=email,
            next_url=next_url,
            csrf_token=csrf_cookie,
        )
        return HTMLResponse(html, status_code=500)

    html = render_index_page(
        info="We sent a 6 digit code to your email.",
        error="",
        otp_phase=True,
        email_prefill=email,
        otp_id=otp_id,
        next_url=next_url,
        csrf_token=csrf_cookie,
    )
    return HTMLResponse(html)


@app.post("/login/verify", response_class=HTMLResponse)
async def login_verify(
    request: Request,
    otp_id: str = Form(""),
    otp_code: str = Form(""),
    next: str = Form(""),
    csrf: str = Form(""),
) -> HTMLResponse:
    next_url = _safe_next_url(next)
    csrf_body = (csrf or "").strip()
    req_csrf = _csrf_from_request(request, csrf_body)
    csrf_cookie = str(request.cookies.get("csrf_token") or "")
    if not otp_id or not otp_code:
        print("[login_verify] missing fields")
        return RedirectResponse("/login?err=missing", status_code=303)
    if not req_csrf or not csrf_cookie or req_csrf != csrf_cookie:
        print("[login_verify] csrf check failed (have_cookie=%s, have_token=%s)" % (bool(csrf_cookie), bool(req_csrf)))
        return RedirectResponse("/login?err=csrf", status_code=303)

    try:
        email = consume_otp(otp_id.strip(), otp_code.strip())
    except Exception as exc:
        print("[login_verify] exception during OTP consume:", exc)
        print(traceback.format_exc())
        email = None

    if not email:
        print("[login_verify] invalid or expired otp")
        html = render_index_page(
            info="",
            error="Code not valid or expired. Please start again.",
            otp_phase=False,
            next_url=next_url,
            csrf_token=csrf_cookie,
        )
        return HTMLResponse(html, status_code=400)

    try:
        session_id, csrf = create_session(email)
    except Exception as exc:
        print("[login_verify] session creation failed:", exc)
        print(traceback.format_exc())
        html = render_index_page(
            info="",
            error="Temporary error. Please try signing in again.",
            otp_phase=False,
            next_url=next_url,
            csrf_token=csrf_cookie,
        )
        return HTMLResponse(html, status_code=500)

    redirect_to = next_url or "/console"
    resp = RedirectResponse(url=redirect_to, status_code=302)
    # cookie per 4 ore
    resp.set_cookie(
        "ai_session",
        session_id,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="lax",
        max_age=4 * 60 * 60,
    )

    # csrf token cookie (double-submit). Not HttpOnly so JS can read it.
    resp.set_cookie(
        "csrf_token",
        csrf,
        httponly=False,
        secure=_cookie_secure(request),
        samesite="lax",
        max_age=4 * 60 * 60,
    )

    # audit (best-effort)
    try:
        u = get_user_by_email(email)
        audit_event(
            event="login",
            user_email=email,
            user_id=str(u.get("id") or "") if u else None,
            ip=str(getattr(request.client, "host", "") or "") or None,
            ua=str(request.headers.get("user-agent") or "") or None,
        )
    except Exception:
        pass
    return resp

@app.post("/logout")
async def logout(request: Request):
    sid = request.cookies.get("ai_session")
    email = None
    if sid:
        try:
            email = db_get_session_email(session_id=sid)
        except Exception:
            email = None
        db_delete_session(session_id=sid)

    # audit (best-effort)
    try:
        u = get_user_by_email(email) if email else None
        audit_event(
            event="logout",
            user_email=email,
            user_id=str(u.get("id") or "") if u else None,
            ip=str(getattr(request.client, "host", "") or "") or None,
            ua=str(request.headers.get("user-agent") or "") or None,
        )
    except Exception:
        pass
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("ai_session")
    response.delete_cookie("csrf_token")
    return response


@app.post("/logout_all")
async def logout_all(request: Request):
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    deleted = 0
    try:
        deleted = db_delete_sessions_by_email(user_email=email)
    except Exception:
        deleted = 0

    # audit (best-effort)
    try:
        u = get_user_by_email(email)
        audit_event(
            event="logout_all",
            user_email=email,
            user_id=str(u.get("id") or "") if u else None,
            ip=str(getattr(request.client, "host", "") or "") or None,
            ua=str(request.headers.get("user-agent") or "") or None,
            meta={"sessions_deleted": int(deleted or 0)},
        )
    except Exception:
        pass

    resp = JSONResponse({"ok": True, "sessions_deleted": int(deleted or 0)})
    resp.delete_cookie("ai_session")
    resp.delete_cookie("csrf_token")
    return resp


@app.post("/api/conversations/{conversation_id}/archive")
async def api_archive_conversation(conversation_id: str, request: Request):
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    ok = set_conversation_archived(user_email=email, conversation_id=conversation_id, archived=True)
    return JSONResponse({"ok": ok})

@app.post("/api/conversations/{conversation_id}/unarchive")
async def api_unarchive_conversation(conversation_id: str, request: Request):
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    ok = set_conversation_archived(user_email=email, conversation_id=conversation_id, archived=False)
    return JSONResponse({"ok": ok})

@app.post("/api/conversations/{conversation_id}/trash")
async def api_trash_conversation(conversation_id: str, request: Request):
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    ok = soft_delete_conversation(user_email=email, conversation_id=conversation_id)
    return JSONResponse({"ok": ok})

@app.post("/api/conversations/{conversation_id}/restore")
async def api_restore_conversation(conversation_id: str, request: Request):
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    ok = restore_conversation(user_email=email, conversation_id=conversation_id)
    return JSONResponse({"ok": ok})

@app.delete("/api/conversations/{conversation_id}")
async def api_hard_delete_conversation(conversation_id: str, request: Request):
    email = get_email_from_request(request)
    if not email:
        return JSONResponse({"error": "Unauthorized"}, status_code=401)
    ok = hard_delete_conversation(user_email=email, conversation_id=conversation_id)
    return JSONResponse({"ok": ok})



@app.get("/console", response_class=HTMLResponse)
async def console_from_session(request: Request) -> HTMLResponse:
    email = get_email_from_request(request)
    if not email:
        html = render_index_page(
            info="",
            error="Please log in first.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=401)

    user = get_user_by_email(email)
    if not user or not user.get("is_active", True):
        html = render_index_page(
            info="",
            error="Account not active.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=403)

    profile_id = (user.get("profile_id") or "").strip()
    if not profile_id:
        body = "<p>No profile is linked to this user yet. Ask the owner to attach one in the console.</p>"
        return HTMLResponse(render_layout(body, "No profile linked"), status_code=403)

    profile = load_profile(profile_id)
    if not profile:
        body = "<p>Profile file not found on the server.</p>"
        return HTMLResponse(render_layout(body, "Profile not found"), status_code=404)

    html = render_console_page(profile, token=None, session_email=email)
    return HTMLResponse(html)


@app.get("/t/{token}", response_class=HTMLResponse)
async def console_by_token(request: Request, token: str) -> HTMLResponse:
    token = token.strip()
    tokens = list_tokens()
    info = tokens.get(token)
    if not info:
        html = render_index_page(
            info="",
            error="Token not found or revoked.",
            otp_phase=False,
        )
        return HTMLResponse(html, status_code=404)

    profile_id = info.get("profile_id") or ""
    profile = load_profile(profile_id)
    if not profile:
        body = "<p>Profile linked to this token does not exist.</p>"
        return HTMLResponse(render_layout(body, "Profile not found"), status_code=404)

    email = get_email_from_request(request)
    html = render_console_page(profile, token=token, session_email=email)
    return HTMLResponse(html)


@app.post("/api/chat")
async def api_chat(request: Request) -> JSONResponse:
    """
    JSON:
      { "message": "...", "token": "...", "profile_id": "..." }
    """
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    message = str(data.get("message", "")).strip()
    if not message:
        return JSONResponse({"error": "Empty message."}, status_code=400)

    token = str(data.get("token", "")).strip() or None
    profile_id = str(data.get("profile_id", "")).strip() or None

    email = get_email_from_request(request)

    # Se profile_id non arriva dal frontend, inferiamo da token o da utente
    if not profile_id:
        if token:
            profile = get_profile_for_token(token)
            if not profile:
                return JSONResponse({"error": "Token not valid or profile not found."}, status_code=400)
            profile_id = profile.get("id") or ""
        else:
            if email:
                user = get_user_by_email(email)
                if user:
                    profile_id = str(user.get("profile_id") or "").strip()

    if not profile_id:
        return JSONResponse({"error": "No profile linked to this request."}, status_code=400)

    reply = run_llm_for_profile(profile_id, message)

    # log history se abbiamo una mail (utente loggato)
    if email:
        append_chat_history(email, "user", message, profile_id)
        append_chat_history(email, "assistant", reply, profile_id)

    return JSONResponse({"reply": reply})




# -------------------------------------------------------------------
# Security: CSRF double-submit + simple rate limit
# -------------------------------------------------------------------

_RATE_BUCKETS: Dict[str, List[float]] = {}


def _client_ip(request: Request) -> str:
    try:
        ip = str(getattr(request.client, "host", "") or "")
    except Exception:
        ip = ""
    return ip or "unknown"


def _rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    """Return True if rate-limited."""
    now = datetime.utcnow().timestamp()
    win = max(1, int(window_seconds or 60))
    lim = max(1, int(limit or 30))
    bucket = _RATE_BUCKETS.get(key) or []
    cutoff = now - win
    bucket = [t for t in bucket if t >= cutoff]
    if len(bucket) >= lim:
        _RATE_BUCKETS[key] = bucket
        return True
    bucket.append(now)
    _RATE_BUCKETS[key] = bucket
    return False


def _cookie_secure(request: Request) -> bool:
    proto = str(request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
    return proto == "https"


def _csrf_from_request(request: Request, form_csrf: str = "") -> str:
    header_token = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")
    if header_token:
        return str(header_token).strip()
    if form_csrf:
        return str(form_csrf).strip()
    return ""


def _random_csrf_cookie() -> str:
    return secrets.token_urlsafe(32)


async def _extract_csrf_token(request: Request) -> str:
    # header
    h = request.headers.get("x-csrf-token") or request.headers.get("X-CSRF-Token")
    if h:
        return str(h).strip()

    ct = str(request.headers.get("content-type") or "").lower()
    if "multipart/form-data" in ct:
        try:
            form = await request.form()
            v = str(form.get("csrf") or "").strip()
            if v:
                return v
        except Exception:
            return ""

    try:
        body_bytes = await request.body()
    except Exception:
        body_bytes = b""

    # cache body so downstream handlers can still parse form/json
    try:
        request._body = body_bytes  # type: ignore[attr-defined]
    except Exception:
        pass

    if "application/x-www-form-urlencoded" in ct:
        try:
            parsed = parse_qs(body_bytes.decode("utf-8", errors="ignore"), keep_blank_values=True)
            vals = parsed.get("csrf") or []
            if vals:
                return str(vals[0]).strip()
        except Exception:
            pass

    if "application/json" in ct:
        try:
            data = json.loads(body_bytes.decode("utf-8") or "{}")
            v = str((data or {}).get("csrf") or "").strip()
            if v:
                return v
        except Exception:
            pass

    return ""


async def _csrf_check(request: Request) -> Optional[JSONResponse]:
    """Double-submit check:

    - cookie csrf_token must exist
    - request must send csrf via header or form
    - if session cookie exists, csrf must match session.csrf_token
    """

    cookie_csrf = str(request.cookies.get("csrf_token") or "").strip()
    if not cookie_csrf:
        return JSONResponse({"error": "CSRF cookie missing."}, status_code=403)

    req_csrf = (await _extract_csrf_token(request)).strip()
    if not req_csrf:
        return JSONResponse({"error": "CSRF token missing."}, status_code=403)

    if req_csrf != cookie_csrf:
        return JSONResponse({"error": "CSRF token mismatch."}, status_code=403)

    sid = str(request.cookies.get("ai_session") or "").strip()
    if sid:
        try:
            email = db_get_session_email(session_id=sid)
            if email:
                expected = db_get_session_csrf(session_id=sid) or ""
                if expected and expected != req_csrf:
                    return JSONResponse({"error": "CSRF token invalid."}, status_code=403)
        except Exception:
            pass

    return None


@app.middleware("http")
async def _security_middleware(request: Request, call_next):
    # Basic global rate limit for mutating requests
    login_paths = {"/login", "/login/verify"}
    secure_flag = _cookie_secure(request)
    new_csrf_token = ""
    if request.method in ("GET", "HEAD") and not request.cookies.get("csrf_token"):
        new_csrf_token = _random_csrf_cookie()
        try:
            request._cookies = dict(request.cookies)
            request._cookies["csrf_token"] = new_csrf_token
        except Exception:
            pass
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        ip = _client_ip(request)
        if _rate_limited(f"mut:{ip}:{request.url.path}", limit=240, window_seconds=60):
            return JSONResponse({"error": "Too many requests."}, status_code=429)
        err = await _csrf_check(request)
        if err is not None:
            if request.url.path in login_paths:
                return RedirectResponse(url="/login?err=csrf", status_code=303)
            return err

    response = await call_next(request)

    # Ensure csrf cookie exists for UX (login form CSRF, etc.)
    if request.method in ("GET", "HEAD"):
        existing_csrf_cookie = any(
            header.lower() == b"set-cookie" and b"csrf_token=" in value.lower()
            for header, value in response.raw_headers
        )
        if new_csrf_token and not existing_csrf_cookie:
            response.set_cookie(
                "csrf_token",
                new_csrf_token,
                httponly=False,
                secure=secure_flag,
                samesite="lax",
                max_age=6 * 60 * 60,
            )
        elif not request.cookies.get("csrf_token") and not existing_csrf_cookie:
            response.set_cookie(
                "csrf_token",
                _random_csrf_cookie(),
                httponly=False,
                secure=secure_flag,
                samesite="lax",
                max_age=6 * 60 * 60,
            )

    # If logged in, always sync csrf cookie with session value
    sid = request.cookies.get("ai_session")
    if sid:
        try:
            email = db_get_session_email(session_id=str(sid))
            if email:
                csrf = db_get_session_csrf(session_id=str(sid))
                if csrf:
                    response.set_cookie(
                        "csrf_token",
                        csrf,
                        httponly=False,
                        secure=secure_flag,
                        samesite="lax",
                        max_age=4 * 60 * 60,
                    )
        except Exception:
            pass

    return response


# -------------------------------------------------------------------
# 2FA helpers (TOTP + backup codes stored in users.json)
# -------------------------------------------------------------------


def _update_user(email: str, patch: Dict) -> bool:
    email_n = _normalize_email_addr(email)
    users = _load_users_for_web()
    ok = False
    for u in users:
        if _normalize_email_addr(str(u.get("email", ""))) == email_n:
            u.update(patch or {})
            ok = True
            break
    if ok:
        _save_users_for_web(users)
    return ok


def _get_user_by_session(request: Request) -> Tuple[Optional[str], Optional[Dict]]:
    email = get_email_from_request(request)
    if not email:
        return None, None
    user = get_user_by_email(email)
    return email, user


def _require_2fa_or_error(request: Request, user: Dict, code: str) -> Optional[str]:
    """Return None if OK, else error string."""
    if not user or not user.get("two_factor_enabled"):
        return "2FA not enabled for this account."

    secret = str(user.get("totp_secret") or "").strip()
    if not secret:
        return "2FA secret missing."

    backups = user.get("backup_code_hashes") or []
    ok, updated_backups = verify_2fa_code(secret, backups, code)
    if not ok:
        return "Invalid 2FA code."

    # Persist consumed backup code if needed
    if updated_backups is not None and updated_backups != backups:
        _update_user(user.get("email"), {"backup_code_hashes": updated_backups})

    return None


# -------------------------------------------------------------------
# Workspace env (piano B multi-chat) + projects
# -------------------------------------------------------------------


def _require_workspace(request: Request, workspace_id: str) -> Tuple[Optional[Dict], Optional[str], Optional[Dict], Optional[str], Optional[JSONResponse]]:
    email, user = _get_user_by_session(request)
    if not email or not user:
        return None, None, None, None, JSONResponse({"error": "Unauthorized"}, status_code=401)

    ws = get_workspace(workspace_id)
    if not ws or str(ws.get("status") or "active") == "deleted":
        return None, None, None, None, JSONResponse({"error": "Workspace not found"}, status_code=404)

    uid = str(user.get("id") or "").strip()
    role = get_user_role(workspace_id, uid)
    if not role:
        return None, None, None, None, JSONResponse({"error": "Forbidden"}, status_code=403)

    # legacy fix: if workspace has no profile_id, inherit owner's profile_id and persist
    if ws and not str(ws.get("profile_id") or "").strip():
        owner_id = str(ws.get("owner_user_id") or "").strip()
        pid = ""

        # prefer owner's profile_id from users.json
        if owner_id:
            for uu in _load_users_for_web():
                if str(uu.get("id") or "").strip() == owner_id:
                    pid = str(uu.get("profile_id") or "").strip()
                    break

        # fallback if current user is owner
        if not pid and role == "owner":
            pid = str(user.get("profile_id") or "").strip()

        if pid:
            try:
                set_workspace_profile_id(
                    workspace_id=str(ws.get("id") or workspace_id),
                    profile_id=pid,
                    actor_user_id=owner_id or uid,
                )
                ws = get_workspace(str(workspace_id)) or ws
            except Exception:
                pass

    return ws, email, user, role, None


def render_account_security_page(session_email: str, user: Dict, info: str = "", error: str = "") -> str:
    enabled = bool(user.get("two_factor_enabled"))
    pending_secret = str(user.get("totp_secret_pending") or "").strip()

    status_chip = "<span class='chip ok'>Enabled</span>" if enabled else "<span class='chip warn'>Disabled</span>"

    setup_html = ""
    if not enabled:
        if not pending_secret:
            setup_html = """
            <div class="am-card" style="margin-top:14px;">
              <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
                <div>
                  <div class="h2">Two-factor authentication (TOTP)</div>
                  <div class="muted">Add a second factor with an authenticator app (TOTP) + backup codes.</div>
                </div>
                <form method="post" action="/account/security/2fa/setup">
                  <button class="am-btn primary" type="submit">Setup 2FA</button>
                </form>
              </div>
            </div>
            """
        else:
            uri = otpauth_uri("amamau", session_email, pending_secret)
            backup_codes = user.get("backup_codes_pending_plain") or []
            codes_html = "".join([f"<div class='mono'>{html_escape.escape(c)}</div>" for c in backup_codes])
            setup_html = f"""
            <div class="am-card" style="margin-top:14px;">
              <div class="h2">Enable 2FA</div>
              <div class="muted">Scan/add this secret in your authenticator app, then confirm with a TOTP code.</div>
              <div style="display:grid;grid-template-columns:1fr;gap:10px;margin-top:10px;">
                <div>
                  <div class="label">Secret</div>
                  <div class="mono">{html_escape.escape(pending_secret)}</div>
                </div>
                <div>
                  <div class="label">otpauth URI (manual)</div>
                  <div class="mono" style="word-break:break-all;">{html_escape.escape(uri)}</div>
                </div>
                <div>
                  <div class="label">Backup codes (save now)</div>
                  <div class="mono" style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:6px;">{codes_html}</div>
                </div>
              </div>

              <form method="post" action="/account/security/2fa/enable" style="margin-top:12px;display:flex;gap:10px;align-items:center;">
                <input class="am-input" name="code" placeholder="123456" autocomplete="one-time-code" required />
                <button class="am-btn primary" type="submit">Enable</button>
              </form>

              <form method="post" action="/account/security/2fa/cancel" style="margin-top:10px;">
                <button class="am-btn" type="submit">Cancel setup</button>
              </form>
            </div>
            """
    else:
        setup_html = """
        <div class="am-card" style="margin-top:14px;">
          <div class="h2">Two-factor authentication (TOTP)</div>
          <div class="muted">2FA is enabled. To disable, you must provide a valid TOTP or backup code.</div>
          <form method="post" action="/account/security/2fa/disable" style="margin-top:12px;display:flex;gap:10px;align-items:center;">
            <input class="am-input" name="code" placeholder="TOTP or backup code" required />
            <button class="am-btn" type="submit">Disable 2FA</button>
          </form>
        </div>
        """

    msg_html = ""
    if info:
        msg_html = f"<div class='am-msg ok'>{html_escape.escape(info)}</div>"
    if error:
        msg_html = f"<div class='am-msg err'>{html_escape.escape(error)}</div>"

    body = f"""
    <div class="page">
      <div class="am-card">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div>
            <div class="h1">Security</div>
            <div class="muted">Account protection settings.</div>
          </div>
          <div>
            {status_chip}
          </div>
        </div>
        {msg_html}
        <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;">
          <a class="am-btn" href="/account">Back to Account</a>
        </div>
      </div>
      {setup_html}
    </div>
    """

    return render_layout(body, title="Security", current_page="account", session_email=session_email)


@app.get("/account/security", response_class=HTMLResponse)
async def account_security_page(request: Request) -> HTMLResponse:
    email, user = _get_user_by_session(request)
    if not email or not user:
        html = render_index_page(info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    return HTMLResponse(render_account_security_page(email, user))


@app.post("/account/security/2fa/setup", response_class=HTMLResponse)
async def account_security_2fa_setup(request: Request) -> HTMLResponse:
    email, user = _get_user_by_session(request)
    if not email or not user:
        html = render_index_page(info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    ip = _client_ip(request)
    if _rate_limited(f"2fa_setup:{ip}:{email}", limit=6, window_seconds=60):
        return HTMLResponse(render_account_security_page(email, user, error="Too many requests."), status_code=429)

    if user.get("two_factor_enabled"):
        return HTMLResponse(render_account_security_page(email, user, info="2FA already enabled."))

    secret = generate_base32_secret()
    backup_codes = generate_backup_codes(n=10)
    hashes = backup_codes_to_hashes(backup_codes)

    _update_user(email, {
        "totp_secret_pending": secret,
        "backup_code_hashes_pending": hashes,
        # store plaintext only during setup flow to show once; cleared on enable/cancel
        "backup_codes_pending_plain": backup_codes,
    })

    # reload user
    user = get_user_by_email(email) or user

    try:
        audit_event(
            event="two_factor_setup",
            user_email=email,
            user_id=str(user.get("id") or "") if user else None,
            ip=ip,
            ua=str(request.headers.get("user-agent") or "") or None,
        )
    except Exception:
        pass

    return HTMLResponse(render_account_security_page(email, user, info="Setup started. Save your backup codes."))


@app.post("/account/security/2fa/enable", response_class=HTMLResponse)
async def account_security_2fa_enable(request: Request, code: str = Form(...)) -> HTMLResponse:
    email, user = _get_user_by_session(request)
    if not email or not user:
        html = render_index_page(info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    pending_secret = str(user.get("totp_secret_pending") or "").strip()
    pending_hashes = user.get("backup_code_hashes_pending") or []

    if not pending_secret:
        return HTMLResponse(render_account_security_page(email, user, error="No pending setup."), status_code=400)

    code = str(code or "").strip()
    if not code.isdigit():
        return HTMLResponse(render_account_security_page(email, user, error="Enter a valid TOTP code."), status_code=400)

    ok, _updated = verify_2fa_code(pending_secret, [], code)
    if not ok:
        return HTMLResponse(render_account_security_page(email, user, error="Invalid TOTP code."), status_code=400)

    _update_user(email, {
        "two_factor_enabled": True,
        "totp_secret": pending_secret,
        "backup_code_hashes": pending_hashes,
        "totp_secret_pending": "",
        "backup_code_hashes_pending": [],
        "backup_codes_pending_plain": [],
    })

    user = get_user_by_email(email) or user

    try:
        audit_event(
            event="two_factor_enable",
            user_email=email,
            user_id=str(user.get("id") or "") if user else None,
            ip=_client_ip(request),
            ua=str(request.headers.get("user-agent") or "") or None,
        )
    except Exception:
        pass

    return HTMLResponse(render_account_security_page(email, user, info="2FA enabled."))


@app.post("/account/security/2fa/cancel", response_class=HTMLResponse)
async def account_security_2fa_cancel(request: Request) -> HTMLResponse:
    email, user = _get_user_by_session(request)
    if not email or not user:
        html = render_index_page(info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    _update_user(email, {
        "totp_secret_pending": "",
        "backup_code_hashes_pending": [],
        "backup_codes_pending_plain": [],
    })

    user = get_user_by_email(email) or user
    return HTMLResponse(render_account_security_page(email, user, info="Setup canceled."))


@app.post("/account/security/2fa/disable", response_class=HTMLResponse)
async def account_security_2fa_disable(request: Request, code: str = Form(...)) -> HTMLResponse:
    email, user = _get_user_by_session(request)
    if not email or not user:
        html = render_index_page(info="", error="Please log in first.", otp_phase=False)
        return HTMLResponse(html, status_code=401)

    ip = _client_ip(request)
    if _rate_limited(f"2fa_disable:{ip}:{email}", limit=8, window_seconds=60):
        return HTMLResponse(render_account_security_page(email, user, error="Too many requests."), status_code=429)

    err = _require_2fa_or_error(request, user, str(code or "").strip())
    if err:
        return HTMLResponse(render_account_security_page(email, user, error=err), status_code=400)

    _update_user(email, {
        "two_factor_enabled": False,
        "totp_secret": "",
        "backup_code_hashes": [],
        "totp_secret_pending": "",
        "backup_code_hashes_pending": [],
        "backup_codes_pending_plain": [],
    })

    user = get_user_by_email(email) or user

    try:
        audit_event(
            event="two_factor_disable",
            user_email=email,
            user_id=str(user.get("id") or "") if user else None,
            ip=ip,
            ua=str(request.headers.get("user-agent") or "") or None,
        )
    except Exception:
        pass

    return HTMLResponse(render_account_security_page(email, user, info="2FA disabled."))


# ------------------------------
# Workspace UI pages
# ------------------------------


def _ws_top_nav(workspace_id: str, active: str = "chat") -> str:
    a1 = 'aria-current="page"' if active == 'chat' else ''
    a2 = 'aria-current="page"' if active == 'projects' else ''
    a3 = 'aria-current="page"' if active == 'settings' else ''
    return (
        f'<div style="display:flex;gap:10px;flex-wrap:wrap;">'
        f'<a class="am-btn" href="/w/{workspace_id}" {a1}>Chat</a>'
        f'<a class="am-btn" href="/w/{workspace_id}/projects" {a2}>Projects</a>'
        f'<a class="am-btn" href="/w/{workspace_id}/settings" {a3}>Settings</a>'
        f'<a class="am-btn" href="/workspace">Manage</a>'
        f'</div>'
    )



def render_workspace_chat_page(session_email: str, ws: Dict, role: str) -> str:
    wsid = str(ws.get('id') or '')
    wsname = str(ws.get('name') or 'Workspace')
    status = str(ws.get('status') or 'active')
    profile_id = str(ws.get('profile_id') or '').strip()

    ro_note = ""
    if status == 'archived':
        ro_note = "<div class='am-msg warn'>Workspace archived: read-only.</div>"

    owner_actions = ""
    if role == 'owner':
        owner_actions = """
        <div class=\"am-card\" style=\"margin-top:14px;\">
          <div class=\"h2\">Danger zone</div>
          <div class=\"muted\">Archive or delete this workspace (2FA required).</div>
          <div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-top:12px;\">
            <button class=\"am-btn\" id=\"wsArchiveBtn\">Archive</button>
            <button class=\"am-btn\" id=\"wsDeleteBtn\">Delete workspace</button>
          </div>
        </div>
        """

    # IMPORTANT: keep JS out of f-strings (avoid { } collisions). We inject values via placeholder replacement.
    body = f"""
    <div class=\"page\">
      <div class=\"am-card\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;\">
          <div>
            <div class=\"h1\">{html_escape.escape(wsname)}</div>
            <div class=\"muted\">Workspace chat · profile: <span class=\"mono\">{html_escape.escape(profile_id or '-')}</span></div>
          </div>
          {_ws_top_nav(wsid, 'chat')}
        </div>
        {ro_note}
      </div>

      <div class=\"console-grid\" style=\"margin-top:14px;\">
        <div class=\"am-card\" style=\"padding:12px;\">
          <div style=\"display:flex;gap:10px;align-items:center;justify-content:space-between;\">
            <div class=\"h2\">Conversations</div>
            <button class=\"am-btn primary\" id=\"wsNewChat\">New</button>
          </div>
          <div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;\">
            <button class=\"am-btn\" id=\"wsTabActive\">Active</button>
            <button class=\"am-btn\" id=\"wsTabArchived\">Archived</button>
            <button class=\"am-btn\" id=\"wsTabTrash\">Trash</button>
          </div>
          <div style=\"margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;align-items:center;\">
            <select class=\"am-input\" id=\"wsProjFilter\" style=\"min-width:220px;\"></select>
          </div>
          <div id=\"wsConvList\" style=\"margin-top:10px;display:flex;flex-direction:column;gap:8px;\"></div>
        </div>

        <div class=\"am-card\" style=\"padding:12px;display:flex;flex-direction:column;min-height:520px;\">
          <div style=\"display:flex;align-items:center;justify-content:space-between;gap:10px;\">
            <div>
              <div class=\"h2\" id=\"wsActiveTitle\">Select a conversation</div>
              <div class=\"muted\" id=\"wsActiveMeta\"></div>
            </div>
            <div style=\"display:flex;gap:8px;flex-wrap:wrap;align-items:center;\">
              <select class=\"am-input\" id=\"wsActiveProject\" style=\"min-width:220px;\"></select>
              <button class=\"am-btn\" id=\"wsRename\">Rename</button>
              <button class=\"am-btn\" id=\"wsShare\">Share</button>
              <button class=\"am-btn\" id=\"wsArchive\">Archive</button>
              <button class=\"am-btn\" id=\"wsTrash\">Trash</button>
              <button class=\"am-btn\" id=\"wsRestore\">Restore</button>
            </div>
          </div>

          <div id=\"wsThread\" class=\"thread\" style=\"margin-top:12px;flex:1;overflow:auto;\"></div>

          <div style=\"display:flex;gap:10px;align-items:center;margin-top:12px;\">
            <input class=\"am-input\" id=\"wsMsg\" placeholder=\"Type a message...\" style=\"flex:1;\" />
            <button class=\"am-btn primary\" id=\"wsSend\">Send</button>
          </div>
        </div>
      </div>

      {owner_actions}
    </div>
    """

    wsid_js = json.dumps(wsid)
    status_js = json.dumps(status)

    script = """\
<script>
(function(){
  const wsId = __WSID__;
  const wsStatus = __STATUS__;
  const meEmail = __ME__;
  let projFilter = (() => { try { return (new URL(window.location.href)).searchParams.get('p') || ''; } catch (e) { return ''; } })().trim();

  const listEl = document.getElementById('wsConvList');
  const threadEl = document.getElementById('wsThread');
  const msgEl = document.getElementById('wsMsg');
  const sendBtn = document.getElementById('wsSend');

  const projFilterEl = document.getElementById('wsProjFilter');
  const activeProjEl = document.getElementById('wsActiveProject');

  let projectsActive = [];
  let projectNames = {}; // id -> name (active+archived)

  const newBtn = document.getElementById('wsNewChat');
  const renameBtn = document.getElementById('wsRename');
  const shareBtn = document.getElementById('wsShare');
  const archBtn = document.getElementById('wsArchive');
  const trashBtn = document.getElementById('wsTrash');
  const restoreBtn = document.getElementById('wsRestore');
  const titleEl = document.getElementById('wsActiveTitle');
  const metaEl = document.getElementById('wsActiveMeta');
  const tabActive = document.getElementById('wsTabActive');
  const tabArchived = document.getElementById('wsTabArchived');
  const tabTrash = document.getElementById('wsTabTrash');

  let activeId = '';
  let activeStatus = 'active';


  let listStatus = 'active';

  const safe = (fn) => async (...args) => {
    try { return await fn(...args); }
    catch (e) { await window.modalConfirm('Error', (e && e.message) ? e.message : String(e), 'OK'); }
  };
  const openFromUrl = (() => { try { return (new URL(window.location.href)).searchParams.get('c') || ''; } catch (e) { return ''; } })();

  function setTab(btn, on){
    if (!btn) return;
    if (on) btn.classList.add('primary');
    else btn.classList.remove('primary');
  }
  function syncTabs(){
    setTab(tabActive, listStatus === 'active');
    setTab(tabArchived, listStatus === 'archived');
    setTab(tabTrash, listStatus === 'deleted');
  }
  function setListStatus(st){
    listStatus = st || 'active';
    syncTabs();
    // Reload data (and surface errors to the user)
    safe(async () => {
      await loadProjects();
      await loadConversations();
    })();
  }


  function disabledForRO(){ return wsStatus === 'archived' || wsStatus === 'deleted'; }

  function setUrlParam(key, val){
    try {
      const u = new URL(window.location.href);
      if (val === null || val === undefined || String(val).trim() === '') u.searchParams.delete(key);
      else u.searchParams.set(key, String(val));
      window.history.replaceState({}, '', u.toString());
    } catch (e) {}
  }

  function populateProjectFilter(){
    if (!projFilterEl) return;
    projFilterEl.innerHTML = '';

    const addOpt = (value, label) => {
      const o = document.createElement('option');
      o.value = value;
      o.textContent = label;
      projFilterEl.appendChild(o);
    };

    addOpt('', 'All projects');
    addOpt('none', 'No project');
    (projectsActive || []).forEach(p => addOpt(p.id, p.name || p.id));

    // normalize selection
    const want = projFilter || '';
    const valid = want === '' || want === 'none' || (projectsActive || []).some(p => p.id === want);
    projFilterEl.value = valid ? want : '';
    projFilter = (projFilterEl.value || '').trim();
  }

  function populateActiveProject(selectedId){
    if (!activeProjEl) return;
    activeProjEl.innerHTML = '';

    const addOpt = (value, label) => {
      const o = document.createElement('option');
      o.value = value;
      o.textContent = label;
      activeProjEl.appendChild(o);
    };

    addOpt('none', 'No project');
    (projectsActive || []).forEach(p => addOpt(p.id, p.name || p.id));

    const want = selectedId ? String(selectedId) : 'none';
    const valid = want === 'none' || (projectsActive || []).some(p => p.id === want);
    activeProjEl.value = valid ? want : 'none';
  }

  async function loadProjects(){
    // We load active projects for selection, and active+archived for name resolution.
    const a = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects?status=active`);
    const b = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects?status=archived`);

    projectsActive = (a.projects || []).filter(p => p && p.id);
    projectNames = {};
    (a.projects || []).concat(b.projects || []).forEach(p => {
      if (p && p.id) projectNames[p.id] = (p.name || p.id);
    });

    populateProjectFilter();
  }


  function renderBubble(role, text, authorEmail, authorName){
    const wrap = document.createElement('div');
    wrap.className = 'bubble ' + (role === 'user' ? 'bubble-user' : 'bubble-ai');
    const label = document.createElement('div');
    label.className = 'bubble-label';

    if (role === 'user') {
      const ae = (authorEmail || '').toLowerCase();
      if (ae && meEmail && ae === String(meEmail).toLowerCase()) label.textContent = 'You';
      else label.textContent = (authorName || authorEmail || 'User');
    } else {
      label.textContent = 'AI';
    }

    const body = document.createElement('div');
    body.textContent = text || '';
    wrap.appendChild(label);
    wrap.appendChild(body);
    threadEl.appendChild(wrap);
    threadEl.scrollTop = threadEl.scrollHeight;
  }

  function clearThread(){ threadEl.innerHTML = ''; }

  function updateActionStates(){
    const ro = disabledForRO();
    const has = !!activeId;
    renameBtn.disabled = ro || !has;
    if (shareBtn) shareBtn.disabled = !has;
    trashBtn.disabled = ro || !has || activeStatus === 'deleted';
    archBtn.disabled = ro || !has || activeStatus === 'deleted';
    restoreBtn.disabled = ro || !has || activeStatus !== 'deleted';
    if (activeProjEl) activeProjEl.disabled = ro || !has;
    archBtn.textContent = (activeStatus === 'archived') ? 'Unarchive' : 'Archive';
  }

  async function loadConversations(){
    let url = `/api/workspaces/${encodeURIComponent(wsId)}/conversations?status=${encodeURIComponent(listStatus)}`;
    if (projFilter) url += `&project_id=${encodeURIComponent(projFilter)}`;
    const data = await window.fetchJSON(url);
    listEl.innerHTML = '';
    (data.conversations || []).forEach(c => {
      const item = document.createElement('div');
      item.className = 'conv-item' + (c.id === activeId ? ' active' : '');
      item.dataset.id = c.id;
      item.style.cursor = 'pointer';
      item.style.display = 'flex';
      item.style.justifyContent = 'space-between';
      item.style.alignItems = 'center';
      item.style.gap = '10px';

      const t = document.createElement('div');
      t.textContent = c.title || 'New chat';
      t.style.flex = '1';
      const s = document.createElement('div');
      s.className = 'muted';
            const bits = [];
      if (c.project_id) bits.push(projectNames[c.project_id] || 'project');
      if (c.archived) bits.push('archived');
      else if (c.deleted) bits.push('deleted');
      s.textContent = bits.join(' · ');

      item.appendChild(t);
      item.appendChild(s);
      item.onclick = () => openConversation(c.id);
      listEl.appendChild(item);
    });
    if (!activeId && openFromUrl) {
      openConversation(openFromUrl).catch(() => {});
    }
  }

  async function openConversation(cid){
    activeId = cid;
    const data = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(cid)}`);
    const conv = data.conversation || {};
    activeStatus = conv.deleted ? 'deleted' : (conv.archived ? 'archived' : 'active');
    titleEl.textContent = conv.title || 'Chat';
        const pname = conv.project_id ? (projectNames[conv.project_id] || conv.project_id) : '';
    metaEl.textContent = (conv.created_by_email || '') + (pname ? ` · ${pname}` : '');
    populateActiveProject(conv.project_id || null);

    clearThread();
    (data.messages || []).forEach(m => renderBubble(m.role, m.content, m.author_email, m.author_name));

    try {
      const u = new URL(window.location.href);
      u.searchParams.set('c', cid);
      window.history.replaceState({}, '', u.toString());
    } catch (e) {}

    updateActionStates();
  }

  async function newConversation(){
    if (disabledForRO()) { await window.modalConfirm('Read-only', 'Workspace archived. No new chats.', 'OK'); return; }
    const data = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: 'New chat', project_id: (projFilter && projFilter !== 'none') ? projFilter : '' })
    });
    await loadConversations();
    if (data.conversation && data.conversation.id) await openConversation(data.conversation.id);
  }

  async function sendMessage(){
    if (!activeId) return;
    if (disabledForRO()) { await window.modalConfirm('Read-only', 'Workspace archived. Messaging disabled.', 'OK'); return; }
    const text = (msgEl.value || '').trim();
    if (!text) return;
    msgEl.value = '';
    renderBubble('user', text, meEmail, '');
    const data = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}/message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text })
    });
    renderBubble('assistant', data.reply || '');
    await loadConversations();
  }

  async function renameConversation(){
    if (!activeId) return;
    const current = titleEl.textContent || 'New chat';
    const next = await window.modalPrompt('Rename chat', current, 'Enter a new title', 'Save');

    if (next === null) return;
    const clean = String(next || '').trim();
    if (!clean) return;
    await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: clean })
    });
    await loadConversations();
    await openConversation(activeId);
  }


  async function shareChat(){
    if (!activeId) return;
    const link = (() => {
      try {
        const u = new URL(window.location.href);
        u.searchParams.set('c', activeId);
        return u.toString();
      } catch (e) {
        return window.location.origin + `/w/${encodeURIComponent(wsId)}?c=${encodeURIComponent(activeId)}`;
      }
    })();
    try {
      await navigator.clipboard.writeText(link);
      await window.modalConfirm('Link copied', 'Share this link with workspace members.', 'OK');
    } catch (e) {
      await window.modalPrompt('Share link', link, 'Copy this link', 'Close');

    }
  }

  async function archiveConversation(){
    if (!activeId) return;
    if (disabledForRO()) { await window.modalConfirm('Read-only', 'Workspace archived. No changes.', 'OK'); return; }

    if (activeStatus === 'archived') {
      await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}/unarchive`, { method: 'POST' });
      activeStatus = 'active';
      listStatus = 'active';
    } else {
      await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}/archive`, { method: 'POST' });
      activeStatus = 'archived';
      listStatus = 'archived';
    }
    syncTabs();
    await loadConversations();
    await openConversation(activeId);
  }

  async function trashConversation(){
    if (!activeId) return;
    if (disabledForRO()) { await window.modalConfirm('Read-only', 'Workspace archived. No changes.', 'OK'); return; }
    await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}/trash`, { method: 'POST' });
    activeStatus = 'deleted';
    listStatus = 'deleted';
    syncTabs();
    await loadConversations();
    await openConversation(activeId);
  }

  async function restoreConversation(){
    if (!activeId) return;
    if (disabledForRO()) { await window.modalConfirm('Read-only', 'Workspace archived. No changes.', 'OK'); return; }
    if (activeStatus !== 'deleted') return;
    await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}/restore`, { method: 'POST' });
    activeStatus = 'active';
    listStatus = 'active';
    syncTabs();
    await loadConversations();
    await openConversation(activeId);
  }

  async function wsDangerAction(action){
    // Confirm BEFORE asking 2FA
    if (action === 'archive') {
      const ok = await window.modalConfirm('Archive workspace', 'Workspace becomes read-only. Continue?', 'Archive');
      if (!ok) return;
    }
    if (action === 'restore') {
      const ok = await window.modalConfirm('Unarchive workspace', 'Workspace will be writable again. Continue?', 'Unarchive');
      if (!ok) return;
    }

    const code = await window.modalPrompt('2FA required', '', 'Enter TOTP or backup code', 'Confirm');
    if (code === null) return;

    await window.fetchJSON(`/workspace/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workspace_id: wsId, code: String(code||'').trim() })
    });

    if (action === 'delete') window.location.href = '/workspace';
    else window.location.reload();
  }

  newBtn.onclick = safe(newConversation);
  sendBtn.onclick = safe(sendMessage);
  msgEl.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') safe(sendMessage)(); });
  renameBtn.onclick = safe(renameConversation);
  if (shareBtn) shareBtn.onclick = safe(shareChat);
  archBtn.onclick = safe(archiveConversation);
  trashBtn.onclick = safe(trashConversation);
  restoreBtn.onclick = safe(restoreConversation);

  if (projFilterEl) {
    // init selection from URL param
    populateProjectFilter();
    projFilterEl.onchange = () => {
      projFilter = (projFilterEl.value || '').trim();
      setUrlParam('p', projFilter);
      // keep current status tab but reload list
      safe(async () => {
        await loadProjects();
        await loadConversations();
      })();
    };
  }

  if (activeProjEl) {
    activeProjEl.onchange = safe(async () => {
      if (!activeId) return;
      if (disabledForRO()) return;
      const v = (activeProjEl.value || '').trim();
      await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/conversations/${encodeURIComponent(activeId)}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ project_id: v })
      });
      await loadConversations();
      await openConversation(activeId);
    });
  }


  if (tabActive) tabActive.onclick = () => setListStatus('active');
  if (tabArchived) tabArchived.onclick = () => setListStatus('archived');
  if (tabTrash) tabTrash.onclick = () => setListStatus('deleted');
  syncTabs();
  updateActionStates();

  const wsArchiveBtn = document.getElementById('wsArchiveBtn');
  const wsDeleteBtn = document.getElementById('wsDeleteBtn');
  if (wsArchiveBtn) {
    wsArchiveBtn.textContent = (wsStatus === 'archived') ? 'Unarchive workspace' : 'Archive workspace';
    wsArchiveBtn.onclick = () => wsDangerAction(wsStatus === 'archived' ? 'restore' : 'archive');
  }
  if (wsDeleteBtn) wsDeleteBtn.onclick = async () => {
    const ok = await window.modalConfirm('Delete workspace', 'This will mark the workspace as deleted. Continue?', 'Delete');
    if (!ok) return;
    await wsDangerAction('delete');
  };

  // Initial load (surface errors instead of silently failing)
  safe(async () => {
    await loadProjects();
    await loadConversations();
  })();
})();
</script>
"""

    me_js = json.dumps(session_email)

    script = script.replace('__WSID__', wsid_js).replace('__STATUS__', status_js).replace('__ME__', me_js)

    return render_layout(body + script, title=f"Workspace · {wsname}", current_page="workspace", session_email=session_email)



def render_workspace_projects_page(session_email: str, ws: Dict, role: str) -> str:
    wsid = str(ws.get('id') or '')
    wsname = str(ws.get('name') or 'Workspace')
    status = str(ws.get('status') or 'active')

    ro_note = ""
    if status == 'archived':
        ro_note = "<div class='am-msg warn'>Workspace archived: read-only.</div>"

    body = f"""
    <div class=\"page\">
      <div class=\"am-card\">
        <div style=\"display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;\">
          <div>
            <div class=\"h1\">{html_escape.escape(wsname)} · Projects</div>
            <div class=\"muted\">Manage workspace projects.</div>
          </div>
          {_ws_top_nav(wsid, 'projects')}
        </div>
        {ro_note}
      </div>

      <div class=\"am-card\" style=\"margin-top:14px;\">
        <div style=\"display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap;\">
          <div class=\"h2\">Projects</div>
          <div style=\"display:flex;gap:10px;flex-wrap:wrap;\">
            <input class=\"am-input\" id=\"projName\" placeholder=\"Project name\" style=\"min-width:240px;\" />
            <button class=\"am-btn primary\" id=\"projCreate\">Create</button>
          </div>
        </div>
        <div style=\"display:flex;gap:8px;flex-wrap:wrap;margin-top:10px;\">
          <button class=\"am-btn\" id=\"projTabActive\">Active</button>
          <button class=\"am-btn\" id=\"projTabArchived\">Archived</button>
          <button class=\"am-btn\" id=\"projTabTrash\">Trash</button>
        </div>
        <div id=\"projList\" style=\"margin-top:12px;display:flex;flex-direction:column;gap:10px;\"></div>
      </div>
    </div>
    """

    wsid_js = json.dumps(wsid)
    status_js = json.dumps(status)

    script = """\
<script>
(function(){
  const wsId = __WSID__;
  const wsStatus = __STATUS__;
  const meEmail = __ME__;
  let projFilter = (() => { try { return (new URL(window.location.href)).searchParams.get('p') || ''; } catch (e) { return ''; } })().trim();
  const listEl = document.getElementById('projList');
  const nameEl = document.getElementById('projName');
  const createBtn = document.getElementById('projCreate');

  const esc = (s) => String(s||'').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

  const tabActive = document.getElementById('projTabActive');
  const tabArchived = document.getElementById('projTabArchived');
  const tabTrash = document.getElementById('projTabTrash');

  let listStatus = 'active';

  const safe = (fn) => async (...args) => {
    try { return await fn(...args); }
    catch (e) { await window.modalConfirm('Error', (e && e.message) ? e.message : String(e), 'OK'); }
  };

  function setTab(btn, on){ if (!btn) return; if (on) btn.classList.add('primary'); else btn.classList.remove('primary'); }
  function syncTabs(){
    setTab(tabActive, listStatus === 'active');
    setTab(tabArchived, listStatus === 'archived');
    setTab(tabTrash, listStatus === 'deleted');
  }
  function setListStatus(st){
    listStatus = st;
    syncTabs();
    safe(load)();
  }

  syncTabs();
  if (tabActive) tabActive.onclick = () => setListStatus('active');
  if (tabArchived) tabArchived.onclick = () => setListStatus('archived');
  if (tabTrash) tabTrash.onclick = () => setListStatus('deleted');

  function disabledForRO(){ return wsStatus === 'archived' || wsStatus === 'deleted'; }

  function setUrlParam(key, val){
    try {
      const u = new URL(window.location.href);
      if (val === null || val === undefined || String(val).trim() === '') u.searchParams.delete(key);
      else u.searchParams.set(key, String(val));
      window.history.replaceState({}, '', u.toString());
    } catch (e) {}
  }

  function populateProjectFilter(){
    if (!projFilterEl) return;
    projFilterEl.innerHTML = '';

    const addOpt = (value, label) => {
      const o = document.createElement('option');
      o.value = value;
      o.textContent = label;
      projFilterEl.appendChild(o);
    };

    addOpt('', 'All projects');
    addOpt('none', 'No project');
    (projectsActive || []).forEach(p => addOpt(p.id, p.name || p.id));

    // normalize selection
    const want = projFilter || '';
    const valid = want === '' || want === 'none' || (projectsActive || []).some(p => p.id === want);
    projFilterEl.value = valid ? want : '';
  }

  function populateActiveProject(selectedId){
    if (!activeProjEl) return;
    activeProjEl.innerHTML = '';

    const addOpt = (value, label) => {
      const o = document.createElement('option');
      o.value = value;
      o.textContent = label;
      activeProjEl.appendChild(o);
    };

    addOpt('none', 'No project');
    (projectsActive || []).forEach(p => addOpt(p.id, p.name || p.id));

    const want = selectedId ? String(selectedId) : 'none';
    const valid = want === 'none' || (projectsActive || []).some(p => p.id === want);
    activeProjEl.value = valid ? want : 'none';
  }

  async function loadProjects(){
    // We load active projects for selection, and active+archived for name resolution.
    const a = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects?status=active`);
    const b = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects?status=archived`);

    projectsActive = (a.projects || []).filter(p => p && p.id);
    projectNames = {};
    (a.projects || []).concat(b.projects || []).forEach(p => {
      if (p && p.id) projectNames[p.id] = (p.name || p.id);
    });

    populateProjectFilter();
  }


  async function load(){
    const data = await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects?status=${encodeURIComponent(listStatus)}`);
    listEl.innerHTML = '';
    (data.projects || []).forEach(p => {
      const card = document.createElement('div');
      card.className = 'am-card';
      card.style.padding = '12px';
      const head = document.createElement('div');
      head.style.display = 'flex';
      head.style.justifyContent = 'space-between';
      head.style.alignItems = 'center';
      head.style.gap = '10px';
      const t = document.createElement('div');
      const desc = String(p.description||'').trim();
      t.innerHTML = `<div class='h2'>${esc(p.name||'')}</div><div class='muted'>${esc(p.created_by_email||'')}</div>` + (desc ? `<div class='small-note'>${esc(desc)}</div>` : '');
      const actions = document.createElement('div');
      actions.style.display = 'flex';
      actions.style.gap = '8px';
      actions.style.flexWrap = 'wrap';

      const addBtn = (label, fn) => {
        const b = document.createElement('button');
        b.className = 'am-btn';
        b.textContent = label;
        b.onclick = fn;
        actions.appendChild(b);
      };

      addBtn('Open chats', () => { window.location.href = `/w/${encodeURIComponent(wsId)}?p=${encodeURIComponent(p.id)}`; });

      if (listStatus !== 'deleted') {
        addBtn('Edit', async () => {
        if (disabledForRO()) return;
        const nextName = await window.modalPrompt('Edit project', p.name || '', 'Project name', 'Save');
        if (nextName === null) return;
        const cleanName = String(nextName||'').trim();
        if (!cleanName) return;

        const nextDesc = await window.modalPrompt('Edit project', (p.description||''), 'Description (optional)', 'Save');
        if (nextDesc === null) return;
        const cleanDesc = String(nextDesc||'').trim();

        await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects/${encodeURIComponent(p.id)}`, {
          method:'PATCH',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: cleanName, description: cleanDesc })
        });
        safe(load)();
        });
      }

      if (listStatus === 'active') {
        addBtn('Archive', async () => {
          if (disabledForRO()) return;
          await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects/${encodeURIComponent(p.id)}/archive`, { method:'POST' });
          setListStatus('archived');
        });
        addBtn('Trash', async () => {
          if (disabledForRO()) return;
          await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects/${encodeURIComponent(p.id)}/trash`, { method:'POST' });
          setListStatus('deleted');
        });
      } else if (listStatus === 'archived') {
        addBtn('Unarchive', async () => {
          if (disabledForRO()) return;
          await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects/${encodeURIComponent(p.id)}/unarchive`, { method:'POST' });
          setListStatus('active');
        });
        addBtn('Trash', async () => {
          if (disabledForRO()) return;
          await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects/${encodeURIComponent(p.id)}/trash`, { method:'POST' });
          setListStatus('deleted');
        });
      } else {
        addBtn('Restore', async () => {
          if (disabledForRO()) return;
          await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects/${encodeURIComponent(p.id)}/restore`, { method:'POST' });
          setListStatus('active');
        });
      }
      head.appendChild(t);
      head.appendChild(actions);
      card.appendChild(head);
      listEl.appendChild(card);
    });
  }

  async function create(){
    if (disabledForRO()) return;
    const name = (nameEl.value||'').trim();
    if (!name) return;
    nameEl.value = '';
    await window.fetchJSON(`/api/workspaces/${encodeURIComponent(wsId)}/projects`, {
      method:'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ name })
    });
    await load();            // refresh lista subito
    setListStatus('active'); // mantiene tab attiva (se serve)
  }
  createBtn.onclick = safe(create);
  syncTabs();
  safe(load)();
})();
</script>
"""

    me_js = json.dumps(session_email)

    script = script.replace('__WSID__', wsid_js).replace('__STATUS__', status_js).replace('__ME__', me_js)

    return render_layout(body + script, title=f"Workspace · {wsname} · Projects", current_page="workspace", session_email=session_email)




def render_workspace_settings_page(session_email: str, ws: Dict[str, Any], role: str, user: Dict[str, Any], info: str = "", error: str = "") -> str:
    wsid = str(ws.get('id') or '')
    wsname = str(ws.get('name') or 'Workspace')
    status = str(ws.get('status') or 'active')
    uid = str(user.get('id') or '')

    ro_note = ""
    if status == 'archived':
        ro_note = "<div class='am-msg warn'>Workspace archived: read-only. (You can unarchive in the Danger zone.)</div>"
    elif status == 'deleted':
        ro_note = "<div class='am-msg err'>Workspace deleted.</div>"

    info_html = f"<div class='am-msg ok'>{html_escape.escape(info)}</div>" if info else ""
    error_html = f"<div class='am-msg err'>{html_escape.escape(error)}</div>" if error else ""

    members = list_members(wsid) or []
    # deterministic ordering
    members = sorted(members, key=lambda m: (0 if (m.get('role') == 'owner') else 1, str(m.get('email') or '')))

    members_rows = ""
    for m in members:
        mrole = str(m.get('role') or '')
        mid = str(m.get('user_id') or '')
        name = str(m.get('name') or '')
        email = str(m.get('email') or '')

        actions = ""
        if role == 'owner' and mrole != 'owner':
            actions = f"""
            <form method='post' action='/w/{html_escape.escape(wsid)}/member/remove' style='display:inline;'>
              <input type='hidden' name='member_user_id' value='{html_escape.escape(mid)}' />
              <button class='am-btn' type='submit'>Remove</button>
            </form>
            """
        elif role != 'owner' and mid == uid:
            actions = f"""
            <form method='post' action='/w/{html_escape.escape(wsid)}/leave' style='display:inline;'>
              <button class='am-btn' type='submit'>Leave</button>
            </form>
            """

        members_rows += f"<tr><td>{html_escape.escape(mrole)}</td><td>{html_escape.escape(name)}</td><td>{html_escape.escape(email)}</td><td>{actions}</td></tr>"

    owner_sections = ""
    if role == 'owner':
        pending = list_pending_invites(wsid) or []
        invites_rows = ""
        for inv in pending:
            inv_email = str(inv.get('email') or '')
            exp = str(inv.get('expires_at') or '')
            token = str(inv.get('token') or '')
            invites_rows += f"""
            <tr>
              <td>{html_escape.escape(inv_email)}</td>
              <td>{html_escape.escape(exp)}</td>
              <td style='display:flex;gap:8px;flex-wrap:wrap;'>
                <button class='am-btn js-copy-invite' type='button' data-token='{html_escape.escape(token)}'>Copy link</button>
                <form method='post' action='/w/{html_escape.escape(wsid)}/invite/revoke' style='display:inline;'>
                  <input type='hidden' name='token' value='{html_escape.escape(token)}' />
                  <button class='am-btn' type='submit'>Revoke</button>
                </form>
              </td>
            </tr>
            """

        owner_sections = f"""
        <div class='am-card' style='margin-top:14px;'>
          <div class='h2'>Rename workspace</div>
          <form method='post' action='/w/{html_escape.escape(wsid)}/rename' style='display:flex;gap:10px;align-items:center;flex-wrap:wrap;'>
            <input class='am-input' name='name' value='{html_escape.escape(wsname)}' placeholder='Workspace name' style='min-width:260px;' {'disabled' if status!='active' else ''} />
            <button class='am-btn primary' type='submit' {'disabled' if status!='active' else ''}>Save</button>
          </form>
          <div class='muted' style='margin-top:8px;'>Workspace ID: <code>{html_escape.escape(wsid)}</code></div>
        </div>

        <div class='am-card' style='margin-top:14px;'>
          <div class='h2'>Invite member</div>
          <form method='post' action='/w/{html_escape.escape(wsid)}/invite' style='display:flex;gap:10px;align-items:center;flex-wrap:wrap;'>
            <input class='am-input' name='email' placeholder='email@domain.com' style='min-width:260px;' {'disabled' if status!='active' else ''} />
            <button class='am-btn primary' type='submit' {'disabled' if status!='active' else ''}>Create invite</button>
          </form>
          <div class='muted' style='margin-top:8px;'>MVP: invites work for existing active accounts.</div>
        </div>

        <div class='am-card' style='margin-top:14px;'>
          <div class='h2'>Pending invites</div>
          <table class='am-table'>
            <thead><tr><th>Email</th><th>Expires</th><th>Actions</th></tr></thead>
            <tbody>
              {invites_rows or '<tr><td colspan="3" class="muted">No pending invites.</td></tr>'}
            </tbody>
          </table>
        </div>
        """

    danger = ""
    if role == 'owner':
        danger = """
        <div class='am-card' style='margin-top:14px;'>
          <div class='h2'>Danger zone</div>
          <div class='muted'>2FA required. Archive makes the workspace read-only; delete hides it.</div>
          <div style='display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;'>
            <button class='am-btn' id='wsArchiveBtn' type='button'>Archive</button>
            <button class='am-btn' id='wsDeleteBtn' type='button'>Delete</button>
          </div>
        </div>
        """

    body = f"""
    <div class='page'>
      <div class='am-card'>
        <div style='display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;'>
          <div>
            <div class='h1'>{html_escape.escape(wsname)} · Settings</div>
            <div class='muted'>Members, invites and workspace settings.</div>
          </div>
          {_ws_top_nav(wsid, 'settings')}
        </div>
      </div>
      {ro_note}
      {info_html}
      {error_html}

      <div class='am-card' style='margin-top:14px;'>
        <div class='h2'>Members</div>
        <table class='am-table'>
          <thead><tr><th>Role</th><th>Name</th><th>Email</th><th>Actions</th></tr></thead>
          <tbody>
            {members_rows or '<tr><td colspan="4" class="muted">No members.</td></tr>'}
          </tbody>
        </table>
      </div>

      {owner_sections}
      {danger}
    </div>
    """

    script = """<script>
(function(){
  const wsId = __WSID__;
  const wsStatus = __STATUS__;

  async function wsDangerAction(action){
    // Confirm BEFORE asking 2FA
   if (action === 'archive') {
      const ok = await window.modalConfirm('Archive workspace', 'Workspace becomes read-only. Continue?', 'Archive');
      if (!ok) return;
    }
    if (action === 'restore') {
      const ok = await window.modalConfirm('Unarchive workspace', 'Workspace will be writable again. Continue?', 'Unarchive');
      if (!ok) return;
    }

    // modalPrompt(title, value, placeholder, okText)
    const code = await window.modalPrompt('2FA required', '', 'Enter TOTP or backup code', 'Confirm');
    if (code === null) return;

    await window.fetchJSON(`/workspace/${action}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ workspace_id: wsId, code: String(code||'').trim() })
    });

    if (action === 'delete') window.location.href = '/workspace';
    else window.location.reload();
  }

  const wsArchiveBtn = document.getElementById('wsArchiveBtn');
  const wsDeleteBtn = document.getElementById('wsDeleteBtn');
  if (wsArchiveBtn) {
    wsArchiveBtn.textContent = (wsStatus === 'archived') ? 'Unarchive workspace' : 'Archive workspace';
    wsArchiveBtn.disabled = (wsStatus === 'deleted');
    wsArchiveBtn.onclick = () => wsDangerAction(wsStatus === 'archived' ? 'restore' : 'archive');
  }
  if (wsDeleteBtn) {
    wsDeleteBtn.disabled = (wsStatus === 'deleted');
    wsDeleteBtn.onclick = async () => {
      const ok = await window.modalConfirm('Delete workspace', 'This will mark the workspace as deleted. Continue?', 'Delete');
      if (!ok) return;
      await wsDangerAction('delete');
    };
  }

  // copy invite links
  document.querySelectorAll('.js-copy-invite').forEach(btn => {
    btn.addEventListener('click', async () => {
      const tok = btn.getAttribute('data-token') || '';
      if (!tok) return;
      const link = window.location.origin + `/workspace/invite/${tok}`;
      try {
        await navigator.clipboard.writeText(link);
        await window.modalConfirm('Link copied', 'Share this link with the invited user.', 'OK');
      } catch (e) {
        await window.modalPrompt('Invite link', link, 'Copy this link', 'Close');

      }
    });
  });
})();
</script>
"""
    script = script.replace('__WSID__', json.dumps(wsid)).replace('__STATUS__', json.dumps(status))

    return render_layout(body + script, title=f"Workspace · {wsname} · Settings", current_page="workspace", session_email=session_email)


@app.get("/w/{workspace_id}", response_class=HTMLResponse)
async def workspace_env_page(request: Request, workspace_id: str) -> HTMLResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and email and role
    return HTMLResponse(render_workspace_chat_page(email, ws, role))


@app.get("/w/{workspace_id}/projects", response_class=HTMLResponse)
async def workspace_projects_page(request: Request, workspace_id: str) -> HTMLResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and email and role
    return HTMLResponse(render_workspace_projects_page(email, ws, role))




@app.get("/w/{workspace_id}/settings", response_class=HTMLResponse)
async def workspace_settings_page(request: Request, workspace_id: str) -> HTMLResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and email and role and user
    return HTMLResponse(render_workspace_settings_page(email, ws, role, user))


@app.post("/w/{workspace_id}/rename", response_class=HTMLResponse)
async def workspace_settings_rename(request: Request, workspace_id: str, name: str = Form(...)) -> HTMLResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and email and user
    if role != 'owner':
        return HTMLResponse(render_workspace_settings_page(email, ws, role, user, info='', error='Owner only.'), status_code=403)
    if str(ws.get('status') or 'active') != 'active':
        return HTMLResponse(render_workspace_settings_page(email, ws, role, user, info='', error='Workspace is not active.'), status_code=403)

    new_name = str(name or '').strip()
    if not new_name:
        return HTMLResponse(render_workspace_settings_page(email, ws, role, user, info='', error='Name required.'), status_code=400)

    ok = update_workspace_name(workspace_id=str(workspace_id), new_name=new_name, actor_user_id=str(user.get('id') or ''))
    if not ok:
        return HTMLResponse(render_workspace_settings_page(email, ws, role, user, info='', error='Rename failed.'), status_code=500)
    ws2 = get_workspace(str(workspace_id)) or ws
    return HTMLResponse(render_workspace_settings_page(email, ws2, role, user, info='Workspace renamed.', error=''))


@app.post("/w/{workspace_id}/invite", response_class=HTMLResponse)
async def workspace_settings_invite(request: Request, workspace_id: str, email: str = Form(...)) -> HTMLResponse:
    ws, session_email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and session_email and user
    if role != 'owner':
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Owner only.'), status_code=403)
    if str(ws.get('status') or 'active') != 'active':
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Workspace is not active.'), status_code=403)

    invite_email = _normalize_email_addr(email)
    if not invite_email:
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Invite email is required.'), status_code=400)

    invited_user = get_user_by_email(invite_email)
    if not invited_user or not invited_user.get('is_active', True):
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='MVP: invite existing active users only.'), status_code=400)

    try:
        token = create_invite(workspace_id=str(workspace_id), email=invite_email, invited_by_user_id=str(user.get('id') or ''), ttl_hours=48)
    except Exception as exc:
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error=f'Failed to create invite: {exc}'), status_code=500)

    base = str(request.base_url).rstrip('/')
    link = f"{base}/workspace/invite/{token}"

    try:
        subject = 'amamau Insight AI - workspace invite'
        html_body = f"""
          <p>You have been invited to join a workspace on amamau Insight AI.</p>
          <p>Workspace: <strong>{html_escape.escape(str(ws.get('name') or 'Workspace'))}</strong></p>
          <p>Invite for: <strong>{html_escape.escape(invite_email)}</strong></p>
          <p><a href="{html_escape.escape(link)}">Accept invite</a></p>
          <p>This link expires in 48 hours.</p>
        """
        _send_email(invite_email, subject, html_body)
    except Exception:
        pass

    ws2 = get_workspace(str(workspace_id)) or ws
    return HTMLResponse(render_workspace_settings_page(session_email, ws2, role, user, info=f'Invite created for {invite_email}.', error=''))


@app.post("/w/{workspace_id}/invite/revoke", response_class=HTMLResponse)
async def workspace_settings_invite_revoke(request: Request, workspace_id: str, token: str = Form(...)) -> HTMLResponse:
    ws, session_email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and session_email and user
    if role != 'owner':
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Owner only.'), status_code=403)

    ok = revoke_invite(token=str(token or '').strip(), actor_user_id=str(user.get('id') or ''))
    ws2 = get_workspace(str(workspace_id)) or ws
    if not ok:
        return HTMLResponse(render_workspace_settings_page(session_email, ws2, role, user, info='', error='Revoke failed.'), status_code=400)
    return HTMLResponse(render_workspace_settings_page(session_email, ws2, role, user, info='Invite revoked.', error=''))


@app.post("/w/{workspace_id}/member/remove", response_class=HTMLResponse)
async def workspace_settings_member_remove(request: Request, workspace_id: str, member_user_id: str = Form(...)) -> HTMLResponse:
    ws, session_email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and session_email and user
    if role != 'owner':
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Owner only.'), status_code=403)

    mid = str(member_user_id or '').strip()
    if not mid:
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='member_user_id required.'), status_code=400)

    ok = remove_member(workspace_id=str(workspace_id), user_id=mid)
    ws2 = get_workspace(str(workspace_id)) or ws
    if not ok:
        return HTMLResponse(render_workspace_settings_page(session_email, ws2, role, user, info='', error='Remove failed.'), status_code=400)
    return HTMLResponse(render_workspace_settings_page(session_email, ws2, role, user, info='Member removed.', error=''))


@app.post("/w/{workspace_id}/leave", response_class=HTMLResponse)
async def workspace_settings_leave(request: Request, workspace_id: str) -> HTMLResponse:
    ws, session_email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return HTMLResponse(err.body.decode('utf-8') if hasattr(err, 'body') else 'Forbidden', status_code=err.status_code)
    assert ws and session_email and user

    if role == 'owner':
        return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Owner cannot leave the workspace.'), status_code=400)

    ok = remove_member(workspace_id=str(workspace_id), user_id=str(user.get('id') or ''))
    if ok:
        return RedirectResponse(url='/workspace', status_code=302)
    return HTMLResponse(render_workspace_settings_page(session_email, ws, role, user, info='', error='Leave failed.'), status_code=400)


# ------------------------------
# Workspace API: conversations
# ------------------------------


@app.get("/api/workspaces/{workspace_id}/conversations")
async def api_ws_list_conversations(request: Request, workspace_id: str, status: str = "active", project_id: str = ""):
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    convs = ws_list_conversations(workspace_id=str(workspace_id), limit=100, status=status, project_id=project_id)
    return JSONResponse({"conversations": convs})


@app.post("/api/workspaces/{workspace_id}/conversations")
async def api_ws_create_conversation(request: Request, workspace_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        data = {}

    title = str((data or {}).get('title') or '').strip() or 'New chat'
    project_id = str((data or {}).get('project_id') or '').strip() or None
    profile_id = str(ws.get('profile_id') or '').strip()
    if not profile_id:
        return JSONResponse({"error": "Workspace has no profile_id."}, status_code=400)

    conv_id = uuid.uuid4().hex
    conv = ws_create_conversation(conv_id=conv_id, workspace_id=str(workspace_id), profile_id=profile_id, created_by_email=str(email), title=title, project_id=project_id)
    try:
        audit_event('ws.conversation.create', str(email), {'workspace_id': str(workspace_id), 'conversation_id': str(conv_id), 'project_id': project_id or ''})
    except Exception:
        pass
    return JSONResponse({"conversation": conv})


@app.get("/api/workspaces/{workspace_id}/conversations/{conversation_id}")
async def api_ws_get_conversation(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err

    conv = ws_get_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id))
    if not conv:
        return JSONResponse({"error": "Conversation not found."}, status_code=404)

    msgs = ws_list_messages(workspace_id=str(workspace_id), conversation_id=str(conversation_id), limit=400)
    return JSONResponse({"conversation": conv, "messages": msgs})


@app.patch("/api/workspaces/{workspace_id}/conversations/{conversation_id}")
async def api_ws_update_conversation(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON."}, status_code=400)

    title = str((data or {}).get('title') or '').strip()
    has_project_field = isinstance(data, dict) and ('project_id' in data)
    project_id = str((data or {}).get('project_id') or '').strip() if has_project_field else None

    if not title and not has_project_field:
        return JSONResponse({"error": "No fields to update."}, status_code=400)

    if title:
        ok = ws_rename_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id), title=title)
        if not ok:
            return JSONResponse({"error": "Unable to update title."}, status_code=500)

    if has_project_field:
        ok = ws_set_conversation_project(workspace_id=str(workspace_id), conversation_id=str(conversation_id), project_id=str(project_id or ''))
        if not ok:
            return JSONResponse({"error": "Unable to update project."}, status_code=400)

    try:
        audit_event('ws.conversation.update', str(email), {'workspace_id': str(workspace_id), 'conversation_id': str(conversation_id), 'title': title or '', 'project_id': (project_id if has_project_field else '')})
    except Exception:
        pass

    conv = ws_get_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id))
    return JSONResponse({"conversation": conv})



@app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/message")
async def api_ws_send_message(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON body."}, status_code=400)

    message = str((data or {}).get('message') or '').strip()
    if not message:
        return JSONResponse({"error": "Empty message."}, status_code=400)

    conv = ws_get_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id))
    if not conv:
        return JSONResponse({"error": "Conversation not found."}, status_code=404)

    profile_id = str(ws.get('profile_id') or '').strip()
    if not profile_id:
        return JSONResponse({"error": "Workspace has no profile."}, status_code=400)

    # auto-title
    try:
        current_title = str(conv.get('title') or '').strip().lower()
        if current_title in ('', 'new chat'):
            ws_rename_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id), title=_title_from_msg(message))
    except Exception:
        pass

    prev = ws_list_messages(workspace_id=str(workspace_id), conversation_id=str(conversation_id), limit=400)
    history_pairs = db_build_history_pairs(prev, max_pairs=6)

    ws_add_message(workspace_id=str(workspace_id), conversation_id=str(conversation_id), role='user', content=message, author_email=str(email), author_name=str((user or {}).get('name') or ''))
    reply = run_llm_for_profile_with_history(profile_id, message, history_pairs)
    ws_add_message(workspace_id=str(workspace_id), conversation_id=str(conversation_id), role='assistant', content=reply, author_email='', author_name='AI')

    return JSONResponse({"reply": reply})


@app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/archive")
async def api_ws_archive_conversation(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_archive_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id), archived=True)
    if ok:
        audit_event('ws.conversation.archive', str(email), {'workspace_id': str(workspace_id), 'conversation_id': str(conversation_id)})
    return JSONResponse({"ok": ok})


@app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/unarchive")
async def api_ws_unarchive_conversation(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_archive_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id), archived=False)
    if ok:
        audit_event('ws.conversation.unarchive', str(email), {'workspace_id': str(workspace_id), 'conversation_id': str(conversation_id)})
    return JSONResponse({"ok": ok})


@app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/trash")
async def api_ws_trash_conversation(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_soft_delete_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id))
    if ok:
        audit_event('ws.conversation.trash', str(email), {'workspace_id': str(workspace_id), 'conversation_id': str(conversation_id)})
    return JSONResponse({"ok": ok})


@app.post("/api/workspaces/{workspace_id}/conversations/{conversation_id}/restore")
async def api_ws_restore_conversation(request: Request, workspace_id: str, conversation_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_restore_conversation(workspace_id=str(workspace_id), conversation_id=str(conversation_id))
    if ok:
        audit_event('ws.conversation.restore', str(email), {'workspace_id': str(workspace_id), 'conversation_id': str(conversation_id)})
    return JSONResponse({"ok": ok})


# ------------------------------
# Workspace API: projects
# ------------------------------


@app.get("/api/workspaces/{workspace_id}/projects")
async def api_ws_list_projects(request: Request, workspace_id: str, status: str = "active") -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    projs = ws_list_projects(workspace_id=str(workspace_id), limit=200, status=status)
    return JSONResponse({"projects": projs})


@app.post("/api/workspaces/{workspace_id}/projects")
async def api_ws_create_project(request: Request, workspace_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)

    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON."}, status_code=400)

    name = str((data or {}).get('name') or '').strip()
    desc = str((data or {}).get('description') or '').strip() or None
    if not name:
        return JSONResponse({"error": "Missing name."}, status_code=400)

    pid = uuid.uuid4().hex
    proj = ws_create_project(project_id=pid, workspace_id=str(workspace_id), name=name, description=desc, created_by_email=str(email))
    if proj:
        audit_event('ws.project.create', str(email), {'workspace_id': str(workspace_id), 'project_id': str(pid), 'name': name})
    return JSONResponse({"project": proj})


@app.get("/api/workspaces/{workspace_id}/projects/{project_id}")
async def api_ws_get_project(request: Request, workspace_id: str, project_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    proj = ws_get_project(workspace_id=str(workspace_id), project_id=str(project_id))
    if not proj:
        return JSONResponse({"error": "Project not found."}, status_code=404)
    return JSONResponse({"project": proj})


@app.patch("/api/workspaces/{workspace_id}/projects/{project_id}")
async def api_ws_update_project(request: Request, workspace_id: str, project_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    try:
        data = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON."}, status_code=400)
    name = (data or {}).get('name')
    desc = (data or {}).get('description')
    if name is not None:
        name = str(name or '').strip()
        if not name:
            return JSONResponse({"error": "Name required."}, status_code=400)
    if desc is not None:
        desc = str(desc or '').strip()
    ok = ws_update_project(workspace_id=str(workspace_id), project_id=str(project_id), name=name, description=desc)
    if ok:
        audit_event('ws.project.update', str(email), {'workspace_id': str(workspace_id), 'project_id': str(project_id)})
    return JSONResponse({"ok": bool(ok)})


@app.post("/api/workspaces/{workspace_id}/projects/{project_id}/archive")
async def api_ws_archive_project(request: Request, workspace_id: str, project_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_set_project_archived(workspace_id=str(workspace_id), project_id=str(project_id), archived=True)
    if ok:
        audit_event('ws.project.archive', str(email), {'workspace_id': str(workspace_id), 'project_id': str(project_id)})
    return JSONResponse({"ok": ok})


@app.post("/api/workspaces/{workspace_id}/projects/{project_id}/unarchive")
async def api_ws_unarchive_project(request: Request, workspace_id: str, project_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_set_project_archived(workspace_id=str(workspace_id), project_id=str(project_id), archived=False)
    if ok:
        audit_event('ws.project.unarchive', str(email), {'workspace_id': str(workspace_id), 'project_id': str(project_id)})
    return JSONResponse({"ok": ok})


@app.post("/api/workspaces/{workspace_id}/projects/{project_id}/trash")
async def api_ws_trash_project(request: Request, workspace_id: str, project_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_soft_delete_project(workspace_id=str(workspace_id), project_id=str(project_id))
    if ok:
        audit_event('ws.project.trash', str(email), {'workspace_id': str(workspace_id), 'project_id': str(project_id)})
    return JSONResponse({"ok": ok})


@app.post("/api/workspaces/{workspace_id}/projects/{project_id}/restore")
async def api_ws_restore_project(request: Request, workspace_id: str, project_id: str) -> JSONResponse:
    ws, email, user, role, err = _require_workspace(request, workspace_id)
    if err:
        return err
    if str(ws.get('status') or 'active') == 'archived':
        return JSONResponse({"error": "Workspace archived."}, status_code=403)
    ok = ws_restore_project(workspace_id=str(workspace_id), project_id=str(project_id))
    if ok:
        audit_event('ws.project.restore', str(email), {'workspace_id': str(workspace_id), 'project_id': str(project_id)})
    return JSONResponse({"ok": ok})


# ------------------------------
# Workspace dangerous actions (2FA required)
# ------------------------------


@app.post("/workspace/archive")
async def api_workspace_archive(request: Request) -> JSONResponse:
    wsid = ""
    code = ""
    try:
        data = await request.json()
        wsid = str((data or {}).get('workspace_id') or '').strip()
        code = str((data or {}).get('code') or '').strip()
    except Exception:
        pass

    if not wsid:
        return JSONResponse({"error": "workspace_id required"}, status_code=400)

    ws, email, user, role, err = _require_workspace(request, wsid)
    if err:
        return err
    assert user is not None and email is not None

    if role != 'owner':
        return JSONResponse({"error": "Owner only"}, status_code=403)

    ip = _client_ip(request)
    if _rate_limited(f"ws_archive:{ip}:{wsid}", limit=6, window_seconds=60):
        return JSONResponse({"error": "Too many requests"}, status_code=429)

    err2 = _require_2fa_or_error(request, user, code)
    if err2:
        return JSONResponse({"error": err2}, status_code=400)

    ok = archive_workspace(workspace_id=wsid, actor_user_id=str(user.get('id') or ''))

    try:
        audit_event(
            event="workspace_archive",
            user_email=email,
            user_id=str(user.get('id') or '') if user else None,
            ip=ip,
            ua=str(request.headers.get('user-agent') or '') or None,
            meta={"workspace_id": wsid},
        )
    except Exception:
        pass

    return JSONResponse({"ok": bool(ok)})



@app.post("/workspace/restore")
async def api_workspace_restore(request: Request) -> JSONResponse:
    wsid = ""
    code = ""
    try:
        data = await request.json()
        wsid = str((data or {}).get('workspace_id') or '').strip()
        code = str((data or {}).get('code') or '').strip()
    except Exception:
        pass

    if not wsid:
        return JSONResponse({"error": "workspace_id required"}, status_code=400)

    ws, email, user, role, err = _require_workspace(request, wsid)
    if err:
        return err
    assert user is not None and email is not None

    if role != 'owner':
        return JSONResponse({"error": "Owner only"}, status_code=403)

    ip = _client_ip(request)
    if _rate_limited(f"ws_restore:{ip}:{wsid}", limit=6, window_seconds=60):
        return JSONResponse({"error": "Too many requests"}, status_code=429)

    err2 = _require_2fa_or_error(request, user, code)
    if err2:
        return JSONResponse({"error": err2}, status_code=400)

    ok = restore_workspace(workspace_id=wsid, actor_user_id=str(user.get('id') or ''))

    try:
        audit_event(
            event="workspace_restore",
            user_email=email,
            user_id=str(user.get('id') or '') if user else None,
            ip=ip,
            ua=str(request.headers.get('user-agent') or '') or None,
            meta={"workspace_id": wsid},
        )
    except Exception:
        pass

    return JSONResponse({"ok": bool(ok)})

@app.post("/workspace/delete")
async def api_workspace_delete(request: Request) -> JSONResponse:
    wsid = ""
    code = ""
    try:
        data = await request.json()
        wsid = str((data or {}).get('workspace_id') or '').strip()
        code = str((data or {}).get('code') or '').strip()
    except Exception:
        pass

    if not wsid:
        return JSONResponse({"error": "workspace_id required"}, status_code=400)

    ws, email, user, role, err = _require_workspace(request, wsid)
    if err:
        return err
    assert user is not None and email is not None

    if role != 'owner':
        return JSONResponse({"error": "Owner only"}, status_code=403)

    ip = _client_ip(request)
    if _rate_limited(f"ws_delete:{ip}:{wsid}", limit=4, window_seconds=60):
        return JSONResponse({"error": "Too many requests"}, status_code=429)

    err2 = _require_2fa_or_error(request, user, code)
    if err2:
        return JSONResponse({"error": err2}, status_code=400)

    ok = delete_workspace(workspace_id=wsid, actor_user_id=str(user.get('id') or ''))

    try:
        audit_event(
            event="workspace_delete",
            user_email=email,
            user_id=str(user.get('id') or '') if user else None,
            ip=ip,
            ua=str(request.headers.get('user-agent') or '') or None,
            meta={"workspace_id": wsid},
        )
    except Exception:
        pass

    return JSONResponse({"ok": bool(ok)})



# -------------------------------------------------------------------
# End
# -------------------------------------------------------------------
