#!/usr/bin/env python3
import sys
import json
import getpass
from pathlib import Path
from typing import Dict, List

from config import PROFILES_DIR, MEMORY_DIR
from profiles import (
    list_profiles,
    create_profile_interactive,
    edit_profile_interactive,
)
from tokens import (
    list_tokens,
    create_token,
    delete_token,
)

try:
    import bcrypt
except ImportError:
    print(
        "This console requires bcrypt.\n"
        "Install it in your venv:\n\n"
        "  (venv) pip install bcrypt\n"
    )
    sys.exit(1)

BASE_DIR = Path(__file__).resolve().parent
USERS_PATH = BASE_DIR / "data" / "users.json"


# =========================
# Generic helpers
# =========================

def _pause() -> None:
    input("\nPress ENTER to continue...")


# =========================
# USER MANAGEMENT HELPERS
# =========================

def load_users() -> List[Dict]:
    if not USERS_PATH.exists():
        return []
    with open(USERS_PATH, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print("ERROR: users.json is not valid JSON", file=sys.stderr)
            sys.exit(1)


def save_users(users: List[Dict]) -> None:
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = USERS_PATH.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)
    tmp.replace(USERS_PATH)


def find_user(users: List[Dict], email: str) -> Dict:
    email = email.lower().strip()
    for u in users:
        if u.get("email", "").lower() == email:
            return u
    return None


def hash_password(raw: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(raw.encode("utf-8"), salt).decode("utf-8")


# =========================
# PROFILE MANAGEMENT
# =========================

def do_list_profiles() -> None:
    profiles = list_profiles()
    if not profiles:
        print("\nNo profiles found.")
        _pause()
        return

    print("\n=== Profiles ===")
    for idx, p in enumerate(profiles, start=1):
        print(
            f"{idx}. id: {p.get('id')} | name: {p.get('name')} | "
            f"lang: {p.get('language', 'it')} | industry: {p.get('industry', '')}"
        )
        desc = p.get("description", "")
        if desc:
            print(f"    desc: {desc}")
    _pause()


def do_create_profile() -> None:
    create_profile_interactive()
    _pause()


def do_edit_profile() -> None:
    edit_profile_interactive()
    _pause()


def do_delete_profile() -> None:
    from profiles import list_profiles  # ensure fresh list

    profiles = list_profiles()
    if not profiles:
        print("\nNo profiles to delete.")
        _pause()
        return

    print("\n=== Delete profile ===")
    for idx, p in enumerate(profiles, start=1):
        print(f"{idx}. {p.get('name')} (id: {p.get('id')})")
    print()

    choice = input("Select profile number to delete: ").strip()
    if not choice.isdigit():
        print("Invalid choice.")
        _pause()
        return

    idx = int(choice)
    if not (1 <= idx <= len(profiles)):
        print("Number out of range.")
        _pause()
        return

    profile = profiles[idx - 1]
    pid = profile.get("id")
    confirm = input(
        f"Type 'DELETE' to permanently remove profile '{pid}' and its memory: "
    ).strip()
    if confirm != "DELETE":
        print("Cancelled.")
        _pause()
        return

    # delete profile JSON
    profile_path = PROFILES_DIR / f"{pid}.json"
    if profile_path.exists():
        profile_path.unlink()
        print(f"[OK] Profile file removed: {profile_path}")
    else:
        print("[WARN] Profile file not found.")

    # delete memory file if exists
    mem_path = MEMORY_DIR / f"{pid}.md"
    if mem_path.exists():
        mem_path.unlink()
        print(f"[OK] Memory file removed: {mem_path}")

    # clean tokens pointing to this profile
    tokens = list_tokens()
    removed = 0
    for token, info in list(tokens.items()):
        if info.get("profile_id") == pid:
            delete_token(token)
            removed += 1
    if removed:
        print(f"[OK] Removed {removed} token(s) pointing to this profile.")

    _pause()


# =========================
# TOKEN MANAGEMENT
# =========================

def do_list_tokens() -> None:
    tokens: Dict[str, Dict] = list_tokens()
    if not tokens:
        print("\nNo tokens defined.")
        _pause()
        return

    print("\n=== Tokens ===")
    for idx, (token, info) in enumerate(tokens.items(), start=1):
        short = token[:8] + "..." if len(token) > 8 else token
        print(f"{idx}. token: {short}")
        print(f"    profile_id: {info.get('profile_id')}")
        label = info.get("label", "")
        if label:
            print(f"    label     : {label}")
    _pause()


def do_create_token() -> None:
    from profiles import list_profiles  # fresh

    profiles = list_profiles()
    if not profiles:
        print("\nNo profiles found. Create a profile first.")
        _pause()
        return

    print("\n=== Create token for profile ===")
    for idx, p in enumerate(profiles, start=1):
        print(f"{idx}. {p.get('name')} (id: {p.get('id')})")
    print()

    choice = input("Select profile number: ").strip()
    if not choice.isdigit():
        print("Invalid choice.")
        _pause()
        return

    idx = int(choice)
    if not (1 <= idx <= len(profiles)):
        print("Number out of range.")
        _pause()
        return

    profile = profiles[idx - 1]
    pid = profile.get("id")
    label = input("Optional label for this token (beta tester name, etc.): ").strip()

    token = create_token(profile_id=pid, label=label)
    print("\n[OK] Token created.")
    print(f"Token (50 chars): {token}")
    print(f"Suggested URL: https://ai.amamau.com/t/{token}")
    _pause()


def do_delete_token() -> None:
    tokens = list_tokens()
    if not tokens:
        print("\nNo tokens to delete.")
        _pause()
        return

    items = list(tokens.items())
    print("\n=== Delete token ===")
    for idx, (token, info) in enumerate(items, start=1):
        short = token[:8] + "..." if len(token) > 8 else token
        print(
            f"{idx}. token: {short} | profile_id: {info.get('profile_id')} | "
            f"label: {info.get('label', '')}"
        )
    print()

    choice = input("Select token number to delete: ").strip()
    if not choice.isdigit():
        print("Invalid choice.")
        _pause()
        return

    idx = int(choice)
    if not (1 <= idx <= len(items)):
        print("Number out of range.")
        _pause()
        return

    token, info = items[idx - 1]
    confirm = input(f"Type 'DELETE' to remove token {token[:8]}...: ").strip()
    if confirm != "DELETE":
        print("Cancelled.")
        _pause()
        return

    if delete_token(token):
        print("[OK] Token removed.")
    else:
        print("[WARN] Token not found (race condition?).")
    _pause()


# =========================
# USER MANAGEMENT (accounts)
# =========================

def do_list_users() -> None:
    users = load_users()
    if not users:
        print("\nNo users found.")
        _pause()
        return

    print("\n=== Users ===")
    print(f"Total: {len(users)}\n")
    for u in users:
        flags = []
        if u.get("is_owner"):
            flags.append("OWNER")
        if not u.get("is_active", True):
            flags.append("INACTIVE")
        flags_str = f" [{' ,'.join(flags)}]" if flags else ""
        print(
            f"- {u.get('email')}  (name='{u.get('name')}', "
            f"profile_id='{u.get('profile_id', '')}'){flags_str}"
        )
    _pause()


def do_create_user() -> None:
    users = load_users()
    email = input("Email: ").strip().lower()
    if not email:
        print("Email required.")
        _pause()
        return
    if find_user(users, email):
        print(f"ERROR: user {email} already exists")
        _pause()
        return

    name = input("Name (display): ").strip()
    profile_id = input("Linked profile_id (optional): ").strip()
    owner_flag = input("Is owner? [y/N]: ").strip().lower() == "y"

    pwd1 = getpass.getpass("Password: ")
    pwd2 = getpass.getpass("Repeat password: ")
    if pwd1 != pwd2:
        print("ERROR: passwords do not match.")
        _pause()
        return

    pwd_hash = hash_password(pwd1)
    new_user = {
        "id": "u_" + Path().stem + "_" + str(len(users) + 1),
        "email": email,
        "password_hash": pwd_hash,
        "name": name or email,
        "profile_id": profile_id,
        "is_active": True,
        "is_owner": owner_flag,
    }
    users.append(new_user)
    save_users(users)
    print(f"[OK] Created user {email}.")
    _pause()


def _select_user_interactive(users: List[Dict]) -> Dict:
    if not users:
        print("\nNo users found.")
        return None

    print("\n=== Select user ===")
    for idx, u in enumerate(users, start=1):
        flags = []
        if u.get("is_owner"):
            flags.append("OWNER")
        if not u.get("is_active", True):
            flags.append("INACTIVE")
        flags_str = f" [{' ,'.join(flags)}]" if flags else ""
        print(f"{idx}. {u.get('email')} (name='{u.get('name')}'){flags_str}")
    print()
    choice = input("Select user number: ").strip()
    if not choice.isdigit():
        print("Invalid choice.")
        return None
    idx = int(choice)
    if not (1 <= idx <= len(users)):
        print("Number out of range.")
        return None
    return users[idx - 1]


def do_edit_user() -> None:
    users = load_users()
    user = _select_user_interactive(users)
    if not user:
        _pause()
        return

    print("\nEditing user:")
    print(f"Current name       : {user.get('name')}")
    print(f"Current profile_id : {user.get('profile_id', '')}")
    print()

    new_name = input("New name (ENTER to keep): ").strip()
    new_profile_id = input("New profile_id (ENTER to keep): ").strip()

    if new_name:
        user["name"] = new_name
    if new_profile_id:
        user["profile_id"] = new_profile_id

    save_users(users)
    print("[OK] User updated.")
    _pause()


def do_toggle_active_user() -> None:
    users = load_users()
    user = _select_user_interactive(users)
    if not user:
        _pause()
        return

    current = user.get("is_active", True)
    user["is_active"] = not current
    save_users(users)
    print(f"[OK] User {user.get('email')} is_active set to {user['is_active']}.")
    _pause()


def do_toggle_owner_user() -> None:
    users = load_users()
    user = _select_user_interactive(users)
    if not user:
        _pause()
        return

    current = user.get("is_owner", False)
    user["is_owner"] = not current
    save_users(users)
    print(f"[OK] User {user.get('email')} is_owner set to {user['is_owner']}.")
    _pause()


def do_reset_user_password() -> None:
    users = load_users()
    user = _select_user_interactive(users)
    if not user:
        _pause()
        return

    pwd1 = getpass.getpass("New password: ")
    pwd2 = getpass.getpass("Repeat password: ")
    if pwd1 != pwd2:
        print("ERROR: passwords do not match.")
        _pause()
        return

    user["password_hash"] = hash_password(pwd1)
    save_users(users)
    print(f"[OK] Password reset for {user.get('email')}.")
    _pause()


def do_delete_user() -> None:
    users = load_users()
    if not users:
        print("\nNo users to delete.")
        _pause()
        return

    user = _select_user_interactive(users)
    if not user:
        _pause()
        return

    email = user.get("email")
    confirm = input(
        f"Type 'DELETE' to permanently remove user {email}: "
    ).strip()
    if confirm != "DELETE":
        print("Cancelled.")
        _pause()
        return

    users = [u for u in users if u.get("email") != email]
    save_users(users)
    print(f"[OK] User {email} removed.")
    _pause()


# =========================
# MAIN MENU
# =========================

def menu() -> None:
    while True:
        print("\n=== AMAMAU Owner Console ===")
        print("Profiles / tokens")
        print("  1) List profiles")
        print("  2) Create profile")
        print("  3) Edit profile")
        print("  4) Delete profile")
        print("  5) List tokens")
        print("  6) Create token for profile")
        print("  7) Delete token")
        print("")
        print("Users (accounts)")
        print("  8) List users")
        print("  9) Create user")
        print(" 10) Edit user (name/profile)")
        print(" 11) Toggle user active/inactive")
        print(" 12) Toggle user owner flag")
        print(" 13) Reset user password")
        print(" 14) Delete user")
        print("")
        print(" 15) Exit")

        choice = input("Choose an option: ").strip()

        if choice == "1":
            do_list_profiles()
        elif choice == "2":
            do_create_profile()
        elif choice == "3":
            do_edit_profile()
        elif choice == "4":
            do_delete_profile()
        elif choice == "5":
            do_list_tokens()
        elif choice == "6":
            do_create_token()
        elif choice == "7":
            do_delete_token()
        elif choice == "8":
            do_list_users()
        elif choice == "9":
            do_create_user()
        elif choice == "10":
            do_edit_user()
        elif choice == "11":
            do_toggle_active_user()
        elif choice == "12":
            do_toggle_owner_user()
        elif choice == "13":
            do_reset_user_password()
        elif choice == "14":
            do_delete_user()
        elif choice == "15":
            print("Bye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    menu()
