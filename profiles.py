import json
import re
from pathlib import Path
from typing import List, Dict

from config import PROFILES_DIR


def _profile_path(profile_id: str) -> Path:
    return PROFILES_DIR / f"{profile_id}.json"


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", name.strip().lower()).strip("-")
    return slug or "profile"


def list_profiles() -> List[Dict]:
    profiles: List[Dict] = []
    for path in PROFILES_DIR.glob("*.json"):
        try:
            with path.open(encoding="utf-8") as f:
                data = json.load(f)
                profiles.append(data)
        except Exception:
            continue
    profiles.sort(key=lambda p: p.get("name", "").lower())
    return profiles


def load_profile(profile_id: str) -> Dict:
    path = _profile_path(profile_id)
    if not path.exists():
        raise FileNotFoundError(f"Profile '{profile_id}' not found.")
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def create_profile_interactive() -> Dict:
    print("\n=== Create new business profile ===")
    name = input("Profile name (example: 'THITA', 'AMAMAU Core'): ").strip()
    while not name:
        name = input("Profile name cannot be empty. Enter a name: ").strip()

    description = input("Short description (business model, target, etc.): ").strip()
    language = input("Preferred language (it/en, default: it): ").strip().lower() or "it"
    industry = input("Industry (example: SaaS, e-commerce, agency): ").strip()

    base_id = _slugify(name)
    profile_id = base_id
    i = 2
    while _profile_path(profile_id).exists():
        profile_id = f"{base_id}-{i}"
        i += 1

    data: Dict = {
        "id": profile_id,
        "name": name,
        "description": description,
        "language": language,
        "industry": industry,
    }

    path = _profile_path(profile_id)
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"\n[OK] Profile created with id: {profile_id}")
    return data


def _print_profile_summary(profile: Dict) -> None:
    print(f"- id: {profile.get('id')}")
    print(f"  name: {profile.get('name')}")
    print(f"  language: {profile.get('language', 'it')}")
    print(f"  industry: {profile.get('industry', '')}")
    desc = profile.get("description", "")
    if desc:
        print(f"  description: {desc}")


def select_profile_interactive() -> Dict:
    profiles = list_profiles()
    if not profiles:
        print("\nNo profiles found. Creating a new one.")
        return create_profile_interactive()

    print("\n=== Available profiles ===")
    for idx, p in enumerate(profiles, start=1):
        print(f"{idx}. {p.get('name')} (id: {p.get('id')}, lang: {p.get('language', 'it')})")
        if p.get("description"):
            print(f"   {p['description']}")
    print()

    while True:
        choice = input("Select profile number or 'n' to create new: ").strip().lower()
        if choice == "n":
            return create_profile_interactive()
        if not choice.isdigit():
            print("Invalid choice.")
            continue
        idx = int(choice)
        if 1 <= idx <= len(profiles):
            return profiles[idx - 1]
        print("Number out of range.")


def edit_profile_interactive() -> None:
    profiles = list_profiles()
    if not profiles:
        print("\nNo profiles to edit.")
        return

    print("\n=== Edit profile ===")
    for idx, p in enumerate(profiles, start=1):
        print(f"{idx}. {p.get('name')} (id: {p.get('id')})")
    print()

    choice = input("Select profile number to edit: ").strip()
    if not choice.isdigit():
        print("Invalid choice.")
        return
    idx = int(choice)
    if not (1 <= idx <= len(profiles)):
        print("Number out of range.")
        return

    profile = profiles[idx - 1]
    print(f"\nEditing profile '{profile.get('name')}' (id: {profile.get('id')})")

    new_name = input(f"New name (blank to keep '{profile.get('name')}'): ").strip()
    new_desc = input("New description (blank to keep current): ").strip()
    new_lang = input(f"New language (blank to keep '{profile.get('language', 'it')}'): ").strip()
    new_industry = input(f"New industry (blank to keep '{profile.get('industry', '')}'): ").strip()

    if new_name:
        profile["name"] = new_name
    if new_desc:
        profile["description"] = new_desc
    if new_lang:
        profile["language"] = new_lang
    if new_industry:
        profile["industry"] = new_industry

    path = _profile_path(profile["id"])
    with path.open("w", encoding="utf-8") as f:
        json.dump(profile, f, ensure_ascii=False, indent=2)

    print("[OK] Profile updated.")
    print("\nUpdated profile:")
    _print_profile_summary(profile)
