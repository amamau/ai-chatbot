import sys
import time
from typing import List, Tuple

from profiles import select_profile_interactive, edit_profile_interactive
from memory import (
    get_memory_excerpt,
    append_memory,
    load_full_memory,
    clear_memory,
)
from llm_client import generate_business_reply, LLMError
from config import TYPEWRITER_DELAY


def typewriter_print(text: str, delay: float) -> None:
    """
    Print text character by character with a small delay
    to simulate streaming output. If delay <= 0, print at once.
    """
    if delay <= 0:
        sys.stdout.write(text + "\n")
        sys.stdout.flush()
        return

    for ch in text:
        sys.stdout.write(ch)
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\n")
    sys.stdout.flush()


def print_help() -> None:
    print("\nAvailable commands:")
    print("  /help            Show this help")
    print("  /profile         Show current profile details")
    print("  /memory          Show full long-term memory for this profile")
    print("  /clear_memory    Delete long-term memory for this profile (with confirm)")
    print("  /speed X         Set typewriter delay in seconds (0 = no streaming)")
    print("  /exit            Exit chat and go back to main menu\n")


def run_chat_loop(profile: dict) -> None:
    type_delay = TYPEWRITER_DELAY

    print("\n=======================================")
    print(f" Business assistant for profile: {profile.get('name')}")
    print(" Type '/help' for commands. Type '/exit' to go back to the main menu.")
    print("=======================================\n")

    history: List[Tuple[str, str]] = []

    while True:
        try:
            user_message = input("You: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting chat.\n")
            break

        if not user_message:
            continue

        # commands
        if user_message.startswith("/"):
            parts = user_message.split()
            cmd = parts[0].lower()

            if cmd in {"/exit", "/quit"}:
                break
            elif cmd == "/help":
                print_help()
            elif cmd == "/profile":
                print("\nCurrent profile:")
                print(f"  id: {profile.get('id')}")
                print(f"  name: {profile.get('name')}")
                print(f"  language: {profile.get('language', 'it')}")
                print(f"  industry: {profile.get('industry', '')}")
                desc = profile.get("description", "")
                if desc:
                    print(f"  description: {desc}")
                print()
            elif cmd == "/memory":
                mem = load_full_memory(profile["id"])
                if not mem:
                    print("\n[Memory] No long-term memory for this profile yet.\n")
                else:
                    print("\n[Memory] Long-term memory for this profile:")
                    print(mem)
                    print()
            elif cmd == "/clear_memory":
                confirm = input(
                    "Type 'YES' to permanently delete long-term memory for this profile: "
                ).strip()
                if confirm == "YES":
                    clear_memory(profile["id"])
                    print("[Memory] Long-term memory cleared.\n")
                else:
                    print("[Memory] Clear memory cancelled.\n")
            elif cmd == "/speed":
                if len(parts) < 2:
                    print(f"Current speed: {type_delay} seconds per character.")
                    print("Usage: /speed 0.004  (0 disables streaming)\n")
                else:
                    try:
                        new_delay = float(parts[1])
                        type_delay = max(0.0, new_delay)
                        print(f"[UI] Typewriter delay set to {type_delay} seconds.\n")
                    except ValueError:
                        print("[UI] Invalid value. Example: /speed 0.004\n")
            else:
                print("Unknown command. Type /help for available commands.\n")

            continue

        memory_excerpt = get_memory_excerpt(profile["id"])
        try:
            result = generate_business_reply(profile, history, memory_excerpt, user_message)
        except LLMError as exc:
            print(f"\n[LLM ERROR] {exc}\n")
            continue

        reply = result["reply"]

        sys.stdout.write(f"\nAI ({profile.get('name')}): ")
        sys.stdout.flush()
        typewriter_print(reply, delay=type_delay)

        if result["should_write_memory"] and result["memory_note"]:
            append_memory(profile["id"], result["memory_note"])
            print("[Memory] Note saved for this profile.\n")

        history.append((user_message, reply))


def main_menu() -> None:
    while True:
        print("\n=== AMAMAU Business Assistant ===")
        print("1) Start assistant for a profile")
        print("2) Edit existing profile")
        print("3) Exit")
        choice = input("Choose an option: ").strip()

        if choice == "1":
            profile = select_profile_interactive()
            run_chat_loop(profile)
        elif choice == "2":
            edit_profile_interactive()
        elif choice == "3":
            print("Bye.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    main_menu()
