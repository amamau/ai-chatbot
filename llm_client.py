import json
from typing import List, Dict, Tuple

import requests

from config import (
    LLM_API_KEY,
    LLM_API_BASE,
    LLM_MODEL,
    LLM_TEMPERATURE,
    LLM_TOP_P,
    LLM_MAX_TOKENS,
)
from prompts import BUSINESS_SYSTEM_PROMPT


class LLMError(Exception):
    pass


def _build_messages(
    profile: Dict,
    history: List[Tuple[str, str]],
    memory_excerpt: str,
    user_message: str,
) -> List[Dict[str, str]]:
    profile_info = (
        "Active business profile:\n"
        f"- Name: {profile.get('name')}\n"
        f"- Industry: {profile.get('industry')}\n"
        f"- Description: {profile.get('description')}\n"
        f"- Preferred language: {profile.get('language', 'it')}\n"
        "\n"
    )

    if memory_excerpt:
        profile_info += "Long-term memory for this profile:\n"
        profile_info += memory_excerpt
    else:
        profile_info += "No long-term memory for this profile yet.\n"

    messages: List[Dict[str, str]] = [
        {"role": "system", "content": BUSINESS_SYSTEM_PROMPT},
        {"role": "system", "content": profile_info},
    ]

    # short-term history
    for user, assistant in history[-6:]:
        messages.append({"role": "user", "content": user})
        messages.append({"role": "assistant", "content": assistant})

    messages.append({"role": "user", "content": user_message})
    return messages


def _parse_json_response(text: str) -> Dict:
    cleaned = text.strip()
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        raise LLMError(f"Model did not return JSON. Raw content: {cleaned[:200]}")
    json_str = cleaned[start : end + 1]
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError as exc:
        raise LLMError(f"Invalid JSON from model: {exc} | Raw: {cleaned[:200]}")
    return data


def call_llm_raw(messages: List[Dict[str, str]]) -> str:
    if not LLM_API_KEY:
        raise LLMError("LLM_API_KEY is not set. Configure it in .env.")

    url = LLM_API_BASE.rstrip("/") + "/chat/completions"

    payload: Dict = {
        "model": LLM_MODEL,
        "messages": messages,
        "temperature": LLM_TEMPERATURE,
        "top_p": LLM_TOP_P,
        "max_tokens": LLM_MAX_TOKENS,
    }

    headers = {
        "Authorization": f"Bearer {LLM_API_KEY}",
        "Content-Type": "application/json",
    }

    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
    except requests.RequestException as exc:
        raise LLMError(f"Network error calling LLM API: {exc}") from exc

    if resp.status_code != 200:
        raise LLMError(f"LLM API error {resp.status_code}: {resp.text[:200]}")

    try:
        data = resp.json()
    except ValueError as exc:
        raise LLMError(f"Invalid JSON body from LLM API: {exc}") from exc

    try:
        content = data["choices"][0]["message"]["content"]
    except Exception as exc:
        raise LLMError(f"Unexpected LLM API response format: {exc} | Raw: {data}") from exc

    return content


def generate_business_reply(
    profile: Dict,
    history: List[Tuple[str, str]],
    memory_excerpt: str,
    user_message: str,
) -> Dict:
    """
    Call the LLM and ALWAYS return a usable reply.

    Strategy:
    - Try to parse a JSON object with keys: reply, should_write_memory, memory_note.
    - If parsing fails (model ignored the JSON protocol), fall back to:
      reply = raw text from model
      should_write_memory = False
      memory_note = ""
    This way the CLI never crashes and the user always gets an answer.
    """
    messages = _build_messages(profile, history, memory_excerpt, user_message)
    raw = call_llm_raw(messages)
    cleaned = (raw or "").strip()

    # Fallback reply if everything goes wrong
    fallback = {
        "reply": cleaned if cleaned else "Nessuna risposta valida ricevuta dal modello.",
        "should_write_memory": False,
        "memory_note": "",
    }

    if not cleaned:
        # No content at all from the model
        return fallback

    # Try to extract a JSON object from the text
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        # Model did not follow JSON protocol: use fallback
        return fallback

    json_str = cleaned[start : end + 1]
    try:
        parsed = json.loads(json_str)
    except json.JSONDecodeError:
        # JSON present but invalid: use fallback
        return fallback

    reply = (parsed.get("reply") or "").strip()
    should_write = bool(parsed.get("should_write_memory", False))
    memory_note = (parsed.get("memory_note") or "").strip()

    if not reply:
        # Parsed JSON but empty reply: use fallback
        return fallback

    return {
        "reply": reply,
        "should_write_memory": bool(should_write and memory_note),
        "memory_note": memory_note if should_write and memory_note else "",
    }
