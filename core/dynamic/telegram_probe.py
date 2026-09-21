"""
Telegram Bot OSINT — attacker attribution via the Telegram Bot API.

Many banking trojans exfiltrate stolen data straight to a Telegram bot instead
of (or alongside) Firebase. The bot token + chat ID recovered by static
analysis (behavior_detector's C2 classifier, or pulled by hand from a report)
can be queried with standard, read-only Bot API calls — no special access
needed, this is public API surface:

  getMe          -> the bot's own identity (username, name)
  getChat        -> the target chat's identity. For a private chat this is
                    often the attacker's own Telegram account: first_name,
                    last_name, username — direct human attribution.
  getWebhookInfo -> if the attacker uses a webhook instead of polling, this
                    reveals the webhook URL — frequently a second piece of
                    C2 infrastructure (a VPS/panel) not visible anywhere else.

All three are safe: no data is sent, modified, or deleted. A revoked/dead
token (common — Telegram proactively disables bots reported for abuse, and
operators rotate them) returns 401 and is reported as such, not an error.
"""

import requests

_BASE = "https://api.telegram.org/bot{token}"
_TIMEOUT = 10


def _call(token: str, method: str, params: dict | None = None) -> dict:
    try:
        r = requests.get(f"{_BASE.format(token=token)}/{method}", params=params or {}, timeout=_TIMEOUT)
        return r.json()
    except (requests.RequestException, ValueError) as e:
        return {"ok": False, "error_code": 0, "description": f"{type(e).__name__}: {e}"}


def probe(token: str, chat_id: str | None = None) -> dict:
    """Returns {token_alive, bot, chat, webhook, attribution}. `attribution`
    is a best-effort human-readable summary of who/what was identified."""
    result = {"token_alive": False, "bot": None, "chat": None, "webhook": None,
             "attribution": None, "errors": []}

    me = _call(token, "getMe")
    if not me.get("ok"):
        result["errors"].append(
            f"Bot token invalid/revoked (getMe: {me.get('description', 'unknown error')})")
        return result

    result["token_alive"] = True
    result["bot"] = me.get("result")

    hook = _call(token, "getWebhookInfo")
    if hook.get("ok"):
        info = hook.get("result", {})
        result["webhook"] = info if info.get("url") else None

    if chat_id:
        chat = _call(token, "getChat", {"chat_id": chat_id})
        if chat.get("ok"):
            result["chat"] = chat.get("result")
        else:
            result["errors"].append(f"getChat failed: {chat.get('description', 'unknown')}")

    result["attribution"] = _summarise(result)
    return result


def _summarise(result: dict) -> str:
    parts = []
    bot = result.get("bot") or {}
    if bot:
        parts.append(f"Bot: @{bot.get('username', '?')} ({bot.get('first_name', '')})")
    chat = result.get("chat") or {}
    if chat:
        if chat.get("type") == "private":
            name = " ".join(filter(None, [chat.get("first_name"), chat.get("last_name")]))
            handle = f"@{chat['username']}" if chat.get("username") else "no public @handle"
            parts.append(f"Operator (private chat): {name or 'unnamed'} — {handle} — id {chat.get('id')}")
        else:
            parts.append(f"Target chat: {chat.get('title', '?')} ({chat.get('type')}, {chat.get('id')})")
    webhook = result.get("webhook")
    if webhook and webhook.get("url"):
        parts.append(f"Webhook (2nd C2 endpoint): {webhook['url']}")
    return " | ".join(parts) if parts else "Token valid but no further identity recovered."


if __name__ == "__main__":
    # ponytail self-check: an invalid token must report token_alive=False with a
    # clear reason, never raise.
    r = probe("000000:INVALID_TOKEN_FOR_TEST_1234567890123")
    assert r["token_alive"] is False and r["errors"], r
    print(f"OK — dead-token path handled cleanly: {r['errors'][0]}")
