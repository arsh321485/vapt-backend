"""
Outbound side of the bot — getting an access token to call the Bot
Framework Connector API, and sending messages/cards back into Teams.
Mirrors the Slack integration's hand-built HTTP calls (no botbuilder SDK).
"""
import logging
import time

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

# Bot Framework's OWN token authority — fixed, NOT our Azure tenant. Every
# bot (regardless of which tenant its app registration lives in) gets its
# outbound Connector API token from this same endpoint.
_TOKEN_URL = "https://login.microsoftonline.com/botframework.com/oauth2/v2.0/token"
_TOKEN_SCOPE = "https://api.botframework.com/.default"

_cached_token = None
_cached_token_expires_at = 0


def _get_bot_access_token() -> str:
    """Client-credentials token for calling the Connector API — cached in
    -process until shortly before it expires (tokens are normally ~1hr)."""
    global _cached_token, _cached_token_expires_at
    if _cached_token and time.time() < _cached_token_expires_at - 60:
        return _cached_token

    resp = requests.post(
        _TOKEN_URL,
        data={
            "grant_type": "client_credentials",
            "client_id": settings.MICROSOFT_CLIENT_ID,
            "client_secret": settings.MICROSOFT_CLIENT_SECRET,
            "scope": _TOKEN_SCOPE,
        },
        timeout=15,
    )
    resp.raise_for_status()
    data = resp.json()
    _cached_token = data["access_token"]
    _cached_token_expires_at = time.time() + int(data.get("expires_in", 3600))
    return _cached_token


def _connector_headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_bot_access_token()}",
        "Content-Type": "application/json",
    }


def reply_to_activity(service_url: str, conversation_id: str, activity_id: str, activity: dict):
    """
    Reply within the SAME turn as an incoming activity (e.g. answering a
    command, acknowledging a card action). `activity` is a Bot Framework
    Activity dict — for a plain text reply: {"type": "message", "text": "..."};
    for a card: {"type": "message", "attachments": [adaptive_card_attachment(...)]}.
    """
    url = f"{service_url.rstrip('/')}/v3/conversations/{conversation_id}/activities/{activity_id}"
    resp = requests.post(url, json=activity, headers=_connector_headers(), timeout=15)
    if resp.status_code >= 300:
        logger.warning(f"[TeamsBot] reply_to_activity failed ({resp.status_code}): {resp.text[:500]}")
    return resp


def send_activity(service_url: str, conversation_id: str, activity: dict):
    """
    Send a NEW message into an existing conversation (not a reply to a
    specific activity) — used for proactive messages (e.g. notifying an
    admin) outside the turn that created the conversation.
    """
    url = f"{service_url.rstrip('/')}/v3/conversations/{conversation_id}/activities"
    resp = requests.post(url, json=activity, headers=_connector_headers(), timeout=15)
    if resp.status_code >= 300:
        logger.warning(f"[TeamsBot] send_activity failed ({resp.status_code}): {resp.text[:500]}")
    return resp


def adaptive_card_attachment(card: dict) -> dict:
    """Wraps a raw Adaptive Card JSON body as a Bot Framework attachment."""
    return {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": card,
    }


def text_message(text: str) -> dict:
    return {"type": "message", "text": text}


def card_message(card: dict) -> dict:
    return {"type": "message", "attachments": [adaptive_card_attachment(card)]}
