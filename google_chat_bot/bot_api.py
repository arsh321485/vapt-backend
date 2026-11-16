"""
Outbound side of the bot — getting an access token to call the Google
Chat API, and sending/updating/deleting messages. Mirrors the Slack/
Teams integrations' hand-built HTTP calls (no google-api-python-client,
just google-auth for the service-account token + requests for the
actual calls).
"""
import logging

import requests
from google.oauth2 import service_account
from google.auth.transport.requests import Request as GoogleAuthRequest
from django.conf import settings

logger = logging.getLogger(__name__)

_CHAT_API_BASE = "https://chat.googleapis.com/v1"
_SCOPES = ["https://www.googleapis.com/auth/chat.bot"]

_cached_credentials = None


def _get_credentials():
    """Service-account credentials for calling the Chat API — cached
    in-process and refreshed on demand (google-auth handles expiry)."""
    global _cached_credentials
    if _cached_credentials is None:
        _cached_credentials = service_account.Credentials.from_service_account_file(
            settings.GOOGLE_CHAT_SERVICE_ACCOUNT_FILE, scopes=_SCOPES,
        )
    if not _cached_credentials.valid:
        _cached_credentials.refresh(GoogleAuthRequest())
    return _cached_credentials


def _chat_headers() -> dict:
    return {
        "Authorization": f"Bearer {_get_credentials().token}",
        "Content-Type": "application/json",
    }


def send_message(space_name: str, message: dict, thread_key: str = None):
    """
    Posts a NEW message into a space (space_name like "spaces/AAAAAAAAAA").
    `message` is a Chat Message resource dict — for plain text:
    {"text": "..."}; for a card: {"cardsV2": [...]} (see card_message).
    """
    url = f"{_CHAT_API_BASE}/{space_name}/messages"
    params = {}
    if thread_key:
        params["messageReplyOption"] = "REPLY_MESSAGE_OR_FAIL"
    try:
        resp = requests.post(url, json=message, params=params, headers=_chat_headers(), timeout=15)
    except Exception:
        logger.exception("[GoogleChatBot] send_message request failed")
        return None
    if resp.status_code >= 300:
        logger.warning(f"[GoogleChatBot] send_message failed ({resp.status_code}): {resp.text[:500]}")
    return resp


def update_message(message_name: str, message: dict):
    """
    Edits an EXISTING message in place (Chat's PATCH — the direct
    equivalent of Slack's chat.update / Teams' update_activity) instead
    of posting a new one. `message_name` is like
    "spaces/AAAAAAAAAA/messages/BBBBBBBBBB".
    """
    url = f"{_CHAT_API_BASE}/{message_name}"
    params = {"updateMask": "cardsV2,text"}
    try:
        resp = requests.patch(url, json=message, params=params, headers=_chat_headers(), timeout=15)
    except Exception:
        logger.exception("[GoogleChatBot] update_message request failed")
        return None
    if resp.status_code >= 300:
        logger.warning(f"[GoogleChatBot] update_message failed ({resp.status_code}): {resp.text[:500]}")
    return resp


def delete_message(message_name: str):
    """Deletes a previously-sent bot message — used to remove the old
    onboarding/dashboard card right before posting a new one, the same
    single-live-card pattern teams_bot/users already use."""
    if not message_name:
        return None
    url = f"{_CHAT_API_BASE}/{message_name}"
    try:
        resp = requests.delete(url, headers=_chat_headers(), timeout=15)
        if resp.status_code >= 300:
            logger.info(f"[GoogleChatBot] delete_message ({message_name}) -> {resp.status_code} (likely already gone/too old, harmless)")
        return resp
    except Exception:
        logger.exception(f"[GoogleChatBot] delete_message request failed for {message_name}")
        return None


def text_message(text: str) -> dict:
    return {"text": text}


def card_message(card_id: str, card: dict) -> dict:
    """Wraps a raw Cards v2 card body as a Chat Message resource."""
    return {"cardsV2": [{"cardId": card_id, "card": card}]}
