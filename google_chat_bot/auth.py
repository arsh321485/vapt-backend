"""
Verifies that an incoming POST to our bot webhook genuinely came from
Google Chat — not just anyone who found the URL. Hand-rolled the same
way the Slack/Teams integrations validate their own requests, rather
than pulling in the full Google API client just for this one check.

Reference: https://developers.google.com/workspace/chat/authenticate-authorize-chat-app#verify_that_requests_are_coming_from_google_chat
"""
import logging

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token
from django.conf import settings

logger = logging.getLogger(__name__)

# Fixed, well-known issuer — Chat's own service-account identity, not
# tenant/workspace-specific (mirrors teams_bot.auth's fixed Bot Framework
# issuer, "https://api.botframework.com").
_EXPECTED_ISSUER = "chat@system.gserviceaccount.com"

_request_adapter = None


def _get_request_adapter():
    global _request_adapter
    if _request_adapter is None:
        _request_adapter = google_requests.Request()
    return _request_adapter


class BotAuthError(Exception):
    pass


def verify_chat_request(auth_header: str) -> dict:
    """
    Validates the bearer token Google Chat attaches to every event POST.
    Raises BotAuthError on anything invalid; returns the decoded token
    claims on success.

    Checks: signature (against Google's published certs, fetched by
    google-auth), issuer (must be Chat's own service-account identity),
    and audience (must be OUR Chat app's project number —
    settings.GOOGLE_CHAT_PROJECT_NUMBER).
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise BotAuthError("Missing or malformed Authorization header")

    token = auth_header[len("Bearer "):].strip()

    try:
        claims = id_token.verify_oauth2_token(token, _get_request_adapter())
    except Exception as e:
        raise BotAuthError(f"Token validation failed: {e}")

    if claims.get("iss") != _EXPECTED_ISSUER:
        raise BotAuthError(f"Unexpected issuer: {claims.get('iss')}")

    expected_audience = str(settings.GOOGLE_CHAT_PROJECT_NUMBER)
    if not expected_audience or claims.get("aud") != expected_audience:
        raise BotAuthError(f"Unexpected audience: {claims.get('aud')}")

    return claims
