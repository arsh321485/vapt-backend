"""
Verifies that an incoming POST to our bot webhook genuinely came from the
Bot Framework Connector service (Microsoft's channel service) — not just
anyone who found the URL. Hand-rolled the same way the Slack integration
validates its own requests, rather than pulling in the full (async-only)
botbuilder-core SDK just for this one check.

Reference: https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-connector-authentication
"""
import logging
import time

import jwt
from jwt import PyJWKClient
from django.conf import settings

logger = logging.getLogger(__name__)

# Fixed, well-known endpoints — not tenant-specific (Bot Framework's own
# identity authority, separate from our Azure AD tenant).
_OPENID_METADATA_URL = "https://login.botframework.com/v1/.well-known/openidconfiguration"
_JWKS_URL = "https://login.botframework.com/v1/.well-known/keys"
_EXPECTED_ISSUER = "https://api.botframework.com"

_jwk_client = None


def _get_jwk_client() -> PyJWKClient:
    global _jwk_client
    if _jwk_client is None:
        _jwk_client = PyJWKClient(_JWKS_URL)
    return _jwk_client


class BotAuthError(Exception):
    pass


def verify_bot_framework_request(auth_header: str) -> dict:
    """
    Validates the Authorization header Bot Framework attaches to every
    Activity POST. Raises BotAuthError on anything invalid; returns the
    decoded token claims on success.

    Checks: signature (against Microsoft's published JWKS), issuer,
    audience (must be OUR bot's App ID — settings.MICROSOFT_CLIENT_ID,
    since we're using the existing app registration as the bot identity),
    and expiry.
    """
    if not auth_header or not auth_header.startswith("Bearer "):
        raise BotAuthError("Missing or malformed Authorization header")

    token = auth_header[len("Bearer "):].strip()

    try:
        signing_key = _get_jwk_client().get_signing_key_from_jwt(token)
    except Exception as e:
        raise BotAuthError(f"Could not resolve signing key: {e}")

    try:
        claims = jwt.decode(
            token,
            signing_key.key,
            algorithms=["RS256"],
            audience=settings.MICROSOFT_CLIENT_ID,
            issuer=_EXPECTED_ISSUER,
            options={"require": ["exp", "iss", "aud"]},
        )
    except jwt.PyJWTError as e:
        raise BotAuthError(f"Token validation failed: {e}")

    return claims
