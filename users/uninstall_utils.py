"""
Deferred confirmation for "delete all my VaptFix data" triggered from the
Slack side (app_uninstalled/tokens_revoked).

Slack's own "Remove App" screen can't show a VaptFix confirmation popup —
by the time VaptFix's SlackEventsView receives the event, the customer has
already removed the app on Slack's side. To still guarantee "only delete
everything after an explicit yes" for that path (same guarantee the
website's own confirm-modal gives directly), the Slack-side event only
does the safe, reversible credential cleanup immediately (see
_disconnect_slack_for_admin in users/views.py) and emails the admin a
one-time confirmation link instead. Nothing is deleted until they click it.

Same token-in-cache pattern as users/invite_utils.py's report-claim magic
links — no new DB table needed, expiry handled by the cache backend.
"""
import logging
import secrets

from django.core.cache import cache

logger = logging.getLogger(__name__)

# Deliberately much longer than invite_utils' 15-minute signup link — this
# is asking a human to notice an email and make a permanent-deletion
# decision, not complete an in-progress signup. 48 hours.
UNINSTALL_CONFIRM_TTL_SECONDS = 48 * 60 * 60
_CACHE_PREFIX = "slack_uninstall_confirm_"


def _cache_key(token: str) -> str:
    return f"{_CACHE_PREFIX}{token}"


def create_uninstall_confirmation(admin_id: str) -> str:
    """Generate a fresh one-time token for this admin's pending deletion."""
    token = secrets.token_urlsafe(32)
    cache.set(_cache_key(token), {"admin_id": str(admin_id)}, timeout=UNINSTALL_CONFIRM_TTL_SECONDS)
    return token


def consume_uninstall_confirmation(token: str):
    """
    Read AND invalidate in one step — a deletion-confirmation link must
    only ever work once (unlike peek_invite's read-only check, there's no
    separate "commit" step later that needs the token to still be valid).
    Returns the admin_id, or None if the token is missing/expired/already used.
    """
    if not token:
        return None
    key = _cache_key(token)
    data = cache.get(key)
    if not data:
        return None
    cache.delete(key)
    return data.get("admin_id")
