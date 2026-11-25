"""
Auto-creates the VaptFix Chat spaces for a newly-connected admin, using
the ADMIN'S OWN OAuth access_token (not the bot's service account) — see
users.views.GoogleChatOAuthUrlView's own comment on why chat.spaces.create
/ chat.memberships.app are requested as USER-authenticated scopes instead
of app authentication (no Workspace-admin approval needed this way).

Same 5-space set as the existing Slack channel set
(users.views.ensure_vaptfix_channels): one admin-dashboard space plus one
per security domain.
"""
import logging
import uuid

import requests

from . import space_store

logger = logging.getLogger(__name__)

_CHAT_API_BASE = "https://chat.googleapis.com/v1"

SPACE_DISPLAY_NAMES = [
    "vaptfix-admin-dashboard",
    "vaptfix-architectural-flaws-team",
    "vaptfix-configuration-management-team",
    "vaptfix-network-security-team",
    "vaptfix-patch-management-team",
]


def _create_space(access_token: str, display_name: str) -> dict:
    resp = requests.post(
        f"{_CHAT_API_BASE}/spaces",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"space": {"displayName": display_name, "spaceType": "SPACE"}, "requestId": str(uuid.uuid4())},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def _add_bot_to_space(access_token: str, space_name: str) -> dict:
    """member.name = "users/app" is the documented literal for "the Chat
    app making this call" — see spaces.members.create's own reference."""
    resp = requests.post(
        f"{_CHAT_API_BASE}/{space_name}/members",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        json={"member": {"name": "users/app", "type": "BOT"}},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()


def ensure_vaptfix_spaces(access_token: str, admin_id: str) -> list:
    """
    Idempotent — does nothing (just returns the existing names) if this
    admin already has spaces recorded, so a repeat Google Chat login
    doesn't spawn duplicate spaces. Returns the list of space resource
    names (created or already-existing).
    """
    existing = space_store.get_spaces_for_team(admin_id)
    if existing:
        return [doc["space_name"] for doc in existing]

    created = []
    for display_name in SPACE_DISPLAY_NAMES:
        try:
            space = _create_space(access_token, display_name)
            space_name = space.get("name")
            if not space_name:
                continue
        except Exception:
            logger.exception(f"[GoogleChatSpaceProvision] Failed to create space '{display_name}' for admin {admin_id}")
            continue

        try:
            _add_bot_to_space(access_token, space_name)
        except Exception:
            logger.exception(f"[GoogleChatSpaceProvision] Failed to add bot to {space_name}")

        space_store.save_space_reference(space_name, display_name, space.get("spaceType"))
        space_store.save_space_team(space_name, admin_id, display_name)
        created.append(space_name)

    return created
