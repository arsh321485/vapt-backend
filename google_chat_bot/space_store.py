"""
Stores the Space <-> VaptFix team mapping and the id of whichever card
is currently "live" in a space, so proactive messages (status updates,
tab re-renders) know where to post/update/delete. Google Chat addresses
a space directly by its resource name ("spaces/AAAAAAAAAA") — unlike
Bot Framework, there's no separate "conversation reference" that needs
capturing from an incoming activity first (see
teams_bot.conversation_store's docstring for why Teams needs that extra
step and this doesn't).

Raw pymongo (not a Django model) — matches how
teams_bot/conversation_store.py and the rest of this project's high-
volume/operational Mongo collections are handled, not the
Django-admin-managed ones.
"""
import logging
import datetime

from vaptfix.mongo_client import MongoContext

logger = logging.getLogger(__name__)

COLLECTION = "google_chat_bot_spaces"


def save_space_reference(space_name: str, display_name: str = None, space_type: str = None):
    """Upserts what we know about a space every time we see an event
    from it — same role as teams_bot.conversation_store.save_team_channel_reference."""
    if not space_name:
        return
    doc = {
        "space_name": space_name,
        "display_name": display_name,
        "space_type": space_type,
        "updated_at": datetime.datetime.utcnow(),
    }
    try:
        with MongoContext() as db:
            db[COLLECTION].update_one(
                {"space_name": space_name},
                {"$set": doc, "$setOnInsert": {"created_at": datetime.datetime.utcnow()}},
                upsert=True,
            )
    except Exception:
        logger.exception("[GoogleChatBot] Failed to save space reference")


def get_space_reference(space_name: str):
    if not space_name:
        return None
    with MongoContext() as db:
        return db[COLLECTION].find_one({"space_name": space_name})


def save_space_team(space_name: str, team_id: str, team_name: str = None):
    """Maps a space to the admin's VaptFix team_id (and optionally the
    canonical sub-team name — "Patch Management" etc, the same role as
    teams_bot_sub_channels for Teams' 4 per-team channels) once the
    onboarding flow has decided which team this space represents."""
    if not space_name or not team_id:
        return
    with MongoContext() as db:
        db[COLLECTION].update_one(
            {"space_name": space_name},
            {"$set": {"team_id": team_id, "team_name": team_name, "updated_at": datetime.datetime.utcnow()}},
        )


def get_team_for_space(space_name: str):
    """Returns (team_id, team_name) for a space, or (None, None) if this
    space was never mapped yet."""
    doc = get_space_reference(space_name)
    if not doc:
        return (None, None)
    return (doc.get("team_id"), doc.get("team_name"))


def set_active_message_name(space_name: str, message_name: str):
    """Tracks the resource name of the single "live" card currently
    posted in this space, so the next proactive post can delete this one
    first instead of leaving an orphaned extra card behind — same
    single-live-card pattern as
    teams_bot.conversation_store.set_active_message_id."""
    if not space_name:
        return
    with MongoContext() as db:
        db[COLLECTION].update_one(
            {"space_name": space_name},
            {"$set": {"active_message_name": message_name}},
        )


def get_active_message_name(space_name: str):
    doc = get_space_reference(space_name)
    return doc.get("active_message_name") if doc else None
