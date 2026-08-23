"""
Stores Bot Framework "conversation references" — everything needed to
proactively message someone later (e.g. a notification), since Teams bots
can't just call an API with a user's ID the way Slack's bot_token lets us.
Captured every time we see an activity from that conversation.

Raw pymongo (not a Django model) — matches how the rest of this project's
high-volume/operational Mongo collections (nessus_reports,
vulnerability_cards, etc.) are handled, not the Django-admin-managed ones.
"""
import logging
import datetime

from vaptfix.mongo_client import MongoContext

logger = logging.getLogger(__name__)

COLLECTION = "teams_bot_conversations"


def save_conversation_reference(activity: dict):
    """
    Upserts the conversation reference from an incoming activity, keyed by
    (conversation_id, user_aad_object_id) — a user can have more than one
    conversation (personal chat vs a channel), so we keep them distinct
    rather than collapsing to one record per user.
    """
    conversation = activity.get("conversation") or {}
    from_user = activity.get("from") or {}
    channel_data = activity.get("channelData") or {}
    team = channel_data.get("team") or {}
    tenant = channel_data.get("tenant") or {}

    conversation_id = conversation.get("id")
    user_aad_id = from_user.get("aadObjectId") or from_user.get("id")
    if not conversation_id or not user_aad_id:
        return

    doc = {
        "conversation_id": conversation_id,
        "user_aad_id": user_aad_id,
        "user_name": from_user.get("name"),
        "service_url": activity.get("serviceUrl"),
        "channel_id": activity.get("channelId"),
        "team_id": team.get("id"),
        "team_aad_group_id": team.get("aadGroupId"),
        "tenant_id": tenant.get("id"),
        "conversation_type": conversation.get("conversationType"),
        "bot_id": (activity.get("recipient") or {}).get("id"),
        "updated_at": datetime.datetime.utcnow(),
    }

    try:
        with MongoContext() as db:
            db[COLLECTION].update_one(
                {"conversation_id": conversation_id, "user_aad_id": user_aad_id},
                {"$set": doc, "$setOnInsert": {"created_at": datetime.datetime.utcnow()}},
                upsert=True,
            )
    except Exception:
        logger.exception("[TeamsBot] Failed to save conversation reference")


def get_conversation_reference(user_aad_id: str, conversation_type: str = None):
    """Most-recently-seen conversation for this user (optionally filtered
    to a conversation_type — "personal" for 1:1 DM-equivalent, "channel")."""
    query = {"user_aad_id": user_aad_id}
    if conversation_type:
        query["conversation_type"] = conversation_type
    with MongoContext() as db:
        return db[COLLECTION].find_one(query, sort=[("updated_at", -1)])


TEAM_CHANNEL_COLLECTION = "teams_bot_team_channels"


def save_team_channel_reference(activity: dict):
    """
    Separate from save_conversation_reference — a team-scope conversationUpdate
    (bot added to the whole team) often carries no resolvable real-admin
    aadObjectId in `from` (it's the app-install identity), so we can't rely
    on the per-user store to later find "the admin dashboard channel for
    this team". Keyed by team_id alone, one row per team, always overwritten
    with the latest-seen reference — this is what proactive onboarding/nav
    messages into the admin-dashboard channel are sent through.
    """
    channel_data = activity.get("channelData") or {}
    team = channel_data.get("team") or {}
    conversation = activity.get("conversation") or {}
    # team.id is a conversation/thread id ("19:...@thread.tacv2"), NOT the
    # Graph/AAD Group id our User.ms_team_id stores — aadGroupId is the one
    # that actually matches it, so it's what this collection is keyed by.
    # team.id is kept too (as thread_id) purely for debugging.
    team_id = team.get("aadGroupId") or team.get("id")
    conversation_id = conversation.get("id")
    if not team_id or not conversation_id:
        return

    doc = {
        "team_id": team_id,
        "team_thread_id": team.get("id"),
        "conversation_id": conversation_id,
        "channel_id": (channel_data.get("channel") or {}).get("id") or conversation_id,
        "service_url": activity.get("serviceUrl"),
        "tenant_id": (channel_data.get("tenant") or {}).get("id"),
        "bot_id": (activity.get("recipient") or {}).get("id"),
        "updated_at": datetime.datetime.utcnow(),
    }
    try:
        with MongoContext() as db:
            db[TEAM_CHANNEL_COLLECTION].update_one(
                {"team_id": team_id},
                {"$set": doc, "$setOnInsert": {"created_at": datetime.datetime.utcnow()}},
                upsert=True,
            )
    except Exception:
        logger.exception("[TeamsBot] Failed to save team channel reference")


def get_team_channel_reference(team_id: str):
    """The admin-dashboard-channel conversation reference for a team_id —
    used to proactively post welcome/risk-criteria/navbar messages."""
    if not team_id:
        return None
    with MongoContext() as db:
        return db[TEAM_CHANNEL_COLLECTION].find_one({"team_id": team_id})


def set_active_message_id(team_id: str, message_id):
    """
    Tracks the id of the single "live" onboarding/dashboard card currently
    posted in this team's admin-dashboard channel — so the next proactive
    post (welcome -> risk-criteria -> navbar transitions) can delete this
    one first instead of leaving it behind as an orphaned extra card.
    """
    if not team_id:
        return
    with MongoContext() as db:
        db[TEAM_CHANNEL_COLLECTION].update_one(
            {"team_id": team_id},
            {"$set": {"active_message_id": message_id}},
        )


def save_admin_dashboard_channel_reference(team_id: str, channel_id: str):
    """
    Points the stored "admin dashboard channel" conversation reference at
    a newly created STANDARD channel (see users.views.ADMIN_DASHBOARD_CHANNEL_NAME),
    without waiting for any conversationUpdate webhook — a standard
    channel is already covered by the team-scope bot install (only a
    genuinely PRIVATE channel needs its own explicit per-channel install
    event, which is why this whole approach exists: that path wasn't
    reliable). A Teams channel's Bot Framework conversation id IS its
    Graph channel id (both are the same "19:...@thread.tacv2" string), so
    this just reuses whatever service_url/tenant_id this team already has
    on file (from the original team-scope install/first conversationUpdate)
    and repoints conversation_id + channel_id at the new channel.
    Returns True if it could (i.e. a prior reference already existed to
    borrow service_url from), False otherwise (safe no-op — proactive
    posts just keep going wherever they were going before).
    """
    if not team_id or not channel_id:
        return False
    with MongoContext() as db:
        existing = db[TEAM_CHANNEL_COLLECTION].find_one({"team_id": team_id})
        if not existing or not existing.get("service_url"):
            logger.warning(f"[TeamsBot] Cannot point admin-dashboard channel at {channel_id} — no existing team reference for team_id={team_id}")
            return False
        if existing.get("conversation_id") == channel_id:
            return True  # already pointed here
        db[TEAM_CHANNEL_COLLECTION].update_one(
            {"team_id": team_id},
            {"$set": {
                "conversation_id": channel_id,
                "channel_id": channel_id,
                "updated_at": datetime.datetime.utcnow(),
                # The previously tracked "live card" id belongs to whatever
                # conversation we were posting into before (e.g. General) —
                # clear it so the next post doesn't try to delete a message
                # id that never existed in the new conversation.
                "active_message_id": None,
            }},
        )
        logger.info(f"[TeamsBot] Admin-dashboard channel reference for team_id={team_id} repointed to channel_id={channel_id}")
        return True


def resolve_team_id_from_thread_id(thread_id: str):
    """
    Confirmed via real production data: Bot Framework only includes
    channelData.team.aadGroupId (the Graph/AAD Group id — the one that
    matches User.ms_team_id) on some activity types (conversationUpdate,
    seen when the bot is first added). On plain "message" activities (a
    typed message, an Action.Submit card click) team.aadGroupId comes back
    None — only team.id (the "19:...@thread.tacv2" conversation-thread
    form) is present. This maps that thread id back to the real GUID,
    using whatever the last conversationUpdate for that team recorded —
    so admin resolution still works on every message, not just the first.
    """
    if not thread_id:
        return None
    with MongoContext() as db:
        doc = db[TEAM_CHANNEL_COLLECTION].find_one({"team_thread_id": thread_id})
        return doc.get("team_id") if doc else None


def get_conversation_reference_by_email(email: str, conversation_type: str = None):
    """
    Look up via the admin/UserDetail's stored aad object id (see
    users.models.User.ms_teams_object_id / UserDetail.ms_teams_member_id —
    whichever field ends up holding it) rather than the raw id directly.
    Left as a thin wrapper so callers don't need to know that indirection.
    """
    from django.contrib.auth import get_user_model
    User = get_user_model()
    user = User.objects.filter(email__iexact=email).first()
    aad_id = getattr(user, "ms_teams_object_id", None) if user else None
    if not aad_id:
        from users_details.models import UserDetail
        ud = UserDetail.objects.filter(email__iexact=email).first()
        aad_id = getattr(ud, "ms_teams_member_id", None) if ud else None
    if not aad_id:
        return None
    return get_conversation_reference(aad_id, conversation_type)
