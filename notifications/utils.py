import logging
from datetime import datetime
from bson import ObjectId
import requests

logger = logging.getLogger(__name__)

COLLECTION = "notifications_notification"

# Kept as a local constant (not imported from users.views.SlackSlashCommandView)
# to avoid a circular import — userregister/views.py already imports
# create_notification from this module.
_TEAM_CHANNELS = {
    "Patch Management":         "vaptfix-patch-management-team",
    "Configuration Management": "vaptfix-configuration-management-team",
    "Network Security":         "vaptfix-network-security-team",
    "Architectural Flaws":      "vaptfix-architectural-flaws-team",
}
_ADMIN_CHANNEL = "vaptfix-admin-dashboard"


def _slack_get(method, token, params=None):
    try:
        resp = requests.get(
            f"https://slack.com/api/{method}",
            headers={"Authorization": f"Bearer {token}"},
            params=params, timeout=10,
        )
        return resp.json()
    except Exception:
        logger.exception("[SlackNotify] GET %s failed", method)
        return {}


def _slack_post(method, token, json_body=None):
    try:
        resp = requests.post(
            f"https://slack.com/api/{method}",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=json_body, timeout=10,
        )
        return resp.json()
    except Exception:
        logger.exception("[SlackNotify] POST %s failed", method)
        return {}


def _slack_channel_id_by_name(token, channel_name):
    data = _slack_get("conversations.list", token, params={"types": "public_channel,private_channel", "limit": 1000})
    for ch in data.get("channels", []):
        if ch.get("name") == channel_name:
            return ch.get("id")
    return None


_SEVERITY_STYLE = (
    ("critical", "🔴", "#e01e5a"),
    ("high",     "🟠", "#e8912d"),
    ("medium",   "🟡", "#ecb22e"),
    ("low",      "🟢", "#2eb67d"),
)


def _build_notification_blocks(title, message):
    """
    Card-style message matching the demo mockup: a colored vertical bar
    (via Slack's `attachments` + `color`, the same mechanism GitHub/Jira's
    own Slack integrations use for this exact look) wrapping a header +
    detail line, instead of a single plain-text chat line. Picks the
    severity dot/color from the title (e.g. "[Critical] ...") when present.
    """
    icon, color = next(((e, c) for key, e, c in _SEVERITY_STYLE if key in title.lower()), ("🔔", "#1264a3"))
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{icon} {title}"[:150], "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": message}},
    ]
    return blocks, f"{icon} {title}", color


def _slack_dm(token, slack_user_id, blocks, fallback_text, color=None):
    """DM a specific Slack user — this is what triggers their personal
    Slack push notification (desktop/mobile), matching the website's bell."""
    if not slack_user_id:
        return
    opened = _slack_post("conversations.open", token, {"users": slack_user_id})
    channel_id = (opened.get("channel") or {}).get("id")
    if not channel_id:
        logger.warning("[SlackNotify] conversations.open failed for user=%s: %s", slack_user_id, opened.get("error"))
        return
    payload = {"channel": channel_id, "text": fallback_text}
    if color:
        payload["attachments"] = [{"color": color, "blocks": blocks}]
    else:
        payload["blocks"] = blocks
    resp = _slack_post("chat.postMessage", token, payload)
    if not resp.get("ok"):
        logger.warning("[SlackNotify] DM chat.postMessage failed: %s", resp.get("error"))


def _slack_channel_post(token, channel_name, blocks, fallback_text, color=None):
    channel_id = _slack_channel_id_by_name(token, channel_name)
    if not channel_id:
        logger.warning("[SlackNotify] channel not found: %s", channel_name)
        return
    payload = {"channel": channel_id, "text": fallback_text}
    if color:
        payload["attachments"] = [{"color": color, "blocks": blocks}]
    else:
        payload["blocks"] = blocks
    resp = _slack_post("chat.postMessage", token, payload)
    if not resp.get("ok"):
        logger.warning("[SlackNotify] channel chat.postMessage failed for %s: %s", channel_name, resp.get("error"))


def _send_slack_notification(admin_id, recipient_type, title, message, metadata, recipient_email):
    """
    Best-effort mirror of every website in-app notification into Slack:
    DMs the specific resolved recipient AND posts into that event's
    relevant team/admin channel. Never raises — a Slack-side failure must
    never break the underlying notification record that already exists
    regardless (the website bell doesn't depend on this).
    """
    try:
        from django.contrib.auth import get_user_model
        from users_details.models import UserDetail

        User = get_user_model()
        admin = User.objects.filter(id=admin_id).first()
        if not admin or not getattr(admin, "slack_bot_token", None):
            return
        token = admin.slack_bot_token
        blocks, fallback_text, color = _build_notification_blocks(title, message)

        if recipient_email:
            # A specific person — either the admin themselves or one team member.
            if recipient_email.strip().lower() == (admin.email or "").strip().lower():
                _slack_dm(token, getattr(admin, "slack_user_id", None), blocks, fallback_text, color)
                _slack_channel_post(token, _ADMIN_CHANNEL, blocks, fallback_text, color)
                return
            member = UserDetail.objects.filter(admin=admin, email=recipient_email).first()
            if member:
                _slack_dm(token, getattr(member, "slack_member_id", None), blocks, fallback_text, color)
                team_name = (metadata or {}).get("assigned_team") or member.team_name or next(iter(member.Member_role or []), None)
                channel_name = _TEAM_CHANNELS.get(team_name)
                if channel_name:
                    _slack_channel_post(token, channel_name, blocks, fallback_text, color)
            return

        if recipient_type == "admin":
            _slack_dm(token, getattr(admin, "slack_user_id", None), blocks, fallback_text, color)
            _slack_channel_post(token, _ADMIN_CHANNEL, blocks, fallback_text, color)
            return

        # Broadcast to every user under this admin — DM each one who has a
        # linked Slack account. Only also post into a team channel when
        # metadata pins this to one specific team, to avoid spamming all 4
        # team channels with something that isn't really team-specific.
        for member in UserDetail.objects.filter(admin=admin):
            _slack_dm(token, getattr(member, "slack_member_id", None), blocks, fallback_text, color)
        pinned_channel = _TEAM_CHANNELS.get((metadata or {}).get("assigned_team"))
        if pinned_channel:
            _slack_channel_post(token, pinned_channel, blocks, fallback_text, color)
    except Exception:
        logger.exception("[SlackNotify] _send_slack_notification failed")


def create_notification(admin, recipient_type, notif_type, title, message,
                        metadata=None, recipient_email=''):
    """
    admin  – User instance OR admin_id string (both accepted)
    recipient_email – user's email; '' = broadcast to all users of this admin
    Uses raw pymongo to avoid djongo ORM bugs.
    """
    try:
        from vaptfix.mongo_client import MongoContext
        admin_id = admin if isinstance(admin, str) else str(admin.id)
        print(f"[NOTIF] create_notification: type={notif_type} | recipient={recipient_type} | admin_id={admin_id} | email={recipient_email}", flush=True)
        doc = {
            "_id":             ObjectId(),
            "admin_id":        admin_id,
            "recipient_email": recipient_email or '',
            "recipient_type":  recipient_type,
            "notif_type":      notif_type,
            "title":           title,
            "message":         message,
            "metadata":        metadata or {},
            "is_read":         False,
            "created_at":      datetime.utcnow(),
        }
        with MongoContext() as db:
            db[COLLECTION].insert_one(doc)
        _send_slack_notification(admin_id, recipient_type, title, message, metadata, recipient_email)
    except Exception as exc:
        logger.error("create_notification failed [%s | %s]: %s", notif_type, recipient_type, exc)
