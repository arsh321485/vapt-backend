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

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

_STATUS_DOT = {"pending": "🟡", "success": "🟢", "error": "🔴", "info": "🔵"}


def _build_notification_blocks(title, message):
    """
    Generic fallback card (header + section) for any notif_type that
    doesn't have a dedicated rich template below — a colored vertical bar
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


def _fact_blocks(facts):
    """
    facts: list of (label, value, full_width) tuples. Renders short facts
    packed 2-per-row via a section's `fields` array (Slack's native
    equivalent of the design's 2-column facts grid), and full-width facts
    as their own standalone section — matching the mockup's `.fact` vs
    `.fact.full` distinction. Facts with an empty value are skipped.
    """
    blocks = []
    pending = []

    def flush():
        if pending:
            blocks.append({"type": "section", "fields": list(pending)})
            pending.clear()

    for label, value, full in facts:
        if not value:
            continue
        if full:
            flush()
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{label}*\n{value}"}})
        else:
            pending.append({"type": "mrkdwn", "text": f"*{label}*\n{value}"})
    flush()
    return blocks


def _rich_card_blocks(icon, title, status_key, status_text, body_text, facts, footer_parts):
    """Matches the `.attachment` mockup style: title, colored status line,
    optional body sentence, facts grid, footer."""
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{icon} {title}"[:150], "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"{_STATUS_DOT.get(status_key, '⚪')} {status_text}"}},
    ]
    if body_text:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": body_text}})
    blocks.extend(_fact_blocks(facts))
    if footer_parts:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "  •  ".join(footer_parts)}]})
    return blocks


def _action_card_blocks(icon, title, pills, facts, hint_commands):
    """Matches the `.action-card` mockup style: title, pill row
    (vuln/severity/asset), facts grid, admin-commands hint."""
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"{icon} {title}"[:150], "emoji": True}},
    ]
    if pills:
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "   ".join(pills)}})
    blocks.extend(_fact_blocks(facts))
    if hint_commands:
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"*Admin commands*\n{hint_commands}"}]})
    return blocks


def _sev_pill(severity):
    sev = (severity or "").strip().lower()
    return f"{_SEV_EMOJI.get(sev, '⚪')} {sev.title()}" if sev else ""


def _card_extension_requested(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vulnerability_name", "")
    asset = meta.get("asset", "")
    days = meta.get("requested_days") or meta.get("extension_days")
    reason = meta.get("reason", "")
    requested_by = meta.get("requested_by", "")
    team = meta.get("assigned_team", "")
    pills = [p for p in (f"`{vuln}`" if vuln else "", _sev_pill(meta.get("severity")), f"`{asset}`" if asset else "") if p]
    facts = [
        ("Requested", f"+{days} day(s)" if days else "", False),
        ("Reason", reason, False),
        ("Requested by", requested_by, True),
    ]
    title_text = f"Timeline Extension Request — {team}" if team else "Timeline Extension Request"
    hint = "Use `/request` to review, then `/approve [request-id]` or `/reject [request-id]`."
    blocks = _action_card_blocks("⏳", title_text, pills, facts, hint)
    return blocks, f"⏳ {title_text}", "#1264a3"


def _card_extension_approved(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vulnerability_name", "")
    asset = meta.get("asset", "")
    days = meta.get("extension_days") or meta.get("requested_days")
    facts = [
        ("Vulnerability", vuln, True),
        ("Asset / IP", asset, False),
        ("Extension", f"+{days} day(s)" if days else "", False),
    ]
    body = "Your timeline extension request has been approved by admin."
    blocks = _rich_card_blocks(
        "✅", f"Extension Approved: {vuln}", "success", "Deadline extended successfully",
        body, facts, ["Added by vaptfix", "Status: Approved"],
    )
    return blocks, f"✅ Extension Approved: {vuln}", "#2eb67d"


def _card_extension_rejected(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vulnerability_name", "")
    asset = meta.get("asset", "")
    reason = meta.get("admin_comment", "")
    facts = [
        ("Vulnerability", vuln, True),
        ("Asset / IP", asset, False),
        ("Status", "Rejected", False),
        ("Admin reason", reason, True),
    ]
    body = "Your timeline extension request has been rejected by admin."
    blocks = _rich_card_blocks(
        "❌", f"Extension Rejected: {vuln}", "error", "Request rejected — proceed with current deadline",
        body, facts, ["Added by vaptfix", "Status: Rejected"],
    )
    return blocks, f"❌ Extension Rejected: {vuln}", "#e01e5a"


def _card_support_submitted(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vul_name", "")
    asset = meta.get("host_name", "")
    step = meta.get("step_number", "")
    facts = [
        ("Vulnerability", vuln, True),
        ("Asset / IP", asset, False),
        ("Step", f"Step {step}" if step else "", False),
        ("Status", "Submitted successfully", True),
    ]
    body = "Your support request has been submitted and is waiting for admin response."
    blocks = _rich_card_blocks(
        "🔔", f"Support Request Submitted: {vuln}", "success", "Ticket created successfully",
        body, facts, ["Added by vaptfix", "Support ticket"],
    )
    return blocks, f"🔔 Support Request Submitted: {vuln}", "#1264a3"


def _card_support_admin_action(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vul_name", "")
    asset = meta.get("host_name", "")
    team = meta.get("assigned_team", "")
    requested_by = meta.get("requested_by", "")
    issue_type = meta.get("issue_type", "")
    details = meta.get("description", "")
    pills = [p for p in (f"`{vuln}`" if vuln else "", _sev_pill(meta.get("severity")), f"`{asset}`" if asset else "") if p]
    facts = [
        ("From", requested_by, False),
        ("Issue type", issue_type, False),
        ("Details", details, True),
    ]
    title_text = f"Support Request — {team}" if team else "Support Request"
    hint = "Use `/support` to review, then `/support-resolve [ticket-id]` or `/support-reply [ticket-id]`."
    blocks = _action_card_blocks("🆘", title_text, pills, facts, hint)
    return blocks, f"🆘 {title_text}", "#1264a3"


def _card_mitigation_submitted(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vulnerability_name", "")
    asset = meta.get("asset", "")
    submitted_by = meta.get("requested_by", "")
    facts = [
        ("Vulnerability", vuln, True),
        ("Asset / IP", asset, False),
        # No "fix method" field exists anywhere upstream — the app only
        # ever supports the manual step-by-step flow, so this is a fixed
        # label rather than sourced from metadata.
        ("Method", "Manual Fix", False),
    ]
    body = f"{submitted_by} has submitted a mitigation for review." if submitted_by else "A mitigation has been submitted for review."
    blocks = _rich_card_blocks(
        "🔔", f"Mitigation Submitted: {vuln}", "pending", "Awaiting admin verification",
        body, facts, ["Added by vaptfix", "Pending verification"],
    )
    return blocks, f"🔔 Mitigation Submitted: {vuln}", "#1264a3"


def _card_vuln_closed(title, message, metadata):
    meta = metadata or {}
    vuln = meta.get("vulnerability_name", "")
    asset = meta.get("asset", "")
    team = meta.get("assigned_team", "")
    facts = [
        ("Vulnerability", vuln, True),
        ("Asset / IP", asset, False),
        ("Closed by", team, False),
        ("Team", team, True),
    ]
    body = "This vulnerability has been verified and closed by the assigned team."
    blocks = _rich_card_blocks(
        "🔔", f"Vulnerability Verified & Closed: {vuln}", "success", "Verified and closed successfully",
        body, facts, ["Added by vaptfix", "Status: Closed"],
    )
    return blocks, f"🔔 Vulnerability Verified & Closed: {vuln}", "#1264a3"


# notif_type -> (title, message, metadata) -> (blocks, fallback_text, color)
_NOTIF_CARD_BUILDERS = {
    "extension_requested":       _card_extension_requested,
    "extension_approved":        _card_extension_approved,
    "extension_rejected":        _card_extension_rejected,
    "support_request_received":  _card_support_submitted,
    "support_request_created":   _card_support_admin_action,
    "vuln_verification_request": _card_mitigation_submitted,
    "vuln_closed":               _card_vuln_closed,
}


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


def _send_slack_notification(admin_id, recipient_type, notif_type, title, message, metadata, recipient_email):
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
        card_builder = _NOTIF_CARD_BUILDERS.get(notif_type)
        if card_builder:
            blocks, fallback_text, color = card_builder(title, message, metadata)
        else:
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
        _send_slack_notification(admin_id, recipient_type, notif_type, title, message, metadata, recipient_email)
    except Exception as exc:
        logger.error("create_notification failed [%s | %s]: %s", notif_type, recipient_type, exc)
