"""
User-side Support Status tab — raise a support ticket + view your team's
existing ones. Mirrors users.views.SlackSlashCommandView._cmd_support
exactly, including writing straight to the `support_requests` Mongo
collection (same schema, "source": "teams" instead of "slack") rather than
going through a REST endpoint — this is deliberate, matching Slack: it's
the same collection the admin's own Home dashboard "Support Requests"
stat and website support-request views already read, so a ticket raised
from Teams shows up everywhere immediately, with no extra endpoint needed.
"""
import logging
import datetime

from . import cards
from . import fix_tab
from . import user_fix_tab as fix

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
COLLECTION = "support_requests"


def _status_icon(status):
    s = (status or "open").strip().lower()
    return "✅" if s == "closed" else ("🟠" if "progress" in s else "🔴")


def _status_color(status):
    """Adaptive Cards' semantic TextBlock colors — real request: the
    status badge on each row should be colored according to status, not
    just carry an emoji."""
    s = (status or "open").strip().lower()
    if s == "closed":
        return "good"
    if "progress" in s:
        return "warning"
    return "attention"


def _support_row(title_text, subtitle_text, status, action_id, value):
    """Same 2-column shape as fix_tab._row, plus a 3rd column for a
    colored status badge between the title/subtitle and the View button —
    real request: the vuln name row should show status (colored) on its
    right, not just inside the View column."""
    return {
        "type": "ColumnSet",
        "spacing": "Medium",
        "separator": True,
        "columns": [
            {
                "type": "Column", "width": "stretch",
                "items": [
                    {"type": "TextBlock", "text": title_text, "weight": "Bolder", "size": "Small", "wrap": True},
                    {"type": "TextBlock", "text": subtitle_text, "size": "Small", "isSubtle": True, "wrap": True, "spacing": "None"},
                ],
            },
            {
                "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                "items": [{
                    "type": "TextBlock", "text": fix_tab._status_label(status),
                    "weight": "Bolder", "size": "Small", "color": _status_color(status), "wrap": False,
                }],
            },
            {
                "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                "items": [{
                    "type": "ActionSet",
                    "actions": [cards._execute_action("View ›", {"action_id": action_id, **value})],
                }],
            },
        ],
    }


def list_support_requests(admin, member_user, team_name, offset=0):
    from vaptfix.mongo_client import MongoContext

    report_id = fix._fetch_team_data(member_user, team_name).get("report_id")
    query = {"assigned_team": team_name}
    if report_id:
        query["report_id"] = str(report_id)
    with MongoContext() as db:
        tickets = list(db[COLLECTION].find(query, sort=[("requested_at", -1)]))

    total = len(tickets)
    page = tickets[offset:offset + PAGE_SIZE]
    open_count = sum(1 for t in tickets if (t.get("status") or "open").strip().lower() != "closed")
    closed_count = total - open_count

    # Real request: "Raise Support Request" button removed — this tab
    # should only show the list, not offer to create a new one. The
    # underlying raise-request flow (usup_raise_form/raise_request_form_body/
    # usup_submit) is left in place but is now unreachable from any button,
    # same as other since-removed entry points elsewhere in this module.
    body = [
        {"type": "TextBlock", "text": "🎫 Support Status", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"{team_name} — {open_count} open, {closed_count} closed.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No support requests yet.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body

    for i, t in enumerate(page):
        title = t.get("vul_name") or "General request"
        when = str(t.get("requested_at") or "")[:10]
        reason = f"{t.get('description') or ''}".strip()[:120] or "—"
        asset_line = f"**Asset:** {t.get('host_name') or '—'}"
        reason_line = f"**Reason:** {reason}"
        by_line = f"**By:** {t.get('requested_by') or '—'}   ·   {when}"
        body.append(_support_row(
            title, f"{asset_line}\n{reason_line}\n{by_line}", t.get("status"),
            "usup_view", {"idx": offset + i, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "usup_pg"))
    return body


def view_body(admin, member_user, team_name, idx, back_offset=0):
    from vaptfix.mongo_client import MongoContext

    report_id = fix._fetch_team_data(member_user, team_name).get("report_id")
    query = {"assigned_team": team_name}
    if report_id:
        query["report_id"] = str(report_id)
    with MongoContext() as db:
        tickets = list(db[COLLECTION].find(query, sort=[("requested_at", -1)]))

    body = [fix_tab._back_action("← Back to Support Status", "usup_back", {"offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(tickets):
        body.append({"type": "TextBlock", "text": "This request could not be found.", "wrap": True, "spacing": "Medium"})
        return body
    t = tickets[idx]
    icon = _status_icon(t.get("status"))
    when = str(t.get("requested_at") or "")[:10]
    body.append({"type": "TextBlock", "text": t.get("vul_name") or "General request", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Status", "value": f"{icon} {(t.get('status') or 'open').title()}"},
            {"title": "Asset", "value": str(t.get("host_name") or "—")},
            {"title": "Step", "value": str(t.get("step_number") or "—")},
            {"title": "Requested By", "value": str(t.get("requested_by") or "—")},
            {"title": "Requested At", "value": when},
        ],
    })
    body.append({"type": "TextBlock", "text": "Message", "weight": "Bolder", "size": "Small", "spacing": "Medium"})
    body.append({"type": "TextBlock", "text": t.get("description") or "—", "wrap": True, "size": "Small"})
    return body


def raise_form_body():
    return [
        cards._section_title("➕ Raise Support Request"),
        {"type": "TextBlock", "text": "Describe what you need help with — your admin will be notified.", "size": "Small", "isSubtle": True, "wrap": True},
        {"type": "Input.Text", "id": "usup_message", "label": "Message", "isMultiline": True, "placeholder": "e.g. Need help with SSL cert fix on 192.168.1.1"},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [cards._execute_action("✅ Submit", {"action_id": "usup_submit"}, style="positive")],
        },
    ]


def raise_support_request(admin, member_user, member_detail, team_name, message):
    from vaptfix.mongo_client import MongoContext

    message = (message or "").strip()
    if not message:
        return False, "Please enter a message before submitting."

    report_id = fix._fetch_team_data(member_user, team_name).get("report_id") or ""
    doc = {
        "report_id": str(report_id),
        "user_id": getattr(member_detail, "ms_teams_member_id", "") or str(member_user.id),
        "admin_id": str(admin.id),
        "vul_name": None,
        "host_name": None,
        "severity": None,
        "assigned_team": team_name,
        "step_number": 0,
        "description": message,
        "status": "open",
        "source": "teams",
        "requested_by": member_user.email,
        "requested_at": datetime.datetime.utcnow(),
    }
    try:
        with MongoContext() as db:
            db[COLLECTION].insert_one(doc)
        try:
            from notifications.utils import create_notification
            create_notification(
                admin, "admin", "support_requested",
                f"Support Request: {team_name}",
                f"{member_user.email} raised a support request for {team_name}: {message[:200]}",
                {"assigned_team": team_name, "requested_by": member_user.email, "message": message},
            )
        except Exception:
            logger.exception("[TeamsBot] support request notification failed (non-fatal)")
        return True, None
    except Exception:
        logger.exception("[TeamsBot] raise_support_request insert failed")
        return False, "Something went wrong — please try again."
