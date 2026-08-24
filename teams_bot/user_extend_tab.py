"""
User-side Timeline Extension tab — list of the team's own extension
requests + status (review/approved/rejected), and a real "Request
Extension" form (vuln picker + days + reason) — Adaptive Cards support
inline Input elements directly (unlike Slack, which has to open a
separate modal for the same form, see users.views.SlackSlashCommandView.
_build_extend_request_modal), so this is the same flow, just inline.
"""
import logging

from . import cards
from . import fix_tab
from . import user_fix_tab as fix

logger = logging.getLogger(__name__)

PAGE_SIZE = 5

UEX_SUBTABS = [
    ("uex_sub_list", "📋 Extension Requests"),
    ("uex_sub_new",  "⏳ Request Extension"),
]

_STATUS_ICON = {"review": "🟠 Pending", "approved": "✅ Approved", "rejected": "❌ Rejected"}


def extend_subnav_columnset(active_sub):
    return cards.pill_columnset(UEX_SUBTABS, active_sub, lambda k: {"action_id": k})


def _fetch_requests(member_user, team_name):
    def _fetch():
        from userdashboard.views import UserMitigationTimelineExtensionReportAPIView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(UserMitigationTimelineExtensionReportAPIView, member_user, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"extension report fetch failed: {status_code}")
        # This endpoint's own response oddly stores the TEAM name (not the
        # requester's identity) under "requested_by" — see
        # UserMitigationTimelineExtensionReportAPIView's own payload build.
        return [r for r in (data.get("results") or []) if r.get("requested_by") == team_name]
    return fix_tab.cached_fetch(f"user_extend_requests:{member_user.id}:{team_name}", 20, _fetch)


def request_list_body(member_user, team_name, offset=0):
    rows = _fetch_requests(member_user, team_name)
    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📋 Extension Requests", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"{team_name}'s timeline extension requests and their status.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No extension requests yet — use the \"Request Extension\" tab above.", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
        return body
    for r in page:
        icon = fix_tab._SEV_ICON.get((r.get("severity") or "medium").lower(), "🟡")
        name = r.get("vul_name") or "Unnamed vulnerability"
        status_label = _STATUS_ICON.get(r.get("status"), r.get("status") or "review")
        body.append({
            "type": "Container", "spacing": "Medium", "separator": True,
            "items": [
                {"type": "TextBlock", "text": f"{icon} {name}", "weight": "Bolder", "size": "Small", "wrap": True},
                {"type": "TextBlock", "text": f"{r.get('asset') or '—'}   ·   +{r.get('extension_days', 0)}d   ·   {status_label}", "size": "Small", "isSubtle": True, "spacing": "None"},
                {"type": "TextBlock", "text": r.get("reason") or "", "size": "Small", "isSubtle": True, "wrap": True, "spacing": "None"},
            ],
        })
    body.extend(fix_tab._pagination_body(offset, total, "uex_pg"))
    return body


def _open_vulns(member_user, team_name):
    rows = fix._fetch_team_rows(member_user, team_name)
    return [r for r in rows if (r.get("status") or "open").strip().lower() != "closed"]


def new_request_form_body(member_user, team_name):
    open_rows = _open_vulns(member_user, team_name)
    body = [
        {"type": "TextBlock", "text": "⏳ Request Extension", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Pick a vulnerability assigned to {team_name}, then how many extra days you need.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not open_rows:
        body.append({"type": "TextBlock", "text": "No open vulnerabilities to request an extension for.", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
        return body

    choices = [
        {"title": f"{r.get('asset') or '—'} — {(r.get('vul_name') or 'Unnamed')[:60]}", "value": str(i)}
        for i, r in enumerate(open_rows[:50])
    ]
    body.extend([
        {"type": "Input.ChoiceSet", "id": "uex_new_idx", "label": "Vulnerability", "style": "compact", "choices": choices},
        {"type": "Input.Number", "id": "uex_new_days", "label": "Extra days needed", "min": 1, "max": 90, "value": 7},
        {"type": "Input.Text", "id": "uex_new_reason", "label": "Reason", "isMultiline": True, "placeholder": "e.g. Need more time for patch testing"},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [cards._execute_action("✅ Submit Request", {"action_id": "uex_new_submit"}, style="positive")],
        },
    ])
    if len(open_rows) > 50:
        body.append({"type": "TextBlock", "text": f"Showing the first 50 of {len(open_rows)} open vulnerabilities.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


def submit_new_request(member_user, team_name, idx, days, reason):
    open_rows = _open_vulns(member_user, team_name)
    if idx is None or idx < 0 or idx >= len(open_rows):
        return False, "Please pick a vulnerability."
    merged = dict(open_rows[idx], _requested_days=days or 7, _reason=reason)
    return fix.submit_extension_request(member_user, merged)


def extend_tab_body(member_user, team_name, active_sub="uex_sub_list", offset=0):
    body = [extend_subnav_columnset(active_sub)]
    try:
        if active_sub == "uex_sub_new":
            body.extend(new_request_form_body(member_user, team_name))
        else:
            body.extend(request_list_body(member_user, team_name, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] user extend_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
