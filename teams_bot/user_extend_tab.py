"""
User-side Timeline Extension tab — list of the team's own extension
requests + status (review/approved/rejected). Raising a NEW request
happens from a vuln's own detail page (see user_fix_tab.py's "⏳ Request
Extension" button) rather than a separate picker here, since the request
needs a specific vulnerability's severity/asset/name — this sub-tab is
just a shortcut pointing there plus the status list.
"""
import logging

from . import cards
from . import fix_tab

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
        body.append({"type": "TextBlock", "text": "No extension requests yet — open a vulnerability from Fix or Register and tap \"Request Extension\".", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
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


def new_request_info_body():
    return [
        {"type": "TextBlock", "text": "⏳ Request Extension", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {
            "type": "TextBlock",
            "text": "To request more time on a specific vulnerability, open it from **Fix** or **Register** and tap \"⏳ Request Extension\" there — it'll carry over the asset/severity automatically.",
            "wrap": True, "size": "Small", "isSubtle": True, "spacing": "Medium",
        },
    ]


def extend_tab_body(member_user, team_name, active_sub="uex_sub_list", offset=0):
    body = [extend_subnav_columnset(active_sub)]
    try:
        if active_sub == "uex_sub_new":
            body.extend(new_request_info_body())
        else:
            body.extend(request_list_body(member_user, team_name, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] user extend_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
