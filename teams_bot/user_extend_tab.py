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

# Same Day/Week choice set the website's own "Extend Timeline" panel uses
# for "Extended Deadline" — real request: match that dropdown exactly
# instead of a freeform 1-90 number input.
_DEADLINE_DAY_OPTIONS = [
    "1 Day", "2 Days", "3 Days", "4 Days", "5 Days", "6 Days",
    "1 Week", "2 Weeks", "3 Weeks", "4 Weeks", "5 Weeks", "6 Weeks",
]


def _fetch_rc_days(member_user):
    """severity -> the admin's configured SLA days for it (RiskCriteria),
    e.g. {"medium": 14, ...} — same source + same day-string parsing as
    user_reminder_tab._fetch_buckets uses for the exact same "how many
    days does this severity get" question. Returns {} if no RiskCriteria
    is configured yet (extension form still works — just can't show a
    real Original Deadline)."""
    from userrisk_criteria.views import UserRiskCriteriaListView
    from .actions import _call_view_in_process
    from .user_reminder_tab import _parse_rc_days

    status_code, rc_data = _call_view_in_process(UserRiskCriteriaListView, member_user, method="get")
    rc_list = (rc_data.get("risk_criteria") or []) if (status_code < 300 and isinstance(rc_data, dict)) else []
    if not rc_list:
        return {}
    rc = rc_list[0]
    return {
        sev: _parse_rc_days(rc.get(sev))
        for sev in ("critical", "high", "medium", "low")
        if _parse_rc_days(rc.get(sev)) is not None
    }


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
    for i, r in enumerate(page):
        icon = fix_tab._SEV_ICON.get((r.get("severity") or "medium").lower(), "🟡")
        name = r.get("vul_name") or "Unnamed vulnerability"
        status_label = _STATUS_ICON.get(r.get("status"), r.get("status") or "review")
        subtitle = f"{r.get('asset') or '—'}   ·   +{r.get('extension_days', 0)}d   ·   {status_label}\n{r.get('reason') or ''}"
        body.append(fix_tab._row(f"{icon} {name}", subtitle, "uex_view", {"idx": offset + i, "offset": offset}))
    body.extend(fix_tab._pagination_body(offset, total, "uex_pg"))
    return body


def request_detail_body(member_user, team_name, idx, back_offset=0):
    rows = _fetch_requests(member_user, team_name)
    body = [fix_tab._back_action("← Back to Extension Requests", "uex_view_back", {"offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(rows):
        body.append({"type": "TextBlock", "text": "This request could not be found.", "wrap": True, "spacing": "Medium"})
        return body
    r = rows[idx]
    icon = fix_tab._SEV_ICON.get((r.get("severity") or "medium").lower(), "🟡")
    status_label = _STATUS_ICON.get(r.get("status"), r.get("status") or "review")
    body.append({"type": "TextBlock", "text": r.get("vul_name") or "Unnamed vulnerability", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Status", "value": status_label},
            {"title": "Asset", "value": str(r.get("asset") or "—")},
            {"title": "Severity", "value": f"{icon} {(r.get('severity') or '—').title()}"},
            {"title": "Extension", "value": f"+{r.get('extension_days', 0)} days"},
            {"title": "Requested By", "value": str(r.get("requested_by_email") or "—")},
            {"title": "Requested At", "value": str(r.get("request_date") or "—")[:10]},
        ],
    })
    body.append({"type": "TextBlock", "text": "Reason", "weight": "Bolder", "size": "Small", "spacing": "Medium"})
    body.append({"type": "TextBlock", "text": r.get("reason") or "—", "wrap": True, "size": "Small"})
    # Real bug report: admin's own reject reason (admin_comment) never
    # showed here — the user could see their request got rejected, but not
    # WHY, since only their own original "Reason" was ever displayed.
    if (r.get("status") or "").strip().lower() == "rejected" and r.get("admin_comment"):
        body.append({"type": "TextBlock", "text": "Admin's Reason for Rejection", "weight": "Bolder", "size": "Small", "spacing": "Medium", "color": "attention"})
        body.append({"type": "TextBlock", "text": r.get("admin_comment"), "wrap": True, "size": "Small"})
    return body


def _open_vulns(member_user, team_name):
    rows = fix._fetch_team_rows(member_user, team_name)
    return [r for r in rows if (r.get("status") or "open").strip().lower() != "closed"]


def _asset_vulns_for(open_rows, selected_asset):
    return [r for r in open_rows if (r.get("asset") or "—") == selected_asset]


def new_request_form_body(member_user, team_name, selected_asset=None, selected_idx=None):
    """Three-step wizard: Asset -> Vulnerability (on that asset) ->
    confirm + set the extension. Same Asset -> Vulnerability cascade as
    Slack's _build_extend_request_modal (users.views.SlackSlashCommandView),
    just as separate Adaptive Card screens instead of Slack's
    dispatch_action live-updating select (Adaptive Cards have no
    "re-render on every keystroke/selection" primitive — an explicit
    "Next" step is the documented way to get the same result).

    Real request: showing the vulnerability's REAL current SLA deadline
    (e.g. "Original Deadline: 14 Days", from the admin's own RiskCriteria
    for that severity — same source/formula as the Reminder tab's overdue
    buckets, see _fetch_rc_days) — and a Day/Week dropdown for the new
    one, matching the website's own "Extend Timeline" panel exactly —
    needs the specific vulnerability (for its severity) already picked,
    which is why this is 3 steps rather than 2: there's nowhere to show a
    per-vulnerability fact before a specific vulnerability is confirmed."""
    open_rows = _open_vulns(member_user, team_name)
    body = [
        {"type": "TextBlock", "text": "⏳ Request Extension", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
    ]
    if not open_rows:
        body.append({"type": "TextBlock", "text": f"Pick a vulnerability assigned to {team_name}, then how many extra days you need.", "size": "Small", "isSubtle": True, "wrap": True})
        body.append({"type": "TextBlock", "text": "No open vulnerabilities to request an extension for.", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
        return body

    assets = sorted({(r.get("asset") or "—") for r in open_rows})

    # Step 1 — Asset
    if not selected_asset or selected_asset not in assets:
        body.append({"type": "TextBlock", "text": f"Pick an asset assigned to {team_name}, then a vulnerability on it.", "size": "Small", "isSubtle": True, "wrap": True})
        asset_choices = [{"title": a, "value": a} for a in assets]
        body.extend([
            {"type": "Input.ChoiceSet", "id": "uex_new_asset", "label": "Asset", "style": "compact", "choices": asset_choices},
            {
                "type": "ActionSet", "spacing": "Medium",
                "actions": [cards._execute_action("Next →", {"action_id": "uex_new_pick_asset"}, style="positive")],
            },
        ])
        return body

    asset_vulns = _asset_vulns_for(open_rows, selected_asset)
    target = asset_vulns[selected_idx] if (selected_idx is not None and 0 <= selected_idx < len(asset_vulns)) else None

    # Step 2 — Vulnerability (asset already picked, not yet confirmed)
    if target is None:
        body.append({"type": "TextBlock", "text": f"**Asset:** {selected_asset}", "wrap": True, "spacing": "Small"})
        choices = [
            {"title": (r.get("vul_name") or "Unnamed")[:75], "value": str(i)}
            for i, r in enumerate(asset_vulns[:50])
        ]
        body.extend([
            {"type": "Input.ChoiceSet", "id": "uex_new_idx", "label": "Vulnerability", "style": "compact", "choices": choices},
            {
                "type": "ActionSet", "spacing": "Medium",
                "actions": [
                    cards._execute_action("← Change asset", {"action_id": "uex_new_back_to_asset"}),
                    cards._execute_action("Next →", {"action_id": "uex_new_pick_vuln", "asset": selected_asset}, style="positive"),
                ],
            },
        ])
        if len(asset_vulns) > 50:
            body.append({"type": "TextBlock", "text": f"Showing the first 50 of {len(asset_vulns)} open vulnerabilities on this asset.", "size": "Small", "isSubtle": True, "spacing": "Small"})
        return body

    # Step 3 — confirm + set the extension, real Original Deadline shown
    sev = (target.get("severity") or "medium").strip().lower()
    rc_days = _fetch_rc_days(member_user)
    original_days = rc_days.get(sev)
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Asset", "value": selected_asset},
            {"title": "Vulnerability", "value": target.get("vul_name") or "Unnamed"},
            {"title": "Original Deadline", "value": f"{original_days} Days" if original_days is not None else "Not configured"},
        ],
    })
    body.extend([
        {"type": "Input.ChoiceSet", "id": "uex_new_deadline", "label": "Extended Deadline", "style": "compact",
         "placeholder": "Select Extension",
         "choices": [{"title": d, "value": d} for d in _DEADLINE_DAY_OPTIONS]},
        {"type": "Input.Text", "id": "uex_new_reason", "label": "Reason", "isMultiline": True, "placeholder": "e.g. Need more time for patch testing"},
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [
                cards._execute_action("← Change vulnerability", {"action_id": "uex_new_pick_asset", "uex_new_asset": selected_asset}),
                cards._execute_action("✅ Submit Request", {"action_id": "uex_new_submit", "asset": selected_asset, "idx": str(selected_idx)}, style="positive"),
            ],
        },
    ])
    return body


def submit_new_request(member_user, team_name, selected_asset, idx, deadline_choice, reason):
    open_rows = _open_vulns(member_user, team_name)
    asset_vulns = _asset_vulns_for(open_rows, selected_asset) if selected_asset else []
    if not selected_asset or idx is None or idx < 0 or idx >= len(asset_vulns):
        return False, "Please pick a vulnerability."
    from .user_reminder_tab import _parse_rc_days
    days = _parse_rc_days(deadline_choice) if deadline_choice else None
    if not days:
        return False, "Please pick an extended deadline."
    merged = dict(asset_vulns[idx], _requested_days=days, _reason=reason)
    return fix.submit_extension_request(member_user, merged)


def extend_tab_body(member_user, team_name, active_sub="uex_sub_list", offset=0, selected_asset=None, selected_idx=None):
    body = [extend_subnav_columnset(active_sub)]
    try:
        if active_sub == "uex_sub_new":
            body.extend(new_request_form_body(member_user, team_name, selected_asset=selected_asset, selected_idx=selected_idx))
        else:
            body.extend(request_list_body(member_user, team_name, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] user extend_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
