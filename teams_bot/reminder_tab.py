"""
Reminder tab — Overdue / Due Today / This Week / Next Week (deadline-
urgency buckets computed from RiskCriteria SLA days, same formula the rest
of the app uses) and Support (support-ticket list). Mirrors
users.views.SlackSlashCommandView._notification_subtab_blocks /
_bucket_deadline_rows / _format_notification_tab / _support_tab_blocks /
_format_support_tab — read-only, no per-row click-through (Slack doesn't
have one here beyond the deadline list itself).
"""
import logging

from . import cards
from . import fix_tab

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
_SEV_ICON = fix_tab._SEV_ICON

# Real follow-up request: same one-row-full-text experiment as the top
# nav bar (cards.NAV_ITEMS) — see its comment for the reasoning and the
# unverified-in-real-Teams caveat. Emoji dropped from every label except
# the colored circles, which are the actual severity/urgency indicator
# (not decoration) so they stay.
REMINDER_SUBTABS = [
    ("notif_sub_overdue", "🔴 Overdue"),
    ("notif_sub_today", "🟠 Due Today"),
    ("notif_sub_thisweek", "🟡 This Week"),
    ("notif_sub_nextweek", "🟢 Next Week"),
    ("notif_sub_support", "Support"),
]

SUPPORT_STATUS_FILTERS = [("all", "All"), ("open", "Open"), ("closed", "Closed")]
SUPPORT_TEAM_FILTERS = [
    ("all", "All Teams"), ("patch", "Patch Management"), ("config", "Configuration Management"),
    ("network", "Network Security"), ("arch", "Architectural Flaws"),
]
_SUPPORT_TEAM_MATCH = {
    "patch": "patch management", "config": "configuration management",
    "network": "network security", "arch": "architectural flaws",
}


def reminder_subnav_columnset(active_sub):
    # One row — see REMINDER_SUBTABS' own comment for the real-Teams-
    # testing status of this. Revert to cards.two_row_pill_columnset(
    # REMINDER_SUBTABS, active_sub, lambda k: {"action_id": k}) if this
    # renders broken/truncated in real Teams.
    return cards.pill_columnset(REMINDER_SUBTABS, active_sub, lambda k: {"action_id": k})


# ── Deadline buckets (Overdue / Due Today / This Week / Next Week) ──────

def _parse_rc_days(raw_value):
    if raw_value is None:
        return None
    text = str(raw_value).strip().lower()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    import re
    total_days = 0
    matched = False
    week_match = re.search(r"(\d+)\s*week", text)
    if week_match:
        total_days += int(week_match.group(1)) * 7
        matched = True
    day_match = re.search(r"(\d+)\s*day|day\s*(\d+)", text)
    if day_match:
        num = day_match.group(1) or day_match.group(2)
        total_days += int(num)
        matched = True
    return total_days if matched else None


def _fetch_risk_criteria_days(admin):
    def _fetch():
        from risk_criteria.views import RiskCriteriaListView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(RiskCriteriaListView, admin, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            return None
        rc_list = data.get("risk_criteria") or []
        if not rc_list:
            return None
        rc = rc_list[0]
        return {
            "critical": _parse_rc_days(rc.get("critical")),
            "high": _parse_rc_days(rc.get("high")),
            "medium": _parse_rc_days(rc.get("medium")),
            "low": _parse_rc_days(rc.get("low")),
        }
    # A None result (not configured yet) is never cached by cached_fetch
    # (it treats a cached None the same as a miss) -- harmless here, that
    # state resolves the moment the admin finishes the risk-criteria
    # onboarding step, not from anything on this tab.
    return fix_tab.cached_fetch(f"risk_criteria_days:{admin.id}", 20, _fetch)


def _bucket_deadline_rows(rows, rc_days):
    from datetime import datetime, timezone as _tz
    buckets = {"overdue": [], "today": [], "thisweek": [], "nextweek": []}
    today = datetime.now(_tz.utc).date()

    for row_idx, row in enumerate(rows):
        status = (row.get("status") or "open").strip().lower()
        if status == "closed":
            continue
        sev = (row.get("severity") or "").strip().lower()
        days = rc_days.get(sev)
        if days is None:
            continue
        first_obs_raw = row.get("first_observation")
        if not first_obs_raw:
            continue
        try:
            first_obs = datetime.fromisoformat(str(first_obs_raw).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        elapsed = max(0, (today - first_obs.date()).days)
        remaining_days = days - elapsed
        # Real request: a View button per row, opening the vuln's own Fix
        # detail — needs the ORIGINAL index into the flat `rows` list (the
        # same one fix_tab._vuln_detail_full_body indexes into), not just
        # this row's position within its bucket.
        row_out = dict(row, remaining_days=remaining_days, _row_idx=row_idx)
        if remaining_days < 0:
            buckets["overdue"].append(row_out)
        elif remaining_days == 0:
            buckets["today"].append(row_out)
        elif 1 <= remaining_days <= 6:
            buckets["thisweek"].append(row_out)
        else:
            # Real bug report: this was `elif 7 <= remaining_days <= 13`,
            # capping Next Week at 13 days. Real risk-criteria data has a
            # Medium SLA of "2 Weeks" (14 days) and Low of "4 Weeks" (28
            # days) — on a freshly-uploaded report (elapsed=0) those give
            # remaining_days=14/28, both OUTSIDE every bucket's range
            # (This Week 1-6, Next Week 7-13), so the vulnerability
            # vanished from all 4 tabs entirely until enough days had
            # passed to bring it under 14. Next Week is meant to be
            # everything not-yet-due beyond This Week — open-ended catches
            # any remaining_days >= 7 instead of only 7-13.
            buckets["nextweek"].append(row_out)
    return buckets


_BUCKET_TITLES = {
    "overdue": "🔴 Overdue", "today": "🟠 Due Today",
    "thisweek": "🟡 Due This Week", "nextweek": "🟢 Due Next Week",
}
_SUB_TO_BUCKET = {
    "notif_sub_overdue": "overdue", "notif_sub_today": "today",
    "notif_sub_thisweek": "thisweek", "notif_sub_nextweek": "nextweek",
}


def deadline_bucket_body(admin, bucket_key, offset=0):
    rows = fix_tab._fetch_register_rows(admin)
    rc_days = _fetch_risk_criteria_days(admin)
    if rc_days is None:
        return [{"type": "TextBlock", "text": "No Risk Criteria configured yet — set it up first (onboarding step).", "wrap": True, "isSubtle": True, "spacing": "Medium"}]

    buckets = _bucket_deadline_rows(rows, rc_days)
    items = buckets.get(bucket_key) or []
    total = len(items)
    page = items[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": _BUCKET_TITLES.get(bucket_key, "Reminder"), "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Deadline urgency, computed from your Risk Criteria SLA days.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "Nothing in this bucket right now.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for v in page:
        name = v.get("vul_name") or "Unnamed vulnerability"
        asset = v.get("asset") or "—"
        sev = (v.get("severity") or "").strip().lower() or "medium"
        if sev not in _SEV_ICON:
            sev = "medium"
        remaining = v.get("remaining_days", 0)
        if bucket_key == "overdue":
            due_label = f"{abs(remaining)} day{'s' if abs(remaining) != 1 else ''} overdue"
        elif remaining == 0:
            due_label = "Due today"
        else:
            due_label = f"Due in {remaining} day{'s' if remaining != 1 else ''}"
        subtitle = f"{asset}   ·   {_SEV_ICON[sev]} {sev.title()}   ·   {due_label}"
        body.append(fix_tab._row(
            name, subtitle, "remind_bucket_view",
            {"idx": v.get("_row_idx"), "bucket": bucket_key, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "remind_bucket_pg", {"bucket": bucket_key}))
    return body


def deadline_vuln_detail_body(admin, idx, bucket_key, back_offset=0, sub="manual", step_number=None):
    """Real request: a View button per Reminder-bucket row, opening that
    vulnerability's own (read-only, admin-side) Fix detail — reuses
    fix_tab._vuln_detail_full_body verbatim via its ctx="reminder"
    extension point (same shape as Register's ctx="register"), so this
    never drifts out of sync with the identical detail every other entry
    point already shows. `idx` is the row's index into the SAME flat
    fix_tab._fetch_register_rows(admin) list _bucket_deadline_rows itself
    read from — no separate index-mapping needed (unlike Common Vulns,
    which has a genuine two-index problem)."""
    return fix_tab._vuln_detail_full_body(
        admin, idx, sub=sub, ctx="reminder", offset=back_offset, step_number=step_number,
        back_action_id="remind_bucket_back",
        back_title=f"← Back to {_BUCKET_TITLES.get(bucket_key, 'Reminder')}",
        extra_value={"bucket": bucket_key},
    )


# ── Support ───────────────────────────────────────────────────────────

def _match_support_status(record, st_filter):
    st = (record.get("status") or "open").strip().lower()
    if st_filter == "all":
        return True
    if st_filter == "open":
        return st != "closed"
    return st == "closed"


def _match_support_team(record, team_filter):
    if team_filter == "all":
        return True
    target = _SUPPORT_TEAM_MATCH.get(team_filter, "")
    raw = (record.get("assigned_team") or "").strip().lower()
    return raw == target or (target and target in raw)


def _fetch_support_requests(admin):
    from adminregister.views import SupportRequestByReportAPIView
    from .actions import _call_view_in_process
    report_data = fix_tab._fetch_register_data(admin)
    report_id = report_data.get("report_id")
    if not report_id:
        return []
    status_code, data = _call_view_in_process(
        SupportRequestByReportAPIView, admin, method="get", url_kwargs={"report_id": report_id},
    )
    if status_code >= 300 or not isinstance(data, dict):
        return []
    return data.get("results") or []


def support_list_body(admin, st="all", team="all", offset=0):
    raw = _fetch_support_requests(admin)

    st_counts = {
        "all": len([r for r in raw if _match_support_team(r, team)]),
        "open": sum(1 for r in raw if _match_support_team(r, team) and _match_support_status(r, "open")),
        "closed": sum(1 for r in raw if _match_support_team(r, team) and _match_support_status(r, "closed")),
    }
    filtered = [r for r in raw if _match_support_status(r, st) and _match_support_team(r, team)]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "🎫 Support Requests", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Streamlining the resolution of critical infrastructure vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
        cards.pill_columnset(
            [(k, f"{label} {st_counts.get(k, 0)}") for k, label in SUPPORT_STATUS_FILTERS], st,
            lambda k: {"action_id": "remind_sup_filter", "st": k, "team": team, "offset": 0},
        ),
        cards.two_row_pill_columnset(
            SUPPORT_TEAM_FILTERS, team,
            lambda k: {"action_id": "remind_sup_filter", "st": st, "team": k, "offset": 0},
        ),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No support requests found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for i, r in enumerate(page):
        name = r.get("vul_name") or "General Request"
        host = r.get("host_name") or "—"
        team_name = r.get("assigned_team") or "—"
        requester = r.get("requested_by") or "Unknown"
        when = str(r.get("requested_at") or "")[:10]
        st_val = (r.get("status") or "open").strip().lower()
        st_label = "🟢 Closed" if st_val == "closed" else "🔴 Open"
        subtitle = f"{host}   ·   Team: {team_name}\nBy: {requester}   ·   {when}   ·   {st_label}"
        body.append(fix_tab._row(
            name, subtitle, "remind_sup_view",
            {"idx": offset + i, "st": st, "team": team, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "remind_sup_pg", {"st": st, "team": team}))
    return body


def support_detail_body(admin, idx, st="all", team="all", back_offset=0):
    raw = _fetch_support_requests(admin)
    filtered = [r for r in raw if _match_support_status(r, st) and _match_support_team(r, team)]

    body = [fix_tab._back_action("← Back to Support Requests", "remind_sup_back", {"st": st, "team": team, "offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(filtered):
        body.append({"type": "TextBlock", "text": "This request could not be found.", "wrap": True, "spacing": "Medium"})
        return body
    r = filtered[idx]
    st_val = (r.get("status") or "open").strip().lower()
    st_label = "🟢 Closed" if st_val == "closed" else "🔴 Open"
    body.append({"type": "TextBlock", "text": r.get("vul_name") or "General Request", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Status", "value": st_label},
            {"title": "Asset", "value": str(r.get("host_name") or "—")},
            {"title": "Team", "value": str(r.get("assigned_team") or "—")},
            {"title": "Requested By", "value": str(r.get("requested_by") or "—")},
            {"title": "Requested At", "value": str(r.get("requested_at") or "—")[:16].replace("T", " ")},
        ],
    })
    body.append({"type": "TextBlock", "text": "Message", "weight": "Bolder", "size": "Small", "spacing": "Medium"})
    body.append({"type": "TextBlock", "text": r.get("description") or "—", "wrap": True, "size": "Small"})
    return body


# ── Top-level entry point ────────────────────────────────────────────────

def reminder_tab_body(admin, active_sub="notif_sub_overdue", st="all", team="all", offset=0):
    body = [reminder_subnav_columnset(active_sub)]
    try:
        if active_sub == "notif_sub_support":
            body.extend(support_list_body(admin, st=st, team=team, offset=offset))
        else:
            bucket_key = _SUB_TO_BUCKET.get(active_sub, "overdue")
            body.extend(deadline_bucket_body(admin, bucket_key, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] reminder_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
