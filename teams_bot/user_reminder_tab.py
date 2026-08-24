"""
User-side Reminder tab — Overdue / Due Today / This Week / Next Week
deadline buckets, team-scoped. Mirrors SlackSlashCommandView.
_team_reminder_subtab_blocks / _bucket_deadline_rows / _parse_rc_days
exactly (same RiskCriteria-SLA-days-minus-elapsed-calendar-days formula) —
copied here rather than imported since those are bound instance methods
on SlackSlashCommandView with no natural non-Slack home yet.
"""
import logging
import re as _re
from datetime import datetime, timezone as _tz

from . import cards
from . import fix_tab
from . import user_fix_tab as fix

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
_SEV_ICON = fix_tab._SEV_ICON

UREM_SUBTABS = [
    ("urem_sub_overdue",  "🔴 Overdue"),
    ("urem_sub_today",    "🟠 Due Today"),
    ("urem_sub_thisweek", "🟡 This Week"),
    ("urem_sub_nextweek", "🟢 Next Week"),
]

_BUCKET_LABEL = {"overdue": "🔴 Overdue", "today": "🟠 Due Today", "thisweek": "🟡 This Week", "nextweek": "🟢 Next Week"}
_BUCKET_KEY = {
    "urem_sub_today": "today", "urem_sub_thisweek": "thisweek", "urem_sub_nextweek": "nextweek",
}


def reminder_subnav_columnset(active_sub):
    return cards.pill_columnset(UREM_SUBTABS, active_sub, lambda k: {"action_id": k})


def _parse_rc_days(raw_value):
    if raw_value is None:
        return None
    text = str(raw_value).strip().lower()
    if not text:
        return None
    if text.isdigit():
        return int(text)
    total_days = 0
    matched = False
    week_match = _re.search(r"(\d+)\s*week", text)
    if week_match:
        total_days += int(week_match.group(1)) * 7
        matched = True
    day_match = _re.search(r"(\d+)\s*day|day\s*(\d+)", text)
    if day_match:
        num = day_match.group(1) or day_match.group(2)
        total_days += int(num)
        matched = True
    return total_days if matched else None


def _bucket_deadline_rows(rows, rc_days):
    buckets = {"overdue": [], "today": [], "thisweek": [], "nextweek": []}
    today = datetime.now(_tz.utc).date()
    for row in rows:
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
        row_out = dict(row, remaining_days=remaining_days)
        if remaining_days < 0:
            buckets["overdue"].append(row_out)
        elif remaining_days == 0:
            buckets["today"].append(row_out)
        elif 1 <= remaining_days <= 6:
            buckets["thisweek"].append(row_out)
        elif 7 <= remaining_days <= 13:
            buckets["nextweek"].append(row_out)
    return buckets


def _fetch_buckets(member_user, team_name):
    def _fetch():
        from userrisk_criteria.views import UserRiskCriteriaListView
        from .actions import _call_view_in_process

        rows = fix._fetch_team_rows(member_user, team_name)
        status_code, rc_data = _call_view_in_process(UserRiskCriteriaListView, member_user, method="get")
        rc_list = (rc_data.get("risk_criteria") or []) if (status_code < 300 and isinstance(rc_data, dict)) else []
        if not rc_list:
            return None
        rc = rc_list[0]
        rc_days = {
            "critical": _parse_rc_days(rc.get("critical")),
            "high": _parse_rc_days(rc.get("high")),
            "medium": _parse_rc_days(rc.get("medium")),
            "low": _parse_rc_days(rc.get("low")),
        }
        return _bucket_deadline_rows(rows, rc_days)
    return fix_tab.cached_fetch(f"user_reminder_buckets:{member_user.id}:{team_name}", 30, _fetch)


def reminder_list_body(member_user, team_name, sub_action_id="urem_sub_overdue", offset=0):
    bucket_key = _BUCKET_KEY.get(sub_action_id, "overdue")
    buckets = _fetch_buckets(member_user, team_name)
    body = [reminder_subnav_columnset(sub_action_id)]
    if buckets is None:
        body.append({"type": "TextBlock", "text": "❌ No Risk Criteria configured yet for your admin.", "wrap": True, "spacing": "Medium"})
        return body

    rows = buckets[bucket_key]
    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]
    body.append({"type": "TextBlock", "text": _BUCKET_LABEL[bucket_key], "weight": "Bolder", "size": "Medium", "spacing": "Medium"})
    body.append({"type": "TextBlock", "text": f"{team_name} — {total} vulnerability(ies).", "size": "Small", "isSubtle": True, "wrap": True})
    if not page:
        body.append({"type": "TextBlock", "text": "Nothing here.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for r in page:
        sev = (r.get("severity") or "medium").strip().lower()
        if sev not in _SEV_ICON:
            sev = "medium"
        name = r.get("vul_name") or "Unnamed vulnerability"
        host = r.get("asset") or "—"
        remaining = r.get("remaining_days", 0)
        due_text = f"{abs(remaining)}d overdue" if remaining < 0 else ("Due today" if remaining == 0 else f"{remaining}d left")
        body.append({
            "type": "Container", "spacing": "Medium", "separator": True,
            "items": [
                {"type": "TextBlock", "text": f"{_SEV_ICON[sev]} {name}", "weight": "Bolder", "size": "Small", "wrap": True},
                {"type": "TextBlock", "text": f"{host}   ·   {due_text}", "size": "Small", "isSubtle": True, "spacing": "None"},
            ],
        })
    body.extend(fix_tab._pagination_body(offset, total, "urem_pg", {"sub": sub_action_id}))
    return body
