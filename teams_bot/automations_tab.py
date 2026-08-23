"""
Automations tab — Full / Partial automation coverage, classified from the
automation-scripts library's automation_possible field, scoped to the
plugin_ids in the admin's own report(s) (same stats source as Register's
Script sub-tab). Mirrors users.views.SlackSlashCommandView.
_automation_subtab_blocks / _format_automation_tab — read-only list, no
per-row detail click (Slack doesn't have one here either).
"""
import logging

from . import cards
from . import fix_tab
from . import register_tab

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
_SEV_ICON = fix_tab._SEV_ICON

AUTOMATION_SUBTABS = [
    ("auto_sub_full", "✅ Full"),
    ("auto_sub_partial", "🌓 Partial"),
]

SEV_FILTERS = [("all", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]


def automation_subnav_columnset(active_sub):
    return cards.pill_columnset(AUTOMATION_SUBTABS, active_sub, lambda k: {"action_id": k})


def _classify(raw_value):
    """"Yes"/"Yes [100%]" -> full. Anything containing "Partial" -> partial
    (covers conditional strings like "Yes (if X unused) / Partial (if X in
    use)"). Missing/blank -> None, excluded from both tabs rather than
    guessed — same rule as Slack's _classify_automation_possible."""
    text = (raw_value or "").strip().lower()
    if not text:
        return None
    if "partial" in text:
        return "partial"
    if text.startswith("yes"):
        return "full"
    return None


def _fetch_category_by_plugin(admin):
    def _fetch():
        from automation_scripts_api import views as auto_views
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(auto_views.admin_list_scripts, admin, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            return {}
        category_by_plugin = {}
        for s in data.get("scripts") or []:
            pid = s.get("plugin_id")
            if pid is None:
                continue
            try:
                pid = int(pid)
            except (TypeError, ValueError):
                continue
            if pid in category_by_plugin:
                continue
            cat = _classify(s.get("automation_possible"))
            if cat:
                category_by_plugin[pid] = cat
        return category_by_plugin
    # Library-wide, not admin/report scoped — but keyed by admin id anyway
    # for a simple, consistent cache-key shape with everything else here.
    return fix_tab.cached_fetch(f"category_by_plugin:{admin.id}", 30, _fetch)


def _sev_filter_columnset(category, active_sev, counts):
    options = [(k, f"{label} {counts.get(k, 0)}") for k, label in SEV_FILTERS]
    return cards.pill_columnset(
        options, active_sev,
        lambda k: {"action_id": "auto_sev", "category": category, "sev": k, "offset": 0},
    )


def automation_list_body(admin, category="full", sev="all", offset=0):
    stats = register_tab._fetch_script_stats(admin)
    category_by_plugin = _fetch_category_by_plugin(admin)

    def _norm_sev(v):
        return (v.get("severity") or "").strip().lower()

    rows = []
    for s in stats:
        pid = s.get("plugin_id")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            continue
        if category_by_plugin.get(pid) == category:
            rows.append(s)

    sev_counts = {
        "all": len(rows),
        "critical": sum(1 for v in rows if _norm_sev(v) == "critical"),
        "high": sum(1 for v in rows if _norm_sev(v) == "high"),
        "medium": sum(1 for v in rows if _norm_sev(v) == "medium"),
        "low": sum(1 for v in rows if _norm_sev(v) == "low"),
    }
    filtered = rows if sev == "all" else [v for v in rows if _norm_sev(v) == sev]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]

    title = "✅ Fully Automated" if category == "full" else "🌓 Partially Automated"
    badge = "✅ Full" if category == "full" else "🌓 Partial [50%]"
    body = [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Automation coverage by severity — classified from the automation library's Automation Possible field.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset(category, sev, sev_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No scripts found for this filter.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for s in page:
        sn = _norm_sev(s) or "medium"
        if sn not in _SEV_ICON:
            sn = "medium"
        name = s.get("vulnerability") or "Unknown"
        team = (s.get("team") or "").strip() or "—"
        subtitle = f"Team: {team}   ·   {badge}"
        body.append({
            "type": "Container", "spacing": "Medium", "separator": True,
            "items": [
                {"type": "TextBlock", "text": f"{_SEV_ICON[sn]} {name}", "weight": "Bolder", "size": "Small", "wrap": True},
                {"type": "TextBlock", "text": subtitle, "size": "Small", "isSubtle": True, "spacing": "None"},
            ],
        })
    body.extend(fix_tab._pagination_body(offset, total, "auto_list_pg", {"category": category, "sev": sev}))
    return body


def automations_tab_body(admin, active_sub="auto_sub_full", sev="all", offset=0):
    body = [automation_subnav_columnset(active_sub)]
    category = "partial" if active_sub == "auto_sub_partial" else "full"
    try:
        body.extend(automation_list_body(admin, category=category, sev=sev, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] automations_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
