"""
Automations tab — Full / Partial automation coverage for the logged-in
admin's own latest report, scoped by report_id, read straight from the
AI-generated automation_card on each vulnerability_cards document (see
upload_report/mitigation_tool.py's Automation Engineer agent and
upload_report/views.py's VulnerabilityCardListView).

Real bug report: this used to classify Full/Partial from the OLD, human-
curated automation_scripts library's automation_possible field (matched
by plugin_id — a fixed ~63-plugin reference set that covers only a
handful of any real report's actual findings), AND had a genuine crash —
register_tab._fetch_script_stats(admin) returns a dict
({"stats": [...], "premium_required": ..., "message": ...}), not the list
this file iterated directly, so every load hit the dict's own KEYS
("stats", "premium_required", "message") as rows and blew up on the very
first `.get("plugin_id")` call — exactly the "Could not load this right
now." symptom seen live. Rebuilt to read every vulnerability on the
admin's own report via automation_card.automation_status instead, which
covers ALL of it, not just the curated 63.
"""
import logging

from . import cards
from . import fix_tab

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


def _fetch_automation_cards(admin):
    """
    Every vulnerability_cards document for the admin's own latest report
    (report_id resolved the same way fix_tab._fetch_register_data already
    does for Register/Fix), each carrying its own automation_card.
    automation_status ("full" | "partial" | "not_possible" | missing).
    """
    def _fetch():
        report_data = fix_tab._fetch_register_data(admin)
        report_id = report_data.get("report_id") if isinstance(report_data, dict) else None
        if not report_id:
            return []
        from upload_report.views import VulnerabilityCardListView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(
            VulnerabilityCardListView, admin, data={"report_id": report_id}, method="get",
        )
        if status_code >= 300 or not isinstance(data, dict):
            return []
        return data.get("cards") or []
    return fix_tab.cached_fetch(f"automation_cards:{admin.id}", 20, _fetch)


def _card_severity(card):
    automation = card.get("automation_card") or {}
    sev_val = (
        automation.get("severity")
        or (card.get("vaptcode_analysis") or {}).get("severity")
        or ""
    )
    return sev_val.strip().lower()


def _sev_filter_columnset(category, active_sev, counts):
    options = [(k, f"{label} {counts.get(k, 0)}") for k, label in SEV_FILTERS]
    return cards.pill_columnset(
        options, active_sev,
        lambda k: {"action_id": "auto_sev", "category": category, "sev": k, "offset": 0},
    )


def automation_list_body(admin, category="full", sev="all", offset=0):
    all_cards = _fetch_automation_cards(admin)
    target_status = "partial" if category == "partial" else "full"

    rows = [
        c for c in all_cards
        if (c.get("automation_card") or {}).get("automation_status") == target_status
    ]

    sev_counts = {
        "all": len(rows),
        "critical": sum(1 for c in rows if _card_severity(c) == "critical"),
        "high": sum(1 for c in rows if _card_severity(c) == "high"),
        "medium": sum(1 for c in rows if _card_severity(c) == "medium"),
        "low": sum(1 for c in rows if _card_severity(c) == "low"),
    }
    filtered = rows if sev == "all" else [c for c in rows if _card_severity(c) == sev]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]

    title = "✅ Fully Automated" if category == "full" else "🌓 Partially Automated"
    badge = "✅ Full" if category == "full" else "🌓 Partial"
    body = [
        {"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {
            "type": "TextBlock",
            "text": "Automation coverage for your latest report — from the AI-generated automation analysis on each vulnerability.",
            "size": "Small", "isSubtle": True, "wrap": True,
        },
        _sev_filter_columnset(category, sev, sev_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found for this filter.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for c in page:
        sn = _card_severity(c) or "medium"
        if sn not in _SEV_ICON:
            sn = "medium"
        name = c.get("vulnerability_name") or "Unknown"
        team = (c.get("assigned_team") or "").strip() or "—"
        host = (c.get("host_name") or "").strip()
        subtitle = f"{host + '   ·   ' if host else ''}Team: {team}   ·   {badge}"
        # Real gap: rows here were plain read-only text, unlike every other
        # list in the bot (Fix/Register/Common Vulns) which pairs each row
        # with a "View ›" button opening its own detail page — this tab
        # had automation_card data one click away with no way to actually
        # open it. fix_tab._row gives the same row+button layout those
        # other tabs already use; card_id + the current category/sev/
        # offset ride along in the button's value so Back can return to
        # this exact page (see auto_card_view/auto_list_pg in actions.py).
        body.append(fix_tab._row(
            f"{_SEV_ICON[sn]} {name}", subtitle, "auto_card_view",
            {"card_id": c.get("card_id"), "category": category, "sev": sev, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "auto_list_pg", {"category": category, "sev": sev}))
    return body


def automation_card_detail_body(admin, card_id, category="full", sev="all", offset=0):
    """One card's own full Automation Fix detail — reached via the 'View ›'
    button on automation_list_body's rows. Read-only for admin, same as
    every other admin drill-down (fix_tab._vuln_detail_full_body)."""
    back_value = {"category": category, "sev": sev, "offset": offset}
    body = [fix_tab._back_action("← Back to list", "auto_list_pg", back_value)]

    all_cards = _fetch_automation_cards(admin)
    card = next((c for c in all_cards if c.get("card_id") == card_id), None)
    if not card:
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have refreshed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body

    name = card.get("vulnerability_name") or "Unknown"
    team = (card.get("assigned_team") or "").strip() or "—"
    host = (card.get("host_name") or "").strip() or "—"
    body.append({"type": "TextBlock", "text": name, "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Asset", "value": host},
            {"title": "Team", "value": team},
        ],
    })

    automation = fix_tab.shape_automation_detail(card)
    body.extend(fix_tab._automation_fix_body(automation, admin=admin))
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
