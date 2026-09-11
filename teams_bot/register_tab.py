"""
Register tab — Register (severity+status filterable vuln list, clicking a
row opens the SAME Manual/Automation Fix detail the Fix tab uses — Slack's
own reg_view_ handler reuses _allvuln_detail_blocks the exact same way, see
users.views.SlackSlashCommandView._format_register_tab) and Script (read-
only automation-scripts download stats, mirrors _format_script_tab).
"""
import logging

from . import cards
from . import fix_tab

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
_SEV_ICON = fix_tab._SEV_ICON

REGISTER_SUBTABS = [
    ("reg_sub_register", "📋 Register"),
    ("reg_sub_script", "📜 Script"),
]

SEV_FILTERS = [("all", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
STATUS_FILTERS = [("all", "All"), ("open", "Open"), ("closed", "Closed"), ("in_progress", "In Progress")]


def register_subnav_columnset(active_sub):
    return cards.pill_columnset(REGISTER_SUBTABS, active_sub, lambda k: {"action_id": k})


def _norm_sev(r):
    return (r.get("severity") or "").strip().lower()


def _norm_status(r):
    return (r.get("status") or "open").strip().lower()


def _match_sev(r, sev):
    return sev == "all" or _norm_sev(r) == sev


def _match_status(r, st):
    s = _norm_status(r)
    if st == "all":
        return True
    if st == "in_progress":
        return "progress" in s
    if st == "open":
        return s == "open" or s.startswith("open/")
    if st == "closed":
        return s == "closed"
    return s == st


def _sev_filter_columnset(active_sev, active_st, offset):
    return cards.pill_columnset(
        SEV_FILTERS, active_sev,
        lambda k: {"action_id": "reg_sev", "sev": k, "st": active_st, "offset": 0},
    )


def _status_filter_columnset(active_sev, active_st, counts):
    options = [(k, f"{label} {counts.get(k, 0)}") for k, label in STATUS_FILTERS]
    return cards.pill_columnset(
        options, active_st,
        lambda k: {"action_id": "reg_st", "sev": active_sev, "st": k, "offset": 0},
    )


def register_list_body(admin, sev="all", st="all", offset=0):
    rows = fix_tab._fetch_register_rows(admin)
    # Keep the index into the FULL unfiltered list — "View" needs to hand
    # back an idx the shared vuln-detail body can resolve later, same
    # reasoning as fix_tab.asset_detail_body.
    st_base = [r for r in rows if _match_sev(r, sev)]
    st_counts = {
        "all": len(st_base),
        "open": sum(1 for r in st_base if _norm_status(r) == "open" or _norm_status(r).startswith("open/")),
        "closed": sum(1 for r in st_base if _norm_status(r) == "closed"),
        "in_progress": sum(1 for r in st_base if "progress" in _norm_status(r)),
    }

    filtered = [(i, r) for i, r in enumerate(rows) if _match_sev(r, sev) and _match_status(r, st)]
    total = len(filtered)
    page = filtered[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📋 Register", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "All vulnerabilities in your latest report with status and remediation actions.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset(sev, st, offset),
        _status_filter_columnset(sev, st, st_counts),
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body

    for idx, r in page:
        name = r.get("vul_name") or "Unnamed vulnerability"
        rsev = _norm_sev(r) or "medium"
        if rsev not in _SEV_ICON:
            rsev = "medium"
        host = r.get("asset") or "—"
        status = r.get("status") or "open"
        subtitle = f"{host}   ·   {fix_tab._status_label(status)}"
        body.append(fix_tab._row(
            f"{_SEV_ICON[rsev]} {name}", subtitle, "reg_view",
            {"idx": idx, "sev": sev, "st": st, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "reg_view_pg", {"sev": sev, "st": st}))
    return body


def register_vuln_detail_body(admin, idx, sub="manual", sev="all", st="all", offset=0, step_number=None):
    return fix_tab._vuln_detail_full_body(
        admin, idx, sub=sub, ctx="register", offset=offset, step_number=step_number,
        back_action_id="reg_view_back", back_title="← Back to Register",
        extra_value={"sev": sev, "st": st},
    )


# ─── Script sub-tab ──────────────────────────────────────────────────────
#
# Same rebuild as user_register_tab.py's Scripts sub-tab — was scoped to
# the curated ~63-plugin automation_scripts library (admin_download_stats),
# now reads every vulnerability_cards.automation_card for the admin's own
# report. Read-only for admin (no Download button), matching the rest of
# this file's admin-is-read-only convention.

def script_list_body(admin, offset=0):
    report_data = fix_tab._fetch_register_data(admin)
    report_id = report_data.get("report_id") if isinstance(report_data, dict) else None

    all_cards = fix_tab._fetch_automation_cards_for_report(admin, report_id) if report_id else []
    rows = [c for c in all_cards if (c.get("automation_card") or {}).get("automation_status") in ("full", "partial")]
    premium_required = any((c.get("automation_card") or {}).get("premium_required") for c in all_cards)

    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📜 Script", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "AI-generated automation scripts across your latest report.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if premium_required and not rows:
        body.append({
            "type": "TextBlock",
            "text": "🔒 Automation scripts are a Premium/Custom feature — upgrade your plan to generate them for your report's vulnerabilities.",
            "wrap": True, "weight": "Bolder", "color": "attention", "spacing": "Medium",
        })
        # Same parity fix as fix_tab.py's _automation_fix_body — Slack's
        # equivalent lock notice always ships with an "Upgrade to Premium"
        # button, Teams only had the text.
        body.append({
            "type": "ActionSet",
            "spacing": "Small",
            "actions": [{
                "type": "Action.OpenUrl",
                "title": "⭐ Upgrade to Premium",
                "url": cards.pricing_url(admin),
                "style": "positive",
            }],
        })
        return body
    if not page:
        body.append({"type": "TextBlock", "text": "No automation scripts generated yet.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for c in page:
        automation = c.get("automation_card") or {}
        sev = (automation.get("severity") or (c.get("vaptcode_analysis") or {}).get("severity") or "").strip().lower() or "medium"
        if sev not in _SEV_ICON:
            sev = "medium"
        name = c.get("vulnerability_name") or "Unknown"
        downloads = automation.get("download_count", 0)
        team = (c.get("assigned_team") or "—").strip() or "—"
        badge = "✅ Full" if automation.get("automation_status") == "full" else "🌓 Partial"
        subtitle = f"{badge}   ·   Downloads: {downloads}   ·   Team: {team}"
        body.append({
            "type": "Container", "spacing": "Medium", "separator": True,
            "items": [
                {"type": "TextBlock", "text": f"{_SEV_ICON[sev]} {name}", "weight": "Bolder", "size": "Small", "wrap": True},
                {"type": "TextBlock", "text": subtitle, "size": "Small", "isSubtle": True, "spacing": "None"},
            ],
        })
    body.extend(fix_tab._pagination_body(offset, total, "script_pg"))
    return body


# ─── Top-level entry point ──────────────────────────────────────────────

def register_tab_body(admin, active_sub="reg_sub_register", sev="all", st="all", offset=0):
    body = [register_subnav_columnset(active_sub)]
    try:
        if active_sub == "reg_sub_script":
            body.extend(script_list_body(admin, offset=offset))
        else:
            body.extend(register_list_body(admin, sev=sev, st=st, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] register_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
