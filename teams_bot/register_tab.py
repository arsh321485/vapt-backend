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


def register_vuln_detail_body(admin, idx, sub="manual", sev="all", st="all", offset=0):
    return fix_tab._vuln_detail_full_body(
        admin, idx, sub=sub, ctx="register", offset=offset,
        back_action_id="reg_view_back", back_title="← Back to Register",
        extra_value={"sev": sev, "st": st},
    )


# ─── Script sub-tab ──────────────────────────────────────────────────────

def _fetch_script_stats(admin):
    def _fetch():
        from automation_scripts_api import views as auto_views
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(auto_views.admin_download_stats, admin, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"script stats fetch failed: {status_code}")
        return data.get("stats") or []
    return fix_tab.cached_fetch(f"script_stats:{admin.id}", 20, _fetch)


def script_list_body(admin, offset=0):
    stats = _fetch_script_stats(admin)
    total = len(stats)
    page = stats[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📜 Script", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Automation scripts library — downloads and assigned team.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No scripts found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for i, s in enumerate(page):
        sev = (s.get("severity") or "").strip().lower() or "medium"
        if sev not in _SEV_ICON:
            sev = "medium"
        name = s.get("vulnerability") or "Unknown"
        downloads = s.get("download_count", 0)
        team = (s.get("team") or "—").strip() or "—"
        subtitle = f"Downloads: {downloads}   ·   Team: {team}"
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
