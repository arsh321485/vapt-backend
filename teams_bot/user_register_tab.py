"""
User-side Register tab — Register (severity+status filterable, team-scoped
vuln list, clicking a row opens the same Manual/Auto Fix + Mark Mitigated
detail user_fix_tab.py already built) and Scripts (automation scripts
library — members get a real Download button, admin's own equivalent is
stats-only/read-only, see register_tab.py's docstring + memory note that
only members may download scripts).
"""
import logging

from . import cards
from . import fix_tab
from . import user_fix_tab as fix

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
_SEV_ICON = fix_tab._SEV_ICON

UREG_SUBTABS = [
    ("ureg_sub_register", "📋 Register"),
    ("ureg_sub_scripts",  "📜 Scripts"),
]
SEV_FILTERS = [("all", "All"), ("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
STATUS_FILTERS = [("all", "All"), ("open", "Open"), ("closed", "Closed"), ("in_progress", "In Progress")]


def register_subnav_columnset(active_sub):
    return cards.pill_columnset(UREG_SUBTABS, active_sub, lambda k: {"action_id": k})


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


def _sev_filter_columnset(active_sev, active_st):
    return cards.pill_columnset(
        SEV_FILTERS, active_sev,
        lambda k: {"action_id": "ureg_sev", "sev": k, "st": active_st, "offset": 0},
    )


def _status_filter_columnset(active_sev, active_st, counts):
    options = [(k, f"{label} {counts.get(k, 0)}") for k, label in STATUS_FILTERS]
    return cards.pill_columnset(
        options, active_st,
        lambda k: {"action_id": "ureg_st", "sev": active_sev, "st": k, "offset": 0},
    )


def register_list_body(member_user, team_name, sev="all", st="all", offset=0):
    rows = fix._fetch_team_rows(member_user, team_name)
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
        {"type": "TextBlock", "text": f"Every vulnerability assigned to {team_name}, with status and remediation actions.", "size": "Small", "isSubtle": True, "wrap": True},
        _sev_filter_columnset(sev, st),
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
            f"{_SEV_ICON[rsev]} {name}", subtitle, "ureg_view",
            {"idx": idx, "sev": sev, "st": st, "offset": offset},
        ))
    body.extend(fix_tab._pagination_body(offset, total, "ureg_view_pg", {"sev": sev, "st": st}))
    return body


def register_vuln_detail_body(member_user, team_name, idx, sub="manual", sev="all", st="all", offset=0):
    """Same detail (facts + Manual/Auto toggle + Mark Mitigated + Request
    Extension) as the Fix tab's own vuln detail — Register is just a
    differently-filtered entry point into the identical rows."""
    return fix.vuln_detail_body(
        member_user, team_name, idx, ctx="register", offset=offset, sub=sub,
        extra_value={"sev": sev, "st": st},
        back_action_id="ureg_view_back", back_title="← Back to Register",
    )


# ─── Scripts sub-tab (real download, member-only) ───────────────────────

def _fetch_script_stats(member_user):
    def _fetch():
        from automation_scripts_api import views as auto_views
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(auto_views.user_download_stats, member_user, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"script stats fetch failed: {status_code}")
        return data.get("stats") or []
    return fix_tab.cached_fetch(f"user_script_stats:{member_user.id}", 20, _fetch)


def _script_download_url(team_id, team_name, plugin_id):
    import time
    from urllib.parse import quote
    from django.conf import settings
    from users.views import _dashboard_image_signer

    token = _dashboard_image_signer().sign(team_id)
    backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
    return (
        f"{backend}/api/admin/users/teams/script-download/?token={quote(token)}"
        f"&team={quote(team_name)}&plugin_id={plugin_id}&t={int(time.time())}"
    )


def script_list_body(member_user, team_id, team_name, offset=0):
    stats = _fetch_script_stats(member_user)
    total = len(stats)
    page = stats[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📜 Scripts", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Automation scripts library — download the ones for your team.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No scripts found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for s in page:
        sev = (s.get("severity") or "").strip().lower() or "medium"
        if sev not in _SEV_ICON:
            sev = "medium"
        name = s.get("vulnerability") or "Unknown"
        plugin_id = s.get("plugin_id")
        downloads = s.get("download_count", 0)
        items = [
            {"type": "TextBlock", "text": f"{_SEV_ICON[sev]} {name}", "weight": "Bolder", "size": "Small", "wrap": True},
            {"type": "TextBlock", "text": f"Downloads: {downloads}", "size": "Small", "isSubtle": True, "spacing": "None"},
        ]
        if plugin_id:
            items.append({
                "type": "ActionSet", "spacing": "Small",
                "actions": [{"type": "Action.OpenUrl", "title": "📥 Download", "url": _script_download_url(team_id, team_name, plugin_id)}],
            })
        body.append({"type": "Container", "spacing": "Medium", "separator": True, "items": items})
    body.extend(fix_tab._pagination_body(offset, total, "ureg_script_pg"))
    return body


def register_tab_body(member_user, team_id, team_name, active_sub="ureg_sub_register", sev="all", st="all", offset=0):
    body = [register_subnav_columnset(active_sub)]
    try:
        if active_sub == "ureg_sub_scripts":
            body.extend(script_list_body(member_user, team_id, team_name, offset=offset))
        else:
            body.extend(register_list_body(member_user, team_name, sev=sev, st=st, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] user register_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
