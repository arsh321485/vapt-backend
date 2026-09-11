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


def register_vuln_detail_body(member_user, team_id, team_name, idx, sub="manual", sev="all", st="all", offset=0, step_number=None):
    """Same detail (facts + Manual/Auto toggle + Mark Mitigated + Request
    Extension) as the Fix tab's own vuln detail — Register is just a
    differently-filtered entry point into the identical rows."""
    return fix.vuln_detail_body(
        member_user, team_id, team_name, idx, ctx="register", offset=offset, sub=sub,
        extra_value={"sev": sev, "st": st}, step_number=step_number,
        back_action_id="ureg_view_back", back_title="← Back to Register",
    )


# ─── Scripts sub-tab (real download, member-only) ───────────────────────
#
# Real bug report: this used to list ONLY the curated ~63-plugin
# automation_scripts library (matched by plugin_id via user_download_stats)
# — a real report's vulnerabilities are overwhelmingly OUTSIDE that fixed
# set, so a member's own team usually saw just 1-3 scripts here no matter
# how much automation the AI had actually generated for their vulnerabilities.
# Rebuilt to list every vulnerability_cards.automation_card the member's
# team owns (full or partial) — same source automations_tab.py and the Fix
# tab's own Automation Fix button already use — with a real Download button
# routed through TeamsAIScriptDownloadView (card_id-based), not the old
# plugin_id-based curated download.

def script_list_body(member_user, team_id, team_name, offset=0):
    data = fix._fetch_team_data(member_user, team_name)
    report_id = data.get("report_id") if isinstance(data, dict) else None

    all_cards = fix_tab._fetch_automation_cards_for_report(member_user, report_id, as_member=True) if report_id else []
    rows = [c for c in all_cards if (c.get("automation_card") or {}).get("automation_status") in ("full", "partial")]
    # A card missing automation entirely on a Freemium admin comes back
    # from UserVulnerabilityCardListAPIView shaped like
    # upload_report/views.py's _freemium_automation_placeholder() —
    # {"premium_required": True, ...} — same signal used here.
    premium_required = any((c.get("automation_card") or {}).get("premium_required") for c in all_cards)

    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📜 Scripts", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "AI-generated automation scripts for your team's vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if premium_required and not rows:
        body.append({
            "type": "TextBlock",
            "text": "🔒 Automation scripts are a Premium/Custom feature — ask your admin to upgrade to generate them for your team's vulnerabilities.",
            "wrap": True, "weight": "Bolder", "color": "attention", "spacing": "Medium",
        })
        return body
    if not page:
        body.append({"type": "TextBlock", "text": "No automation scripts available for your team yet.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for c in page:
        automation = c.get("automation_card") or {}
        sev = (automation.get("severity") or (c.get("vaptcode_analysis") or {}).get("severity") or "").strip().lower() or "medium"
        if sev not in _SEV_ICON:
            sev = "medium"
        name = c.get("vulnerability_name") or "Unknown"
        downloads = automation.get("download_count", 0)
        host = (c.get("host_name") or "").strip()
        badge = "✅ Full" if automation.get("automation_status") == "full" else "🌓 Partial"
        # Real bug report: the same vulnerability name legitimately appears
        # once per affected asset (a separate card each) — without the
        # host shown, these looked like exact duplicate rows. Explicit
        # product request: this is a read-only overview list now — no
        # inline Download button here (downloading happens from the
        # vulnerability's own Automation Fix detail page instead, matching
        # the website's Script list, which has no per-row download button
        # either).
        subtitle = f"{(host + '   ·   ') if host else ''}{badge}   ·   Downloads: {downloads}"
        items = [
            {"type": "TextBlock", "text": f"{_SEV_ICON[sev]} {name}", "weight": "Bolder", "size": "Small", "wrap": True},
            {"type": "TextBlock", "text": subtitle, "size": "Small", "isSubtle": True, "spacing": "None"},
        ]
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
