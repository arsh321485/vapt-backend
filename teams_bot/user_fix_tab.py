"""
User-side Fix tab — All Assets / All Vulns, team-scoped. Mirrors
teams_bot.fix_tab (admin side) almost exactly — same row/pagination/detail
layout, same field names (both admin's LatestSuperAdminVulnerabilityRegisterAPIView
and this one's UserLatestVulnerabilityRegisterAPIView return the identical
vul_name/asset/severity/port/protocol/status shape) — reuses fix_tab's
generic row-building helpers directly rather than duplicating them.
Common Vulns (the 3rd Slack sub-tab, tfix_sub_common) isn't wired yet.
"""
import logging

from . import cards
from .fix_tab import (
    _row, _pagination_body, _back_action, _sev_dots_text, _status_label,
    _SEV_ICON, cached_fetch, _group_assets, PAGE_SIZE,
)

logger = logging.getLogger(__name__)

UFIX_SUBTABS = [
    ("ufix_sub_assets", "🖥 All Assets"),
    ("ufix_sub_vulns",  "📋 All Vulns"),
]


def _fix_subnav_columnset(active_sub):
    return cards.pill_columnset(UFIX_SUBTABS, active_sub, lambda action_id: {"action_id": action_id})


def _fetch_team_rows(member_user, team_name):
    def _fetch():
        from userregister.views import UserLatestVulnerabilityRegisterAPIView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(
            UserLatestVulnerabilityRegisterAPIView, member_user, method="get", data={"team": team_name},
        )
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"user register fetch failed: {status_code}")
        return data.get("rows") or []
    return cached_fetch(f"user_register_rows:{member_user.id}:{team_name}", 20, _fetch)


def assets_list_body(member_user, team_name, offset=0):
    rows = _fetch_team_rows(member_user, team_name)
    assets = _group_assets(rows)
    total = len(assets)
    page = assets[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "💻 All Assets", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Assets assigned to {team_name}. Tap View to see its vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No assets found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for a in page:
        subtitle = f"{a['total']} Vulns   ·   {_status_label(a['status'])}\n{_sev_dots_text(a['counts'])}"
        body.append(_row(f"🖥 {a['host']}", subtitle, "ufix_asset_view", {"host": a["host"], "offset": offset}))
    body.extend(_pagination_body(offset, total, "ufix_asset_pg"))
    return body


def asset_detail_body(member_user, team_name, host, back_offset=0):
    rows = _fetch_team_rows(member_user, team_name)
    host_rows = [(i, r) for i, r in enumerate(rows) if (r.get("asset") or "Unknown").strip() == host]

    body = [_back_action("← Back to All Assets", "ufix_asset_back", {"offset": back_offset})]
    body.append({"type": "TextBlock", "text": f"🖥 {host}", "weight": "Bolder", "size": "Medium", "spacing": "Medium", "wrap": True})
    body.append({"type": "TextBlock", "text": f"{len(host_rows)} vulnerabilities on this asset.", "size": "Small", "isSubtle": True})
    if not host_rows:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for idx, r in host_rows[:20]:
        name = r.get("vul_name") or "Unnamed vulnerability"
        sev = (r.get("severity") or "medium").strip().lower()
        if sev not in _SEV_ICON:
            sev = "medium"
        status = r.get("status") or "open"
        subtitle = f"{_SEV_ICON[sev]} {sev.title()}   ·   {_status_label(status)}"
        body.append(_row(name, subtitle, "ufix_asset_vuln_view", {"idx": idx, "host": host, "offset": back_offset}))
    if len(host_rows) > 20:
        body.append({"type": "TextBlock", "text": f"+ {len(host_rows) - 20} more not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


def vulns_list_body(member_user, team_name, offset=0):
    rows = _fetch_team_rows(member_user, team_name)
    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📋 All Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Every vulnerability assigned to {team_name}.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No vulnerabilities found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for i, r in enumerate(page):
        name = r.get("vul_name") or "Unnamed vulnerability"
        sev = (r.get("severity") or "medium").strip().lower()
        if sev not in _SEV_ICON:
            sev = "medium"
        host = r.get("asset") or "—"
        status = r.get("status") or "open"
        subtitle = f"{host}   ·   {_status_label(status)}"
        body.append(_row(f"{_SEV_ICON[sev]} {name}", subtitle, "ufix_vuln_view", {"idx": offset + i, "offset": offset}))
    body.extend(_pagination_body(offset, total, "ufix_vuln_pg"))
    return body


def _vuln_facts_body(r):
    sev = (r.get("severity") or "medium").strip().lower()
    if sev not in _SEV_ICON:
        sev = "medium"
    status = r.get("status") or "open"
    return [
        {"type": "TextBlock", "text": r.get("vul_name") or "Unnamed vulnerability", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"},
        {
            "type": "FactSet",
            "facts": [
                {"title": "Asset", "value": str(r.get("asset") or "—")},
                {"title": "Severity", "value": f"{_SEV_ICON[sev]} {sev.title()}"},
                {"title": "Status", "value": _status_label(status)},
                {"title": "Port", "value": str(r.get("port") or "—")},
                {"title": "Protocol", "value": str(r.get("protocol") or "—")},
            ],
        },
    ]


def vuln_detail_body(member_user, team_name, idx, back_action_id, back_value):
    rows = _fetch_team_rows(member_user, team_name)
    if idx is None or idx < 0 or idx >= len(rows):
        return [
            _back_action("← Back", back_action_id, back_value),
            {"type": "TextBlock", "text": "This vulnerability is no longer available (the report may have refreshed).", "size": "Small", "isSubtle": True, "wrap": True, "spacing": "Medium"},
        ]
    body = [_back_action("← Back", back_action_id, back_value)]
    body.extend(_vuln_facts_body(rows[idx]))
    return body


def fix_tab_body(member_user, team_name, sub_action_id="ufix_sub_assets", offset=0):
    body = [_fix_subnav_columnset(sub_action_id)]
    if sub_action_id == "ufix_sub_vulns":
        body.extend(vulns_list_body(member_user, team_name, offset=offset))
    else:
        body.extend(assets_list_body(member_user, team_name, offset=offset))
    return body
