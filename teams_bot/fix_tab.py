"""
Fix tab content — All Assets / All Vulns / Common Vulns.

Built as native, clickable Adaptive Card elements (rows with a real "View"
Action.Submit button, Prev/Next pagination, and a drill-down detail card)
rather than the flat PNG snapshot the first version used — a picture has no
clickable regions, so "View" never actually did anything. This mirrors
Slack's own real Block Kit behaviour for the same tabs (see
users.views.SlackSlashCommandView._format_asset_list/_format_asset_vulns
for All Assets, and _group_common_vulns_by_team for Common Vulns) — same
data sources, same drill-down shape, just Adaptive Card JSON instead of
Block Kit blocks. Home/Team stay as PNG images (cards.dashboard_image_card_body)
since those don't have per-row interaction to begin with.
"""
import logging

from . import cards

logger = logging.getLogger(__name__)

PAGE_SIZE = 5

_SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}


def _status_label(status):
    st = (status or "open").strip().lower()
    if st == "closed":
        return "🟢 Closed"
    if "progress" in st:
        return "🟠 In Progress"
    if "review" in st:
        return "🟣 Open/Review"
    return "🔴 Open"


def _sev_dots_text(counts):
    parts = [f"{_SEV_ICON[k]} {k.title()}: {counts.get(k, 0)}" for k in ("critical", "high", "medium", "low") if counts.get(k, 0)]
    return "   ".join(parts) if parts else "No open vulnerabilities"


def _row(title_text, subtitle_text, action_id, value):
    """One clickable list row — title/subtitle on the left, a real 'View'
    button on the right (matches Slack's section+accessory-button rows)."""
    return {
        "type": "ColumnSet",
        "spacing": "Medium",
        "separator": True,
        "columns": [
            {
                "type": "Column", "width": "stretch",
                "items": [
                    {"type": "TextBlock", "text": title_text, "weight": "Bolder", "size": "Small", "wrap": True},
                    {"type": "TextBlock", "text": subtitle_text, "size": "Small", "isSubtle": True, "wrap": True, "spacing": "None"},
                ],
            },
            {
                "type": "Column", "width": "auto", "verticalContentAlignment": "Center",
                "items": [{
                    "type": "ActionSet",
                    "actions": [{"type": "Action.Submit", "title": "View ›", "data": {"action_id": action_id, **value}}],
                }],
            },
        ],
    }


def _pagination_body(offset, total, action_id, extra_value=None):
    extra_value = extra_value or {}
    start = offset + 1 if total else 0
    end = min(offset + PAGE_SIZE, total)
    body = [{"type": "TextBlock", "text": f"Showing {start}-{end} of {total}", "size": "Small", "isSubtle": True, "spacing": "Medium"}]
    actions = []
    if offset > 0:
        actions.append({"type": "Action.Submit", "title": "‹ Prev", "data": {"action_id": action_id, "offset": max(0, offset - PAGE_SIZE), **extra_value}})
    if offset + PAGE_SIZE < total:
        actions.append({"type": "Action.Submit", "title": "Next ›", "data": {"action_id": action_id, "offset": offset + PAGE_SIZE, **extra_value}})
    if actions:
        body.append({"type": "ActionSet", "actions": actions})
    return body


def _back_action(title, action_id, value):
    return {"type": "ActionSet", "actions": [{"type": "Action.Submit", "title": title, "data": {"action_id": action_id, **value}}]}


def _fetch_register_rows(admin):
    from adminregister.views import LatestSuperAdminVulnerabilityRegisterAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(LatestSuperAdminVulnerabilityRegisterAPIView, admin, method="get")
    if status_code >= 300 or not isinstance(data, dict):
        raise ValueError(f"register fetch failed: {status_code}")
    return data.get("rows") or []


def _group_assets(rows):
    assets = {}
    order = []
    for r in rows:
        host = (r.get("asset") or "Unknown").strip() or "Unknown"
        if host not in assets:
            assets[host] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "statuses": set()}
            order.append(host)
        sev = (r.get("severity") or "").strip().lower()
        if sev in assets[host]:
            assets[host][sev] += 1
        assets[host]["statuses"].add((r.get("status") or "open").strip().lower())
    result = []
    for host in order:
        info = assets[host]
        total = info["critical"] + info["high"] + info["medium"] + info["low"]
        statuses = info["statuses"]
        status = "closed" if statuses == {"closed"} else ("in_progress" if any("progress" in s for s in statuses) else "open")
        result.append({"host": host, "total": total, "status": status, "counts": info})
    return result


# ─── All Assets ─────────────────────────────────────────────────────────

def assets_list_body(admin, offset=0):
    rows = _fetch_register_rows(admin)
    assets = _group_assets(rows)
    total = len(assets)
    page = assets[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "💻 All Assets", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Every asset in your latest report. Tap View to see its vulnerabilities.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No assets found.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for a in page:
        subtitle = f"{a['total']} Vulns   ·   {_status_label(a['status'])}\n{_sev_dots_text(a['counts'])}"
        body.append(_row(f"🖥 {a['host']}", subtitle, "fix_asset_view", {"host": a["host"], "offset": offset}))
    body.extend(_pagination_body(offset, total, "fix_asset_pg"))
    return body


def asset_detail_body(admin, host, back_offset=0):
    rows = _fetch_register_rows(admin)
    # Keep each row's index in the FULL (unfiltered) list, not its position
    # within this host's own subset — "View" on a row needs to hand back an
    # idx that vuln_facts / asset_vuln_detail_body can look up again from
    # that same full list on the next click.
    host_rows = [(i, r) for i, r in enumerate(rows) if (r.get("asset") or "Unknown").strip() == host]

    body = [_back_action("← Back to All Assets", "fix_asset_back", {"offset": back_offset})]
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
        body.append(_row(name, subtitle, "fix_asset_vuln_view", {"idx": idx, "host": host, "offset": back_offset}))
    if len(host_rows) > 20:
        body.append({"type": "TextBlock", "text": f"+ {len(host_rows) - 20} more not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


# ─── All Vulns (flat list) ──────────────────────────────────────────────

def vulns_list_body(admin, offset=0):
    rows = _fetch_register_rows(admin)
    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "📋 All Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Every vulnerability in your latest report.", "size": "Small", "isSubtle": True, "wrap": True},
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
        body.append(_row(f"{_SEV_ICON[sev]} {name}", subtitle, "fix_vuln_view", {"idx": offset + i, "offset": offset}))
    body.extend(_pagination_body(offset, total, "fix_vuln_pg"))
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
                {"title": "OS", "value": str(r.get("operating_system") or "—")},
            ],
        },
    ]


def vuln_detail_body(admin, idx, back_offset=0):
    """Reached from the flat All Vulns list — Back returns there."""
    rows = _fetch_register_rows(admin)
    body = [_back_action("← Back to All Vulns", "fix_vuln_back", {"offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(rows):
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have changed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body
    body.extend(_vuln_facts_body(rows[idx]))
    return body


def asset_vuln_detail_body(admin, idx, host, back_offset=0):
    """Reached from an asset's own vulnerability list — Back returns to
    that asset's detail page, not the flat All Vulns list."""
    rows = _fetch_register_rows(admin)
    body = [_back_action(f"← Back to {host}", "fix_asset_vuln_back", {"host": host, "offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(rows):
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have changed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body
    body.extend(_vuln_facts_body(rows[idx]))
    return body


# ─── Common Vulns (team-scoped) ─────────────────────────────────────────

def _fetch_common_vulns_grouped(admin):
    from adminmitigationstrategy.views import MitigationStrategyByTeamAPIView
    from users.views import SlackSlashCommandView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(MitigationStrategyByTeamAPIView, admin, method="get")
    if status_code >= 300 or not isinstance(data, dict):
        raise ValueError(f"mitigation strategy fetch failed: {status_code}")
    return SlackSlashCommandView()._group_common_vulns_by_team(data)


def common_vulns_list_body(admin, team_key="config", offset=0):
    grouped = _fetch_common_vulns_grouped(admin)
    team = grouped.get(team_key) or {"display_name": dict(cards.COMMON_VULNS_TEAMS).get(team_key, team_key), "severity": {}, "vulns": []}
    vulns = team.get("vulns") or []
    sev = team.get("severity") or {}
    total = len(vulns)
    page = vulns[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "🧩 Common Vulnerabilities", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": "Vulnerabilities appearing on 4+ assets, by team.", "size": "Small", "isSubtle": True, "wrap": True},
        {
            "type": "TextBlock",
            "text": (f"{team.get('display_name', team_key)}  ·  Total Vulns: {total}\n"
                     f"🔴 Critical: {sev.get('critical', 0)}   🟠 High: {sev.get('high', 0)}   "
                     f"🟡 Medium: {sev.get('medium', 0)}   🟢 Low: {sev.get('low', 0)}"),
            "size": "Small", "weight": "Bolder", "wrap": True, "spacing": "Small",
        },
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "No common vulnerabilities for this team. Nothing appears on 4+ assets yet.", "size": "Small", "isSubtle": True, "spacing": "Medium", "wrap": True})
        return body
    for i, v in enumerate(page):
        vsev = (v.get("severity") or "medium").strip().lower()
        if vsev not in _SEV_ICON:
            vsev = "medium"
        asset_count = v.get("asset_count") or len(v.get("assets") or [])
        subtitle = f"💻 {asset_count} assets   ·   {_SEV_ICON[vsev]} {vsev.title()}"
        body.append(_row(v.get("name") or "Unnamed vulnerability", subtitle, "fix_common_vuln_view", {"team": team_key, "idx": offset + i, "offset": offset}))
    body.extend(_pagination_body(offset, total, "fix_common_vuln_pg", {"team": team_key}))
    return body


def common_vuln_detail_body(admin, team_key, idx, back_offset=0):
    grouped = _fetch_common_vulns_grouped(admin)
    team = grouped.get(team_key) or {"vulns": []}
    vulns = team.get("vulns") or []

    body = [_back_action("← Back to Common Vulns", "fix_common_vuln_back", {"team": team_key, "offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(vulns):
        body.append({"type": "TextBlock", "text": "This vulnerability could not be found — the report may have changed. Go back and try again.", "wrap": True, "spacing": "Medium"})
        return body
    v = vulns[idx]
    sev = (v.get("severity") or "medium").strip().lower()
    if sev not in _SEV_ICON:
        sev = "medium"
    assets = v.get("assets") or []
    body.append({"type": "TextBlock", "text": v.get("name") or "Unnamed vulnerability", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    body.append({"type": "TextBlock", "text": f"{_SEV_ICON[sev]} {sev.title()}   ·   Affects {len(assets)} asset(s)", "size": "Small", "weight": "Bolder", "spacing": "Small"})
    for a in assets[:15]:
        body.append({
            "type": "TextBlock",
            "text": f"🖥 {a.get('host') or '—'}   ·   {_status_label(a.get('status'))}   ·   port {a.get('port') or '—'}",
            "size": "Small", "wrap": True, "spacing": "Small",
        })
    if len(assets) > 15:
        body.append({"type": "TextBlock", "text": f"+ {len(assets) - 15} more not shown.", "size": "Small", "isSubtle": True, "spacing": "Small"})
    return body


# ─── Top-level entry point ──────────────────────────────────────────────

def fix_tab_body(admin, active_sub="fix_sub_assets", offset=0, common_team="config"):
    """Sub-nav row + that sub-tab's real (clickable) content."""
    body = [cards._fix_subnav_columnset(active_sub)]
    try:
        if active_sub == "fix_sub_vulns":
            body.extend(vulns_list_body(admin, offset=offset))
        elif active_sub == "fix_sub_common":
            body.append(cards._common_vulns_team_columnset(common_team))
            body.extend(common_vulns_list_body(admin, team_key=common_team, offset=offset))
        else:
            body.extend(assets_list_body(admin, offset=offset))
    except Exception:
        logger.exception(f"[TeamsBot] fix_tab_body failed for {active_sub}")
        body.append({"type": "TextBlock", "text": "Could not load this right now.", "wrap": True, "spacing": "Medium"})
    return body
