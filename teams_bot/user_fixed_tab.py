"""
User-side Fixed tab — closed/mitigated vulnerabilities for the member's
own team. Mirrors SlackSlashCommandView._get_team_fixed_rows/
_format_team_fixed_list: calls UserClosedVulnerabilitiesAPIView (which
returns closed vulns across ALL the member's teams, no ?team= filter) and
filters client-side to `assigned_team == team_name`, same as Slack does.
"""
import logging

from . import cards
from . import fix_tab
from . import user_fix_tab as fix_detail

logger = logging.getLogger(__name__)

PAGE_SIZE = 5
_SEV_ICON = fix_tab._SEV_ICON


def _fetch_closed(member_user, team_name):
    def _fetch():
        from userregister.views import UserClosedVulnerabilitiesAPIView
        from .actions import _call_view_in_process
        status_code, data = _call_view_in_process(UserClosedVulnerabilitiesAPIView, member_user, method="get")
        if status_code >= 300 or not isinstance(data, dict):
            raise ValueError(f"closed vulns fetch failed: {status_code}")
        rows = data.get("closed_vulnerabilities") or []
        return [r for r in rows if (r.get("assigned_team") or "") == team_name]
    return fix_tab.cached_fetch(f"user_closed_vulns:{member_user.id}:{team_name}", 20, _fetch)


def fixed_list_body(member_user, team_name, offset=0):
    rows = _fetch_closed(member_user, team_name)
    total = len(rows)
    page = rows[offset:offset + PAGE_SIZE]

    body = [
        {"type": "TextBlock", "text": "✅ Fixed", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": f"Vulnerabilities already mitigated for {team_name}.", "size": "Small", "isSubtle": True, "wrap": True},
    ]
    if not page:
        body.append({"type": "TextBlock", "text": "Nothing fixed yet.", "size": "Small", "isSubtle": True, "spacing": "Medium"})
        return body
    for i, r in enumerate(page):
        sev = (r.get("risk_factor") or "medium").strip().lower()
        if sev not in _SEV_ICON:
            sev = "medium"
        name = r.get("plugin_name") or "Unnamed vulnerability"
        host = r.get("host_name") or "—"
        closed_at = (r.get("closed_at") or "—").split("T")[0]
        subtitle = f"{host}   ·   Closed {closed_at}"
        body.append(fix_tab._row(f"{_SEV_ICON[sev]} {name}", subtitle, "ufixed_view", {"idx": offset + i, "offset": offset}))
    body.extend(fix_tab._pagination_body(offset, total, "ufixed_pg"))
    return body


def fixed_detail_body(member_user, team_name, idx, back_offset=0):
    rows = _fetch_closed(member_user, team_name)
    body = [fix_tab._back_action("← Back to Fixed", "ufixed_back", {"offset": back_offset})]
    if idx is None or idx < 0 or idx >= len(rows):
        body.append({"type": "TextBlock", "text": "This record could not be found.", "wrap": True, "spacing": "Medium"})
        return body
    r = rows[idx]
    sev = (r.get("risk_factor") or "medium").strip().lower()
    if sev not in _SEV_ICON:
        sev = "medium"
    body.append({"type": "TextBlock", "text": r.get("plugin_name") or "Unnamed vulnerability", "weight": "Bolder", "size": "Medium", "wrap": True, "spacing": "Medium"})
    body.append({
        "type": "FactSet",
        "facts": [
            {"title": "Asset", "value": str(r.get("host_name") or "—")},
            {"title": "Severity", "value": f"{_SEV_ICON[sev]} {sev.title()}"},
            {"title": "Port", "value": str(r.get("port") or "—")},
            {"title": "OS", "value": str(r.get("os") or "—")},
            {"title": "Closed At", "value": str(r.get("closed_at") or "—").split("T")[0]},
            {"title": "Closed By", "value": str(r.get("closed_by") or "—")},
        ],
    })
    fix_vuln_id = r.get("fix_vulnerability_id")
    if fix_vuln_id:
        try:
            steps_data = fix_detail._fetch_fix_steps(member_user, fix_vuln_id)
            body.extend(fix_detail._all_steps_readonly_body(steps_data, r.get("os")))
        except Exception:
            logger.exception("[TeamsBot] fixed_detail_body steps fetch failed")
    return body
