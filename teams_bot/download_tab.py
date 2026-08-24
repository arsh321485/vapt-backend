"""
Download Report tab — real report summary stats (same consolidated data
the website's own report page and Slack's /downloadreport show), plus a
real, direct download of the report file itself. Mirrors
users.views.SlackSlashCommandView._cmd_downloadreport's summary card.

The actual file comes from the SAME AdminReportDownloadAPIView Slack's
/downloadreport already uses (HTML or PDF, WeasyPrint-rendered) — served
through a signed-token URL (teams_bot.views.TeamsReportDownloadView,
same pattern as the dashboard PNG images) so an Action.OpenUrl click
downloads it straight from the clicker's own browser, no website login
needed (Action.OpenUrl opens in the clicker's own browser, which has no
way to carry the admin's website session — that's why this can't just
link to the login-gated /reports page and expect a direct download).
"""
import logging

logger = logging.getLogger(__name__)


def _fetch_report_summary(admin):
    from adminregister.views import AdminReportDownloadDataAPIView
    from .actions import _call_view_in_process
    status_code, data = _call_view_in_process(AdminReportDownloadDataAPIView, admin, method="get")
    if status_code >= 300 or not isinstance(data, dict):
        raise ValueError(f"report download-data fetch failed: {status_code}")
    return data


def _download_url(team_id, fmt):
    import time
    from urllib.parse import quote
    from django.conf import settings
    from users.views import _dashboard_image_signer

    token = _dashboard_image_signer().sign(team_id)
    backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
    return f"{backend}/api/admin/users/teams/report-download/?token={quote(token)}&type={fmt}&t={int(time.time())}"


def download_report_body(admin, team_id):
    data = _fetch_report_summary(admin)
    vulns = data.get("vulnerabilities") or {}
    total = sum(v for v in vulns.values() if isinstance(v, (int, float)))

    body = [
        {"type": "TextBlock", "text": "📄 Download Report", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {
            "type": "FactSet",
            "facts": [
                {"title": "Report", "value": str(data.get("vul_management_program") or "—")},
                {"title": "Generated On", "value": str(data.get("report_generated_on") or "—").split(" ")[0].split("T")[0]},
                {"title": "Total Assets", "value": str(data.get("total_assets", 0))},
                {"title": "Risk Score", "value": f"{data.get('risk_score', 0)}/100"},
            ],
        },
        {
            "type": "TextBlock",
            "text": (
                f"**Findings:** {total} total — "
                f"🔴 {vulns.get('critical', 0)} Critical   🟠 {vulns.get('high', 0)} High   "
                f"🟡 {vulns.get('medium', 0)} Medium   🟢 {vulns.get('low', 0)} Low"
            ),
            "wrap": True, "size": "Small", "spacing": "Medium",
        },
        {
            "type": "ActionSet", "spacing": "Medium",
            "actions": [
                {"type": "Action.OpenUrl", "title": "📥 Download HTML Report", "url": _download_url(team_id, "html"), "style": "positive"},
            ],
        },
    ]
    return body
