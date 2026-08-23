"""
Download Report tab — real report summary stats (same consolidated data
the website's own report page and Slack's /downloadreport show), plus a
link to open/download the full report on the website. Mirrors
users.views.SlackSlashCommandView._cmd_downloadreport's summary card,
minus the file upload — Teams channel bots can't post files into a
channel any more reliably than they can receive them (see
cards.open_website_upload_card for the same platform-limitation reasoning
on the upload side), so this links out instead of attempting one.
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


def download_report_body(admin):
    from django.conf import settings

    data = _fetch_report_summary(admin)
    vulns = data.get("vulnerabilities") or {}
    total = sum(v for v in vulns.values() if isinstance(v, (int, float)))
    frontend = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai").rstrip("/")

    body = [
        {"type": "TextBlock", "text": "📄 Download Report", "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {
            "type": "FactSet",
            "facts": [
                {"title": "Report", "value": str(data.get("vul_management_program") or "—")},
                {"title": "Generated On", "value": str(data.get("report_generated_on") or "—")},
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
            "actions": [{"type": "Action.OpenUrl", "title": "📥 Open Full Report", "url": f"{frontend}/reports", "style": "positive"}],
        },
    ]
    return body
