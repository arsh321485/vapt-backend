from django.urls import path
from .views import (
    ReportTotalAssetsAPIView, ReportAvgScoreAPIView,
    ReportVulnerabilitiesAPIView,
    ReportMitigationTimelineAPIView, ReportMeanTimeRemediateAPIView,
    # Admin-level dashboard views
    AdminTotalAssetsAPIView, AdminAvgScoreAPIView,
    AdminVulnerabilitiesAPIView, AdminMitigationTimelineAPIView,
    AdminMeanTimeRemediateAPIView, AdminVulnerabilitiesFixedAPIView,
    AdminSupportRequestsAPIView,
    AdminDashboardSummaryAPIView,
    AdminReportStatusAPIView, AdminDistributionByTeamAPIView,
    AdminDistributionByTeamDetailAPIView, AdminDetailedVulnerabilitiesAPIView,
    AdminAssetsByTeamAPIView,
    AdminInProcessRemediationTimelineAPIView,
    AdminMitigationTimelineExtensionAPIView,
    AdminMitigationTimelineExtensionReportAPIView,
    AdminMitigationTimelineExtensionStatusAPIView,
)

urlpatterns = [
    # Report-specific endpoints (require report_id)
    path("report/<str:report_id>/total-assets/", ReportTotalAssetsAPIView.as_view(), name="report-total-assets"),
    path("report/<str:report_id>/avg-score/", ReportAvgScoreAPIView.as_view(), name="report-avg-score"),
    path("report/<str:report_id>/vulnerabilities/", ReportVulnerabilitiesAPIView.as_view(), name="report-vulnerabilities"),
    path("report/<str:report_id>/mitigation-timeline/", ReportMitigationTimelineAPIView.as_view(), name="report-mitigation-timeline"),
    path("report/<str:report_id>/mean-time-remediate/", ReportMeanTimeRemediateAPIView.as_view(), name="report-mean-time-remediate"),

    # Admin-level endpoints (aggregate data for logged-in admin)
    path("dashboard/report-status/", AdminReportStatusAPIView.as_view(), name="admin-report-status"),
    path("dashboard/summary/", AdminDashboardSummaryAPIView.as_view(), name="admin-dashboard-summary"),
    path("dashboard/total-assets/", AdminTotalAssetsAPIView.as_view(), name="admin-total-assets"),
    path("dashboard/avg-score/", AdminAvgScoreAPIView.as_view(), name="admin-avg-score"),
    path("dashboard/vulnerabilities/", AdminVulnerabilitiesAPIView.as_view(), name="admin-vulnerabilities"),
    path("dashboard/mitigation-timeline/", AdminMitigationTimelineAPIView.as_view(), name="admin-mitigation-timeline"),
    path("dashboard/mean-time-remediate/", AdminMeanTimeRemediateAPIView.as_view(), name="admin-mean-time-remediate"),
    path("dashboard/vulnerabilities-fixed/", AdminVulnerabilitiesFixedAPIView.as_view(), name="admin-vulnerabilities-fixed"),
    path("dashboard/support-requests/", AdminSupportRequestsAPIView.as_view(), name="admin-support-requests"),
    path("dashboard/distribution-by-team/", AdminDistributionByTeamAPIView.as_view(), name="admin-distribution-by-team"),
    path("dashboard/distribution-by-team/detail/", AdminDistributionByTeamDetailAPIView.as_view(), name="admin-distribution-by-team-detail"),
    path("dashboard/detailed-vulnerabilities/", AdminDetailedVulnerabilitiesAPIView.as_view(), name="admin-detailed-vulnerabilities"),
    path("dashboard/assets-by-team/", AdminAssetsByTeamAPIView.as_view(), name="admin-assets-by-team"),
    path("dashboard/remediation-timeline/in-process/", AdminInProcessRemediationTimelineAPIView.as_view(), name="admin-remediation-timeline-in-process"),
    path("dashboard/mitigation-timeline-extension/", AdminMitigationTimelineExtensionAPIView.as_view(), name="admin-mitigation-timeline-extension"),
    path("dashboard/mitigation-timeline-extension/report/", AdminMitigationTimelineExtensionReportAPIView.as_view(), name="admin-mitigation-timeline-extension-report"),
    path("dashboard/mitigation-timeline-extension/<str:request_id>/status/", AdminMitigationTimelineExtensionStatusAPIView.as_view(), name="admin-mitigation-timeline-extension-status"),
]

