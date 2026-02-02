from django.urls import path
from .views import (
    ReportTotalAssetsAPIView, ReportAvgScoreAPIView,
    ReportVulnerabilitiesAPIView,
    ReportMitigationTimelineAPIView, ReportMeanTimeRemediateAPIView,
    # Admin-level dashboard views
    AdminTotalAssetsAPIView, AdminAvgScoreAPIView,
    AdminVulnerabilitiesAPIView, AdminMitigationTimelineAPIView,
    AdminMeanTimeRemediateAPIView, AdminVulnerabilitiesFixedAPIView,
    AdminSupportRequestsAPIView, AdminDashboardSummaryAPIView
)

urlpatterns = [
    # Report-specific endpoints (require report_id)
    path("report/<str:report_id>/total-assets/", ReportTotalAssetsAPIView.as_view(), name="report-total-assets"),
    path("report/<str:report_id>/avg-score/", ReportAvgScoreAPIView.as_view(), name="report-avg-score"),
    path("report/<str:report_id>/vulnerabilities/", ReportVulnerabilitiesAPIView.as_view(), name="report-vulnerabilities"),
    path("report/<str:report_id>/mitigation-timeline/", ReportMitigationTimelineAPIView.as_view(), name="report-mitigation-timeline"),
    path("report/<str:report_id>/mean-time-remediate/", ReportMeanTimeRemediateAPIView.as_view(), name="report-mean-time-remediate"),

    # Admin-level endpoints (aggregate data for logged-in admin)
    path("dashboard/summary/", AdminDashboardSummaryAPIView.as_view(), name="admin-dashboard-summary"),
    path("dashboard/total-assets/", AdminTotalAssetsAPIView.as_view(), name="admin-total-assets"),
    path("dashboard/avg-score/", AdminAvgScoreAPIView.as_view(), name="admin-avg-score"),
    path("dashboard/vulnerabilities/", AdminVulnerabilitiesAPIView.as_view(), name="admin-vulnerabilities"),
    path("dashboard/mitigation-timeline/", AdminMitigationTimelineAPIView.as_view(), name="admin-mitigation-timeline"),
    path("dashboard/mean-time-remediate/", AdminMeanTimeRemediateAPIView.as_view(), name="admin-mean-time-remediate"),
    path("dashboard/vulnerabilities-fixed/", AdminVulnerabilitiesFixedAPIView.as_view(), name="admin-vulnerabilities-fixed"),
    path("dashboard/support-requests/", AdminSupportRequestsAPIView.as_view(), name="admin-support-requests"),
]

