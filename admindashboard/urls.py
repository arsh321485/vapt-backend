from django.urls import path
from .views import (
    ReportTotalAssetsAPIView, ReportAvgScoreAPIView,
    ReportVulnerabilitiesAPIView, ReportSummaryAPIView,
    ReportMitigationTimelineAPIView,ReportMeanTimeRemediateAPIView
)

urlpatterns = [
    path("report/<str:report_id>/total-assets/", ReportTotalAssetsAPIView.as_view(), name="report-total-assets"),
    path("report/<str:report_id>/avg-score/", ReportAvgScoreAPIView.as_view(), name="report-avg-score"),
    path("report/<str:report_id>/vulnerabilities/", ReportVulnerabilitiesAPIView.as_view(), name="report-vulnerabilities"),
    path("report/<str:report_id>/summary/", ReportSummaryAPIView.as_view(), name="report-summary"),
    path("report/<str:report_id>/mitigation-timeline/", ReportMitigationTimelineAPIView.as_view(), name="report-mitigation-timeline"),
    path("report/<str:report_id>/mean-time-remediate/", ReportMeanTimeRemediateAPIView.as_view(), name="report-mean-time-remediate"),
]

