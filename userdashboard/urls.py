from django.urls import path
from .views import (
    UserTeamsAPIView,
    UserTotalAssetsAPIView,
    UserAvgScoreAPIView,
    UserVulnerabilitiesAPIView,
    UserVulnerabilitiesFixedAPIView,
    UserMitigationTimelineAPIView,
    UserMeanTimeRemediateAPIView,
    UserSupportRequestsAPIView,
    UserPatchManagementAPIView,
    UserInProcessRemediationTimelineAPIView,
    UserMitigationTimelineExtensionAPIView,
    UserMitigationTimelineExtensionOptionsAPIView,
    UserMitigationTimelineExtensionOptionsByFixAPIView,
    UserMitigationTimelineExtensionCreateAPIView,
    UserMitigationTimelineExtensionReportAPIView,
    UserDashboardSummaryAPIView,
)

urlpatterns = [
    # Full summary (recommended — single call for all metrics)
    path("summary/",                 UserDashboardSummaryAPIView.as_view(),      name="user-dashboard-summary"),

    # Individual endpoints
    path("teams/",                   UserTeamsAPIView.as_view(),                 name="user-teams"),
    path("total-assets/",            UserTotalAssetsAPIView.as_view(),           name="user-total-assets"),
    path("avg-score/",               UserAvgScoreAPIView.as_view(),              name="user-avg-score"),
    path("vulnerabilities/",         UserVulnerabilitiesAPIView.as_view(),       name="user-vulnerabilities"),
    path("vulnerabilities-fixed/",   UserVulnerabilitiesFixedAPIView.as_view(),  name="user-vulnerabilities-fixed"),
    path("mitigation-timeline/",     UserMitigationTimelineAPIView.as_view(),    name="user-mitigation-timeline"),
    path("mean-time-remediate/",     UserMeanTimeRemediateAPIView.as_view(),     name="user-mean-time-remediate"),
    path("support-requests/",        UserSupportRequestsAPIView.as_view(),       name="user-support-requests"),
    path("patch-management/",        UserPatchManagementAPIView.as_view(),       name="user-patch-management"),
    path("remediation-timeline/in-process/", UserInProcessRemediationTimelineAPIView.as_view(), name="user-remediation-timeline-in-process"),
    path("mitigation-timeline-extension/", UserMitigationTimelineExtensionAPIView.as_view(), name="user-mitigation-timeline-extension"),
    path("mitigation-timeline-extension/options/", UserMitigationTimelineExtensionOptionsAPIView.as_view(), name="user-mitigation-timeline-extension-options"),
    path("mitigation-timeline-extension/options-by-fix/", UserMitigationTimelineExtensionOptionsByFixAPIView.as_view(), name="user-mitigation-timeline-extension-options-by-fix"),
    path("mitigation-timeline-extension/request/", UserMitigationTimelineExtensionCreateAPIView.as_view(), name="user-mitigation-timeline-extension-request"),
    path("mitigation-timeline-extension/report/", UserMitigationTimelineExtensionReportAPIView.as_view(), name="user-mitigation-timeline-extension-report"),
]
