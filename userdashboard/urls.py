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
    # UserDashboardSummaryAPIView,
)

urlpatterns = [
    # Full summary (recommended — single call for all metrics)
    # path("summary/",                 UserDashboardSummaryAPIView.as_view(),      name="user-dashboard-summary"),

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
]
