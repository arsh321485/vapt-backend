from django.urls import path
from .views import (
    UserLatestVulnerabilityRegisterAPIView,
    UserFixVulnerabilityCreateAPIView,
    UserFixVulnerabilityCardAPIView,
    UserFixVulnerabilityStepsAPIView,
    UserFixStepFeedbackAPIView,
    UserFixVulnerabilityFinalFeedbackAPIView,
    UserVulnerabilityTimelineAPIView,
    UserRaiseSupportRequestAPIView,
    UserRaiseSupportRequestByVulnerabilityAPIView,
    UserSupportRequestsByReportAPIView,
    UserCreateTicketAPIView,
    UserTicketByReportAPIView,
    UserTicketOpenListAPIView,
    UserTicketClosedListAPIView,
    UserTicketDetailAPIView,
)

urlpatterns = [
    # 1. Team-filtered vulnerability listing (main listing)
    path(
        "register/latest/vulns/",
        UserLatestVulnerabilityRegisterAPIView.as_view(),
        name="user-latest-vulns",
    ),

    # 2. Fix vulnerability create + list (per asset)
    path(
        "fix-vulnerability/report/<str:report_id>/asset/<str:host_name>/create/",
        UserFixVulnerabilityCreateAPIView.as_view(),
        name="user-fix-vuln-create",
    ),

    # 3. Fix card detail (by fix_vuln_id)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/card/",
        UserFixVulnerabilityCardAPIView.as_view(),
        name="user-fix-vuln-card",
    ),

    # 4. Steps (GET = fetch, POST = complete next step)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/step-complete/",
        UserFixVulnerabilityStepsAPIView.as_view(),
        name="user-fix-vuln-steps",
    ),

    # 5. Step feedback
    path(
        "fix-vulnerability/<str:fix_vuln_id>/feedback/",
        UserFixStepFeedbackAPIView.as_view(),
        name="user-fix-step-feedback",
    ),

    # 6. Final feedback (only after closed)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/final-feedback/",
        UserFixVulnerabilityFinalFeedbackAPIView.as_view(),
        name="user-fix-final-feedback",
    ),

    # 7. Vulnerability timeline
    path(
        "fix-vulnerability/<str:fix_vuln_id>/timeline/",
        UserVulnerabilityTimelineAPIView.as_view(),
        name="user-vuln-timeline",
    ),

    # 8. Raise support request (POST = create, GET = check existing)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/raise-support-request/",
        UserRaiseSupportRequestAPIView.as_view(),
        name="user-raise-support-request",
    ),

    # 9. Check support request by vulnerability (GET only)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/support-request-status/",
        UserRaiseSupportRequestByVulnerabilityAPIView.as_view(),
        name="user-support-request-status",
    ),

    # 10. All support requests by report (team-filtered)
    path(
        "support-requests/report/<str:report_id>/",
        UserSupportRequestsByReportAPIView.as_view(),
        name="user-support-requests-by-report",
    ),

    # 11. Create ticket
    path(
        "tickets/report/<str:report_id>/fix/<str:fix_vulnerability_id>/create/",
        UserCreateTicketAPIView.as_view(),
        name="user-create-ticket",
    ),

    # 12. All tickets by report (team-filtered)
    path(
        "tickets/report/<str:report_id>/",
        UserTicketByReportAPIView.as_view(),
        name="user-tickets-by-report",
    ),

    # 13. Open tickets by report
    path(
        "reports/<str:report_id>/tickets/open/",
        UserTicketOpenListAPIView.as_view(),
        name="user-tickets-open",
    ),

    # 14. Closed tickets by report
    path(
        "reports/<str:report_id>/tickets/closed/",
        UserTicketClosedListAPIView.as_view(),
        name="user-tickets-closed",
    ),

    # 15. Single ticket detail
    path(
        "tickets/fix/<str:fix_vulnerability_id>/ticket/<str:ticket_id>/",
        UserTicketDetailAPIView.as_view(),
        name="user-ticket-detail",
    ),
]
