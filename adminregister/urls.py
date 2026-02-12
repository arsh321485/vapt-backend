# adminregister/urls.py
from django.urls import path
from .views import (
    # VulnerabilityRegisterAPIView,
    LatestSuperAdminVulnerabilityRegisterAPIView,
    VulnerabilitiesByHostListAPIView,
    VulnerabilitiesByHostDetailAPIView,
    FixVulnerabilityCreateAPIView,
    RaiseSupportRequestAPIView,
    SupportRequestByReportAPIView,
    FixVulnerabilityStepsAPIView,
    FixStepFeedbackAPIView,
    FixVulnerabilityFinalFeedbackAPIView,
    FixVulnerabilityDetailAPIView,
    RaiseSupportRequestByVulnerabilityAPIView,
    CreateTicketAPIView,
    TicketByReportAPIView,
    TicketOpenListAPIView,
    TicketClosedListAPIView,
    TicketDetailAPIView
 )
                    
urlpatterns = [
    # Fetch vulnerabilities from the LATEST Super Admin upload (no report_id needed)
    path('register/latest/vulns/', LatestSuperAdminVulnerabilityRegisterAPIView.as_view(), name='latest-superadmin-vulns'),

    # Fetch vulnerabilities by specific report_id
    # path('register/<str:report_id>/vulns/', VulnerabilityRegisterAPIView.as_view(), name='report-vulns-by-id'),

    # Get list of hosts with vulnerability counts by risk factor
    path('register/hosts/', VulnerabilitiesByHostListAPIView.as_view(), name='vulnerabilities-by-host-list'),

    # Get vulnerabilities for a specific host, grouped by risk factor
    path('register/host/<str:host_name>/vulns/', VulnerabilitiesByHostDetailAPIView.as_view(), name='vulnerabilities-by-host-detail'),

    path(
        "fix-vulnerability/report/<str:report_id>/asset/<str:host_name>/create/",
        FixVulnerabilityCreateAPIView.as_view(),
    ),

    path(
        "fix-vulnerability/<str:fix_vuln_id>/step-complete/",
        FixVulnerabilityStepsAPIView.as_view(),
        name="fix-vulnerability-steps"
    ),

    # Feedback API for fix steps (per-step feedback)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/feedback/",
        FixStepFeedbackAPIView.as_view(),
        name="fix-step-feedback"
    ),

    # Final Feedback API (ONLY after vulnerability is CLOSED)
    path(
        "fix-vulnerability/<str:fix_vuln_id>/final-feedback/",
        FixVulnerabilityFinalFeedbackAPIView.as_view(),
        name="fix-vulnerability-final-feedback"
    ),

    # Get complete fix vulnerability details for Fix Now card
    path(
        "fix-vulnerability/<str:fix_vuln_id>/detail/",
        FixVulnerabilityDetailAPIView.as_view(),
        name="fix-vulnerability-detail"
    ),

    #create raise support request
    path(
    "support-requests/raise/report/<str:report_id>/vulnerability/<str:vulnerability_id>/",
    RaiseSupportRequestAPIView.as_view(),
    name="raise-support-request"
    ),
    
    #Get raise support request by (vulnerbility id by)
    path(
        "raise-support-requests/vulnerability/<str:vulnerability_id>/",
        RaiseSupportRequestByVulnerabilityAPIView.as_view(),
        name="support-request-by-vulnerability"
    ),

    # Get support requests by report_id
    path(
    "support-requests/report/<str:report_id>/",
    SupportRequestByReportAPIView.as_view(),
    name="support-requests-by-report"    
    ),
 
    path(
        "tickets/report/<str:report_id>/fix/<str:fix_vulnerability_id>/create/",
        CreateTicketAPIView.as_view(),
        name="create-ticket"
    ),
    
    path(
        "tickets/report/<str:report_id>/",
        TicketByReportAPIView.as_view(),
        name="all-tickets-by-report"
    ),
    
    path(
    "reports/<str:report_id>/tickets/open/",
    TicketOpenListAPIView.as_view(),
    name="tickets-open"
    ),

    path(
        "reports/<str:report_id>/tickets/closed/",
        TicketClosedListAPIView.as_view(),
        name="tickets-closed"
    ),
    
    path(
    "tickets/fix/<str:fix_vulnerability_id>/ticket/<str:ticket_id>/",
    TicketDetailAPIView.as_view(),
    name="get-ticket-detail"
),


]
