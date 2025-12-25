# adminregister/urls.py
from django.urls import path
from .views import (
    VulnerabilityRegisterAPIView,
    FixVulnerabilityCreateAPIView,
    RaiseSupportRequestAPIView,
    SupportRequestByReportAPIView,
    RaiseSupportRequestByVulnerabilityAPIView,
    CreateTicketAPIView,
    TicketByReportAPIView,
    TicketOpenListAPIView,
    TicketClosedListAPIView,
    TicketDetailAPIView
 )
                    
urlpatterns = [
    path('register/<str:report_id>/vulns/', VulnerabilityRegisterAPIView.as_view(), name='report-vulns-by-id'),

    path(
    "fix-vulnerability/report/<str:report_id>/asset/<str:host_name>/create/",
    FixVulnerabilityCreateAPIView.as_view(),
    name="fix-vulnerability-create-by-asset"
    ),

    path(
    "support-requests/raise/report/<str:report_id>/vulnerability/<str:vulnerability_id>/",
    RaiseSupportRequestAPIView.as_view(),
    name="raise-support-request"
    ),
    
    path(
        "raise-support-requests/vulnerability/<str:vulnerability_id>/",
        RaiseSupportRequestByVulnerabilityAPIView.as_view(),
        name="support-request-by-vulnerability"
    ),


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
    "tickets/<str:ticket_id>/",
    TicketDetailAPIView.as_view(),
    name="get-ticket-detail"
),


]
