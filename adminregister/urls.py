# adminregister/urls.py
from django.urls import path
from .views import (
    VulnerabilityRegisterAPIView,
    FixVulnerabilityCreateAPIView,
    RaiseSupportRequestAPIView,
    SupportRequestByReportAPIView,
    SupportRequestDetailAPIView,
    CreateTicketAPIView,
 )
                    
urlpatterns = [
    path('register/<str:report_id>/vulns/', VulnerabilityRegisterAPIView.as_view(), name='report-vulns-by-id'),

    path(
    "fix-vulnerability/report/<str:report_id>/asset/<str:host_name>/create/",
    FixVulnerabilityCreateAPIView.as_view(),
    name="fix-vulnerability-create-by-asset"
    ),
    
    # path(
    # "support-requests/raise/",
    # RaiseSupportRequestAPIView.as_view(),
    # name="raise-support-request"
    # ),
    path(
    "support-requests/raise/report/<str:report_id>/vulnerability/<str:vulnerability_id>/",
    RaiseSupportRequestAPIView.as_view(),
    name="raise-support-request"
    ),
    
    path(
    "support-requests/<str:support_request_id>/",
    SupportRequestDetailAPIView.as_view(),
    name="support-request-detail"
    ),


    path(
    "support-requests/report/<str:report_id>/",
    SupportRequestByReportAPIView.as_view(),
    name="support-requests-by-report"    
    ),
    path(
        "tickets/create/",
        CreateTicketAPIView.as_view(),
        name="create-ticket"
    ),


]
