# adminregister/urls.py
from django.urls import path
from .views import VulnerabilityRegisterAPIView,FixVulnerabilityCreateAPIView,RaiseSupportRequestAPIView

urlpatterns = [
    path('register/<str:report_id>/vulns/', VulnerabilityRegisterAPIView.as_view(), name='report-vulns-by-id'),
    # path(
    #     "fix-vulnerability/create/",
    #     FixVulnerabilityCreateAPIView.as_view(),
    #     name="fix-vulnerability-create"
    # ),
    path(
    "fix-vulnerability/report/<str:report_id>/asset/<str:host_name>/create/",
    FixVulnerabilityCreateAPIView.as_view(),
    name="fix-vulnerability-create-by-asset"
    ),
    
    path(
    "support-requests/raise/",
    RaiseSupportRequestAPIView.as_view(),
    name="raise-support-request"
)
]
