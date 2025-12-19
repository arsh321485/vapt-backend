# adminregister/urls.py
from django.urls import path
from .views import VulnerabilityRegisterAPIView,FixVulnerabilityCreateAPIView

urlpatterns = [
    path('register/<str:report_id>/vulns/', VulnerabilityRegisterAPIView.as_view(), name='report-vulns-by-id'),
    path(
        "fix-vulnerability/create/",
        FixVulnerabilityCreateAPIView.as_view(),
        name="fix-vulnerability-create"
    ),
]
