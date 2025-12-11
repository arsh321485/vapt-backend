# adminregister/urls.py
from django.urls import path
from .views import VulnerabilityRegisterAPIView

urlpatterns = [
    path('register/<str:report_id>/vulns/', VulnerabilityRegisterAPIView.as_view(), name='report-vulns-by-id'),
]
