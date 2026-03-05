from django.urls import path
from .views import (
    MitigationStrategyLatestAPIView,
    MitigationStrategyByHostAPIView,
)

urlpatterns = [
    # All vulnerabilities from latest report (host_name, os, plugin_name, risk_factor, status)
    path(
        "latest/",
        MitigationStrategyLatestAPIView.as_view(),
        name="mitigation-strategy-latest",
    ),

    # Vulnerabilities for a specific host from latest report
    path(
        "host/<str:host_name>/vulnerabilities/",
        MitigationStrategyByHostAPIView.as_view(),
        name="mitigation-strategy-by-host",
    ),
]
