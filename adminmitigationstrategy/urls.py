from django.urls import path
from .views import (
    MitigationStrategyByTeamAPIView,
    VulnerabilityAssetCountAPIView,
)

urlpatterns = [
    # Vulnerabilities grouped by assigned_team (from vulnerability_cards)
    path(
        "by-team/",
        MitigationStrategyByTeamAPIView.as_view(),
        name="mitigation-strategy-by-team",
    ),
    # Same vulnerability name → count in how many assets it appears
    path(
        "vuln-asset-count/",
        VulnerabilityAssetCountAPIView.as_view(),
        name="vuln-asset-count",
    ),
]
