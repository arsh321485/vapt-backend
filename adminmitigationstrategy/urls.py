from django.urls import path
from .views import (
    MitigationStrategyByTeamAPIView,
)

urlpatterns = [
    # Vulnerabilities grouped by assigned_team (from vulnerability_cards)
    path(
        "by-team/",
        MitigationStrategyByTeamAPIView.as_view(),
        name="mitigation-strategy-by-team",
    ),
]
