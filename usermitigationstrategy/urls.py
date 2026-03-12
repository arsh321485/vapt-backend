from django.urls import path
from .views import (
    UserMitigationStrategyByTeamAPIView,
    UserVulnerabilityAssetCountAPIView,
)

urlpatterns = [
    path("by-team/", UserMitigationStrategyByTeamAPIView.as_view(), name="user-mitigation-by-team"),
    path("vuln-asset-count/", UserVulnerabilityAssetCountAPIView.as_view(), name="user-vuln-asset-count"),
]
