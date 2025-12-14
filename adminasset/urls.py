from django.urls import path
from .views import (
    ReportAssetsAPIView,
    AssetSearchAPIView,
    AssetDeleteAPIView,
    AssetVulnerabilitiesByHostAPIView,
    AssetHoldAPIView,
    AssetUnholdAPIView
)

urlpatterns = [
    # list all assets for a given report (report_id)
    path("report/<str:report_id>/assets/", ReportAssetsAPIView.as_view(), name="report-assets"),

    # search across all reports by host name (q=)
    path("assets/search/", AssetSearchAPIView.as_view(), name="report-asset-search"),

    # IMPORTANT: more specific 'assets/vulnerabilities/' MUST come before the generic host_name route
    path("report/<str:report_id>/asset/<path:host_name>/vulnerabilities/", AssetVulnerabilitiesByHostAPIView.as_view(), name="report-asset-vulns-by-host"),
    
    path("report/<str:report_id>/assets/<path:host_name>/hold/", AssetHoldAPIView.as_view(), name="asset-hold"),
    path("report/<str:report_id>/assets/<path:host_name>/unhold/", AssetUnholdAPIView.as_view(), name="asset-unhold"),
    
       # delete a specific host from a report (host_name should be URL-encoded if needed)
    path(
        "report/<str:report_id>/assets/<path:host_name>/",
        AssetDeleteAPIView.as_view(),
        name="report-asset-delete",
    ),

]

