from django.urls import path
from .views import (
    ReportAssetsAPIView,
    AssetDeleteAPIView,
    AssetVulnerabilitiesByHostAPIView,
    SupportRequestByHostAPIView,
    AssetHoldAPIView,
    AssetUnholdAPIView,
    HoldAssetsByReportAPIView,
)

urlpatterns = [
    # ---------------- ASSETS LIST ----------------
    path(
        "report/<str:report_id>/assets/",
        ReportAssetsAPIView.as_view(),
        name="report-assets",
    ),

    # ---------------- HELD ASSETS LIST (NEW) ----------------
    # MUST be before generic <host_name> route
    path(
        "report/<str:report_id>/assets/hold-list/",
        HoldAssetsByReportAPIView.as_view(),
        name="held-assets-by-report",
    ),


    # ---------------- VULNERABILITIES BY HOST ----------------
    path(
        "report/<str:report_id>/asset/<path:host_name>/vulnerabilities/",
        AssetVulnerabilitiesByHostAPIView.as_view(),
        name="report-asset-vulns-by-host",
    ),

  # ---------------- HOST NAME BY RAISE SUPPORT REQUEST ----------------
    path(
        "support-requests/host/<str:host_name>/",
        SupportRequestByHostAPIView.as_view(),
        name="support-requests-by-host"
    ),
    # ---------------- HOLD / UNHOLD ----------------
    path(
        "report/<str:report_id>/assets/<path:host_name>/hold/",
        AssetHoldAPIView.as_view(),
        name="asset-hold",
    ),
    path(
        "report/<str:report_id>/assets/<path:host_name>/unhold/",
        AssetUnholdAPIView.as_view(),
        name="asset-unhold",
    ),

    # ---------------- DELETE ASSET (LAST) ----------------
    path(
        "report/<str:report_id>/assets/<path:host_name>/",
        AssetDeleteAPIView.as_view(),
        name="report-asset-delete",
    ),
]


