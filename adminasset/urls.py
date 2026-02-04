from django.urls import path
from .views import (
    ReportAssetsAPIView,
    AssetDeleteAPIView,
    AssetVulnerabilitiesByHostAPIView,
    SupportRequestByHostAPIView,
    ClosedFixVulnerabilitiesByHostAPIView,
    AssetHoldAPIView,
    AssetUnholdAPIView,
    HoldAssetsByReportAPIView,
    # Admin-level endpoints (auto-refresh from latest report)
    AdminAssetsAPIView,
    AdminAssetVulnerabilitiesAPIView,
    AdminHoldAssetsAPIView,
)

urlpatterns = [
    # ================== ADMIN-LEVEL ENDPOINTS ==================
    # These automatically fetch data from the most recently uploaded report
    # for the logged-in admin (similar to Admin Dashboard API)

    # Get all assets from latest report (auto-refreshes when new report is uploaded)
    path(
        "assets/",
        AdminAssetsAPIView.as_view(),
        name="admin-assets",
    ),

    # Get held assets from latest report
    path(
        "assets/hold-list/",
        AdminHoldAssetsAPIView.as_view(),
        name="admin-held-assets",
    ),

    # Get vulnerabilities for a specific asset from latest report
    path(
        "assets/<path:host_name>/vulnerabilities/",
        AdminAssetVulnerabilitiesAPIView.as_view(),
        name="admin-asset-vulnerabilities",
    ),

    # ================== REPORT-SPECIFIC ENDPOINTS ==================
    # These require a specific report_id

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
    
      # ---------------- HOST NAME BY FixVulnerabilitie ----------------
    path(
        "fix-vulnerabilities/host/<str:host_name>/closed/",
        ClosedFixVulnerabilitiesByHostAPIView.as_view(),
        name="closed-fix-vulnerabilities-by-host"
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


