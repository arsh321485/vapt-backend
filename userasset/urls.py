from django.urls import path
from .views import (
    UserAssetsAPIView,
    UserHoldAssetsAPIView,
    UserAssetVulnerabilitiesAPIView,
    UserReportAssetsAPIView,
    UserHoldAssetsByReportAPIView,
    UserAssetVulnerabilitiesByHostAPIView,
    UserSupportRequestByHostAPIView,
    UserClosedFixVulnerabilitiesByHostAPIView,
    UserAssetHoldAPIView,
    UserAssetUnholdAPIView,
    UserAssetDeleteAPIView,
    # Vulnerability-level management
    UserAllVulnerabilitiesAPIView,
    UserVulnAssetListAPIView,
    UserBulkVulnHoldAPIView,
    UserBulkVulnUnholdAPIView,
    UserBulkVulnDeleteAPIView,
)

urlpatterns = [

    # ================== LATEST REPORT ENDPOINTS ==================
    # (auto-fetch from admin's most recently uploaded report)

    # GET all team-filtered assets
    path(
        "assets/",
        UserAssetsAPIView.as_view(),
        name="user-assets",
    ),

    # GET held assets (latest report)  — MUST be before <host_name> route
    path(
        "assets/hold-list/",
        UserHoldAssetsAPIView.as_view(),
        name="user-held-assets",
    ),

    # GET team-filtered vulnerabilities for a specific asset
    path(
        "assets/<path:host_name>/vulnerabilities/",
        UserAssetVulnerabilitiesAPIView.as_view(),
        name="user-asset-vulnerabilities",
    ),

    # ================== REPORT-SPECIFIC ENDPOINTS ==================

    # GET team-filtered assets from a specific report
    path(
        "report/<str:report_id>/assets/",
        UserReportAssetsAPIView.as_view(),
        name="user-report-assets",
    ),

    # GET held assets from a specific report  — MUST be before <host_name> route
    path(
        "report/<str:report_id>/assets/hold-list/",
        UserHoldAssetsByReportAPIView.as_view(),
        name="user-held-assets-by-report",
    ),

    # GET team-filtered vulnerabilities for a specific asset in a specific report
    path(
        "report/<str:report_id>/asset/<path:host_name>/vulnerabilities/",
        UserAssetVulnerabilitiesByHostAPIView.as_view(),
        name="user-report-asset-vulns-by-host",
    ),

    # POST hold an asset (team-validated)
    path(
        "report/<str:report_id>/assets/<path:host_name>/hold/",
        UserAssetHoldAPIView.as_view(),
        name="user-asset-hold",
    ),

    # POST unhold an asset (team-validated)
    path(
        "report/<str:report_id>/assets/<path:host_name>/unhold/",
        UserAssetUnholdAPIView.as_view(),
        name="user-asset-unhold",
    ),

    # Backward-compatible alias:
    # Some clients call ".../assets/<host_name>/delete/" (extra 'delete/' suffix).
    # NOTE: This MUST be declared before the generic delete route, because
    # `<path:host_name>` in the generic route can otherwise swallow "delete".
    path(
        "report/<str:report_id>/assets/<path:host_name>/delete/",
        UserAssetDeleteAPIView.as_view(),
        name="user-asset-delete-alias",
    ),

    # DELETE an asset (team-validated)  — MUST be last for <host_name>
    path(
        "report/<str:report_id>/assets/<path:host_name>/",
        UserAssetDeleteAPIView.as_view(),
        name="user-asset-delete",
    ),

    # ================== HOST-LEVEL ENDPOINTS ==================

    # GET support requests raised by this user for a host
    path(
        "support-requests/host/<str:host_name>/",
        UserSupportRequestByHostAPIView.as_view(),
        name="user-support-requests-by-host",
    ),

    # GET closed fix-vulnerabilities for a host (team-filtered)
    path(
        "fix-vulnerabilities/host/<str:host_name>/closed/",
        UserClosedFixVulnerabilitiesByHostAPIView.as_view(),
        name="user-closed-fix-vulnerabilities-by-host",
    ),

    # ================== VULNERABILITY-LEVEL MANAGEMENT ==================

    # GET all team-assigned vulns (grouped by plugin_name with status counts)
    path(
        "report/<str:report_id>/vulnerabilities/",
        UserAllVulnerabilitiesAPIView.as_view(),
        name="user-all-vulnerabilities",
    ),

    # GET assets that have a specific vulnerability (checkbox list)
    path(
        "report/<str:report_id>/vulnerability/<path:plugin_name>/assets/",
        UserVulnAssetListAPIView.as_view(),
        name="user-vuln-asset-list",
    ),

    # POST hold this vulnerability on selected assets
    path(
        "report/<str:report_id>/vulnerability/<path:plugin_name>/hold/",
        UserBulkVulnHoldAPIView.as_view(),
        name="user-bulk-vuln-hold",
    ),

    # POST unhold this vulnerability on selected assets
    path(
        "report/<str:report_id>/vulnerability/<path:plugin_name>/unhold/",
        UserBulkVulnUnholdAPIView.as_view(),
        name="user-bulk-vuln-unhold",
    ),

    # DELETE this vulnerability from selected assets
    path(
        "report/<str:report_id>/vulnerability/<path:plugin_name>/delete/",
        UserBulkVulnDeleteAPIView.as_view(),
        name="user-bulk-vuln-delete",
    ),
]

