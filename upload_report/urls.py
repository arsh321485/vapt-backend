from django.urls import path
from .views import (
    UploadReportView,
    UploadReportLocationAPIView,
    UploadReportDetailAPIView,
    serve_report_file,
    UploadReportListByAdminAPIView,
    UploadReportDeleteAPIView,
    GenerateVulnerabilityCardView,
    RunMitigationView,
    VulnerabilityCardListView,
    VulnerabilityCardDetailView,
    SuperAdminVerificationListAPIView,
    SuperAdminApproveVerificationAPIView,
)

app_name = 'upload_report'

urlpatterns = [
    # Upload endpoint
    path('upload/', UploadReportView.as_view(), name='upload_report'),
    
    path(
            "upload/locations/<str:report_id>/",
            UploadReportLocationAPIView.as_view(),
            name="upload_report_locations_by_report",
        ),
    
    path("upload/all/", UploadReportListByAdminAPIView.as_view(), name="upload_report_list_by_admin"),
    
    path(
        "upload/<str:report_id>/",
        UploadReportDetailAPIView.as_view(),
        name="upload_report_detail",
    ),
     
    path(
        "upload/<str:report_id>/delete/",
        UploadReportDeleteAPIView.as_view(),
        name="upload_report_delete",
    ),
     
     
     path("media/<path:path>", serve_report_file),

    # Vulnerability Card endpoints
    path(
        "vulnerability-cards/generate/",
        GenerateVulnerabilityCardView.as_view(),
        name="vulnerability_card_generate",
    ),
    path(
        "run-mitigation/",
        RunMitigationView.as_view(),
        name="run_mitigation",
    ),
    path(
        "vulnerability-cards/",
        VulnerabilityCardListView.as_view(),
        name="vulnerability_card_list",
    ),
    path(
        "vulnerability-cards/<str:card_id>/",
        VulnerabilityCardDetailView.as_view(),
        name="vulnerability_card_detail",
    ),

    # Superadmin verification
    path(
        "verifications/pending/",
        SuperAdminVerificationListAPIView.as_view(),
        name="superadmin_verification_list",
    ),
    path(
        "verifications/approve/",
        SuperAdminApproveVerificationAPIView.as_view(),
        name="superadmin_verification_approve",
    ),
]