from django.urls import path
from .views import (
    UploadReportView,
    UploadReportLocationAPIView,
    UploadReportDetailAPIView,
    serve_report_file,
    UploadReportListByAdminAPIView,
    UploadReportDeleteAPIView
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
    
]