# # upload_report/urls.py
# from django.urls import path
# from .views import UploadReportView

# urlpatterns = [
#     path('upload/', UploadReportView.as_view(), name='upload-report'),
# ]

# upload_report/urls.py
"""
URLs configuration for upload_report app
"""

from django.urls import path
from .views import UploadReportView,UploadReportLocationAPIView,UploadReportDetailAPIView,serve_report_file

app_name = 'upload_report'

urlpatterns = [
    # Upload endpoint
    path('upload/', UploadReportView.as_view(), name='upload_report'),
    
    path(
            "upload/locations/<str:report_id>/",
            UploadReportLocationAPIView.as_view(),
            name="upload_report_locations_by_report",
        ),
    
    
     path(
        "upload/<str:report_id>/",
        UploadReportDetailAPIView.as_view(),
        name="upload_report_detail",
    ),
     
     
     path("media/<path:path>", serve_report_file),
    
]