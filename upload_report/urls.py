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
from .views import UploadReportView

app_name = 'upload_report'

urlpatterns = [
    # Upload endpoint
    path('upload/', UploadReportView.as_view(), name='upload_report'),
]