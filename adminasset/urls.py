from django.urls import path
from .views import ReportAssetsAPIView

urlpatterns = [
    path("report/<str:report_id>/assets/", ReportAssetsAPIView.as_view(), name="report-assets"),
]
