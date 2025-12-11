from django.urls import path
from .views import ReportAssetsAPIView,AssetSearchAPIView,AssetDeleteAPIView

urlpatterns = [
    path("report/<str:report_id>/assets/", ReportAssetsAPIView.as_view(), name="report-assets"),
    path("assets/search/", AssetSearchAPIView.as_view(), name="report-asset-search"),
    # delete host from report (host_name should be URL-encoded when calling)
    path("report/<str:report_id>/assets/<path:host_name>/", AssetDeleteAPIView.as_view(), name="report-asset-delete"),
]
