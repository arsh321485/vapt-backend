from django.urls import path
from .views import PartnerApplicationCreateAPIView, PartnerFormOptionsAPIView

urlpatterns = [
    path("apply/", PartnerApplicationCreateAPIView.as_view(), name="partner-apply"),
    path("form-options/", PartnerFormOptionsAPIView.as_view(), name="partner-form-options"),
]
