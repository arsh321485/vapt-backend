from django.urls import path
from .views import WebinarRegistrationCreateAPIView, WebinarFormOptionsAPIView

urlpatterns = [
    path("register/", WebinarRegistrationCreateAPIView.as_view(), name="webinar-register"),
    path("form-options/", WebinarFormOptionsAPIView.as_view(), name="webinar-form-options"),
]
