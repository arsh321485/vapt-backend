from django.urls import path
from .views import ProjectDetailView, TestingMethodologyView, ScopingSubmitView, UploadStatusView

urlpatterns = [
    path('project-details/', ProjectDetailView.as_view(), name='scoping-project-details'),
    path('testing-methodology/', TestingMethodologyView.as_view(), name='scoping-testing-methodology'),
    path('submit/', ScopingSubmitView.as_view(), name='scoping-submit'),
    path('upload-status/', UploadStatusView.as_view(), name='scoping-upload-status'),
]
