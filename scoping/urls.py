from django.urls import path
from .views import ProjectDetailView, TestingMethodologyView

urlpatterns = [
    path('project-details/', ProjectDetailView.as_view(), name='scoping-project-details'),
    path('testing-methodology/', TestingMethodologyView.as_view(), name='scoping-testing-methodology'),
]
