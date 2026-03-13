from django.urls import path
from .views import (
    UserRiskCriteriaListView,
    UserRiskCriteriaDetailView,
    UserRiskCriteriaUpdateView,
    UserRiskCriteriaDeleteView,
    UserRiskCriteriaCalendarView,
)

app_name = 'userrisk_criteria'

urlpatterns = [
    path('risks/', UserRiskCriteriaListView.as_view(), name='user-risk-list'),
    path('risks/<str:risk_id>/', UserRiskCriteriaDetailView.as_view(), name='user-risk-detail'),
    path('risks/<str:risk_id>/update/', UserRiskCriteriaUpdateView.as_view(), name='user-risk-update'),
    path('risks/<str:risk_id>/delete/', UserRiskCriteriaDeleteView.as_view(), name='user-risk-delete'),
    path('risks/<str:risk_id>/calendar/', UserRiskCriteriaCalendarView.as_view(), name='user-risk-calendar'),
]
