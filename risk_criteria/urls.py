from django.urls import path
from .views import (
    RiskCriteriaCreateView,
    RiskCriteriaListView,
    RiskCriteriaDetailView,
    RiskCriteriaUpdateView,
    RiskCriteriaDeleteView,
)

app_name = 'risk_criteria'

urlpatterns = [
    path('add-risk/', RiskCriteriaCreateView.as_view(), name='risk-create'),
    path('risks/', RiskCriteriaListView.as_view(), name='risk-list'),
    path('risks/<str:risk_id>/', RiskCriteriaDetailView.as_view(), name='risk-detail'),
    path('risks/<str:risk_id>/update/', RiskCriteriaUpdateView.as_view(), name='risk-update'),
    path('risks/<str:risk_id>/delete/', RiskCriteriaDeleteView.as_view(), name='risk-delete'),
]
