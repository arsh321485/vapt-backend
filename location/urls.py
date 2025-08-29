from django.urls import path
from .views import (
    LocationCreateView,
    LocationListView,
    LocationDetailView,
    LocationUpdateView,
    LocationDeleteView,
)

app_name = 'location'

urlpatterns = [
    # CRUD Operations
    path('add-location/', LocationCreateView.as_view(), name='location-create'),
    path('locations/', LocationListView.as_view(), name='location-list'),
    path('locations/<str:location_id>/', LocationDetailView.as_view(), name='location-detail'),
    path('locations/<str:location_id>/update/', LocationUpdateView.as_view(), name='location-update'),
    path('locations/<str:location_id>/delete/', LocationDeleteView.as_view(), name='location-delete'),
]

