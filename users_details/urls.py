from django.urls import path
from .views import (
    UserDetailCreateView,
    UserDetailListView,
    UserDetailSearchView,
    UserDetailView,
    UserDetailUpdateView,
    UserDetailDeleteView
)

app_name = "users_details"

urlpatterns = [
    path("add-user-detail/", UserDetailCreateView.as_view(), name="userdetail-create"),
    path("list-user-details/", UserDetailListView.as_view(), name="userdetail-list"),
    path("search-user-details/", UserDetailSearchView.as_view(), name="userdetail-search"),
    path("user-detail/<str:detail_id>/", UserDetailView.as_view(), name="userdetail-detail"),
    path("user-detail/<str:detail_id>/update/", UserDetailUpdateView.as_view(), name="userdetail-update"),
    path("user-detail/<str:detail_id>/delete/", UserDetailDeleteView.as_view(), name="userdetail-delete"),
]
