from django.urls import path
from .views import (
    UserDetailCreateView,
    UserDetailListView,
    UserDetailSearchView,
    UserDetailView,
    UserDetailUpdateView,
    UserDetailRoleDeleteView,
    UserDetailCompleteDeleteView,
    UserDetailRoleUpdateView,
    UserDetailByAdminAPIView
)

app_name = "users_details"

urlpatterns = [
    path("add-user-detail/", UserDetailCreateView.as_view(), name="userdetail-create"),
    path("list-user-details/", UserDetailListView.as_view(), name="userdetail-list"),
    path("search-user-details/", UserDetailSearchView.as_view(), name="userdetail-search"),
    path("user-detail/<str:detail_id>/", UserDetailView.as_view(), name="userdetail-detail"),
    path("user-detail/<str:detail_id>/update/", UserDetailUpdateView.as_view(), name="userdetail-update"),
    path("user-detail/<str:detail_id>/delete-role/", UserDetailRoleDeleteView.as_view(), name="userdetail-delete-role"),
    path("user-detail/<str:detail_id>/update-role/", UserDetailRoleUpdateView.as_view(), name="userdetail-update-role"),
    path("user-detail/<str:detail_id>/delete/", UserDetailCompleteDeleteView.as_view(), name="userdetail-delete-complete"),
    path(
    "admin/<str:admin_id>/user-details/",
    UserDetailByAdminAPIView.as_view(),
    name="userdetail-by-admin"
),
]
