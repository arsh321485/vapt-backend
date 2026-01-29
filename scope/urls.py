from django.urls import path
from .views import (
    ScopeCreateAPIView,
    ScopeListAPIView,
    ScopeDetailAPIView,
    ScopeEntriesAPIView,
    ScopeEntryDeleteAPIView,
    ScopeEntryUpdateAPIView,
    ScopeFileUploadAPIView,
    ScopeLockAPIView,
    TestingTypesAPIView,
    ScopesByAdminAPIView,
)

urlpatterns = [
    # Create scope (file upload OR manual targets)
    path(
        "create/",
        ScopeCreateAPIView.as_view(),
        name="scope-create"
    ),

    # List scopes
    path(
        "",
        ScopeListAPIView.as_view(),
        name="scope-list"
    ),

    # Get testing types used by admin
    path(
        "testing-types/",
        TestingTypesAPIView.as_view(),
        name="testing-types"
    ),

    # List scopes by admin (super admin only)
    path(
        "admin/<str:admin_id>/",
        ScopesByAdminAPIView.as_view(),
        name="scopes-by-admin"
    ),

    # Get/Update/Delete scope by ID
    path(
        "<str:scope_id>/",
        ScopeDetailAPIView.as_view(),
        name="scope-detail"
    ),

    # List/Add entries for a scope
    path(
        "<str:scope_id>/entries/",
        ScopeEntriesAPIView.as_view(),
        name="scope-entries"
    ),

    # Delete a single entry
    path(
        "<str:scope_id>/entries/<str:entry_id>/",
        ScopeEntryDeleteAPIView.as_view(),
        name="scope-entry-delete"
    ),

    # Update a single entry
    path(
        "<str:scope_id>/entries/<str:entry_id>/update/",
        ScopeEntryUpdateAPIView.as_view(),
        name="scope-entry-update"
    ),

    # Upload file to existing scope
    path(
        "<str:scope_id>/upload/",
        ScopeFileUploadAPIView.as_view(),
        name="scope-upload"
    ),

    # Lock/Unlock scope
    path(
        "<str:scope_id>/lock/",
        ScopeLockAPIView.as_view(),
        name="scope-lock"
    ),
]
