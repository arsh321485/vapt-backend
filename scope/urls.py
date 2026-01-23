from django.urls import path
from .views import (
    ScopeListView,
    ScopeCreateView,
    ScopeDetailView,
    ScopeBulkDeleteView,
    ScopeStatsView,
    ScopeByTypeView,
)

app_name = 'scope'

urlpatterns = [
    # List all targets
    path('', ScopeListView.as_view(), name='scope-list'),
    
    # Unified create endpoint (handles single, bulk text, and file upload)
    path('create/', ScopeCreateView.as_view(), name='scope-create'),
    
    # Statistics and grouped views (must come before <str:pk>/ to avoid conflicts)
    path('stats/', ScopeStatsView.as_view(), name='scope-stats'),
    path('by-type/', ScopeByTypeView.as_view(), name='scope-by-type'),
    
    # Bulk operations
    path('bulk-delete/', ScopeBulkDeleteView.as_view(), name='scope-bulk-delete'),
    
    # Detail, update, delete (must be last to avoid matching other paths)
    path('<str:pk>/', ScopeDetailView.as_view(), name='scope-detail'),
]
