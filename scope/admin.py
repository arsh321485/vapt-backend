from django.contrib import admin
from .models import Scope, ScopeFileUpload


@admin.register(ScopeFileUpload)
class ScopeFileUploadAdmin(admin.ModelAdmin):
    list_display = ['_id', 'admin', 'file_name', 'file_type', 'targets_count', 'created_at']
    list_filter = ['file_type', 'created_at']
    search_fields = ['file_name', 'admin__email']
    readonly_fields = ['_id', 'created_at']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('admin')


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    list_display = ['_id', 'admin', 'target_type', 'target_value', 'is_active', 'file_upload', 'created_at']
    list_filter = ['target_type', 'is_active', 'created_at']
    search_fields = ['target_value', 'admin__email']
    readonly_fields = ['_id', 'created_at', 'updated_at']
    list_editable = ['is_active']
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('admin', 'file_upload')
