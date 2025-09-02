from django.contrib import admin
from .models import RiskCriteria


@admin.register(RiskCriteria)
class RiskCriteriaAdmin(admin.ModelAdmin):
    list_display = ('_id', 'admin', 'critical', 'high', 'medium', 'low', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('admin__email', 'admin__firstname', 'admin__lastname', 'critical', 'high', 'medium', 'low')
    ordering = ('-created_at',)
    readonly_fields = ('_id', 'created_at', 'updated_at')

    fieldsets = (
        ('Admin', {
            'fields': ('admin',)
        }),
        ('Risk Levels', {
            'fields': ('critical', 'high', 'medium', 'low')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
