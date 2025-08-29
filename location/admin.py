from django.contrib import admin
from .models import Location


@admin.register(Location)
class LocationAdmin(admin.ModelAdmin):
    list_display = ('_id', 'location_name', 'admin', 'created_at', 'updated_at')
    list_filter = ('created_at', 'updated_at')
    search_fields = ('location_name', 'admin__email', 'admin__firstname', 'admin__lastname')
    ordering = ('-created_at',)
    readonly_fields = ('_id', 'created_at', 'updated_at')
    
    fieldsets = (
        ('Location Information', {
            'fields': ('location_name', 'admin')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )