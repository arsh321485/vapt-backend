from django.contrib import admin
from .models import UploadReport

@admin.register(UploadReport)
class UploadReportAdmin(admin.ModelAdmin):
    list_display = ('_id', 'file', 'get_location_name', 'get_admin_email', 'uploaded_at')
    search_fields = ('file',)
    list_filter = ('uploaded_at',)

    def get_location_name(self, obj):
        return getattr(obj.location, "location_name", None)
    get_location_name.short_description = "Location"

    def get_admin_email(self, obj):
        return getattr(obj.admin, "email", None)
    get_admin_email.short_description = "Admin"
