from django.contrib import admin
from .models import UserDetail


@admin.register(UserDetail)
class UserDetailAdmin(admin.ModelAdmin):
    list_display = ("_id", "first_name", "last_name", "email", "user_type", "Member_role", "admin", "location", "created_at")
    search_fields = ("first_name", "last_name", "email", "user_type", "Member_role", "admin__email", "location__location_name")
    list_filter = ("user_type", "Member_role", "created_at")
    readonly_fields = ("_id", "created_at", "updated_at")
