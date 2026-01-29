from django.contrib import admin
from .models import Scope, ScopeEntry


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    list_display = ["name", "admin", "testing_type", "is_locked", "created_at"]
    list_filter = ["testing_type", "is_locked", "created_at"]
    search_fields = ["name", "admin__email"]
    readonly_fields = ["id", "created_at", "updated_at"]


@admin.register(ScopeEntry)
class ScopeEntryAdmin(admin.ModelAdmin):
    list_display = ["value", "entry_type", "is_internal", "scope", "created_at"]
    list_filter = ["entry_type", "is_internal", "created_at"]
    search_fields = ["value", "scope__name"]
    readonly_fields = ["id", "created_at", "updated_at"]
