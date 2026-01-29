from django.contrib import admin
from django.utils import timezone
from django.contrib import messages
from .models import Scope, ScopeEntry
from .utils import send_scope_lock_notification


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    list_display = ["name", "admin", "testing_type", "is_locked", "locked_by", "locked_at", "entry_count", "created_at"]
    list_filter = ["testing_type", "is_locked", "created_at"]
    search_fields = ["name", "admin__email"]
    readonly_fields = ["id", "created_at", "updated_at", "locked_by", "locked_at"]
    list_per_page = 25
    ordering = ["-created_at"]

    fieldsets = (
        ("Scope Information", {
            "fields": ("id", "name", "admin", "testing_type")
        }),
        ("Lock Status", {
            "fields": ("is_locked", "locked_by", "locked_at"),
            "classes": ("collapse",)
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",)
        }),
    )

    actions = ["lock_selected_scopes", "unlock_selected_scopes"]

    def entry_count(self, obj):
        """Display the number of entries in the scope."""
        return obj.entries.count()
    entry_count.short_description = "Entries"

    def lock_selected_scopes(self, request, queryset):
        """Lock selected scopes and send email notifications."""
        locked_count = 0
        already_locked = 0

        for scope in queryset:
            if scope.is_locked:
                already_locked += 1
                continue

            scope.is_locked = True
            scope.locked_by = request.user.email
            scope.locked_at = timezone.now()
            scope.save()

            # Send email notification to scope owner
            send_scope_lock_notification(
                scope_owner_email=scope.admin.email,
                scope_name=scope.name,
                locked_by_email=request.user.email
            )
            locked_count += 1

        if locked_count:
            self.message_user(
                request,
                f"Successfully locked {locked_count} scope(s). Email notifications sent.",
                messages.SUCCESS
            )
        if already_locked:
            self.message_user(
                request,
                f"{already_locked} scope(s) were already locked.",
                messages.WARNING
            )

    lock_selected_scopes.short_description = "Lock selected scopes (sends email notification)"

    def unlock_selected_scopes(self, request, queryset):
        """Unlock selected scopes."""
        unlocked_count = 0
        already_unlocked = 0

        for scope in queryset:
            if not scope.is_locked:
                already_unlocked += 1
                continue

            scope.is_locked = False
            scope.locked_by = None
            scope.locked_at = None
            scope.save()
            unlocked_count += 1

        if unlocked_count:
            self.message_user(
                request,
                f"Successfully unlocked {unlocked_count} scope(s).",
                messages.SUCCESS
            )
        if already_unlocked:
            self.message_user(
                request,
                f"{already_unlocked} scope(s) were already unlocked.",
                messages.WARNING
            )

    unlock_selected_scopes.short_description = "Unlock selected scopes"

    def has_change_permission(self, request, obj=None):
        """Only super admin can change scopes."""
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        """Only super admin can delete scopes."""
        return request.user.is_superuser

    def has_add_permission(self, request):
        """Only super admin can add scopes via admin."""
        return request.user.is_superuser


@admin.register(ScopeEntry)
class ScopeEntryAdmin(admin.ModelAdmin):
    list_display = ["value", "entry_type", "is_internal", "scope_name", "scope_locked", "created_at"]
    list_filter = ["entry_type", "is_internal", "scope__testing_type", "created_at"]
    search_fields = ["value", "scope__name", "scope__admin__email"]
    readonly_fields = ["id", "created_at", "updated_at"]
    list_per_page = 50
    ordering = ["-created_at"]

    fieldsets = (
        ("Entry Information", {
            "fields": ("id", "scope", "value", "entry_type")
        }),
        ("Classification", {
            "fields": ("is_internal", "subnet_mask")
        }),
        ("Timestamps", {
            "fields": ("created_at", "updated_at"),
            "classes": ("collapse",)
        }),
    )

    def scope_name(self, obj):
        """Display the scope name."""
        return obj.scope.name
    scope_name.short_description = "Scope"
    scope_name.admin_order_field = "scope__name"

    def scope_locked(self, obj):
        """Display if the parent scope is locked."""
        return obj.scope.is_locked
    scope_locked.short_description = "Locked"
    scope_locked.boolean = True

    def has_change_permission(self, request, obj=None):
        """Only super admin can change entries."""
        return request.user.is_superuser

    def has_delete_permission(self, request, obj=None):
        """Only super admin can delete entries."""
        return request.user.is_superuser

    def has_add_permission(self, request):
        """Only super admin can add entries via admin."""
        return request.user.is_superuser
