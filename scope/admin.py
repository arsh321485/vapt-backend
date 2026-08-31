from django.contrib import admin
from django.urls import path, reverse
from django.utils import timezone
from django.utils.html import format_html
from django.contrib import messages
from django.shortcuts import get_object_or_404
from django.http import HttpResponse
from .models import Scope, ScopeEntry
from .utils import send_scope_lock_notification


@admin.register(Scope)
class ScopeAdmin(admin.ModelAdmin):
    list_display = ["name", "admin", "is_locked", "locked_by", "locked_at", "entry_count", "download_file", "created_at"]
    list_filter = ["is_locked", "created_at"]
    search_fields = ["name", "admin__email"]
    readonly_fields = ["id", "created_at", "updated_at", "locked_by", "locked_at", "download_file"]
    list_per_page = 25
    ordering = ["-created_at"]

    fieldsets = (
        ("Scope Information", {
            "fields": ("id", "name", "admin", "download_file")
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

    def get_urls(self):
        custom = [
            path(
                "<str:scope_id>/download-csv/",
                self.admin_site.admin_view(self.download_csv_view),
                name="scope_scope_download_csv",
            ),
        ]
        return custom + super().get_urls()

    def download_csv_view(self, request, scope_id):
        """
        Targets-as-CSV, for ANY scope — file-upload or manual entry. Manual
        entry has no original file to hand back (source_file is blank), so
        this is the only download option that works uniformly for both;
        it's what 'download_file' below links to.

        Single "value" column, exactly what the admin typed/uploaded — no
        entry_type/is_internal/subnet_mask, and a subnet that got
        auto-expanded into individual IPs at submission time collapses back
        into the one original subnet line instead of every expanded IP
        (real bug report: a "10.0.0.10/24" entry was downloading as 256
        separate rows). See scope/utils.py's reconstruct_original_scope_values.
        """
        import csv
        from .utils import reconstruct_original_scope_values
        scope = get_object_or_404(Scope, id=scope_id)
        response = HttpResponse(content_type="text/csv")
        safe_name = "".join(c for c in scope.name if c.isalnum() or c in (" ", "-", "_")).strip() or scope.id
        response["Content-Disposition"] = f'attachment; filename="scope_{safe_name}.csv"'
        writer = csv.writer(response)
        writer.writerow(["value"])
        for value in reconstruct_original_scope_values(scope.entries.all().order_by("created_at")):
            writer.writerow([value])
        return response

    def entry_count(self, obj):
        """Display the number of entries in the scope."""
        return obj.entries.count()
    entry_count.short_description = "Entries"

    def download_file(self, obj):
        """
        Always offers a working download, for both scope sources — a CSV of
        the parsed targets, generated fresh from the database on every
        click. Deliberately does NOT link to the raw source_file: that link
        only resolves on whichever server actually received the original
        upload (MongoDB is shared across environments, MEDIA_ROOT disk
        storage is not — confirmed via a real 404 testing locally against a
        scope uploaded through a different server), so it was unreliable
        depending on which server admin happened to be looking from.
        """
        if not obj.pk:
            return "—"
        csv_url = reverse("admin:scope_scope_download_csv", args=[obj.id])
        return format_html('<a href="{}" target="_blank">⬇ Download (CSV)</a>', csv_url)
    download_file.short_description = "Download"

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


# Not registered — no separate "Scope entrys" tab in the admin sidebar.
# Entries are still visible per-scope (Scope.entry_count / the Scope's own
# detail page); this class is kept so it can be re-registered easily if a
# dedicated entries list is ever needed again.
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
