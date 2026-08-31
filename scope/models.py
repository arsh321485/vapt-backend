from djongo import models
from django.conf import settings
from django.utils import timezone
import uuid


def scope_source_file_path(instance, filename):
    return f"scope_files/{instance.admin_id}/{filename}"


class Scope(models.Model):
    """
    Represents a penetration testing scope containing multiple entries (IPs, URLs, subnets).
    Same admin can have multiple scopes with different testing types.
    """
    TESTING_TYPE_CHOICES = (
        ("white_box", "White Box"),
        ("grey_box", "Grey Box"),
        ("black_box", "Black Box"),
    )

    id = models.CharField(
        primary_key=True,
        default=uuid.uuid4,
        max_length=36,
        editable=False
    )
    admin = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="scopes"
    )
    name = models.CharField(max_length=255)
    testing_type = models.CharField(
        max_length=20,
        choices=TESTING_TYPE_CHOICES,
        default="black_box"
    )
    # The original uploaded CSV/XLSX/etc, kept so the Super Admin can view/
    # download exactly what the admin submitted — not just the parsed
    # ScopeEntry rows. Blank for scopes entered manually (no source file).
    source_file = models.FileField(
        upload_to=scope_source_file_path,
        null=True,
        blank=True,
    )
    is_locked = models.BooleanField(default=False)
    locked_by = models.EmailField(null=True, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
    # Set once a Super Admin uploads a real test result "for" this scope
    # (Django Admin's "Add Upload Report" form gets a "Fulfills Scope"
    # dropdown that sets these) — lets the admin-panel scope list show
    # "pending" vs "fulfilled", and is how _auto_generate_cards_bg knows
    # whether a given report should trigger the scope-completion email.
    fulfilled_report_id = models.CharField(max_length=64, null=True, blank=True)
    fulfilled_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "scopes"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.testing_type}) - {self.admin.email}"

    def save(self, *args, **kwargs):
        if self.id and not isinstance(self.id, str):
            self.id = str(self.id)
        super().save(*args, **kwargs)


class ScopeEntry(models.Model):
    """
    Individual entry within a scope (IP address, URL, or subnet).
    """
    ENTRY_TYPE_CHOICES = (
        ("internal_ip", "Internal IP"),
        ("external_ip", "External IP"),
        ("web_url", "Web URL"),
        ("mobile_url", "Mobile URL"),
        ("subnet", "Subnet"),
    )

    id = models.CharField(
        primary_key=True,
        default=uuid.uuid4,
        max_length=36,
        editable=False
    )
    scope = models.ForeignKey(
        Scope,
        on_delete=models.CASCADE,
        related_name="entries"
    )
    value = models.CharField(max_length=500)
    entry_type = models.CharField(
        max_length=20,
        choices=ENTRY_TYPE_CHOICES
    )
    subnet_mask = models.CharField(max_length=50, null=True, blank=True)
    is_internal = models.BooleanField(default=False)
    # Set only when `value` is one of the individual IPs a subnet got
    # auto-expanded into at submission time (process_entries() in
    # scope/utils.py) — holds the original subnet notation the admin
    # actually typed (e.g. "10.0.0.10/24"), so the Super Admin's download
    # can show exactly what was entered instead of 256 separate IP rows.
    # Blank for entries the admin typed directly (already the original
    # value) and for subnets too large to expand (already stored as-is).
    expanded_from = models.CharField(max_length=500, null=True, blank=True)
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "scope_entries"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.value} ({self.entry_type})"

    def save(self, *args, **kwargs):
        if self.id and not isinstance(self.id, str):
            self.id = str(self.id)
        super().save(*args, **kwargs)
