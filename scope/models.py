from djongo import models
from django.conf import settings
from django.utils import timezone
import uuid


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
    is_locked = models.BooleanField(default=False)
    locked_by = models.EmailField(null=True, blank=True)
    locked_at = models.DateTimeField(null=True, blank=True)
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
