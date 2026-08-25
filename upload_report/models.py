from djongo import models
from bson import ObjectId
from users.models import User
from location.models import Location

def upload_report_file_path(instance, filename):
    return f"reports/{filename}"

class UploadReport(models.Model):
    MEMBER_TYPE_CHOICES = [
        ('internal', 'Internal'),
        ('external', 'External'),
    ]

    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    file = models.FileField(upload_to=upload_report_file_path)
    file_hash = models.CharField(max_length=64, db_index=True)

    location = models.ForeignKey(
        Location, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="reports"
    )

    admin = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="upload_reports"
    )

    member_type = models.CharField(
        max_length=100,
        choices=MEMBER_TYPE_CHOICES,
        blank=True,
        null=True
    )

    uploaded_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    parsed_count = models.IntegerField(default=0)

    class Meta:
        db_table = "upload_reports"
        indexes = [
            models.Index(fields=["admin", "file_hash"])  # ✅ ONLY RULE
        ]

    def __str__(self):
        loc = self.location.location_name if self.location else "NoLocation"
        admin_email = getattr(self.admin, "email", "NoAdmin")
        return f"{self.file} - {loc} ({admin_email})"


class MagicPinUpload(UploadReport):
    """
    Proxy of UploadReport — same table, same form, same save/parse/store
    pipeline (UploadReportAdmin.save_model etc.) — this exists purely to
    give Super Admin a separate, clearly-labeled sidebar tab for magic-pin
    uploads, distinct from the general 'Upload reports' list. A report
    uploaded from here is the exact same kind of row and still shows up in
    the regular Upload reports list too (proxy models share the underlying
    table) — no separate storage, just a separate entry point. See
    upload_report/admin.py's MagicPinUploadAdmin.
    """
    class Meta:
        proxy = True
        app_label = 'upload_report'
        verbose_name = 'Magic Pin Upload'
        verbose_name_plural = 'Magic Pin Upload'


class FixVulnVerification(models.Model):
    """Proxy model for Django admin — no DB table created (managed=False).
    Used only to show pending verifications panel in superadmin."""
    class Meta:
        app_label = 'upload_report'
        managed = False
        verbose_name = 'Pending Verification'
        verbose_name_plural = 'Pending Verifications'


class SupportRequestReview(models.Model):
    """Proxy model for Django admin — no DB table created (managed=False).
    Used only to show the open support-requests panel in superadmin, so
    they can close a ticket directly instead of only ever having it
    auto-close as a side effect of closing the linked vulnerability."""
    class Meta:
        app_label = 'upload_report'
        managed = False
        verbose_name = 'Support Request'
        verbose_name_plural = 'Support Requests'
