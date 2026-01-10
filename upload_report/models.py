from djongo import models
from bson import ObjectId
from users.models import User
from location.models import Location

def upload_report_file_path(instance, filename):
    return f"reports/{filename}"

class UploadReport(models.Model):
    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    file = models.FileField(upload_to=upload_report_file_path)
    file_hash = models.CharField(max_length=64, db_index=True)  # ✅ ADD THIS

    location = models.ForeignKey(
        Location, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="reports"
    )

    admin = models.ForeignKey(
        User, on_delete=models.SET_NULL,
        null=True, blank=True, related_name="upload_reports"
    )

    member_type = models.CharField(max_length=100, blank=True, null=True)

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
