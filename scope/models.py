from djongo import models
from bson import ObjectId
from users.models import User


class ScopeFileUpload(models.Model):
    """
    Model to track file uploads for scope targets.
    """
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    admin = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name="scope_file_uploads"
    )
    file_name = models.CharField(max_length=255)
    file_size = models.IntegerField()  # Size in bytes
    file_type = models.CharField(max_length=50)  # .xlsx, .csv, .txt, etc.
    targets_count = models.IntegerField(default=0)  # Number of targets extracted
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = "scope_file_uploads"
        indexes = [
            models.Index(fields=["admin", "created_at"]),
        ]
    
    def __str__(self):
        return f"{self.file_name} ({self.admin.email}) - {self.targets_count} targets"


class Scope(models.Model):
    """
    Model to store assessment targets (Internal IPs, External IPs, Web URLs, Mobile URLs)
    associated with an admin user.
    """
    TARGET_TYPE_CHOICES = (
        ('internal_ip', 'Internal IP Address'),
        ('external_ip', 'External IP Address'),
        ('web_url', 'Web URL'),
        ('mobile_url', 'Mobile URL'),
        ('subnet', 'Subnet'),
    )
    
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    admin = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name="scope_targets"
    )
    target_type = models.CharField(
        max_length=20,
        choices=TARGET_TYPE_CHOICES,
        db_index=True
    )
    target_value = models.CharField(max_length=500, db_index=True)
    notes = models.TextField(blank=True, null=True)
    is_active = models.BooleanField(default=True)
    # Subnet count (number of IPs in subnet, only for subnets)
    subnet_count = models.IntegerField(null=True, blank=True, help_text="Number of IPs in subnet (only for subnets)")
    # Link to file upload if created from file
    file_upload = models.ForeignKey(
        ScopeFileUpload,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scope_targets"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = "scope"
        indexes = [
            models.Index(fields=["admin", "target_type"]),
            models.Index(fields=["admin", "target_value"]),
            models.Index(fields=["admin", "is_active"]),
            models.Index(fields=["file_upload"]),
        ]
        unique_together = [['admin', 'target_value']]  # Prevent duplicate targets per admin
    
    def __str__(self):
        return f"{self.target_type}: {self.target_value} ({self.admin.email})"
