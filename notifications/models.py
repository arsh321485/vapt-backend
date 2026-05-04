from djongo import models
from bson import ObjectId


class Notification(models.Model):
    NOTIF_TYPES = [
        ('deadline_today',            'Deadline Today'),
        ('deadline_tomorrow',         'Deadline Tomorrow'),
        ('deadline_updated',          'Deadline Updated'),
        ('overdue',                   'Overdue'),
        ('asset_held',                'Asset Held'),
        ('asset_deleted',             'Asset Deleted'),
        ('support_request_created',   'Support Request Created'),
        ('support_request_received',  'Support Request Received'),
        ('extension_requested',       'Extension Requested'),
        ('extension_approved',        'Extension Approved'),
        ('extension_rejected',        'Extension Rejected'),
        ('asset_unhold',              'Asset Unhold'),
        ('vuln_closed',               'Vulnerability Closed'),
    ]

    RECIPIENT_TYPES = [
        ('admin', 'Admin'),
        ('user',  'User'),
    ]

    _id             = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    admin_id        = models.CharField(max_length=100)       # UUID string — same pattern as rest of project
    recipient_email = models.CharField(max_length=254, blank=True, default='')
    recipient_type  = models.CharField(max_length=10, choices=RECIPIENT_TYPES)
    notif_type      = models.CharField(max_length=50, choices=NOTIF_TYPES)
    title           = models.CharField(max_length=255)
    message         = models.TextField()
    metadata        = models.JSONField(default=dict, blank=True)
    is_read         = models.BooleanField(default=False)
    created_at      = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']
