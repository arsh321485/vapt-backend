from djongo import models
from bson import ObjectId
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from django.contrib.auth import get_user_model

User = get_user_model()

class Ticket(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", _("Open")
        CLOSE = "close", _("Close")

    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="tickets_admin")
    subject = models.CharField(max_length=512)
    asset = models.CharField(max_length=255, blank=True, null=True)
    description = models.TextField(blank=True, null=True)
    category = models.CharField(max_length=255, blank=True, null=True)
    status = models.CharField(max_length=10, choices=Status.choices, default=Status.OPEN)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.subject} ({self.get_status_display()})"
