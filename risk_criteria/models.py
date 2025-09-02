from djongo import models
from bson import ObjectId
from users.models import User


class RiskCriteria(models.Model):
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)  # MongoDB ObjectId
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="riskcriteria_admin")
    critical = models.CharField(max_length=255)
    high = models.CharField(max_length=255)
    medium = models.CharField(max_length=255)
    low = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"RiskCriteria ({self.admin.email})"
