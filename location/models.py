from djongo import models
from bson import ObjectId
from users.models import User  

class Location(models.Model):
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)  # MongoDB ObjectId
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="admin_id")
    location_name = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.location_name} ({self.admin.email})"
