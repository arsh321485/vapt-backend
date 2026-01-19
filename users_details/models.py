from djongo import models
from bson import ObjectId
from users.models import User
# from location.models import Location

class UserDetail(models.Model):
    _id = models.ObjectIdField(primary_key=True, default=ObjectId, editable=False)

    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="userdetails_admin")
    # location = models.ForeignKey(Location, on_delete=models.CASCADE, related_name="locations_admin")
    first_name = models.CharField(max_length=255)
    last_name = models.CharField(max_length=255)
    user_type = models.CharField(max_length=255)
    email = models.EmailField(unique=True)
    # select_location = models.CharField(max_length=255)
    Member_role = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
