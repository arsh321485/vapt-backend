from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Ticket


User = get_user_model()


"""
------------------------------------------------------
  TICKET CREATE / DETAIL / LIST UNIFIED SERIALIZER
------------------------------------------------------
This serializer works for:
✔ Creating a ticket
✔ Updating a ticket
✔ Reading a ticket
✔ Listing all tickets
------------------------------------------------------
"""

class TicketSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField(read_only=True)

    # admin_id → only for write (create/update)
    admin_id = serializers.CharField(write_only=True)

    # admin_email → only for read
    admin_email = serializers.CharField(source="admin.email", read_only=True)

    class Meta:
        model = Ticket
        fields = [
            "id", "_id", "admin_id", "admin_email",
            "subject", "asset", "description", "category",
            "status", "created_at", "updated_at"
        ]
        read_only_fields = ["_id", "created_at", "updated_at"]

    # Convert MongoDB _id to string
    def get_id(self, obj):
        return str(obj._id)

    # Convert admin_id → User object
    def validate_admin_id(self, value):
        try:
            user = User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist.")
        return user

    # Validate status
    def validate_status(self, value):
        if value not in dict(Ticket.Status.choices):
            raise serializers.ValidationError("Invalid ticket status.")
        return value

    # Create Ticket
    def create(self, validated_data):
        admin = validated_data.pop("admin_id")     # This is already a User object
        return Ticket.objects.create(admin=admin, **validated_data)

    # Update Ticket
    def update(self, instance, validated_data):
        if "admin_id" in validated_data:
            instance.admin = validated_data.pop("admin_id")

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance



"""
------------------------------------------------------
  TICKET LIST SERIALIZER (USED FOR OPEN/CLOSED LISTS)
------------------------------------------------------
"""

class TicketListSerializer(serializers.ModelSerializer):
    id = serializers.SerializerMethodField()
    admin_id = serializers.CharField(source="admin.id", read_only=True)
    admin_email = serializers.CharField(source="admin.email", read_only=True)

    class Meta:
        model = Ticket
        fields = [
            "id", "_id", "admin_id", "admin_email",
            "subject", "asset", "description", "category",
            "status", "created_at", "updated_at"
        ]
        read_only_fields = ["_id", "created_at", "updated_at"]

    def get_id(self, obj):
        return str(obj._id)
