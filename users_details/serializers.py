from rest_framework import serializers
from django.contrib.auth import get_user_model
from bson import ObjectId
from location.models import Location
from .models import UserDetail

User = get_user_model()


class UserDetailSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(source="admin.id", read_only=True)
    location_id = serializers.CharField(source="location._id", read_only=True)

    class Meta:
        model = UserDetail
        fields = [
            "_id", "admin_id", "location_id",
            "first_name", "last_name",
            "user_type", "email", "select_location",
            "Member_role", "created_at", "updated_at"
        ]
        read_only_fields = ["_id", "created_at", "updated_at"]


class UserDetailCreateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True)
    location_id = serializers.CharField(write_only=True)

    class Meta:
        model = UserDetail
        fields = [
            "admin_id", "location_id",
            "first_name", "last_name",
            "user_type", "email", "select_location", "Member_role"
        ]

    def validate_admin_id(self, value):
        try:
            return User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist")

    def validate_location_id(self, value):
        try:
            return Location.objects.get(_id=ObjectId(value))
        except Location.DoesNotExist:
            raise serializers.ValidationError("Location with this ID does not exist")

    def create(self, validated_data):
        admin = validated_data.pop("admin_id")
        location = validated_data.pop("location_id")
        return UserDetail.objects.create(admin=admin, location=location, **validated_data)
    
    
class UserDetailUpdateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True, required=False)
    location_id = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = UserDetail
        fields = [
            "admin_id", "location_id",
            "first_name", "last_name",
            "user_type", "email", "select_location", "Member_role"
        ]

    def validate_admin_id(self, value):
        if value:
            try:
                return User.objects.get(id=value)
            except User.DoesNotExist:
                raise serializers.ValidationError("Admin with this ID does not exist")
        return None

    def validate_location_id(self, value):
        if value:
            try:
                return Location.objects.get(_id=ObjectId(value))
            except Location.DoesNotExist:
                raise serializers.ValidationError("Location with this ID does not exist")
        return None

    def update(self, instance, validated_data):
        # Update admin and location if provided
        if "admin_id" in validated_data:
            instance.admin = validated_data.pop("admin_id")
        if "location_id" in validated_data:
            instance.location = validated_data.pop("location_id")

        # Update other fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance
