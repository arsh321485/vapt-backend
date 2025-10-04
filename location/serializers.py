from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Location
import logging

logger = logging.getLogger(__name__)
User = get_user_model()


# class LocationSerializer(serializers.ModelSerializer):
#     admin_id = serializers.CharField(source='admin.id', read_only=True)
    
#     class Meta:
#         model = Location
#         fields = ['_id', 'admin_id', 'location_name', 'created_at', 'updated_at']
#         read_only_fields = ['_id', 'admin_id', 'created_at', 'updated_at']

class LocationSerializer(serializers.ModelSerializer):
    """Serializer for listing locations"""
    admin_id = serializers.CharField(source='admin.id', read_only=True)
    admin_name = serializers.CharField(source='admin.username', read_only=True)  # optional: show admin name

    class Meta:
        model = Location
        fields = ['_id', 'admin_id', 'admin_name', 'location_name', 'created_at', 'updated_at']
        read_only_fields = ['_id', 'admin_id', 'admin_name', 'created_at', 'updated_at']
class LocationCreateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True)
    
    class Meta:
        model = Location
        fields = ['admin_id', 'location_name']
    
    def validate_admin_id(self, value):
        """Validate that admin_id exists in User model"""
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist")
        return value
    
    def validate_location_name(self, value):
        """Validate location name length and format"""
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Location name must be at least 2 characters long")
        return value.strip()
    
    def create(self, validated_data):
        admin_id = validated_data.pop('admin_id')
        admin = User.objects.get(id=admin_id)
        location = Location.objects.create(admin=admin, **validated_data)
        return location


class LocationUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['location_name']
    
    def validate_location_name(self, value):
        """Validate location name length and format"""
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError("Location name must be at least 2 characters long")
        return value.strip() if value else value



