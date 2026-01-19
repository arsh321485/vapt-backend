from rest_framework import serializers
from django.contrib.auth import get_user_model
from bson import ObjectId
# from location.models import Location
from .models import UserDetail

User = get_user_model()

class UserDetailSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(source="admin.id", read_only=True)
    # location_id = serializers.CharField(source="location._id", read_only=True)
    Member_role = serializers.ListField(child=serializers.CharField(), read_only=True)

    class Meta:
        model = UserDetail
        fields = [
            "_id", "admin_id", 
            "first_name", "last_name",
            "user_type", "email", 
            "Member_role", "created_at", "updated_at"
        ]
        read_only_fields = ["_id", "created_at", "updated_at"]


# class UserDetailCreateSerializer(serializers.ModelSerializer):
#     admin_id = serializers.CharField(write_only=True)
#     location_id = serializers.CharField(write_only=True)

#     # allow list input
#     Member_role = serializers.ListField(
#         child=serializers.CharField(),
#         allow_empty=False
#     )

#     class Meta:
#         model = UserDetail
#         fields = [
#             "admin_id", "location_id",
#             "first_name", "last_name",
#             "user_type", "email", "select_location", "Member_role"
#         ]

#     def validate_admin_id(self, value):
#         try:
#             return User.objects.get(id=value)
#         except User.DoesNotExist:
#             raise serializers.ValidationError("Admin with this ID does not exist")

#     def validate_location_id(self, value):
#         try:
#             return Location.objects.get(_id=ObjectId(value))
#         except Location.DoesNotExist:
#             raise serializers.ValidationError("Location with this ID does not exist")

#     def create(self, validated_data):
#         admin = validated_data.pop("admin_id")
#         location = validated_data.pop("location_id")
#         return UserDetail.objects.create(admin=admin, location=location, **validated_data)


class UserDetailCreateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True)

    # allow list input
    Member_role = serializers.ListField(
        child=serializers.CharField(),
        allow_empty=False
    )

    class Meta:
        model = UserDetail
        fields = [
            "admin_id",
            "first_name",
            "last_name",
            "user_type",
            "email",
            "Member_role"
        ]

    def validate_admin_id(self, value):
        try:
            return User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist")

    def create(self, validated_data):
        admin = validated_data.pop("admin_id")
        return UserDetail.objects.create(
            admin=admin,
            **validated_data
        )

# class UserDetailUpdateSerializer(serializers.ModelSerializer):
#     admin_id = serializers.CharField(write_only=True, required=False)
#     location_id = serializers.CharField(write_only=True, required=False)
#     Member_role = serializers.ListField(child=serializers.CharField(), required=False)

#     class Meta:
#         model = UserDetail
#         fields = [
#             "admin_id", "location_id",
#             "first_name", "last_name",
#             "user_type", "email", "select_location", "Member_role"
#         ]

#     def validate_admin_id(self, value):
#         if value:
#             try:
#                 return User.objects.get(id=value)
#             except User.DoesNotExist:
#                 raise serializers.ValidationError("Admin with this ID does not exist")
#         return None

#     def validate_location_id(self, value):
#         if value:
#             try:
#                 return Location.objects.get(_id=ObjectId(value))
#             except Location.DoesNotExist:
#                 raise serializers.ValidationError("Location with this ID does not exist")
#         return None

#     def update(self, instance, validated_data):
#         if "admin_id" in validated_data:
#             instance.admin = validated_data.pop("admin_id")
#         if "location_id" in validated_data:
#             instance.location = validated_data.pop("location_id")

#         for attr, value in validated_data.items():
#             setattr(instance, attr, value)

#         instance.save()
#         return instance
    
class UserDetailUpdateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True, required=False)
    Member_role = serializers.ListField(
        child=serializers.CharField(),
        required=False
    )

    class Meta:
        model = UserDetail
        fields = [
            "admin_id",
            "first_name",
            "last_name",
            "user_type",
            "email",
            "Member_role"
        ]

    def validate_admin_id(self, value):
        if value:
            try:
                return User.objects.get(id=value)
            except User.DoesNotExist:
                raise serializers.ValidationError("Admin with this ID does not exist")
        return None

    def update(self, instance, validated_data):
        if "admin_id" in validated_data:
            instance.admin = validated_data.pop("admin_id")

        for attr, value in validated_data.items():
            setattr(instance, attr, value)

        instance.save()
        return instance
    
    
class UserDetailRoleUpdateSerializer(serializers.Serializer):
    old_role = serializers.CharField(required=False, allow_blank=True)
    new_roles = serializers.ListField(child=serializers.CharField(), allow_empty=False)
    # operation: add (default) or replace
    operation = serializers.ChoiceField(choices=("add", "replace"), required=False, default="add")
    # confirm optional: if present and False -> reject; if omitted or True -> proceed
    confirm = serializers.BooleanField(required=False)

    def validate_new_roles(self, value):
        if not isinstance(value, list) or len(value) == 0:
            raise serializers.ValidationError("new_roles must be a non-empty list")
        return [v.strip() for v in value if v is not None]