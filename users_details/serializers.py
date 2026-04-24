from rest_framework import serializers
from django.contrib.auth import get_user_model
from bson import ObjectId
# from location.models import Location
from .models import UserDetail

User = get_user_model()


def _extract_domain(email: str) -> str:
    value = (email or "").strip().lower()
    if "@" not in value:
        return ""
    return value.rsplit("@", 1)[1]


def _enforce_user_type_email_domain(user_type: str, email: str, admin_email: str):
    """
    Business rule:
    - internal users must use same domain as admin
    - external users must use a different domain than admin
    """
    normalized_type = (user_type or "").strip().lower()
    member_email = (email or "").strip().lower()
    admin_domain = _extract_domain(admin_email)
    member_domain = _extract_domain(member_email)

    if not normalized_type or not member_email:
        return

    if not admin_domain or not member_domain:
        raise serializers.ValidationError({
            "email": "Invalid email format for admin or member."
        })

    if normalized_type == "internal" and member_domain != admin_domain:
        raise serializers.ValidationError({
            "email": (
                f"Internal users must use the same domain as admin "
                f"(@{admin_domain})."
            )
        })

    if normalized_type == "external" and member_domain == admin_domain:
        raise serializers.ValidationError({
            "email": (
                f"External users cannot use admin domain (@{admin_domain}). "
                f"Please use a different domain."
            )
        })

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
            "Member_role", "team_id", "team_name",
            "created_at", "updated_at"
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
            "Member_role",
            "team_id",
            "team_name"
        ]

    def validate_admin_id(self, value):
        try:
            return User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist")

    def validate(self, attrs):
        admin_user = attrs.get("admin_id")
        _enforce_user_type_email_domain(
            user_type=attrs.get("user_type"),
            email=attrs.get("email"),
            admin_email=getattr(admin_user, "email", ""),
        )
        return attrs

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
            "Member_role",
            "team_id",
            "team_name"
        ]

    def validate_admin_id(self, value):
        if value:
            try:
                return User.objects.get(id=value)
            except User.DoesNotExist:
                raise serializers.ValidationError("Admin with this ID does not exist")
        return None

    def validate(self, attrs):
        current_instance = getattr(self, "instance", None)
        effective_user_type = attrs.get("user_type")
        effective_email = attrs.get("email")
        effective_admin = attrs.get("admin_id")

        if current_instance is not None:
            effective_user_type = effective_user_type or current_instance.user_type
            effective_email = effective_email or current_instance.email
            effective_admin = effective_admin or current_instance.admin

        _enforce_user_type_email_domain(
            user_type=effective_user_type,
            email=effective_email,
            admin_email=getattr(effective_admin, "email", ""),
        )
        return attrs

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