from rest_framework import serializers
from .models import Scope, ScopeEntry


class ScopeEntrySerializer(serializers.ModelSerializer):
    """Serializer for ScopeEntry model."""

    class Meta:
        model = ScopeEntry
        fields = [
            "id",
            "value",
            "entry_type",
            "subnet_mask",
            "is_internal",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["id", "created_at", "updated_at"]


class ScopeSerializer(serializers.ModelSerializer):
    """Serializer for Scope model with entries."""
    entries = ScopeEntrySerializer(many=True, read_only=True)
    admin_email = serializers.EmailField(source="admin.email", read_only=True)
    entry_count = serializers.SerializerMethodField()

    class Meta:
        model = Scope
        fields = [
            "id",
            "admin",
            "admin_email",
            "name",
            "testing_type",
            "is_locked",
            "locked_by",
            "locked_at",
            "created_at",
            "updated_at",
            "entries",
            "entry_count",
        ]
        read_only_fields = [
            "id",
            "admin",
            "is_locked",
            "locked_by",
            "locked_at",
            "created_at",
            "updated_at",
        ]

    def get_entry_count(self, obj):
        return obj.entries.count()


class ScopeListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for listing scopes (without entries)."""
    admin_email = serializers.EmailField(source="admin.email", read_only=True)
    entry_count = serializers.SerializerMethodField()

    class Meta:
        model = Scope
        fields = [
            "id",
            "admin",
            "admin_email",
            "name",
            "testing_type",
            "is_locked",
            "locked_by",
            "locked_at",
            "created_at",
            "updated_at",
            "entry_count",
        ]

    def get_entry_count(self, obj):
        return obj.entries.count()


class ScopeUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating scope details."""

    class Meta:
        model = Scope
        fields = ["name"]


class ScopeEntryUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating a scope entry."""

    class Meta:
        model = ScopeEntry
        fields = ["value", "entry_type", "subnet_mask", "is_internal"]

    def validate_entry_type(self, value):
        valid_types = ["internal_ip", "external_ip", "web_url", "mobile_url", "subnet"]
        if value not in valid_types:
            raise serializers.ValidationError(
                f"Invalid entry_type. Must be one of: {', '.join(valid_types)}"
            )
        return value


class ScopeLockSerializer(serializers.Serializer):
    """Serializer for locking/unlocking a scope."""
    action = serializers.ChoiceField(choices=["lock", "unlock"])


class BulkEntrySerializer(serializers.Serializer):
    """Serializer for adding multiple entries at once."""
    values = serializers.ListField(
        child=serializers.CharField(max_length=500),
        min_length=1,
        max_length=1000
    )
    expand_subnets = serializers.BooleanField(default=True)

    def validate_values(self, values):
        cleaned = list(set(v.strip() for v in values if v.strip()))
        if not cleaned:
            raise serializers.ValidationError("No valid values provided")
        return cleaned


class FileUploadSerializer(serializers.Serializer):
    """Serializer for file upload."""
    file = serializers.FileField()
    expand_subnets = serializers.BooleanField(default=True)

    def validate_file(self, file):
        filename = file.name.lower()
        valid_extensions = [".csv", ".xlsx", ".xls", ".txt"]

        if not any(filename.endswith(ext) for ext in valid_extensions):
            raise serializers.ValidationError(
                f"Unsupported file type. Allowed: {', '.join(valid_extensions)}"
            )

        max_size = 10 * 1024 * 1024
        if file.size > max_size:
            raise serializers.ValidationError("File size exceeds 10MB limit")

        return file


class ContactSuperAdminSerializer(serializers.Serializer):
    """Serializer for admin to contact super admin about scope issues."""
    subject = serializers.CharField(max_length=200)
    message = serializers.CharField(max_length=2000)

    def validate_subject(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Subject must be at least 5 characters")
        return value.strip()

    def validate_message(self, value):
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Message must be at least 10 characters")
        return value.strip()


class ContactSupportSerializer(serializers.Serializer):
    """Serializer for admin to contact super admin for general support."""
    subject = serializers.CharField(max_length=200)
    message = serializers.CharField(max_length=2000)
    scope_id = serializers.CharField(max_length=50, required=False, allow_blank=True)

    def validate_subject(self, value):
        if len(value.strip()) < 5:
            raise serializers.ValidationError("Subject must be at least 5 characters")
        return value.strip()

    def validate_message(self, value):
        if len(value.strip()) < 10:
            raise serializers.ValidationError("Message must be at least 10 characters")
        return value.strip()
