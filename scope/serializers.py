from rest_framework import serializers
from .models import Scope
from .utils import classify_target


class ScopeSerializer(serializers.ModelSerializer):
    """Serializer for Scope model."""
    
    class Meta:
        model = Scope
        fields = ['_id', 'admin', 'target_type', 'target_value', 'notes', 'is_active', 'subnet_count', 'created_at', 'updated_at']
        read_only_fields = ['_id', 'created_at', 'updated_at']
    
    def validate_target_value(self, value):
        """Validate that target_value is a valid IP or URL."""
        result = classify_target(value)
        if not result:
            raise serializers.ValidationError(
                f"'{value}' is not a valid IP address or URL."
            )
        return value
    
    def validate(self, data):
        """Validate that target_type matches the target_value."""
        target_value = data.get('target_value')
        target_type = data.get('target_type')
        
        if target_value and target_type:
            result = classify_target(target_value)
            if result:
                detected_type, normalized_value = result
                if detected_type != target_type:
                    raise serializers.ValidationError(
                        f"Target type mismatch. '{target_value}' is detected as '{detected_type}', "
                        f"but you specified '{target_type}'."
                    )
                # Update with normalized value
                data['target_value'] = normalized_value
            else:
                raise serializers.ValidationError(
                    f"'{target_value}' is not a valid IP address or URL."
                )
        
        return data


class ScopeCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating Scope entries."""
    
    class Meta:
        model = Scope
        fields = ['target_type', 'target_value', 'notes', 'is_active', 'subnet_count']
    
    def validate_target_value(self, value):
        """Validate and normalize target_value."""
        result = classify_target(value)
        if not result:
            raise serializers.ValidationError(
                f"'{value}' is not a valid IP address or URL."
            )
        # Return normalized value
        _, normalized = result
        return normalized
    
    def validate(self, data):
        """Auto-detect target_type from target_value."""
        target_value = data.get('target_value')
        
        if target_value:
            result = classify_target(target_value)
            if result:
                detected_type, normalized_value = result
                data['target_type'] = detected_type
                data['target_value'] = normalized_value
            else:
                raise serializers.ValidationError(
                    f"'{target_value}' is not a valid IP address or URL."
                )
        
        return data


class ScopeBulkCreateSerializer(serializers.Serializer):
    """Serializer for bulk creating Scope entries from text or file."""
    
    targets = serializers.CharField(
        required=False,
        help_text="Text containing targets (one per line). IPs and URLs will be extracted."
    )
    
    def validate_targets(self, value):
        """Validate targets text."""
        if not value or not value.strip():
            raise serializers.ValidationError("Targets text cannot be empty.")
        return value


class ScopeListSerializer(serializers.ModelSerializer):
    """Serializer for listing Scope entries with admin email."""
    
    admin_email = serializers.EmailField(source='admin.email', read_only=True)
    file_upload_id = serializers.SerializerMethodField()
    admin_id = serializers.CharField(source='admin.id', read_only=True)
    
    class Meta:
        model = Scope
        fields = ['_id', 'admin', 'admin_id', 'admin_email', 'target_type', 'target_value', 'notes', 'is_active', 'subnet_count', 'file_upload_id', 'created_at', 'updated_at']
    
    def get_file_upload_id(self, obj):
        """Return file upload ID if exists."""
        return str(obj.file_upload._id) if obj.file_upload else None


class ScopeStatsSerializer(serializers.Serializer):
    """Serializer for scope statistics."""
    
    success = serializers.BooleanField(default=True)
    message = serializers.CharField(default="Statistics retrieved successfully.")
    admin_id = serializers.CharField(required=False, allow_null=True)
    admin_email = serializers.EmailField(required=False, allow_null=True)
    total_targets = serializers.IntegerField()
    internal_ips = serializers.IntegerField()
    external_ips = serializers.IntegerField()
    web_urls = serializers.IntegerField()
    mobile_urls = serializers.IntegerField()
    subnets = serializers.IntegerField()
    active_targets = serializers.IntegerField()
    inactive_targets = serializers.IntegerField()
