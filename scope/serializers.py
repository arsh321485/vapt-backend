from rest_framework import serializers
from bson import ObjectId
from .models import Scope
from .utils import classify_target


class ScopeSerializer(serializers.ModelSerializer):
    """Serializer for Scope model."""
    
    testing_type = serializers.ChoiceField(
        choices=["white_box", "grey_box", "black_box"],
        required=False,
        allow_null=True,
        allow_blank=True
    )
    
    class Meta:
        model = Scope
        fields = ['_id', 'admin', 'target_type', 'target_value', 'notes', 'is_active', 'testing_type', 'subnet_count', 'file_upload', 'created_at', 'updated_at']
        read_only_fields = ['_id', 'created_at', 'updated_at']
    
    def to_representation(self, instance):
        """Ensure all ObjectId fields and target_value are returned as strings from MongoDB."""
        data = super().to_representation(instance)
        
        # Convert _id (ObjectId) to string
        if '_id' in data and data['_id'] is not None:
            try:
                if isinstance(data['_id'], ObjectId):
                    data['_id'] = str(data['_id'])
                else:
                    data['_id'] = str(data['_id'])
            except (TypeError, ValueError):
                data['_id'] = str(instance._id) if hasattr(instance, '_id') else None
        
        # Convert admin (ForeignKey) to string if it's an ObjectId
        if 'admin' in data and data['admin'] is not None:
            try:
                if isinstance(data['admin'], ObjectId):
                    data['admin'] = str(data['admin'])
                elif hasattr(instance, 'admin') and instance.admin:
                    data['admin'] = str(instance.admin.id)
            except (TypeError, ValueError, AttributeError):
                pass
        
        # Convert file_upload (ForeignKey) to string if it's an ObjectId
        if 'file_upload' in data and data['file_upload'] is not None:
            try:
                if isinstance(data['file_upload'], ObjectId):
                    data['file_upload'] = str(data['file_upload'])
                elif hasattr(instance, 'file_upload') and instance.file_upload:
                    data['file_upload'] = str(instance.file_upload._id)
            except (TypeError, ValueError, AttributeError):
                pass
        
        # Ensure target_value is a string (not converted to number by MongoDB/Djongo)
        if 'target_value' in data:
            if data['target_value'] is not None:
                try:
                    data['target_value'] = str(data['target_value'])
                except (TypeError, ValueError):
                    # Fallback if conversion fails - get directly from instance
                    data['target_value'] = str(instance.target_value) if hasattr(instance, 'target_value') and instance.target_value else None
            else:
                data['target_value'] = None
        
        return data
    
    def validate_target_value(self, value):
        """Validate that target_value is a valid IP or URL."""
        result = classify_target(value)
        if not result:
            raise serializers.ValidationError(
                f"'{value}' is not accepted. Only Internal IP, External IP, Mobile URL, and Web URL are accepted."
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
                    f"'{target_value}' is not accepted. Only Internal IP, External IP, Mobile URL, and Web URL are accepted."
                )
        
        return data


class ScopeCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating Scope entries."""
    
    testing_type = serializers.ChoiceField(
        choices=["white_box", "grey_box", "black_box"],
        required=False,
        allow_null=True,
        allow_blank=True,
        help_text="Single testing type. If not provided, will use current_testing_box parameter or admin's selected testing type."
    )
    
    class Meta:
        model = Scope
        fields = ['target_type', 'target_value', 'notes', 'is_active', 'testing_type', 'subnet_count']
    
    def validate_target_value(self, value):
        """Validate and normalize target_value - preserve exact IP format."""
        # Ensure value is a string
        if not isinstance(value, str):
            value = str(value)
        value = value.strip()
        
        result = classify_target(value)
        if not result:
            raise serializers.ValidationError(
                f"'{value}' is not accepted. Only Internal IP, External IP, Mobile URL, and Web URL are accepted."
            )
        # Return normalized value (removes /32, adds https:// for URLs, but preserves IP format)
        _, normalized = result
        # Ensure normalized value is a string (not converted to number)
        return str(normalized)
    
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
                    f"'{target_value}' is not accepted. Only Internal IP, External IP, Mobile URL, and Web URL are accepted."
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
    testing_type = serializers.ChoiceField(
        choices=["white_box", "grey_box", "black_box"],
        required=False,
        allow_null=True,
        allow_blank=True
    )
    
    class Meta:
        model = Scope
        fields = ['_id', 'admin', 'admin_id', 'admin_email', 'target_type', 'target_value', 'notes', 'is_active', 'testing_type', 'subnet_count', 'file_upload_id', 'created_at', 'updated_at']
    
    def to_representation(self, instance):
        """Ensure all ObjectId fields and target_value are returned as strings from MongoDB."""
        data = super().to_representation(instance)
        
        # Convert _id (ObjectId) to string
        if '_id' in data and data['_id'] is not None:
            try:
                if isinstance(data['_id'], ObjectId):
                    data['_id'] = str(data['_id'])
                else:
                    data['_id'] = str(data['_id'])
            except (TypeError, ValueError):
                data['_id'] = str(instance._id) if hasattr(instance, '_id') else None
        
        # Convert admin (ForeignKey) to string if it's an ObjectId
        if 'admin' in data and data['admin'] is not None:
            try:
                if isinstance(data['admin'], ObjectId):
                    data['admin'] = str(data['admin'])
                elif hasattr(instance, 'admin') and instance.admin:
                    data['admin'] = str(instance.admin.id)
            except (TypeError, ValueError, AttributeError):
                pass
        
        # Ensure target_value is a string (not converted to number by MongoDB/Djongo)
        if 'target_value' in data and data['target_value'] is not None:
            try:
                data['target_value'] = str(data['target_value'])
            except (TypeError, ValueError):
                data['target_value'] = str(instance.target_value) if hasattr(instance, 'target_value') and instance.target_value else None
        
        return data
    
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
