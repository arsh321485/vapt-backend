from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import RiskCriteria

User = get_user_model()


class RiskCriteriaSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(source='admin.id', read_only=True)

    class Meta:
        model = RiskCriteria
        fields = ['_id', 'admin_id', 'critical', 'high', 'medium', 'low', 'created_at', 'updated_at']
        read_only_fields = ['_id', 'admin_id', 'created_at', 'updated_at']


class RiskCriteriaCreateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True)

    class Meta:
        model = RiskCriteria
        fields = ['admin_id', 'critical', 'high', 'medium', 'low']

    def validate_admin_id(self, value):
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist")
        return value

    def create(self, validated_data):
        admin_id = validated_data.pop('admin_id')
        admin = User.objects.get(id=admin_id)
        risk_criteria = RiskCriteria.objects.create(admin=admin, **validated_data)
        return risk_criteria


class RiskCriteriaUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskCriteria
        fields = ['critical', 'high', 'medium', 'low']
