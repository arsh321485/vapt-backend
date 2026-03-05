from rest_framework import serializers
from .models import RiskCriteria


class RiskCriteriaSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(source='admin.id', read_only=True)

    class Meta:
        model = RiskCriteria
        fields = ['_id', 'admin_id', 'critical', 'high', 'medium', 'low', 'created_at', 'updated_at']
        read_only_fields = ['_id', 'admin_id', 'created_at', 'updated_at']


class RiskCriteriaCreateSerializer(serializers.ModelSerializer):
    """admin is set from request.user in the view — not passed in body."""

    class Meta:
        model = RiskCriteria
        fields = ['critical', 'high', 'medium', 'low']


class RiskCriteriaUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskCriteria
        fields = ['critical', 'high', 'medium', 'low']
