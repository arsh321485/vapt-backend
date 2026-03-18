import re
from rest_framework import serializers
from location.serializers import VALID_COUNTRIES
from .models import ProjectDetail, TestingMethodology


VALID_TESTING_TYPES = ['black_box', 'grey_box', 'white_box']

VALID_ASSESSMENT_CATEGORIES = [
    'network', 'web_app', 'mobile_app', 'api',
    'cloud', 'social_eng', 'wireless', 'iot_ot'
]

VALID_COMPLIANCE_STANDARDS = [
    'owasp', 'nist', 'iso_27001', 'pci_dss', 'hipaa', 'soc2', 'gdpr'
]


class ProjectDetailSerializer(serializers.ModelSerializer):
    project_id = serializers.SerializerMethodField()
    admin_id = serializers.SerializerMethodField()

    class Meta:
        model = ProjectDetail
        fields = [
            'project_id', 'admin_id',
            'organization_name', 'industry', 'country',
            'full_name', 'email_address', 'phone_number',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['project_id', 'admin_id', 'created_at', 'updated_at']

    def get_project_id(self, obj):
        return str(obj._id)

    def get_admin_id(self, obj):
        return str(obj.admin_id)

    def validate_phone_number(self, value):
        if not value:
            return value
        digits_only = re.sub(r'[\s\-\(\)\+]', '', value.strip())
        if not digits_only.isdigit():
            raise serializers.ValidationError(
                "Phone number can only contain digits, +, -, spaces, and parentheses."
            )
        if len(digits_only) < 7 or len(digits_only) > 15:
            raise serializers.ValidationError(
                "Phone number must have 7 to 15 digits (international standard)."
            )
        return value.strip()

    def validate_country(self, value):
        if value not in VALID_COUNTRIES:
            raise serializers.ValidationError(
                "Invalid country. Please select a valid country from the list."
            )
        return value

    def validate_industry(self, value):
        valid = [c[0] for c in ProjectDetail.INDUSTRY_CHOICES]
        if value not in valid:
            raise serializers.ValidationError(
                f"Invalid industry. Choose from: {', '.join(valid)}"
            )
        return value


class TestingMethodologySerializer(serializers.ModelSerializer):
    methodology_id = serializers.SerializerMethodField()
    admin_id = serializers.SerializerMethodField()

    class Meta:
        model = TestingMethodology
        fields = [
            'methodology_id', 'admin_id',
            'testing_type', 'assessment_categories', 'assessment_notes',
            'network_perspective', 'environment',
            'compliance_standards', 'compliance_notes',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['methodology_id', 'admin_id', 'created_at', 'updated_at']

    def get_methodology_id(self, obj):
        return str(obj._id)

    def get_admin_id(self, obj):
        return str(obj.admin_id)

    def validate_testing_type(self, value):
        if value not in VALID_TESTING_TYPES:
            raise serializers.ValidationError(
                f"Invalid testing type: '{value}'. Valid: {VALID_TESTING_TYPES}"
            )
        return value

    def validate_assessment_categories(self, value):
        if not isinstance(value, list) or len(value) == 0:
            raise serializers.ValidationError("Select at least one assessment category.")
        invalid = [v for v in value if v not in VALID_ASSESSMENT_CATEGORIES]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid categories: {invalid}. Valid: {VALID_ASSESSMENT_CATEGORIES}"
            )
        return value

    def validate_compliance_standards(self, value):
        if not isinstance(value, list) or len(value) == 0:
            raise serializers.ValidationError("Select at least one compliance standard.")
        invalid = [v for v in value if v not in VALID_COMPLIANCE_STANDARDS]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid standards: {invalid}. Valid: {VALID_COMPLIANCE_STANDARDS}"
            )
        return value

    def validate_network_perspective(self, value):
        valid = [c[0] for c in TestingMethodology.NETWORK_PERSPECTIVE_CHOICES]
        if value not in valid:
            raise serializers.ValidationError(
                f"Invalid network perspective. Choose from: {', '.join(valid)}"
            )
        return value

    def validate_environment(self, value):
        valid = [c[0] for c in TestingMethodology.ENVIRONMENT_CHOICES]
        if value not in valid:
            raise serializers.ValidationError(
                f"Invalid environment. Choose from: {', '.join(valid)}"
            )
        return value
