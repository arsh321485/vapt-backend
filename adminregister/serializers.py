from rest_framework import serializers

class AdminRegisterSimpleVulnSerializer(serializers.Serializer):
    """
    Serializer for vulnerability register with plugin_id for unique identification.
    """
    plugin_id = serializers.CharField(allow_blank=True, allow_null=True)  # Unique identifier
    vul_name = serializers.CharField(allow_blank=True, allow_null=True)
    asset = serializers.CharField(allow_blank=True, allow_null=True)
    severity = serializers.CharField(allow_blank=True, allow_null=True)
    port = serializers.CharField(allow_blank=True, allow_null=True)  # Port number
    protocol = serializers.CharField(allow_blank=True, allow_null=True)  # Protocol (tcp/udp)
    first_observation = serializers.CharField(allow_null=True)
    second_observation = serializers.CharField(allow_null=True)
    status = serializers.CharField()  # will be 'open' by default

    

class FixVulnerabilityCreateSerializer(serializers.Serializer):
    """
    Serializer for creating a fix vulnerability with required and optional fields.
    """
    id = serializers.CharField(required=True)
    plugin_name = serializers.CharField(required=True)
    risk_factor = serializers.CharField(required=True)
    port = serializers.CharField(required=False, allow_blank=True, default="")
    status = serializers.ChoiceField(
        choices=["open", "in_progress", "closed"],
        default="open",
        required=False
    )
    vulnerability_type = serializers.CharField(
        default="SQL Injection",
        required=False,
        allow_blank=True
    )
    affected_ports_ranges = serializers.CharField(
        required=False,
        allow_blank=True,
        default=""
    )
    file_path = serializers.CharField(
        required=False,
        allow_blank=True,
        default="N/A"
    )
    

class RaiseSupportRequestSerializer(serializers.Serializer):
    step = serializers.CharField()
    description = serializers.CharField()
    
    
class CreateTicketSerializer(serializers.Serializer):
    category = serializers.CharField()
    subject = serializers.CharField()
    description = serializers.CharField()


class FixStepFeedbackSerializer(serializers.Serializer):
    """Serializer for fix step feedback."""
    step_number = serializers.IntegerField(min_value=1, max_value=6)
    feedback_comment = serializers.CharField()
    fix_status = serializers.ChoiceField(
        choices=["fixed", "partially_fixed", "not_fixed"]
    )


class FixVulnerabilityFinalFeedbackSerializer(serializers.Serializer):
    """
    Serializer for final feedback after vulnerability closure.
    Only allowed after all 6 steps are completed and vulnerability is CLOSED.
    """
    feedback_comment = serializers.CharField()
    fix_result = serializers.ChoiceField(
        choices=["resolved", "partially_resolved", "not_resolved"]
    )