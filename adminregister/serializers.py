from rest_framework import serializers

class AdminRegisterSimpleVulnSerializer(serializers.Serializer):
    """
    Minimal serializer returning exactly the fields your frontend needs.
    """
    vul_name = serializers.CharField(allow_blank=True, allow_null=True)
    asset = serializers.CharField(allow_blank=True, allow_null=True)
    severity = serializers.CharField(allow_blank=True, allow_null=True)
    first_observation = serializers.CharField(allow_null=True)
    second_observation = serializers.CharField(allow_null=True)
    status = serializers.CharField()  # will be 'open' by default

    

class FixVulnerabilitySerializer(serializers.Serializer):
    # host_name = serializers.CharField()
    pass
    

class RaiseSupportRequestSerializer(serializers.Serializer):
    vulnerability_id = serializers.CharField()
    step = serializers.CharField()          # Step 1 / Step 2 / All Steps
    description = serializers.CharField()