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
