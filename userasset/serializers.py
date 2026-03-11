from rest_framework import serializers


class UserAssetSerializer(serializers.Serializer):
    asset = serializers.CharField()
    first_seen = serializers.CharField(allow_null=True)
    last_seen = serializers.CharField(allow_null=True)
    member_type = serializers.CharField(allow_null=True, allow_blank=True, required=False)
    total_vulnerabilities = serializers.IntegerField()
    severity_counts = serializers.DictField(child=serializers.IntegerField())
    host_information = serializers.DictField(
        child=serializers.CharField(allow_blank=True),
        required=False,
        allow_null=True
    )
    assigned_teams = serializers.ListField(child=serializers.CharField(), required=False)


class UserAssetVulnSerializer(serializers.Serializer):
    asset = serializers.CharField()
    exposure = serializers.CharField(allow_blank=True, allow_null=True)
    owner = serializers.CharField(allow_blank=True, allow_null=True)
    severity = serializers.CharField(allow_blank=True)
    vul_name = serializers.CharField(allow_blank=True)
    vendor_fix_available = serializers.CharField()
    cvss_score = serializers.CharField(allow_blank=True, allow_null=True)
    description = serializers.CharField(allow_blank=True)
    status = serializers.CharField()
    assigned_team = serializers.CharField(allow_blank=True, allow_null=True, required=False)
