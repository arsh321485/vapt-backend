from rest_framework import serializers

class AdminAssetSerializer(serializers.Serializer):
    asset = serializers.CharField()
    owner = serializers.CharField(allow_blank=True, allow_null=True)
    exposure = serializers.CharField(allow_blank=True, allow_null=True)
    first_seen = serializers.CharField(allow_null=True)
    last_seen = serializers.CharField(allow_null=True)
    total_vulnerabilities = serializers.IntegerField()
    severity_counts = serializers.DictField(child=serializers.IntegerField())
    host_information = serializers.DictField(child=serializers.CharField(allow_blank=True), required=False, allow_null=True)
