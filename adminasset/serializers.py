from rest_framework import serializers
class AdminAssetSerializer(serializers.Serializer):
    asset = serializers.CharField()
    first_seen = serializers.CharField(allow_null=True)
    last_seen = serializers.CharField(allow_null=True)
    total_vulnerabilities = serializers.IntegerField()
    severity_counts = serializers.DictField(child=serializers.IntegerField())
    host_information = serializers.DictField(child=serializers.CharField(allow_blank=True), required=False, allow_null=True)


class AssetSearchSerializer(serializers.Serializer):
    asset = serializers.CharField()
    
class AssetHostVulnSerializer(serializers.Serializer):
    # fields required by frontend for a single host vulnerabilities list
    asset = serializers.CharField()
    exposure = serializers.CharField(allow_blank=True, allow_null=True)
    owner = serializers.CharField(allow_blank=True, allow_null=True)
    severity = serializers.CharField(allow_blank=True)
    vul_name = serializers.CharField(allow_blank=True)
    vendor_fix_available = serializers.CharField()   # will be "Yes"
    cvss_score = serializers.CharField(allow_blank=True, allow_null=True)
    description = serializers.CharField(allow_blank=True)
    

class HoldAssetSerializer(serializers.Serializer):
    report_id = serializers.CharField()
    host_name = serializers.CharField()
    held_at = serializers.DateTimeField()
    held_by = serializers.CharField(allow_null=True, required=False)
    host_entry = serializers.DictField()
    
class HoldAssetListSerializer(serializers.Serializer):
    asset = serializers.CharField()
    total_vulnerabilities = serializers.IntegerField()
    severity_counts = serializers.DictField(child=serializers.IntegerField())
    host_information = serializers.DictField(required=False)
    held_at = serializers.DateTimeField()
    held_by = serializers.CharField(allow_null=True)
