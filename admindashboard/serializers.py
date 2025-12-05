from rest_framework import serializers

class TotalAssetsSerializer(serializers.Serializer):
    total_assets = serializers.IntegerField()

class AvgScoreSerializer(serializers.Serializer):
    avg_score = serializers.FloatField(allow_null=True)

class VulnerabilitiesSerializer(serializers.Serializer):
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()

class ReportSummarySerializer(serializers.Serializer):
    report_id = serializers.CharField()
    total_assets = serializers.IntegerField()
    avg_score = serializers.FloatField(allow_null=True)
    vulnerabilities = VulnerabilitiesSerializer()
    
class MitigationTimelineSerializer(serializers.Serializer):
    critical = serializers.CharField(allow_blank=True)
    critical_hours = serializers.IntegerField()
    high = serializers.CharField(allow_blank=True)
    high_hours = serializers.IntegerField()
    medium = serializers.CharField(allow_blank=True)
    medium_hours = serializers.IntegerField()
    low = serializers.CharField(allow_blank=True)
    low_hours = serializers.IntegerField()
    mitigation_timeline_total_hours = serializers.IntegerField()

class MeanTimeRemediateSerializer(serializers.Serializer):
    report_id = serializers.CharField()
    mitigation_timeline_total_hours = serializers.IntegerField()
    mitigation_timeline_total_human = serializers.CharField()
    mean_time_weighted_hours = serializers.FloatField()
    mean_time_weighted_human = serializers.CharField()
    mean_time_simple_hours = serializers.FloatField()
    mean_time_simple_human = serializers.CharField()
    total_vulnerabilities = serializers.IntegerField()
