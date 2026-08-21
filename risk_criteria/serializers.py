from rest_framework import serializers
from .models import RiskCriteria
from .utils import parse_days

_SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def _validate_severity_order(values: dict):
    """
    Enforce: critical days <= high days <= medium days <= low days.
    More severe findings must get an equal-or-shorter remediation window
    than less severe ones — e.g. Critical=3 days means High can't be set
    to anything less than 3.

    `values` must already have all four keys resolved (either freshly
    submitted, or merged with the existing record's saved values for a
    partial update) — raises on the first out-of-order pair found.
    """
    parsed = {}
    for key in _SEVERITY_ORDER:
        try:
            parsed[key] = parse_days(values[key])
        except (ValueError, TypeError, KeyError):
            raise serializers.ValidationError(
                {key: f"Could not understand '{values.get(key)}' as a day/week value."}
            )

    for lower, higher in zip(_SEVERITY_ORDER, _SEVERITY_ORDER[1:]):
        if parsed[higher] < parsed[lower]:
            raise serializers.ValidationError(
                f"{higher.capitalize()} ({values[higher]}) can't be shorter than "
                f"{lower.capitalize()} ({values[lower]}). Each severity must take "
                f"at least as long to fix as the one above it."
            )


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

    def validate(self, attrs):
        _validate_severity_order(attrs)
        return attrs


class RiskCriteriaUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = RiskCriteria
        fields = ['critical', 'high', 'medium', 'low']

    def validate(self, attrs):
        # Partial update — a field left out of this request still has its
        # current saved value, so merge before checking the ordering rule
        # (otherwise e.g. changing only "high" would validate against a
        # missing "critical"/"medium"/"low" instead of the real ones).
        merged = {
            "critical": self.instance.critical,
            "high": self.instance.high,
            "medium": self.instance.medium,
            "low": self.instance.low,
        }
        merged.update({k: v for k, v in attrs.items() if k in merged})
        _validate_severity_order(merged)
        return attrs
