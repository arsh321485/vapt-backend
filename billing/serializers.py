from rest_framework import serializers
from .models import Subscription, Invoice, SalesLead
from .plans import PLAN_CHOICES, MODE_CHOICES, CYCLE_CHOICES


class PlanEstimateRequestSerializer(serializers.Serializer):
    plan = serializers.ChoiceField(choices=PLAN_CHOICES)
    mode = serializers.ChoiceField(choices=MODE_CHOICES, required=False)
    billing_cycle = serializers.ChoiceField(choices=CYCLE_CHOICES, required=False)


class PremiumCheckoutRequestSerializer(serializers.Serializer):
    mode = serializers.ChoiceField(choices=MODE_CHOICES)
    billing_cycle = serializers.ChoiceField(choices=CYCLE_CHOICES, required=False)

    def validate(self, attrs):
        if attrs["mode"] == "management" and not attrs.get("billing_cycle"):
            raise serializers.ValidationError(
                {"billing_cycle": "billing_cycle is required for Management mode."}
            )
        return attrs


class CustomLeadRequestSerializer(serializers.Serializer):
    full_name = serializers.CharField(max_length=255)
    work_email = serializers.EmailField()
    company = serializers.CharField(max_length=255, required=False, allow_blank=True)
    estimated_assets = serializers.CharField(max_length=50, required=False, allow_blank=True)


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = [
            "stripe_invoice_id", "amount", "currency", "asset_count",
            "status", "hosted_invoice_url", "created_at",
        ]


class SubscriptionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subscription
        fields = [
            "plan", "mode", "billing_cycle", "asset_count", "price_per_ip",
            "amount_due", "currency", "status",
            "current_period_start", "current_period_end", "trial_end",
            "created_at", "updated_at",
        ]


class SalesLeadSerializer(serializers.ModelSerializer):
    class Meta:
        model = SalesLead
        fields = ["full_name", "work_email", "company", "estimated_assets", "status", "created_at"]
