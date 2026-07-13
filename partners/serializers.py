from rest_framework import serializers
from location.serializers import VALID_COUNTRIES

COMPANY_SIZE_CHOICES = ["1-50", "51-200", "201-500", "500+"]

PARTNER_TYPE_CHOICES = [
    "Referral Partner",
    "Reseller",
    "Managed Service Provider (MSP)",
    "Consulting Partner",
]


class PartnerApplicationSerializer(serializers.Serializer):
    # Contact Information
    full_name        = serializers.CharField(max_length=255)
    job_title         = serializers.CharField(max_length=255, required=False, allow_blank=True, default="")
    work_email        = serializers.EmailField()
    phone_number      = serializers.CharField(max_length=30, required=False, allow_blank=True, default="")
    linkedin_profile  = serializers.URLField(required=False, allow_blank=True, default="")

    # Company Information
    company_name      = serializers.CharField(max_length=255)
    website           = serializers.URLField(required=False, allow_blank=True, default="")
    country           = serializers.CharField(max_length=100)
    industry          = serializers.CharField(max_length=255, required=False, allow_blank=True, default="")
    company_size      = serializers.ChoiceField(choices=COMPANY_SIZE_CHOICES, required=False, allow_blank=True, default="")
    year_founded      = serializers.IntegerField(required=False, allow_null=True, default=None)

    # Partnership Details
    partner_type      = serializers.ChoiceField(choices=PARTNER_TYPE_CHOICES)
    why_partner       = serializers.CharField(required=False, allow_blank=True, default="")
    markets_regions   = serializers.CharField(max_length=255, required=False, allow_blank=True, default="")
    target_customer   = serializers.CharField(max_length=255, required=False, allow_blank=True, default="")
    promotion_plan    = serializers.CharField(required=False, allow_blank=True, default="")

    # Qualification
    sells_similar_service        = serializers.BooleanField()
    estimated_referrals_per_year = serializers.IntegerField(required=False, allow_null=True, default=None)
    total_active_clients         = serializers.IntegerField(required=False, allow_null=True, default=None)
    audience_description         = serializers.CharField(required=False, allow_blank=True, default="")

    # Consent
    agreed_privacy_policy   = serializers.BooleanField()
    consent_communications  = serializers.BooleanField(required=False, default=False)

    def validate_agreed_privacy_policy(self, value):
        if not value:
            raise serializers.ValidationError("You must agree to the privacy policy to submit an application.")
        return value

    def validate_country(self, value):
        if value not in VALID_COUNTRIES:
            raise serializers.ValidationError("Invalid country name. Only country names are allowed.")
        return value
