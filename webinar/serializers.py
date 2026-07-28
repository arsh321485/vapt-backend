from rest_framework import serializers

TEAM_SIZE_CHOICES = ["1", "2-5", "6-10", "10+"]


class WebinarRegistrationSerializer(serializers.Serializer):
    full_name = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Full name is required.",
            "blank": "Full name cannot be empty.",
        },
    )
    work_email = serializers.EmailField(
        error_messages={
            "required": "Work email is required.",
            "blank": "Work email cannot be empty.",
            "invalid": "Enter a valid email address.",
        },
    )
    job_title = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Job title is required.",
            "blank": "Job title cannot be empty.",
        },
    )
    company_name = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Company name is required.",
            "blank": "Company name cannot be empty.",
        },
    )
    company_website = serializers.URLField(
        error_messages={
            "required": "Company website is required.",
            "blank": "Company website cannot be empty.",
            "invalid": "Enter a valid website URL, e.g. https://example.com.",
        },
    )
    company_linkedin = serializers.URLField(
        required=False,
        allow_blank=True,
        default="",
        error_messages={"invalid": "Enter a valid LinkedIn URL, e.g. https://linkedin.com/company/your-company."},
    )
    team_size = serializers.ChoiceField(
        choices=TEAM_SIZE_CHOICES,
        error_messages={
            "required": "Please select the team size attending.",
            "invalid_choice": "Team size must be one of: 1, 2-5, 6-10, 10+.",
        },
    )
    team_size_count = serializers.IntegerField(
        required=False,
        allow_null=True,
        default=None,
        min_value=11,
        error_messages={
            "invalid": "Enter a valid number of attendees.",
            "min_value": "Number of attendees must be greater than 10.",
        },
    )
    phone_number = serializers.CharField(
        max_length=30,
        error_messages={
            "required": "Phone number is required.",
            "blank": "Phone number cannot be empty.",
        },
    )

    def validate_work_email(self, value):
        return value.strip().lower()

    def validate(self, attrs):
        if attrs.get("team_size") == "10+" and attrs.get("team_size_count") is None:
            raise serializers.ValidationError(
                {"team_size_count": "Enter the exact number of people attending."}
            )
        return attrs
