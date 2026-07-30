from rest_framework import serializers
from location.serializers import VALID_COUNTRIES

COMPANY_SIZE_CHOICES = ["1-50", "51-200", "201-500", "500+"]

PARTNER_TYPE_CHOICES = [
    "Reseller",
    "Gold",
    "Premium",
    "Strategic",
]

# ISO country -> international dialing code, for the phone-number country-code dropdown.
COUNTRY_CALLING_CODES = {
    "Afghanistan": "+93", "Albania": "+355", "Algeria": "+213", "Andorra": "+376",
    "Angola": "+244", "Antigua and Barbuda": "+1268", "Argentina": "+54",
    "Armenia": "+374", "Australia": "+61", "Austria": "+43", "Azerbaijan": "+994",
    "Bahamas": "+1242", "Bahrain": "+973", "Bangladesh": "+880", "Barbados": "+1246",
    "Belarus": "+375", "Belgium": "+32", "Belize": "+501", "Benin": "+229",
    "Bhutan": "+975", "Bolivia": "+591", "Bosnia and Herzegovina": "+387",
    "Botswana": "+267", "Brazil": "+55", "Brunei": "+673", "Bulgaria": "+359",
    "Burkina Faso": "+226", "Burundi": "+257", "Cabo Verde": "+238",
    "Cambodia": "+855", "Cameroon": "+237", "Canada": "+1",
    "Central African Republic": "+236", "Chad": "+235", "Chile": "+56",
    "China": "+86", "Colombia": "+57", "Comoros": "+269", "Congo": "+242",
    "Costa Rica": "+506", "Cote d'Ivoire": "+225", "Croatia": "+385", "Cuba": "+53",
    "Cyprus": "+357", "Czech Republic": "+420",
    "Democratic Republic of the Congo": "+243", "Denmark": "+45", "Djibouti": "+253",
    "Dominica": "+1767", "Dominican Republic": "+1809",
    "Ecuador": "+593", "Egypt": "+20", "El Salvador": "+503",
    "Equatorial Guinea": "+240", "Eritrea": "+291", "Estonia": "+372",
    "Eswatini": "+268", "Ethiopia": "+251",
    "Fiji": "+679", "Finland": "+358", "France": "+33",
    "Gabon": "+241", "Gambia": "+220", "Georgia": "+995", "Germany": "+49",
    "Ghana": "+233", "Greece": "+30", "Grenada": "+1473", "Guatemala": "+502",
    "Guinea": "+224", "Guinea-Bissau": "+245", "Guyana": "+592",
    "Haiti": "+509", "Honduras": "+504", "Hungary": "+36",
    "Iceland": "+354", "India": "+91", "Indonesia": "+62", "Iran": "+98",
    "Iraq": "+964", "Ireland": "+353", "Israel": "+972", "Italy": "+39",
    "Jamaica": "+1876", "Japan": "+81", "Jordan": "+962",
    "Kazakhstan": "+7", "Kenya": "+254", "Kiribati": "+686", "Kosovo": "+383",
    "Kuwait": "+965", "Kyrgyzstan": "+996",
    "Laos": "+856", "Latvia": "+371", "Lebanon": "+961", "Lesotho": "+266",
    "Liberia": "+231", "Libya": "+218", "Liechtenstein": "+423", "Lithuania": "+370",
    "Luxembourg": "+352",
    "Madagascar": "+261", "Malawi": "+265", "Malaysia": "+60", "Maldives": "+960",
    "Mali": "+223", "Malta": "+356", "Marshall Islands": "+692",
    "Mauritania": "+222", "Mauritius": "+230", "Mexico": "+52",
    "Micronesia": "+691", "Moldova": "+373", "Monaco": "+377", "Mongolia": "+976",
    "Montenegro": "+382", "Morocco": "+212", "Mozambique": "+258", "Myanmar": "+95",
    "Namibia": "+264", "Nauru": "+674", "Nepal": "+977", "Netherlands": "+31",
    "New Zealand": "+64", "Nicaragua": "+505", "Niger": "+227", "Nigeria": "+234",
    "North Korea": "+850", "North Macedonia": "+389", "Norway": "+47",
    "Oman": "+968",
    "Pakistan": "+92", "Palau": "+680", "Palestine": "+970", "Panama": "+507",
    "Papua New Guinea": "+675", "Paraguay": "+595", "Peru": "+51",
    "Philippines": "+63", "Poland": "+48", "Portugal": "+351",
    "Qatar": "+974",
    "Romania": "+40", "Russia": "+7", "Rwanda": "+250",
    "Saint Kitts and Nevis": "+1869", "Saint Lucia": "+1758",
    "Saint Vincent and the Grenadines": "+1784", "San Marino": "+378",
    "Sao Tome and Principe": "+239", "Saudi Arabia": "+966", "Senegal": "+221",
    "Serbia": "+381", "Seychelles": "+248", "Sierra Leone": "+232",
    "Singapore": "+65", "Slovakia": "+421", "Slovenia": "+386",
    "Solomon Islands": "+677", "Somalia": "+252", "South Africa": "+27",
    "South Korea": "+82", "South Sudan": "+211", "Spain": "+34",
    "Sri Lanka": "+94", "Sudan": "+249", "Suriname": "+597", "Sweden": "+46",
    "Switzerland": "+41", "Syria": "+963",
    "Taiwan": "+886", "Tajikistan": "+992", "Tanzania": "+255", "Thailand": "+66",
    "Timor-Leste": "+670", "Togo": "+228", "Tonga": "+676",
    "Trinidad and Tobago": "+1868", "Tunisia": "+216", "Turkey": "+90",
    "Turkmenistan": "+993", "Tuvalu": "+688",
    "Uganda": "+256", "Ukraine": "+380", "United Arab Emirates": "+971",
    "United Kingdom": "+44", "United States": "+1", "Uruguay": "+598",
    "Uzbekistan": "+998",
    "Vanuatu": "+678", "Venezuela": "+58", "Vietnam": "+84",
    "Yemen": "+967",
    "Zambia": "+260", "Zimbabwe": "+263",
}

VALID_PHONE_CODES = set(COUNTRY_CALLING_CODES.values())


class PartnerApplicationSerializer(serializers.Serializer):
    # Contact Information
    full_name = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Full name is required.",
            "blank": "Full name cannot be empty.",
        },
    )
    job_title = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Job title is required.",
            "blank": "Job title cannot be empty.",
        },
    )
    work_email = serializers.EmailField(
        error_messages={
            "required": "Work email is required.",
            "blank": "Work email cannot be empty.",
            "invalid": "Enter a valid email address.",
        },
    )
    phone_country_code = serializers.CharField(
        max_length=6,
        required=False,
        allow_blank=True,
        default="",
        error_messages={"blank": "Please select a country code."},
    )
    phone_number = serializers.CharField(
        max_length=30,
        required=False,
        allow_blank=True,
        default="",
        error_messages={"blank": "Phone number cannot be empty."},
    )
    linkedin_profile = serializers.URLField(
        required=False,
        allow_blank=True,
        default="",
        error_messages={"invalid": "Enter a valid LinkedIn URL, e.g. https://linkedin.com/in/username."},
    )

    # Company Information
    company_name = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Company name is required.",
            "blank": "Company name cannot be empty.",
        },
    )
    website = serializers.URLField(
        error_messages={
            "required": "Website is required.",
            "blank": "Website cannot be empty.",
            "invalid": "Enter a valid website URL, e.g. https://example.com.",
        },
    )
    country = serializers.CharField(
        max_length=100,
        error_messages={
            "required": "Country is required.",
            "blank": "Country cannot be empty.",
        },
    )
    industry = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Industry is required.",
            "blank": "Industry cannot be empty.",
        },
    )
    company_size = serializers.ChoiceField(
        choices=COMPANY_SIZE_CHOICES,
        required=False,
        allow_blank=True,
        default="",
        error_messages={"invalid_choice": "Select a valid company size."},
    )
    year_founded = serializers.IntegerField(
        required=False,
        allow_null=True,
        default=None,
        min_value=1800,
        error_messages={
            "invalid": "Enter a valid year.",
            "min_value": "Enter a valid year founded.",
        },
    )

    # Partnership Details
    partner_type = serializers.ChoiceField(
        choices=PARTNER_TYPE_CHOICES,
        error_messages={
            "required": "Partner type is required.",
            "invalid_choice": "Select a valid partner type.",
        },
    )
    why_partner = serializers.CharField(
        error_messages={
            "required": "Please tell us why you want to partner with us.",
            "blank": "Please tell us why you want to partner with us.",
        },
    )
    markets_regions = serializers.CharField(
        max_length=255,
        error_messages={
            "required": "Markets/regions is required.",
            "blank": "Markets/regions cannot be empty.",
        },
    )
    target_customer = serializers.CharField(
        max_length=255,
        required=False,
        allow_blank=True,
        default="",
        error_messages={"blank": "Target customer cannot be empty."},
    )
    promotion_plan = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        error_messages={"blank": "Promotion plan cannot be empty."},
    )

    # Qualification
    sells_similar_service = serializers.BooleanField(
        error_messages={
            "required": "Please tell us if you sell a similar security service.",
            "invalid": "This field must be true or false.",
        },
    )
    estimated_referrals_per_year = serializers.IntegerField(
        min_value=0,
        error_messages={
            "required": "Estimated referrals per year is required.",
            "invalid": "Enter a valid number.",
            "min_value": "Estimated referrals per year cannot be negative.",
        },
    )
    total_active_clients = serializers.IntegerField(
        min_value=0,
        error_messages={
            "required": "Total no of active clients is required.",
            "invalid": "Enter a valid number.",
            "min_value": "Total no of active clients cannot be negative.",
        },
    )
    audience_description = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        error_messages={"blank": "Audience description cannot be empty."},
    )

    # Consent
    agreed_privacy_policy = serializers.BooleanField(
        error_messages={
            "required": "You must agree to the privacy policy to submit an application.",
            "invalid": "This field must be true or false.",
        },
    )
    consent_communications = serializers.BooleanField(
        required=False,
        default=False,
        error_messages={"invalid": "This field must be true or false."},
    )

    def validate_agreed_privacy_policy(self, value):
        if not value:
            raise serializers.ValidationError("You must agree to the privacy policy to submit an application.")
        return value

    def validate_country(self, value):
        if value not in VALID_COUNTRIES:
            raise serializers.ValidationError("Invalid country name. Only country names are allowed.")
        return value

    def validate_phone_number(self, value):
        if not value:
            return value
        if not value.isdigit():
            raise serializers.ValidationError("Phone number must contain only digits.")
        if len(value) != 10:
            raise serializers.ValidationError("Phone number must be exactly 10 digits.")
        return value

    def validate_phone_country_code(self, value):
        if not value:
            return value
        if value not in VALID_PHONE_CODES:
            raise serializers.ValidationError("Select a valid country code.")
        return value

    def validate(self, attrs):
        phone_number = attrs.get("phone_number", "")
        phone_country_code = attrs.get("phone_country_code", "")
        if phone_number and not phone_country_code:
            raise serializers.ValidationError(
                {"phone_country_code": "Please select a country code for your phone number."}
            )
        if phone_country_code and not phone_number:
            raise serializers.ValidationError(
                {"phone_number": "Please enter your phone number."}
            )
        return attrs
