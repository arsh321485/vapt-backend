from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Location
import logging

logger = logging.getLogger(__name__)
User = get_user_model()



class LocationSerializer(serializers.ModelSerializer):
    """Serializer for listing locations"""
    admin_id = serializers.CharField(source='admin.id', read_only=True)
    admin_name = serializers.CharField(source='admin.username', read_only=True)  # optional: show admin name

    class Meta:
        model = Location
        fields = ['_id', 'admin_id', 'admin_name', 'location_name', 'created_at', 'updated_at']
        read_only_fields = ['_id', 'admin_id', 'admin_name', 'created_at', 'updated_at']
        
VALID_COUNTRIES = {
    "Afghanistan", "Albania", "Algeria", "Andorra", "Angola", "Argentina",
    "Armenia", "Australia", "Austria", "Azerbaijan",
    "Bahamas", "Bahrain", "Bangladesh", "Barbados", "Belarus", "Belgium",
    "Belize", "Benin", "Bhutan", "Bolivia", "Bosnia and Herzegovina",
    "Botswana", "Brazil", "Brunei", "Bulgaria", "Burkina Faso", "Burundi",
    "Cambodia", "Cameroon", "Canada", "Chad", "Chile", "China", "Colombia",
    "Comoros", "Congo", "Costa Rica", "Croatia", "Cuba", "Cyprus", "Czech Republic",
    "Denmark", "Djibouti", "Dominica", "Dominican Republic",
    "Ecuador", "Egypt", "El Salvador", "Eritrea", "Estonia", "Ethiopia",
    "Fiji", "Finland", "France",
    "Gabon", "Gambia", "Georgia", "Germany", "Ghana", "Greece", "Guatemala",
    "Guinea", "Guyana",
    "Haiti", "Honduras", "Hungary",
    "Iceland", "India", "Indonesia", "Iran", "Iraq", "Ireland", "Israel", "Italy",
    "Jamaica", "Japan", "Jordan",
    "Kazakhstan", "Kenya", "Kuwait", "Kyrgyzstan",
    "Laos", "Latvia", "Lebanon", "Lesotho", "Liberia", "Libya", "Lithuania",
    "Luxembourg",
    "Madagascar", "Malawi", "Malaysia", "Maldives", "Mali", "Malta", 
    "Mauritania", "Mauritius", "Mexico",
    "Moldova", "Mongolia", "Morocco", "Mozambique", "Myanmar",
    "Namibia", "Nepal", "Netherlands", "New Zealand", "Nicaragua", "Niger", "Nigeria",
    "North Korea", "North Macedonia", "Norway",
    "Oman",
    "Pakistan", "Panama", "Paraguay", "Peru", "Philippines", "Poland",
    "Portugal",
    "Qatar",
    "Romania", "Russia", "Rwanda",
    "Saudi Arabia", "Senegal", "Serbia", "Seychelles", "Sierra Leone",
    "Singapore", "Slovakia", "Slovenia", "Somalia", "South Africa", 
    "South Korea", "Spain", "Sri Lanka", "Sudan", "Sweden", "Switzerland", "Syria",
    "Taiwan", "Tajikistan", "Tanzania", "Thailand", "Togo", "Tunisia", "Turkey",
    "Uganda", "Ukraine", "United Arab Emirates", "United Kingdom", "United States",
    "Uruguay", "Uzbekistan",
    "Venezuela", "Vietnam",
    "Yemen",
    "Zambia", "Zimbabwe"
}


class LocationCreateSerializer(serializers.ModelSerializer):
    admin_id = serializers.CharField(write_only=True)

    class Meta:
        model = Location
        fields = ['admin_id', 'location_name']

    def validate_location_name(self, value):
        value = value.strip()

        if value not in VALID_COUNTRIES:
            raise serializers.ValidationError("Invalid country name. Only country names are allowed.")

        return value

    def validate_admin_id(self, value):
        try:
            User.objects.get(id=value)
        except User.DoesNotExist:
            raise serializers.ValidationError("Admin with this ID does not exist")
        return value

    def create(self, validated_data):
        admin = User.objects.get(id=validated_data.pop('admin_id'))
        return Location.objects.create(admin=admin, **validated_data)
    
    
# class LocationCreateSerializer(serializers.ModelSerializer):
#     admin_id = serializers.CharField(write_only=True)
    
#     class Meta:
#         model = Location
#         fields = ['admin_id', 'location_name']
    
#     def validate_admin_id(self, value):
#         """Validate that admin_id exists in User model"""
#         try:
#             User.objects.get(id=value)
#         except User.DoesNotExist:
#             raise serializers.ValidationError("Admin with this ID does not exist")
#         return value
    
#     def validate_location_name(self, value):
#         """Validate location name length and format"""
#         if len(value.strip()) < 2:
#             raise serializers.ValidationError("Location name must be at least 2 characters long")
#         return value.strip()
    
#     def create(self, validated_data):
#         admin_id = validated_data.pop('admin_id')
#         admin = User.objects.get(id=admin_id)
#         location = Location.objects.create(admin=admin, **validated_data)
#         return location


# class LocationUpdateSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = Location
#         fields = ['location_name']
    
#     def validate_location_name(self, value):
#         """Validate location name length and format"""
#         if value and len(value.strip()) < 2:
#             raise serializers.ValidationError("Location name must be at least 2 characters long")
#         return value.strip() if value else value


class LocationUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Location
        fields = ['location_name']

    def validate_location_name(self, value):
        value = value.strip()
        # Ensure it's one of the allowed country names
        if value not in VALID_COUNTRIES:
            raise serializers.ValidationError("Invalid country name. Only country names are allowed.")
        # Optionally: ensure the new country doesn't already exist for this admin
        request = self.context.get('request')
        if request and hasattr(request, 'user'):
            admin = None
            # For admin-owner check, the instance exists when updating:
            instance = getattr(self, 'instance', None)
            if instance:
                admin = instance.admin
            # if admin exists, check duplicates
            if admin:
                qs = Location.objects.filter(admin=admin, location_name__iexact=value)
                # exclude current instance (so updating same name is allowed)
                if instance:
                    qs = qs.exclude(pk=instance.pk)
                if qs.exists():
                    raise serializers.ValidationError("This country is already added for the same admin.")
        return value
