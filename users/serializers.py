from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError   
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.forms import ValidationError
from .models import User
from .utils import Util, verify_recaptcha
import logging
logger = logging.getLogger(__name__)
from django.contrib.auth import get_user_model
import requests
from django.conf import settings
from .utils import verify_recaptcha
from rest_framework_simplejwt.tokens import RefreshToken
User = get_user_model()



class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)
    recaptcha = serializers.CharField(
        write_only=True,
        required=False,
        allow_blank=True
    )

    class Meta:
        model = User
        fields = [
            "firstname",
            "lastname",
            "organisation_name",
            "organisation_url",
            "email",
            "password",
            "confirm_password",
            "recaptcha"  # <-- must include it here!
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "confirm_password": {"write_only": True},
            "recaptcha": {"write_only": True},
        }

    def validate(self, attrs):
        # Password match check
        if attrs.get("password") != attrs.get("confirm_password"):
            raise serializers.ValidationError("Passwords don't match")

        # reCAPTCHA check only in production
        if not settings.DEBUG:
            recaptcha_value = attrs.get("recaptcha", "")
            is_valid, message = verify_recaptcha(recaptcha_value)
            if not is_valid:
                raise serializers.ValidationError({"recaptcha": message})
        else:
            logger.info("DEBUG mode active – skipping reCAPTCHA verification")

        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password", None)
        validated_data.pop("recaptcha", None)
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)
    recaptcha = serializers.CharField(write_only=True, required=True)

    def validate_recaptcha(self, value):
        """
        Validate reCAPTCHA response
        """
        is_valid, message = verify_recaptcha(value)
        if not is_valid:
            raise serializers.ValidationError(message)
        return value

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")

        if email and password:
            user = authenticate(
                request=self.context.get("request"),
                username=email,
                password=password
            )

            if not user:
                raise serializers.ValidationError("Invalid credentials")

            if not user.is_active:
                raise serializers.ValidationError("User account is disabled")

            attrs["user"] = user
            return attrs
        else:
            raise serializers.ValidationError("Must include email and password")

class UserProfileSerializer(serializers.ModelSerializer):
    full_name = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = [
            "id", "email", "firstname", "lastname",
            "organisation_name", "organisation_url", "created_at",
            "full_name",
        ]
        read_only_fields = ["id", "email", "created_at"]

    def get_full_name(self, obj):
        return f"{obj.firstname} {obj.lastname}".strip()


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    current_password = serializers.CharField(write_only=True, required=False)
    new_password = serializers.CharField(write_only=True, required=False)
    confirm_password = serializers.CharField(write_only=True, required=False)

    class Meta:
        model = User
        fields = [
            "firstname", "lastname", "organisation_name", "organisation_url",
            "current_password", "new_password", "confirm_password"
        ]
        extra_kwargs = {
            "firstname": {"required": False},
            "lastname": {"required": False},
            "organisation_name": {"required": False},
            "organisation_url": {"required": False},
        }

    def validate_firstname(self, value):
        if value is not None and len(value.strip()) < 2:
            raise serializers.ValidationError("First name must be at least 2 characters long")
        return value.strip() if value else value

    def validate_lastname(self, value):
        if value is not None and len(value.strip()) < 2:
            raise serializers.ValidationError("Last name must be at least 2 characters long")
        return value.strip() if value else value

    def validate_current_password(self, value):
        if value:
            user = self.context["request"].user
            if not authenticate(username=user.email, password=value):
                raise serializers.ValidationError("Current password is incorrect")
        return value

    def validate_new_password(self, value):
        if value:
            try:
                validate_password(value, self.context["request"].user)
            except ValidationError as e:
                raise serializers.ValidationError(e.messages)
        return value

    def validate(self, attrs):
        current_password = attrs.get("current_password")
        new_password = attrs.get("new_password")
        confirm_password = attrs.get("confirm_password")

        password_fields = [current_password, new_password, confirm_password]
        password_fields_provided = [field for field in password_fields if field]

        if password_fields_provided:
            if not all(password_fields):
                raise serializers.ValidationError(
                    "To update password, you must provide current_password, new_password, and confirm_password"
                )

            if new_password != confirm_password:
                raise serializers.ValidationError({
                    "confirm_password": "New password and confirm password do not match"
                })

            if new_password == current_password:
                raise serializers.ValidationError({
                    "new_password": "New password must be different from current password"
                })

        return attrs

    def update(self, instance, validated_data):
        instance.firstname = validated_data.get("firstname", instance.firstname)
        instance.lastname = validated_data.get("lastname", instance.lastname)
        instance.organisation_name = validated_data.get("organisation_name", instance.organisation_name)
        instance.organisation_url = validated_data.get("organisation_url", instance.organisation_url)

        new_password = validated_data.get("new_password")
        if new_password:
            instance.set_password(new_password)

        instance.save()
        return instance


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True, write_only=True)
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("New passwords don't match")
        return attrs

    def validate_old_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Old password is incorrect")
        return value


class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField()

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("No user found with this email address.")
        return value


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(
        max_length=255,
        style={"input_type": "password"},
        write_only=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(
        max_length=255,
        style={"input_type": "password"},
        write_only=True
    )

    class Meta:
        fields = ["password", "confirm_password"]

    def validate(self, attrs):
        try:
            password = attrs.get("password")
            confirm_password = attrs.get("confirm_password")
            uid = self.context.get("uid")
            token = self.context.get("token")

            if not uid or not token:
                raise serializers.ValidationError({"error": "Invalid reset link"})

            # Decode user ID
            try:
                user_id = smart_str(urlsafe_base64_decode(uid))
                user = User.objects.get(id=user_id)  # Changed from _id to id
            except (ValueError, User.DoesNotExist):
                raise serializers.ValidationError({"error": "Invalid reset link"})

            # Verify token
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise serializers.ValidationError({"error": "Token is not valid or expired"})

            # Check password confirmation
            if password != confirm_password:
                raise serializers.ValidationError({"error": "Password and confirm password don't match"})

            # Set new password
            user.set_password(password)
            user.save()

            logger.info(f"Password reset successful for user: {user.email}")
            return attrs

        except DjangoUnicodeDecodeError:
            raise serializers.ValidationError({"error": "Invalid reset link"})
        except Exception as e:
            logger.error(f"Error in UserPasswordResetSerializer: {str(e)}")
            raise serializers.ValidationError({"error": "Password reset failed. Please try again."})
        
        
class SetPasswordSerializer(serializers.Serializer):
    new_password = serializers.CharField(
        required=True,
        write_only=True,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        if attrs["new_password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords do not match")
        return attrs
    

class GoogleOAuthSerializer(serializers.Serializer):
    # Accept either access_token (OAuth) or id_token (Google One Tap / Sign-In)
    access_token = serializers.CharField(required=False, allow_blank=True)
    id_token = serializers.CharField(required=False, allow_blank=True)
    # Also accept 'credential' (GSI callback field) as alias for id_token
    credential = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        # Map 'credential' to 'id_token' if present
        if attrs.get("credential") and not attrs.get("id_token"):
            attrs["id_token"] = attrs["credential"]
        # Ensure at least one token is provided
        if not attrs.get("access_token") and not attrs.get("id_token"):
            raise serializers.ValidationError("Provide either access_token or id_token")
        return attrs

    def get_google_user_data(self, *, access_token: str | None = None, id_token: str | None = None):
        """
        Retrieve Google user info using either an OAuth access_token or an ID token.
        - access_token: calls Google UserInfo endpoint
        - id_token: verifies via tokeninfo and validates audience
        Returns a dict containing at minimum: email, given_name, family_name
        """
        try:
            user_data = None
            if access_token:
                # OAuth access token path
                google_user_info_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
                response = requests.get(google_user_info_url, timeout=10)
                if response.status_code != 200:
                    raise serializers.ValidationError("Invalid Google access token")
                user_data = response.json()
            elif id_token:
                # ID token path - verify using tokeninfo
                tokeninfo_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
                response = requests.get(tokeninfo_url, timeout=10)
                if response.status_code != 200:
                    raise serializers.ValidationError("Invalid Google ID token")
                token_info = response.json()

                # Validate audience
                aud = token_info.get("aud")
                expected_aud = settings.GOOGLE_OAUTH2_CLIENT_ID
                if expected_aud and aud != expected_aud:
                    raise serializers.ValidationError("Google token audience mismatch")

                # Map token info to unified structure
                user_data = {
                    "email": token_info.get("email"),
                    "given_name": token_info.get("given_name") or (token_info.get("name") or "").split(" ")[0] if token_info.get("name") else "",
                    "family_name": token_info.get("family_name") or (token_info.get("name") or "").split(" ")[-1] if token_info.get("name") else "",
                }

            # Validate required fields
            required_fields = ["email", "given_name", "family_name"]
            for field in required_fields:
                if not user_data or field not in user_data or user_data[field] is None:
                    raise serializers.ValidationError(f"Missing required field: {field}")

            return user_data

        except requests.RequestException as e:
            logger.error(f"Google API request failed: {str(e)}")
            raise serializers.ValidationError("Failed to validate Google token")
        except serializers.ValidationError:
            # Bubble up explicit validation errors
            raise
        except Exception as e:
            logger.error(f"Google token validation error: {str(e)}")
            raise serializers.ValidationError("Invalid Google token")

    def create_or_get_user(self, google_user_data):
        """
        Create or get user from Google data
        """
        email = google_user_data['email']

        try:
            # Try to get existing user
            user = User.objects.get(email=email)
            logger.info(f"Existing user found: {email}")
            return user

        except User.DoesNotExist:
            # Create new user
            user = User.objects.create_user(
                email=email,
                firstname=google_user_data.get('given_name', ''),
                lastname=google_user_data.get('family_name', ''),
                # Set unusable password since they're using Google OAuth
                password=None
            )
            user.set_unusable_password()
            user.save()

            logger.info(f"New user created via Google OAuth: {email}")
            return user