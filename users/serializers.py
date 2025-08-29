from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError   
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.forms import ValidationError
from .models import User
from .utils import Util
import logging
logger = logging.getLogger(__name__)
from rest_framework import serializers
from django.contrib.auth import get_user_model

User = get_user_model()


class UserRegistrationSerializer(serializers.ModelSerializer):
    password = serializers.CharField(
        write_only=True,
        min_length=8,
        validators=[validate_password]
    )
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            "firstname",
            "lastname", 
            "organisation_name",
            "organisation_url",
            "email",
            "password",
            "confirm_password"
        ]
        extra_kwargs = {
            "password": {"write_only": True},
            "confirm_password": {"write_only": True},
        }

    def validate(self, attrs):
        if attrs["password"] != attrs["confirm_password"]:
            raise serializers.ValidationError("Passwords don't match")
        return attrs

    def create(self, validated_data):
        validated_data.pop("confirm_password", None)
        user = User.objects.create_user(**validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

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