from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError   
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.forms import ValidationError
from .models import User



from typing import Optional
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from .utils import Util, verify_recaptcha
import re
import logging
logger = logging.getLogger(__name__)
from django.contrib.auth import get_user_model
import requests
import secrets
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
    access_token = serializers.CharField(required=False, allow_blank=True)
    id_token = serializers.CharField(required=False, allow_blank=True)
    credential = serializers.CharField(required=False, allow_blank=True)

    def validate(self, attrs):
        if attrs.get("credential") and not attrs.get("id_token"):
            attrs["id_token"] = attrs["credential"]

        if not attrs.get("access_token") and not attrs.get("id_token"):
            raise serializers.ValidationError(
                "Provide either access_token or id_token"
            )
        return attrs

    def get_google_user_data(
        self,
        *,
        access_token: Optional[str] = None,
        id_token: Optional[str] = None
    ):
        if access_token:
            url = "https://www.googleapis.com/oauth2/v2/userinfo"
            response = requests.get(
                url,
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10
            )
            if response.status_code != 200:
                raise serializers.ValidationError("Invalid Google access token")
            data = response.json()

        else:
            url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
            response = requests.get(url, timeout=10)
            if response.status_code != 200:
                raise serializers.ValidationError("Invalid Google ID token")

            token_info = response.json()
            if token_info.get("aud") != settings.GOOGLE_OAUTH2_CLIENT_ID:
                raise serializers.ValidationError("Google token audience mismatch")

            data = {
                "email": token_info.get("email"),
                "given_name": token_info.get("given_name", ""),
                "family_name": token_info.get("family_name", ""),
            }

        if not data.get("email"):
            raise serializers.ValidationError("Email not found")

        return data

    def create_or_get_user(self, google_user_data):
        email = google_user_data["email"]

        try:
            user = User.objects.get(email=email)
            return user, False  # OLD USER

        except User.DoesNotExist:
            user = User.objects.create_user(
                email=email,
                firstname=google_user_data.get("given_name", ""),
                lastname=google_user_data.get("family_name", ""),
                password=None,
            )
            user.set_unusable_password()
            user.save()
            return user, True 


# class GoogleOAuthSerializer(serializers.Serializer):
#     # Accept either access_token (OAuth) or id_token (Google One Tap / Sign-In)
#     access_token = serializers.CharField(required=False, allow_blank=True)
#     id_token = serializers.CharField(required=False, allow_blank=True)
#     # Also accept 'credential' (GSI callback field) as alias for id_token
#     credential = serializers.CharField(required=False, allow_blank=True)

#     def validate(self, attrs):
#         # Map 'credential' to 'id_token' if present
#         if attrs.get("credential") and not attrs.get("id_token"):
#             attrs["id_token"] = attrs["credential"]
#         # Ensure at least one token is provided
#         if not attrs.get("access_token") and not attrs.get("id_token"):
#             raise serializers.ValidationError("Provide either access_token or id_token")
#         return attrs
#     # def get_google_user_data(self, *, access_token: Optional[str] = None, id_token: Optional[str] = None):
#     def get_google_user_data(self, *, access_token: Optional[str] = None, id_token: Optional[str] = None):

#     # def get_google_user_data(self, *, access_token: str | None = None, id_token: str | None = None):
#         """
#         Retrieve Google user info using either an OAuth access_token or an ID token.
#         - access_token: calls Google UserInfo endpoint
#         - id_token: verifies via tokeninfo and validates audience
#         Returns a dict containing at minimum: email, given_name, family_name
#         """
#         try:
#             user_data = None
#             if access_token:
#                 # OAuth access token path
#                 google_user_info_url = f"https://www.googleapis.com/oauth2/v2/userinfo?access_token={access_token}"
#                 response = requests.get(google_user_info_url, timeout=10)
#                 if response.status_code != 200:
#                     raise serializers.ValidationError("Invalid Google access token")
#                 user_data = response.json()
#             elif id_token:
#                 # ID token path - verify using tokeninfo
#                 tokeninfo_url = f"https://oauth2.googleapis.com/tokeninfo?id_token={id_token}"
#                 response = requests.get(tokeninfo_url, timeout=10)
#                 if response.status_code != 200:
#                     raise serializers.ValidationError("Invalid Google ID token")
#                 token_info = response.json()

#                 # Validate audience
#                 aud = token_info.get("aud")
#                 expected_aud = settings.GOOGLE_OAUTH2_CLIENT_ID
#                 if expected_aud and aud != expected_aud:
#                     raise serializers.ValidationError("Google token audience mismatch")

#                 # Map token info to unified structure
#                 user_data = {
#                     "email": token_info.get("email"),
#                     "given_name": token_info.get("given_name") or (token_info.get("name") or "").split(" ")[0] if token_info.get("name") else "",
#                     "family_name": token_info.get("family_name") or (token_info.get("name") or "").split(" ")[-1] if token_info.get("name") else "",
#                 }

#             # Validate required fields
#             required_fields = ["email", "given_name", "family_name"]
#             for field in required_fields:
#                 if not user_data or field not in user_data or user_data[field] is None:
#                     raise serializers.ValidationError(f"Missing required field: {field}")

#             return user_data

#         except requests.RequestException as e:
#             logger.error(f"Google API request failed: {str(e)}")
#             raise serializers.ValidationError("Failed to validate Google token")
#         except serializers.ValidationError:
#             # Bubble up explicit validation errors
#             raise
#         except Exception as e:
#             logger.error(f"Google token validation error: {str(e)}")
#             raise serializers.ValidationError("Invalid Google token")

#     def create_or_get_user(self, google_user_data):
#         """
#         Create or get user from Google data
#         """
#         email = google_user_data['email']

#         try:
#             # Try to get existing user
#             user = User.objects.get(email=email)
#             logger.info(f"Existing user found: {email}")
#             return user

#         except User.DoesNotExist:
#             # Create new user
#             user = User.objects.create_user(
#                 email=email,
#                 firstname=google_user_data.get('given_name', ''),
#                 lastname=google_user_data.get('family_name', ''),
#                 # Set unusable password since they're using Google OAuth
#                 password=None
#             )
#             user.set_unusable_password()
#             user.save()

#             logger.info(f"New user created via Google OAuth: {email}")
#             return user
        

class MicrosoftTeamsOAuthSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    
    def validate_access_token(self, value):
        """Validate Microsoft access token"""
        if not value:
            raise serializers.ValidationError("Access token is required")
        return value

    def get_microsoft_user_data(self, access_token):
        """Retrieve Microsoft user info using access token via Microsoft Graph API"""
        try:
            graph_url = "https://graph.microsoft.com/v1.0/me"
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(graph_url, headers=headers, timeout=10)
            
            if response.status_code != 200:
                logger.error(f"Microsoft Graph API error: {response.status_code} - {response.text}")
                raise serializers.ValidationError("Invalid Microsoft access token")
            
            user_data = response.json()
            logger.info(f"Microsoft user data received: {user_data.get('mail', 'No email')}")
            
            # Map Microsoft Graph response to our format
            mapped_data = {
                "email": user_data.get("mail") or user_data.get("userPrincipalName"),
                "given_name": user_data.get("givenName", ""),
                "family_name": user_data.get("surname", ""),
                "display_name": user_data.get("displayName", ""),
                "id": user_data.get("id", ""),
            }
            
            if not mapped_data["email"]:
                raise serializers.ValidationError("Email not found in Microsoft profile")
                
            return mapped_data
            
        except requests.RequestException as e:
            logger.error(f"Microsoft Graph API request failed: {str(e)}")
            raise serializers.ValidationError("Failed to validate Microsoft token")
        except serializers.ValidationError:
            raise
        except Exception as e:
            logger.error(f"Microsoft token validation error: {str(e)}")
            raise serializers.ValidationError("Invalid Microsoft token")

    def create_or_get_user(self, microsoft_user_data):
        """Create or get user from Microsoft data"""
        email = microsoft_user_data['email']
        
        try:
            user = User.objects.get(email=email)
            logger.info(f"Existing user found: {email}")
            return user
            
        except User.DoesNotExist:
            user = User.objects.create_user(
                email=email,
                firstname=microsoft_user_data.get('given_name', ''),
                lastname=microsoft_user_data.get('family_name', ''),
                password=None
            )
            user.set_unusable_password()
            user.save()
            
            logger.info(f"New user created via Microsoft OAuth: {email}")
            return user

# Other serializers remain the same...
class CreateChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    channel_name = serializers.CharField(required=True, max_length=50)
    description = serializers.CharField(required=False, allow_blank=True, max_length=1024)
    
    def validate_channel_name(self, value):
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Channel name must be at least 2 characters long")
        return value.strip()
    
class UpdateChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    channel_id = serializers.CharField(required=True)
    channel_name = serializers.CharField(required=False, max_length=50)
    description = serializers.CharField(required=False, allow_blank=True, max_length=1024)
    
    def validate(self, data):
        if not data.get('channel_name') and not data.get('description'):
            raise serializers.ValidationError("At least one field (channel_name or description) must be provided for update")
        return data
    
    def validate_channel_name(self, value):
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError("Channel name must be at least 2 characters long")
        return value.strip() if value else value

class DeleteChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    channel_id = serializers.CharField(required=True)

class SendMessageSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    channel_id = serializers.CharField(required=True)
    message = serializers.CharField(required=True, max_length=4000)
    
    def validate_message(self, value):
        if len(value.strip()) < 1:
            raise serializers.ValidationError("Message cannot be empty")
        return value.strip()

class ListTeamsSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)

class ListChannelsSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    
class CreateTeamSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_name = serializers.CharField(required=True, max_length=100)
    description = serializers.CharField(required=False, allow_blank=True, max_length=1024)
    visibility = serializers.ChoiceField(choices=['Private', 'Public'], default='Private')
    
    def validate_team_name(self, value):
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Team name must be at least 2 characters long")
        return value.strip()
    

class UpdateTeamSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    team_name = serializers.CharField(required=False, max_length=100)
    description = serializers.CharField(required=False, allow_blank=True, max_length=1024)
    visibility = serializers.ChoiceField(choices=['Private', 'Public'], required=False)
    
    def validate(self, data):
        if not any([data.get('team_name'), data.get('description'), data.get('visibility')]):
            raise serializers.ValidationError("At least one field must be provided for update")
        return data
    
    def validate_team_name(self, value):
        if value and len(value.strip()) < 2:
            raise serializers.ValidationError("Team name must be at least 2 characters long")
        return value.strip() if value else value

class DeleteTeamSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)

class AddUserToChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    team_id = serializers.CharField(required=True)
    channel_id = serializers.CharField(required=True)
    user_email = serializers.EmailField(required=True)
    user_role = serializers.ChoiceField(choices=['owner', 'member'], default='member')
    
    def validate_user_email(self, value):
        if not value:
            raise serializers.ValidationError("User email is required")
        return value.lower()
    

class SlackOAuthUrlSerializer(serializers.Serializer):
    base_url = serializers.URLField(
        required=True,
        help_text="Your current ngrok or production base URL (e.g. https://92f335c03179.ngrok-free.app)"
    )
    state = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Optional custom state string (external system identifier or token)"
    )


class SlackCallbackSerializer(serializers.Serializer):
    code = serializers.CharField(required=True, help_text="Authorization code from Slack")
    state = serializers.CharField(required=False, allow_blank=True, help_text="Optional state value")
    
    
class SlackOAuthSerializer(serializers.Serializer):
    access_token = serializers.CharField(
        required=True,
        help_text="Slack bot access token returned from OAuth callback"
    )
    
       
class SlackTokenValidationSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True, help_text="Slack access token to validate")
    

class SlackLoginSerializer(serializers.Serializer):
    bot_access_token = serializers.CharField(required=True)
    user_access_token = serializers.CharField(required=True)
class SlackMessageSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True, help_text="Slack access token")
    channel = serializers.CharField(required=True, help_text="Channel ID or name (e.g., #general, C1234567890)")
    text = serializers.CharField(required=True, help_text="Message text content")
    blocks = serializers.JSONField(
        required=False, 
        help_text="Slack Block Kit blocks for rich formatting"
    )

class SlackOAuthSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)
    redirect_uri = serializers.CharField(required=False, allow_blank=True)

    def validate_code(self, value):
        if not value:
            raise serializers.ValidationError("Slack authorization code is required.")
        return value

    def get_slack_user_data(self, code, redirect_uri):
        """Exchange code for tokens and fetch Slack user data"""
        try:
            # Dynamic redirect URI — fallback to default
            redirect_uri = redirect_uri or getattr(settings, "SLACK_REDIRECT_URI", "http://localhost:3000/slack/callback")

            token_url = "https://slack.com/api/oauth.v2.access"
            token_data = {
                "client_id": settings.SLACK_CLIENT_ID,
                "client_secret": settings.SLACK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri
            }

            token_response = requests.post(token_url, data=token_data)
            token_result = token_response.json()

            if not token_result.get("ok"):
                logger.error(f"Slack OAuth failed: {token_result}")
                raise serializers.ValidationError(f"Slack OAuth failed: {token_result.get('error', 'Unknown error')}")

            # Extract bot + user tokens
            bot_access_token = token_result.get("access_token")
            bot_user_id = token_result.get("bot_user_id", "")
            team_info = token_result.get("team", {})
            authed_user = token_result.get("authed_user", {})
            user_token = authed_user.get("access_token")

            if not user_token:
                raise serializers.ValidationError("User access token not found in Slack response.")

            # Fetch user info
            user_info_response = requests.get(
                "https://slack.com/api/users.identity",
                headers={"Authorization": f"Bearer {user_token}"},
                timeout=10
            )
            user_info_data = user_info_response.json()

            if not user_info_data.get("ok"):
                raise serializers.ValidationError(f"Slack user info fetch failed: {user_info_data.get('error')}")

            user = user_info_data.get("user", {})
            email = user.get("email")
            name = user.get("name", "")
            image = user.get("image_192", "")

            if not email:
                raise serializers.ValidationError("Email not found in Slack user profile.")

            # Combine all Slack data
            mapped_data = {
                "email": email,
                "firstname": name.split(" ")[0] if name else "",
                "lastname": " ".join(name.split(" ")[1:]) if len(name.split(" ")) > 1 else "",
                "display_name": name,
                "image": image,
                "user_id": user.get("id", ""),
                "bot_access_token": bot_access_token,
                "bot_user_id": bot_user_id,
                "user_access_token": user_token,
                "team_id": team_info.get("id"),
                "team_name": team_info.get("name"),
                "redirect_uri": redirect_uri,  # Keep dynamic redirect URI
            }

            logger.info(f"Slack user data mapped for {email}")
            return mapped_data

        except requests.RequestException as e:
            logger.error(f"Slack API request failed: {str(e)}")
            raise serializers.ValidationError("Failed to connect to Slack API.")
        except Exception as e:
            logger.error(f"Slack user fetch error: {str(e)}")
            raise serializers.ValidationError("Slack login failed.")

    def create_or_get_user(self, slack_user_data):
        """Create or get user from Slack user data"""
        email = slack_user_data["email"]

        try:
            user = User.objects.get(email=email)
            logger.info(f"Existing Slack user found: {email}")
            return user, False
        except User.DoesNotExist:
            user = User.objects.create_user(
                email=email,
                firstname=slack_user_data.get("firstname", ""),
                lastname=slack_user_data.get("lastname", ""),
                password=None
            )
            user.set_unusable_password()
            user.save()
            logger.info(f"New user created via Slack OAuth: {email}")
            return user, True
class SlackTokenValidationSerializer(serializers.Serializer):
    access_token = serializers.CharField(
        required=True, 
        help_text="Slack access token to validate",
        min_length=10
    )
    
    def validate_access_token(self, value):
        """Validate Slack token format"""
        if not value.startswith(('xoxb-', 'xoxp-', 'xoxa-')):
            raise serializers.ValidationError(
                "Invalid Slack token format. Token should start with xoxb-, xoxp-, or xoxa-"
            )
        return value


class SlackUserLoginResponseSerializer(serializers.Serializer):
    """Serializer for documenting the login response structure"""
    access_token = serializers.CharField()
    token_type = serializers.CharField(default="Bearer")
    scope = serializers.CharField()
    team = serializers.DictField()
    user = serializers.DictField()

class SlackOperationSerializer(serializers.Serializer):
    access_token = serializers.CharField(
        required=True, 
        help_text="Slack access token"
    )
    
    def validate_access_token(self, value):
        """Validate Slack token format"""
        if not value.startswith(('xoxb-', 'xoxp-', 'xoxa-')):
            raise serializers.ValidationError(
                "Invalid Slack token format"
            )
        return value

class SlackLoginSerializer(serializers.Serializer):
    code = serializers.CharField(
        required=True, 
        help_text="Authorization code received from Slack OAuth callback",
        min_length=10
    )
    redirect_uri = serializers.URLField(
        required=False, 
        default="http://localhost:3000/slack/callback",
        help_text="Redirect URI that was used in the OAuth flow"
    )
    
    def validate_code(self, value):
        """Basic validation for OAuth code format"""
        if len(value) < 10:
            raise serializers.ValidationError(
                "Invalid authorization code format"
            )
        return value


class SlackChannelListSerializer(serializers.Serializer):
    access_token = serializers.CharField(
        required=True, 
        help_text="Slack access token"
    )
    exclude_archived = serializers.BooleanField(
        default=True,
        help_text="Whether to exclude archived channels"
    )
    types = serializers.CharField(
        default="public_channel,private_channel",
        help_text="Comma-separated list of channel types to include"
    )
    limit = serializers.IntegerField(
        default=100,
        min_value=1,
        max_value=1000,
        help_text="Maximum number of channels to return"
    )
    
    def validate_access_token(self, value):
        if not value.startswith(('xoxb-', 'xoxp-', 'xoxa-')):
            raise serializers.ValidationError("Invalid Slack token format")
        return value
    
    def validate_types(self, value):
        """Validate channel types"""
        valid_types = [
            'public_channel', 'private_channel', 'mpim', 'im'
        ]
        types_list = [t.strip() for t in value.split(',')]
        for channel_type in types_list:
            if channel_type not in valid_types:
                raise serializers.ValidationError(
                    f"Invalid channel type: {channel_type}. "
                    f"Valid types are: {', '.join(valid_types)}"
                )
        return value


class CreateSlackChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    name = serializers.CharField(required=True)
    is_private = serializers.BooleanField(required=False, default=False)



class UpdateSlackChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True, help_text="Slack access token")
    channel_id = serializers.CharField(required=True, help_text="Slack channel ID")
    name = serializers.CharField(required=True, help_text="New channel name")



class DeleteSlackChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
    channel_id = serializers.CharField(required=True)



class SlackInteractiveMessageSerializer(serializers.Serializer):
    access_token = serializers.CharField(
        required=True, 
        help_text="Slack access token"
    )
    channel = serializers.CharField(
        required=True, 
        help_text="Channel ID or name"
    )
    text = serializers.CharField(
        default="Interactive message",
        help_text="Fallback text for the message"
    )
    blocks = serializers.JSONField(
        required=True,
        help_text="Slack Block Kit blocks for interactive elements"
    )
    
    def validate_access_token(self, value):
        if not value.startswith(('xoxb-', 'xoxp-', 'xoxa-')):
            raise serializers.ValidationError("Invalid Slack token format")
        return value
    
    def validate_blocks(self, value):
        """Basic validation for blocks structure"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Blocks must be a list")
        if len(value) == 0:
            raise serializers.ValidationError("At least one block is required")
        return value



class AddUserToSlackChannelSerializer(serializers.Serializer):
    access_token = serializers.CharField(
        required=True,
        help_text="Slack access token (Bot User OAuth Token, e.g., xoxb-...)"
    )
    channel = serializers.CharField(
        required=True,
        help_text="Slack channel ID (e.g., C1234567890)"
    )
    user_id = serializers.CharField(
        required=True,
        help_text="Slack user ID to invite (e.g., U1234567890)"
    )
    

class SlackInviteUserSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True, help_text="Slack Bot/User token")
    channel = serializers.CharField(required=True, help_text="Slack channel ID (e.g., C1234567890)")
    users = serializers.ListField(
        child=serializers.CharField(),
        required=True,
        help_text="List of Slack User IDs (e.g., ['U12345', 'U67890'])"
    )
    


class JiraOAuthSerializer(serializers.Serializer):
    code = serializers.CharField(required=True)
    state = serializers.CharField(required=False)

class JiraOAuthUrlSerializer(serializers.Serializer):
    auth_url = serializers.URLField()
    state = serializers.CharField()

class JiraTokenSerializer(serializers.Serializer):
    access_token = serializers.CharField()
    refresh_token = serializers.CharField()
    expires_in = serializers.IntegerField()
    scope = serializers.CharField()

class JiraUserSerializer(serializers.Serializer):
    account_id = serializers.CharField()
    email = serializers.EmailField()
    name = serializers.CharField()
    picture = serializers.URLField(required=False)

class JiraIssueSerializer(serializers.Serializer):
    project_key = serializers.CharField(required=True)
    summary = serializers.CharField(required=True)
    description = serializers.CharField(required=False, allow_blank=True)
    issue_type = serializers.CharField(default="Task")
    priority = serializers.CharField(required=False, default="Medium")

class JiraProjectSerializer(serializers.Serializer):
    id = serializers.CharField()
    key = serializers.CharField()
    name = serializers.CharField()
    project_type = serializers.CharField()

class JiraCommentSerializer(serializers.Serializer):
    issue_key = serializers.CharField(required=True)
    comment = serializers.CharField(required=True)
    


# -----------------------------------------------
# 🧱 ISSUE CRUD SERIALIZERS
# -----------------------------------------------
class JiraIssueCreateSerializer(serializers.Serializer):
    project_key = serializers.CharField(max_length=10)
    summary = serializers.CharField(max_length=255)
    description = serializers.CharField(allow_blank=True, required=False)
    issue_type = serializers.CharField(default="Task")

    def validate_project_key(self, value):
        if not value.isupper():
            raise serializers.ValidationError("Project key must be uppercase, e.g. 'PROJ'")
        return value


class JiraIssueUpdateSerializer(serializers.Serializer):
    summary = serializers.CharField(required=False, max_length=255)
    description = serializers.CharField(required=False, allow_blank=True)
    issue_type = serializers.CharField(required=False)
    project_key = serializers.CharField(required=False)


class JiraIssueSearchSerializer(serializers.Serializer):
    jql = serializers.CharField(
        required=False,
        allow_blank=True,
        help_text="Optional JQL string. Default: 'order by created DESC'"
    )


class JiraAssignIssueSerializer(serializers.Serializer):
    account_id = serializers.CharField(required=True, help_text="Jira Account ID of user to assign issue to")


# -----------------------------------------------
# 🧱 PROJECT CRUD SERIALIZERS
# -----------------------------------------------
class JiraProjectCreateSerializer(serializers.Serializer):
    key = serializers.CharField(max_length=10)
    name = serializers.CharField(max_length=255)
    description = serializers.CharField(required=False, allow_blank=True)
    projectTypeKey = serializers.CharField(default="software")
    projectTemplateKey = serializers.CharField(
        required=False,
        default="com.pyxis.greenhopper.jira:gh-simplified-agility-scrum"
    )
    leadAccountId = serializers.CharField(required=True)
    assigneeType = serializers.CharField(default="PROJECT_LEAD")

    def validate_key(self, value):
        if not value.isupper():
            raise serializers.ValidationError("Project key must be uppercase letters only.")
        if len(value) > 10:
            raise serializers.ValidationError("Project key must be 10 characters or fewer.")
        return value


class JiraProjectUpdateSerializer(serializers.Serializer):
    name = serializers.CharField(required=False, max_length=255)
    description = serializers.CharField(required=False, allow_blank=True)
    leadAccountId = serializers.CharField(required=False)


class JiraProjectDeleteSerializer(serializers.Serializer):
    confirm = serializers.BooleanField(default=True, help_text="Confirmation flag for deletion")


# -----------------------------------------------
# 🧱 COMMON SERIALIZER RESPONSE WRAPPERS
# -----------------------------------------------
class JiraResponseSerializer(serializers.Serializer):
    message = serializers.CharField()
    detail = serializers.JSONField(required=False)
