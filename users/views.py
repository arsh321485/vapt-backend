from django.forms import ValidationError
from .renderers import UserRenderer
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from rest_framework import serializers
from django.contrib.auth import login
from .models import User
from django.apps import apps
from django.contrib.auth.hashers import make_password
from django.shortcuts import redirect
from django.utils import timezone
import requests
import secrets
import traceback
import json
import time
import re
import hashlib
import hmac
from urllib.parse import urljoin
import logging
import uuid
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from urllib.parse import urlencode
import random
from django.conf import settings
from pymongo import MongoClient
from django.core.cache import cache
from rest_framework_simplejwt.tokens import RefreshToken
# from .utils import send_signup_otp, verify_signup_otp, verify_recaptcha,send_admin_welcome_email
from .utils import Util, verify_recaptcha
from .validators import strong_password_validator
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from .validators import strong_password_validator  # Your custom validator

class SlackAccessTokenSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    AdminTestingTypeSerializer,
    UserProfileSerializer,
    # UserProfileUpdateSerializer,
    ChangePasswordSerializer,
    UserPasswordResetSerializer,
    SendPasswordResetEmailSerializer,
    # SetPasswordSerializer,
    GoogleOAuthSerializer,    
    MicrosoftTeamsOAuthSerializer,
    CreateChannelSerializer,
    SendMessageSerializer,
    ListTeamsSerializer,
    ListChannelsSerializer,
    AddUserToChannelSerializer,
    CreateTeamSerializer,
    DeleteTeamSerializer,
    UpdateTeamSerializer,
    DeleteChannelSerializer,
    UpdateChannelSerializer,
    SlackOAuthUrlSerializer,
    SlackCallbackSerializer,
    SlackOAuthSerializer,
    SlackLoginSerializer,
    UpdateSlackChannelSerializer,
    DeleteSlackChannelSerializer,
    AddUserToSlackChannelSerializer,
    SlackInviteUserSerializer,
    JiraOAuthSerializer,
    JiraOAuthUrlSerializer,
    JiraTokenSerializer,
    JiraUserSerializer,
    JiraIssueSerializer,
    JiraProjectSerializer,
    JiraCommentSerializer
)
from .utils import JiraTokenManager
import requests
import logging
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
logger = logging.getLogger(__name__)
from .utils import Util

#Admin Registration View
@method_decorator(csrf_exempt, name='dispatch')
class UserRegistrationView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def create(self, request, *args, **kwargs):
        from rest_framework.exceptions import ValidationError as DRFValidationError
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user = serializer.save()
            logger.debug(f"User saved with id={getattr(user, 'id', None)} and email={user.email}")

            # Try to generate JWT tokens, but don't fail the whole request if this errors
            tokens = None
            try:
                refresh = RefreshToken.for_user(user)
                tokens = {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
                logger.debug("JWT tokens generated successfully")
            except Exception:
                logger.exception("Token generation failed during registration")

            # Try to serialize user profile, fall back to minimal payload on error
            try:
                user_payload = UserProfileSerializer(user).data
            except Exception:
                logger.exception("UserProfile serialization failed during registration")
                user_payload = {"email": user.email}

            logger.info(f"Admin account created successfully: {user.email}")
            # 📧 Send admin welcome email
            try:
                Util.send_admin_welcome_email(user.email)
            except Exception:
                logger.exception("Failed to send admin welcome email")
                
            response_body = {
                "message": "Welcome! Your admin account has been created successfully",
                "user": user_payload,
            }
            if tokens:
                response_body["tokens"] = tokens

            return Response(response_body, status=status.HTTP_201_CREATED)

        except (ValidationError, DRFValidationError) as e:
            # Return actual validation errors
            detail = getattr(e, 'detail', None) or getattr(e, 'message', None) or e.args or {"error": "Validation error"}
            logger.error(f"Validation error: {detail}")
            return Response(detail, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.exception("Registration error occurred")
            # Do NOT expose request data with passwords in logs in production; okay for local debug
            safe_data = {k: (v if k != 'password' else '***') for k, v in dict(request.data).items()}
            logger.debug(f"Request data: {safe_data}")
            return Response({"error": "Something went wrong"}, status=400)
      
#Admin Login View  
# class UserLoginView(generics.GenericAPIView):
#     serializer_class = UserLoginSerializer
#     permission_classes = [AllowAny]

#     def post(self, request, *args, **kwargs):
#         serializer = self.get_serializer(data=request.data)
#         serializer.is_valid(raise_exception=True)
#         user = serializer.validated_data["user"]

#         refresh = RefreshToken.for_user(user)

#         return Response({
#             "message": "Welcome back! You have successfully logged in as an admin",
#             "user": {
#                 "id": user.id,
#                 "email": user.email
#             },
#             "tokens": {
#                 "refresh": str(refresh),
#                 "access": str(refresh.access_token),
#             }

#         }, status=status.HTTP_200_OK)
class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]

        user.last_login = timezone.now()
        user.login_provider = 'email'
        user.save()

        refresh = RefreshToken.for_user(user)

        return Response({
            "message": "Welcome back! You have successfully logged in as an admin",
            "user": {
                "id": user.id,
                "email": user.email,
            },
            "tokens": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        }, status=status.HTTP_200_OK)


#  Admin Signup OTP View   
class AdminSignupSendOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")
        recaptcha = request.data.get("recaptcha")

        if not email or not password or not confirm_password:
            return Response({"error": "All fields required"}, status=400)

        if password != confirm_password:
            return Response({"error": "Passwords do not match"}, status=400)

        # Password strength validation
        try:
            validate_password(password)
            strong_password_validator(password)
        except ValidationError as e:
            return Response({"error": e.messages}, status=400)

        if User.objects.filter(email=email).exists():
            return Response({"error": "User already exists"}, status=400)

        # reCAPTCHA
        ok, msg = verify_recaptcha(recaptcha)
        if not ok:
            return Response({"error": msg}, status=400)

        # ✅ Store BOTH OTP + PASSWORD in cache for 5 minutes
        otp = str(random.randint(100000, 999999))
        cache_data = {
            'otp': otp,
            'password': password  # Store hashed? No, hash when creating user
        }
        cache.set(f"signup_data_{email}", cache_data, timeout=300)

        # Send OTP email
        email_sent, email_error = Util.send_signup_otp(email, otp)

        if not email_sent:
            logger.error(f"Signup OTP email failed for {email}: {email_error}")
            return Response({"error": "Failed to send OTP email. Please try again.", "detail": email_error}, status=500)

        return Response({"message": "OTP sent to your email"}, status=200)


  
# Admin Signup Verify OTP View
class AdminSignupVerifyOTPView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        email = (request.data.get("email") or "").strip().lower()
        otp = request.data.get("otp")

        if not email or not otp:
            return Response({"error": "Email and OTP are required"}, status=400)

        # ✅ Get cached OTP + password
        cache_key = f"signup_data_{email}"
        cached_data = cache.get(cache_key)
        
        if not cached_data:
            return Response({"error": "No signup session found. Please start again."}, status=400)
        
        if cached_data['otp'] != otp:
            return Response({"error": "Invalid OTP"}, status=400)

        # ✅ OTP valid → create admin user with cached password
        try:
            user = User.objects.create_user(
                email=email,
                password=cached_data['password'],  # Use cached password
                is_active=True,
                is_staff=True,  # Admin privileges
                is_superuser=False
            )
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            return Response({"error": "Failed to create account"}, status=500)

        # ✅ Clean up cache
        cache.delete(cache_key)
        cache.delete(f"signup_otp_{email}")

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        # Send welcome email
        try:
            Util.send_admin_welcome_email(user.email)
        except:
            pass  # Don't fail signup if email fails

        return Response({
            "message": "Welcome! Your admin account has been created successfully",
            "user": {
                "id": user.id,
                "email": user.email,
                "is_staff": user.is_staff
            },
            "tokens": {
                "access": str(refresh.access_token),
                "refresh": str(refresh)
            },
        }, status=201)


# Admin Testing Type View
class AdminTestingTypeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, admin_id):
        admin = User.objects.filter(id=admin_id).first()

        if not admin:
            return Response(
                {"error": "Admin not found"},
                status=status.HTTP_404_NOT_FOUND
            )

        if not admin.is_staff:
            return Response(
                {"error": "User is not an admin"},
                status=status.HTTP_403_FORBIDDEN
            )

        return Response({
            "message": "Admin testing types fetched successfully",
            "data": {
                "id": admin.id,
                "email": admin.email,
                "testing_type": admin.testing_type or []
            }
        }, status=status.HTTP_200_OK)

# ADMIN PROFILE VIEW     
class UserProfileView(generics.RetrieveAPIView):
    serializer_class = UserProfileSerializer
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get_object(self):
        return self.request.user

    def retrieve(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            serializer = self.get_serializer(instance)
            return Response({
                "message": "Profile retrieved successfully",
                "user": serializer.data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Profile retrieval error: {str(e)}")
            return Response({
                "error": "Failed to retrieve profile"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# class UserProfileUpdateView(generics.UpdateAPIView):
#     serializer_class = UserProfileUpdateSerializer
#     permission_classes = [permissions.IsAuthenticated]
#     renderer_classes = [UserRenderer]

#     def get_object(self):
#         return self.request.user

#     def update(self, request, *args, **kwargs):
#         try:
#             partial = kwargs.pop('partial', True)
#             instance = self.get_object()
#             serializer = self.get_serializer(
#                 instance,
#                 data=request.data,
#                 partial=partial,
#                 context={"request": request}
#             )
#             serializer.is_valid(raise_exception=True)
#             self.perform_update(serializer)

#             # Get updated user data
#             updated_user = self.get_object()
            
#             return Response({
#                 "message": "Profile updated successfully",
#                 "user": UserProfileSerializer(updated_user).data
#             }, status=status.HTTP_200_OK)
#         except Exception as e:
#             logger.error(f"Profile update error: {str(e)}")
#             return Response({
#                 "error": "Failed to update profile"
#             }, status=status.HTTP_400_BAD_REQUEST)

#     def patch(self, request, *args, **kwargs):
#         kwargs['partial'] = True
#         return self.update(request, *args, **kwargs)

# ADMIN CHANGE PASSWORD VIEW
class ChangePasswordView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        try:
            user = self.get_object()
            serializer = self.get_serializer(data=request.data, context={"request": request})

            if serializer.is_valid():
                # Set the new password
                user.set_password(serializer.validated_data["new_password"])
                user.save()

                return Response({
                    "message": "Password changed successfully"
                }, status=status.HTTP_200_OK)

            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"Password change error: {str(e)}")
            return Response({
                "error": "Failed to change password"
            }, status=status.HTTP_400_BAD_REQUEST)


# ADMIN FORGOT PASSWORD VIEW
@method_decorator(csrf_exempt, name="dispatch")
class SendPasswordResetEmailView(generics.GenericAPIView):
    serializer_class = SendPasswordResetEmailSerializer
    permission_classes = [AllowAny]
    authentication_classes = []
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            user_email = serializer.validated_data["email"]

            # Build reset link with uid + token
            from django.utils.http import urlsafe_base64_encode
            from django.utils.encoding import force_bytes
            from django.contrib.auth.tokens import PasswordResetTokenGenerator
            from django.contrib.auth import get_user_model

            User = get_user_model()
            user = User.objects.get(email=user_email)
            uid = urlsafe_base64_encode(force_bytes(user.pk))  # This will use the UUID id
            token = PasswordResetTokenGenerator().make_token(user)

            reset_link = f"https://vapt-frontend-liart.vercel.app/reset-password/{uid}/{token}/"

            data = {
                "to_email": user_email,
                "subject": "Reset Your Password",
                "body": f"Click the link to reset your password: {reset_link}"
            }

            success, _ = Util.send_mail(data)
            if success:
                return Response(
                    {"msg": "Password reset link sent. Please check your email."},
                    status=status.HTTP_200_OK
                )
            return Response(
                {"error": "Failed to send email"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        except User.DoesNotExist:
            return Response(
                {"error": "User with this email does not exist"},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            logger.error(f"Password reset email error: {str(e)}")
            return Response(
                {"error": "Failed to send password reset email"}, 
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# ADMIN PASSWORD RESET VIEW
class UserPasswordResetView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uid, token):
        serializer = UserPasswordResetSerializer(
            data=request.data,
            context={"uid": uid, "token": token}
        )
        serializer.is_valid(raise_exception=True)

        return Response(
            {"msg": "Password reset successfully"},
            status=status.HTTP_200_OK
        )

# ADMIN LOGOUT VIEW
@api_view(["POST"])
@permission_classes([AllowAny]) 
def logout_view(request):
    return Response({"message": "Logout successful"}, status=200)
    
    
# Admin Google OAuth View
class GoogleOAuthView(generics.GenericAPIView):
    serializer_class = GoogleOAuthSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        access_token = serializer.validated_data.get("access_token")
        id_token = serializer.validated_data.get("id_token")

        google_user_data = serializer.get_google_user_data(
            access_token=access_token,
            id_token=id_token
        )

        user, is_new_user = serializer.create_or_get_user(google_user_data)

        user.login_provider = 'google'
        user.save(update_fields=['login_provider'])

        login(request, user)

        refresh = RefreshToken.for_user(user)

        return Response({
            "message": "Google login successful",
            "user": UserProfileSerializer(user).data,
            "tokens": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            },
            "is_new_user": is_new_user
        }, status=status.HTTP_200_OK)
        
        
           
# class GoogleOAuthView(generics.GenericAPIView):
#     serializer_class = GoogleOAuthSerializer
#     permission_classes = [AllowAny]
#     renderer_classes = [UserRenderer]

#     def post(self, request, *args, **kwargs):
#         try:
#             serializer = self.get_serializer(data=request.data)
            
#             if serializer.is_valid(raise_exception=True):
#                 # Get Google user data using either access_token or id_token
#                 access_token = serializer.validated_data.get('access_token')
#                 id_token = serializer.validated_data.get('id_token')
#                 google_user_data = serializer.get_google_user_data(
#                     access_token=access_token if access_token else None,
#                     id_token=id_token if id_token else None,
#                 )
                
#                 # Create or get user
#                 user = serializer.create_or_get_user(google_user_data)
                
#                 # Login user
#                 login(request, user)
                
#                 # Generate JWT tokens
#                 refresh = RefreshToken.for_user(user)
                
#                 logger.info(f"Google OAuth login successful: {user.email}")
                
#                 return Response({
#                     "message": "Google login successful",
#                     "user": UserProfileSerializer(user).data,
#                     "tokens": {
#                         "refresh": str(refresh),
#                         "access": str(refresh.access_token),
#                     },
#                     # Simplified: backend does not track "is_new_user" here reliably
#                     # "is_new_user": False
#                     "is_new_user": True
#                 }, status=status.HTTP_200_OK)
                
#         except Exception as e:
#             logger.error(f"Google OAuth error: {str(e)}")
#             return Response({
#                 "error": "Google authentication failed. Please try again."
#             }, status=status.HTTP_400_BAD_REQUEST)
            
import base64
import json

class MicrosoftTeamsOAuthUrlView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            frontend_redirect = request.GET.get("redirect_uri")
            if not frontend_redirect:
                return JsonResponse({"error": "Missing redirect_uri"}, status=400)

            # Encode redirect_uri into state
            state_data = {
                "redirect_uri": frontend_redirect,
                "nonce": secrets.token_urlsafe(8)
            }
            state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

            # ✅ Use the backend redirect URI that matches Azure App Registration
            backend_redirect = settings.MICROSOFT_REDIRECT_URI

            auth_url = (
                f"{settings.MICROSOFT_AUTH_URL}?"
                f"client_id={settings.MICROSOFT_CLIENT_ID}"
                f"&response_type=code"
                f"&redirect_uri={backend_redirect}"
                f"&response_mode=query"
                f"&scope=https://graph.microsoft.com/User.Read offline_access openid email profile"
                f"&prompt=select_account"
                f"&state={state}"
            )

            print("✅ Generated Microsoft Auth URL:", auth_url)
            print("🧩 Encoded state:", state)

            return JsonResponse({"auth_url": auth_url, "state": state})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
        
        
class MicrosoftTeamsCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger = logging.getLogger(__name__)

        try:
            code = request.GET.get("code")
            state = request.GET.get("state")

            if not code:
                return JsonResponse({"error": "Missing code"}, status=400)
            if not state:
                return JsonResponse({"error": "Missing state"}, status=400)

            # ✅ Decode state (get frontend redirect URL)
            try:
                decoded = base64.urlsafe_b64decode(state + "==").decode()
                state_data = json.loads(decoded)
                frontend_redirect = state_data.get("redirect_uri")
                print("🌐 Decoded frontend redirect:", frontend_redirect)
            except Exception as decode_error:
                logger.error(f"State decode failed: {decode_error}")
                frontend_redirect = None

            # ✅ Exchange authorization code for access token
            token_payload = {
                "grant_type": "authorization_code",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.MICROSOFT_REDIRECT_URI,  # must match App Registration
            }
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            token_response = requests.post(settings.MICROSOFT_TOKEN_URL, data=token_payload, headers=headers)
            token_data = token_response.json()

            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_data}")
                return JsonResponse({"error": "Token exchange failed", "details": token_data},
                                    status=token_response.status_code)

            access_token = token_data.get("access_token")
            if not access_token:
                return JsonResponse({"error": "No access token returned"}, status=400)

            # ✅ Fetch Microsoft user info
            user_info = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}
            ).json()
            print("👤 Microsoft user info:", user_info)

            # ✅ Save user to DB
            email = user_info.get("mail") or user_info.get("userPrincipalName")
            full_name = user_info.get("displayName", "")
            first_name, last_name = (full_name.split(" ", 1) + [""])[:2]

            if email:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "first_name": first_name,
                        "last_name": last_name,
                        "password": make_password(None)
                    }
                )
                logger.info(f"✅ Microsoft user {'created' if created else 'exists'}: {email}")
            else:
                logger.warning("⚠️ Microsoft user missing email — skipped saving")

            # ✅ Redirect popup to frontend callback
            if frontend_redirect:
                redirect_url = f"{frontend_redirect}/teams-callback?code={code}&state={state}"
                print("🔁 Redirecting to:", redirect_url)
                return redirect(redirect_url)

            return JsonResponse({"message": "Login successful, but no redirect found."})

        except Exception as e:
            logger.error(f"Microsoft callback error: {str(e)}", exc_info=True)
            return JsonResponse({"error": str(e)}, status=500)
        
       

class MicrosoftTeamsOAuthUrlView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            frontend_redirect = request.GET.get("redirect_uri")
            if not frontend_redirect:
                return JsonResponse({"error": "Missing redirect_uri"}, status=400)

            # Create state (encodes frontend redirect)
            state_data = {
                "redirect_uri": frontend_redirect,
                "nonce": secrets.token_urlsafe(8)
            }
            state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

            backend_redirect = settings.MICROSOFT_REDIRECT_URI

            scopes = [
                "https://graph.microsoft.com/User.Read",
                "https://graph.microsoft.com/Team.Create",
                "https://graph.microsoft.com/Group.ReadWrite.All",
                "https://graph.microsoft.com/Channel.Create",
                "https://graph.microsoft.com/ChannelMessage.Send",
                "https://graph.microsoft.com/TeamMember.ReadWrite.All",
                "https://graph.microsoft.com/ChannelMember.ReadWrite.All",
                "offline_access",
                "openid",
                "email",
                "profile",
            ]
            scope_param = "%20".join(scopes)

            auth_url = (
                f"{settings.MICROSOFT_AUTH_URL}?"
                f"client_id={settings.MICROSOFT_CLIENT_ID}"
                f"&response_type=code"
                f"&redirect_uri={backend_redirect}"
                f"&response_mode=query"
                f"&scope={scope_param}"
                f"&state={state}"
            )

            print("🔗 Auth URL:", auth_url)
            return JsonResponse({"auth_url": auth_url, "state": state})

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)


def auto_create_vaptfix_team(access_token):
    """
    Auto-create a team named 'VAPTFIX' with 4 default channels if it doesn't already exist.
    Returns dict with team_id, team_name, and channels info.
    """
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    # Step 1: Check if VAPTFIX team already exists
    try:
        search_url = "https://graph.microsoft.com/v1.0/me/joinedTeams"
        resp = requests.get(search_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            teams = resp.json().get('value', [])
            for team in teams:
                if team.get('displayName') == 'VAPTFIX':
                    logger.info(f"VAPTFIX team already exists: {team.get('id')}")
                    return {
                        "team_id": team.get('id'),
                        "team_name": "VAPTFIX",
                        "status": "already_exists",
                        "channels": []
                    }
    except Exception as e:
        logger.warning(f"Error checking existing teams: {str(e)}")

    # Step 2: Create VAPTFIX team
    try:
        create_url = "https://graph.microsoft.com/v1.0/teams"
        payload = {
            "template@odata.bind": "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
            "displayName": "VAPTFIX",
            "description": "VAPTFIX Security Management Team",
            "visibility": "private",
        }
        resp = requests.post(create_url, headers=headers, json=payload, timeout=30)

        team_id = None
        if resp.status_code in (200, 201):
            team_location = resp.headers.get('Location', '')
            match = re.search(r"teams\('([^']+)'\)", team_location)
            if match:
                team_id = match.group(1)
            elif resp.status_code == 200:
                team_id = resp.json().get('id')
        elif resp.status_code == 202:
            team_location = resp.headers.get('Location', '')
            match = re.search(r"teams\('([^']+)'\)", team_location)
            if match:
                team_id = match.group(1)
            # Wait for team to be provisioned
            if team_id:
                for attempt in range(5):
                    time.sleep(10)
                    check = requests.get(
                        f"https://graph.microsoft.com/v1.0/teams/{team_id}",
                        headers=headers, timeout=10
                    )
                    if check.status_code == 200:
                        break
                    logger.info(f"VAPTFIX team not ready, retry {attempt + 1}/5")
        else:
            logger.error(f"Failed to create VAPTFIX team: {resp.status_code} {resp.text}")
            return {"team_id": None, "team_name": "VAPTFIX", "status": "creation_failed", "error": resp.text, "channels": []}

        if not team_id:
            return {"team_id": None, "team_name": "VAPTFIX", "status": "creation_failed", "error": "Could not extract team ID", "channels": []}

        # Step 3: Create 4 default channels
        default_channels = ["Patch Management", "Configuration Management", "Network Security", "Architectural Flaws"]
        channels_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels"
        channels_result = []

        for channel_name in default_channels:
            ch_payload = {
                "displayName": channel_name,
                "description": f"{channel_name} channel",
                "membershipType": "private"
            }
            try:
                ch_resp = requests.post(channels_url, headers=headers, json=ch_payload, timeout=15)
                if ch_resp.status_code in (200, 201):
                    ch_data = ch_resp.json()
                    channels_result.append({
                        "channelName": channel_name,
                        "channelId": ch_data.get("id"),
                        "status": "created"
                    })
                else:
                    channels_result.append({
                        "channelName": channel_name,
                        "status": "failed",
                        "error": ch_resp.text
                    })
            except Exception as e:
                channels_result.append({
                    "channelName": channel_name,
                    "status": "failed",
                    "error": str(e)
                })

        logger.info(f"VAPTFIX team created: {team_id} with {len([c for c in channels_result if c['status'] == 'created'])} channels")
        return {
            "team_id": team_id,
            "team_name": "VAPTFIX",
            "status": "created",
            "channels": channels_result
        }

    except Exception as e:
        logger.error(f"Auto-create VAPTFIX team error: {str(e)}")
        return {"team_id": None, "team_name": "VAPTFIX", "status": "error", "error": str(e), "channels": []}


class MicrosoftTeamsCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        logger = logging.getLogger(__name__)

        try:
            code = request.GET.get("code")
            state = request.GET.get("state")

            if not code:
                return JsonResponse({"error": "Missing code"}, status=400)
            if not state:
                return JsonResponse({"error": "Missing state"}, status=400)

            # Decode state (to get frontend redirect)
            # State can be either base64-encoded JSON or a plain random string
            frontend_redirect = settings.FRONTEND_URL if hasattr(settings, 'FRONTEND_URL') else "http://localhost:3000"
            try:
                decoded_state = base64.urlsafe_b64decode(state + "==").decode()
                state_data = json.loads(decoded_state)
                frontend_redirect = state_data.get("redirect_uri", frontend_redirect)
            except (UnicodeDecodeError, json.JSONDecodeError, Exception):
                # State is a plain string (not base64-encoded JSON), use default redirect
                logger.info(f"State is plain string: {state}, using default redirect: {frontend_redirect}")
            print("Frontend redirect:", frontend_redirect)

            # Exchange code for tokens
            token_payload = {
                "grant_type": "authorization_code",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
            }
            token_response = requests.post(settings.MICROSOFT_TOKEN_URL, data=token_payload)
            token_data = token_response.json()
            print("🔑 Token Response:", token_data)

            if token_response.status_code != 200 or "access_token" not in token_data:
                return JsonResponse({
                    "error": "Token exchange failed",
                    "details": token_data
                }, status=400)

            access_token = token_data["access_token"]

            # Get user info from Microsoft Graph
            user_info = requests.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}
            ).json()
            print("👤 User info:", user_info)

            email = user_info.get("mail") or user_info.get("userPrincipalName")
            full_name = user_info.get("displayName", "")
            firstname, lastname = (full_name.split(" ", 1) + [""])[:2]

            # Save user in DB
            user_data = None
            if email:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "password": make_password(None),
                        "login_provider": "microsoft_teams",
                    },
                )
                if not created:
                    user.login_provider = 'microsoft_teams'
                    user.save(update_fields=['login_provider'])
                user_data = {
                    "email": user.email,
                    "id": str(user.id),
                    "displayName": full_name,
                }
                logger.info(f"Microsoft user {'created' if created else 'exists'}: {email}")

            # Auto-create VAPTFIX team with 4 channels
            vaptfix_team = auto_create_vaptfix_team(access_token)
            logger.info(f"VAPTFIX team result: {vaptfix_team}")

            # HTML response: log access token to console and redirect immediately to MS Teams
            html = f"""
            <html>
            <head><title>Redirecting...</title></head>
            <body>
                <script>
                    console.log("=== Microsoft Teams Access Token ===");
                    console.log("{token_data.get('access_token', '')}");
                    console.log("=== User Data ===");
                    console.log({json.dumps(user_data)});
                    console.log("=== VAPTFIX Team ===");
                    console.log({json.dumps(vaptfix_team)});

                    // Post message to opener if popup
                    if (window.opener) {{
                        window.opener.postMessage({{
                            success: true,
                            user: {json.dumps(user_data)},
                            tokens: {json.dumps(token_data)},
                            vaptfix_team: {json.dumps(vaptfix_team)}
                        }}, "{frontend_redirect}");
                    }}

                    // Redirect immediately to Microsoft Teams website
                    window.location.href = "https://teams.microsoft.com";
                </script>
            </body>
            </html>
            """
            return HttpResponse(html)

        except Exception as e:
            logger.error(f"Callback error: {str(e)}", exc_info=True)
            return JsonResponse({"error": str(e)}, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class MicrosoftTeamsOAuthView(generics.GenericAPIView):
    serializer_class = MicrosoftTeamsOAuthSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data.get('access_token')
                microsoft_user_data = serializer.get_microsoft_user_data(access_token)
                user = serializer.create_or_get_user(microsoft_user_data)

                user.login_provider = 'microsoft_teams'
                user.save(update_fields=['login_provider'])

                login(request, user)
                refresh = RefreshToken.for_user(user)

                # Auto-create VAPTFIX team with 4 channels
                vaptfix_team = auto_create_vaptfix_team(access_token)

                logger.info(f"Microsoft Teams OAuth login successful: {user.email}")

                return Response({
                    "message": "Microsoft Teams login successful",
                    "user": UserProfileSerializer(user).data,
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    "access_token": str(access_token),
                    "is_new_user": False,
                    "vaptfix_team": vaptfix_team
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.error(f"Microsoft Teams OAuth error: {str(e)}")
            return Response({
                "error": "Microsoft Teams authentication failed. Please try again."
            }, status=status.HTTP_400_BAD_REQUEST)


@method_decorator(csrf_exempt, name='dispatch')
class MicrosoftTeamsTokenExchangeView(APIView):
    """
    Exchange Microsoft authorization code for a delegated access token.
    Frontend sends the authorization code, backend exchanges it for tokens.

    Step 1 (Frontend): Redirect user to Microsoft OAuth URL to get authorization code
    Step 2 (Frontend): Send the code to this endpoint
    Step 3 (Backend): Exchange code for delegated access token and return it

    Usage in Postman:
      1. GET /api/admin/users/microsoft-teams/oauth-url/?redirect_uri=http://localhost:3000
         → Copy the auth_url, open in browser, login, get code from redirect URL
      2. POST /api/admin/users/microsoft-teams/token-exchange/
         Body: {"code": "<authorization_code>", "redirect_uri": "http://localhost:3000"}
         → Returns delegated access_token
      3. Use that access_token in /api/admin/users/microsoft-teams-oauth/
    """
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            code = request.data.get('code')
            redirect_uri = request.data.get('redirect_uri')

            if not code:
                return Response({
                    "error": "Authorization code is required",
                    "hint": "First get the code by visiting the OAuth URL from /microsoft-teams/oauth-url/"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Must match the redirect_uri used in the OAuth URL (Azure App Registration)
            token_redirect_uri = settings.MICROSOFT_REDIRECT_URI

            token_payload = {
                "grant_type": "authorization_code",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "code": code,
                "redirect_uri": token_redirect_uri,
                "scope": "https://graph.microsoft.com/User.Read https://graph.microsoft.com/Team.Create https://graph.microsoft.com/Group.ReadWrite.All https://graph.microsoft.com/Channel.Create offline_access"
            }

            token_response = requests.post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
            token_data = token_response.json()

            if token_response.status_code != 200 or "access_token" not in token_data:
                return Response({
                    "error": "Token exchange failed",
                    "details": token_data
                }, status=status.HTTP_400_BAD_REQUEST)

            return Response({
                "message": "Token exchange successful. Use this access_token in /microsoft-teams-oauth/",
                "access_token": token_data.get("access_token"),
                "refresh_token": token_data.get("refresh_token", ""),
                "expires_in": token_data.get("expires_in"),
                "token_type": token_data.get("token_type"),
                "scope": token_data.get("scope", "")
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Microsoft token exchange error: {str(e)}")
            return Response({
                "error": "Token exchange failed",
                "detail": str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class CreateTeamsChannelView(generics.GenericAPIView):
    serializer_class = CreateChannelSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def validate_token_permissions(self, access_token):
        """Enhanced token validation with permission checking"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Check user profile and permissions
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                return False, f"Token validation failed: {response.status_code}"
            
            # Additional check - try to access teams
            teams_response = requests.get("https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers, timeout=10)
            
            if teams_response.status_code == 403:
                return False, "Insufficient permissions. Token needs Team.ReadBasic.All and Channel.Create scopes"
            
            return True, "Token valid with required permissions"
            
        except Exception as e:
            return False, f"Token validation error: {str(e)}"

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                channel_name = serializer.validated_data['channel_name']
                description = serializer.validated_data.get('description', '')
                
                # Enhanced token validation
                token_valid, token_message = self.validate_token_permissions(access_token)
                if not token_valid:
                    return Response({
                        "error": f"Token validation failed: {token_message}",
                        "solution": "Please re-authenticate with the required permissions"
                    }, status=status.HTTP_401_UNAUTHORIZED)
                
                # Create channel
                url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels"
                
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                payload = {
                    "displayName": channel_name,
                    "description": description,
                    "channelType": "standard"
                }
                
                logger.info(f"Creating channel: {payload}")
                
                response = requests.post(url, headers=headers, json=payload, timeout=30)
                
                if response.status_code == 201:
                    channel_data = response.json()
                    return Response({
                        "message": "Channel created successfully",
                        "channel": {
                            "id": channel_data.get("id"),
                            "displayName": channel_data.get("displayName"),
                            "description": channel_data.get("description"),
                            "webUrl": channel_data.get("webUrl")
                        }
                    }, status=status.HTTP_201_CREATED)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    # Enhanced error handling
                    error_code = error_data.get('error', {}).get('code', 'Unknown')
                    error_message = error_data.get('error', {}).get('message', 'Unknown error')
                    
                    # Specific error handling
                    if response.status_code == 403:
                        return Response({
                            "error": "Insufficient permissions to create channels",
                            "solution": "Please ensure your token has Channel.Create and Group.ReadWrite.All permissions",
                            "details": error_message
                        }, status=status.HTTP_403_FORBIDDEN)
                    elif response.status_code == 401:
                        return Response({
                            "error": "Unauthorized - Invalid or expired token",
                            "solution": "Please re-authenticate to get a fresh token",
                            "details": error_message
                        }, status=status.HTTP_401_UNAUTHORIZED)
                    else:
                        return Response({
                            "error": f"Failed to create channel: {error_message}",
                            "error_code": error_code,
                            "status_code": response.status_code,
                            "details": error_data
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Create channel error: {str(e)}")
            return Response({
                "error": f"Failed to create channel: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Other views remain similar with enhanced error handling...
@method_decorator(csrf_exempt, name='dispatch')
class SendTeamsMessageView(generics.GenericAPIView):
    serializer_class = SendMessageSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                channel_id = serializer.validated_data['channel_id']
                message = serializer.validated_data['message']
                
                url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/messages"
                
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                payload = {
                    "body": {
                        "contentType": "text",
                        "content": message
                    }
                }
                
                response = requests.post(url, headers=headers, json=payload, timeout=10)
                
                if response.status_code == 201:
                    message_data = response.json()
                    return Response({
                        "message": "Message sent successfully",
                        "messageDetails": {
                            "id": message_data.get("id"),
                            "createdDateTime": message_data.get("createdDateTime")
                        }
                    }, status=status.HTTP_201_CREATED)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    if response.status_code == 403:
                        return Response({
                            "error": "Insufficient permissions to send messages",
                            "solution": "Ensure token has ChannelMessage.Send permissions"
                        }, status=status.HTTP_403_FORBIDDEN)
                    else:
                        return Response({
                            "error": f"Failed to send message: {error_data.get('error', {}).get('message', 'Unknown error')}"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Send message error: {str(e)}")
            return Response({
                "error": "Failed to send message. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class ListTeamsView(generics.GenericAPIView):
    serializer_class = ListTeamsSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                
                url = "https://graph.microsoft.com/v1.0/me/joinedTeams"
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    teams_data = response.json()
                    teams_list = []
                    
                    for team in teams_data.get('value', []):
                        teams_list.append({
                            "id": team.get("id"),
                            "displayName": team.get("displayName"),
                            "description": team.get("description"),
                            "visibility": team.get("visibility"),
                            "webUrl": team.get("webUrl")
                        })
                    
                    return Response({
                        "teams": teams_list,
                        "count": len(teams_list)
                    }, status=status.HTTP_200_OK)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    return Response({
                        "error": f"Failed to fetch teams: {error_data.get('error', {}).get('message', 'Unknown error')}"
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"List teams error: {str(e)}")
            return Response({
                "error": "Failed to fetch teams. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class ListChannelsView(generics.GenericAPIView):
    serializer_class = ListChannelsSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                
                url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels"
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                response = requests.get(url, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    channels_data = response.json()
                    channels_list = []
                    
                    for channel in channels_data.get('value', []):
                        channels_list.append({
                            "id": channel.get("id"),
                            "displayName": channel.get("displayName"),
                            "description": channel.get("description"),
                            "membershipType": channel.get("membershipType"),
                            "webUrl": channel.get("webUrl")
                        })
                    
                    return Response({
                        "channels": channels_list,
                        "count": len(channels_list)
                    }, status=status.HTTP_200_OK)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    return Response({
                        "error": f"Failed to fetch channels: {error_data.get('error', {}).get('message', 'Unknown error')}"
                    }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"List channels error: {str(e)}")
            return Response({
                "error": "Failed to fetch channels. Please try again."
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
@method_decorator(csrf_exempt, name='dispatch')
class CreateTeamView(generics.GenericAPIView):
    serializer_class = CreateTeamSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def validate_token_permissions(self, access_token):
        """Validate token has required permissions for team creation"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Check user profile
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                return False, f"Token validation failed: {response.status_code}"
            
            # Check if user can create teams (try to list joined teams)
            teams_response = requests.get("https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers, timeout=10)
            
            if teams_response.status_code == 403:
                return False, "Insufficient permissions. Token needs Team.Create and Group.ReadWrite.All scopes"
            
            return True, "Token valid with required permissions"
            
        except Exception as e:
            return False, f"Token validation error: {str(e)}"

    def check_duplicate_team(self, access_token, team_name):
        """Check if a team with the same name already exists"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Search for teams with the same display name
            # Using groups endpoint because teams are built on Office 365 groups
            search_url = f"https://graph.microsoft.com/v1.0/groups?$filter=displayName eq '{team_name}' and resourceProvisioningOptions/Any(x:x eq 'Team')"
            
            response = requests.get(search_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                existing_teams = data.get('value', [])
                
                if existing_teams:
                    return True, f"A team with the name '{team_name}' already exists"
                return False, "No duplicate found"
            else:
                # If we can't check for duplicates, log warning but don't block creation
                logger.warning(f"Could not check for duplicate teams: {response.status_code}")
                return False, "Duplicate check skipped due to API limitations"
                
        except Exception as e:
            logger.warning(f"Error checking for duplicate teams: {str(e)}")
            return False, "Duplicate check failed but proceeding"

    DEFAULT_CHANNELS = [
        "Patch Management",
        "Configuration Management",
        "Network Security",
        "Architectural Flaws",
    ]

    def create_default_channels(self, access_token, team_id):
        """Create 4 default channels in the newly created team."""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels"
        results = []
        for channel_name in self.DEFAULT_CHANNELS:
            payload = {
                "displayName": channel_name,
                "description": f"{channel_name} channel",
                "membershipType": "private"
            }
            try:
                resp = requests.post(url, headers=headers, json=payload, timeout=15)
                if resp.status_code in (200, 201):
                    channel_data = resp.json()
                    results.append({
                        "channelName": channel_name,
                        "channelId": channel_data.get("id"),
                        "status": "created"
                    })
                else:
                    results.append({
                        "channelName": channel_name,
                        "status": "failed",
                        "error": resp.text
                    })
            except Exception as e:
                results.append({
                    "channelName": channel_name,
                    "status": "failed",
                    "error": str(e)
                })
        return results

    def wait_for_team_and_create_channels(self, access_token, team_id, max_retries=5, delay=10):
        """Wait for async team provisioning to complete, then create default channels."""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        for attempt in range(max_retries):
            time.sleep(delay)
            try:
                resp = requests.get(
                    f"https://graph.microsoft.com/v1.0/teams/{team_id}",
                    headers=headers,
                    timeout=10
                )
                if resp.status_code == 200:
                    return self.create_default_channels(access_token, team_id)
            except Exception:
                pass
            logger.info(f"Team {team_id} not ready yet, retry {attempt + 1}/{max_retries}")
        return [{"status": "failed", "error": "Team provisioning timed out. Channels were not created."}]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)

            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_name = serializer.validated_data['team_name']
                description = serializer.validated_data.get('description', '')
                visibility = serializer.validated_data['visibility']
                
                # Enhanced token validation
                token_valid, token_message = self.validate_token_permissions(access_token)
                if not token_valid:
                    return Response({
                        "error": f"Token validation failed: {token_message}",
                        "solution": "Please re-authenticate with Team.Create and Group.ReadWrite.All permissions"
                    }, status=status.HTTP_401_UNAUTHORIZED)
                
                # Check for duplicate team names
                is_duplicate, duplicate_message = self.check_duplicate_team(access_token, team_name)
                if is_duplicate:
                    return Response({
                        "error": "Team name already exists",
                        "message": duplicate_message,
                        "solution": "Please choose a different team name",
                        "team_name": team_name
                    }, status=status.HTTP_409_CONFLICT)
                
                # Create team using Groups API (Teams are built on top of Office 365 Groups)
                url = "https://graph.microsoft.com/v1.0/teams"
                
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                # Team creation payload
                payload = {
                    "template@odata.bind": "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
                    "displayName": team_name,
                    "description": description,
                    "visibility": visibility.lower(),
                    "memberSettings": {
                        "allowCreateUpdateChannels": True,
                        "allowDeleteChannels": True,
                        "allowAddRemoveApps": True,
                        "allowCreateUpdateRemoveConnectors": True,
                        "allowCreateUpdateRemoveTabs": True
                    },
                    "guestSettings": {
                        "allowCreateUpdateChannels": False,
                        "allowDeleteChannels": False
                    },
                    "messagingSettings": {
                        "allowUserEditMessages": True,
                        "allowUserDeleteMessages": True,
                        "allowOwnerDeleteMessages": True,
                        "allowTeamMentions": True,
                        "allowChannelMentions": True
                    },
                    "funSettings": {
                        "allowGiphy": True,
                        "giphyContentRating": "moderate",
                        "allowStickersAndMemes": True,
                        "allowCustomMemes": True
                    }
                }
                
                logger.info(f"Creating team: {payload}")
                
                response = requests.post(url, headers=headers, json=payload, timeout=30)
                
                if response.status_code == 201:
                    # Team creation is successful and completed immediately
                    team_location = response.headers.get('Location')

                    # Extract team ID from location header
                    team_id = None
                    if team_location:
                        match = re.search(r"teams\('([^']+)'\)", team_location)
                        if match:
                            team_id = match.group(1)

                    # Auto-create default channels
                    channels_result = []
                    if team_id:
                        channels_result = self.create_default_channels(access_token, team_id)

                    return Response({
                        "message": "Team created successfully",
                        "status": "completed",
                        "team": {
                            "id": team_id,
                            "displayName": team_name,
                            "description": description,
                            "visibility": visibility,
                            "location": team_location
                        },
                        "default_channels": channels_result
                    }, status=status.HTTP_201_CREATED)
                    
                elif response.status_code == 202:
                    # Team creation is being processed asynchronously
                    team_location = response.headers.get('Location')

                    # Extract team ID from location header for 202 responses
                    team_id = None
                    if team_location:
                        team_match = re.search(r"teams\('([^']+)'\)", team_location)
                        if team_match:
                            team_id = team_match.group(1)

                    # Wait for team provisioning, then create default channels
                    channels_result = []
                    if team_id:
                        channels_result = self.wait_for_team_and_create_channels(access_token, team_id)

                    return Response({
                        "message": "Team creation initiated and default channels created.",
                        "status": "completed",
                        "team_id": team_id,
                        "location": team_location,
                        "default_channels": channels_result
                    }, status=status.HTTP_201_CREATED)
                    
                elif response.status_code == 200:
                    # Sometimes Microsoft Graph returns 200 for successful operations
                    try:
                        response_data = response.json()
                        team_id = response_data.get('id')

                        # Auto-create default channels
                        channels_result = []
                        if team_id:
                            channels_result = self.create_default_channels(access_token, team_id)

                        return Response({
                            "message": "Team created successfully",
                            "status": "completed",
                            "team": {
                                "id": team_id,
                                "displayName": team_name,
                                "description": description,
                                "visibility": visibility,
                                "data": response_data
                            },
                            "default_channels": channels_result
                        }, status=status.HTTP_201_CREATED)
                    except Exception:
                        return Response({
                            "message": "Team creation may have succeeded but response format is unexpected",
                            "status": "unknown",
                            "raw_response": response.text
                        }, status=status.HTTP_200_OK)
                        
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    # Enhanced error handling
                    error_code = error_data.get('error', {}).get('code', 'Unknown')
                    error_message = error_data.get('error', {}).get('message', 'Unknown error')
                    
                    # Handle specific Microsoft Graph error for duplicate teams
                    if response.status_code == 409 or error_code == 'Request_ResourceAlreadyExists':
                        return Response({
                            "error": "Team name already exists",
                            "message": f"A team with the name '{team_name}' already exists in your organization",
                            "solution": "Please choose a different team name",
                            "team_name": team_name,
                            "details": error_message
                        }, status=status.HTTP_409_CONFLICT)
                    elif response.status_code == 403:
                        return Response({
                            "error": "Insufficient permissions to create teams",
                            "solution": "Please ensure your token has Team.Create and Group.ReadWrite.All permissions",
                            "details": error_message
                        }, status=status.HTTP_403_FORBIDDEN)
                    elif response.status_code == 401:
                        return Response({
                            "error": "Unauthorized - Invalid or expired token",
                            "solution": "Please re-authenticate to get a fresh token",
                            "details": error_message
                        }, status=status.HTTP_401_UNAUTHORIZED)
                    elif response.status_code == 400 and 'displayName' in error_message.lower():
                        return Response({
                            "error": "Invalid team name",
                            "message": "The team name contains invalid characters or format",
                            "solution": "Please use a valid team name without special characters",
                            "details": error_message
                        }, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({
                            "error": f"Failed to create team: {error_message}",
                            "error_code": error_code,
                            "status_code": response.status_code,
                            "details": error_data
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Create team error: {str(e)}")
            return Response({
                "error": f"Failed to create team: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@method_decorator(csrf_exempt, name='dispatch')
class AddUserToChannelView(generics.GenericAPIView):
    serializer_class = AddUserToChannelSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get_user_id_by_email(self, access_token, email):
        """Get Microsoft user ID by email"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Search for user by email
            url = f"https://graph.microsoft.com/v1.0/users/{email}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                user_data = response.json()
                return user_data.get('id'), None
            else:
                return None, f"User with email {email} not found"
                
        except Exception as e:
            return None, f"Error finding user: {str(e)}"

    def add_member_to_team(self, access_token, team_id, user_id, role):
        """Add user as team member first (required before adding to channel)"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"
            
            payload = {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')",
                "roles": [role] if role == "owner" else []
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            
            if response.status_code in [201, 409]:  # 409 means user already exists
                return True, "User added to team successfully"
            else:
                error_data = {}
                try:
                    error_data = response.json()
                except:
                    pass
                return False, f"Failed to add user to team: {error_data.get('error', {}).get('message', 'Unknown error')}"
                
        except Exception as e:
            return False, f"Error adding user to team: {str(e)}"

    def add_member_to_channel(self, access_token, team_id, channel_id, user_id, role):
        """Add user to specific channel"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}/members"
            
            payload = {
                "@odata.type": "#microsoft.graph.aadUserConversationMember",
                "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')",
                "roles": [role] if role == "owner" else []
            }
            
            response = requests.post(url, headers=headers, json=payload, timeout=10)
            
            if response.status_code in [201, 409]:  # 409 means user already exists
                return True, "User added to channel successfully"
            else:
                error_data = {}
                try:
                    error_data = response.json()
                except:
                    pass
                return False, f"Failed to add user to channel: {error_data.get('error', {}).get('message', 'Unknown error')}"
                
        except Exception as e:
            return False, f"Error adding user to channel: {str(e)}"

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                channel_id = serializer.validated_data['channel_id']
                user_email = serializer.validated_data['user_email']
                user_role = serializer.validated_data['user_role']
                
                # Check if user exists in our UserDetail model
                try:
                    from users_details.models import UserDetail
                    user_detail = UserDetail.objects.get(email=user_email)
                    logger.info(f"Found user in database: {user_detail.first_name} {user_detail.last_name}")
                except UserDetail.DoesNotExist:
                    return Response({
                        "error": f"User with email {user_email} not found in the system",
                        "solution": "Please ensure the user is registered in your system first"
                    }, status=status.HTTP_404_NOT_FOUND)
                
                # Get Microsoft user ID by email
                user_id, error_msg = self.get_user_id_by_email(access_token, user_email)
                if not user_id:
                    return Response({
                        "error": error_msg,
                        "solution": "Please ensure the user has a Microsoft account and is in your organization"
                    }, status=status.HTTP_404_NOT_FOUND)
                
                # First, add user to team (required before adding to channel)
                team_success, team_message = self.add_member_to_team(access_token, team_id, user_id, user_role)
                if not team_success:
                    return Response({
                        "error": team_message,
                        "step": "Adding user to team"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Then, add user to channel
                channel_success, channel_message = self.add_member_to_channel(access_token, team_id, channel_id, user_id, user_role)
                if not channel_success:
                    return Response({
                        "error": channel_message,
                        "step": "Adding user to channel",
                        "note": "User was added to team but failed to add to channel"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                return Response({
                    "message": "User added to channel successfully",
                    "user": {
                        "id": user_id,
                        "email": user_email,
                        "name": f"{user_detail.first_name} {user_detail.last_name}",
                        "role": user_role,
                        "user_type": user_detail.user_type,
                        "location": user_detail.select_location
                    },
                    "team_id": team_id,
                    "channel_id": channel_id
                }, status=status.HTTP_201_CREATED)
                    
        except Exception as e:
            logger.error(f"Add user to channel error: {str(e)}")
            return Response({
                "error": f"Failed to add user to channel: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
@method_decorator(csrf_exempt, name='dispatch')
class UpdateChannelView(generics.GenericAPIView):
    serializer_class = UpdateChannelSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def patch(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)

            access_token = serializer.validated_data['access_token']
            team_id = serializer.validated_data['team_id']
            channel_id = serializer.validated_data['channel_id']
            channel_name = serializer.validated_data.get('channel_name')
            description = serializer.validated_data.get('description')

            url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}"

            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            }

            payload = {}
            if channel_name:
                payload["displayName"] = channel_name
            if description is not None:
                payload["description"] = description

            response = requests.patch(url, headers=headers, json=payload, timeout=30)

            if response.status_code == 204:
                return Response({
                    "message": "Channel updated successfully",
                    "channel_id": channel_id
                }, status=status.HTTP_200_OK)

            elif response.status_code == 200:
                channel_data = response.json()
                return Response({
                    "message": "Channel updated successfully",
                    "channel": {
                        "id": channel_data.get("id"),
                        "displayName": channel_data.get("displayName"),
                        "description": channel_data.get("description"),
                        "webUrl": channel_data.get("webUrl")
                    }
                }, status=status.HTTP_200_OK)

            else:
                try:
                    error_data = response.json()
                    error_code = error_data.get('error', {}).get('code', 'Unknown')
                    error_message = error_data.get('error', {}).get('message', 'Unknown error')
                except Exception:
                    error_code = "Unknown"
                    error_message = response.text

                return Response({
                    "error": f"Failed to update channel: {error_message}",
                    "error_code": error_code,
                    "status_code": response.status_code
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                "error": f"Failed to update channel: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
class DeleteChannelView(generics.GenericAPIView):
    serializer_class = DeleteChannelSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def delete(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                channel_id = serializer.validated_data['channel_id']
                
                # Delete channel
                url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{channel_id}"
                
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                logger.info(f"Deleting channel {channel_id} from team {team_id}")
                
                response = requests.delete(url, headers=headers, timeout=30)
                
                if response.status_code == 204:
                    return Response({
                        "message": "Channel deleted successfully",
                        "channel_id": channel_id,
                        "team_id": team_id
                    }, status=status.HTTP_200_OK)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    error_code = error_data.get('error', {}).get('code', 'Unknown')
                    error_message = error_data.get('error', {}).get('message', 'Unknown error')
                    
                    if response.status_code == 403:
                        return Response({
                            "error": "Insufficient permissions to delete channel",
                            "solution": "Please ensure your token has Channel.Delete permissions",
                            "details": error_message
                        }, status=status.HTTP_403_FORBIDDEN)
                    elif response.status_code == 404:
                        return Response({
                            "error": "Channel or Team not found",
                            "solution": "Please check the team_id and channel_id",
                            "details": error_message
                        }, status=status.HTTP_404_NOT_FOUND)
                    elif response.status_code == 400 and "General" in error_code:
                        return Response({
                            "error": "Cannot delete General channel",
                            "solution": "The General channel is default and cannot be deleted",
                            "details": error_message
                        }, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({
                            "error": f"Failed to delete channel: {error_message}",
                            "error_code": error_code,
                            "status_code": response.status_code
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Delete channel error: {str(e)}")
            return Response({
                "error": f"Failed to delete channel: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@method_decorator(csrf_exempt, name='dispatch')
class UpdateTeamView(generics.GenericAPIView):
    serializer_class = UpdateTeamSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def validate_token_permissions(self, access_token):
        """Validate token has required permissions for team updates"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Check user profile
            response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                return False, f"Token validation failed: {response.status_code}"
            
            return True, "Token valid"
            
        except Exception as e:
            return False, f"Token validation error: {str(e)}"

    def get_team_details(self, access_token, team_id):
        """Get current team details after update"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            response = requests.get(f"https://graph.microsoft.com/v1.0/teams/{team_id}", headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            return None
            
        except Exception as e:
            logger.warning(f"Could not fetch team details: {str(e)}")
            return None

    def check_duplicate_team_for_update(self, access_token, team_name, current_team_id):
        """Check if a team with the same name already exists (excluding current team)"""
        try:
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Search for teams with the same display name
            search_url = f"https://graph.microsoft.com/v1.0/groups?$filter=displayName eq '{team_name}' and resourceProvisioningOptions/Any(x:x eq 'Team')"
            
            response = requests.get(search_url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                existing_teams = data.get('value', [])
                
                # Filter out the current team being updated
                duplicate_teams = [team for team in existing_teams if team.get('id') != current_team_id]
                
                if duplicate_teams:
                    return True, f"A team with the name '{team_name}' already exists"
                return False, "No duplicate found"
            else:
                # If we can't check for duplicates, log warning but don't block update
                logger.warning(f"Could not check for duplicate teams: {response.status_code}")
                return False, "Duplicate check skipped due to API limitations"
                
        except Exception as e:
            logger.warning(f"Error checking for duplicate teams: {str(e)}")
            return False, "Duplicate check failed but proceeding"

    def patch(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                team_name = serializer.validated_data.get('team_name')
                description = serializer.validated_data.get('description')
                visibility = serializer.validated_data.get('visibility')
                
                # Validate token permissions
                token_valid, token_message = self.validate_token_permissions(access_token)
                if not token_valid:
                    return Response({
                        "error": f"Token validation failed: {token_message}",
                        "solution": "Please re-authenticate with Group.ReadWrite.All permissions"
                    }, status=status.HTTP_401_UNAUTHORIZED)
                
                # Check for duplicate team names if team name is being updated
                if team_name:
                    is_duplicate, duplicate_message = self.check_duplicate_team_for_update(access_token, team_name, team_id)
                    if is_duplicate:
                        return Response({
                            "error": "Team name already exists",
                            "message": duplicate_message,
                            "solution": "Please choose a different team name",
                            "team_name": team_name
                        }, status=status.HTTP_409_CONFLICT)
                
                # Update team
                url = f"https://graph.microsoft.com/v1.0/teams/{team_id}"
                
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                }
                
                # Build payload with only provided fields
                payload = {}
                if team_name:
                    payload["displayName"] = team_name
                if description is not None:
                    payload["description"] = description
                if visibility:
                    payload["visibility"] = visibility.lower()
                
                if not payload:
                    return Response({
                        "error": "No fields provided for update",
                        "message": "At least one field (team_name, description, or visibility) must be provided",
                        "solution": "Please provide fields to update"
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                logger.info(f"Updating team {team_id}: {payload}")
                
                response = requests.patch(url, headers=headers, json=payload, timeout=30)
                
                # Microsoft Graph API returns 204 No Content for successful PATCH operations
                if response.status_code == 204:
                    # Success - Get updated team details
                    team_data = self.get_team_details(access_token, team_id)
                    
                    if team_data:
                        return Response({
                            "message": "Team updated successfully",
                            "status": "completed",
                            "team": {
                                "id": team_data.get("id"),
                                "displayName": team_data.get("displayName"),
                                "description": team_data.get("description"),
                                "visibility": team_data.get("visibility"),
                                "webUrl": team_data.get("webUrl"),
                                "createdDateTime": team_data.get("createdDateTime")
                            }
                        }, status=status.HTTP_200_OK)
                    else:
                        # Update was successful but couldn't fetch details
                        return Response({
                            "message": "Team updated successfully",
                            "status": "completed",
                            "team": {
                                "id": team_id,
                                "displayName": team_name if team_name else "Updated",
                                "description": description if description is not None else "Updated",
                                "visibility": visibility if visibility else "Updated"
                            }
                        }, status=status.HTTP_200_OK)
                        
                elif response.status_code == 200:
                    # Some operations might return 200 with data
                    team_data = response.json()
                    return Response({
                        "message": "Team updated successfully",
                        "status": "completed",
                        "team": {
                            "id": team_data.get("id"),
                            "displayName": team_data.get("displayName"),
                            "description": team_data.get("description"),
                            "visibility": team_data.get("visibility"),
                            "webUrl": team_data.get("webUrl"),
                            "createdDateTime": team_data.get("createdDateTime")
                        }
                    }, status=status.HTTP_200_OK)
                    
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    error_code = error_data.get('error', {}).get('code', 'Unknown')
                    error_message = error_data.get('error', {}).get('message', 'Unknown error')
                    
                    # Handle specific error cases
                    if response.status_code == 409 or error_code == 'Request_ResourceAlreadyExists':
                        return Response({
                            "error": "Team name already exists",
                            "message": f"A team with the name '{team_name}' already exists in your organization",
                            "solution": "Please choose a different team name",
                            "team_name": team_name,
                            "details": error_message
                        }, status=status.HTTP_409_CONFLICT)
                    elif response.status_code == 403:
                        return Response({
                            "error": "Insufficient permissions to update team",
                            "solution": "Please ensure your token has Group.ReadWrite.All permissions",
                            "details": error_message
                        }, status=status.HTTP_403_FORBIDDEN)
                    elif response.status_code == 404:
                        return Response({
                            "error": "Team not found",
                            "message": f"Team with ID '{team_id}' does not exist or you don't have access to it",
                            "solution": "Please check the team_id and ensure you have proper permissions",
                            "team_id": team_id,
                            "details": error_message
                        }, status=status.HTTP_404_NOT_FOUND)
                    elif response.status_code == 401:
                        return Response({
                            "error": "Unauthorized - Invalid or expired token",
                            "solution": "Please re-authenticate to get a fresh token",
                            "details": error_message
                        }, status=status.HTTP_401_UNAUTHORIZED)
                    elif response.status_code == 400:
                        return Response({
                            "error": "Invalid request data",
                            "message": "The provided data is invalid or malformed",
                            "solution": "Please check your team_name, description, and visibility values",
                            "details": error_message
                        }, status=status.HTTP_400_BAD_REQUEST)
                    else:
                        return Response({
                            "error": f"Failed to update team: {error_message}",
                            "error_code": error_code,
                            "status_code": response.status_code,
                            "details": error_data
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Update team error: {str(e)}")
            return Response({
                "error": f"Failed to update team: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
@method_decorator(csrf_exempt, name='dispatch')
class DeleteTeamView(generics.GenericAPIView):
    serializer_class = DeleteTeamSerializer
    permission_classes = [IsAuthenticated]
    renderer_classes = [UserRenderer]

    def delete(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                
                # Delete team (this actually deletes the underlying Office 365 Group)
                url = f"https://graph.microsoft.com/v1.0/groups/{team_id}"
                
                headers = {
                    'Authorization': f'Bearer {access_token}',
                    'Content-Type': 'application/json'
                }
                
                logger.info(f"Deleting team {team_id}")
                
                response = requests.delete(url, headers=headers, timeout=30)
                
                if response.status_code == 204:
                    return Response({
                        "message": "Team deleted successfully",
                        "team_id": team_id,
                        "note": "Team deletion may take a few minutes to complete"
                    }, status=status.HTTP_200_OK)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass
                    
                    error_code = error_data.get('error', {}).get('code', 'Unknown')
                    error_message = error_data.get('error', {}).get('message', 'Unknown error')
                    
                    if response.status_code == 403:
                        return Response({
                            "error": "Insufficient permissions to delete team",
                            "solution": "Please ensure your token has Group.ReadWrite.All permissions and you are an owner of the team",
                            "details": error_message
                        }, status=status.HTTP_403_FORBIDDEN)
                    elif response.status_code == 404:
                        return Response({
                            "error": "Team not found",
                            "solution": "Please check the team_id or the team may have already been deleted",
                            "details": error_message
                        }, status=status.HTTP_404_NOT_FOUND)
                    else:
                        return Response({
                            "error": f"Failed to delete team: {error_message}",
                            "error_code": error_code,
                            "status_code": response.status_code,
                            "note": "Only team owners can delete teams"
                        }, status=status.HTTP_400_BAD_REQUEST)
                    
        except Exception as e:
            logger.error(f"Delete team error: {str(e)}")
            return Response({
                "error": f"Failed to delete team: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



# ─── Slack workspace / channel helpers ───────────────────────────────────────

VAPTFIX_CHANNELS = [
    "patch-management",
    "configuration-management",
    "network-security",
    "architectural-flaws",
]


def ensure_vaptfix_channels(bot_token, slack_user_id=None):
    """
    Ensures the 4 vaptfix Slack channels exist.
    Creates any that are missing, bot joins them, and optionally invites the user.
    Returns dict of {channel_name: channel_id}.
    """
    headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}

    # List existing channels
    resp = requests.get(
        "https://slack.com/api/conversations.list",
        headers=headers,
        params={"types": "public_channel", "limit": 200},
    )
    existing = {ch["name"]: ch["id"] for ch in resp.json().get("channels", [])}

    channel_ids = {}
    for name in VAPTFIX_CHANNELS:
        if name in existing:
            channel_ids[name] = existing[name]
        else:
            create_resp = requests.post(
                "https://slack.com/api/conversations.create",
                headers=headers,
                json={"name": name, "is_private": False},
            )
            ch = create_resp.json().get("channel", {})
            channel_ids[name] = ch.get("id")

        channel_id = channel_ids[name]
        if not channel_id:
            continue

        # Bot joins channel
        requests.post(
            "https://slack.com/api/conversations.join",
            headers=headers,
            json={"channel": channel_id},
        )

        # Invite the logged-in Slack user
        if slack_user_id:
            requests.post(
                "https://slack.com/api/conversations.invite",
                headers=headers,
                json={"channel": channel_id, "users": slack_user_id},
            )

    return channel_ids


class SlackOAuthUrlView(APIView):
    """
    Dynamically generates Slack OAuth authorization URL
    for both ngrok (local) and production environments.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        state = str(uuid.uuid4())

        # Use SLACK_REDIRECT_URI from settings if configured, otherwise detect dynamically
        redirect_uri = getattr(settings, "SLACK_REDIRECT_URI", "")
        if not redirect_uri:
            base_url = request.data.get("base_url", "")
            if not base_url:
                try:
                    ngrok_resp = requests.get("http://127.0.0.1:4040/api/tunnels").json()
                    https_tunnel = next(
                        (t for t in ngrok_resp.get("tunnels", []) if t["public_url"].startswith("https://")),
                        None
                    )
                    base_url = https_tunnel["public_url"] if https_tunnel else request.build_absolute_uri("/").rstrip("/")
                except Exception:
                    base_url = request.build_absolute_uri("/").rstrip("/")
            redirect_uri = f"{base_url.rstrip('/')}/api/admin/users/slack/callback/"
        client_id = settings.SLACK_CLIENT_ID

        slack_url = (
            f"https://slack.com/oauth/v2/authorize?"
            f"client_id={client_id}"
            f"&scope=chat:write,channels:manage,channels:join,mpim:write,groups:write,im:write,users:read,users:read.email"
            f"&user_scope=identity.basic,identity.email,identity.avatar,identity.team"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
        )

        return Response({
            "success": True,
            "redirect_uri": redirect_uri,
            "state": state,
            "auth_url": slack_url
        }, status=status.HTTP_200_OK)


class SlackOAuthCallbackView(APIView):
    """
    Handles Slack OAuth callback (GET).
    Exchanges code for tokens, saves Slack user in DB,
    and returns an HTML that sends a postMessage to frontend before closing.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            code = request.GET.get("code")
            state = request.GET.get("state", "")

            if not code:
                return self._html_response(success=False, error="Missing code from Slack")

            # Use SLACK_REDIRECT_URI from settings if configured, otherwise detect dynamically
            redirect_uri = getattr(settings, "SLACK_REDIRECT_URI", "")
            if not redirect_uri:
                try:
                    ngrok_resp = requests.get("http://127.0.0.1:4040/api/tunnels").json()
                    https_tunnel = next(
                        (t for t in ngrok_resp.get("tunnels", []) if t["public_url"].startswith("https://")),
                        None
                    )
                    base_url = https_tunnel["public_url"] if https_tunnel else request.build_absolute_uri("/").rstrip("/")
                except Exception:
                    base_url = request.build_absolute_uri("/").rstrip("/")
                redirect_uri = f"{base_url}/api/admin/users/slack/callback/"
            logger.info(f"Slack callback received: code={code}, redirect_uri={redirect_uri}")

            # ✅ Step 1: Exchange code for access tokens
            token_url = "https://slack.com/api/oauth.v2.access"
            token_data = {
                "client_id": settings.SLACK_CLIENT_ID,
                "client_secret": settings.SLACK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            }

            try:
                token_res = requests.post(token_url, data=token_data, timeout=10)
                token_json = token_res.json()
            except Exception as e:
                logger.error(f"Slack token exchange failed: {str(e)}")
                return self._html_response(success=False, error="Slack token exchange failed")

            if not token_json.get("ok"):
                error = token_json.get("error", "OAuth failed")
                logger.error(f"Slack OAuth error: {error}")
                return self._html_response(success=False, error=error)

            # ✅ Step 2: Extract Slack tokens
            bot_token = token_json.get("access_token")
            team_info = token_json.get("team", {})
            authed_user = token_json.get("authed_user", {})


            # ✅ Step 3: Fetch user profile from Slack
            user_id = authed_user.get("id")
            user_info = requests.get(
                "https://slack.com/api/users.info",
                params={"user": user_id},
                headers={"Authorization": f"Bearer {bot_token}"},
            ).json()

            if not user_info.get("ok"):
                logger.error(f"Slack user info error: {user_info.get('error')}")
                return self._html_response(success=False, error="Failed to fetch user info from Slack")

            user_data = user_info.get("user", {})
            email = user_data.get("profile", {}).get("email")
            name = user_data.get("real_name") or user_data.get("name") or "Slack User"
            firstname = name.split()[0]
            lastname = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

            # ✅ Step 4: Create or update user
            user, created = User.objects.get_or_create(
                email=email,
                defaults={"login_provider": "slack", "password": ""},
            )
            if not created:
                user.login_provider = "slack"
                user.slack_user_id = user_id
                user.slack_team_id = team_info.get("id")
                user.save()
            else:
                user.slack_user_id = user_id
                user.slack_team_id = team_info.get("id")
                user.save()

            # ✅ Step 4b: Ensure vaptfix channels exist and invite user
            channels = {}
            try:
                channels = ensure_vaptfix_channels(bot_token, slack_user_id=user_id)
            except Exception:
                logger.warning("ensure_vaptfix_channels failed in callback", exc_info=True)

            # ✅ Step 5: Redirect to the Slack workspace
            team_id = team_info.get("id")
            slack_redirect_url = f"https://app.slack.com/client/{team_id}" if team_id else "https://slack.com"
            return redirect(slack_redirect_url)

        except Exception as e:
            logger.exception("Slack OAuth callback exception")
            return self._html_response(success=False, error=str(e))

    # def _html_response(self, success=True, data=None, error=None):
    #     """
    #     Returns a minimal HTML:
    #       - Sends result via postMessage to parent window
    #       - Closes popup after a short delay
    #     """
    #     payload = {"success": success}
    #     if success:
    #         payload.update(data or {})
    #     else:
    #         payload.update({"error": error})

    #     html = f"""
    #     <html>
    #     <head>
    #         <title>Slack OAuth</title>
    #          <script>
    #             (function() {{
    #                 var payload = {json.dumps(payload)};
    #                 console.log("Slack OAuth finished:", payload);
    #                 if (window.opener) {{
    #                     window.opener.postMessage({
    #                         type: "slack-auth-success",
    #                         payload: payload
    #                     }, "*");
    #                 }}
    #                 window.close();
    #             }})();
    #         </script>
    #     </head>
    #     <body style="font-family:sans-serif; text-align:center; margin-top:40px;">
    #         <h2>Slack login successful 🎉</h2>
    #         <p>You can close this window now.</p>
    #     </body>
    #     </html>
    #     """
    #     return HttpResponse(html)
    
    def _html_response(self, success=True, data=None, error=None):
        """
        Returns a minimal HTML:
        - Sends result via postMessage to parent window
        - Closes popup after a short delay
        """
        payload = {"success": success}
        if success:
            payload.update(data or {})
        else:
            payload.update({"error": error})

        # Convert payload to JSON string first
        payload_json = json.dumps(payload)

        html = f"""
        <html>
        <head>
            <title>Slack OAuth</title>
            <script>
                (function() {{
                    var payload = {payload_json};
                    console.log("Slack OAuth finished:", payload);
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: "slack-auth-success",
                            payload: payload
                        }}, "*");
                    }}
                    window.close();
                }})();
            </script>
        </head>
        <body style="font-family:sans-serif; text-align:center; margin-top:40px;">
            <h2>Slack login successful 🎉</h2>
            <p>You can close this window now.</p>
        </body>
        </html>
        """
        return HttpResponse(html)
             
# class SlackLoginView(APIView):
#     """
#     Slack Login API
#     Takes bot_access_token and user_access_token from callback response,
#     fetches Slack user info, and saves user to database.
#     """
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         # ✅ Validate incoming tokens
#         serializer = SlackLoginSerializer(data=request.data)
#         serializer.is_valid(raise_exception=True)

#         bot_token = serializer.validated_data["bot_access_token"]
#         user_token = serializer.validated_data["user_access_token"]

#         # ✅ Step 1: Get Slack user info
#         user_info_response = requests.get(
#             "https://slack.com/api/users.identity",
#             headers={"Authorization": f"Bearer {user_token}"}
#         )
#         user_info = user_info_response.json()

#         if not user_info.get("ok"):
#             return Response(
#                 {"success": False, "error": user_info.get("error", "Unable to fetch Slack user info")},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         # ✅ Step 2: Extract Slack user data
#         user_data = user_info.get("user", {})
#         team_data = user_info.get("team", {})

#         email = user_data.get("email")
#         name = user_data.get("name") or "Slack User"
#         firstname = name.split()[0]
#         lastname = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

#         # ✅ Step 3: Create or update local user (no model change)
#         user, created = User.objects.get_or_create(
#             email=email,
#             defaults={
#                 "firstname": firstname,
#                 "lastname": lastname,
#                 "password": ""
#             }
#         )

#         # ✅ Step 4: Optionally store Slack tokens (if SlackAuth model exists)
#         try:
#             SlackAuth = apps.get_model("users", "SlackAuth")
#             SlackAuth.objects.create(
#                 user=user,
#                 bot_token=bot_token,
#                 user_token=user_token,
#                 team_id=team_data.get("id"),
#                 team_name=team_data.get("name"),
#             )
#         except LookupError:
#             pass  # skip if SlackAuth model not present

#         # ✅ Step 5: Return clean response
#         return Response({
#             "success": True,
#             "message": "Slack user login successful",
#             "user": {
#                 "id": user.id,
#                 "email": user.email,
#                 "name": f"{user.firstname} {user.lastname}"
#             },
#             "team": team_data,
#             "tokens": {
#                 "bot_access_token": bot_token,
#                 "user_access_token": user_token
#             }
#         }, status=status.HTTP_200_OK)
        
                        
     
class SlackLoginView(APIView):
    """
    Slack Login API - Tracks login source + identifies existing users
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SlackLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        bot_token = serializer.validated_data["bot_access_token"]
        user_token = serializer.validated_data["user_access_token"]

        try:
            # 1. Get Slack user identity (PRIMARY email source)
            user_identity = requests.get(
                "https://slack.com/api/users.identity",
                headers={"Authorization": f"Bearer {user_token}"}
            ).json()

            slack_user_id = None
            slack_email = None
            slack_name = None
            slack_team = {}
            bot_response = None
            profile = {}

            if user_identity.get("ok"):
                slack_user = user_identity.get("user", {})
                slack_team = user_identity.get("team", {})
                slack_email = slack_user.get("email")
                slack_user_id = slack_user.get("id")
                slack_name = slack_user.get("name")
            else:
                # Fallback: bot token users.info
                bot_response = requests.get(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {bot_token}"}
                ).json()

                user_info = requests.get(
                    "https://slack.com/api/users.info",
                    headers={"Authorization": f"Bearer {bot_token}"},
                    params={"user": bot_response.get("user_id")}
                ).json()

                slack_user = user_info.get("user", {}) if user_info.get("ok") else {}
                profile = slack_user.get("profile", {})
                slack_team = {"id": bot_response.get("team_id"), "name": bot_response.get("team")}
                slack_email = profile.get("email")
                slack_user_id = slack_user.get("id")
                slack_name = slack_user.get("real_name") or slack_user.get("name")

            # ✅ CRITICAL: Validate email exists
            if not slack_email:
                return Response(
                    {"success": False, "error": "No email found in Slack profile"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 2. IDENTIFY existing user OR create new
            user, created = User.objects.get_or_create(
                email=slack_email,
                defaults={
                    "is_active": True,
                    "is_staff": True,
                    "is_superuser": True,
                    "password": "",
                    "last_login": timezone.now(),
                    "login_provider": "slack",
                    "slack_user_id": slack_user_id,
                    "slack_team_id": slack_team.get("id"),
                }
            )

            # 3. Update existing users
            if not created:
                user.last_login = timezone.now()
                user.login_provider = "slack"
                user.slack_user_id = slack_user_id
                user.slack_team_id = slack_team.get("id")
                user.save()

            # 3b. Ensure vaptfix channels exist and invite user
            channels = {}
            try:
                channels = ensure_vaptfix_channels(bot_token, slack_user_id=slack_user_id)
            except Exception:
                logger.warning("ensure_vaptfix_channels failed in login", exc_info=True)

            # 4. PERFECT RESPONSE FORMAT
            return Response({
                "success": True,
                "message": "Slack login successful",
                "data": {
                    "bot_access_token": bot_token,
                    "bot_user_id": bot_response.get("user_id") if bot_response else None,
                    "team": slack_team,
                    "user_access_token": user_token,
                    "channels": channels,
                    "user": {
                        "id": slack_user_id,
                        "name": slack_name or "Slack User",
                        "display_name": slack_name,
                        "email": slack_email,
                        "image": profile.get("image_192", ""),
                    },
                    "local_user": {
                        "id": str(user.id),
                        "email": user.email,
                        "login_provider": user.login_provider,
                        "is_superuser": user.is_superuser,
                        "slack_user_id": user.slack_user_id,
                        "last_login": user.last_login.isoformat() if user.last_login else None
                    }
                }
            }, status=status.HTTP_200_OK)

        except User.DoesNotExist:
            return Response({"success": False, "error": "User not found"}, status=404)
        except Exception as e:
            logger.error(f"Slack login error: {str(e)}")
            return Response({"success": False, "error": str(e)}, status=500)
     
class SlackOAuthView(APIView):
    """
    Verifies a Slack bot access token and returns bot/team/user info.
    This API can be used externally after Slack OAuth callback success.
    """
    permission_classes = [AllowAny]  # allow external use

    def post(self, request):
        print(">>> Inside SlackOAuthView <<<")
        serializer = SlackOAuthSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        access_token = serializer.validated_data.get("access_token")

        try:
            # ✅ 1. Verify token and get identity info
            auth_test_url = "https://slack.com/api/auth.test"
            headers = {"Authorization": f"Bearer {access_token}"}
            auth_response = requests.get(auth_test_url, headers=headers)
            auth_json = auth_response.json()

            if not auth_json.get("ok"):
                logger.error(f"Invalid Slack token: {auth_json}")
                return Response(
                    {"success": False, "error": auth_json.get("error", "Invalid Slack token")},
                    status=status.HTTP_401_UNAUTHORIZED
                )

            # ✅ 2. Optionally fetch bot info (if it's a bot token)
            bot_info = {}
            if auth_json.get("bot_id"):
                bot_info_url = "https://slack.com/api/bots.info"
                bot_info_response = requests.get(
                    bot_info_url,
                    headers=headers,
                    params={"bot": auth_json.get("bot_id")}
                )
                bot_info = bot_info_response.json().get("bot", {})

            # ✅ 3. Return a clean, structured response
            return Response({
                "success": True,
                "message": "Slack bot access token verified successfully",
                "data": {
                    "team": {
                        "id": auth_json.get("team_id"),
                        "name": auth_json.get("team"),
                    },
                    "user": {
                        "id": auth_json.get("user_id"),
                        "name": auth_json.get("user"),
                    },
                    "bot": {
                        "id": auth_json.get("bot_id"),
                        "info": bot_info
                    }
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Slack OAuth verification error: {str(e)}")
            return Response(
                {"success": False, "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
                                      
class SlackValidateTokenView(APIView):
    """
    Validate Slack access token and return user info
    """
    permission_classes = []
    
    def post(self, request):
        access_token = request.data.get('access_token')
        
        if not access_token:
            return Response({
                'success': False,
                'message': 'Access token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Test token validity and get user info
            headers = {'Authorization': f'Bearer {access_token}'}
            
            # Get auth test (validates token)
            auth_test_response = requests.get('https://slack.com/api/auth.test', headers=headers)
            auth_test_data = auth_test_response.json()
            
            if not auth_test_data.get('ok'):
                return Response({
                    'success': False,
                    'message': 'Invalid or expired access token'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Get detailed user info
            user_id = auth_test_data.get('user_id')
            user_response = requests.get(
                'https://slack.com/api/users.info', 
                headers=headers, 
                params={'user': user_id}
            )
            user_data = user_response.json()
            
            if user_data.get('ok'):
                user_profile = user_data.get('user', {}).get('profile', {})
                return Response({
                    'success': True,
                    'message': 'Token is valid',
                    'data': {
                        'team_id': auth_test_data.get('team_id'),
                        'team': auth_test_data.get('team'),
                        'user': {
                            'id': user_id,
                            'name': user_profile.get('real_name'),
                            'display_name': user_profile.get('display_name'),
                            'email': user_profile.get('email'),
                            'image': user_profile.get('image_192')
                        },
                        'bot_id': auth_test_data.get('bot_id')
                    }
                }, status=status.HTTP_200_OK)
            
            return Response({
                'success': True,
                'message': 'Token is valid',
                'data': {
                    'team_id': auth_test_data.get('team_id'),
                    'team': auth_test_data.get('team'),
                    'user_id': user_id
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Token validation error: {str(e)}")
            return Response({
                'success': False,
                'message': f'Error validating token: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            

# class SlackLoginView(APIView):
#     """
#     Slack Login API
#     Logs in the user using bot and user access tokens.
#     Fetches all Slack user info and stores user locally.
#     """
#     permission_classes = [permissions.AllowAny]

#     def post(self, request):
#         serializer = SlackLoginSerializer(data=request.data)
#         if not serializer.is_valid():
#             return Response(
#                 {"success": False, "errors": serializer.errors},
#                 status=status.HTTP_400_BAD_REQUEST,
#             )

#         validated_data = serializer.validated_data
#         user, created = serializer.create_or_update_user(validated_data)

#         profile = validated_data["user_info"].get("user", {}).get("profile", {})
#         team = validated_data["team_info"].get("team", {})

#         response_data = {
#             "success": True,
#             "message": "Slack user login successful",
#             "bot_data": {
#                 "ok": validated_data["bot_auth"].get("ok"),
#                 "bot_user_id": validated_data["bot_auth"].get("user_id"),
#                 "team_id": validated_data["bot_auth"].get("team_id"),
#                 "team": validated_data["bot_auth"].get("team"),
#             },
#             "user_data": {
#                 "ok": validated_data["user_auth"].get("ok"),
#                 "user_id": validated_data["user_auth"].get("user_id"),
#                 "team_id": validated_data["user_auth"].get("team_id"),
#                 "user_name": validated_data.get("name"),
#                 "email": validated_data.get("email"),
#                 "image_512": profile.get("image_512"),
#                 "title": profile.get("title"),
#                 "phone": profile.get("phone"),
#             },
#             "team_info": {
#                 "ok": validated_data["team_info"].get("ok"),
#                 "team": team,
#             },
#             "local_user": {
#                 "id": user.id,
#                 "email": user.email,
#                 "name": user.first_name,
#                 "created": created,
#             },
#         }

#         return Response(response_data, status=status.HTTP_200_OK)
    
    
class SendSlackMessageView(APIView):
    """Send messages to Slack channels or users"""
    authentication_classes = []
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            access_token = request.data.get('access_token')
            channel = request.data.get('channel')
            text = request.data.get('text')
            blocks = request.data.get('blocks')
            
            # Validation
            if not access_token:
                return Response({
                    'success': False,
                    'message': 'Slack access token is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not channel or not text:
                return Response({
                    'success': False,
                    'message': 'Channel and text are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Prepare payload
            payload = {
                'channel': channel,
                'text': text
            }
            
            if blocks:
                payload['blocks'] = blocks
            
            # Send message to Slack
            response = self._send_slack_message(access_token, payload)
            
            if response['success']:
                return Response({
                    'success': True,
                    'message': 'Message sent successfully',
                    'data': response['data']
                }, status=status.HTTP_200_OK)
            else:
                # Handle specific Slack errors
                error_message = self._get_user_friendly_error(response['error'])
                return Response({
                    'success': False,
                    'message': error_message,
                    'slack_error': response['error']
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except requests.RequestException as e:
            logger.error(f"Slack API request error: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to connect to Slack API'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
            
        except Exception as e:
            logger.error(f"Slack message error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred while sending message: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _send_slack_message(self, access_token, payload):
        """Send message to Slack API"""
        url = 'https://slack.com/api/chat.postMessage'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        result = response.json()
        
        if result.get('ok'):
            return {
                'success': True,
                'data': {
                    'message_ts': result.get('ts'),
                    'channel': result.get('channel'),
                    'permalink': result.get('permalink')
                }
            }
        else:
            return {
                'success': False,
                'error': result.get('error', 'unknown_error')
            }
    
    def _get_user_friendly_error(self, slack_error):
        """Convert Slack error codes to user-friendly messages"""
        error_messages = {
            'not_in_channel': 'Bot is not a member of this channel. Please add the bot to the channel first.',
            'channel_not_found': 'Channel not found. Please check the channel ID or name.',
            'invalid_auth': 'Invalid Slack token. Please check your access token.',
            'token_revoked': 'Slack token has been revoked. Please generate a new token.',
            'missing_scope': 'Missing required permissions. Bot needs chat:write scope.',
            'account_inactive': 'Slack account is inactive.',
            'user_not_found': 'User not found. Please check the user ID.',
            'is_archived': 'Cannot send message to archived channel.',
            'msg_too_long': 'Message text is too long (max 4000 characters).',
            'no_text': 'Message text is required.',
            'rate_limited': 'Rate limited. Please try again later.',
            'fatal_error': 'Slack API fatal error. Please try again later.'
        }
        
        return error_messages.get(
            slack_error, 
            f'Slack API error: {slack_error}'
        )
 
 
class JoinSlackChannelView(APIView):
    """Join a Slack channel"""
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            access_token = request.data.get('access_token')
            channel = request.data.get('channel')

            # Validation
            if not access_token:
                return Response({
                    'success': False,
                    'message': 'Slack access token is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            if not channel:
                return Response({
                    'success': False,
                    'message': 'Channel ID or name is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Call Slack API to join channel
            response = self._join_channel(access_token, channel)

            if response['success']:
                return Response({
                    'success': True,
                    'message': 'Joined channel successfully',
                    'data': response['data']
                }, status=status.HTTP_200_OK)
            else:
                error_message = self._get_user_friendly_error(response['error'])
                return Response({
                    'success': False,
                    'message': error_message,
                    'slack_error': response['error']
                }, status=status.HTTP_400_BAD_REQUEST)

        except requests.RequestException as e:
            logger.error(f"Slack API request error: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to connect to Slack API'
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        
        except Exception as e:
            logger.error(f"Slack join channel error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _join_channel(self, access_token, channel):
        """Call Slack conversations.join API"""
        url = 'https://slack.com/api/conversations.join'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        payload = {'channel': channel}

        response = requests.post(url, headers=headers, json=payload, timeout=30)
        result = response.json()

        if result.get('ok'):
            return {
                'success': True,
                'data': {
                    'channel': result.get('channel', {}).get('id'),
                    'name': result.get('channel', {}).get('name')
                }
            }
        else:
            return {
                'success': False,
                'error': result.get('error', 'unknown_error')
            }

    def _get_user_friendly_error(self, slack_error):
        """Convert Slack error codes to user-friendly messages"""
        error_messages = {
            'method_not_supported_for_channel_type': 'Cannot join this type of channel. Private channels require the bot to be invited manually.',
            'already_in_channel': 'Bot is already a member of this channel.',
            'channel_not_found': 'Channel not found. Please check the channel ID or name.',
            'invalid_auth': 'Invalid Slack token. Please check your access token.',
            'token_revoked': 'Slack token has been revoked. Please generate a new token.',
            'missing_scope': 'Missing required permissions. Bot needs channels:join scope.',
            'is_archived': 'Cannot join archived channels.',
            'restricted_action': 'Bot cannot join this channel due to restrictions.',
        }

        return error_messages.get(slack_error, f'Slack API error: {slack_error}')       
class CreateSlackChannelView(APIView):
    """Create new Slack channels"""
    authentication_classes = []
    permission_classes = [AllowAny]
    
    def post(self, request):
        try:
            access_token = request.data.get('access_token')
            name = request.data.get('name')
            is_private = request.data.get('is_private', False)
            
            if not access_token or not name:
                return Response({
                    'success': False,
                    'message': 'Access token and channel name are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Create channel
            url = 'https://slack.com/api/conversations.create'
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            payload = {
                'name': name,
                'is_private': is_private
            }
            
            response = requests.post(url, headers=headers, json=payload)
            result = response.json()
            
            if result.get('ok'):
                channel_info = result.get('channel', {})
                return Response({
                    'success': True,
                    'message': 'Channel created successfully',
                    'data': {
                        'channel_id': channel_info.get('id'),
                        'channel_name': channel_info.get('name'),
                        'is_private': channel_info.get('is_private'),
                        'created': channel_info.get('created')
                    }
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'message': f"Failed to create channel: {result.get('error', 'Unknown error')}"
                }, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.error(f"Slack channel creation error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred while creating channel: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UpdateSlackChannelView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def patch(self, request, *args, **kwargs):
        return self._update_channel(request)

    def post(self, request, *args, **kwargs):
        # Allow POST as alias for PATCH
        return self._update_channel(request)

    def _update_channel(self, request):
        serializer = UpdateSlackChannelSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        access_token = serializer.validated_data['access_token']
        channel_id = serializer.validated_data['channel_id']
        new_name = serializer.validated_data['name']

        url = 'https://slack.com/api/conversations.rename'
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }
        payload = {'channel': channel_id, 'name': new_name}

        response = requests.post(url, headers=headers, json=payload)
        result = response.json()

        if result.get('ok'):
            channel_info = result.get('channel', {})
            return Response({
                'success': True,
                'message': 'Channel renamed successfully',
                'data': {
                    'channel_id': channel_info.get('id'),
                    'channel_name': channel_info.get('name')
                }
            }, status=status.HTTP_200_OK)
        else:
            return Response({
                'success': False,
                'message': f"Failed to rename channel: {result.get('error', 'Unknown error')}"
            }, status=status.HTTP_400_BAD_REQUEST)

class DeleteSlackChannelView(APIView):
    """Archive (delete) Slack channel"""
    authentication_classes = []
    permission_classes = [AllowAny]

    def delete(self, request):
        serializer = DeleteSlackChannelSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        access_token = serializer.validated_data['access_token']
        channel_id = serializer.validated_data['channel_id']

        try:
            url = 'https://slack.com/api/conversations.archive'
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            payload = {
                'channel': channel_id
            }

            response = requests.post(url, headers=headers, json=payload)
            result = response.json()

            if result.get('ok'):
                return Response({
                    'success': True,
                    'message': 'Channel archived (deleted) successfully'
                }, status=status.HTTP_200_OK)
            else:
                return Response({
                    'success': False,
                    'message': f"Failed to delete channel: {result.get('error', 'Unknown error')}"
                }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"Slack channel delete error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred while deleting channel: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
class ListSlackChannelsView(APIView):
    """List Slack channels using bot token from Authorization header"""
    authentication_classes = []
    permission_classes = [AllowAny]
    def get(self, request):
        try:
            # Get Slack bot token from Authorization header
            auth_header = request.headers.get('Authorization', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    'success': False,
                    'message': 'Authorization header with Bearer token is required'
                }, status=400)
            
            access_token = auth_header.replace('Bearer ', '').strip()
            if not access_token:
                return Response({
                    'success': False,
                    'message': 'Slack bot token is required'
                }, status=400)

            # Optional query params
            exclude_archived = request.query_params.get('exclude_archived', 'true').lower() == 'true'
            types = request.query_params.get('types', 'public_channel,private_channel')

            # Call Slack API
            url = 'https://slack.com/api/conversations.list'
            headers = {'Authorization': f'Bearer {access_token}'}
            params = {
                'exclude_archived': exclude_archived,
                'types': types
            }

            response = requests.get(url, headers=headers, params=params)
            result = response.json()

            if not result.get('ok'):
                return Response({
                    'success': False,
                    'message': f"Failed to retrieve channels: {result.get('error', 'Unknown error')}"
                }, status=400)

            channels = result.get('channels', [])
            return Response({
                'success': True,
                'message': 'Channels retrieved successfully',
                'data': {
                    'channels': [
                        {
                            'id': channel.get('id'),
                            'name': channel.get('name'),
                            'is_private': channel.get('is_private'),
                            'is_member': channel.get('is_member'),
                            'num_members': channel.get('num_members'),
                            'created': channel.get('created')
                        }
                        for channel in channels
                    ]
                }
            }, status=200)

        except Exception as e:
            logger.error(f"Slack channels list error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred while retrieving channels: {str(e)}'
            }, status=500) 

@api_view(['GET'])
@permission_classes([])
def slack_oauth_url(request):
    """Generate Slack OAuth URL for frontend"""
    try:
        redirect_uri = request.GET.get('redirect_uri', 'http://localhost:3000/slack/callback')
        
        params = {
            'client_id': settings.SLACK_CLIENT_ID,
            'scope': 'channels:read,channels:write,chat:write,users:read,users:read.email',
            'redirect_uri': redirect_uri,
            'response_type': 'code'
        }
        
        auth_url = f"https://slack.com/oauth/v2/authorize?{urlencode(params)}"
        
        return JsonResponse({
            'success': True,
            'auth_url': auth_url
        })
        
    except Exception as e:
        logger.error(f"Slack OAuth URL generation error: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Error generating OAuth URL: {str(e)}'
        }, status=500)
        
        
class AddUserToSlackChannelView(APIView):
    """Invite a user to a Slack channel"""
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = AddUserToSlackChannelSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                "success": False,
                "message": "Validation failed",
                "errors": serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        access_token = serializer.validated_data["access_token"]
        channel = serializer.validated_data["channel"]
        user_id = serializer.validated_data["user_id"]

        try:
            response = self._add_user(access_token, channel, user_id)

            if response["success"]:
                return Response({
                    "success": True,
                    "message": "User added to channel successfully",
                    "data": response["data"]
                }, status=status.HTTP_200_OK)
            else:
                error_message = self._get_user_friendly_error(response["error"])
                return Response({
                    "success": False,
                    "message": error_message,
                    "slack_error": response["error"]
                }, status=status.HTTP_400_BAD_REQUEST)

        except requests.RequestException as e:
            logger.error(f"Slack API request error: {str(e)}")
            return Response({
                "success": False,
                "message": "Failed to connect to Slack API"
            }, status=status.HTTP_503_SERVICE_UNAVAILABLE)

        except Exception as e:
            logger.error(f"Slack invite user error: {str(e)}")
            return Response({
                "success": False,
                "message": f"An error occurred: {str(e)}"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _add_user(self, access_token, channel, user_id):
        """Call Slack conversations.invite API"""
        url = "https://slack.com/api/conversations.invite"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {
            "channel": channel,
            "users": user_id  # Can be multiple, comma-separated
        }

        response = requests.post(url, headers=headers, json=payload, timeout=30)
        result = response.json()

        if result.get("ok"):
            return {
                "success": True,
                "data": result.get("channel")
            }
        else:
            return {
                "success": False,
                "error": result.get("error", "unknown_error")
            }

    def _get_user_friendly_error(self, slack_error):
        """Map Slack errors to user-friendly messages"""
        error_messages = {
            "already_in_channel": "User is already a member of this channel.",
            "channel_not_found": "Channel not found. Please check the channel ID.",
            "user_not_found": "User not found. Please check the user ID.",
            "cant_invite_self": "You cannot invite the bot itself.",
            "not_in_channel": "The bot must be in the channel before inviting users.",
            "not_authed": "Invalid or missing authentication token.",
            "missing_scope": "Missing required scope (channels:manage or groups:write).",
            "restricted_action": "Bot is restricted from inviting users to this channel.",
        }
        return error_messages.get(slack_error, f"Slack API error: {slack_error}")
    
    
class SlackUserListView(APIView):
    """
    Fetch all Slack users with their IDs
    """
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        access_token = request.data.get("access_token")
        if not access_token:
            return Response({"success": False, "message": "Access token is required"}, status=400)

        url = "https://slack.com/api/users.list"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers)
        data = response.json()

        if not data.get("ok"):
            return Response({"success": False, "error": data.get("error")}, status=400)

        # Return only user IDs, names, and emails
        users = []
        for member in data.get("members", []):
            users.append({
                "id": member.get("id"),
                "name": member.get("name"),
                "real_name": member.get("real_name"),
                "email": member.get("profile", {}).get("email")
            })

        return Response({"success": True, "users": users}, status=200)


class SlackInviteUserView(APIView):
    """
    Invite a user to a Slack channel
    """
    authentication_classes = []
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = SlackInviteUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        access_token = serializer.validated_data["access_token"]
        channel = serializer.validated_data["channel"]
        users = ",".join(serializer.validated_data["users"])  # multiple users supported

        url = "https://slack.com/api/conversations.invite"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {"channel": channel, "users": users}

        response = requests.post(url, headers=headers, json=payload)
        data = response.json()

        if not data.get("ok"):
            return Response({"success": False, "error": data.get("error")}, status=400)

        return Response({"success": True, "data": data}, status=200)
    

# -------------------- JIRA OAUTH CALLBACK --------------------
class JiraOAuthCallbackView(APIView):
    """Handle JIRA OAuth callback - exchanges authorization code for access token."""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            code = request.GET.get('code')
            state = request.GET.get('state')

            if not code:
                return Response({'error': 'Authorization code not provided'},
                                status=status.HTTP_400_BAD_REQUEST)

            # Verify state (optional in dev)
            stored_state = request.session.get('jira_oauth_state')
            if stored_state and state != stored_state:
                logger.warning(f"State mismatch: stored={stored_state}, received={state}")
                # In production, enforce this check
                # return Response({'error': 'Invalid state parameter'}, status=status.HTTP_400_BAD_REQUEST)

            # Exchange code for token
            token_data = {
                'grant_type': 'authorization_code',
                'client_id': settings.JIRA_CLIENT_ID,
                'client_secret': settings.JIRA_CLIENT_SECRET,
                'code': code,
                'redirect_uri': settings.JIRA_REDIRECT_URI
            }

            logger.info(f"Exchanging code for token at {settings.JIRA_TOKEN_URL}")

            token_response = requests.post(
                settings.JIRA_TOKEN_URL,
                json=token_data,
                headers={'Content-Type': 'application/json'}
            )

            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_response.text}")
                return Response({
                    'error': 'Failed to exchange code for token',
                    'detail': token_response.text
                }, status=status.HTTP_400_BAD_REQUEST)

            tokens = token_response.json()

            # Clean up session
            if 'jira_oauth_state' in request.session:
                del request.session['jira_oauth_state']

            return Response({
                'message': 'JIRA OAuth successful',
                'access_token': tokens.get('access_token'),
                'refresh_token': tokens.get('refresh_token', ''),
                'expires_in': tokens.get('expires_in'),
                'token_type': tokens.get('token_type'),
                'scope': tokens.get('scope', '')
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("JIRA OAuth callback failed")
            return Response({'error': 'OAuth callback failed', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- JIRA OAUTH URL --------------------
class JiraOAuthUrlView(APIView):
    """Generate JIRA OAuth URL"""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            # Generate secure state
            state = secrets.token_urlsafe(32)

            # Store in session
            request.session['jira_oauth_state'] = state
            request.session.save()

            params = {
                'audience': 'api.atlassian.com',
                'client_id': settings.JIRA_CLIENT_ID,
                'scope': ' '.join(settings.JIRA_SCOPES),
                'redirect_uri': settings.JIRA_REDIRECT_URI,
                'state': state,
                'response_type': 'code',
                'prompt': 'consent'
            }

            auth_url = f"{settings.JIRA_AUTH_URL}?{urlencode(params)}"
            logger.info(f"Generated JIRA OAuth URL: {auth_url}")

            return Response({
                'auth_url': auth_url,
                'state': state,
                'redirect_uri': settings.JIRA_REDIRECT_URI
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Failed to generate JIRA OAuth URL")
            return Response({'error': 'Failed to generate OAuth URL', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- JIRA OAUTH EXCHANGE --------------------
class JiraOAuthView(APIView):
    """Exchange authorization code for access token"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            serializer = JiraOAuthSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            code = serializer.validated_data['code']

            token_data = {
                'grant_type': 'authorization_code',
                'client_id': settings.JIRA_CLIENT_ID,
                'client_secret': settings.JIRA_CLIENT_SECRET,
                'code': code,
                'redirect_uri': settings.JIRA_REDIRECT_URI
            }

            token_response = requests.post(
                settings.JIRA_TOKEN_URL,
                json=token_data,
                headers={'Content-Type': 'application/json'}
            )

            if token_response.status_code != 200:
                return Response({
                    'error': 'Failed to exchange code for token',
                    'detail': token_response.text
                }, status=status.HTTP_400_BAD_REQUEST)

            tokens = token_response.json()

            # Fetch user info
            user_response = requests.get(
                'https://api.atlassian.com/me',
                headers={'Authorization': f"Bearer {tokens['access_token']}"}
            )

            if user_response.status_code != 200:
                return Response({'error': 'Failed to fetch user info'},
                                status=status.HTTP_400_BAD_REQUEST)

            user_data = user_response.json()

            # Create or update user
            from .models import User
            user, created = User.objects.get_or_create(
                email=user_data['email'],
                defaults={
                    'username': user_data['email'],
                    'full_name': user_data.get('name', ''),
                    'is_active': True,
                    'login_provider': 'jira',
                    'jira_access_token': tokens['access_token'],
                    'jira_refresh_token': tokens.get('refresh_token', '')
                }
            )

            if not created:
                user.login_provider = 'jira'
                user.jira_access_token = tokens['access_token']
                user.jira_refresh_token = tokens.get('refresh_token', '')
                user.save()

            # Generate JWT
            refresh = RefreshToken.for_user(user)

            return Response({
                'message': 'JIRA OAuth successful',
                'user': {
                    'id': str(user.id),
                    'email': user.email,
                    'name': user.full_name,
                    'account_id': user_data.get('account_id', '')
                },
                'jira_tokens': tokens,
                'jwt_tokens': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("JIRA OAuth exchange failed")
            return Response({'error': 'OAuth failed', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- VALIDATE TOKEN --------------------
class JiraValidateTokenView(APIView):
    """Validate JIRA access token"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            access_token = request.data.get('access_token')
            if not access_token:
                return Response({'error': 'Access token is required'},
                                status=status.HTTP_400_BAD_REQUEST)

            response = requests.get(
                'https://api.atlassian.com/me',
                headers={'Authorization': f'Bearer {access_token}'}
            )

            if response.status_code == 200:
                return Response({'valid': True, 'user': response.json()},
                                status=status.HTTP_200_OK)
            return Response({'valid': False, 'error': 'Invalid or expired token'},
                            status=status.HTTP_401_UNAUTHORIZED)

        except Exception as e:
            logger.exception("Token validation failed")
            return Response({'error': 'Token validation failed', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- GET JIRA USER --------------------
class JiraGetUserView(APIView):
    """Fetch JIRA user profile"""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            if not access_token:
                return Response({'error': 'JIRA access token is required'},
                                status=status.HTTP_400_BAD_REQUEST)

            response = requests.get(
                'https://api.atlassian.com/me',
                headers={'Authorization': f'Bearer {access_token}'}
            )

            if response.status_code != 200:
                return Response({'error': 'Failed to fetch user info'},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({'user': response.json()}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Failed to get JIRA user info")
            return Response({'error': 'Failed to get user info', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- LIST PROJECTS --------------------
class JiraListProjectsView(APIView):
    """List accessible JIRA projects"""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'},
                                status=status.HTTP_400_BAD_REQUEST)

            response = requests.get(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json'
                }
            )

            if response.status_code != 200:
                return Response({'error': 'Failed to fetch projects'},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({'projects': response.json()}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Error listing JIRA projects")
            return Response({'error': 'Failed to list projects', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class JiraCreateProjectView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            project_data = request.data
            payload = {
                "key": project_data["key"],           # 2-10 uppercase letters
                "name": project_data["name"],
                "projectTypeKey": project_data.get("projectTypeKey", "software"),
                "projectTemplateKey": project_data.get(
                    "projectTemplateKey",
                    "com.pyxis.greenhopper.jira:gh-simplified-agility-scrum"
                ),
                "description": project_data.get("description", "Created via API"),
                "leadAccountId": project_data["leadAccountId"],  # required
                "assigneeType": "PROJECT_LEAD"
            }

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project"
            response = requests.post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }
            )

            return Response(response.json(), status=response.status_code)
        except Exception as e:
            logger.error(f"Project create failed: {str(e)}")
            return Response({'error': str(e)}, status=500)


# -------------------- CREATE UPDATE DELETE LIST ISSUE --------------------
class JiraCreateIssueView(APIView):
    """Create a JIRA issue"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer = JiraIssueSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            issue_data = {
                'fields': {
                    'project': {'key': serializer.validated_data['project_key']},
                    'summary': serializer.validated_data['summary'],
                    'description': {
                        'type': 'doc',
                        'version': 1,
                        'content': [{
                            'type': 'paragraph',
                            'content': [{
                                'type': 'text',
                                'text': serializer.validated_data.get('description', '')
                            }]
                        }]
                    },
                    'issuetype': {'name': serializer.validated_data.get('issue_type', 'Task')}
                }
            }

            response = requests.post(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue',
                json=issue_data,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            )

            if response.status_code not in [200, 201]:
                return Response({'error': 'Failed to create issue', 'detail': response.text},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({'message': 'Issue created', 'issue': response.json()},
                            status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.exception("Failed to create JIRA issue")
            return Response({'error': 'Failed to create issue', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class JiraGetIssueView(APIView):
    permission_classes = [AllowAny]

    def get(self, request, issue_key):
        access_token = request.headers.get('Jira-Access-Token')
        cloud_id = request.headers.get('Jira-Cloud-Id')

        url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}"
        response = requests.get(
            url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
        )

        return Response(response.json(), status=response.status_code)
    

class JiraUpdateIssueView(APIView):
    permission_classes = [AllowAny]

    def patch(self, request, issue_key):
        access_token = request.headers.get('Jira-Access-Token')
        cloud_id = request.headers.get('Jira-Cloud-Id')
        payload = {"fields": request.data}

        url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}"
        response = requests.put(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        )

        return Response(
            {"message": " Issue Update successfully" if response.status_code == 204 else response.json()},
            status=response.status_code
        )

class JiraDeleteIssueView(APIView):
    permission_classes = [AllowAny]

    def delete(self, request, issue_key):
        access_token = request.headers.get('Jira-Access-Token')
        cloud_id = request.headers.get('Jira-Cloud-Id')

        url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}"
        response = requests.delete(
            url,
            headers={"Authorization": f"Bearer {access_token}"}
        )

        return Response(
            {"message": "Issue Delete successfully" if response.status_code == 204 else response.json()},
            status=response.status_code
        )

class JiraSearchIssuesView(APIView):
    """Search issues via JQL"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')
            jql = request.GET.get('jql', 'order by created DESC')

            if not access_token or not cloud_id:
                return Response({'error': 'Missing Jira headers'}, status=400)

            response = requests.get(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/search',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json'
                },
                params={'jql': jql}
            )

            if response.status_code != 200:
                return Response({'error': 'Failed to search issues', 'detail': response.text}, status=400)

            return Response(response.json(), status=200)

        except Exception as e:
            return Response({'error': 'Search failed', 'detail': str(e)}, status=500)


class JiraAssignIssueView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, issue_key):
        access_token = request.headers.get('Jira-Access-Token')
        cloud_id = request.headers.get('Jira-Cloud-Id')
        account_id = request.data.get('account_id')

        url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/assignee"
        payload = {"accountId": account_id}

        response = requests.put(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }
        )

        return Response(
            {"message": "Assign successfully" if response.status_code == 204 else response.json()},
            status=response.status_code
        )


# -------------------- GET RESOURCES --------------------
class JiraGetResourcesView(APIView):
    """Fetch accessible JIRA resources (cloud IDs)"""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            if not access_token:
                return Response({'error': 'Access token is required'},
                                status=status.HTTP_400_BAD_REQUEST)

            response = requests.get(
                'https://api.atlassian.com/oauth/token/accessible-resources',
                headers={'Authorization': f'Bearer {access_token}'}
            )

            if response.status_code != 200:
                return Response({'error': 'Failed to get resources'},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({'resources': response.json()}, status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Failed to get resources")
            return Response({'error': 'Failed to get resources', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- ADD COMMENT --------------------
class JiraAddCommentView(APIView):
    """Add a comment to JIRA issue"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'},
                                status=status.HTTP_400_BAD_REQUEST)

            serializer = JiraCommentSerializer(data=request.data)
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            issue_key = serializer.validated_data['issue_key']
            comment_text = serializer.validated_data['comment']

            comment_data = {
                'body': {
                    'type': 'doc',
                    'version': 1,
                    'content': [{
                        'type': 'paragraph',
                        'content': [{
                            'type': 'text',
                            'text': comment_text
                        }]
                    }]
                }
            }

            response = requests.post(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/comment',
                json=comment_data,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }
            )

            if response.status_code not in [200, 201]:
                return Response({'error': 'Failed to add comment', 'detail': response.text},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response({'message': 'Comment added', 'comment': response.json()},
                            status=status.HTTP_201_CREATED)

        except Exception as e:
            logger.exception("Failed to add JIRA comment")
            return Response({'error': 'Failed to add comment', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SlackEventsView(APIView):
    """
    Receives Slack event callbacks.
    Handles: url_verification, channel_created/rename/deleted/archive/unarchive,
             member_joined_channel, member_left_channel.
    Verifies requests using SLACK_SIGNING_SECRET.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        if not self._verify_signature(request):
            return Response({"error": "Invalid signature"}, status=status.HTTP_403_FORBIDDEN)

        payload = request.data
        event_type = payload.get("type")

        # URL verification challenge
        if event_type == "url_verification":
            return Response({"challenge": payload.get("challenge")})

        # Handle event callbacks
        if event_type == "event_callback":
            event = payload.get("event", {})
            self._handle_event(event)

        return Response({"ok": True})

    def _verify_signature(self, request):
        signing_secret = getattr(settings, "SLACK_SIGNING_SECRET", "")
        if not signing_secret:
            return True  # skip verification if not configured
        timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
        signature = request.headers.get("X-Slack-Signature", "")
        # Reject requests older than 5 minutes
        try:
            if abs(time.time() - int(timestamp)) > 300:
                return False
        except (ValueError, TypeError):
            return False
        body = request.body.decode("utf-8")
        base = f"v0:{timestamp}:{body}"
        computed = "v0=" + hmac.new(
            signing_secret.encode(), base.encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(computed, signature)

    def _handle_event(self, event):
        from users_details.models import UserDetail
        etype = event.get("type")

        if etype == "channel_created":
            logger.info(f"Slack channel_created: {event.get('channel', {}).get('name')}")

        elif etype == "channel_rename":
            ch = event.get("channel", {})
            new_id = ch.get("id")
            new_name = ch.get("name")
            for ud in UserDetail.objects.filter(slack_channel_ids__contains=new_id):
                logger.info(f"Slack channel renamed to {new_name}, updated UserDetail {ud._id}")

        elif etype in ("channel_deleted", "channel_archive"):
            ch_id = event.get("channel")
            logger.info(f"Slack channel {etype}: {ch_id}")
            for ud in UserDetail.objects.all():
                ids = ud.slack_channel_ids or []
                if ch_id in ids:
                    ids.remove(ch_id)
                    ud.slack_channel_ids = ids
                    ud.save()

        elif etype == "channel_unarchive":
            logger.info(f"Slack channel unarchived: {event.get('channel')}")

        elif etype == "member_joined_channel":
            logger.info(f"Slack member {event.get('user')} joined {event.get('channel')}")

        elif etype == "member_left_channel":
            logger.info(f"Slack member {event.get('user')} left {event.get('channel')}")