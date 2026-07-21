from django.forms import ValidationError
from .renderers import UserRenderer
from rest_framework import status, generics, permissions
from rest_framework.renderers import BaseRenderer, JSONRenderer
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from rest_framework import serializers
from django.contrib.auth import login, get_user_model
from .models import User
from django.apps import apps
from django.contrib.auth.hashers import make_password
from django.shortcuts import redirect
from django.utils import timezone
import requests

REQUEST_TIMEOUT_SECONDS = 15

def _http_get(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.get(url, timeout=timeout, **kwargs)

def _http_post(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.post(url, timeout=timeout, **kwargs)

def _http_put(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.put(url, timeout=timeout, **kwargs)

def _http_delete(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.delete(url, timeout=timeout, **kwargs)

def _http_patch(url, **kwargs):
    timeout = kwargs.pop("timeout", REQUEST_TIMEOUT_SECONDS)
    return requests.patch(url, timeout=timeout, **kwargs)
import os
import secrets
import traceback
import json
import time
import threading
import re
import hashlib
import hmac
from urllib.parse import urljoin, quote
import logging
import uuid
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect, JsonResponse
from urllib.parse import urlencode
import secrets
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
    JiraCommentSerializer,
    UserMemberLoginSerializer,
    UserForgotPasswordSerializer,
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


# Team Member Login View (email + recaptcha only)
class UserMemberLoginView(generics.GenericAPIView):
    serializer_class = UserMemberLoginSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data["user"]
        user_detail = serializer.validated_data["user_detail"]

        user.last_login = timezone.now()
        user.save(update_fields=["last_login"])

        refresh = RefreshToken.for_user(user)

        return Response({
            "message": "Login successful",
            "user": {
                "id": str(user.id),
                "email": user_detail.email,
                "first_name": user_detail.first_name,
                "last_name": user_detail.last_name,
                "user_type": user_detail.user_type,
                "Member_role": user_detail.Member_role,
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

        # Store OTP + PASSWORD in DB so all Gunicorn workers can access it.
        # Replaces cache.set (LocMemCache is per-process — breaks with multiple workers).
        otp = str(secrets.randbelow(900000) + 100000)
        from .models import SignupOTPSession
        SignupOTPSession.objects.update_or_create(
            email=email,
            defaults={'otp': otp, 'password': password, 'created_at': timezone.now()}
        )

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

        # Get OTP session from DB (works across all Gunicorn workers)
        from .models import SignupOTPSession
        try:
            session = SignupOTPSession.objects.get(email=email)
        except SignupOTPSession.DoesNotExist:
            return Response({"error": "No signup session found. Please start again."}, status=400)

        # Check 5-minute expiry
        from django.utils import timezone as tz
        age_seconds = (tz.now() - session.created_at).total_seconds()
        if age_seconds > 300:
            # Use queryset delete for Djongo compatibility (model instance pk can be None)
            SignupOTPSession.objects.filter(email=email).delete()
            return Response({"error": "OTP has expired. Please start again."}, status=400)

        if session.otp != str(otp):
            return Response({"error": "Invalid OTP"}, status=400)

        # OTP valid → create admin user
        try:
            user = User.objects.create_user(
                email=email,
                password=session.password,
                is_active=True,
                is_staff=True,
                is_superuser=False
            )
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            return Response({"error": "Failed to create account"}, status=500)

        # Delete session immediately after successful verification.
        # Use queryset delete for Djongo compatibility (model instance pk can be None).
        SignupOTPSession.objects.filter(email=email).delete()

        # Generate tokens
        refresh = RefreshToken.for_user(user)

        # Send welcome email
        try:
            Util.send_admin_welcome_email(user.email)
        except Exception as e:
            logger.warning("Welcome email send failed for %s: %s", user.email, e)

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

            reset_link = f"https://vaptfix.ai/reset-password/{uid}/{token}/"

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

# USER MEMBER FORGOT PASSWORD VIEW
class UserForgotPasswordView(generics.GenericAPIView):
    serializer_class = UserForgotPasswordSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        from django.utils.http import urlsafe_base64_encode
        from django.utils.encoding import force_bytes
        from django.contrib.auth.tokens import PasswordResetTokenGenerator
        from django.contrib.auth import get_user_model

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        User = get_user_model()

        # Get or create Django User for this team member
        user, created = User.objects.get_or_create(
            email=email,
            defaults={"is_active": True}
        )
        if created:
            user.set_unusable_password()
            user.save()

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = PasswordResetTokenGenerator().make_token(user)

        reset_link = f"https://vaptfix.ai/auth?mode=set-password&uid={uid}&token={token}"

        # Load logo
        import os, base64
        logo_b64 = None
        logo_path = os.path.join(str(settings.BASE_DIR), "users", "static", "users", "logo.png")
        if os.path.exists(logo_path):
            with open(logo_path, "rb") as f:
                logo_b64 = base64.b64encode(f.read()).decode("utf-8")

        if logo_b64:
            logo_html = f'<img src="data:image/png;base64,{logo_b64}" alt="VAPTFIX" style="height:60px;" />'
        else:
            logo_html = '<h2 style="color:#1a73e8; margin:0;">VAPTFIX</h2>'

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"></head>
        <body style="margin:0; padding:0; background-color:#f4f6f8; font-family:Arial, sans-serif;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f8; padding:40px 0;">
            <tr>
              <td align="center">
                <table width="600" cellpadding="0" cellspacing="0"
                       style="background:#ffffff; border-radius:8px; overflow:hidden;
                              box-shadow:0 2px 8px rgba(0,0,0,0.08);">
                  <tr>
                    <td style="background-color:#ffffff; padding:30px 40px; text-align:center;
                                border-bottom:1px solid #e8eaed;">
                      {logo_html}
                    </td>
                  </tr>
                  <tr>
                    <td style="padding:40px;">
                      <h2 style="color:#1a1a2e; margin:0 0 8px 0;">Reset Your Password</h2>
                      <hr style="border:none; border-top:2px solid #1a73e8; margin:0 0 24px 0; width:60px; text-align:left;" />
                      <p style="color:#444; font-size:15px; line-height:1.6;">
                        We received a request to reset your VAPTFIX account password.
                        Click the button below to set a new password:
                      </p>
                      <div style="text-align:center; margin:28px 0;">
                        <a href="{reset_link}"
                           style="background-color:#1a73e8; color:#ffffff; padding:14px 32px;
                                  text-decoration:none; border-radius:6px; font-size:15px;
                                  font-weight:bold; display:inline-block;">
                          Reset Password
                        </a>
                      </div>
                      <p style="color:#444; font-size:14px; line-height:1.6;">
                        This link will expire after a limited time. If you did not request a
                        password reset, please ignore this email.
                      </p>
                      <hr style="border:none; border-top:1px solid #e8eaed; margin:24px 0;" />
                      <p style="color:#444; font-size:14px; margin:0;">
                        Best regards,<br/>
                        <strong>Security Management Team</strong><br/>
                        VAPTFIX
                      </p>
                    </td>
                  </tr>
                  <tr>
                    <td style="background-color:#f4f6f8; padding:20px 40px; text-align:center;">
                      <p style="color:#888; font-size:12px; margin:0;">
                        &copy; 2026 VAPTFIX. All rights reserved.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
        """

        data = {
            "to_email": email,
            "subject": "Reset Your VAPTFIX Password",
            "html_content": html_content,
            "inline_logo_b64": logo_b64,
        }

        success, _ = Util.send_mail(data)
        if success:
            return Response({"msg": "Password set link sent. Please check your email."}, status=status.HTTP_200_OK)
        return Response({"error": "Failed to send email"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# USER MEMBER SET PASSWORD VIEW
class UserSetPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uid, token):
        serializer = UserPasswordResetSerializer(
            data=request.data,
            context={"uid": uid, "token": token}
        )
        try:
            serializer.is_valid(raise_exception=True)
        except serializers.ValidationError as exc:
            errors = exc.detail
            detail_message = "Unable to set password."

            if isinstance(errors, dict):
                first_error = next(iter(errors.values()), None)
                if isinstance(first_error, list) and first_error:
                    detail_message = str(first_error[0])
                elif first_error is not None:
                    detail_message = str(first_error)
            elif isinstance(errors, list) and errors:
                detail_message = str(errors[0])
            elif errors:
                detail_message = str(errors)

            return Response(
                {
                    "msg": "Failed to set password",
                    "detail": detail_message,
                    "errors": errors,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Send post-password welcome email
        try:
            from django.utils.http import urlsafe_base64_decode
            from django.utils.encoding import smart_str
            from users_details.models import UserDetail
            from users_details.views import UserDetailCreateView

            user_id = smart_str(urlsafe_base64_decode(uid))
            User = get_user_model()
            user = User.objects.filter(id=user_id).first()
            if user:
                user_detail = UserDetail.objects.filter(email=user.email).first()
                if user_detail:
                    view = UserDetailCreateView()
                    view.send_post_password_welcome_email(
                        email=user.email,
                        first_name=user_detail.first_name or "",
                        last_name=user_detail.last_name or "",
                        roles=user_detail.Member_role or [],
                    )
        except Exception:
            logger.exception("[UserSetPassword] Error sending post-password welcome email")

        return Response({"msg": "Your password has been set successfully. You can now log in."}, status=status.HTTP_200_OK)


# LOGOUT VIEW
@api_view(["POST"])
@permission_classes([permissions.IsAuthenticated])
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
                f"&scope=https://graph.microsoft.com/User.Read Team.ReadBasic.All TeamSettings.Read.All Channel.ReadBasic.All ChannelMessage.Send GroupMember.ReadWrite.All TeamMember.Read.All offline_access openid email profile"
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

            token_response = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, headers=headers, timeout=15)
            token_data = token_response.json()

            # Extract tenant_id from id_token JWT (tid claim)
            tenant_id = ""
            id_token = token_data.get("id_token", "")
            if id_token:
                try:
                    payload_part = id_token.split(".")[1]
                    payload_part += "=" * (4 - len(payload_part) % 4)
                    jwt_payload = json.loads(base64.urlsafe_b64decode(payload_part))
                    tenant_id = jwt_payload.get("tid", "")
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

            if token_response.status_code != 200:
                logger.error(f"Token exchange failed: {token_data}")
                return JsonResponse({"error": "Token exchange failed", "details": token_data},
                                    status=token_response.status_code)

            access_token = token_data.get("access_token")
            if not access_token:
                return JsonResponse({"error": "No access token returned"}, status=400)

            # ✅ Fetch Microsoft user info
            user_info = _http_get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}, timeout=15
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
            # Use admin_id from query param, else fall back to the authenticated request user
            admin_id = request.GET.get("admin_id")
            if not admin_id and request.user and request.user.is_authenticated:
                admin_id = str(request.user.id)
            state_data = {
                "redirect_uri": frontend_redirect,
                "nonce": secrets.token_urlsafe(8),
                "admin_id": admin_id,
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


def _create_vaptfix_channels(team_id, headers):
    """Create 4 default channels on a provisioned team (safe to call from background thread)."""
    default_channels = ["Patch Management", "Configuration Management", "Network Security", "Architectural Flaws"]
    channels_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels"
    results = []
    for channel_name in default_channels:
        try:
            ch_resp = _http_post(channels_url, headers=headers, json={
                "displayName": channel_name,
                "description": f"{channel_name} channel",
                "membershipType": "standard"
            }, timeout=15)
            ch_data = {}
            try:
                ch_data = ch_resp.json()
            except Exception:
                ch_data = {}
            results.append({
                "channelName": channel_name,
                "channelId": ch_data.get("id"),
                "status": "created" if ch_resp.status_code in (200, 201) else "failed"
            })
        except Exception as e:
            results.append({"channelName": channel_name, "status": "failed", "error": str(e)})
    return results


def _build_teams_tab_urls(team_id, tenant_id=None, channel_id=None, channel_name="General"):
    """Build stable deep links that open the Teams tab (not chat)."""
    if not team_id:
        return {
            "web_url": None,
            "desktop_url": None,
            "web_url_alt": None,
            "general_web_url": None,
            "general_web_url_alt": None,
            "general_desktop_url": None,
        }
    web_url = f"https://teams.cloud.microsoft/l/team/{team_id}/conversations?groupId={team_id}"
    if tenant_id:
        web_url = f"{web_url}&tenantId={tenant_id}"
    web_url_alt = web_url.replace("https://teams.cloud.microsoft/l/team/", "https://teams.cloud.microsoft/_#/l/team/")
    channel_web_url = None
    if channel_id:
        safe_name = quote(channel_name or "General")
        channel_web_url = f"https://teams.cloud.microsoft/l/channel/{channel_id}/{safe_name}?groupId={team_id}"
        if tenant_id:
            channel_web_url = f"{channel_web_url}&tenantId={tenant_id}"
    general_web_url = channel_web_url if ((channel_name or "").strip().lower() == "general" and channel_web_url) else web_url
    if "/l/channel/" in general_web_url:
        general_web_url_alt = general_web_url.replace("https://teams.cloud.microsoft/l/channel/", "https://teams.cloud.microsoft/_#/l/channel/")
    else:
        general_web_url_alt = general_web_url.replace("https://teams.cloud.microsoft/l/team/", "https://teams.cloud.microsoft/_#/l/team/")
    desktop_url = web_url.replace("https://", "msteams://")
    general_desktop_url = general_web_url.replace("https://", "msteams://")
    channel_desktop_url = channel_web_url.replace("https://", "msteams://") if channel_web_url else None
    return {
        "web_url": web_url,
        "web_url_alt": web_url_alt,
        "desktop_url": desktop_url,
        "general_web_url": general_web_url,
        "general_web_url_alt": general_web_url_alt,
        "general_desktop_url": general_desktop_url,
        "channel_web_url": channel_web_url,
        "channel_desktop_url": channel_desktop_url,
    }


def _get_team_channels(team_id, headers):
    channels = []
    if not team_id:
        return channels
    try:
        ch_resp = _http_get(
            f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels",
            headers=headers, timeout=10
        )
        if ch_resp.status_code == 200:
            channels = ch_resp.json().get("value", []) or []
    except Exception:
        logger.warning(f"Unable to fetch channels for team_id={team_id}", exc_info=True)
    return channels


def _pick_general_channel_id(channels):
    for ch in channels or []:
        nm = (ch.get("displayName") or ch.get("channelName") or "").strip().lower()
        if nm == "general":
            return ch.get("id") or ch.get("channelId")
    return None


def _get_vaptfix_team_icon_bytes():
    """
    Resolve VAPTFIX icon bytes from local path first, then logo URL.
    Optional env/settings:
      - VAPTFIX_TEAMS_ICON_PATH: absolute/relative file path
      - VAPTFIX_LOGO_URL: public URL
    """
    icon_path = getattr(settings, "VAPTFIX_TEAMS_ICON_PATH", "") or ""
    logo_url = getattr(settings, "VAPTFIX_LOGO_URL", "") or ""

    try:
        if icon_path:
            resolved = icon_path
            if not os.path.isabs(resolved):
                resolved = os.path.join(settings.BASE_DIR, resolved)
            if os.path.exists(resolved):
                with open(resolved, "rb") as f:
                    return f.read()
    except Exception:
        logger.warning("Failed to read VAPTFIX_TEAMS_ICON_PATH", exc_info=True)

    try:
        if logo_url:
            resp = _http_get(logo_url, timeout=15)
            if resp.status_code == 200 and resp.content:
                return resp.content
    except Exception:
        logger.warning("Failed to fetch VAPTFIX_LOGO_URL for Teams icon", exc_info=True)

    return None


def _png_to_jpeg_bytes(png_bytes):
    """Convert PNG bytes to JPEG bytes. Teams desktop app requires JPEG."""
    try:
        from PIL import Image
        import io
        img = Image.open(io.BytesIO(png_bytes)).convert("RGB")
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=95)
        return buf.getvalue()
    except Exception:
        return None


def _set_vaptfix_team_icon(team_id, access_token):
    """
    Upload team icon as JPEG (required by Teams desktop app).
    Groups endpoint is authoritative for M365-backed Teams.
    """
    if not team_id or not access_token:
        return False

    raw_bytes = _get_vaptfix_team_icon_bytes()
    if not raw_bytes:
        logger.info("VAPTFIX icon skipped: no icon bytes available")
        return False

    icon_path = getattr(settings, "VAPTFIX_TEAMS_ICON_PATH", "") or ""
    if icon_path.lower().endswith((".jpg", ".jpeg")) or raw_bytes[:3] == b'\xff\xd8\xff':
        # Already JPEG — use directly
        icon_bytes = raw_bytes
        content_type = "image/jpeg"
    else:
        # PNG — convert to JPEG for desktop app compatibility
        jpeg_bytes = _png_to_jpeg_bytes(raw_bytes)
        if jpeg_bytes:
            icon_bytes = jpeg_bytes
            content_type = "image/jpeg"
        else:
            icon_bytes = raw_bytes
            content_type = "image/png"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": content_type,
    }

    # Groups endpoint works for both browser and desktop app.
    # Teams endpoint is a secondary fallback.
    candidate_urls = [
        f"https://graph.microsoft.com/v1.0/groups/{team_id}/photo/$value",
        f"https://graph.microsoft.com/v1.0/teams/{team_id}/photo/$value",
    ]
    for url in candidate_urls:
        try:
            resp = _http_put(url, headers=headers, data=icon_bytes, timeout=20)
            if resp.status_code in (200, 201, 204):
                logger.info(f"VAPTFIX team icon updated for team_id={team_id} via {url}")
                return True
            logger.warning(
                f"VAPTFIX icon upload failed for team_id={team_id} url={url} "
                f"status={resp.status_code} body={resp.text[:300]}"
            )
        except Exception:
            logger.warning(f"VAPTFIX icon upload exception for team_id={team_id} url={url}", exc_info=True)

    return False


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
        resp = _http_get(search_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            teams = resp.json().get('value', [])
            for team in teams:
                if team.get('displayName') == 'Vaptfix':
                    team_id = team.get('id')
                    logger.info(f"VAPTFIX team already exists: {team_id}")
                    _set_vaptfix_team_icon(team_id, access_token)
                    # Fetch existing channels
                    channels_result = []
                    try:
                        ch_resp = _http_get(
                            f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels",
                            headers=headers, timeout=10
                        )
                        if ch_resp.status_code == 200:
                            for ch in ch_resp.json().get('value', []):
                                channels_result.append({
                                    "channelName": ch.get("displayName"),
                                    "channelId": ch.get("id"),
                                    "status": "exists"
                                })
                    except Exception as e:
                        logger.warning(f"Error fetching channels: {str(e)}")
                    preferred_channel_id = _pick_general_channel_id(channels_result)
                    if not preferred_channel_id and channels_result:
                        preferred_channel_id = channels_result[0].get("channelId")
                    urls = _build_teams_tab_urls(team_id, channel_id=preferred_channel_id)
                    return {
                        "team_id": team_id,
                        "team_name": "Vaptfix",
                        "status": "already_exists",
                        "teams_url": urls.get("channel_web_url") or urls.get("general_web_url") or urls.get("web_url"),
                        "teams_tab_url": urls.get("general_web_url") or urls.get("web_url"),
                        "teams_tab_url_alt": urls.get("general_web_url_alt") or urls.get("web_url_alt"),
                        "teams_desktop_url": urls.get("channel_desktop_url") or urls.get("general_desktop_url") or urls.get("desktop_url"),
                        "channels": channels_result
                    }
    except Exception as e:
        logger.warning(f"Error checking existing teams: {str(e)}")

    # Step 2: Create VAPTFIX team
    try:
        create_url = "https://graph.microsoft.com/v1.0/teams"
        payload = {
            "template@odata.bind": "https://graph.microsoft.com/v1.0/teamsTemplates('standard')",
            "displayName": "Vaptfix",
            "description": "Vaptfix Security Management Team",
            "visibility": "private",
        }
        resp = _http_post(create_url, headers=headers, json=payload, timeout=30)

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
            # Team provisioning is async — create channels in background to avoid blocking
            if team_id:
                def _bg_create_channels(token, tid, hdrs):
                    for attempt in range(5):
                        time.sleep(10)
                        try:
                            check = _http_get(
                                f"https://graph.microsoft.com/v1.0/teams/{tid}",
                                headers=hdrs, timeout=10
                            )
                            if check.status_code == 200:
                                break
                        except Exception as e:
                            logger.warning("Suppressed error: %s", e)
                        logger.info(f"VAPTFIX team not ready, retry {attempt + 1}/5")
                    _create_vaptfix_channels(tid, hdrs)
                    _set_vaptfix_team_icon(tid, token)

                t = threading.Thread(target=_bg_create_channels, args=(access_token, team_id, headers), daemon=True)
                t.start()
            prov_urls = _build_teams_tab_urls(team_id)
            return {
                "team_id": team_id,
                "team_name": "Vaptfix",
                "status": "provisioning",
                "teams_tab_url": prov_urls.get("general_web_url") or prov_urls.get("web_url"),
                "teams_tab_url_alt": prov_urls.get("general_web_url_alt") or prov_urls.get("web_url_alt"),
                "teams_desktop_url": prov_urls.get("general_desktop_url") or prov_urls.get("desktop_url"),
                "channels": [],
            }
        else:
            logger.error(f"Failed to create VAPTFIX team: {resp.status_code} {resp.text}")
            return {"team_id": None, "team_name": "Vaptfix", "status": "creation_failed", "error": resp.text, "channels": []}

        if not team_id:
            return {"team_id": None, "team_name": "Vaptfix", "status": "creation_failed", "error": "Could not extract team ID", "channels": []}

        # Step 3: Create 4 default channels using the shared helper
        channels_result = _create_vaptfix_channels(team_id, headers)
        _set_vaptfix_team_icon(team_id, access_token)
        all_channels = _get_team_channels(team_id, headers)
        preferred_channel_id = _pick_general_channel_id(all_channels) or _pick_general_channel_id(channels_result)
        if not preferred_channel_id and channels_result:
            preferred_channel_id = channels_result[0].get("channelId")
        urls = _build_teams_tab_urls(team_id, channel_id=preferred_channel_id)

        logger.info(f"VAPTFIX team created: {team_id} with {len([c for c in channels_result if c['status'] == 'created'])} channels")
        return {
            "team_id": team_id,
            "team_name": "Vaptfix",
            "status": "created",
            "teams_url": urls.get("channel_web_url") or urls.get("general_web_url") or urls.get("web_url"),
            "teams_tab_url": urls.get("general_web_url") or urls.get("web_url"),
            "teams_tab_url_alt": urls.get("general_web_url_alt") or urls.get("web_url_alt"),
            "teams_desktop_url": urls.get("channel_desktop_url") or urls.get("general_desktop_url") or urls.get("desktop_url"),
            "channels": channels_result
        }

    except Exception as e:
        logger.error(f"Auto-create VAPTFIX team error: {str(e)}")
        return {"team_id": None, "team_name": "Vaptfix", "status": "error", "error": str(e), "channels": []}


class MicrosoftTeamsCallbackView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
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
            admin_id_from_state = None
            try:
                decoded_state = base64.urlsafe_b64decode(state + "==").decode()
                state_data = json.loads(decoded_state)
                frontend_redirect = state_data.get("redirect_uri", frontend_redirect)
                admin_id_from_state = state_data.get("admin_id")
            except (UnicodeDecodeError, json.JSONDecodeError, Exception):
                # State is a plain string (not base64-encoded JSON), use default redirect
                logger.info(f"State is plain string: {state}, using default redirect: {frontend_redirect}")
            print("Frontend redirect:", frontend_redirect)
            print(f"Admin id from state: {admin_id_from_state}")

            # Exchange code for tokens
            token_payload = {
                "grant_type": "authorization_code",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
            }
            token_response = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
            token_data = token_response.json()
            print("🔑 Token Response:", token_data)

            # Extract tenant_id from id_token JWT (tid claim)
            tenant_id = ""
            id_token = token_data.get("id_token", "")
            if id_token:
                try:
                    payload_part = id_token.split(".")[1]
                    payload_part += "=" * (4 - len(payload_part) % 4)
                    jwt_payload = json.loads(base64.urlsafe_b64decode(payload_part))
                    tenant_id = jwt_payload.get("tid", "")
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

            if token_response.status_code != 200 or "access_token" not in token_data:
                return JsonResponse({
                    "error": "Token exchange failed",
                    "details": token_data
                }, status=400)

            access_token = token_data["access_token"]

            # Get user info from Microsoft Graph
            logger.info(f"[TeamsOAuth] Fetching user info from MS Graph...")
            user_info = _http_get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"}, timeout=15
            ).json()
            logger.info(f"[TeamsOAuth] MS Graph /me response: mail={user_info.get('mail')} upn={user_info.get('userPrincipalName')} displayName={user_info.get('displayName')}")

            email = user_info.get("mail") or user_info.get("userPrincipalName")
            full_name = user_info.get("displayName", "")
            firstname, lastname = (full_name.split(" ", 1) + [""])[:2]
            logger.info(f"[TeamsOAuth] Resolved: email={email} full_name={full_name} admin_id_from_state={admin_id_from_state}")

            # Save user tokens in DB for the correct admin.
            # If admin_id is provided in state, bind tokens to that user record.
            user_data = None
            user = None
            if admin_id_from_state:
                user = User.objects.filter(id=admin_id_from_state).first()
                logger.info(f"[TeamsOAuth] Lookup by admin_id_from_state={admin_id_from_state}: found={bool(user)}")

            if not user and email:
                user, created = User.objects.get_or_create(
                    email=email,
                    defaults={
                        "password": make_password(None),
                        "is_active": True,
                        "is_staff": True,
                        "is_superuser": False,
                        "login_provider": "microsoft_teams",
                    },
                )
                logger.info(f"[TeamsOAuth] get_or_create by email={email}: created={created} user_id={user.id if user else None}")
            else:
                created = False

            if user:
                logger.info(f"[TeamsOAuth] Processing user: id={user.id} email={user.email} login_provider={user.login_provider}")

                # Platform enforcement: block email-only admins (email accounts stay email-only)
                if admin_id_from_state and user.login_provider == "email":
                    logger.warning(f"[TeamsOAuth] Blocked — user {user.email} is email-only login")
                    return JsonResponse({
                        "error": "Your account uses email login. Please sign in with your email and password.",
                        "platform_conflict": True,
                    }, status=400)

                # Platform enforcement: block if admin already connected Slack
                if user.login_provider == "slack" and user.slack_bot_token:
                    logger.warning(f"[TeamsOAuth] Blocked — user {user.email} already connected to Slack")
                    return JsonResponse({
                        "error": "Your account is connected to Slack. Please sign in using Slack.",
                        "platform_conflict": True,
                    }, status=400)

                user.is_staff = True
                user.login_provider = 'microsoft_teams'
                user.ms_access_token = access_token
                user.ms_refresh_token = token_data.get('refresh_token', '')
                # Use filter().update() to reliably persist — avoids djongo update_fields issues
                rows = User.objects.filter(pk=user.pk).update(
                    is_staff=True,
                    login_provider='microsoft_teams',
                    ms_access_token=access_token,
                    ms_refresh_token=token_data.get('refresh_token', ''),
                )
                logger.info(f"[TeamsOAuth] ✅ Admin User saved to DB: id={user.id} email={user.email} rows_updated={rows} token_set={bool(access_token)}")

                # Generate Django JWT so frontend can call IsAuthenticated APIs
                refresh = RefreshToken.for_user(user)
                django_access_token = str(refresh.access_token)
                django_refresh_token = str(refresh)

                user_data = {
                    "email": user.email,
                    "id": str(user.id),
                    "displayName": full_name,
                }
                logger.info(f"Microsoft user {'created' if created else 'exists'}: {email}")

            # Auto-create VAPTFIX team with 4 channels
            vaptfix_team = auto_create_vaptfix_team(access_token)
            logger.info(f"VAPTFIX team result: {vaptfix_team}")

            # Ensure ms_team_id is persisted for the correct admin user.
            try:
                team_id = vaptfix_team.get("team_id") if vaptfix_team else None
                if user and team_id:
                    user.ms_team_id = team_id
                    user.save(update_fields=["ms_team_id"])
                elif not user and vaptfix_team and vaptfix_team.get("team_id") and email:
                    User.objects.filter(email=email).update(ms_team_id=vaptfix_team.get("team_id"))
            except Exception:
                logger.warning("Failed to persist ms_team_id after Microsoft Teams OAuth", exc_info=True)

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

                    // Prefer explicit Teams tab links so app opens Team view, not Chat.
                    var teamId = {json.dumps(vaptfix_team.get('team_id') if vaptfix_team else None)};
                    var tenantId = "{tenant_id}";
                    var teamsWebUrl = {json.dumps(vaptfix_team.get('teams_tab_url') if vaptfix_team else None)};
                    var teamsWebUrlAlt = {json.dumps(vaptfix_team.get('teams_tab_url_alt') if vaptfix_team else None)};
                    var teamsDesktopUrl = {json.dumps(vaptfix_team.get('teams_desktop_url') if vaptfix_team else None)};
                    if (!teamsWebUrl && teamId) {{
                        teamsWebUrl = "https://teams.cloud.microsoft/l/team/" + teamId + "/conversations?groupId=" + teamId;
                    }}
                    if (teamsWebUrl && tenantId && teamsWebUrl.indexOf("tenantId=") === -1) {{
                        teamsWebUrl = teamsWebUrl + "&tenantId=" + tenantId;
                    }}
                    if (teamsWebUrlAlt && tenantId && teamsWebUrlAlt.indexOf("tenantId=") === -1) {{
                        teamsWebUrlAlt = teamsWebUrlAlt + "&tenantId=" + tenantId;
                    }}
                    var webUrl = teamsWebUrl || "https://teams.cloud.microsoft";

                    var targetUrl = teamsWebUrl || webUrl;
                    var frontendUrl = {json.dumps(frontend_redirect)};
                    var frontendOrigin = frontendUrl;
                    try {{
                        frontendOrigin = new URL(frontendUrl).origin;
                    }} catch (e) {{}}
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: "TEAMS_CONNECTED",
                            success: true,
                            user: {json.dumps(user_data)},
                            tokens: {{...{json.dumps(token_data)}, tenant_id: "{tenant_id}"}},
                            django_access_token: "{django_access_token}",
                            django_refresh_token: "{django_refresh_token}",
                            vaptfix_team: {json.dumps(vaptfix_team)},
                            redirect_target: "team_tab",
                            teams_target_url: targetUrl,
                            teams_desktop_url: teamsDesktopUrl || null
                        }}, frontendOrigin);
                        // This callback already runs in a separate OAuth tab.
                        // Open Teams in this same tab so VAPTFIX parent tab stays untouched.
                        window.location.replace(targetUrl);
                        setTimeout(function() {{
                            try {{ window.close(); }} catch (e) {{}}
                        }}, 3000);
                    }} else {{
                        // Same-tab callback: never auto-open Teams, just return user to VAPTFIX app.
                        window.location.replace(frontendUrl);
                    }}
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

                ms_refresh_token = serializer.validated_data.get('refresh_token', '')
                user.login_provider = 'microsoft_teams'
                user.ms_access_token = access_token
                user.ms_refresh_token = ms_refresh_token
                user.save(update_fields=['login_provider', 'ms_access_token', 'ms_refresh_token'])

                login(request, user)
                refresh = RefreshToken.for_user(user)

                # Auto-create Vaptfix team with 4 channels
                vaptfix_team = auto_create_vaptfix_team(access_token)

                # Save team_id on the admin user so member-creation sync can use it
                team_id_from_team = vaptfix_team.get("team_id") if vaptfix_team else None
                if team_id_from_team:
                    user.ms_team_id = team_id_from_team
                    user.save(update_fields=["ms_team_id"])

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

            token_response = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
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


class MicrosoftTeamsTokenRefreshView(APIView):
    """
    Silently refresh the MS Teams access token using the stored refresh token.
    Frontend calls this when the stored access token is expired.
    Returns a new access_token so the frontend can continue without re-login.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        user = request.user
        refresh_token = getattr(user, "ms_refresh_token", None)
        if not refresh_token:
            return Response(
                {"error": "No refresh token stored. Please reconnect Microsoft Teams."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            token_payload = {
                "grant_type": "refresh_token",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/.default offline_access",
            }
            resp = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
            data = resp.json()
            new_token = data.get("access_token")
            if not new_token:
                return Response(
                    {"error": "Token refresh failed. Please reconnect Microsoft Teams.", "details": data},
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            user.ms_access_token = new_token
            if data.get("refresh_token"):
                user.ms_refresh_token = data["refresh_token"]
            user.save(update_fields=["ms_access_token", "ms_refresh_token"])
            return Response({
                "access_token": new_token,
                "expires_in": data.get("expires_in", 3600),
                "token_type": data.get("token_type", "Bearer"),
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"MS Teams token refresh error: {e}")
            return Response({"error": "Token refresh failed.", "detail": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
            response = _http_get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                return False, f"Token validation failed: {response.status_code}"
            
            # Additional check - try to access teams
            teams_response = _http_get("https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers, timeout=10)
            
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
                
                response = _http_post(url, headers=headers, json=payload, timeout=30)
                
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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
                
                response = _http_post(url, headers=headers, json=payload, timeout=10)
                
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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

    def _refresh_ms_token(self, user):
        """Try to refresh Microsoft access token using stored refresh token."""
        refresh_token = getattr(user, "ms_refresh_token", None)
        if not refresh_token:
            return None
        try:
            token_payload = {
                "grant_type": "refresh_token",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/.default offline_access",
            }
            resp = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
            data = resp.json()
            new_token = data.get("access_token")
            if new_token:
                user.ms_access_token = new_token
                if data.get("refresh_token"):
                    user.ms_refresh_token = data["refresh_token"]
                user.save(update_fields=["ms_access_token", "ms_refresh_token"])
                return new_token
        except Exception as e:
            logger.warning(f"[ListTeamsView] Token refresh failed: {e}")
        return None

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

                response = _http_get(url, headers=headers, timeout=10)

                # Token expired or forbidden — try auto-refresh once
                refreshed_token = None
                if response.status_code in (401, 403):
                    refreshed_token = self._refresh_ms_token(request.user)
                    if refreshed_token:
                        headers['Authorization'] = f'Bearer {refreshed_token}'
                        response = _http_get(url, headers=headers, timeout=10)

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

                    resp_data = {
                        "status": True,
                        "teams": teams_list,
                        "count": len(teams_list)
                    }
                    # Return new token so frontend can update localStorage
                    if refreshed_token:
                        resp_data["refreshed_access_token"] = refreshed_token
                    return Response(resp_data, status=status.HTTP_200_OK)
                else:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)

                    return Response({
                        "status": False,
                        "error": f"Failed to fetch teams: {error_data.get('error', {}).get('message', 'Unknown error')}"
                    }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f"List teams error: {str(e)}")
            return Response({
                "status": False,
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
                
                response = _http_get(url, headers=headers, timeout=10)
                
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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
            response = _http_get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
            
            if response.status_code != 200:
                return False, f"Token validation failed: {response.status_code}"
            
            # Check if user can create teams (try to list joined teams)
            teams_response = _http_get("https://graph.microsoft.com/v1.0/me/joinedTeams", headers=headers, timeout=10)
            
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
            
            response = _http_get(search_url, headers=headers, timeout=10)
            
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
                "membershipType": "standard"
            }
            try:
                resp = _http_post(url, headers=headers, json=payload, timeout=15)
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
        """Start background thread that waits for team provisioning, then creates channels."""
        headers = {
            'Authorization': f'Bearer {access_token}',
            'Content-Type': 'application/json'
        }

        def _bg(token, tid, hdrs, retries, d):
            for attempt in range(retries):
                time.sleep(d)
                try:
                    resp = _http_get(
                        f"https://graph.microsoft.com/v1.0/teams/{tid}",
                        headers=hdrs, timeout=10
                    )
                    if resp.status_code == 200:
                        _create_vaptfix_channels(tid, hdrs)
                        return
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)
                logger.info(f"Team {tid} not ready yet, retry {attempt + 1}/{retries}")
            logger.warning(f"Team {tid} provisioning timed out — channels not created.")

        t = threading.Thread(target=_bg, args=(access_token, team_id, headers, max_retries, delay), daemon=True)
        t.start()
        return [{"status": "provisioning", "note": "Channels will be created in background once team is ready."}]

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
                
                response = _http_post(url, headers=headers, json=payload, timeout=30)
                
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
                            "location": team_location,
                            "teams_url": _build_teams_tab_urls(team_id).get("general_web_url") or _build_teams_tab_urls(team_id).get("web_url"),
                            "teams_tab_url": _build_teams_tab_urls(team_id).get("general_web_url") or _build_teams_tab_urls(team_id).get("web_url"),
                            "teams_tab_url_alt": _build_teams_tab_urls(team_id).get("general_web_url_alt") or _build_teams_tab_urls(team_id).get("web_url_alt"),
                            "teams_desktop_url": _build_teams_tab_urls(team_id).get("desktop_url"),
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
                        "teams_url": _build_teams_tab_urls(team_id).get("general_web_url") or _build_teams_tab_urls(team_id).get("web_url"),
                        "teams_tab_url": _build_teams_tab_urls(team_id).get("general_web_url") or _build_teams_tab_urls(team_id).get("web_url"),
                        "teams_tab_url_alt": _build_teams_tab_urls(team_id).get("general_web_url_alt") or _build_teams_tab_urls(team_id).get("web_url_alt"),
                        "teams_desktop_url": _build_teams_tab_urls(team_id).get("desktop_url"),
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
                                "data": response_data,
                                "teams_url": _build_teams_tab_urls(team_id).get("general_web_url") or _build_teams_tab_urls(team_id).get("web_url"),
                                "teams_tab_url": _build_teams_tab_urls(team_id).get("general_web_url") or _build_teams_tab_urls(team_id).get("web_url"),
                                "teams_tab_url_alt": _build_teams_tab_urls(team_id).get("general_web_url_alt") or _build_teams_tab_urls(team_id).get("web_url_alt"),
                                "teams_desktop_url": _build_teams_tab_urls(team_id).get("desktop_url"),
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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
            response = _http_get(url, headers=headers, timeout=10)
            
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
            
            response = _http_post(url, headers=headers, json=payload, timeout=10)
            
            if response.status_code in [201, 409]:  # 409 means user already exists
                return True, "User added to team successfully"
            else:
                error_data = {}
                try:
                    error_data = response.json()
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)
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
            
            response = _http_post(url, headers=headers, json=payload, timeout=10)
            
            if response.status_code in [201, 409]:  # 409 means user already exists
                return True, "User added to channel successfully"
            else:
                error_data = {}
                try:
                    error_data = response.json()
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)
                error_msg = error_data.get('error', {}).get('message', 'Unknown error')
                # Standard channels don't support direct member add via Graph API.
                # Team membership already grants access to all standard channels.
                if 'not supported' in error_msg.lower():
                    logger.info(f"[TeamsAddUser] Standard channel detected — skipping channel member add (team membership grants access)")
                    return True, "Standard channel: access granted via team membership"
                return False, f"Failed to add user to channel: {error_msg}"

        except Exception as e:
            return False, f"Error adding user to channel: {str(e)}"

    def post(self, request, *args, **kwargs):
        try:
            logger.info(f"[TeamsAddUser] POST received from user={getattr(request.user, 'email', 'anon')} data_keys={list(request.data.keys())}")
            serializer = self.get_serializer(data=request.data)

            if serializer.is_valid(raise_exception=True):
                access_token = serializer.validated_data['access_token']
                team_id = serializer.validated_data['team_id']
                channel_id = serializer.validated_data['channel_id']
                channel_name = serializer.validated_data.get('channel_name', '')
                admin_id = (serializer.validated_data.get('admin_id') or "").strip()
                user_email = serializer.validated_data['user_email']
                user_role = serializer.validated_data['user_role']
                logger.info(f"[TeamsAddUser] Validated: user_email={user_email} team_id={team_id} channel_name={channel_name} admin_id={admin_id or '(from request.user)'}")

                # Map channel name to Member_role (same mapping as Slack)
                TEAMS_CHANNEL_TO_ROLE = {
                    "patch-management": "Patch Management",
                    "configuration-management": "Configuration Management",
                    "network-security": "Network Security",
                    "architectural-flaws": "Architectural Flaws",
                }
                member_role = [TEAMS_CHANNEL_TO_ROLE.get(channel_name.lower(), "Viewer")]
                logger.info(f"[TeamsAddUser] Channel '{channel_name}' mapped to role '{member_role}'")

                # Save user to UserDetail if not already exists
                from users_details.models import UserDetail
                from django.contrib.auth import get_user_model
                from django.utils.http import urlsafe_base64_encode
                from django.utils.encoding import force_bytes
                from django.contrib.auth.tokens import PasswordResetTokenGenerator
                from users_details.views import UserDetailCreateView

                admin = request.user
                if admin_id:
                    target_admin = User.objects.filter(id=admin_id).first()
                    if not target_admin:
                        return Response({
                            "error": "Admin not found for provided admin_id"
                        }, status=status.HTTP_404_NOT_FOUND)
                    admin = target_admin
                else:
                    # Resolve admin by team_id if request.user's ms_team_id doesn't match.
                    # Also handles case where admin hasn't set ms_team_id yet.
                    if getattr(request.user, "ms_team_id", None) != team_id:
                        team_owner = User.objects.filter(ms_team_id=team_id).first()
                        if team_owner:
                            admin = team_owner
                        else:
                            # ms_team_id not set on any user yet — save under request.user
                            # and stamp ms_team_id so future lookups work.
                            try:
                                request.user.ms_team_id = team_id
                                request.user.save(update_fields=["ms_team_id"])
                            except Exception:
                                logger.warning("[TeamsAddUser] Could not stamp ms_team_id on request.user")
                name_part = user_email.split('@')[0].replace('.', ' ').replace('_', ' ').split()
                first_name = name_part[0].capitalize() if name_part else "Teams"
                last_name = " ".join(p.capitalize() for p in name_part[1:]) if len(name_part) > 1 else "User"

                user_detail, ud_created = UserDetail.objects.get_or_create(
                    admin=admin,
                    email=user_email,
                    defaults={
                        "first_name": first_name,
                        "last_name": last_name,
                        "user_type": "external",
                        "Member_role": member_role,
                        "platform": "microsoft_teams",
                        "team_id": team_id,
                    }
                )
                if ud_created:
                    logger.info(f"[TeamsAddUser] Created UserDetail for {user_email} with role {member_role}")
                else:
                    logger.info(f"[TeamsAddUser] UserDetail already exists for {user_email}")
                    # Use stored name for emails
                    first_name = user_detail.first_name or first_name
                    last_name = user_detail.last_name or last_name
                    updates = {}
                    if not user_detail.platform:
                        updates["platform"] = "microsoft_teams"
                    if not user_detail.team_id:
                        updates["team_id"] = team_id
                    if updates:
                        from users_details.views import _ud_set as _ud_set_teams
                        _ud_set_teams(user_detail, **updates)

                # Send emails in background — do not block the MS Teams API flow
                _admin_email = getattr(request.user, "email", "")
                _ue, _fn, _ln, _mr = user_email, first_name, last_name, member_role

                def _send_teams_emails():
                    try:
                        UserModel = get_user_model()
                        django_user, u_created = UserModel.objects.get_or_create(
                            email=_ue, defaults={"is_active": True}
                        )
                        if u_created:
                            django_user.set_unusable_password()
                            django_user.save()

                        uid = urlsafe_base64_encode(force_bytes(django_user.pk))
                        token = PasswordResetTokenGenerator().make_token(django_user)
                        frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')
                        set_password_url = f"{frontend_url}/auth?mode=set-password&uid={uid}&token={token}"

                        udcv = UserDetailCreateView()
                        email_sent, err = udcv.send_welcome_email(
                            email=_ue, first_name=_fn, last_name=_ln,
                            roles=_mr, set_password_url=set_password_url,
                        )
                        if email_sent:
                            logger.info(f"[TeamsAddUser] Set-password email sent to {_ue}")
                        else:
                            logger.warning(f"[TeamsAddUser] Set-password email failed for {_ue}: {err}")

                        udcv.send_team_welcome_emails(
                            email=_ue, first_name=_fn, last_name=_ln,
                            roles=_mr, admin_email=_admin_email,
                        )
                        udcv.send_platform_access_email(
                            email=_ue,
                            first_name=_fn,
                            last_name=_ln,
                            platform_name="Microsoft Teams",
                            channel_names=_mr,
                        )
                    except Exception:
                        logger.exception(f"[TeamsAddUser] Error sending welcome email to {_ue}")

                threading.Thread(target=_send_teams_emails, daemon=True).start()
                
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
                
                # Persist Teams member linkage for DB login mapping.
                linkage_fields = {}
                if not user_detail.ms_teams_member_id:
                    linkage_fields["ms_teams_member_id"] = user_id
                if not user_detail.platform:
                    linkage_fields["platform"] = "microsoft_teams"
                if not user_detail.team_id:
                    linkage_fields["team_id"] = team_id
                if linkage_fields:
                    from users_details.views import _ud_set as _ud_set_linkage
                    _ud_set_linkage(user_detail, **linkage_fields)

                return Response({
                    "message": "User added to channel successfully",
                    "user": {
                        "id": user_id,
                        "email": user_email,
                        "name": f"{user_detail.first_name} {user_detail.last_name}",
                        "role": user_role,
                        "user_type": user_detail.user_type
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

            response = _http_patch(url, headers=headers, json=payload, timeout=30)

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
                
                response = _http_delete(url, headers=headers, timeout=30)
                
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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
            response = _http_get("https://graph.microsoft.com/v1.0/me", headers=headers, timeout=10)
            
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
            
            response = _http_get(f"https://graph.microsoft.com/v1.0/teams/{team_id}", headers=headers, timeout=10)
            
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
            
            response = _http_get(search_url, headers=headers, timeout=10)
            
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
                
                response = _http_patch(url, headers=headers, json=payload, timeout=30)
                
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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
                
                response = _http_delete(url, headers=headers, timeout=30)
                
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
                    except Exception as e:
                        logger.warning("Suppressed error: %s", e)
                    
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
    "vaptfix-patch-management-team",
    "vaptfix-configuration-management-team",
    "vaptfix-network-security-team",
    "vaptfix-architectural-flaws-team",
]
ADMIN_DASHBOARD_CHANNEL = "vaptfix-admin-dashboard"


def ensure_vaptfix_channels(bot_token, slack_user_id=None, is_admin=False, team_id=None):
    """
    Ensures VaptFix Slack channels exist.
    Admins get all 5 channels (admin dashboard + 4 team channels).
    Regular users get only the 4 team channels.
    Returns dict of {channel_name: channel_id}.

    When #vaptfix-admin-dashboard is genuinely being created for the first
    time (not just re-verified on an existing workspace), also auto-posts
    the clickable navbar + Home dashboard into it — the one-time trigger
    that lets a new admin skip ever typing /dashboard. Needs team_id to
    resolve an admin token for the dashboard data calls.
    """
    channels_to_handle = list(VAPTFIX_CHANNELS)
    if is_admin:
        channels_to_handle = [ADMIN_DASHBOARD_CHANNEL] + channels_to_handle

    headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}

    # List existing channels — Slack always stores names as lowercase
    resp = _http_get(
        "https://slack.com/api/conversations.list",
        headers=headers,
        params={"types": "public_channel", "limit": 1000}, timeout=15
    )
    existing = {ch["name"].lower(): ch["id"] for ch in resp.json().get("channels", [])}

    channel_ids = {}
    newly_created_admin_channel = False
    for name in channels_to_handle:
        # VAPTFIX_CHANNELS are already lowercase; Slack lowercases names automatically
        if name in existing:
            channel_ids[name] = existing[name]
        else:
            create_resp = _http_post(
                "https://slack.com/api/conversations.create",
                headers=headers,
                json={"name": name, "is_private": False}, timeout=15
            )
            ch_data = create_resp.json()
            if ch_data.get("ok"):
                channel_ids[name] = ch_data.get("channel", {}).get("id")
                if name == ADMIN_DASHBOARD_CHANNEL:
                    newly_created_admin_channel = True
            elif ch_data.get("error") == "name_taken":
                # Already exists but not in listing (e.g. archived) — re-fetch
                retry_resp = _http_get(
                    "https://slack.com/api/conversations.list",
                    headers=headers,
                    params={"types": "public_channel,private_channel", "limit": 1000}, timeout=15
                )
                retry_existing = {ch["name"].lower(): ch["id"] for ch in retry_resp.json().get("channels", [])}
                channel_ids[name] = retry_existing.get(name)
            else:
                logger.warning(f"[ensure_vaptfix_channels] Failed to create '{name}': {ch_data.get('error')}")
                channel_ids[name] = None

        channel_id = channel_ids.get(name)
        if not channel_id:
            continue

        # Bot joins channel
        _http_post(
            "https://slack.com/api/conversations.join",
            headers=headers,
            json={"channel": channel_id}, timeout=15
        )

        if name == ADMIN_DASHBOARD_CHANNEL and newly_created_admin_channel and team_id:
            try:
                SlackEventsView()._post_admin_navbar_message(bot_token, channel_id, team_id)
            except Exception:
                logger.warning("[ensure_vaptfix_channels] Failed to auto-post navbar", exc_info=True)

        # Invite the logged-in Slack user
        if slack_user_id:
            invite_resp = _http_post(
                "https://slack.com/api/conversations.invite",
                headers=headers,
                json={"channel": channel_id, "users": slack_user_id}, timeout=15
            )
            invite_data = invite_resp.json()
            if not invite_data.get("ok") and invite_data.get("error") not in ("already_in_channel", "cant_invite_self"):
                logger.warning(f"[ensure_vaptfix_channels] Invite '{slack_user_id}' to '{name}' failed: {invite_data.get('error')}")

    return channel_ids


class UserLoginPlatformView(APIView):
    """
    GET /api/users/user-login-platform/?email=user@company.com
    Returns which platform the user's admin is on (slack / microsoft_teams / email).
    Frontend uses this to decide: show Slack button, Teams button, or password field.

    Response:
    {
        "platform": "slack",          -- or "microsoft_teams" or "email"
        "admin_id": "uuid-of-admin",
        "found": true
    }
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        email = request.GET.get("email", "").strip().lower()
        if not email:
            return Response({"error": "email is required"}, status=status.HTTP_400_BAD_REQUEST)

        from users_details.models import UserDetail

        # Check if this email belongs to an admin (User table)
        admin_user = User.objects.filter(email=email).first()
        if admin_user:
            platform = admin_user.login_provider or "email"
            if platform not in ("slack", "microsoft_teams"):
                platform = "email"
            return Response({
                "platform": platform,
                "admin_id": str(admin_user.id),
                "found": True,
                "role": "admin",
            })

        # Check if this email belongs to a team member (UserDetail table)
        user_detail = UserDetail.objects.filter(email=email).first()
        if user_detail:
            platform = user_detail.platform or "email"
            if platform not in ("slack", "microsoft_teams"):
                # Inherit from admin
                admin = user_detail.admin
                platform = admin.login_provider or "email"
                if platform not in ("slack", "microsoft_teams"):
                    platform = "email"
            return Response({
                "platform": platform,
                "admin_id": str(user_detail.admin.id),
                "found": True,
                "role": "member",
            })

        return Response({
            "platform": "email",
            "found": False,
        })


class SlackOAuthUrlView(APIView):
    """
    Dynamically generates Slack OAuth authorization URL
    for both ngrok (local) and production environments.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        # state is returned back by Slack during callback.
        # We must bind it to the admin selected in UI (admin_id), otherwise tokens can be saved to the wrong User record.
        admin_id = request.data.get("admin_id")
        state_data = {
            "admin_id": admin_id,
            "nonce": str(uuid.uuid4()),
        }
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

        # Use SLACK_REDIRECT_URI from settings if configured, otherwise detect dynamically
        redirect_uri = getattr(settings, "SLACK_REDIRECT_URI", "")
        if not redirect_uri:
            base_url = request.data.get("base_url", "")
            if not base_url:
                try:
                    ngrok_resp = _http_get("http://127.0.0.1:4040/api/tunnels", timeout=15).json()
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
            f"&scope=chat:write,channels:read,channels:manage,channels:join,groups:read,groups:write,mpim:write,im:write,users:read,users:read.email,commands,files:write"
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
                    ngrok_resp = _http_get("http://127.0.0.1:4040/api/tunnels", timeout=15).json()
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
                token_res = _http_post(token_url, data=token_data, timeout=10)
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
            user_access_token = authed_user.get("access_token")

            # ─── Print tokens to Django console (for Postman testing) ───
            print("=" * 60)
            print("SLACK OAUTH TOKENS")
            print(f"  bot_access_token  : {bot_token}")
            print(f"  user_access_token : {user_access_token}")
            print(f"  team              : {team_info.get('name')} ({team_info.get('id')})")
            # Decode state to get UI admin_id (if provided)
            decoded_state = None
            admin_id_from_state = None
            try:
                decoded_state = base64.urlsafe_b64decode(state + "==").decode()
                decoded_state = json.loads(decoded_state)
                admin_id_from_state = decoded_state.get("admin_id")
            except Exception:
                # Backward compatible: older callbacks may have state as plain uuid string
                admin_id_from_state = None
            print(f"  admin_id_from_state: {admin_id_from_state}")
            print("=" * 60)


            # ✅ Step 3: Fetch user profile from Slack
            user_id = authed_user.get("id")
            user_info = _http_get(
                "https://slack.com/api/users.info",
                params={"user": user_id},
                headers={"Authorization": f"Bearer {bot_token}"}, timeout=15
            ).json()

            if not user_info.get("ok"):
                logger.error(f"Slack user info error: {user_info.get('error')}")
                return self._html_response(success=False, error="Failed to fetch user info from Slack")

            user_data = user_info.get("user", {})
            email = user_data.get("profile", {}).get("email")
            name = user_data.get("real_name") or user_data.get("name") or "Slack User"
            firstname = name.split()[0]
            lastname = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

            # ✅ Step 4: Update the correct User record.
            # Preferred: use admin_id from UI state (avoids email mismatch between platform login and Slack email).
            # Fallback: use Slack email (older behavior).
            if admin_id_from_state:
                user = User.objects.filter(id=admin_id_from_state).first()
            else:
                user = None

            if not user:
                user, _ = User.objects.get_or_create(
                    email=email,
                    defaults={"login_provider": "slack", "password": ""},
                )

            # Platform enforcement: block email-only admins (email accounts stay email-only)
            if admin_id_from_state and user.login_provider == "email":
                return self._html_response(
                    success=False,
                    error="Your account uses email login. Please sign in with your email and password.",
                )

            # Platform enforcement: block if admin already connected Teams
            if user.login_provider == "microsoft_teams" and user.ms_access_token:
                return self._html_response(
                    success=False,
                    error="Your account is connected to Microsoft Teams. Please sign in using Microsoft Teams.",
                )

            logger.info(f"[SlackOAuth] Saving admin User: id={user.id} email={user.email} user_id={user_id} team_id={team_info.get('id')} bot_token_set={bool(bot_token)}")
            user.login_provider = "slack"
            user.slack_user_id = user_id
            user.slack_team_id = team_info.get("id")
            user.slack_bot_token = bot_token
            try:
                user.save()
                logger.info(f"[SlackOAuth] ✅ Admin User saved to DB: id={user.id} email={user.email} slack_team_id={user.slack_team_id}")
            except Exception as _save_exc:
                logger.exception(f"[SlackOAuth] ❌ Admin User save FAILED: id={user.id} email={user.email} error={_save_exc}")
                raise  # re-raise so outer except catches it

            # ✅ Step 4b: Ensure vaptfix channels exist and invite user
            channels = {}
            try:
                channels = ensure_vaptfix_channels(
                    bot_token, slack_user_id=user_id, is_admin=True, team_id=team_info.get("id"),
                )
            except Exception:
                logger.warning("ensure_vaptfix_channels failed in callback", exc_info=True)

            # ✅ Step 4c: Generate Django JWT tokens for the user
            refresh = RefreshToken.for_user(user)
            django_access_token = str(refresh.access_token)
            django_refresh_token = str(refresh)

            # ✅ Step 5: postMessage to parent then redirect to Slack
            team_id = team_info.get("id")
            slack_redirect_url = f"https://app.slack.com/client/{team_id}" if team_id else "https://slack.com"
            html = f"""
            <html>
            <head><title>Slack Connected</title></head>
            <body>
                <script>
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: "SLACK_CONNECTED",
                            bot_token: {json.dumps(bot_token)},
                            slack_user_id: {json.dumps(user_id)},
                            django_access_token: {json.dumps(django_access_token)},
                            django_refresh_token: {json.dumps(django_refresh_token)}
                        }}, "*");
                    }}
                    window.location.href = {json.dumps(slack_redirect_url)};
                </script>
            </body>
            </html>
            """
            return HttpResponse(html)

        except Exception as e:
            logger.exception("Slack OAuth callback exception")
            return self._html_response(success=False, error=str(e))

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
            user_identity = _http_get(
                "https://slack.com/api/users.identity",
                headers={"Authorization": f"Bearer {user_token}"}, timeout=15
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
                bot_response = _http_get(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {bot_token}"}, timeout=15
                ).json()

                user_info = _http_get(
                    "https://slack.com/api/users.info",
                    headers={"Authorization": f"Bearer {bot_token}"},
                    params={"user": bot_response.get("user_id")}, timeout=15
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
                    "is_superuser": False,
                    "password": "",
                    "last_login": timezone.now(),
                    "login_provider": "slack",
                    "slack_user_id": slack_user_id,
                    "slack_team_id": slack_team.get("id"),
                }
            )

            # 3. Update existing users — use direct pymongo for is_staff (djongo boolean bug)
            try:
                _mongo_uri = settings.DATABASES['default']['CLIENT']['host']
                import pymongo as _pm
                with _pm.MongoClient(_mongo_uri, serverSelectionTimeoutMS=5000) as _uc:
                    _udb = _uc[settings.DATABASES['default'].get('NAME', 'vaptfix')]
                    _udb['users_user'].update_one(
                        {'id': str(user.id)},
                        {'$set': {
                            'is_staff': True,
                            'login_provider': 'slack',
                            'slack_user_id': slack_user_id,
                            'slack_team_id': slack_team.get('id'),
                            'last_login': timezone.now(),
                        }}
                    )
                user.is_staff = True
                user.login_provider = 'slack'
            except Exception:
                logger.warning("User update via pymongo failed in Slack login", exc_info=True)
                # Fallback to ORM save
                user.last_login = timezone.now()
                user.is_staff = True
                user.login_provider = "slack"
                user.slack_user_id = slack_user_id
                user.slack_team_id = slack_team.get("id")
                user.save()

            # 3a. Ensure UserDetail exists when user authenticates from Slack.
            user_detail_created = False
            user_detail_updated = False
            needs_role_assignment = True
            try:
                from users_details.models import UserDetail
                name_parts = (slack_name or "Slack User").strip().split()
                first_name = name_parts[0] if name_parts else "Slack"
                last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"
                ud, ud_created = UserDetail.objects.get_or_create(
                    admin=user,
                    email=slack_email,
                    defaults={
                        "first_name": first_name,
                        "last_name": last_name,
                        "user_type": "internal",
                        "Member_role": [],
                        "platform": "slack",
                        "slack_member_id": slack_user_id,
                    },
                )
                user_detail_created = ud_created
                if not ud_created:
                    changed = {}
                    if not (ud.first_name or "").strip() and first_name:
                        changed["first_name"] = first_name
                    if not (ud.last_name or "").strip() and last_name:
                        changed["last_name"] = last_name
                    if not ud.platform:
                        changed["platform"] = "slack"
                    if not ud.slack_member_id and slack_user_id:
                        changed["slack_member_id"] = slack_user_id
                    if changed:
                        # Direct pymongo update — djongo update_fields is unreliable
                        try:
                            from bson import ObjectId as _OID
                            _mongo_uri = settings.DATABASES['default']['CLIENT']['host']
                            import pymongo as _pm
                            with _pm.MongoClient(_mongo_uri, serverSelectionTimeoutMS=5000) as _c:
                                _db2 = _c[settings.DATABASES['default'].get('NAME', 'vaptfix')]
                                _db2['users_details_userdetail'].update_one(
                                    {'_id': _OID(str(ud._id))},
                                    {'$set': changed}
                                )
                            for _k, _v in changed.items():
                                setattr(ud, _k, _v)
                            user_detail_updated = True
                        except Exception:
                            logger.warning("UserDetail update failed in Slack login", exc_info=True)
                roles = ud.Member_role or []
                needs_role_assignment = len(roles) == 0

                # Fetch user's Slack channel memberships and save to slack_channel_ids
                try:
                    _ch_resp = _http_get(
                        "https://slack.com/api/users.conversations",
                        headers={"Authorization": f"Bearer {bot_token}"},
                        params={
                            "user": slack_user_id,
                            "types": "public_channel,private_channel",
                            "limit": 200,
                            "exclude_archived": "true",
                        },
                        timeout=10,
                    )
                    _ch_data = _ch_resp.json() if _ch_resp.ok else {}
                    if _ch_data.get("ok"):
                        _ch_ids = [c["id"] for c in _ch_data.get("channels", []) if c.get("id")]
                        if _ch_ids:
                            from bson import ObjectId as _OIDC
                            import pymongo as _pm3
                            _mongo_uri2 = settings.DATABASES['default']['CLIENT']['host']
                            with _pm3.MongoClient(_mongo_uri2, serverSelectionTimeoutMS=5000) as _c3:
                                _db3 = _c3[settings.DATABASES['default'].get('NAME', 'vaptfix')]
                                _db3['users_details_userdetail'].update_one(
                                    {'_id': _OIDC(str(ud._id))},
                                    {'$set': {'slack_channel_ids': _ch_ids}}
                                )
                            ud.slack_channel_ids = _ch_ids
                            logger.info(f"[SlackLogin] Saved {len(_ch_ids)} channel IDs for {slack_email}")
                except Exception:
                    logger.warning("[SlackLogin] Could not fetch/save channel memberships", exc_info=True)

            except Exception:
                logger.warning("UserDetail upsert failed in Slack login", exc_info=True)

            # 3b. Ensure vaptfix channels exist and invite user
            channels = {}
            try:
                channels = ensure_vaptfix_channels(
                    bot_token, slack_user_id=slack_user_id, is_admin=True, team_id=slack_team.get("id"),
                )
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
                    },
                    "vaptfix_sync": {
                        "user_created": created,
                        "user_detail_created": user_detail_created,
                        "user_detail_updated": user_detail_updated,
                        "needs_role_assignment": needs_role_assignment,
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
            auth_response = _http_get(auth_test_url, headers=headers, timeout=15)
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
                bot_info_response = _http_get(
                    bot_info_url,
                    headers=headers,
                    params={"bot": auth_json.get("bot_id")}, timeout=15
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
            auth_test_response = _http_get('https://slack.com/api/auth.test', headers=headers, timeout=15)
            auth_test_data = auth_test_response.json()
            
            if not auth_test_data.get('ok'):
                return Response({
                    'success': False,
                    'message': 'Invalid or expired access token'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            # Get detailed user info
            user_id = auth_test_data.get('user_id')
            user_response = _http_get(
                'https://slack.com/api/users.info', 
                headers=headers, 
                params={'user': user_id}, timeout=15
            )
            user_data = user_response.json()
            
            if user_data.get('ok'):
                user_profile = user_data.get('user', {}).get('profile', {})
                email = user_profile.get('email')

                # If email is null (bot token used), try users.identity for human user email
                if not email:
                    identity_resp = _http_get(
                        'https://slack.com/api/users.identity',
                        headers=headers, timeout=15
                    ).json()
                    if identity_resp.get('ok'):
                        email = identity_resp.get('user', {}).get('email')

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
                            'email': email,
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
        
        response = _http_post(url, headers=headers, json=payload, timeout=30)
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

        response = _http_post(url, headers=headers, json=payload, timeout=30)
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
            
            response = _http_post(url, headers=headers, json=payload, timeout=15)
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

        response = _http_post(url, headers=headers, json=payload, timeout=15)
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

            response = _http_post(url, headers=headers, json=payload, timeout=15)
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
    """List Slack channels using bot token from admin DB record or Authorization header"""
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    def get(self, request):
        try:
            # Prefer the Slack bot token stored in the admin's DB record.
            # Fall back to a Slack token passed explicitly in the Authorization header
            # (legacy path — only used if the header starts with 'xox' which is a Slack token prefix).
            access_token = getattr(request.user, "slack_bot_token", None)
            if not access_token:
                auth_header = request.headers.get('Authorization', '')
                candidate = auth_header.replace('Bearer ', '').strip()
                if candidate.startswith('xox'):
                    access_token = candidate
            if not access_token:
                return Response({
                    'success': False,
                    'message': 'Slack not connected. Please connect Slack first.'
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

            response = _http_get(url, headers=headers, params=params, timeout=15)
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
    permission_classes = [IsAuthenticated]

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
        user_email = serializer.validated_data.get("user_email")
        user_name = serializer.validated_data.get("user_name")

        # Resolve the real target Slack member from email when available.
        # This avoids saving/inviting admin/self ID accidentally from frontend payload.
        if user_email:
            try:
                lookup_resp = _http_get(
                    "https://slack.com/api/users.lookupByEmail",
                    headers={"Authorization": f"Bearer {access_token}"},
                    params={"email": user_email},
                    timeout=10,
                )
                lookup_data = lookup_resp.json() if lookup_resp is not None else {}
                looked_up_user_id = lookup_data.get("user", {}).get("id") if lookup_data.get("ok") else None
                if looked_up_user_id:
                    user_id = looked_up_user_id
                    logger.info(f"[AddUserToSlack] Using user_id={user_id} from lookupByEmail for {user_email}")
            except Exception:
                logger.warning("[AddUserToSlack] lookupByEmail failed; using provided user_id", exc_info=True)

        # Hard-guard: never save/invite admin self when email points to someone else.
        if (
            user_email
            and request.user
            and getattr(request.user, "slack_user_id", None)
            and user_id == getattr(request.user, "slack_user_id", None)
            and user_email.strip().lower() != (getattr(request.user, "email", "") or "").strip().lower()
        ):
            return Response({
                "success": False,
                "message": "Provided user_id belongs to admin account; please select the target Slack member."
            }, status=status.HTTP_400_BAD_REQUEST)

        # Resolve role from channel name
        resolved_role = "Viewer"
        resolved_ch_name = ""
        try:
            ch_info = _http_get(
                "https://slack.com/api/conversations.info",
                params={"channel": channel},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5,
            ).json()
            resolved_ch_name = ch_info.get("channel", {}).get("name", "")
            resolved_role = SLACK_CHANNEL_TO_ROLE.get(resolved_ch_name, "Viewer")
            logger.info(f"[AddUserToSlack] Channel '{resolved_ch_name}' mapped to role '{resolved_role}'")
        except Exception:
            logger.warning("[AddUserToSlack] Could not fetch channel name — defaulting to Viewer")

        try:
            response = self._add_user(access_token, channel, user_id)

            if response["success"]:
                # Save to UserDetail + send welcome email
                db_save_error = None
                try:
                    # Always resolve profile by Slack user ID so DB stores the real member identity,
                    # not whatever email was typed/returned by frontend.
                    SlackInviteUserView()._save_and_email_invited_user(
                        slack_user_id=user_id,
                        bot_token=access_token,
                        admin=request.user,
                        role=resolved_role,
                        channel_id=channel,
                        channel_name=resolved_ch_name,
                        fallback_email=user_email,
                    )
                except Exception as _db_exc:
                    db_save_error = str(_db_exc)
                    logger.exception(f"[AddUserToSlack] Failed to save/email user {user_id}: {_db_exc}")

                resp_body = {
                    "success": True,
                    "message": "User added to channel successfully",
                    "data": response["data"],
                }
                if db_save_error:
                    resp_body["db_save_warning"] = f"User added to Slack but VAPTFIX DB save failed: {db_save_error}"
                    logger.error(f"[AddUserToSlack] DB save FAILED for user_id={user_id} email={user_email}: {db_save_error}")
                return Response(resp_body, status=status.HTTP_200_OK)
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

        response = _http_post(url, headers=headers, json=payload, timeout=30)
        result = response.json()

        if result.get("ok") or result.get("error") == "already_in_channel":
            return {
                "success": True,
                "data": result.get("channel"),
                "already_in_channel": result.get("error") == "already_in_channel",
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

        response = _http_get(url, headers=headers, timeout=15)
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


SLACK_CHANNEL_TO_ROLE = {
    "patch-management": "Patch Management",
    "configuration-management": "Configuration Management",
    "network-security": "Network Security",
    "architectural-flaws": "Architectural Flaws",
}


class SlackInviteUserView(APIView):
    """
    Invite a user to a Slack channel.
    After a successful invite, saves each user to UserDetail and sends
    the same set-password welcome email that the normal user-add flow sends.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = SlackInviteUserSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=400)

        access_token = serializer.validated_data["access_token"]
        channel = serializer.validated_data["channel"]
        slack_user_ids = serializer.validated_data["users"]  # list of Slack user IDs
        user_emails = serializer.validated_data.get("user_emails") or {}  # optional slack_id -> email map

        url = "https://slack.com/api/conversations.invite"
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json"
        }
        payload = {"channel": channel, "users": ",".join(slack_user_ids)}

        response = _http_post(url, headers=headers, json=payload, timeout=15)
        data = response.json()

        if not data.get("ok"):
            return Response({"success": False, "error": data.get("error")}, status=400)

        # Determine role from channel name using Slack conversations.info
        role = "Viewer"
        channel_name = ""
        try:
            ch_info = _http_get(
                "https://slack.com/api/conversations.info",
                params={"channel": channel},
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=5,
            ).json()
            channel_name = ch_info.get("channel", {}).get("name", "")
            role = SLACK_CHANNEL_TO_ROLE.get(channel_name, "Viewer")
            logger.info(f"[SlackInvite] Channel '{channel_name}' mapped to role '{role}'")
        except Exception:
            logger.warning("[SlackInvite] Could not fetch channel name — defaulting to Viewer")

        # admin = the authenticated user making this request
        admin = request.user
        for slack_uid in slack_user_ids:
            try:
                self._save_and_email_invited_user(
                    slack_user_id=slack_uid,
                    bot_token=access_token,
                    admin=admin,
                    role=role,
                    channel_id=channel,
                    channel_name=channel_name,
                    fallback_email=user_emails.get(slack_uid),
                )
            except Exception:
                logger.exception(f"[SlackInvite] Failed to save/email user {slack_uid}")

        return Response({"success": True, "data": data}, status=200)

    def _save_and_email_with_known_email(self, email, name, admin, role="Viewer", channel_name=None):
        """Save to UserDetail and send welcome emails when email is already known."""
        from users_details.models import UserDetail
        parts = name.strip().split()
        first_name = parts[0] if parts else "Slack"
        last_name = " ".join(parts[1:]) if len(parts) > 1 else "User"
        member_role = [role] if isinstance(role, str) else role

        user_detail, created = UserDetail.objects.get_or_create(
            admin=admin,
            email=email,
            defaults={
                "first_name": first_name,
                "last_name": last_name,
                "user_type": "external",
                "Member_role": member_role,
            }
        )

        # Always update slack_channel_ids if channel_name provided
        if channel_name:
            try:
                existing = list(user_detail.slack_channel_ids or [])
                if channel_name not in existing:
                    existing.append(channel_name)
                    from users_details.views import _ud_set as _ud_set_ch
                    _ud_set_ch(user_detail, slack_channel_ids=existing)
            except Exception:
                logger.warning(f"[SlackInvite] Could not update slack_channel_ids for {email}")

        _email = email
        _first = first_name
        _last = last_name
        _roles = member_role
        _admin_email = getattr(admin, "email", "") if admin else ""
        _channel_name = channel_name
        _is_new = created

        if not created:
            logger.info(f"[SlackInvite] UserDetail already exists for {email} — sending Slack platform email only")
        else:
            logger.info(f"[SlackInvite] Created UserDetail for {email} under admin {admin.email} with role {member_role}")

        def _send_slack_known_emails():
            try:
                from users_details.views import UserDetailCreateView
                udcv = UserDetailCreateView()

                # Send set-password + team emails for both new and existing users
                from django.contrib.auth import get_user_model
                from django.utils.http import urlsafe_base64_encode
                from django.utils.encoding import force_bytes
                from django.contrib.auth.tokens import PasswordResetTokenGenerator

                UserModel = get_user_model()
                django_user, u_created = UserModel.objects.get_or_create(
                    email=_email, defaults={"is_active": True}
                )
                if u_created:
                    django_user.set_unusable_password()
                    django_user.save()

                uid = urlsafe_base64_encode(force_bytes(django_user.pk))
                token = PasswordResetTokenGenerator().make_token(django_user)
                frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')
                set_password_url = f"{frontend_url}/auth?mode=set-password&uid={uid}&token={token}"

                email_sent, error = udcv.send_welcome_email(
                    email=_email, first_name=_first, last_name=_last,
                    roles=_roles, set_password_url=set_password_url,
                )
                if email_sent:
                    logger.info(f"[SlackInvite] Set-password email sent to {_email}")
                else:
                    logger.warning(f"[SlackInvite] Set-password email failed for {_email}: {error}")

                udcv.send_team_welcome_emails(
                    email=_email, first_name=_first, last_name=_last,
                    roles=_roles, admin_email=_admin_email,
                )

                # Always send Slack platform email
                if _channel_name:
                    udcv.send_slack_platform_email(
                        email=_email, first_name=_first, last_name=_last,
                        channel_names=[_channel_name],
                    )
            except Exception:
                logger.exception(f"[SlackInvite] Email thread failed for {_email}")

        threading.Thread(target=_send_slack_known_emails, daemon=True).start()

    def _save_and_email_invited_user(
        self,
        slack_user_id,
        bot_token,
        admin,
        role="Viewer",
        channel_id=None,
        channel_name=None,
        fallback_email=None,
    ):
        """Fetch Slack profile, save to UserDetail, send set-password welcome email."""
        user_info = _http_get(
            "https://slack.com/api/users.info",
            params={"user": slack_user_id},
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10,
        ).json()

        email = None
        first_name = "Slack"
        last_name = "User"

        if not user_info.get("ok"):
            logger.warning(f"[SlackInvite] users.info failed for {slack_user_id}: {user_info.get('error')} — falling back to provided email")
            if not fallback_email:
                logger.error(f"[SlackInvite] No fallback_email for {slack_user_id} — user will NOT be saved to DB. Pass user_email in the API request.")
                return
            # Fallback: use provided email to still create/update UserDetail
            email = str(fallback_email).strip().lower()
            name_part = email.split('@')[0].replace('.', ' ').replace('_', ' ').split()
            first_name = name_part[0].capitalize() if name_part else "Slack"
            last_name = " ".join(p.capitalize() for p in name_part[1:]) if len(name_part) > 1 else "User"
        else:
            user_data = user_info.get("user", {})
            if user_data.get("is_bot") or user_data.get("deleted"):
                return
            profile = user_data.get("profile", {})
            email = profile.get("email")
            if not email and fallback_email:
                email = fallback_email
            if not email:
                logger.warning(f"[SlackInvite] No email for {slack_user_id}")
                return
            email = str(email).strip().lower()
            name = user_data.get("real_name") or profile.get("display_name") or "Slack User"
            parts = name.strip().split()
            first_name = parts[0] if parts else "Slack"
            last_name = " ".join(parts[1:]) if len(parts) > 1 else "User"

        # Save to UserDetail
        from users_details.models import UserDetail
        member_role = [role] if isinstance(role, str) else role
        existing_by_member = UserDetail.objects.filter(admin=admin, slack_member_id=slack_user_id).first()
        created = False
        if existing_by_member:
            user_detail = existing_by_member
            _upd = {}
            # Correct stale admin-email rows to actual Slack member email.
            if user_detail.email != email and not UserDetail.objects.filter(admin=admin, email=email).exclude(_id=user_detail._id).exists():
                _upd["email"] = email
            if not user_detail.first_name:
                _upd["first_name"] = first_name
            if not user_detail.last_name:
                _upd["last_name"] = last_name
            if not user_detail.platform:
                _upd["platform"] = "slack"
            if not user_detail.slack_member_id:
                _upd["slack_member_id"] = slack_user_id
            if channel_id:
                existing_channel_ids = list(user_detail.slack_channel_ids or [])
                if channel_id not in existing_channel_ids:
                    existing_channel_ids.append(channel_id)
                    _upd["slack_channel_ids"] = existing_channel_ids
            if _upd:
                from users_details.views import _ud_set as _ud_set_slack
                _ud_set_slack(user_detail, **_upd)
        else:
            defaults = {
                "first_name": first_name,
                "last_name": last_name,
                "user_type": "external",
                "Member_role": member_role,
                "platform": "slack",
                "slack_member_id": slack_user_id,
                "slack_channel_ids": [channel_id] if channel_id else [],
            }
            user_detail, created = UserDetail.objects.get_or_create(
                admin=admin,
                email=email,
                defaults=defaults,
            )
            if not created:
                _upd2 = {}
                if not user_detail.platform:
                    _upd2["platform"] = "slack"
                if not user_detail.slack_member_id:
                    _upd2["slack_member_id"] = slack_user_id
                if channel_id:
                    existing_channel_ids = list(user_detail.slack_channel_ids or [])
                    if channel_id not in existing_channel_ids:
                        existing_channel_ids.append(channel_id)
                        _upd2["slack_channel_ids"] = existing_channel_ids
                if _upd2:
                    from users_details.views import _ud_set as _ud_set_slack2
                    _ud_set_slack2(user_detail, **_upd2)

        _email = email
        _first = first_name
        _last = last_name
        _roles = member_role
        _admin_email = getattr(admin, "email", "") if admin else ""
        _is_new = created

        if not created:
            logger.info(f"[SlackInvite] UserDetail already exists for {email} — sending Slack platform email only")
        else:
            logger.info(f"[SlackInvite] Created UserDetail for {email} under admin {admin.email} with role {member_role}")

        # Use role names directly as channel display names in the Slack platform email
        _channel_names = [channel_name] if channel_name else (list(_roles) if _roles else [])

        def _send_slack_invited_emails():
            try:
                from users_details.views import UserDetailCreateView
                view = UserDetailCreateView()

                from django.contrib.auth import get_user_model
                from django.utils.http import urlsafe_base64_encode
                from django.utils.encoding import force_bytes
                from django.contrib.auth.tokens import PasswordResetTokenGenerator

                UserModel = get_user_model()
                django_user, u_created = UserModel.objects.get_or_create(
                    email=_email, defaults={"is_active": True}
                )
                if u_created:
                    django_user.set_unusable_password()
                    django_user.save()

                uid = urlsafe_base64_encode(force_bytes(django_user.pk))
                token = PasswordResetTokenGenerator().make_token(django_user)
                frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')
                set_password_url = f"{frontend_url}/auth?mode=set-password&uid={uid}&token={token}"

                email_sent, error = view.send_welcome_email(
                    email=_email, first_name=_first, last_name=_last,
                    roles=_roles, set_password_url=set_password_url,
                )
                if email_sent:
                    logger.info(f"[SlackInvite] Set-password email sent to {_email}")
                else:
                    logger.warning(f"[SlackInvite] Set-password email failed for {_email}: {error}")

                view.send_team_welcome_emails(
                    email=_email, first_name=_first, last_name=_last,
                    roles=_roles, admin_email=_admin_email,
                )

                # Always send Slack platform email
                if _channel_names:
                    view.send_slack_platform_email(
                        email=_email, first_name=_first, last_name=_last,
                        channel_names=_channel_names,
                    )
            except Exception:
                logger.exception(f"[SlackInvite] Email thread failed for {_email}")

        threading.Thread(target=_send_slack_invited_emails, daemon=True).start()


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

            logger.info(f"Exchanging code for token at {settings.JIRA_TOKEN_URL} | redirect_uri={settings.JIRA_REDIRECT_URI}")

            try:
                token_response = _http_post(
                    settings.JIRA_TOKEN_URL,
                    json=token_data,
                    headers={'Content-Type': 'application/json'},
                    timeout=15
                )
            except requests.exceptions.Timeout:
                logger.error("Jira token exchange timed out after 15s")
                return Response({'error': 'Jira token exchange timed out'}, status=status.HTTP_504_GATEWAY_TIMEOUT)
            except requests.exceptions.RequestException as e:
                logger.error(f"Jira token exchange request failed: {e}")
                return Response({'error': 'Jira token exchange request failed', 'detail': str(e)}, status=status.HTTP_502_BAD_GATEWAY)

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

            # Redirect to frontend with tokens in query params.
            # Frontend reads them from URL, stores in localStorage, then navigates to /communication.
            from django.http import HttpResponseRedirect
            from urllib.parse import urlencode

            frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')
            params = urlencode({
                'access_token': tokens.get('access_token', ''),
                'refresh_token': tokens.get('refresh_token', ''),
                'expires_in': tokens.get('expires_in', ''),
                'scope': tokens.get('scope', ''),
            })
            return HttpResponseRedirect(f"{frontend_url}/jira/callback?{params}")

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

            token_response = _http_post(
                settings.JIRA_TOKEN_URL,
                json=token_data,
                headers={'Content-Type': 'application/json'}, timeout=15
            )

            if token_response.status_code != 200:
                return Response({
                    'error': 'Failed to exchange code for token',
                    'detail': token_response.text
                }, status=status.HTTP_400_BAD_REQUEST)

            tokens = token_response.json()

            # Fetch user info
            user_response = _http_get(
                'https://api.atlassian.com/me',
                headers={'Authorization': f"Bearer {tokens['access_token']}"}, timeout=15
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
                    'name': user_data.get('name', ''),
                    'account_id': user_data.get('account_id', '')
                },
                'jira_tokens': {
                    'access_token': tokens.get('access_token', ''),
                    'refresh_token': tokens.get('refresh_token', ''),
                    'expires_in': tokens.get('expires_in', 3600),
                    'token_type': tokens.get('token_type', 'Bearer'),
                    'scope': tokens.get('scope', ''),
                },
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

            response = _http_get(
                'https://api.atlassian.com/me',
                headers={'Authorization': f'Bearer {access_token}'}, timeout=15
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

            response = _http_get(
                'https://api.atlassian.com/me',
                headers={'Authorization': f'Bearer {access_token}'}, timeout=15
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

            response = _http_get(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json'
                }, timeout=15
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
            response = _http_post(
                url,
                json=payload,
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "Content-Type": "application/json"
                }, timeout=15
            )

            jira_data = response.json()
            if response.status_code in [200, 201]:
                jira_data['name'] = project_data.get('name', '')
                jira_data['description'] = project_data.get('description', '')
                jira_data['projectTypeKey'] = project_data.get('projectTypeKey', 'software')
            return Response(jira_data, status=response.status_code)
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

            response = _http_post(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue',
                json=issue_data,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }, timeout=15
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
        response = _http_get(
            url,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }, timeout=15
        )

        return Response(response.json(), status=response.status_code)
    

class JiraUpdateIssueView(APIView):
    permission_classes = [AllowAny]

    def patch(self, request, issue_key):
        access_token = request.headers.get('Jira-Access-Token')
        cloud_id = request.headers.get('Jira-Cloud-Id')
        payload = {"fields": request.data}

        url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}"
        response = _http_put(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }, timeout=15
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
        response = _http_delete(
            url,
            headers={"Authorization": f"Bearer {access_token}"}, timeout=15
        )

        return Response(
            {"message": "Issue Delete successfully" if response.status_code == 204 else response.json()},
            status=response.status_code
        )

class JiraSearchIssuesView(APIView):
    """Search issues via JQL"""
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')
            jql = request.GET.get('jql', 'order by created DESC')

            if not access_token or not cloud_id:
                return Response({'error': 'Missing Jira headers'}, status=400)

            response = _http_get(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/search/jql',
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json'
                },
                params={
                    'jql': jql,
                    'fields': 'summary,status,assignee,priority,issuetype,created,updated,description,reporter,project'
                }, timeout=15
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

        response = _http_put(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "Content-Type": "application/json"
            }, timeout=15
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

            response = _http_get(
                'https://api.atlassian.com/oauth/token/accessible-resources',
                headers={'Authorization': f'Bearer {access_token}'}, timeout=15
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

            response = _http_post(
                f'https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/comment',
                json=comment_data,
                headers={
                    'Authorization': f'Bearer {access_token}',
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                }, timeout=15
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


# -------------------- TOKEN REFRESH --------------------
class JiraTokenRefreshView(APIView):
    """Refresh Jira OAuth access token using refresh token"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            refresh_token = request.data.get('refresh_token')
            if not refresh_token:
                return Response({'error': 'refresh_token is required'}, status=status.HTTP_400_BAD_REQUEST)

            token_data = {
                'grant_type': 'refresh_token',
                'client_id': settings.JIRA_CLIENT_ID,
                'client_secret': settings.JIRA_CLIENT_SECRET,
                'refresh_token': refresh_token,
            }

            response = _http_post(
                settings.JIRA_TOKEN_URL,
                json=token_data,
                headers={'Content-Type': 'application/json'}, timeout=15
            )

            if response.status_code != 200:
                return Response({'error': 'Token refresh failed', 'detail': response.text},
                                status=status.HTTP_400_BAD_REQUEST)

            return Response(response.json(), status=status.HTTP_200_OK)

        except Exception as e:
            logger.exception("Jira token refresh failed")
            return Response({'error': 'Token refresh failed', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- DISCONNECT JIRA --------------------
class JiraDisconnectView(APIView):
    """Remove saved Jira tokens from user account"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            from .utils import JiraTokenManager
            if not request.user or not request.user.is_authenticated:
                return Response({'message': 'Jira disconnected successfully'}, status=status.HTTP_200_OK)
            JiraTokenManager.delete_token(request.user)
            return Response({'message': 'Jira disconnected successfully'}, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception("Jira disconnect failed")
            return Response({'error': 'Disconnect failed', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- GET / UPDATE / DELETE PROJECT --------------------
class JiraGetProjectView(APIView):
    """Get a single Jira project by project key"""
    permission_classes = [AllowAny]

    def get(self, request, project_key):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project/{project_key}"
            response = _http_get(url, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }, timeout=15)

            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to get Jira project")
            return Response({'error': 'Failed to get project', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class JiraUpdateProjectView(APIView):
    """Update a Jira project"""
    permission_classes = [AllowAny]

    def patch(self, request, project_key):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project/{project_key}"
            response = _http_put(url, json=request.data, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }, timeout=15)

            jira_data = response.json()
            if response.status_code in [200, 201]:
                jira_data['name'] = request.data.get('name', jira_data.get('name', ''))
                jira_data['description'] = request.data.get('description', jira_data.get('description', ''))
            return Response(jira_data, status=response.status_code)

        except Exception as e:
            logger.exception("Failed to update Jira project")
            return Response({'error': 'Failed to update project', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class JiraDeleteProjectView(APIView):
    """Delete a Jira project"""
    permission_classes = [AllowAny]

    def delete(self, request, project_key):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/project/{project_key}"
            response = _http_delete(url, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }, timeout=15)

            if response.status_code == 204:
                return Response({'message': 'Project deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to delete Jira project")
            return Response({'error': 'Failed to delete project', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- COMMENTS --------------------
class JiraListCommentsView(APIView):
    """List all comments on a Jira issue"""
    permission_classes = [AllowAny]

    def get(self, request, issue_key):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/comment"
            response = _http_get(url, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }, timeout=15)

            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to list Jira comments")
            return Response({'error': 'Failed to list comments', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class JiraUpdateCommentView(APIView):
    """Update a comment on a Jira issue"""
    permission_classes = [AllowAny]

    def put(self, request, issue_key, comment_id):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')
            comment_text = request.data.get('comment')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)
            if not comment_text:
                return Response({'error': 'comment field is required'}, status=status.HTTP_400_BAD_REQUEST)

            comment_data = {
                'body': {
                    'type': 'doc',
                    'version': 1,
                    'content': [{'type': 'paragraph', 'content': [{'type': 'text', 'text': comment_text}]}]
                }
            }

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/comment/{comment_id}"
            response = _http_put(url, json=comment_data, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }, timeout=15)

            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to update Jira comment")
            return Response({'error': 'Failed to update comment', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class JiraDeleteCommentView(APIView):
    """Delete a comment from a Jira issue"""
    permission_classes = [AllowAny]

    def delete(self, request, issue_key, comment_id):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/comment/{comment_id}"
            response = _http_delete(url, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }, timeout=15)

            if response.status_code == 204:
                return Response({'message': 'Comment deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to delete Jira comment")
            return Response({'error': 'Failed to delete comment', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# -------------------- TRANSITIONS --------------------
class JiraListTransitionsView(APIView):
    """List available transitions (statuses) for a Jira issue"""
    permission_classes = [AllowAny]

    def get(self, request, issue_key):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)

            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/transitions"
            response = _http_get(url, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json'
            }, timeout=15)

            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to list Jira transitions")
            return Response({'error': 'Failed to list transitions', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class JiraTransitionIssueView(APIView):
    """Transition (change status of) a Jira issue"""
    permission_classes = [AllowAny]

    def post(self, request, issue_key):
        try:
            access_token = request.headers.get('Jira-Access-Token')
            cloud_id = request.headers.get('Jira-Cloud-Id')
            transition_id = request.data.get('transition_id')

            if not access_token or not cloud_id:
                return Response({'error': 'Access token and cloud ID required'}, status=status.HTTP_400_BAD_REQUEST)
            if not transition_id:
                return Response({'error': 'transition_id is required'}, status=status.HTTP_400_BAD_REQUEST)

            payload = {'transition': {'id': str(transition_id)}}
            url = f"https://api.atlassian.com/ex/jira/{cloud_id}/rest/api/3/issue/{issue_key}/transitions"
            response = _http_post(url, json=payload, headers={
                'Authorization': f'Bearer {access_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }, timeout=15)

            if response.status_code == 204:
                return Response({'message': 'Issue status changed successfully'}, status=status.HTTP_200_OK)
            return Response(response.json(), status=response.status_code)

        except Exception as e:
            logger.exception("Failed to transition Jira issue")
            return Response({'error': 'Failed to transition issue', 'detail': str(e)},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@method_decorator(csrf_exempt, name='dispatch')
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
        try:
            logger.info(f"[SlackEvents] POST received — content_type={request.content_type} method={request.method}")
            payload = request.data
            logger.info(f"[SlackEvents] Payload keys={list(payload.keys()) if isinstance(payload, dict) else type(payload).__name__}")
            event_type = payload.get("type") if isinstance(payload, dict) else None
            logger.info(f"[SlackEvents] event_type={event_type}")

            # URL verification must be handled BEFORE signature check —
            # Slack sends this during setup to confirm the endpoint is reachable.
            if event_type == "url_verification":
                logger.info("[SlackEvents] Handling url_verification challenge")
                return Response({"challenge": payload.get("challenge")})

            sig_ok = self._verify_signature(request)
            logger.info(f"[SlackEvents] Signature verification result={sig_ok}")
            if not sig_ok:
                # Log warning but DO NOT block — wrong SLACK_SIGNING_SECRET causes 403 which
                # stops all event processing. Allow events through with a warning so Slack
                # channel invites and member-join events still save users to DB.
                logger.warning("[SlackEvents] Slack signature verification FAILED — processing anyway. Fix SLACK_SIGNING_SECRET in .env to enforce verification.")

            # Handle event callbacks — run in background so Slack gets 200 immediately
            if event_type == "event_callback":
                event = payload.get("event", {})
                team_id = payload.get("team_id", event.get("team", ""))
                logger.info(f"[SlackEvents] event_callback: event_type={event.get('type')} team_id={team_id}")
                threading.Thread(
                    target=self._handle_event,
                    args=(event, team_id),
                    daemon=True,
                ).start()
            else:
                logger.info(f"[SlackEvents] Unhandled top-level type={event_type} — ignoring")

            return Response({"ok": True})

        except Exception as _exc:
            logger.exception(f"[SlackEvents] UNHANDLED EXCEPTION in post(): {_exc}")
            return Response({"ok": True})  # Always return 200 to Slack to prevent retries

    def _verify_signature(self, request):
        signing_secret = getattr(settings, "SLACK_SIGNING_SECRET", "")
        if not signing_secret:
            logger.warning("[SlackEvents] SLACK_SIGNING_SECRET not set — skipping signature check (INSECURE)")
            return True  # skip verification if not configured
        timestamp = request.headers.get("X-Slack-Request-Timestamp", "")
        signature = request.headers.get("X-Slack-Signature", "")
        logger.debug(f"[SlackEvents] _verify_signature: timestamp={timestamp} signature_present={bool(signature)}")
        # Reject requests older than 5 minutes
        try:
            age = abs(time.time() - int(timestamp))
            logger.debug(f"[SlackEvents] Request age={age:.1f}s")
            if age > 300:
                logger.warning(f"[SlackEvents] Request too old: {age:.1f}s — rejecting")
                return False
        except (ValueError, TypeError) as e:
            logger.warning(f"[SlackEvents] Bad timestamp={timestamp!r}: {e}")
            return False
        try:
            body = request._request.body.decode("utf-8")
        except Exception as e:
            logger.error(f"[SlackEvents] Could not read raw body: {e}")
            return False
        base = f"v0:{timestamp}:{body}"
        computed = "v0=" + hmac.new(
            signing_secret.encode(), base.encode(), hashlib.sha256
        ).hexdigest()
        match = hmac.compare_digest(computed, signature)
        logger.debug(f"[SlackEvents] HMAC match={match}")
        return match

    def _handle_event(self, event, team_id=""):
        try:
            from users_details.models import UserDetail
            etype = event.get("type")
            logger.info(f"[SlackEvent] _handle_event: etype={etype} team_id={team_id} event_keys={list(event.keys())}")

            if etype == "channel_created":
                logger.info(f"[SlackEvent] channel_created: name={event.get('channel', {}).get('name')}")

            elif etype == "channel_rename":
                ch = event.get("channel", {})
                new_id = ch.get("id")
                new_name = ch.get("name")
                logger.info(f"[SlackEvent] channel_rename: id={new_id} new_name={new_name}")
                for ud in UserDetail.objects.filter(slack_channel_ids__contains=new_id):
                    logger.info(f"[SlackEvent] Updated channel name for UserDetail {ud._id}")

            elif etype in ("channel_deleted", "channel_archive"):
                ch_id = event.get("channel")
                logger.info(f"[SlackEvent] {etype}: channel_id={ch_id}")
                for ud in UserDetail.objects.filter(slack_channel_ids__contains=ch_id):
                    ids = list(ud.slack_channel_ids or [])
                    ids.remove(ch_id)
                    ud.slack_channel_ids = ids
                    ud.save()

            elif etype == "channel_unarchive":
                logger.info(f"[SlackEvent] channel_unarchive: channel={event.get('channel')}")

            elif etype == "team_join":
                user_obj = event.get("user", {})
                if isinstance(user_obj, dict):
                    slack_user_id = user_obj.get("id")
                else:
                    slack_user_id = user_obj
                tid = team_id or event.get("team", "")
                logger.info(f"[SlackEvent] team_join: slack_user_id={slack_user_id} tid={tid}")
                self._save_slack_member_to_user_detail(slack_user_id, tid)

            elif etype == "member_joined_channel":
                slack_user_id = event.get("user")
                channel_id = event.get("channel")
                tid = team_id or event.get("team", "")
                logger.info(f"[SlackEvent] member_joined_channel: slack_user_id={slack_user_id} channel_id={channel_id} tid={tid}")
                self._save_slack_member_to_user_detail(slack_user_id, tid, channel_id=channel_id)

                # If it's the BOT itself joining #vaptfix-admin-dashboard (not
                # a human member), auto-post the clickable navbar+dashboard
                # message — this is the one-time trigger that replaces
                # needing to type /dashboard at all.
                admin = User.objects.filter(slack_team_id=tid).first()
                if admin and admin.slack_bot_token:
                    bot_user_id = self._get_bot_user_id(admin.slack_bot_token)
                    if bot_user_id and slack_user_id == bot_user_id:
                        channel_name = self._get_channel_name(admin.slack_bot_token, channel_id)
                        if channel_name == SlackSlashCommandView.ADMIN_CHANNEL:
                            self._post_admin_navbar_message(admin.slack_bot_token, channel_id, tid)

            elif etype == "member_left_channel":
                logger.info(f"[SlackEvent] member_left_channel: user={event.get('user')} channel={event.get('channel')}")

            elif etype == "app_home_opened":
                slack_user_id = event.get("user")
                logger.info(f"[SlackEvent] app_home_opened: slack_user_id={slack_user_id} team_id={team_id}")
                admin = User.objects.filter(slack_team_id=team_id).first()
                if admin and admin.slack_bot_token:
                    self._publish_app_home(admin.slack_bot_token, slack_user_id)
                else:
                    logger.warning(f"[SlackEvent] app_home_opened: no admin/bot_token for team_id={team_id}")

            elif etype == "app_mention":
                channel = event.get("channel")
                thread_ts = event.get("ts")
                slack_user_id = event.get("user")
                logger.info(f"[SlackEvent] app_mention: channel={channel} slack_user_id={slack_user_id}")
                admin = User.objects.filter(slack_team_id=team_id).first()
                if admin and admin.slack_bot_token:
                    self._reply_to_mention(admin.slack_bot_token, channel, thread_ts, slack_user_id)
                else:
                    logger.warning(f"[SlackEvent] app_mention: no admin/bot_token for team_id={team_id}")

            else:
                logger.info(f"[SlackEvent] Unhandled event type={etype}")

        except Exception as _exc:
            logger.exception(f"[SlackEvent] UNHANDLED EXCEPTION in _handle_event: etype={event.get('type')} error={_exc}")

    def _get_bot_user_id(self, bot_token):
        """
        Resolves the bot's own Slack user ID via auth.test — needed to tell
        apart "the bot itself joined this channel" from "a human teammate
        joined this channel" in member_joined_channel, since Slack's event
        payload only gives a user ID, not who/what that ID belongs to.
        """
        try:
            resp = _http_get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": f"Bearer {bot_token}"},
                timeout=10,
            )
            data = resp.json() if resp else {}
            return data.get("user_id") if data.get("ok") else None
        except Exception:
            logger.exception("[SlackEvent] _get_bot_user_id failed")
            return None

    def _get_channel_name(self, bot_token, channel_id):
        """Resolves a channel ID to its name (member_joined_channel only gives the ID)."""
        try:
            resp = _http_get(
                "https://slack.com/api/conversations.info",
                headers={"Authorization": f"Bearer {bot_token}"},
                params={"channel": channel_id},
                timeout=10,
            )
            data = resp.json() if resp else {}
            return (data.get("channel") or {}).get("name") if data.get("ok") else None
        except Exception:
            logger.exception("[SlackEvent] _get_channel_name failed")
            return None

    def _post_admin_navbar_message(self, bot_token, channel_id, team_id):
        """
        Auto-posts the clickable navbar + default "Home" dashboard content
        into #vaptfix-admin-dashboard the moment the bot is added to that
        channel — this is the one-time trigger that replaces needing to
        type /dashboard. Reuses SlackSlashCommandView's nav helpers so the
        content always matches the equivalent slash commands exactly.
        """
        slash = SlackSlashCommandView()
        try:
            section_blocks = slash._nav_section_blocks("nav_home", team_id, user_id=None)
            blocks = slash._nav_buttons_block(active_action_id="nav_home") + section_blocks
            resp = _http_post(
                "https://slack.com/api/chat.postMessage",
                headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
                json={"channel": channel_id, "blocks": blocks, "text": "VaptFix Admin Dashboard"},
                timeout=15,
            )
            data = resp.json() if resp else {}
            if data.get("ok") and data.get("ts"):
                # Pin it so it's always easy to find at the top of the channel —
                # best-effort, a failure here shouldn't block the dashboard post.
                try:
                    _http_post(
                        "https://slack.com/api/pins.add",
                        headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
                        json={"channel": channel_id, "timestamp": data["ts"]},
                        timeout=10,
                    )
                except Exception:
                    logger.exception("[SlackEvent] Failed to pin navbar message")
            elif not data.get("ok"):
                logger.warning(f"[SlackEvent] chat.postMessage for navbar failed: {data.get('error')}")
        except Exception:
            logger.exception("[SlackEvent] _post_admin_navbar_message failed")

    def _publish_app_home(self, bot_token, slack_user_id):
        """Publish a welcome App Home tab view when user opens VaptFix in Slack sidebar."""
        frontend_url = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai")
        view = {
            "type": "home",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "Welcome to VaptFix", "emoji": True},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": "*VaptFix* is an AI-powered vulnerability management platform.\nTrack, prioritize, and fix security vulnerabilities — all from Slack.",
                    },
                },
                {"type": "divider"},
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ":bar_chart: *What you can do:*\n• View your vulnerability reports\n• Get notified of new critical findings\n• Assign fixes to your team",
                    },
                },
                {
                    "type": "actions",
                    "elements": [
                        {
                            "type": "button",
                            "text": {"type": "plain_text", "text": "Open VaptFix Dashboard", "emoji": True},
                            "url": frontend_url,
                            "action_id": "open_dashboard",
                            "style": "primary",
                        }
                    ],
                },
            ],
        }
        try:
            _http_post(
                "https://slack.com/api/views.publish",
                json={"user_id": slack_user_id, "view": view},
                headers={"Authorization": f"Bearer {bot_token}"},
                timeout=10,
            )
        except Exception:
            logger.exception(f"[SlackEvent] Failed to publish App Home for user={slack_user_id}")

    def _reply_to_mention(self, bot_token, channel, thread_ts, slack_user_id):
        """Reply in thread when someone mentions @VaptFix in a Slack channel."""
        frontend_url = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai")
        text = (
            f"Hi <@{slack_user_id}>! :wave:\n"
            f"I'm VaptFix — your AI-powered vulnerability management assistant.\n"
            f"Open your dashboard here: {frontend_url}"
        )
        try:
            _http_post(
                "https://slack.com/api/chat.postMessage",
                json={"channel": channel, "thread_ts": thread_ts, "text": text},
                headers={"Authorization": f"Bearer {bot_token}"},
                timeout=10,
            )
        except Exception:
            logger.exception(f"[SlackEvent] Failed to reply to app_mention in channel={channel}")

    def _resolve_channel_team_role(self, bot_token, channel_id):
        """
        Resolve a Slack channel_id to its team name using the same
        TEAM_CHANNELS mapping the slash commands use (e.g.
        "vaptfix-network-security-team" -> "Network Security"). Returns
        None if the channel isn't one of the 4 team channels (e.g. #general,
        #vaptfix-admin-dashboard) — caller should fall back to "Viewer".
        """
        if not channel_id:
            return None
        try:
            resp = _http_get(
                "https://slack.com/api/conversations.info",
                params={"channel": channel_id},
                headers={"Authorization": f"Bearer {bot_token}"},
                timeout=10,
            )
            data = resp.json() if resp is not None else {}
            if not data.get("ok"):
                logger.warning(f"[SlackEvent] conversations.info failed for channel_id={channel_id}: {data.get('error')}")
                return None
            channel_name = (data.get("channel") or {}).get("name", "")
            return SlackSlashCommandView.TEAM_CHANNELS.get(channel_name)
        except Exception:
            logger.exception(f"[SlackEvent] _resolve_channel_team_role failed for channel_id={channel_id}")
            return None

    def _save_slack_member_to_user_detail(self, slack_user_id, team_id, channel_id=None):
        """
        When a member joins a Slack channel:
        1. Find the admin who owns this workspace (by slack_team_id)
        2. Fetch user info from Slack
        3. Resolve the channel they joined to a team (Network Security etc.)
        4. Save to UserDetail (if not already exists) with that team as
           Member_role — falls back to "Viewer" only for non-team channels
        5. Create Django User + generate set-password link
        6. Send same welcome email that normal user-add flow sends
        """
        try:
            logger.info(f"[SlackEvent] _save_slack_member_to_user_detail: slack_user_id={slack_user_id} team_id={team_id} channel_id={channel_id}")

            if not slack_user_id or not team_id:
                logger.warning(f"[SlackEvent] Missing slack_user_id={slack_user_id} or team_id={team_id} — aborting")
                return

            # Find admin who owns this Slack workspace
            admin = User.objects.filter(slack_team_id=team_id).first()
            if not admin:
                logger.error(f"[SlackEvent] No admin found for team_id={team_id} — check slack_team_id field in DB. All admins with slack_team_id: {list(User.objects.exclude(slack_team_id=None).values_list('email','slack_team_id'))}")
                return
            logger.info(f"[SlackEvent] Found admin: email={admin.email} id={admin.id} slack_team_id={admin.slack_team_id}")

            if not admin.slack_bot_token:
                logger.error(f"[SlackEvent] Admin {admin.email} has no slack_bot_token — cannot call Slack API")
                return

            # Fetch user profile from Slack
            logger.info(f"[SlackEvent] Calling users.info for slack_user_id={slack_user_id}")
            user_info_resp = _http_get(
                "https://slack.com/api/users.info",
                params={"user": slack_user_id},
                headers={"Authorization": f"Bearer {admin.slack_bot_token}"},
                timeout=10,
            )
            user_info = user_info_resp.json() if user_info_resp is not None else {}
            logger.info(f"[SlackEvent] users.info response: ok={user_info.get('ok')} error={user_info.get('error')}")

            if not user_info.get("ok"):
                logger.error(f"[SlackEvent] users.info FAILED for slack_user_id={slack_user_id}: error={user_info.get('error')} — user will NOT be saved")
                return

            user_data = user_info.get("user", {})
            logger.info(f"[SlackEvent] user_data: is_bot={user_data.get('is_bot')} deleted={user_data.get('deleted')} name={user_data.get('real_name')}")

            # Skip bots and deleted accounts
            if user_data.get("is_bot") or user_data.get("deleted"):
                logger.info(f"[SlackEvent] Skipping bot/deleted user slack_user_id={slack_user_id}")
                return

            profile = user_data.get("profile", {})
            email = profile.get("email")
            if not email:
                logger.error(f"[SlackEvent] No email in Slack profile for slack_user_id={slack_user_id} — missing users:read.email scope? profile_keys={list(profile.keys())}")
                return
            logger.info(f"[SlackEvent] Member email={email} name={user_data.get('real_name')}")

            name = user_data.get("real_name") or profile.get("display_name") or "Slack User"
            parts = name.strip().split()
            first_name = parts[0] if parts else "Slack"
            last_name = " ".join(parts[1:]) if len(parts) > 1 else "User"

            # Resolve which team (if any) this channel belongs to, so
            # Member_role reflects the actual team channel the admin invited
            # them to instead of always defaulting to "Viewer".
            resolved_team = self._resolve_channel_team_role(admin.slack_bot_token, channel_id)
            initial_roles = [resolved_team] if resolved_team else ["Viewer"]
            logger.info(f"[SlackEvent] channel_id={channel_id} resolved_team={resolved_team}")

            # Save to UserDetail — skip if already exists for this admin+email
            from users_details.models import UserDetail
            logger.info(f"[SlackEvent] Calling get_or_create for admin={admin.email} email={email}")
            try:
                user_detail, created = UserDetail.objects.get_or_create(
                    admin=admin,
                    email=email,
                    defaults={
                        "first_name": first_name,
                        "last_name": last_name,
                        "user_type": "external",
                        "Member_role": initial_roles,
                        "platform": "slack",
                        "slack_member_id": slack_user_id,
                        "slack_channel_ids": [channel_id] if channel_id else [],
                    }
                )
                logger.info(f"[SlackEvent] get_or_create done: created={created} user_detail_id={user_detail._id}")
            except Exception as _goc_exc:
                logger.exception(f"[SlackEvent] get_or_create FAILED for admin={admin.email} email={email}: {_goc_exc}")
                return

            if not created:
                logger.info(f"[SlackEvent] UserDetail already exists for {email} — updating platform fields")
                _upd = {}
                if user_detail.email != email and not UserDetail.objects.filter(admin=admin, email=email).exclude(_id=user_detail._id).exists():
                    _upd["email"] = email
                if not user_detail.slack_member_id:
                    _upd["slack_member_id"] = slack_user_id
                if not user_detail.platform:
                    _upd["platform"] = "slack"
                # Joined another team's channel — add that team to their
                # existing roles instead of leaving them stuck on "Viewer"
                # (or missing this newer team) forever.
                if resolved_team:
                    existing_roles = list(user_detail.Member_role or [])
                    if resolved_team not in existing_roles:
                        existing_roles = [r for r in existing_roles if r != "Viewer"]
                        existing_roles.append(resolved_team)
                        _upd["Member_role"] = existing_roles
                if channel_id:
                    existing_ids = list(user_detail.slack_channel_ids or [])
                    if channel_id not in existing_ids:
                        existing_ids.append(channel_id)
                        _upd["slack_channel_ids"] = existing_ids
                if _upd:
                    logger.info(f"[SlackEvent] Updating existing UserDetail fields: {list(_upd.keys())}")
                    from users_details.views import _ud_set as _ud_set_event
                    _ud_set_event(user_detail, **_upd)
                logger.info(f"[SlackEvent] UserDetail already existed for {email} — email skipped")
                return

            logger.info(f"[SlackEvent] ✅ Created NEW UserDetail for {email} under admin {admin.email}")

            _email = email
            _first = first_name
            _last = last_name
            _admin_email = getattr(admin, "email", "")
            _roles = initial_roles

            def _send_slack_event_emails():
                try:
                    from django.contrib.auth import get_user_model
                    from django.utils.http import urlsafe_base64_encode
                    from django.utils.encoding import force_bytes
                    from django.contrib.auth.tokens import PasswordResetTokenGenerator
                    from users_details.views import UserDetailCreateView

                    UserModel = get_user_model()
                    django_user, u_created = UserModel.objects.get_or_create(
                        email=_email, defaults={"is_active": True}
                    )
                    if u_created:
                        django_user.set_unusable_password()
                        django_user.save()

                    uid = urlsafe_base64_encode(force_bytes(django_user.pk))
                    token = PasswordResetTokenGenerator().make_token(django_user)
                    frontend_url = getattr(settings, 'FRONTEND_URL', 'https://vaptfix.ai')
                    set_password_url = f"{frontend_url}/auth?mode=set-password&uid={uid}&token={token}"

                    view = UserDetailCreateView()
                    email_sent, error = view.send_welcome_email(
                        email=_email, first_name=_first, last_name=_last,
                        roles=_roles, set_password_url=set_password_url,
                    )
                    if email_sent:
                        logger.info(f"[SlackEvent] Set-password email sent to {_email}")
                    else:
                        logger.warning(f"[SlackEvent] Set-password email failed for {_email}: {error}")

                    view.send_team_welcome_emails(
                        email=_email, first_name=_first, last_name=_last,
                        roles=_roles, admin_email=_admin_email,
                    )
                except Exception:
                    logger.exception(f"[SlackEvent] Email thread failed for {_email}")

            threading.Thread(target=_send_slack_event_emails, daemon=True).start()

        except Exception:
            logger.exception(f"[SlackEvent] _save_slack_member_to_user_detail failed for user={slack_user_id}")


class SlackInstallView(APIView):
    """
    GET /api/users/slack/install/
    'Add to Slack' marketplace entry point. Redirects any user directly to the Slack
    OAuth authorization screen — no VaptFix login required. Used as the 'Add to Slack'
    button URL in the Slack App Directory listing.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def get(self, request):
        state_data = {"nonce": str(uuid.uuid4()), "source": "marketplace"}
        state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

        redirect_uri = getattr(settings, "SLACK_REDIRECT_URI", "")
        if not redirect_uri:
            redirect_uri = request.build_absolute_uri("/").rstrip("/") + "/api/admin/users/slack/callback/"

        scopes = ",".join(getattr(settings, "SLACK_SCOPES", [
            "chat:write", "channels:manage", "channels:join",
            "mpim:write", "groups:write", "im:write",
            "users:read", "users:read.email", "commands", "files:write",
        ]))
        user_scopes = "identity.basic,identity.email,identity.avatar,identity.team"

        auth_url = (
            f"https://slack.com/oauth/v2/authorize"
            f"?client_id={settings.SLACK_CLIENT_ID}"
            f"&scope={scopes}"
            f"&user_scope={user_scopes}"
            f"&redirect_uri={redirect_uri}"
            f"&state={state}"
        )
        return redirect(auth_url)


class SlackMemberLoginView(APIView):
    """
    POST /api/users/slack/member-login/
    Allows a team member (non-admin) to login via Slack OAuth.
    Flow: member clicks "Login with Slack" → Slack OAuth → callback → this view
          matches slack_user_id in UserDetail → returns JWT.

    Body: { "slack_user_id": "U12345", "slack_team_id": "T12345", "bot_token": "xoxb-..." }
    Response: { "access_token": "...", "refresh_token": "...", "user": {...} }
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        slack_user_id = request.data.get("slack_user_id")
        slack_team_id = request.data.get("slack_team_id")
        bot_token = request.data.get("bot_token")

        if not slack_user_id or not slack_team_id:
            return Response({"error": "slack_user_id and slack_team_id are required"}, status=status.HTTP_400_BAD_REQUEST)

        from users_details.models import UserDetail

        # Find admin for this workspace
        admin = User.objects.filter(slack_team_id=slack_team_id).first()
        if not admin:
            return Response({"error": "No VaptFix account found for this Slack workspace"}, status=status.HTTP_404_NOT_FOUND)

        # Find member by slack_member_id
        user_detail = UserDetail.objects.filter(admin=admin, slack_member_id=slack_user_id).first()

        if not user_detail:
            # Fallback: fetch email from Slack API and match by email
            if not bot_token:
                bot_token = admin.slack_bot_token
            if bot_token:
                try:
                    info = _http_get(
                        "https://slack.com/api/users.info",
                        params={"user": slack_user_id},
                        headers={"Authorization": f"Bearer {bot_token}"},
                        timeout=10,
                    ).json()
                    if info.get("ok"):
                        email = info.get("user", {}).get("profile", {}).get("email")
                        if email:
                            user_detail = UserDetail.objects.filter(admin=admin, email=email).first()
                            if user_detail and not user_detail.slack_member_id:
                                user_detail.slack_member_id = slack_user_id
                                user_detail.platform = "slack"
                                user_detail.save(update_fields=["slack_member_id", "platform"])
                except Exception:
                    logger.exception("[SlackMemberLogin] Failed to fetch user info from Slack")

        if not user_detail:
            return Response({"error": "Member not found in VaptFix. Please ask your admin to add you first."}, status=status.HTTP_404_NOT_FOUND)

        # Platform conflict check for member
        member_platform = user_detail.platform or ""
        if member_platform == "microsoft_teams":
            return Response({"error": "Your account is set up for Microsoft Teams login. Please sign in using Microsoft Teams.", "platform_conflict": True}, status=status.HTTP_400_BAD_REQUEST)
        if member_platform == "email":
            return Response({"error": "Your account uses email login. Please sign in with your email and password.", "platform_conflict": True}, status=status.HTTP_400_BAD_REQUEST)

        # Get or create Django User for this member
        member_user, _ = User.objects.get_or_create(
            email=user_detail.email,
            defaults={"is_active": True, "login_provider": "slack"},
        )
        member_user.login_provider = "slack"
        member_user.slack_user_id = slack_user_id
        member_user.slack_team_id = slack_team_id
        member_user.save(update_fields=["login_provider", "slack_user_id", "slack_team_id"])

        refresh = RefreshToken.for_user(member_user)
        return Response({
            "success": True,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "user": {
                "id": str(member_user.id),
                "email": member_user.email,
                "first_name": user_detail.first_name,
                "last_name": user_detail.last_name,
                "platform": "slack",
                "role": "member",
                "admin_id": str(admin.id),
            },
        })


class TeamsMemberLoginView(APIView):
    """
    POST /api/users/teams/member-login/
    Allows a team member (non-admin) to login via Microsoft Teams OAuth.
    Flow: member clicks "Login with Teams" → Teams OAuth → callback → this view
          matches ms_teams_member_id in UserDetail → returns JWT.

    Body: { "ms_user_id": "aad-object-id", "email": "user@company.com", "access_token": "..." }
    Response: { "access_token": "...", "refresh_token": "...", "user": {...} }
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    def post(self, request):
        ms_user_id = request.data.get("ms_user_id", "")
        email = request.data.get("email", "").strip().lower()
        ms_access_token = request.data.get("access_token", "")

        if not email:
            return Response({"error": "email is required"}, status=status.HTTP_400_BAD_REQUEST)

        from users_details.models import UserDetail

        # Find member by ms_teams_member_id OR email
        user_detail = None
        if ms_user_id:
            user_detail = UserDetail.objects.filter(ms_teams_member_id=ms_user_id).first()
        if not user_detail and email:
            user_detail = UserDetail.objects.filter(email=email).first()

        if not user_detail:
            return Response({"error": "Member not found in VaptFix. Please ask your admin to add you first."}, status=status.HTTP_404_NOT_FOUND)

        # Platform conflict check for member
        member_platform = user_detail.platform or ""
        if member_platform == "slack":
            return Response({"error": "Your account is set up for Slack login. Please sign in using Slack.", "platform_conflict": True}, status=status.HTTP_400_BAD_REQUEST)
        if member_platform == "email":
            return Response({"error": "Your account uses email login. Please sign in with your email and password.", "platform_conflict": True}, status=status.HTTP_400_BAD_REQUEST)

        admin = user_detail.admin
        if admin.login_provider != "microsoft_teams":
            return Response({"error": "Your admin is not using Microsoft Teams platform."}, status=status.HTTP_400_BAD_REQUEST)

        # Update ms_teams_member_id if missing
        if ms_user_id and not user_detail.ms_teams_member_id:
            user_detail.ms_teams_member_id = ms_user_id
            user_detail.platform = "microsoft_teams"
            user_detail.save(update_fields=["ms_teams_member_id", "platform"])

        # Get or create Django User for this member
        member_user, _ = User.objects.get_or_create(
            email=user_detail.email,
            defaults={"is_active": True, "login_provider": "microsoft_teams"},
        )
        member_user.login_provider = "microsoft_teams"
        if ms_access_token:
            member_user.ms_access_token = ms_access_token
        member_user.save(update_fields=["login_provider", "ms_access_token"])

        refresh = RefreshToken.for_user(member_user)
        return Response({
            "success": True,
            "access_token": str(refresh.access_token),
            "refresh_token": str(refresh),
            "user": {
                "id": str(member_user.id),
                "email": member_user.email,
                "first_name": user_detail.first_name,
                "last_name": user_detail.last_name,
                "platform": "microsoft_teams",
                "role": "member",
                "admin_id": str(admin.id),
            },
        })


class CreateTeamsSubscriptionView(APIView):
    """
    POST /api/users/teams/webhook/subscribe/
    Admin calls this once after connecting Teams to subscribe to team member changes.
    Required body: { "team_id": "<Teams team ID>" }
    Saves team_id on admin's User record and creates MS Graph change notification subscription.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        team_id = request.data.get("team_id")
        if not team_id:
            logger.error("[TeamsSubscribe] Missing team_id in request")
            return Response({"error": "team_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        access_token = request.user.ms_access_token
        logger.info(f"[TeamsSubscribe] admin={request.user.email} team_id={team_id} access_token_set={bool(access_token)}")
        if not access_token:
            logger.error(f"[TeamsSubscribe] No ms_access_token for admin={request.user.email} — Teams not connected")
            return Response({"error": "Microsoft Teams not connected. Please connect Teams first."}, status=status.HTTP_400_BAD_REQUEST)

        # Save team_id on admin's user record using filter().update() for reliability
        User.objects.filter(pk=request.user.pk).update(ms_team_id=team_id)
        request.user.ms_team_id = team_id

        # Webhook notification URL (must be HTTPS and publicly accessible)
        notification_url = f"{settings.BACKEND_BASE_URL}/api/admin/users/teams/webhook/"
        logger.info(f"[TeamsSubscribe] notification_url={notification_url}")

        payload = {
            "changeType": "created",
            "notificationUrl": notification_url,
            "resource": f"teams/{team_id}/members",
            "expirationDateTime": self._expiry_datetime(),
            "clientState": str(request.user.id),
        }
        logger.info(f"[TeamsSubscribe] Graph payload: {payload}")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        }

        resp = _http_post(
            "https://graph.microsoft.com/v1.0/subscriptions",
            headers=headers,
            json=payload,
            timeout=15,
        )
        logger.info(f"[TeamsSubscribe] Graph response: status={resp.status_code} body={resp.text[:500]}")

        # --- Immediate member sync (Slack-style) ---
        # Regardless of whether the subscription succeeds, sync all existing team
        # members to DB right now so no one is missed even if webhooks never fire.
        sync_result = self._sync_existing_members(request.user, team_id, access_token)
        logger.info(f"[TeamsSubscribe] Immediate member sync: {sync_result}")

        if resp.status_code in (200, 201):
            logger.info(f"[TeamsSubscribe] ✅ Subscription created for team={team_id} admin={request.user.email}")
            return Response({
                "message": "Teams webhook subscription created successfully.",
                "subscription": resp.json(),
                "members_synced": sync_result,
            }, status=status.HTTP_201_CREATED)

        logger.error(f"[TeamsSubscribe] ❌ Subscription FAILED: status={resp.status_code} body={resp.text}")
        # Even if subscription fails, members were synced above — return partial success
        return Response({
            "warning": "Webhook subscription failed but existing team members were synced to DB.",
            "subscription_error": resp.text,
            "graph_status": resp.status_code,
            "members_synced": sync_result,
        }, status=status.HTTP_200_OK)

    def _sync_existing_members(self, admin, team_id, access_token):
        """
        Slack-style immediate sync: fetch all current team members from MS Graph
        and save them to UserDetail. Called on every subscribe attempt so DB stays
        in sync even when webhook subscriptions fail.
        """
        from users_details.models import UserDetail
        headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}
        synced = []
        try:
            members_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"
            resp = _http_get(members_url, headers=headers, timeout=15)
            if resp.status_code != 200:
                logger.warning(f"[TeamsSubscribe] Could not fetch members: status={resp.status_code} body={resp.text[:200]}")
                return {"error": f"Graph status {resp.status_code}", "synced_count": 0}

            members = resp.json().get("value", [])
            logger.info(f"[TeamsSubscribe] Fetched {len(members)} team members for team={team_id}")

            for member in members:
                email = (member.get("email") or "").strip().lower()
                display_name = member.get("displayName") or "Teams User"
                ms_user_id = member.get("userId") or member.get("id") or ""

                # Skip the admin themselves
                if email and email == (getattr(admin, "email", "") or "").strip().lower():
                    continue

                if not email or "@" not in email:
                    logger.warning(f"[TeamsSubscribe] Skipping member with no email: {member}")
                    continue

                name_parts = display_name.strip().split()
                first_name = name_parts[0] if name_parts else "Teams"
                last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"

                user_detail, created = UserDetail.objects.get_or_create(
                    admin=admin,
                    email=email,
                    defaults={
                        "first_name": first_name,
                        "last_name": last_name,
                        "user_type": "external",
                        "Member_role": ["Viewer"],
                        "platform": "microsoft_teams",
                        "team_id": team_id,
                        "ms_teams_member_id": ms_user_id,
                    }
                )
                if created:
                    logger.info(f"[TeamsSubscribe] ✅ Synced new member: {email} under admin={admin.email}")
                    synced.append({"email": email, "status": "created"})
                else:
                    # Update platform fields if missing
                    from users_details.views import _ud_set as _ud_set_sub
                    upd = {}
                    if not user_detail.platform:
                        upd["platform"] = "microsoft_teams"
                    if not user_detail.team_id:
                        upd["team_id"] = team_id
                    if ms_user_id and not user_detail.ms_teams_member_id:
                        upd["ms_teams_member_id"] = ms_user_id
                    if upd:
                        _ud_set_sub(user_detail, **upd)
                    synced.append({"email": email, "status": "already_exists"})

        except Exception as _exc:
            logger.exception(f"[TeamsSubscribe] Member sync failed: {_exc}")
            return {"error": str(_exc), "synced_count": len(synced)}

        return {"synced_count": len(synced), "members": synced}

    def _expiry_datetime(self):
        from datetime import datetime, timedelta, timezone as dt_timezone
        # Max allowed by MS Graph for teams/{id}/members is 4320 min (3 days)
        expiry = datetime.now(dt_timezone.utc) + timedelta(minutes=4230)
        return expiry.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class TeamsMemberSyncView(APIView):
    """
    POST /api/admin/users/teams/sync-members/
    Fast non-blocking sync: immediately returns 202 Accepted and runs the
    actual MS Graph fetch + DB save in a background thread (Slack-style).
    Required body: { "team_id": "<Teams team ID>" }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        team_id = request.data.get("team_id") or getattr(request.user, "ms_team_id", None)
        logger.info(f"[TeamsSyncMembers] admin={request.user.email} team_id={team_id}")

        if not team_id:
            return Response({"error": "team_id is required (or set ms_team_id on admin account)"}, status=status.HTTP_400_BAD_REQUEST)

        access_token = request.user.ms_access_token
        if not access_token:
            return Response({"error": "Microsoft Teams not connected. Please connect Teams first."}, status=status.HTTP_400_BAD_REQUEST)

        # Capture values before background thread (request object not safe across threads)
        _admin_id = str(request.user.pk)
        _admin_email = getattr(request.user, "email", "")
        _refresh_token = getattr(request.user, "ms_refresh_token", None)

        def _do_sync():
            from users_details.models import UserDetail
            from users_details.views import _ud_set as _ud_set_sync

            _access_token = access_token
            headers = {"Authorization": f"Bearer {_access_token}", "Content-Type": "application/json"}
            members_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"

            resp = _http_get(members_url, headers=headers, timeout=15)

            # Auto-refresh token on 401
            if resp is not None and resp.status_code == 401 and _refresh_token:
                logger.info(f"[TeamsSyncMembers] Token expired, refreshing for admin={_admin_email}")
                try:
                    token_resp = _http_post(
                        settings.MICROSOFT_TOKEN_URL,
                        data={
                            "grant_type": "refresh_token",
                            "client_id": settings.MICROSOFT_CLIENT_ID,
                            "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                            "refresh_token": _refresh_token,
                            "scope": "https://graph.microsoft.com/.default offline_access",
                        },
                        timeout=15,
                    )
                    new_data = token_resp.json() if token_resp else {}
                    new_token = new_data.get("access_token")
                    if new_token:
                        _access_token = new_token
                        headers["Authorization"] = f"Bearer {new_token}"
                        User.objects.filter(pk=_admin_id).update(
                            ms_access_token=new_token,
                            ms_refresh_token=new_data.get("refresh_token", _refresh_token),
                        )
                        resp = _http_get(members_url, headers=headers, timeout=15)
                except Exception as _te:
                    logger.warning(f"[TeamsSyncMembers] Token refresh failed: {_te}")

            if resp is None or resp.status_code != 200:
                logger.error(f"[TeamsSyncMembers] Failed to fetch members: status={getattr(resp,'status_code','?')} body={getattr(resp,'text','?')[:200]}")
                return

            try:
                admin_user = User.objects.get(pk=_admin_id)
            except User.DoesNotExist:
                logger.error(f"[TeamsSyncMembers] Admin not found: {_admin_id}")
                return

            members = resp.json().get("value", [])
            logger.info(f"[TeamsSyncMembers] Fetched {len(members)} members for team={team_id}")
            created_count = 0

            for member in members:
                email = (member.get("email") or "").strip().lower()
                display_name = member.get("displayName") or "Teams User"
                ms_user_id = member.get("userId") or member.get("id") or ""

                if not email or "@" not in email:
                    continue
                if email == _admin_email.strip().lower():
                    continue

                name_parts = display_name.strip().split()
                first_name = name_parts[0] if name_parts else "Teams"
                last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"

                try:
                    user_detail, created = UserDetail.objects.get_or_create(
                        admin=admin_user,
                        email=email,
                        defaults={
                            "first_name": first_name,
                            "last_name": last_name,
                            "user_type": "external",
                            "Member_role": ["Viewer"],
                            "platform": "microsoft_teams",
                            "team_id": team_id,
                            "ms_teams_member_id": ms_user_id,
                        }
                    )
                    if created:
                        logger.info(f"[TeamsSyncMembers] ✅ Created: {email}")
                        created_count += 1
                    else:
                        upd = {}
                        if not user_detail.platform:
                            upd["platform"] = "microsoft_teams"
                        if not user_detail.team_id:
                            upd["team_id"] = team_id
                        if ms_user_id and not user_detail.ms_teams_member_id:
                            upd["ms_teams_member_id"] = ms_user_id
                        if upd:
                            _ud_set_sync(user_detail, **upd)
                except Exception as _exc:
                    logger.exception(f"[TeamsSyncMembers] Failed to save {email}: {_exc}")

            logger.info(f"[TeamsSyncMembers] Done: total={len(members)} new={created_count}")

        # Run sync in background — response returns immediately (no wait)
        threading.Thread(target=_do_sync, daemon=True).start()
        return Response({
            "message": "Sync started in background. New members will appear shortly.",
            "team_id": team_id,
        }, status=status.HTTP_202_ACCEPTED)


class _PlainTextRenderer(BaseRenderer):
    """Renderer that satisfies Accept: text/plain for MS Graph webhook validation."""
    media_type = 'text/plain'
    format = 'txt'
    charset = 'utf-8'

    def render(self, data, accepted_media_type=None, renderer_context=None):
        if isinstance(data, str):
            return data.encode(self.charset)
        return data


class TeamsWebhookView(APIView):
    """
    GET  /api/users/teams/webhook/?validationToken=xxx  — MS Graph endpoint validation
    POST /api/users/teams/webhook/                      — Receive member-added notifications

    When a user is added directly on MS Teams:
    1. MS Graph sends notification here
    2. We fetch user's email via Graph API
    3. Save UserDetail in DB
    4. Create Django User + send set-password email
    """
    permission_classes = [AllowAny]
    authentication_classes = []
    renderer_classes = [_PlainTextRenderer, JSONRenderer]

    def dispatch(self, request, *args, **kwargs):
        # MS Graph validation: bypass DRF entirely for GET with validationToken.
        # Use raw QUERY_STRING to avoid Django decoding + as space.
        if request.method == "GET":
            raw_qs = request.META.get("QUERY_STRING", "")
            token = None
            for part in raw_qs.split("&"):
                if part.startswith("validationToken="):
                    token = part[len("validationToken="):]
                    break
            if token:
                return HttpResponse(token, content_type="text/plain; charset=utf-8", status=200)
            return HttpResponse("Missing validationToken", status=400)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request):
        notifications = request.data.get("value", [])
        logger.info(f"[TeamsWebhook] POST received: {len(notifications)} notification(s)")
        for notification in notifications:
            change_type = notification.get("changeType")
            client_state = notification.get("clientState", "")
            resource = notification.get("resource", "")
            logger.info(f"[TeamsWebhook] Notification: changeType={change_type} resource={resource} client_state={client_state[:20] if client_state else ''}")

            if change_type == "created" and "members" in resource:
                logger.info(f"[TeamsWebhook] Handling member_added: resource={resource}")
                self._handle_member_added(notification, client_state, resource)
            else:
                logger.info(f"[TeamsWebhook] Skipping notification: changeType={change_type} resource={resource}")

        return Response({"ok": True})

    def _refresh_admin_ms_token(self, admin):
        """Refresh admin Teams token for webhook Graph calls."""
        refresh_token = getattr(admin, "ms_refresh_token", None)
        if not refresh_token:
            return None
        try:
            token_payload = {
                "grant_type": "refresh_token",
                "client_id": settings.MICROSOFT_CLIENT_ID,
                "client_secret": settings.MICROSOFT_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "scope": "https://graph.microsoft.com/.default offline_access",
            }
            resp = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
            data = resp.json() if resp is not None else {}
            new_token = data.get("access_token")
            if not new_token:
                logger.warning(f"[TeamsWebhook] Token refresh failed for admin={getattr(admin, 'email', '')}: {data}")
                return None
            admin.ms_access_token = new_token
            if data.get("refresh_token"):
                admin.ms_refresh_token = data.get("refresh_token")
            # Use filter().update() to reliably persist refreshed token — avoids djongo update_fields issues
            update_kwargs = {"ms_access_token": new_token}
            if data.get("refresh_token"):
                update_kwargs["ms_refresh_token"] = data["refresh_token"]
            User.objects.filter(pk=admin.pk).update(**update_kwargs)
            return new_token
        except Exception:
            logger.exception(f"[TeamsWebhook] Exception refreshing token for admin={getattr(admin, 'email', '')}")
            return None

    def _resolve_graph_member_email(self, headers, member_obj):
        """Resolve best email for a Graph team member object."""
        email = member_obj.get("email")
        aad_user_id = (
            member_obj.get("userId")
            or member_obj.get("user_id")
            or member_obj.get("id")
        )
        display_name = member_obj.get("displayName") or "Teams User"
        if (not email or "@" not in str(email)) and aad_user_id:
            user_resp = _http_get(
                f"https://graph.microsoft.com/v1.0/users/{aad_user_id}?$select=mail,userPrincipalName,displayName",
                headers=headers,
                timeout=10,
            )
            if user_resp.status_code == 200:
                user_data = user_resp.json()
                email = user_data.get("mail") or user_data.get("userPrincipalName")
                display_name = user_data.get("displayName") or display_name
        return (str(email).strip().lower() if email else ""), display_name, aad_user_id

    def _upsert_member_userdetail(self, admin, team_id, member_id, email, display_name):
        from users_details.models import UserDetail
        if not email or "@" not in email:
            return
        name_parts = (display_name or "Teams User").strip().split()
        first_name = name_parts[0] if name_parts else "Teams"
        last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"

        logger.info(f"[TeamsWebhook] Saving to DB: admin={admin.email} email={email} team_id={team_id}")
        try:
            user_detail, created = UserDetail.objects.get_or_create(
                admin=admin,
                email=email,
                defaults={
                    "first_name": first_name,
                    "last_name": last_name,
                    "user_type": "external",
                    "Member_role": ["Viewer"],
                    "team_id": team_id,
                    "platform": "microsoft_teams",
                    "ms_teams_member_id": member_id,
                }
            )
            logger.info(f"[TeamsWebhook] get_or_create result: created={created} user_detail_id={user_detail._id}")
        except Exception as _goc_exc:
            logger.exception(f"[TeamsWebhook] ❌ get_or_create FAILED for email={email} admin={admin.email}: {_goc_exc}")
            return

        if not created:
            logger.info(f"[TeamsWebhook] UserDetail already exists for {email} — updating fields")
            _upd = {}
            if not user_detail.ms_teams_member_id:
                _upd["ms_teams_member_id"] = member_id
            if not user_detail.platform:
                _upd["platform"] = "microsoft_teams"
            if not user_detail.team_id:
                _upd["team_id"] = team_id
            if _upd:
                from users_details.views import _ud_set as _ud_set_webhook
                _ud_set_webhook(user_detail, **_upd)
        else:
            logger.info(f"[TeamsWebhook] ✅ Created NEW UserDetail for {email} under admin {admin.email}")

    def _sync_all_team_members(self, admin, team_id, headers):
        """Failsafe: sync whole team membership to DB."""
        url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members"
        resp = _http_get(url, headers=headers, timeout=15)
        if resp.status_code == 401:
            new_token = self._refresh_admin_ms_token(admin)
            if new_token:
                headers["Authorization"] = f"Bearer {new_token}"
                resp = _http_get(url, headers=headers, timeout=15)
        if resp.status_code != 200:
            logger.warning(f"[TeamsWebhook] Full team sync failed team_id={team_id} status={resp.status_code} body={resp.text}")
            return
        members = (resp.json() or {}).get("value", [])
        for m in members:
            email, display_name, aad_user_id = self._resolve_graph_member_email(headers, m or {})
            member_id = str((m or {}).get("id") or aad_user_id or "")
            if email and member_id:
                self._upsert_member_userdetail(admin, team_id, member_id, email, display_name)

    def _handle_member_added(self, notification, client_state, resource):
        """
        resource format: teams/{team_id}/members/{member_id}
        clientState = admin's user ID (set when subscription was created)
        """
        try:
            logger.info(f"[TeamsWebhook] _handle_member_added: resource={resource} client_state={client_state[:30] if client_state else ''}")

            team_id = ""
            member_id = ""
            resource_data = notification.get("resourceData") or {}

            if isinstance(resource_data, dict):
                team_id = str(resource_data.get("teamId") or resource_data.get("team_id") or "").strip()
                member_id = str(resource_data.get("id") or resource_data.get("memberId") or "").strip()

            if not team_id or not member_id:
                import re as _re
                m = _re.search(r"teams(?:\('([^']+)'\)|/([^/]+))/members(?:\('([^']+)'\)|/([^/]+))", resource or "")
                if m:
                    team_id = (m.group(1) or m.group(2) or "").strip()
                    member_id = (m.group(3) or m.group(4) or "").strip()

            logger.info(f"[TeamsWebhook] Parsed: team_id={team_id} member_id={member_id}")

            if not team_id or not member_id:
                logger.warning(f"[TeamsWebhook] Could not parse team_id/member_id from resource={resource} resourceData={resource_data}")
                return

            # Find admin by client_state (admin user ID)
            try:
                admin = User.objects.get(id=client_state)
                logger.info(f"[TeamsWebhook] Found admin by client_state: email={admin.email} id={admin.id}")
            except User.DoesNotExist:
                # Fallback: resolve owner by team_id
                admin = User.objects.filter(ms_team_id=team_id).first()
                if not admin:
                    logger.error(f"[TeamsWebhook] ❌ No admin found for client_state={client_state} team_id={team_id} — user will NOT be saved")
                    return
                logger.info(f"[TeamsWebhook] Found admin by ms_team_id={team_id}: email={admin.email}")

            access_token = admin.ms_access_token
            logger.info(f"[TeamsWebhook] Admin token check: email={admin.email} access_token_set={bool(access_token)}")
            if not access_token:
                logger.error(f"[TeamsWebhook] ❌ Admin {admin.email} has no ms_access_token — cannot fetch member details")
                return

            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
            }

            # Failsafe sync: if webhook fired, ensure team members are mirrored in DB.
            logger.info(f"[TeamsWebhook] Running full team member sync for team_id={team_id}")
            self._sync_all_team_members(admin, team_id, headers)

            # Fetch member details from MS Graph
            member_url = f"https://graph.microsoft.com/v1.0/teams/{team_id}/members/{member_id}"
            member_resp = _http_get(member_url, headers=headers, timeout=10)
            if member_resp.status_code == 401:
                new_token = self._refresh_admin_ms_token(admin)
                if new_token:
                    headers["Authorization"] = f"Bearer {new_token}"
                    member_resp = _http_get(member_url, headers=headers, timeout=10)

            email = None
            display_name = "Teams User"
            aad_user_id = None
            member_data = {}

            if member_resp.status_code == 200:
                member_data = member_resp.json()
                display_name = member_data.get("displayName") or "Teams User"
                email = member_data.get("email")
                aad_user_id = (
                    member_data.get("userId")
                    or member_data.get("user_id")
                    or member_data.get("id")
                )
            else:
                logger.warning(f"[TeamsWebhook] Failed to fetch team member by id={member_id}: {member_resp.text}")
                # Fallback: sometimes member_id itself is AAD user object id
                aad_user_id = member_id

            # Graph team-member payload often misses email.
            # Resolve from directory user object using AAD user id.
            if (not email or "@" not in str(email)) and aad_user_id:
                user_resp = _http_get(
                    f"https://graph.microsoft.com/v1.0/users/{aad_user_id}?$select=mail,userPrincipalName,displayName",
                    headers=headers,
                    timeout=10,
                )
                if user_resp.status_code == 401:
                    new_token = self._refresh_admin_ms_token(admin)
                    if new_token:
                        headers["Authorization"] = f"Bearer {new_token}"
                        user_resp = _http_get(
                            f"https://graph.microsoft.com/v1.0/users/{aad_user_id}?$select=mail,userPrincipalName,displayName",
                            headers=headers,
                            timeout=10,
                        )
                if user_resp.status_code == 200:
                    user_data = user_resp.json()
                    email = user_data.get("mail") or user_data.get("userPrincipalName")
                    display_name = user_data.get("displayName") or display_name

            if not email or "@" not in email:
                logger.warning(f"[TeamsWebhook] No valid email for member {member_id}")
                return
            email = str(email).strip().lower()

            name_parts = display_name.strip().split()
            first_name = name_parts[0] if name_parts else "Teams"
            last_name = " ".join(name_parts[1:]) if len(name_parts) > 1 else "User"

            # Save UserDetail — skip if already exists for this admin + email
            from users_details.models import UserDetail
            user_detail, created = UserDetail.objects.get_or_create(
                admin=admin,
                email=email,
                defaults={
                    "first_name": first_name,
                    "last_name": last_name,
                    "user_type": "external",
                    "Member_role": ["Viewer"],
                    "team_id": team_id,
                    "platform": "microsoft_teams",
                    "ms_teams_member_id": member_id,
                }
            )

            if not created:
                # Update platform fields even if record already existed
                updated = False
                if user_detail.email != email and not UserDetail.objects.filter(admin=admin, email=email).exclude(_id=user_detail._id).exists():
                    user_detail.email = email
                    updated = True
                if not user_detail.ms_teams_member_id:
                    user_detail.ms_teams_member_id = member_id
                    updated = True
                if not user_detail.platform:
                    user_detail.platform = "microsoft_teams"
                    updated = True
                if not user_detail.team_id:
                    user_detail.team_id = team_id
                    updated = True
                if updated:
                    user_detail.save()
                logger.info(f"[TeamsWebhook] UserDetail already exists for {email} — skipping")
                return

            logger.info(f"[TeamsWebhook] Created UserDetail for {email} under admin {admin.email}")

            # Create Django User (unusable password) + generate set-password link
            from django.contrib.auth import get_user_model
            from django.utils.http import urlsafe_base64_encode
            from django.utils.encoding import force_bytes
            from django.contrib.auth.tokens import PasswordResetTokenGenerator

            UserModel = get_user_model()
            django_user, u_created = UserModel.objects.get_or_create(
                email=email,
                defaults={"is_active": True}
            )
            if u_created:
                django_user.set_unusable_password()
                django_user.save()

            uid = urlsafe_base64_encode(force_bytes(django_user.pk))
            token = PasswordResetTokenGenerator().make_token(django_user)
            set_password_url = (
                f"https://vaptfix.ai/auth"
                f"?mode=set-password&uid={uid}&token={token}"
            )

            # Send same welcome email
            from users_details.views import UserDetailCreateView
            view = UserDetailCreateView()
            email_sent, error = view.send_welcome_email(
                email=email,
                first_name=first_name,
                last_name=last_name,
                roles=["Viewer"],
                set_password_url=set_password_url,
            )

            if email_sent:
                logger.info(f"[TeamsWebhook] Welcome email sent to {email}")
            else:
                logger.warning(f"[TeamsWebhook] Welcome email failed for {email}: {error}")

        except Exception:
            logger.exception(f"[TeamsWebhook] _handle_member_added failed for resource={resource}")


@csrf_exempt
def teams_webhook_handler(request):
    """
    Pure Django (no DRF) handler for MS Graph webhook.
    GET  — echo validationToken for endpoint validation (parse_qs decodes URL encoding).
    POST — delegate to TeamsWebhookView for notification processing.
    """
    if request.method == "GET":
        raw_qs = request.META.get("QUERY_STRING", "")
        parsed = parse_qs(raw_qs, keep_blank_values=True)
        tokens = parsed.get("validationToken", [])
        if tokens:
            return HttpResponse(tokens[0], content_type="text/plain; charset=utf-8", status=200)
        return HttpResponse("Missing validationToken", status=400)
    return TeamsWebhookView.as_view()(request)


# ── Dashboard image rendering (real dashboard.html design, not Block Kit) ──
#
# Slack's `image` block can only point at a URL that Slack's own servers
# fetch directly (no auth headers from us) — so the dashboard PNG is served
# by SlackDashboardImageView below, gated by a short-lived signed token
# instead of login, and rendered fresh (live data) on every fetch via a
# headless-Chromium screenshot of dashboard.html with real values baked in.

_DASHBOARD_HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>VaptFix Admin Dashboard</title>
  <link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet" />
  <style>
    :root {
      --slack-text: #1d1c1d;
      --slack-sub: #616061;
      --slack-border: #e8e8e8;
      --accent: rgb(14, 106, 111);
      --critical: #e01e5a;
      --high: #e8912d;
      --medium: #ecb22e;
      --low: #2eb67d;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: "Lato", sans-serif;
      background: #f4f6f8;
      color: var(--slack-text);
      font-size: 15px;
      min-height: 100vh;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding: 24px 16px;
    }

    .dash {
      width: 100%;
      max-width: 740px;
      border: 1px solid var(--slack-border);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0,0,0,.05);
      background: #fff;
    }

    .dash-top {
      padding: 18px 22px;
      background: #fff;
      border-bottom: 1px solid var(--slack-border);
    }
    .dash-top h2 { font-size: 19px; font-weight: 900; }
    .dash-top p { font-size: 13px; color: var(--slack-sub); margin-top: 2px; }

    .bento {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      grid-template-rows: auto auto auto;
      gap: 12px;
      padding: 16px;
      background: #f4f6f8;
    }

    .bento-card {
      background: #fff;
      border-radius: 12px;
      border: 1px solid var(--slack-border);
      padding: 16px 18px;
      box-shadow: 0 1px 2px rgba(0,0,0,.04);
    }

    .bento-card.span2 { grid-column: span 2; }
    .bento-card.span3 { grid-column: span 3; }
    .bento-card.span6 { grid-column: span 6; }

    .bento-label {
      font-size: 11px; font-weight: 700; text-transform: uppercase;
      letter-spacing: .05em; color: var(--slack-sub); margin-bottom: 6px;
    }

    .bento-value { font-size: 28px; font-weight: 900; line-height: 1.1; }
    .bento-sub { font-size: 12px; color: var(--slack-sub); margin-top: 4px; }

    .gauge-wrap { display: flex; align-items: center; gap: 16px; }

    .gauge {
      width: 80px; height: 80px; border-radius: 50%;
      display: grid; place-items: center; position: relative; flex-shrink: 0;
    }

    .gauge::after {
      content: ""; width: 58px; height: 58px; border-radius: 50%; background: #fff;
    }

    .gauge span {
      position: absolute; font-size: 18px; font-weight: 900; z-index: 1;
    }

    .gauge-info .bento-value { font-size: 22px; }

    .chart-card .chart-title {
      font-size: 14px; font-weight: 900; margin-bottom: 14px;
    }
    .chart-card .chart-sub {
      display: inline-block;
      font-size: 12px; font-weight: 400; color: var(--slack-sub); margin-left: 6px;
    }

    .vbars {
      display: flex;
      align-items: flex-end;
      justify-content: space-around;
      height: 160px;
      padding-top: 10px;
    }

    .vcol {
      display: flex; flex-direction: column; align-items: center;
      gap: 6px; flex: 1;
    }

    .vcol .num {
      font-size: 13px; font-weight: 900;
      background: #f0f0f0;
      padding: 2px 8px; border-radius: 10px;
    }

    .vcol .col {
      width: 36px;
      border-radius: 8px 8px 4px 4px;
    }

    .vcol .col.critical { background: var(--critical); box-shadow: 0 4px 12px rgba(224,30,90,.3); }
    .vcol .col.high { background: var(--high); box-shadow: 0 4px 12px rgba(232,145,45,.3); }
    .vcol .col.medium { background: var(--medium); box-shadow: 0 4px 12px rgba(236,178,46,.3); }
    .vcol .col.low { background: var(--low); box-shadow: 0 4px 12px rgba(46,182,125,.3); }

    .vcol .lbl {
      font-size: 11px; font-weight: 700; color: var(--slack-sub);
    }

    .donut-wrap {
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 14px;
      padding-top: 4px;
    }

    .donut {
      width: 118px;
      height: 118px;
      border-radius: 50%;
      display: grid;
      place-items: center;
      position: relative;
      flex-shrink: 0;
    }

    .donut::after {
      content: "";
      width: 74px;
      height: 74px;
      border-radius: 50%;
      background: #fff;
    }

    .donut-center {
      position: absolute;
      text-align: center;
      z-index: 1;
      line-height: 1.15;
    }

    .donut-center .big { font-size: 26px; font-weight: 900; }
    .donut-center .small { font-size: 11px; color: var(--slack-sub); font-weight: 700; }

    .donut-legend {
      width: 100%;
      display: flex;
      flex-direction: column;
      gap: 7px;
    }

    .legend-row {
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 13px;
    }

    .legend-row .dot { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
    .legend-row .dot.critical { background: var(--critical); }
    .legend-row .dot.high { background: var(--high); }
    .legend-row .dot.medium { background: var(--medium); }
    .legend-row .dot.low { background: var(--low); }

    .legend-row .name { flex: 1; font-weight: 700; }
    .legend-row .pct { font-weight: 900; color: var(--slack-sub); min-width: 36px; text-align: right; }

    .chips { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 4px; }

    .chip {
      display: flex; align-items: center; gap: 6px;
      padding: 8px 12px; border-radius: 8px;
      font-size: 13px; font-weight: 700;
      border: 1px solid var(--slack-border);
      background: #fafbfc;
    }

    .chip .dot { width: 8px; height: 8px; border-radius: 50%; }
    .chip .dot.red { background: var(--critical); }
    .chip .dot.yellow { background: var(--medium); }

    .chip.danger { border-color: #f5c6cb; background: #fff5f5; }

    .support-row { display: flex; gap: 12px; }

    .support-stat {
      flex: 1; text-align: center;
      padding: 12px; border-radius: 10px;
      background: linear-gradient(135deg, #f8f9ff, #fff);
      border: 1px solid #e0e7ff;
    }

    .support-stat .num { font-size: 24px; font-weight: 900; color: var(--accent); }
    .support-stat .txt { font-size: 11px; color: var(--slack-sub); font-weight: 700; margin-top: 2px; }
  </style>
</head>
<body>
"""


def _dashboard_bar_height(n, m):
    return round(max((n / m) * 130, 8) if n > 0 else 4)


def _dashboard_gauge_gradient(score):
    score = max(0, min(10, score or 0))
    deg = (score / 10) * 360
    color = "#e01e5a" if score >= 7 else ("#e8912d" if score >= 4 else "#2eb67d")
    return f"conic-gradient({color} 0deg {deg}deg, #eee {deg}deg 360deg)"


def _dashboard_donut_gradient(counts):
    colors = {"critical": "#e01e5a", "high": "#e8912d", "medium": "#ecb22e", "low": "#2eb67d"}
    order = ["medium", "low", "high", "critical"]
    total = sum(counts.values())
    if total == 0:
        return "#eee", 0
    deg = 0
    stops = []
    for k in order:
        n = counts.get(k, 0)
        if n > 0:
            slice_deg = (n / total) * 360
            stops.append(f"{colors[k]} {deg}deg {deg + slice_deg}deg")
            deg += slice_deg
    return f"conic-gradient({', '.join(stops)})", total


def _build_dashboard_html(data):
    total_assets = (data.get("total_assets") or {}).get("total_assets", 0)
    avg_score    = (data.get("avg_score") or {}).get("avg_score", 0) or 0
    vulns        = data.get("vulnerabilities") or {}
    critical = vulns.get("critical", 0)
    high     = vulns.get("high", 0)
    medium   = vulns.get("medium", 0)
    low      = vulns.get("low", 0)
    total_vulns = critical + high + medium + low
    max_v = max(critical, high, medium, low, 1)

    timeline = data.get("mitigation_timeline") or {}
    mtr      = (data.get("mean_time_remediate") or {}).get("mean_time_to_remediate") or {}
    fixed    = data.get("vulnerabilities_fixed") or {}
    support  = data.get("support_requests") or {}

    risk_label = "High risk level" if avg_score >= 7 else ("Moderate risk level" if avg_score >= 4 else "Low risk level")
    gauge_bg = _dashboard_gauge_gradient(avg_score)

    fixed_counts = {
        "critical": fixed.get("critical_fixed", 0),
        "high": fixed.get("high_fixed", 0),
        "medium": fixed.get("medium_fixed", 0),
        "low": fixed.get("low_fixed", 0),
    }
    donut_bg, fixed_total = _dashboard_donut_gradient(fixed_counts)
    legend_labels = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}
    legend_html = "".join(
        f'<div class="legend-row"><span class="dot {k}"></span>'
        f'<span class="name">{legend_labels[k]}</span>'
        f'<span class="pct">{fixed_counts[k]}</span></div>'
        for k in ["medium", "low", "high", "critical"]
    )

    def chip(label, info):
        if not info:
            return f'<div class="chip"><span class="dot yellow"></span> {label} — N/A</div>'
        overdue = info.get("status") == "overdue"
        dot = "red" if overdue else "yellow"
        cls = "chip danger" if overdue else "chip"
        status_txt = "Overdue" if overdue else info.get("remaining_label", "")
        return f'<div class="{cls}"><span class="dot {dot}"></span> {label} — {status_txt}</div>'

    chips_html = "".join([
        chip("Critical", timeline.get("critical")),
        chip("High",     timeline.get("high")),
        chip("Medium",   timeline.get("medium")),
        chip("Low",      timeline.get("low")),
    ])

    bars_html = "".join(
        f'<div class="vcol"><span class="num">{n}</span>'
        f'<div class="col {k}" style="height:{_dashboard_bar_height(n, max_v)}px"></div>'
        f'<span class="lbl">{lbl}</span></div>'
        for k, lbl, n in [
            ("critical", "Critical", critical),
            ("high", "High", high),
            ("medium", "Medium", medium),
            ("low", "Low", low),
        ]
    )

    body = f"""  <div class="dash">
    <div class="dash-top">
      <h2>📊 VaptFix Admin Dashboard</h2>
      <p>Overall summary — assets, vuln severity, mitigation timeline, mean fix time, and support tickets.</p>
    </div>

    <div class="bento">
      <div class="bento-card span2">
        <div class="bento-label">🏢 Total Assets</div>
        <div class="bento-value">{total_assets}</div>
        <div class="bento-sub">Monitored endpoints</div>
      </div>

      <div class="bento-card span2">
        <div class="gauge-wrap">
          <div class="gauge" style="background:{gauge_bg}"><span>{avg_score}</span></div>
          <div class="gauge-info">
            <div class="bento-label">⚠️ Avg Risk Score</div>
            <div class="bento-value">{avg_score} <span style="font-size:14px;font-weight:400;color:var(--slack-sub)">/ 10</span></div>
            <div class="bento-sub">{risk_label}</div>
          </div>
        </div>
      </div>

      <div class="bento-card span2">
        <div class="bento-label">⚡ Mean Time to Remediate</div>
        <div class="bento-value">{mtr.get('label', 'N/A')}</div>
        <div class="bento-sub">Average resolution time</div>
      </div>

      <div class="bento-card span3 chart-card">
        <div class="chart-title">🔴 Vulnerabilities by Severity</div>
        <div class="vbars">{bars_html}</div>
      </div>

      <div class="bento-card span3 chart-card">
        <div class="chart-title">🔧 Vulns Fixed<span class="chart-sub">{fixed.get('total_fixed', 0)} / {total_vulns}</span></div>
        <div class="donut-wrap">
          <div class="donut" style="background:{donut_bg}">
            <div class="donut-center"><div class="big">{fixed_total}</div><div class="small">fixed</div></div>
          </div>
          <div class="donut-legend">{legend_html}</div>
        </div>
      </div>

      <div class="bento-card span6">
        <div class="bento-label">⏱️ Mitigation Timeline</div>
        <div class="chips">{chips_html}</div>
      </div>

      <div class="bento-card span6">
        <div class="bento-label">🎫 Support Requests</div>
        <div class="support-row">
          <div class="support-stat"><div class="num">{support.get('total', 0)}</div><div class="txt">Total Requests</div></div>
          <div class="support-stat"><div class="num">{support.get('pending', 0)}</div><div class="txt">Pending</div></div>
          <div class="support-stat"><div class="num">{support.get('closed', 0)}</div><div class="txt">Closed</div></div>
        </div>
      </div>
    </div>
  </div>
"""
    return _DASHBOARD_HTML_HEAD + body + "</body>\n</html>"


_TEAM_OVERVIEW_HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
  <title>Team Overview</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', 'Segoe UI', sans-serif; background: #f4f5f8; padding: 32px; }

    .wrapper {
      background: #fff;
      border-radius: 16px;
      padding: 28px;
      max-width: 900px;
      margin: 0 auto;
      box-shadow: 0 2px 12px rgba(0,0,0,0.07);
    }

    .header { margin-bottom: 24px; }
    .header h2 {
      font-size: 1.25rem;
      font-weight: 700;
      color: #1e1b4b;
      display: flex;
      align-items: center;
      gap: 10px;
      margin-bottom: 6px;
    }
    .header p { font-size: 0.82rem; color: #6b7280; }

    .grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 16px;
    }

    .card {
      border: 1px solid #e5e7eb;
      border-radius: 14px;
      padding: 20px;
      background: #fff;
    }

    .card-title {
      font-size: 1rem;
      font-weight: 700;
      color: #111827;
      margin-bottom: 14px;
    }

    .badges {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 12px;
    }

    .badge {
      font-size: 0.78rem;
      font-weight: 600;
      color: #374151;
      background: #f3f4f6;
      border: 1px solid #e5e7eb;
      border-radius: 999px;
      padding: 4px 12px;
    }
    .badge.fixed { color: #0f696e; }

    .severities {
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      margin-top: 4px;
    }

    .sev {
      font-size: 0.78rem;
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 999px;
    }

    .dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; flex-shrink: 0; }

    /* Critical */
    .sev.critical { color: #b42318; background: #fee2e2; }
    .dot-critical { background: #b42318; }

    /* High */
    .sev.high { color: #dc2626; background: #fee2e2; }
    .dot-high { background: #dc2626; }

    /* Medium */
    .sev.medium { color: rgb(245, 158, 11); background: #fef3c7; }
    .dot-medium { background: rgb(245, 158, 11); }

    /* Low */
    .sev.low { color: #16a34a; background: #dcfce7; }
    .dot-low { background: #16a34a; }

    .no-vuln { font-size: 0.8rem; color: #9ca3af; margin-top: 8px; }
    .full-width { grid-column: 1 / -1; }
  </style>
</head>
<body>
"""


def _build_team_overview_html(data):
    teams_raw = data.get("teams") or data.get("results") or (data if isinstance(data, list) else None)
    if isinstance(teams_raw, dict):
        teams_list = list(teams_raw.items())[:10]
    elif isinstance(teams_raw, list):
        teams_list = [(t.get("team_name") or t.get("name") or "Unknown", t) for t in teams_raw[:10]]
    else:
        teams_list = []

    sev_order = ["critical", "high", "medium", "low"]
    cards_html = ""
    for i, (name, stats) in enumerate(teams_list):
        total  = stats.get("total", 0)
        open_v = stats.get("open", 0)
        closed = stats.get("closed", 0)
        rate   = round((closed / total) * 100) if total else 0
        by_risk = {(k or "").lower(): v for k, v in (stats.get("by_risk") or {}).items()}

        if total == 0:
            body_html = '<p class="no-vuln">No vulnerabilities</p>'
        else:
            sev_html = "".join(
                f'<span class="sev {sev}"><span class="dot dot-{sev}"></span> {sev.capitalize()}: {by_risk[sev]}</span>'
                for sev in sev_order if by_risk.get(sev)
            )
            body_html = f'<div class="severities">{sev_html}</div>'

        full_width = " full-width" if (i == len(teams_list) - 1 and len(teams_list) % 2 == 1) else ""
        cards_html += f"""
    <div class="card{full_width}">
      <div class="card-title">{name}</div>
      <div class="badges">
        <span class="badge">Total: {total}</span>
        <span class="badge">Open: {open_v}</span>
        <span class="badge fixed">Fixed: {closed} ({rate}%)</span>
      </div>
      {body_html}
    </div>"""

    if not teams_list:
        cards_html = '<p class="no-vuln">No team data available.</p>'

    body = f"""  <div class="wrapper">
    <div class="header">
      <h2>👥 Team Overview</h2>
      <p>Per-team breakdown — total, open, and fixed vulns with severity distribution across all teams.</p>
    </div>
    <div class="grid">{cards_html}
    </div>
  </div>
"""
    return _TEAM_OVERVIEW_HTML_HEAD + body + "</body>\n</html>"


_SUPPORT_HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Support Requests | VaptFix</title>
  <link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet" />
  <style>
    :root{--slack-text:#1d1c1d;--slack-sub:#616061;--slack-border:#e8e8e8;--accent:rgb(14,106,111)}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:"Lato",sans-serif;background:#f4f6f8;color:var(--slack-text);font-size:15px;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:24px 16px}
    .dash{width:100%;max-width:760px;border:1px solid var(--slack-border);border-radius:16px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.05);background:#fff}
    .dash-top{padding:18px 22px;border-bottom:1px solid var(--slack-border)}
    .dash-top h2{font-size:19px;font-weight:900}
    .dash-top p{font-size:13px;color:var(--slack-sub);margin-top:2px}
    .panel-body{padding:16px;background:#f4f6f8}
    .card{background:#fff;border-radius:12px;border:1px solid var(--slack-border);padding:16px 18px}
    .support-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:14px}
    .mini-stat{text-align:center;background:#fafbfc;border:1px solid var(--slack-border);border-radius:10px;padding:12px}
    .mini-stat .n{font-size:24px;font-weight:900;color:var(--accent)}
    .mini-stat .t{font-size:11px;font-weight:700;color:var(--slack-sub);margin-top:2px}
    .req-item{border:1px solid var(--slack-border);border-radius:10px;padding:12px 14px;background:#fafbfc;margin-bottom:10px}
    .req-item:last-child{margin-bottom:0}
    .req-title{font-size:14px;font-weight:900;margin-bottom:6px}
    .req-meta{font-size:12px;font-weight:700;color:var(--slack-sub);line-height:1.55}
    .req-note{font-size:13px;margin-top:6px;font-style:italic}
    .code-tag{display:inline-block;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#f8f8f8;border:1px solid var(--slack-border);border-radius:4px;padding:1px 6px;color:#c41e3a}
    .no-vuln{font-size:0.8rem;color:#9ca3af}
  </style>
</head>
<body>
"""


def _build_support_html(data):
    results = data.get("results") or []
    total   = data.get("count", len(results))
    pending = sum(1 for r in results if (r.get("status") or "open") != "closed")
    closed  = sum(1 for r in results if (r.get("status") or "") == "closed")

    if not results:
        items_html = '<p class="no-vuln">No support requests found.</p>'
    else:
        rows = []
        for r in results[:10]:
            vuln      = r.get("vul_name") or "General Request"
            host      = r.get("host_name") or "—"
            team      = r.get("assigned_team") or "—"
            requester = r.get("requested_by") or "Unknown"
            st        = r.get("status") or "open"
            icon      = "✅" if st == "closed" else "🔓"
            desc      = (r.get("description") or "")[:150]
            note_html = f'<div class="req-note">{desc}</div>' if desc else ""
            rows.append(f"""
        <div class="req-item">
          <div class="req-title">{icon} {vuln} ({team})</div>
          <div class="req-meta">Host: <span class="code-tag">{host}</span> | By: {requester} | Status: {st.capitalize()}</div>
          {note_html}
        </div>""")
        items_html = "".join(rows)

    body = f"""  <div class="dash">
    <div class="dash-top">
      <h2>🎫 Support Requests</h2>
      <p>Every support ticket raised by teams — who raised it, which vuln, and status.</p>
    </div>
    <div class="panel-body">
      <div class="card">
        <div class="support-stats">
          <div class="mini-stat"><div class="n">{total}</div><div class="t">Total</div></div>
          <div class="mini-stat"><div class="n">{pending}</div><div class="t">Pending</div></div>
          <div class="mini-stat"><div class="n">{closed}</div><div class="t">Closed</div></div>
        </div>
        {items_html}
      </div>
    </div>
  </div>
"""
    return _SUPPORT_HTML_HEAD + body + "</body>\n</html>"


_VULNSTATS_HTML_HEAD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Vulnerability Statistics | VaptFix</title>
  <link href="https://fonts.googleapis.com/css2?family=Lato:wght@400;700;900&display=swap" rel="stylesheet" />
  <style>
    :root{--slack-text:#1d1c1d;--slack-sub:#616061;--slack-border:#e8e8e8;--accent:rgb(14,106,111);--critical:#e01e5a;--high:#e8912d;--medium:#ecb22e;--low:#2eb67d}
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:"Lato",sans-serif;background:#f4f6f8;color:var(--slack-text);font-size:15px;min-height:100vh;display:flex;align-items:flex-start;justify-content:center;padding:24px 16px}
    .dash{width:100%;max-width:760px;border:1px solid var(--slack-border);border-radius:16px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,.05);background:#fff}
    .dash-top{padding:18px 22px;border-bottom:1px solid var(--slack-border)}
    .dash-top h2{font-size:19px;font-weight:900}
    .dash-top p{font-size:13px;color:var(--slack-sub);margin-top:2px}
    .panel-body{padding:16px;background:#f4f6f8}
    .card{background:#fff;border-radius:12px;border:1px solid var(--slack-border);padding:16px 18px}
    .stat-bars{background:#f8f8f8;border-radius:10px;border:1px solid var(--slack-border);padding:14px 16px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;line-height:1.9}
    .bar-row{display:grid;grid-template-columns:72px 1fr 36px;align-items:center;gap:10px}
    .bar-track{height:10px;background:#e8e8e8;border-radius:4px;overflow:hidden}
    .bar-fill{height:100%;border-radius:4px}
    .bar-fill.critical{background:var(--critical)}
    .bar-fill.high{background:var(--high)}
    .bar-fill.medium{background:var(--medium)}
    .bar-fill.low{background:var(--low)}
    .status-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:14px}
    .status-box{background:#fafbfc;border:1px solid var(--slack-border);border-radius:10px;padding:12px 14px}
    .status-box .k{font-size:12px;font-weight:700;color:var(--slack-sub)}
    .status-box .v{font-size:24px;font-weight:900;margin-top:2px}
  </style>
</head>
<body>
"""


def _build_vulnstats_html(data):
    vulns = data.get("vulnerabilities") or data.get("results") or (data if isinstance(data, list) else [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0,
              "open": 0, "in_progress": 0, "open_review": 0, "fixed": 0}
    if isinstance(vulns, list):
        for v in vulns:
            sev = (v.get("risk_factor") or v.get("severity") or "").lower()
            raw_st = (v.get("status") or "open").strip().lower()
            st = "fixed" if raw_st == "closed" else raw_st.replace(" ", "_").replace("/", "_").replace("-", "_")
            if sev in counts:
                counts[sev] += 1
            if st in counts:
                counts[st] += 1
    else:
        for k in counts:
            counts[k] = data.get(k, 0)

    total = data.get("total") or counts["critical"] + counts["high"] + counts["medium"] + counts["low"] or 0
    max_v = max(total, 1)

    bar_rows = "".join(
        f'<div class="bar-row"><span>{label}</span>'
        f'<div class="bar-track"><div class="bar-fill {key}" style="width:{round(counts[key] / max_v * 100)}%"></div></div>'
        f'<strong>{counts[key]}</strong></div>'
        for key, label in [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low")]
    )

    body = f"""  <div class="dash">
    <div class="dash-top">
      <h2>🛡️ Vulnerability Statistics</h2>
      <p>Total vuln counts by severity (Critical/High/Medium/Low) and by status (Open/In Progress/Open-Review/Fixed).</p>
    </div>
    <div class="panel-body">
      <div class="card">
        <div style="font-weight:900;margin-bottom:8px">By Severity</div>
        <div class="stat-bars">{bar_rows}</div>
        <div class="status-grid">
          <div class="status-box"><div class="k">Open</div><div class="v">{counts['open']}</div></div>
          <div class="status-box"><div class="k">In Progress</div><div class="v">{counts['in_progress']}</div></div>
          <div class="status-box"><div class="k">Open/Review</div><div class="v">{counts['open_review']}</div></div>
          <div class="status-box"><div class="k">Fixed</div><div class="v">{counts['fixed']}</div></div>
          <div class="status-box" style="grid-column:1/-1"><div class="k">Total</div><div class="v">{total}</div></div>
        </div>
      </div>
    </div>
  </div>
"""
    return _VULNSTATS_HTML_HEAD + body + "</body>\n</html>"


def _dashboard_png_bytes(html, selector=".dash"):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        try:
            # device_scale_factor=2 renders at 2x pixel density (retina-style)
            # — Slack still displays the image at the same on-screen width,
            # but the text is twice as sharp instead of looking blurry/small.
            page = browser.new_page(viewport={"width": 900, "height": 200}, device_scale_factor=2)
            page.set_content(html, wait_until="networkidle")
            el = page.query_selector(selector)
            png_bytes = el.screenshot()
        finally:
            browser.close()
    return png_bytes


def _dashboard_image_signer():
    from django.core.signing import TimestampSigner
    return TimestampSigner(salt="vaptfix-dashboard-image")


class SlackStatusIconView(APIView):
    """
    GET /api/admin/users/slack/status-icon/<kind>/

    Public (no auth) — Slack fetches image_url directly for Block Kit
    context/image elements. kind: open | closed | progress | review
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    _KIND_FILES = {
        "open": "status-open.png",
        "closed": "status-closed.png",
        "progress": "status-progress.png",
        "review": "status-open.png",
    }

    def get(self, request, kind="open"):
        filename = self._KIND_FILES.get((kind or "open").strip().lower())
        if not filename:
            return HttpResponse(status=404)
        path = os.path.join(
            settings.BASE_DIR, "users", "static", "users", "icons", filename,
        )
        if not os.path.isfile(path):
            return HttpResponse(status=404)
        with open(path, "rb") as f:
            return HttpResponse(f.read(), content_type="image/png")


class SlackDashboardImageView(APIView):
    """
    GET /api/admin/users/slack/dashboard-image/?token=...

    Public (token-gated, not login-gated) — Slack's own servers fetch this
    URL directly when rendering an `image` block, without any of our auth
    headers, so it can't require IsAuthenticated. Instead the token is a
    short-lived signed team_id (see _dashboard_image_signer), minted fresh
    every time the navbar/dashboard message is (re)built.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        token = request.query_params.get("token", "")
        try:
            team_id = _dashboard_image_signer().unsign(token, max_age=600)
        except Exception:
            return HttpResponse(status=403)

        kind = request.query_params.get("kind", "dashboard")
        slash = SlackSlashCommandView()
        if kind == "team":
            data = slash._call_api(
                "/api/admin/admindashboard/dashboard/distribution-by-team/detail/", team_id,
            )
            html = _build_team_overview_html(data)
            selector = ".wrapper"
        elif kind == "support":
            report_id = slash._get_workspace_report_id(team_id)
            data = (
                slash._call_api(f"/api/admin/adminregister/support-requests/report/{report_id}/", team_id)
                if report_id else {}
            )
            html = _build_support_html(data)
            selector = ".dash"
        elif kind == "stats":
            data = slash._call_api(
                "/api/admin/admindashboard/dashboard/detailed-vulnerabilities/", team_id,
            )
            html = _build_vulnstats_html(data)
            selector = ".dash"
        else:
            data = slash._call_api("/api/admin/admindashboard/dashboard/summary/", team_id)
            html = _build_dashboard_html(data)
            selector = ".dash"

        try:
            png_bytes = _dashboard_png_bytes(html, selector=selector)
        except Exception:
            logger.exception("[SlackDashboardImageView] PNG render failed")
            return HttpResponse(status=500)

        return HttpResponse(png_bytes, content_type="image/png")


class SlackSlashCommandView(APIView):
    """
    Handles all VaptFix Slack slash commands.
    Admin commands: #vaptfix-admin-dashboard
    Team commands: #vaptfix-*-team channels (channel name determines team context).
    Acks Slack within 3s; posts real result to response_url via background thread.
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    ADMIN_CHANNEL = "vaptfix-admin-dashboard"
    TEAM_CHANNELS = {
        "vaptfix-patch-management-team":         "Patch Management",
        "vaptfix-configuration-management-team": "Configuration Management",
        "vaptfix-network-security-team":         "Network Security",
        "vaptfix-architectural-flaws-team":      "Architectural Flaws",
    }
    _SEV_PREFIX = [("Critical", "c"), ("High", "h"), ("Medium", "m"), ("Low", "l")]
    _SEV_ICONS  = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}

    # Admin-dashboard-channel navbar — clicking these updates the SAME
    # message in place (like a tab switcher) instead of requiring the
    # admin to type a slash command. Kept in one place so both the
    # auto-post-on-join handler (SlackEventsView) and the click handler
    # (SlackInteractivityView) build an identical, consistent set.
    _NAV_ITEMS = [
        ("nav_home",     "🏠 Home"),
        ("nav_fix",      "🔧 Fix"),
        ("nav_admin_demo", "🧪 Admin Demo"),
        ("nav_register", "📋 Register"),
        ("nav_team",     "👥 Team"),
        ("nav_teamperf", "📈 Team Performance"),
        ("nav_support",  "🎫 Support"),
        ("nav_download", "📥 Download Report"),
    ]

    # Sub-tabs shown under the "Team Overview" nav tab specifically.
    _TEAM_SUBTABS = [
        ("team_sub_team",         "Team"),
        ("team_sub_adduser",      "➕ Add User"),
        ("team_sub_deleteuser",   "🗑️ Delete User"),
        ("team_sub_externaluser", "🌐 External User"),
    ]

    # Sub-tabs shown under the "All Vulnerabilities" nav tab specifically.
    _ALLVULN_SUBTABS = [
        ("av_sub_list",     "📋 All Vulns"),
        ("av_sub_stats",    "📊 Statistics"),
        ("av_sub_details",  "🔍 Vuln Details"),
        ("av_sub_support",  "🎫 Support"),
        ("av_sub_timeline", "⌛ Timeline Ext."),
        ("av_sub_approve",  "✅ Approve"),
        ("av_sub_reject",   "❌ Reject"),
    ]

    # Sub-tabs shown under the "Fix" nav tab specifically.
    _FIX_SUBTABS = [
        ("fix_sub_assets", "🖥 All Assets"),
        ("fix_sub_vulns",  "📋 All Vulnerabilities"),
    ]

    # Sub-tabs shown under the "Register" nav tab specifically.
    _REGISTER_SUBTABS = [
        ("reg_sub_register", "📋 Register"),
        ("reg_sub_script",   "📜 Script"),
    ]

    # Support tab — status + team filter keys (Slack Block Kit action values).
    _SUPPORT_STATUS_FILTERS = [
        ("all", "All"),
        ("open", "Open"),
        ("closed", "Closed"),
    ]
    _SUPPORT_TEAM_FILTERS = [
        ("all", "All Teams"),
        ("patch", "Patch Management"),
        ("config", "Configuration Management"),
        ("network", "Network Security"),
        ("arch", "Architectural Flaws"),
    ]
    _SUPPORT_TEAM_MATCH = {
        "patch": "patch management",
        "config": "configuration management",
        "network": "network security",
        "arch": "architectural flaws",
    }

    def post(self, request):
        # Verify signature FIRST — before request.POST is accessed.
        # Accessing request.POST causes DRF to consume the body stream, after which
        # request._request.body raises RawPostDataException and signature check silently fails.
        if not self._verify_signature(request):
            return Response({"response_type": "ephemeral", "text": "❌ Unauthorized request."}, status=403)

        # Slack sends application/x-www-form-urlencoded
        data = request.POST
        command = data.get("command", "")
        text = (data.get("text") or "").strip()
        channel_name = data.get("channel_name", "")
        user_id = data.get("user_id", "")
        team_id = data.get("team_id", "")
        response_url = data.get("response_url", "")

        if channel_name == self.ADMIN_CHANNEL:
            # Block non-admins with a clear message instead of showing empty data
            workspace_users   = User.objects.filter(slack_team_id=team_id)
            admin_slack_ids   = {u.slack_user_id for u in workspace_users if u.slack_user_id}
            if admin_slack_ids and user_id not in admin_slack_ids:
                return Response({
                    "response_type": "ephemeral",
                    "text": (
                        "❌ *Access Denied* — `#vaptfix-admin-dashboard` is for VaptFix admins only.\n\n"
                        "Team members, please use commands in your team channel:\n"
                        "• `#vaptfix-patch-management-team`\n"
                        "• `#vaptfix-configuration-management-team`\n"
                        "• `#vaptfix-network-security-team`\n"
                        "• `#vaptfix-architectural-flaws-team`"
                    ),
                })
            handlers = {
                "/teamoverview":   self._cmd_teamoverview,
                "/vulnstats":      self._cmd_vulnstats,
                "/dashboard":      self._cmd_dashboard,
                "/externalusers":  self._cmd_externalusers,
                "/adduser":        self._cmd_adduser,
                "/deleteuser":     self._cmd_deleteuser,
                "/supportdata":    self._cmd_supportdata,
                "/vulndata":       self._cmd_vulndata,
                "/approve":        self._cmd_approve,
                "/reject":         self._cmd_reject,
                "/request":        self._cmd_request,
                "/report":         self._cmd_report,
                "/downloadreport": self._cmd_downloadreport,
                "/vaptcheck":      self._cmd_vaptcheck,
                "/verifications":  self._cmd_verifications,
                "/approvefix":     self._cmd_verify,
                "/postnavbar":     self._cmd_postnavbar,
            }
            team_name = None
        elif channel_name in self.TEAM_CHANNELS:
            team_name = self.TEAM_CHANNELS[channel_name]
            handlers = {
                "/viewassigned":     self._cmd_viewassigned,
                "/mitigationstatus": self._cmd_mitigationstatus,
                "/startfix":         self._cmd_startfix,
                "/manualfix":        self._cmd_manualfix,
                "/autofix":          self._cmd_autofix,
                "/scriptfeedback":   self._cmd_scriptfeedback,
                "/mitigated":        self._cmd_mitigated,
                "/retest":           self._cmd_retest,
                "/support":          self._cmd_support,
                "/extend":           self._cmd_extend,
                "/scriptstats":      self._cmd_scriptstats,
            }
        else:
            return Response({
                "response_type": "ephemeral",
                "text": (
                    "❌ VaptFix commands are not available in this channel.\n"
                    "*Admin commands:* `#vaptfix-admin-dashboard`\n"
                    "*Team commands:* `#vaptfix-patch-management-team`, "
                    "`#vaptfix-configuration-management-team`, "
                    "`#vaptfix-network-security-team`, "
                    "`#vaptfix-architectural-flaws-team`"
                ),
            })

        handler = handlers.get(command)
        if not handler:
            return Response({
                "response_type": "ephemeral",
                "text": f"❌ Unknown command `{command}` for this channel.",
            })

        # Ack Slack immediately; process and reply via response_url in background
        threading.Thread(
            target=self._run_command,
            args=(handler, text, team_id, user_id, response_url, command, team_name),
            daemon=True,
        ).start()
        return Response({"response_type": "in_channel", "text": f"⏳ Processing `{command}`..."})

    # ── Internal helpers ──────────────────────────────────────────────────

    def _run_command(self, handler, text, team_id, user_id, response_url, command, team_name=None):
        try:
            blocks = handler(text, team_id, user_id, team_name) if team_name is not None else handler(text, team_id, user_id)
            payload = {"response_type": "in_channel", "replace_original": True, "blocks": blocks}
        except Exception as exc:
            logger.exception(f"[SlackCmd] {command} failed: {exc}")
            payload = {
                "response_type": "ephemeral",
                "replace_original": True,
                "text": f"❌ `{command}` failed: {exc}",
            }
        if response_url:
            try:
                _http_post(response_url, json=payload, timeout=10)
            except Exception as exc:
                logger.error(f"[SlackCmd] response_url POST failed: {exc}")

    def _verify_signature(self, request):
        # Temporarily bypassed for debugging — re-enable after confirming commands work
        return True

    def _get_admin_token(self, team_id, slack_user_id=None):
        from rest_framework_simplejwt.tokens import RefreshToken as _RT
        # 1. Exact match: user who ran the slash command
        if slack_user_id:
            user = next((u for u in User.objects.filter(slack_user_id=slack_user_id)), None)
            if user:
                return str(_RT.for_user(user).access_token)
        # 2. Any Slack-connected user in this workspace (they connected the bot → they're the admin)
        user = next((u for u in User.objects.filter(slack_team_id=team_id) if u.slack_bot_token), None)
        if not user:
            # 3. Last resort: any Django staff user (djongo can't combine boolean+equality — filter in Python)
            user = next((u for u in User.objects.all() if u.is_staff), None)
        if user:
            return str(_RT.for_user(user).access_token)
        return None

    def _call_api(self, path, team_id, method="get", json_body=None, params=None, slack_user_id=None):
        backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
        token = self._get_admin_token(team_id, slack_user_id=slack_user_id)
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        url = f"{backend}{path}"
        if method == "get":
            resp = _http_get(url, headers=headers, params=params, timeout=15)
        elif method == "post":
            resp = _http_post(url, headers=headers, json=json_body, timeout=15)
        elif method == "patch":
            resp = _http_patch(url, headers=headers, json=json_body, timeout=15)
        elif method == "delete":
            resp = _http_delete(url, headers=headers, json=json_body, timeout=15)
        else:
            resp = _http_get(url, headers=headers, timeout=15)
        return resp.json()

    def _get_member_token(self, team_id, slack_user_id):
        """
        Resolve the JWT of the exact team member who ran the command — required for
        user-scoped fix/automation APIs (/api/user/register/*, /api/user/automation-scripts/*)
        which check request.user against a UserDetail record.
        Resolved via Slack user_id -> email (Slack API) -> Django User, since the member
        may never have personally done Slack OAuth login (only /adduser'd by the admin).
        """
        from rest_framework_simplejwt.tokens import RefreshToken as _RT
        bot_token = self._get_bot_token(team_id, slack_user_id=slack_user_id)
        if not bot_token:
            return None
        resp = _http_get(
            "https://slack.com/api/users.info",
            params={"user": slack_user_id},
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10,
        ).json()
        if not resp.get("ok"):
            return None
        email = resp.get("user", {}).get("profile", {}).get("email", "")
        if not email:
            return None
        user = User.objects.filter(email=email).first()
        if not user:
            return None
        return str(_RT.for_user(user).access_token)

    def _call_user_api(self, path, team_id, user_id, method="get", json_body=None, params=None):
        """Like _call_api but authenticates as the team member (not the admin) — for
        /api/user/register/* and /api/user/automation-scripts/* endpoints."""
        backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
        token = self._get_member_token(team_id, user_id)
        if not token:
            return {
                "detail": "Your Slack account is not linked to a VaptFix user account. Ask your admin to add you via /adduser.",
            }
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{backend}{path}"
        if method == "get":
            resp = _http_get(url, headers=headers, params=params, timeout=15)
        elif method == "post":
            resp = _http_post(url, headers=headers, json=json_body, timeout=15)
        else:
            resp = _http_get(url, headers=headers, timeout=15)
        try:
            return resp.json()
        except ValueError:
            return {"detail": "invalid_response", "status_code": resp.status_code}

    def _call_user_api_raw(self, path, team_id, user_id, params=None):
        """Like _call_user_api but returns the raw response (for binary file downloads)."""
        backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
        token = self._get_member_token(team_id, user_id)
        if not token:
            return None
        headers = {"Authorization": f"Bearer {token}"}
        url = f"{backend}{path}"
        return _http_get(url, headers=headers, params=params, timeout=20)

    def _get_bot_token(self, team_id, slack_user_id=None):
        # Prefer the token of the specific user who ran the command (most likely valid)
        if slack_user_id:
            user = next((u for u in User.objects.filter(slack_user_id=slack_user_id) if u.slack_bot_token), None)
            if user:
                return user.slack_bot_token
        # Fallback: any Slack-connected user in this workspace
        return next(
            (u.slack_bot_token for u in User.objects.filter(slack_team_id=team_id) if u.slack_bot_token),
            None,
        )

    # ── Command handlers ──────────────────────────────────────────────────

    def _cmd_teamoverview(self, text, team_id, user_id):
        data = self._call_api(
            "/api/admin/admindashboard/dashboard/distribution-by-team/detail/", team_id,
            slack_user_id=user_id,
        )
        return self._format_teamoverview(data)

    def _cmd_vulnstats(self, text, team_id, user_id):
        data = self._call_api(
            "/api/admin/admindashboard/dashboard/detailed-vulnerabilities/", team_id,
            slack_user_id=user_id,
        )
        return self._format_vulnstats(data)

    def _cmd_dashboard(self, text, team_id, user_id):
        return [self._dashboard_image_block(team_id)]

    def _dashboard_image_block(self, team_id, kind="dashboard", alt_text="VaptFix Admin Dashboard"):
        """
        Real dashboard.html/team.html design (gauge/donut/bento cards)
        rendered as a PNG via SlackDashboardImageView — Block Kit can't do
        custom CSS, so this is the only way to show the actual design
        instead of a text/emoji approximation. Token is short-lived
        (10 min); `t=` just cache-busts so re-posting always shows fresh
        data.
        """
        import time
        token = _dashboard_image_signer().sign(team_id)
        backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
        url = (
            f"{backend}/api/admin/users/slack/dashboard-image/"
            f"?token={quote(token)}&kind={kind}&t={int(time.time())}"
        )
        return {
            "type": "image",
            "image_url": url,
            "alt_text": alt_text,
        }

    def _cmd_postnavbar(self, text, team_id, user_id):
        """
        /postnavbar — manually (re)posts the clickable navbar + Home
        dashboard message. Only needed for workspaces whose admin channel
        already existed before this feature shipped — new admin installs
        get this automatically the moment their #vaptfix-admin-dashboard
        channel is created (see ensure_vaptfix_channels).
        """
        section_blocks = self._nav_section_blocks("nav_home", team_id, user_id)
        return self._nav_buttons_block(active_action_id="nav_home") + section_blocks

    def _button_row_blocks(self, items, active_action_id=None, chunk_size=5):
        """
        Builds one or more "actions" blocks from (action_id, label) pairs —
        split into chunks of at most `chunk_size` buttons each. Slack's
        client collapses a single actions block with more than ~5 buttons
        into a "+N more" overflow instead of showing them all; splitting
        into several same-row-worth blocks avoids that entirely.
        """
        buttons = [
            {
                "type": "button",
                "text": {"type": "plain_text", "text": label, "emoji": True},
                "action_id": action_id,
                **({"style": "primary"} if action_id == active_action_id else {}),
            }
            for action_id, label in items
        ]
        return [
            {"type": "actions", "elements": buttons[i:i + chunk_size]}
            for i in range(0, len(buttons), chunk_size)
        ]

    def _nav_buttons_block(self, active_action_id=None):
        """
        The clickable navbar row(s) for the admin-dashboard-channel dashboard
        message — same button set every time so re-clicking after an update
        still shows all options. The active section gets a "primary" style
        so it's visually clear which tab is currently open. Returns a LIST
        of blocks (see _button_row_blocks) — callers must concatenate, not
        wrap in another list.
        """
        # All navbar tabs in ONE actions block so Slack shows a single row
        # (not 5+3 wrapped rows). Slack client may still wrap on very narrow
        # screens, but we no longer force a second block.
        return self._button_row_blocks(self._NAV_ITEMS, active_action_id=active_action_id, chunk_size=len(self._NAV_ITEMS))

    def _nav_section_blocks(self, action_id, team_id, user_id):
        """
        Resolves a nav button click to its section's content blocks — reuses
        the exact same data + formatters the equivalent slash command already
        uses, so the navbar never drifts out of sync with /dashboard,
        /vulnstats, /vulndata, /teamoverview, /supportdata.
        """
        if action_id == "nav_fix":
            return self._fix_subnav_block(active_sub="fix_sub_assets") + \
                self._fix_subtab_blocks("fix_sub_assets", team_id, user_id)

        if action_id == "nav_admin_demo":
            return self._allvuln_subnav_block(active_sub="av_sub_list") + \
                self._allvuln_subtab_blocks("av_sub_list", team_id, user_id)

        if action_id == "nav_register":
            return self._register_subnav_block(active_sub="reg_sub_register") + \
                self._register_subtab_blocks("reg_sub_register", team_id, user_id)

        if action_id == "nav_team":
            return self._team_subnav_block(active_sub="team_sub_team") + \
                self._team_subtab_blocks("team_sub_team", team_id, user_id)

        if action_id == "nav_teamperf":
            data = self._call_api(
                "/api/admin/admindashboard/dashboard/distribution-by-team/detail/", team_id,
                slack_user_id=user_id,
            )
            return self._format_teamoverview(data)

        if action_id == "nav_support":
            return self._support_tab_blocks(team_id, user_id)

        if action_id == "nav_download":
            # Uploads the report file to the channel as a side effect (same
            # as /downloadreport) and shows its confirmation card here too.
            return self._cmd_downloadreport("", team_id, user_id)

        # nav_home (default) — real bento-grid design, rendered as an image
        return [self._dashboard_image_block(team_id)]

    def _team_subnav_block(self, active_sub=None):
        """Second-level button row(s) shown under the 'Team Overview' nav tab."""
        return self._button_row_blocks(self._TEAM_SUBTABS, active_action_id=active_sub)

    def _team_subtab_blocks(self, sub_action_id, team_id, user_id):
        """
        Content for the 'Team Overview' sub-tabs. Add User / Delete User are
        NOT handled here — those open a modal instead (see
        SlackInteractivityView._handle_action), since they need input.
        """
        if sub_action_id == "team_sub_externaluser":
            data = self._call_api(
                "/api/admin/users_details/list-user-details/", team_id,
                params={"user_type": "external"}, slack_user_id=user_id,
            )
            return self._format_externalusers(data)

        # team_sub_team (default) — real team.html bento-card design, rendered as an image
        return [self._dashboard_image_block(team_id, kind="team", alt_text="Team Overview")]

    def _allvuln_subnav_block(self, active_sub=None):
        """Second-level button row(s) shown under the 'All Vulnerabilities' nav tab."""
        return self._button_row_blocks(self._ALLVULN_SUBTABS, active_action_id=active_sub)

    def _allvuln_subtab_blocks(self, sub_action_id, team_id, user_id):
        """
        Content for the 'All Vulnerabilities' sub-tabs.
        """
        if sub_action_id == "av_sub_approve":
            data = self._call_api(
                "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                slack_user_id=user_id,
            )
            results = self._assign_severity_short_ids(data.get("results") or [])
            return self._build_approve_list_blocks(results)

        if sub_action_id == "av_sub_reject":
            data = self._call_api(
                "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                slack_user_id=user_id,
            )
            results = self._assign_severity_short_ids(data.get("results") or [])
            return self._build_reject_list_blocks(results)

        if sub_action_id == "av_sub_stats":
            # Real vulnerability-stats.html design, rendered as an image —
            # pure display, no per-row input needed.
            return [self._dashboard_image_block(team_id, kind="stats", alt_text="Vulnerability Statistics")]

        if sub_action_id == "av_sub_support":
            # Real support-requests.html design, rendered as an image — pure
            # display, no per-row input needed, so no interactivity is lost.
            return [self._dashboard_image_block(team_id, kind="support", alt_text="Support Requests")]

        if sub_action_id == "av_sub_timeline":
            data = self._call_api(
                "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                slack_user_id=user_id,
            )
            return self._format_extension_requests(data)

        # av_sub_list / av_sub_details (default) — same paginated list; a
        # vuln clicked from either one lands on the same detail view.
        data = self._call_api(
            "/api/admin/adminregister/register/latest/vulns/", team_id,
            slack_user_id=user_id,
        )
        return self._format_vulndata_list(data)

    def _allvuln_detail_blocks(self, v, sub, team_id):
        """Manual / Automation Fix toggle for one specific vulnerability —
        both sides are strictly read-only for admins (no fix/run actions),
        matching the website's own admin-is-read-only behavior; whatever the
        assigned team actually does shows up here live on next view."""
        sid = v.get("short_id", "?")
        toggle = {
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🛠 Manual", "emoji": True},
                    "action_id": "av_detail_manual",
                    "value": sid,
                    **({"style": "primary"} if sub == "manual" else {}),
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🤖 Automation Fix", "emoji": True},
                    "action_id": "av_detail_automation",
                    "value": sid,
                    **({"style": "primary"} if sub == "automation" else {}),
                },
            ],
        }
        if sub == "automation":
            plugin_id = v.get("plugin_id")
            if not plugin_id:
                content = self._text_block("_No plugin ID available for this vulnerability — automation lookup not possible._")
            else:
                os_param = v.get("operating_system")
                automation = self._call_api(
                    f"/api/admin/automation-scripts/match/{plugin_id}/", team_id,
                    params={"os": os_param} if os_param else None,
                )
                content = self._format_vulndata_automation_detail(v, automation)
        else:
            steps_data = None
            fix_vuln_id = v.get("fix_vulnerability_id")
            if fix_vuln_id:
                steps_data = self._call_api(
                    f"/api/admin/adminregister/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id,
                )
            content = self._format_vulndata_single(v, steps_data)
        return [toggle] + content

    def _fix_subnav_block(self, active_sub=None):
        """Second-level button row(s) shown under the 'Fix' nav tab."""
        return self._button_row_blocks(self._FIX_SUBTABS, active_action_id=active_sub)

    def _register_subnav_block(self, active_sub=None):
        """Second-level button row under the 'Register' nav tab: Register | Script."""
        return self._button_row_blocks(self._REGISTER_SUBTABS, active_action_id=active_sub)

    def _register_subtab_blocks(self, sub_action_id, team_id, user_id):
        """Content for Register sub-tabs — Register (default vuln list) or Script stats."""
        if sub_action_id == "reg_sub_script":
            try:
                data = self._call_api(
                    "/api/admin/automation-scripts/stats/", team_id,
                    slack_user_id=user_id,
                )
            except Exception as exc:
                logger.exception("[reg_sub_script] stats fetch failed: %s", exc)
                return self._text_block(f"❌ Could not load Script data: `{exc}`")
            if not isinstance(data, dict):
                return self._text_block("❌ Could not load Script data (invalid API response).")
            if data.get("detail") and not data.get("stats"):
                return self._text_block(f"❌ {data.get('detail')}")
            return self._format_script_tab(data, offset=0)

        # reg_sub_register (default) — existing Register UI
        try:
            vd_data = self._call_api(
                "/api/admin/adminregister/register/latest/vulns/", team_id,
                slack_user_id=user_id,
            )
        except Exception as exc:
            logger.exception("[reg_sub_register] latest vulns fetch failed: %s", exc)
            return self._text_block(f"❌ Could not load Register data: `{exc}`")
        if not isinstance(vd_data, (dict, list)):
            return self._text_block("❌ Could not load Register data (invalid API response).")
        if isinstance(vd_data, dict) and vd_data.get("detail") and not (
            vd_data.get("rows") or vd_data.get("results") or vd_data.get("vulnerabilities")
        ):
            return self._text_block(f"❌ {vd_data.get('detail')}")
        return self._format_register_tab(vd_data, sev_filter="all", st_filter="all", offset=0)

    def _fix_subtab_blocks(self, sub_action_id, team_id, user_id):
        """Content for the 'Fix' sub-tabs — All Assets (grouped by host from
        the same latest-vulns list, no new backend endpoint needed) and All
        Vulnerabilities (identical list to the All Vulnerabilities nav tab).
        Clicking "View" on any row lands on the same shared Manual/Automation
        detail view the All Vulnerabilities tab uses."""
        if sub_action_id == "fix_sub_vulns":
            data = self._call_api(
                "/api/admin/adminregister/register/latest/vulns/", team_id,
                slack_user_id=user_id,
            )
            return self._format_vulndata_list(data)

        # fix_sub_assets (default)
        data = self._call_api(
            "/api/admin/adminregister/register/latest/vulns/", team_id,
            slack_user_id=user_id,
        )
        rows = data.get("rows") or data.get("results") or (data if isinstance(data, list) else [])
        return self._format_asset_list(rows)

    def _group_assets_from_vulns(self, rows):
        """Groups the flat vuln list by host/asset — total + severity counts
        per asset. No new backend aggregation endpoint needed."""
        assets = {}
        for v in rows:
            host = v.get("asset") or v.get("host_name") or "Unknown"
            sev = (v.get("severity") or v.get("risk_factor") or "").strip().lower()
            entry = assets.setdefault(host, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
            entry["total"] += 1
            if sev in ("critical", "high", "medium", "low"):
                entry[sev] += 1
        return sorted(assets.items(), key=lambda kv: kv[0])

    def _numbered_pagination_block(self, offset, page_size, total, base_action_id, value_prefix=""):
        """
        Design-style pagination (‹ 1 2 3 › instead of plain Previous/Next
        text) — used for the Fix tab's asset/vuln lists. Each page-number
        button needs its OWN action_id (Slack rejects a block where two
        buttons share one action_id — confirmed empirically with the
        earlier Prev/Next "invalid_blocks" bug), so the page number is
        baked into the action_id itself: f"{base_action_id}_p{page_num}".
        `value_prefix` lets callers carry extra context (e.g. "host|") —
        the actual offset is appended after it.
        """
        total_pages = max(1, -(-total // page_size)) if total else 1
        current_page = offset // page_size + 1

        elements = []
        if current_page > 1:
            elements.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "‹", "emoji": True},
                # "_prevp"/"_nextp" (not just "_p{N}") so these can never
                # collide with a numbered page button landing on the same
                # target page — two buttons sharing an action_id is exactly
                # what caused the earlier "invalid_blocks" silent-failure bug.
                "action_id": f"{base_action_id}_prevp{current_page - 1}",
                "value": f"{value_prefix}{(current_page - 2) * page_size}",
            })

        window = 5
        start_p = max(1, min(current_page - window // 2, total_pages - window + 1))
        end_p = min(total_pages, start_p + window - 1)
        for p in range(start_p, end_p + 1):
            elements.append({
                "type": "button",
                "text": {"type": "plain_text", "text": str(p), "emoji": True},
                "action_id": f"{base_action_id}_p{p}",
                "value": f"{value_prefix}{(p - 1) * page_size}",
                **({"style": "primary"} if p == current_page else {}),
            })

        if current_page < total_pages:
            elements.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "›", "emoji": True},
                "action_id": f"{base_action_id}_nextp{current_page + 1}",
                "value": f"{value_prefix}{current_page * page_size}",
            })

        return {"type": "actions", "elements": elements} if elements else None

    # Severity emoji — Block Kit has no custom colors, this is the closest
    # Slack-native approximation to the design's exact RGB pills
    # (critical rgb(180,35,24), high rgb(220,38,38), medium rgb(245,158,11),
    # low rgb(16,185,129)).
    _ASSET_SEV_EMOJI = [("critical", "🔴", "Critical"), ("high", "🟠", "High"), ("medium", "🟡", "Medium"), ("low", "🟢", "Low")]

    def _format_asset_list(self, rows, offset=0):
        PAGE_SIZE = 5
        assets = self._group_assets_from_vulns(rows)
        count = len(assets)
        offset = max(0, min(offset, max(count - 1, 0))) if count else 0
        page_items = assets[offset:offset + PAGE_SIZE]
        end_num = offset + len(page_items)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🖥 All Assets", "emoji": True}},
            self._ctx("Every asset in your latest report. Click one to see its vulnerabilities."),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total:* {count} assets — showing {offset + 1 if page_items else 0}-{end_num}"}},
            {"type": "divider"},
        ]
        if not page_items:
            return blocks + self._text_block("No assets found.")

        for host, c in page_items:
            counts_txt = "  ".join(
                f"{emoji} {label}: {c[key]}" for key, emoji, label in self._ASSET_SEV_EMOJI if c[key]
            ) or "No open vulnerabilities"
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"🖥 `{host}`\n      {c['total']} Vulns\n      {counts_txt}"},
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View", "emoji": True},
                    "action_id": "view_fix_asset",
                    "value": f"{host}|0",
                },
            })
            blocks.append({"type": "divider"})

        pg_block = self._numbered_pagination_block(offset, PAGE_SIZE, count, "view_fix_assets_pg")
        if pg_block:
            blocks.append(pg_block)
        return blocks

    def _format_asset_vulns(self, rows, host, offset=0):
        PAGE_SIZE = 5
        matching = self._assign_severity_short_ids([v for v in rows if (v.get("asset") or v.get("host_name")) == host])
        count = len(matching)
        offset = max(0, min(offset, max(count - 1, 0))) if count else 0
        page_items = matching[offset:offset + PAGE_SIZE]
        end_num = offset + len(page_items)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🖥 {host}"[:150], "emoji": True}},
            self._ctx(f"Vulnerabilities on this asset — {count} total."),
            {
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "← Back to All Assets", "emoji": True},
                    "action_id": "view_fix_asset_back",
                }],
            },
            {"type": "divider"},
        ]
        if not page_items:
            return blocks + self._text_block("No vulnerabilities found for this asset.")

        for v in page_items:
            sid  = v.get("short_id", "?")
            name = v.get("vul_name") or "Unknown"
            sev  = (v.get("severity") or "").capitalize() or "—"
            st   = v.get("status") or "open"
            sev_icon = self._SEV_EMOJI_MAP.get(sev.lower(), "⚪")
            safe_sid = "".join(ch if ch.isalnum() else "_" for ch in str(sid))[:40]
            blocks.append({
                "type": "context",
                "elements": [
                    self._status_icon_image_element(st),
                    {"type": "mrkdwn", "text": f"`{sid}` *{name}*"},
                ],
            })
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{sev_icon} *{sev}*  |  Status: {st.capitalize()}",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View", "emoji": True},
                    "action_id": f"view_allvuln_detail_{safe_sid}",
                    "value": sid,
                },
            })
            blocks.append({"type": "divider"})

        pg_block = self._numbered_pagination_block(
            offset, PAGE_SIZE, count, "view_fix_asset_vulns_pg", value_prefix=f"{host}|",
        )
        if pg_block:
            blocks.append(pg_block)
        return blocks

    def _build_reject_modal(self, sid, vuln_label):
        """
        Reject always needs a reason, and Slack can't do an inline text
        input in a regular message — so "Reject Request" on a specific row
        opens this small modal just for the reason, already knowing exactly
        which request (sid carried via private_metadata, no dropdown needed
        since the row itself already identified the target).
        """
        return {
            "type": "modal",
            "callback_id": "modal_reject_submit",
            "private_metadata": sid,
            "title": {"type": "plain_text", "text": "Reject Request"},
            "submit": {"type": "plain_text", "text": "Reject"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"Rejecting `{sid}` — *{vuln_label}*"}},
                {
                    "type": "input",
                    "block_id": "reason_block",
                    "label": {"type": "plain_text", "text": "Reason"},
                    "optional": True,
                    "element": {"type": "plain_text_input", "action_id": "reason_input"},
                },
            ],
        }

    def _extension_page_for_sid(self, results, sid, page_size=4):
        idx = next((i for i, r in enumerate(results) if r.get("short_id") == sid), 0)
        return (idx // page_size) * page_size

    def _build_approve_list_blocks(self, results, offset=0):
        # Only pending + already-approved — an already-rejected request has
        # no business showing up (with an Approve button) on this tab.
        results = [r for r in results if r.get("status", "review") != "rejected"]
        PAGE_SIZE = 4
        count = len(results)
        offset = max(0, min(offset, max(count - 1, 0))) if count else 0
        page_items = results[offset:offset + PAGE_SIZE]
        end_num = offset + len(page_items)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "✅ Approve Timeline Extension", "emoji": True}},
            self._ctx("Pick a request to approve its mitigation-deadline extension."),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total Requests:* {count}"}},
            {"type": "divider"},
        ]
        if not page_items:
            return blocks + self._text_block("No timeline extension requests found.")

        for r in page_items:
            sid  = r.get("short_id", "?")
            vuln = r.get("vul_name") or "Unknown"
            days = r.get("extension_days", 0)
            st   = r.get("status", "review")
            section = {"type": "section", "text": {"type": "mrkdwn", "text": f"`{sid}` *{vuln}*\n+{days} days"}}
            if st == "approved":
                section["text"]["text"] += "\n✅ *Approved*"
            else:
                section["accessory"] = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Approve Request", "emoji": True},
                    "action_id": "av_list_approve_row",
                    "value": f"{sid}|{offset}",
                    "style": "primary",
                }
            blocks.append(section)

        nav_buttons = []
        if offset > 0:
            nav_buttons.append({
                "type": "button", "text": {"type": "plain_text", "text": "◀ Previous", "emoji": True},
                "action_id": "av_approve_list_prev", "value": f"{max(0, offset - PAGE_SIZE)}",
            })
        if end_num < count:
            nav_buttons.append({
                "type": "button", "text": {"type": "plain_text", "text": "Next ▶", "emoji": True},
                "action_id": "av_approve_list_next", "value": f"{offset + PAGE_SIZE}",
            })
        if nav_buttons:
            blocks.append({"type": "actions", "elements": nav_buttons})
        return blocks

    def _build_reject_list_blocks(self, results, offset=0):
        # Only pending + already-rejected — an already-approved request has
        # no business showing up (with a Reject button) on this tab.
        results = [r for r in results if r.get("status", "review") != "approved"]
        PAGE_SIZE = 4
        count = len(results)
        offset = max(0, min(offset, max(count - 1, 0))) if count else 0
        page_items = results[offset:offset + PAGE_SIZE]
        end_num = offset + len(page_items)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "❌ Reject Timeline Extension", "emoji": True}},
            self._ctx("Pick a request to reject, with an optional reason."),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total Requests:* {count}"}},
            {"type": "divider"},
        ]
        if not page_items:
            return blocks + self._text_block("No timeline extension requests found.")

        for r in page_items:
            sid  = r.get("short_id", "?")
            vuln = r.get("vul_name") or "Unknown"
            days = r.get("extension_days", 0)
            st   = r.get("status", "review")
            section = {"type": "section", "text": {"type": "mrkdwn", "text": f"`{sid}` *{vuln}*\n+{days} days"}}
            if st == "rejected":
                reason = r.get("reason") or "—"
                section["text"]["text"] += f"\n❌ *Rejected* — Reason: {reason}"
            else:
                section["accessory"] = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "Reject Request", "emoji": True},
                    "action_id": "av_list_reject_row",
                    "value": f"{sid}|{offset}",
                    "style": "danger",
                }
            blocks.append(section)

        nav_buttons = []
        if offset > 0:
            nav_buttons.append({
                "type": "button", "text": {"type": "plain_text", "text": "◀ Previous", "emoji": True},
                "action_id": "av_reject_list_prev", "value": f"{max(0, offset - PAGE_SIZE)}",
            })
        if end_num < count:
            nav_buttons.append({
                "type": "button", "text": {"type": "plain_text", "text": "Next ▶", "emoji": True},
                "action_id": "av_reject_list_next", "value": f"{offset + PAGE_SIZE}",
            })
        if nav_buttons:
            blocks.append({"type": "actions", "elements": nav_buttons})
        return blocks

    def _build_adduser_modal(self):
        return {
            "type": "modal",
            "callback_id": "modal_adduser_submit",
            "title": {"type": "plain_text", "text": "Add User"},
            "submit": {"type": "plain_text", "text": "Add User"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
                {
                    "type": "input",
                    "block_id": "user_block",
                    "label": {"type": "plain_text", "text": "User"},
                    "element": {"type": "users_select", "action_id": "user_select"},
                },
                {
                    "type": "input",
                    "block_id": "type_block",
                    "label": {"type": "plain_text", "text": "Type"},
                    "element": {
                        "type": "static_select",
                        "action_id": "type_select",
                        "initial_option": {"text": {"type": "plain_text", "text": "external"}, "value": "external"},
                        "options": [
                            {"text": {"type": "plain_text", "text": "external"}, "value": "external"},
                            {"text": {"type": "plain_text", "text": "internal"}, "value": "internal"},
                        ],
                    },
                },
                {
                    "type": "input",
                    "block_id": "team_block",
                    "label": {"type": "plain_text", "text": "Team(s)"},
                    "element": {
                        "type": "checkboxes",
                        "action_id": "team_checks",
                        "options": [
                            {"text": {"type": "plain_text", "text": name}, "value": code}
                            for code, name in self._TEAM_MAP.items()
                        ],
                    },
                },
            ],
        }

    def _build_deleteuser_modal(self):
        return {
            "type": "modal",
            "callback_id": "modal_deleteuser_submit",
            "title": {"type": "plain_text", "text": "Delete User"},
            "submit": {"type": "plain_text", "text": "Confirm"},
            "close": {"type": "plain_text", "text": "Cancel"},
            "blocks": [
                {
                    "type": "input",
                    "block_id": "user_block",
                    "label": {"type": "plain_text", "text": "User"},
                    "element": {"type": "users_select", "action_id": "user_select"},
                },
                {
                    "type": "input",
                    "block_id": "action_block",
                    "label": {"type": "plain_text", "text": "Action"},
                    "element": {
                        "type": "static_select",
                        "action_id": "action_select",
                        "initial_option": {
                            "text": {"type": "plain_text", "text": "Deactivate (reversible)"},
                            "value": "deactivate",
                        },
                        "options": [
                            {"text": {"type": "plain_text", "text": "Deactivate (reversible)"}, "value": "deactivate"},
                            {"text": {"type": "plain_text", "text": "Delete permanently (cannot be undone)"}, "value": "delete_permanent"},
                        ],
                    },
                },
            ],
        }

    def _build_result_modal(self, title, blocks):
        """A read-only modal used to show a command's result INSIDE the popup
        itself (matching the design's inline success-box), instead of
        posting a separate message to the channel."""
        return {
            "type": "modal",
            "title": {"type": "plain_text", "text": title[:24]},
            "close": {"type": "plain_text", "text": "Done"},
            "blocks": blocks[:100],
        }

    def _get_workspace_report_id(self, team_id):
        """
        Find the latest report_id for this Slack workspace's admin —
        workspace-scoped first (same fix as _get_team_vulns Step 1: don't
        widen to all staff system-wide unless nothing found for this
        workspace, or a multi-tenant install would leak another admin's data).
        """
        import pymongo as _pymongo
        from vaptfix.mongo_client import MongoContext

        workspace_users = list(User.objects.filter(slack_team_id=team_id))

        def _find(users):
            if not users:
                return None
            ids    = [str(u.id) for u in users]
            emails = [e for e in (getattr(u, "email", "") for u in users) if e]
            conds  = [{"admin_id": aid} for aid in ids] + [{"admin_email": em} for em in emails]
            with MongoContext() as db:
                return db["nessus_reports"].find_one(
                    {"$or": conds}, {"report_id": 1}, sort=[("uploaded_at", _pymongo.DESCENDING)],
                )

        meta = _find(workspace_users)
        if not meta:
            staff_users = [u for u in User.objects.all() if getattr(u, "is_staff", False)]
            all_users = list({u.id: u for u in workspace_users + staff_users}.values())
            meta = _find(all_users)
        return meta.get("report_id") if meta else None

    def _cmd_supportdata(self, text, team_id, user_id):
        """
        /supportdata — Per-ticket support request list (who raised it, which
        vuln, status) — not just aggregate counts.
        """
        return self._support_tab_blocks(team_id, user_id)

    def _cmd_request(self, text, team_id, user_id):
        data = self._call_api(
            "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
            slack_user_id=user_id,
        )
        return self._format_extension_requests(data)

    def _lookup_extension_request(self, ident, team_id, user_id):
        """
        Resolve a /approve or /reject identifier (short id c1/h2/m3/l4... OR
        the raw Mongo request id shown in /request) to the FULL request
        details from the existing read-only list API — used both to find
        the real request_id to PATCH and to build a proper confirmation
        message (vuln name/team/days) instead of just echoing back a bare
        Mongo id. No API file touched — this only reads the already-existing
        list endpoint the same way /request itself does.
        """
        data = self._call_api(
            "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/",
            team_id, slack_user_id=user_id,
        )
        results = self._assign_severity_short_ids(data.get("results") or [])
        ident_clean = ident.strip()
        return next(
            (r for r in results
             if r.get("short_id") == ident_clean.lower() or r.get("request_id") == ident_clean),
            None,
        )

    def _cmd_approve(self, text, team_id, user_id):
        display_id = text.strip()
        if not display_id:
            return self._text_block(
                "*Usage:* `/approve [request-id]`\n"
                "_Approves a team's mitigation deadline extension request. Get IDs (short or full) from `/request`._"
            )
        target = self._lookup_extension_request(display_id, team_id, user_id)
        request_id = target.get("request_id") if target else display_id
        data = self._call_api(
            f"/api/admin/admindashboard/dashboard/mitigation-timeline-extension/{request_id}/status/",
            team_id, method="patch", json_body={"status": "approved"}, slack_user_id=user_id,
        )
        return self._format_status_update(data, "approved", display_id, target)

    def _cmd_reject(self, text, team_id, user_id):
        parts = text.strip().split(None, 1)
        if not parts:
            return self._text_block(
                "*Usage:* `/reject [request-id] [reason]`\n"
                "_Rejects a team's timeline extension request with an optional reason. Get IDs (short or full) from `/request`._"
            )
        display_id = parts[0]
        reason = parts[1] if len(parts) > 1 else ""
        target = self._lookup_extension_request(display_id, team_id, user_id)
        request_id = target.get("request_id") if target else display_id
        data = self._call_api(
            f"/api/admin/admindashboard/dashboard/mitigation-timeline-extension/{request_id}/status/",
            team_id, method="patch", json_body={"status": "rejected", "admin_comment": reason},
            slack_user_id=user_id,
        )
        return self._format_status_update(data, "rejected", display_id, target, reason=reason)

    def _cmd_externalusers(self, text, team_id, user_id):
        data = self._call_api(
            "/api/admin/users_details/list-user-details/", team_id,
            params={"user_type": "external"}, slack_user_id=user_id,
        )
        return self._format_externalusers(data)

    def _cmd_report(self, text, team_id, user_id):
        frontend = getattr(settings, "FRONTEND_URL", "https://vaptfix.secureitlab.com")
        parts = text.strip().split(None, 1)

        if not parts:
            # Full platform report — link to dashboard
            return [
                {"type": "header", "text": {"type": "plain_text", "text": "📄 Reports", "emoji": True}},
                self._ctx("Download full or filtered vulnerability reports. Filter by team or specific vuln ID."),
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": (
                        "*Download Options:*\n"
                        f"• Full Report: <{frontend}/reports|Open Reports Dashboard>\n"
                        "• Filter by team: `/report team [team-name]`\n"
                        "• Filter by vuln: `/report vuln [vuln-id]`"
                    )}},
            ]

        subcommand = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if subcommand == "team" and arg:
            report_url = f"{frontend}/reports?team={arg.replace(' ', '+')}"
            return [
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": f"📄 *Report — Team: {arg}*\n<{report_url}|Download Team Report>"}},
            ]
        elif subcommand == "vuln" and arg:
            report_url = f"{frontend}/reports?vuln={arg}"
            return [
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": f"📄 *Report — Vuln ID: `{arg}`*\n<{report_url}|Download Vuln Report>"}},
            ]
        else:
            return self._text_block(
                "Usage:\n"
                "• `/report` — Full platform report\n"
                "• `/report team [team-name]` — Team filtered report\n"
                "• `/report vuln [vuln-id]` — Specific vulnerability report"
            )

    def _cmd_downloadreport(self, text, team_id, user_id):
        """
        /downloadreport — generates the full vulnerability report as a
        self-contained HTML file and uploads it to this channel.
        /downloadreport pdf — same report, as a PDF instead.
        Pulls the same consolidated data (report/download-data/) the
        website's report page shows, then renders it with the exact same
        builders the browser-triggered download uses
        (adminregister.views._render_report_html / _render_report_pdf)
        — so the file looks the same regardless of where it was requested from.
        """
        as_pdf = text.strip().lower() == "pdf"

        data = self._call_api(
            "/api/admin/adminregister/report/download-data/", team_id, slack_user_id=user_id,
        )
        if data.get("detail"):
            return self._text_block(f"❌ {data['detail']}")

        from adminregister.views import _render_report_html
        html = _render_report_html(data)

        pdf_error = None
        if as_pdf:
            from adminregister.views import _render_report_pdf
            try:
                file_bytes = _render_report_pdf(html)
                filename = f"vaptfix-report-{data.get('report_id', 'latest')}.pdf"
            except Exception as exc:
                pdf_error = str(exc)
                file_bytes = html.encode("utf-8")
                filename = f"vaptfix-report-{data.get('report_id', 'latest')}.html"
        else:
            file_bytes = html.encode("utf-8")
            filename = f"vaptfix-report-{data.get('report_id', 'latest')}.html"

        bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
        uploaded = False
        if bot_token:
            admin_ch_id = self._get_admin_channel_id(bot_token)
            if admin_ch_id:
                uploaded = self._upload_file_to_slack(
                    bot_token, admin_ch_id, filename, file_bytes,
                    initial_comment="📄 Vulnerability Management Report",
                )

        vulns = data.get("vulnerabilities") or {}
        total = sum(vulns.values())
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "📄 Download Report", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Report*\n{data.get('vul_management_program', '—')}"},
                {"type": "mrkdwn", "text": f"*Generated On*\n{data.get('report_generated_on', '—')}"},
                {"type": "mrkdwn", "text": f"*Total Assets*\n{data.get('total_assets', 0)}"},
                {"type": "mrkdwn", "text": f"*Risk Score*\n{data.get('risk_score', 0)}/100"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": (
                    f"*Findings:* {total} total — "
                    f"🔴 {vulns.get('critical', 0)} Critical | 🟠 {vulns.get('high', 0)} High | "
                    f"🟡 {vulns.get('medium', 0)} Medium | 🟢 {vulns.get('low', 0)} Low"
                )}},
        ]
        if pdf_error:
            blocks.append(self._ctx(f"⚠️ PDF generation failed ({pdf_error[:150]}) — uploaded HTML instead."))
        elif uploaded:
            ftype = "PDF" if as_pdf else "HTML"
            blocks.append(self._ctx(f"📎 Full {ftype} report uploaded above — open it to view or print."))
        else:
            blocks.append(self._ctx("⚠️ Could not upload the file (check the bot's `files:write` scope) — summary shown above only."))
        return blocks

    def _cmd_vulndata(self, text, team_id, user_id):
        """
        /vulndata — List all vulns in the latest report (page 1)
        /vulndata 2 — Page 2, etc. (reliable text-based paging, works
          regardless of whether the Next/Previous buttons are wired up)
        /vulndata automation — Automation breakdown stats
        /vulndata [short-id] [page] — Full read-only detail + steps for one
          vuln (admin can view the same steps a team member works through,
          but never mark them done — that stays user-only)
        /vulndata [fix_vuln_id] — Step-by-step detail for one vuln
        """
        text_stripped = text.strip()
        short_id_match = re.fullmatch(r"([chml]\d+)(?:\s+(\d+))?", text_stripped.lower())
        if text_stripped.lower() == "automation":
            data = self._call_api("/api/admin/adminregister/register/latest/vulns/", team_id,
                                  slack_user_id=user_id)
            return self._format_vulndata_automation(data)
        elif text_stripped.isdigit() and len(text_stripped) <= 3:
            # Short all-digit argument = page number, not a fix_vuln_id
            # (those are 24-char Mongo ObjectIds).
            page = max(1, int(text_stripped))
            data = self._call_api("/api/admin/adminregister/register/latest/vulns/", team_id,
                                  slack_user_id=user_id)
            return self._format_vulndata_list(data, offset=(page - 1) * 10)
        elif short_id_match:
            # Short vuln ID (h1/m5/c3/l2...) — same style used everywhere
            # else (/viewassigned, /startfix). Resolve against the full
            # admin-wide latest-report list (not team-scoped) and show
            # complete details instead of the near-empty result we used to
            # get from treating it as a fix_vuln_id (a 24-char Mongo id).
            short_id = short_id_match.group(1)
            steps_page = max(1, int(short_id_match.group(2))) if short_id_match.group(2) else 1
            data = self._call_api("/api/admin/adminregister/register/latest/vulns/", team_id,
                                  slack_user_id=user_id)
            rows = self._assign_severity_short_ids(data.get("rows") or [])
            target = next((r for r in rows if r.get("short_id") == short_id), None)
            if not target:
                return self._text_block(
                    f"❌ No vulnerability found with ID `{short_id}`. "
                    f"Run `/vulndata` to see the current list with IDs."
                )
            steps_data = None
            fix_vuln_id = target.get("fix_vulnerability_id")
            if fix_vuln_id:
                steps_data = self._call_api(
                    f"/api/admin/adminregister/fix-vulnerability/{fix_vuln_id}/step-complete/",
                    team_id, slack_user_id=user_id,
                )
            return self._format_vulndata_single(target, steps_data, offset=(steps_page - 1) * 3)
        elif text_stripped:
            fix_vuln_id = text_stripped
            data = self._call_api(
                f"/api/admin/adminregister/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id,
                slack_user_id=user_id,
            )
            return self._format_vulndata_detail(data, fix_vuln_id)
        else:
            data = self._call_api("/api/admin/adminregister/register/latest/vulns/", team_id,
                                  slack_user_id=user_id)
            return self._format_vulndata_list(data)

    def _cmd_vaptcheck(self, text, team_id, user_id):
        """
        /vaptcheck — Admin diagnostic command.
        Directly queries MongoDB and shows: admin found, report count, card count, sample teams.
        Helps diagnose why team channels show no data.
        """
        import pymongo as _pymongo
        from vaptfix.mongo_client import MongoContext

        # Workspace-scoped Slack admins for THIS Slack team only (do NOT widen to
        # all staff system-wide by default — that would show an unrelated admin's
        # data on a multi-tenant install). Only fall back if this workspace has
        # no report at all.
        workspace_users = list(User.objects.filter(slack_team_id=team_id))
        all_users        = workspace_users

        if not all_users:
            return self._text_block("❌ No users found for this Slack workspace. Connect VaptFix to Slack first.")

        def _conditions_for(users):
            ids    = [str(u.id) for u in users]
            emails = [e for e in (getattr(u, "email", "") for u in users) if e]
            return [{"admin_id": aid} for aid in ids] + [{"admin_email": em} for em in emails]

        conditions = _conditions_for(all_users)
        with MongoContext() as _probe_db:
            if _probe_db["nessus_reports"].count_documents({"$or": conditions}) == 0:
                staff_users = [u for u in User.objects.all() if getattr(u, "is_staff", False)]
                all_users   = list({u.id: u for u in workspace_users + staff_users}.values())
                conditions  = _conditions_for(all_users)

        with MongoContext() as db:
            report_count = db["nessus_reports"].count_documents({"$or": conditions})
            latest_doc   = db["nessus_reports"].find_one(
                {"$or": conditions},
                {"report_id": 1, "uploaded_at": 1, "admin_email": 1, "admin_id": 1, "vulnerabilities_by_host": 1},
                sort=[("uploaded_at", _pymongo.DESCENDING)],
            )

            report_id      = str(latest_doc.get("report_id", "")) if latest_doc else "none"
            uploaded_at    = str(latest_doc.get("uploaded_at", ""))[:19] if latest_doc else "—"
            report_owner   = latest_doc.get("admin_email", latest_doc.get("admin_id", "?")) if latest_doc else "—"

            # Count total vulns in latest report
            total_vulns = 0
            if latest_doc:
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    total_vulns += len(host.get("vulnerabilities", []))

            # Count cards and sample assigned_teams
            card_count   = db["vulnerability_cards"].count_documents({"report_id": report_id}) if report_id != "none" else 0
            sample_teams = []
            if card_count > 0:
                for card in db["vulnerability_cards"].find(
                    {"report_id": report_id},
                    {"assigned_team": 1, "vulnerability_name": 1},
                    limit=5,
                ):
                    at = card.get("assigned_team", "—") or "—"
                    vn = (card.get("vulnerability_name", "") or "")[:40]
                    sample_teams.append(f"• `{at}` — {vn}")

            # Count support requests across all workspace users
            support_count = db["support_requests"].count_documents({"admin_id": {"$in": all_ids}})

        status_icon  = "✅" if report_count > 0 else "❌"
        cards_icon   = "✅" if card_count > 0 else "⚠️"
        fallback_msg = "" if card_count > 0 else "\n_No AI cards — keyword-based team assignment active._"
        ws_emails    = ", ".join(all_emails[:4])
        sample_text  = "\n".join(sample_teams) if sample_teams else "_No cards yet_"

        return [
            {"type": "header", "text": {"type": "plain_text", "text": "🔍 VaptFix DB Diagnostic", "emoji": True}},
            self._ctx("Direct MongoDB check — use this to verify data is in the database"),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Workspace Users Checked*\n{ws_emails}"},
                {"type": "mrkdwn", "text": f"*Report Owner (in DB)*\n{report_owner}"},
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Reports in DB*\n{status_icon} {report_count}"},
                {"type": "mrkdwn", "text": f"*Latest Report ID*\n`{report_id}`"},
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Upload Date*\n{uploaded_at}"},
                {"type": "mrkdwn", "text": f"*Total Vulns in Report*\n{total_vulns}"},
            ]},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Vulnerability Cards*\n{cards_icon} {card_count}" + fallback_msg},
                {"type": "mrkdwn", "text": f"*Support Requests*\n{support_count}"},
            ]},
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Sample Card Team Assignments (first 5):*\n{sample_text}"}},
        ]

    def _cmd_verifications(self, text, team_id, user_id):
        """
        /verifications — List vulnerabilities pending superadmin approval
        (status = open/review, i.e. a team ran /retest and is waiting).
        The backing API (/api/admin/upload_report/verifications/pending/) is
        superadmin-only (is_superuser=True) and returns pending items across
        ALL tenants — results are filtered here to this Slack workspace's
        own admin so other tenants' data is never shown.
        """
        data = self._call_api(
            "/api/admin/upload_report/verifications/pending/", team_id, slack_user_id=user_id,
        )
        if data.get("detail"):
            return self._text_block(
                f"❌ `{data.get('detail')}`\n"
                "_This command requires your VaptFix account to be a superadmin (is_superuser)._"
            )
        workspace_admin_ids = {str(u.id) for u in User.objects.filter(slack_team_id=team_id)}
        results = [r for r in (data.get("results") or []) if str(r.get("admin_id", "")) in workspace_admin_ids]
        return self._format_verifications(results)

    def _cmd_verify(self, text, team_id, user_id):
        """
        /approvefix [fix_vuln_id] — Approve a pending verification request.
        This CLOSES the vulnerability immediately (matches the web dashboard's
        superadmin approval flow). Get fix_vuln_id from /verifications.
        (Command is named /approvefix, not /verify — Slack rejected /verify
        as a reserved/unavailable command name.)
        """
        fix_vuln_id = text.strip()
        if not fix_vuln_id:
            return self._text_block(
                "*Usage:* `/approvefix [fix_vuln_id]`\n"
                "_Approves & closes a vulnerability pending verification. Get IDs from `/verifications`._"
            )
        resp = self._call_api(
            "/api/admin/upload_report/verifications/approve/", team_id,
            method="post", json_body={"fix_vuln_id": fix_vuln_id, "action": "approve"},
            slack_user_id=user_id,
        )
        if resp.get("status") != "closed":
            return self._text_block(f"❌ `{resp.get('detail') or 'Could not approve verification.'}`")

        vuln_name = resp.get("vulnerability_name", "")
        asset     = resp.get("asset", "")

        # The approve API doesn't return assigned_team — read it directly from
        # the record it just moved into fix_vulnerabilities_closed, so we know
        # which team's Slack channel to notify. Direct Mongo read, no new API.
        from vaptfix.mongo_client import MongoContext
        assigned_team = ""
        with MongoContext() as db:
            closed_doc = db["fix_vulnerabilities_closed"].find_one(
                {"fix_vulnerability_id": fix_vuln_id}, {"assigned_team": 1},
            )
            if closed_doc:
                assigned_team = closed_doc.get("assigned_team", "")

        if assigned_team:
            self._notify_team(
                team_id, user_id, assigned_team,
                f"✅ *Vulnerability Verified & Closed*\n"
                f"`{vuln_name}` on `{asset}` has been approved by the superadmin and is now closed. Great work!"
            )

        return [
            {"type": "header", "text": {"type": "plain_text", "text": "✅ Verification Approved & Closed", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": (
                f"*Vulnerability:* {vuln_name}\n"
                f"*Asset:* `{asset}`\n\n"
                + ("_Vulnerability is now closed. Team has been notified in their channel._"
                   if assigned_team else
                   "_Vulnerability is now closed._ ⚠️ _Could not determine team channel to notify._")
            )}},
        ]

    # Team short-code → full name mapping for /adduser
    _TEAM_MAP = {
        "pm": "Patch Management",
        "cm": "Configuration Management",
        "ns": "Network Security",
        "af": "Architectural Flaws",
    }

    def _cmd_adduser(self, text, team_id, user_id):
        parts = text.strip().split()
        # Minimum: @mention  type  team
        if len(parts) < 3:
            return self._text_block(
                "*Usage:* `/adduser @username external|internal pm|cm|ns|af [pm|cm|ns|af ...]`\n"
                "*Teams:* `pm` = Patch Management | `cm` = Configuration Management | "
                "`ns` = Network Security | `af` = Architectural Flaws\n"
                "*Example:* `/adduser @Ritu external pm cm`"
            )

        mention   = parts[0]
        user_type = "internal" if parts[1].lower() in ("internal", "team", "admin") else "external"
        team_codes = [p.lower() for p in parts[2:]]

        # Validate team codes
        unknown = [c for c in team_codes if c not in self._TEAM_MAP]
        if unknown:
            return self._text_block(
                f"❌ Unknown team code(s): `{'`, `'.join(unknown)}`\n"
                "Valid codes: `pm` | `cm` | `ns` | `af`"
            )

        team_names  = [self._TEAM_MAP[c] for c in team_codes]
        primary_team = team_names[0]
        member_role  = team_names  # each team grants full access to that team

        # Parse Slack @mention: <@U12345|name> or plain username
        slack_uid = mention.lstrip("<@").split("|")[0].rstrip(">") if mention.startswith("<@") else mention.lstrip("@")

        bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
        if not bot_token:
            return self._text_block("❌ Bot token not found for this workspace.")

        # Get Slack user info
        resp = _http_get(
            "https://slack.com/api/users.info",
            params={"user": slack_uid},
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10,
        ).json()
        if not resp.get("ok"):
            return self._text_block(f"❌ Slack user lookup failed: {resp.get('error')}")

        profile   = resp.get("user", {}).get("profile", {})
        real_name = resp.get("user", {}).get("real_name", "")
        email     = profile.get("email", "")
        if not email:
            return self._text_block("❌ Email not found. Ensure `users:read.email` scope is granted.")

        parts_name = real_name.split(" ") if real_name else [""]
        first = parts_name[0] or ""
        last  = " ".join(parts_name[1:]) if len(parts_name) > 1 else first

        # Find the admin who ran this command
        admin_user = next((u for u in User.objects.filter(slack_user_id=user_id)), None)
        if not admin_user:
            return self._text_block("❌ Your Slack account is not linked to a VaptFix admin account.")

        # Call the proper add-user-detail API
        data = self._call_api(
            "/api/admin/users_details/add-user-detail/", team_id,
            method="post",
            json_body={
                "admin_id":   str(admin_user.id),
                "email":      email,
                "first_name": first,
                "last_name":  last,
                "user_type":  user_type,
                "team_name":  primary_team,
                "Member_role": member_role,
            },
            slack_user_id=user_id,
        )

        err = data.get("error") or data.get("non_field_errors") or data.get("email")
        detail = data.get("detail", "")
        already_exists = ("already exists" in str(err or "")) or ("already exists" in str(detail))

        if err and not already_exists:
            reason = f"{err} — {detail}" if detail and detail != err else err
            return self._text_block(f"❌ {reason}")
        if detail and not already_exists:
            return self._text_block(f"❌ {detail}")

        updated_existing = False
        if already_exists:
            # The create API just rejects duplicates without updating anything
            # — so re-running /adduser on an existing user (e.g. to add them
            # to another team, or to fix a bad role from a Slack channel
            # invite) silently did nothing. Merge the requested teams into
            # their existing Member_role directly via the ORM instead.
            try:
                from users_details.models import UserDetail
                from users_details.views import _ud_set
                existing = UserDetail.objects.filter(admin=admin_user, email=email).first()
                if existing:
                    current_roles = [r for r in (existing.Member_role or []) if r != "Viewer"]
                    for t in team_names:
                        if t not in current_roles:
                            current_roles.append(t)
                    _upd = {"Member_role": current_roles, "user_type": user_type}
                    if not existing.team_name:
                        _upd["team_name"] = primary_team
                    _ud_set(existing, **_upd)  # djongo's .save(update_fields=...) is unreliable here
                    updated_existing = True
                    team_names = current_roles  # reflect the full merged list in the reply
            except Exception:
                logger.exception(f"[SlackCmd] /adduser: failed to merge roles for existing user {email}")

        teams_display = ", ".join(team_names)
        header = "✅ User Updated in VaptFix" if updated_existing else "✅ User Added to VaptFix"
        footer = (
            f"Their team access now includes: {teams_display}."
            if updated_existing else
            "A welcome email with login instructions has been sent."
        )
        return [
            {"type": "header", "text": {"type": "plain_text", "text": header, "emoji": True}},
            self._ctx("Adds a Slack user to VaptFix with team access. Usage: `/adduser @username external|internal pm|cm|ns|af`"),
            {"type": "section", "text": {"type": "mrkdwn",
                "text": (
                    f"*Name:* {real_name}\n"
                    f"*Email:* `{email}`\n"
                    f"*Type:* `{user_type}`\n"
                    f"*Team(s):* {teams_display}\n\n"
                    f"{footer}"
                )}},
        ]

    def _cmd_deleteuser(self, text, team_id, user_id):
        mention = text.strip()
        if not mention:
            return self._text_block("Usage: `/deleteuser @username`")

        slack_uid = mention.lstrip("<@").split("|")[0].rstrip(">") if mention.startswith("<@") else mention.lstrip("@")

        bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
        if not bot_token:
            return self._text_block("❌ Bot token not found.")

        resp = _http_get(
            "https://slack.com/api/users.info",
            params={"user": slack_uid},
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10,
        ).json()
        if not resp.get("ok"):
            return self._text_block(f"❌ Slack user lookup failed: {resp.get('error')}")

        email = resp.get("user", {}).get("profile", {}).get("email", "")
        if not email:
            return self._text_block("❌ Email not found for this Slack user.")

        try:
            target = User.objects.get(email=email)
            target.is_active = False
            target.save(update_fields=["is_active"])
            return [{"type": "section", "text": {"type": "mrkdwn",
                "text": f"✅ User *{email}* has been deactivated from VaptFix."}}]
        except User.DoesNotExist:
            return self._text_block(f"❌ No VaptFix account found for `{email}`.")

    def _cmd_deleteuser_permanent(self, text, team_id, user_id):
        """
        Permanently removes the team-member record — distinct from
        _cmd_deleteuser, which only deactivates (is_active=False, reversible).
        Reuses the same UserDetailCompleteDeleteView the website's own admin
        panel uses for "delete member", instead of inventing new delete logic.
        """
        mention = text.strip()
        if not mention:
            return self._text_block("Usage: pick a user to delete permanently.")

        slack_uid = mention.lstrip("<@").split("|")[0].rstrip(">") if mention.startswith("<@") else mention.lstrip("@")

        bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
        if not bot_token:
            return self._text_block("❌ Bot token not found.")

        resp = _http_get(
            "https://slack.com/api/users.info",
            params={"user": slack_uid},
            headers={"Authorization": f"Bearer {bot_token}"},
            timeout=10,
        ).json()
        if not resp.get("ok"):
            return self._text_block(f"❌ Slack user lookup failed: {resp.get('error')}")

        email = resp.get("user", {}).get("profile", {}).get("email", "")
        if not email:
            return self._text_block("❌ Email not found for this Slack user.")

        listing = self._call_api(
            "/api/admin/users_details/list-user-details/", team_id, slack_user_id=user_id,
        )
        results = listing if isinstance(listing, list) else (listing.get("results") or [])
        target = next((r for r in results if (r.get("email") or "").lower() == email.lower()), None)
        if not target or not target.get("_id"):
            return self._text_block(f"❌ No VaptFix member record found for `{email}`.")

        resp2 = self._call_api(
            f"/api/admin/users_details/user-detail/{target['_id']}/delete/", team_id,
            method="delete", json_body={"confirm": True}, slack_user_id=user_id,
        )
        if resp2.get("message"):
            return [{"type": "section", "text": {"type": "mrkdwn",
                "text": f"🗑️ User *{email}* has been *permanently deleted* from VaptFix. This cannot be undone."}}]
        return self._text_block(f"❌ {resp2.get('detail') or 'Delete failed.'}")

    # ── Team command helpers ───────────────────────────────────────────────

    # Keyword-based team assignment fallback (used when vulnerability_cards not yet generated)
    _TEAM_KEYWORDS = {
        "Patch Management":         ["patch", "update", "upgrade", "version", "software", "outdated", "obsolete", "smb", "windows", "hotfix", "cumulative"],
        "Network Security":         ["network", "firewall", "port", "traffic", "dns", "dhcp", "routing", "icmp", "snmp", "tcp", "udp", "banner", "scan", "nmap", "open port"],
        "Configuration Management": ["config", "setting", "policy", "permission", "registry", "credential", "default", "hardening", "cipher", "weak", "ssl", "tls", "certificate", "insecure"],
        "Architectural Flaws":      ["architecture", "design", "authentication", "authorization", "session", "injection", "xss", "csrf", "api", "exposure", "trust", "privilege"],
    }
    _SLUG_TO_TEAM = {
        "patch-management":         "Patch Management",
        "network-security":         "Network Security",
        "architectural-flaws":      "Architectural Flaws",
        "configuration-management": "Configuration Management",
    }

    def _get_team_vulns(self, team_name, team_id, user_id):
        """
        Fetch vulns assigned to a specific team, scoped to the actual team member
        who ran the Slack command — via the same member-facing API their own
        dashboard uses (/api/user/register/register/latest/vulns/). This
        authenticates as the specific member (via _call_user_api), so there is
        no admin-guessing: the backend resolves "their" admin/report via the
        member's own UserDetail. Unlike /api/admin/adminmitigationstrategy/by-team/
        (used previously), this endpoint does NOT restrict to vulns appearing on
        4+ assets — that filter was hiding everything on small reports.

        NOTE the doubled "register/register/" segment: userregister/urls.py
        defines this path as "register/latest/vulns/" and vaptfix/urls.py mounts
        the whole app under "api/user/register/", so the two "register" segments
        stack. Verified against userregister/urls.py — not a typo here.
        Returns (sorted_vulns, report_id, raw_data).
        """
        from vaptfix.mongo_client import MongoContext

        raw_data = {"report_id": "", "teams": {}}

        data = self._call_user_api(
            "/api/user/register/register/latest/vulns/", team_id, user_id,
            params={"team": team_name},
        )
        if data.get("detail") and "rows" not in data:
            logger.warning("[SlackCmd] _get_team_vulns team=%s failed: %s", team_name, data.get("detail"))
            raw_data["detail"] = data.get("detail")
            return [], "", raw_data

        report_id    = data.get("report_id", "")
        rows         = data.get("rows") or []
        member_teams = data.get("teams") or []
        team_lower   = team_name.strip().lower()

        # This channel's team isn't one of the member's own teams at all
        # (admin added them to a different team) — distinct from "on the
        # team but nothing assigned yet", so the message can say so plainly.
        raw_data["not_member_of_team"] = team_lower not in [t.strip().lower() for t in member_teams]
        raw_data["member_teams"] = member_teams

        vulns = [
            {
                "plugin_name":   r.get("vul_name", ""),
                "host_name":     r.get("asset", ""),
                "risk_factor":   r.get("severity", ""),
                "port":          r.get("port", ""),
                "protocol":      r.get("protocol", ""),
                "status":        r.get("status", "open"),
                "assigned_team": r.get("assigned_team", ""),
            }
            for r in rows
            if (r.get("assigned_team") or "").strip().lower() == team_lower
        ]

        raw_data["report_id"]  = report_id
        raw_data["teams"]      = {team_name: {"count": len(vulns)}}
        raw_data["card_count"] = "via_api"
        raw_data["has_cards"]  = bool(vulns)

        logger.info(
            "[SlackCmd] _get_team_vulns team=%s report_id=%s vuln_count=%d",
            team_name, report_id, len(vulns),
        )

        # ── Attach plugin_id + host OS via a direct Mongo read ──────────────────
        # Needed to look up automated-fix scripts (automation_scripts collection is
        # keyed by plugin_id + os, since fix scripts now differ by target
        # platform). No API is touched — same direct MongoContext pattern
        # already used elsewhere in this file (e.g. _cmd_vaptcheck).
        plugin_id_map = {}
        host_os_map = {}
        if report_id:
            with MongoContext() as _db:
                _nessus_doc = _db["nessus_reports"].find_one(
                    {"report_id": report_id},
                    {
                        "vulnerabilities_by_host.host_name": 1,
                        "vulnerabilities_by_host.host": 1,
                        "vulnerabilities_by_host.host_information": 1,
                        "vulnerabilities_by_host.vulnerabilities.plugin_name": 1,
                        "vulnerabilities_by_host.vulnerabilities.plugin_id": 1,
                    },
                )
            if _nessus_doc:
                for _host in _nessus_doc.get("vulnerabilities_by_host", []):
                    _h_name = _host.get("host_name") or _host.get("host") or ""
                    _os_raw = (
                        (_host.get("host_information") or {}).get("OS")
                        or (_host.get("host_information") or {}).get("operating-system")
                        or (_host.get("host_information") or {}).get("operating_system")
                        or (_host.get("host_information") or {}).get("os")
                        or ""
                    ).strip().lower()
                    if _os_raw:
                        if "windows" in _os_raw:
                            host_os_map[_h_name] = "Windows"
                        elif "linux" in _os_raw or "ubuntu" in _os_raw or "unix" in _os_raw:
                            host_os_map[_h_name] = "Linux"
                        elif "cisco" in _os_raw or "ios" in _os_raw:
                            host_os_map[_h_name] = "Cisco"
                    for _v in _host.get("vulnerabilities", []):
                        _pname = _v.get("plugin_name") or _v.get("pluginname") or _v.get("name") or ""
                        _pid   = _v.get("plugin_id")
                        if _pname and _pid:
                            plugin_id_map[(_pname, _h_name)] = _pid

        # ── Assign deterministic short IDs grouped by severity ─────────────────
        grouped = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for v in vulns:
            sev    = (v.get("risk_factor") or "").strip().title()
            # NOTE: must check key membership, not truthiness — `grouped[sev]` is an
            # empty list `[]` (falsy) until something is appended to it, so
            # `grouped.get(sev) or grouped["Low"]` would silently route EVERY
            # severity into "Low" on first use. That was the bug behind c/h/m
            # IDs never appearing — everything showed up as `l1, l2, l3...`.
            bucket = grouped[sev] if sev in grouped else grouped["Low"]
            bucket.append(v)
        for sev_list in grouped.values():
            sev_list.sort(key=lambda x: (x.get("plugin_name") or "").lower())

        result = []
        for sev, prefix in self._SEV_PREFIX:
            for i, v in enumerate(grouped[sev], 1):
                entry = dict(v)
                entry["short_id"]  = f"{prefix}{i}"
                entry["sev_label"] = sev
                entry["plugin_id"] = plugin_id_map.get((v.get("plugin_name", ""), v.get("host_name", "")))
                entry["host_os"]   = host_os_map.get(v.get("host_name", ""))
                result.append(entry)
        return result, report_id, raw_data

    def _resolve_vuln_id(self, short_id, team_name, team_id, user_id):
        """Resolve a short ID (e.g. c2, h1) to the actual vuln dict."""
        vulns, report_id, _ = self._get_team_vulns(team_name, team_id, user_id)
        target = next((v for v in vulns if v.get("short_id") == short_id.lower()), None)
        return target, report_id

    def _assign_severity_short_ids(self, items, name_key="vul_name"):
        """
        Assign deterministic short IDs (c1/h2/m3/l4...) grouped by severity —
        same scheme _get_team_vulns uses for per-team vuln lists — so
        admin-wide lists (/vulndata, /request) can be referenced the same
        short way (e.g. `/vulndata m6`, `/approve m6`) instead of requiring
        a 24-char Mongo id to be copy-pasted every time.
        """
        grouped = {"Critical": [], "High": [], "Medium": [], "Low": []}
        for item in items:
            sev = (item.get("severity") or "").strip().title()
            bucket = grouped[sev] if sev in grouped else grouped["Low"]
            bucket.append(item)
        for sev_list in grouped.values():
            sev_list.sort(key=lambda x: (x.get(name_key) or "").lower())
        result = []
        for sev, prefix in self._SEV_PREFIX:
            for i, item in enumerate(grouped[sev], 1):
                entry = dict(item)
                entry["short_id"] = f"{prefix}{i}"
                result.append(entry)
        return result

    def _get_or_create_fix_vuln_id(self, vuln, report_id, team_id, user_id):
        """
        Get-or-create the fix_vulnerability_id for a vuln via the existing
        idempotent user-facing API (POST is safe to call repeatedly — it
        returns the existing record if one already exists). No new API —
        reuses /api/user/register/fix-vulnerability/report/.../asset/.../create/.
        Returns (fix_vuln_id_or_None, raw_response_dict).
        """
        host_name = vuln.get("host_name") or ""
        data = self._call_user_api(
            f"/api/user/register/fix-vulnerability/report/{report_id}/asset/{host_name}/create/",
            team_id, user_id, method="post",
            json_body={
                "plugin_name": vuln.get("plugin_name", ""),
                "risk_factor": vuln.get("risk_factor") or vuln.get("sev_label") or "Medium",
                "port": vuln.get("port", ""),
            },
        )
        fix_vuln_id = (data.get("data") or {}).get("_id")
        return fix_vuln_id, data

    def _get_channel_id_by_name(self, bot_token, channel_name):
        """Look up a Slack channel's ID by name via the Slack API."""
        resp = _http_get(
            "https://slack.com/api/conversations.list",
            headers={"Authorization": f"Bearer {bot_token}"},
            params={"types": "public_channel,private_channel", "limit": 200},
            timeout=10,
        )
        if not resp:
            return None
        for ch in (resp.json().get("channels") or []):
            if ch.get("name") == channel_name:
                return ch.get("id")
        return None

    def _get_admin_channel_id(self, bot_token):
        """Look up the vaptfix-admin-dashboard channel ID via Slack API."""
        return self._get_channel_id_by_name(bot_token, self.ADMIN_CHANNEL)

    def _post_to_channel(self, bot_token, channel_id, message):
        resp = _http_post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
            json={"channel": channel_id, "text": message},
            timeout=10,
        )
        return bool(resp and resp.json().get("ok"))

    def _notify_admin(self, team_id, user_id, message):
        """Post a notification message to #vaptfix-admin-dashboard."""
        bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
        if not bot_token:
            return False
        admin_ch_id = self._get_admin_channel_id(bot_token)
        if not admin_ch_id:
            return False
        return self._post_to_channel(bot_token, admin_ch_id, message)

    def _notify_team(self, team_id, user_id, team_name, message):
        """Post a notification message to a team's own channel (e.g. #vaptfix-configuration-management-team)."""
        channel_name = next((cn for cn, tn in self.TEAM_CHANNELS.items() if tn == team_name), None)
        if not channel_name:
            return False
        bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
        if not bot_token:
            return False
        team_ch_id = self._get_channel_id_by_name(bot_token, channel_name)
        if not team_ch_id:
            return False
        return self._post_to_channel(bot_token, team_ch_id, message)

    def _upload_file_to_slack(self, bot_token, channel_id, filename, content_bytes, initial_comment=""):
        """
        Upload a file to a Slack channel using the modern (2024+) external
        upload flow — a separate feature from posting messages, requiring the
        files:write bot scope: (1) get an upload URL, (2) POST the raw bytes
        to it, (3) finalize the upload attaching it to the channel.
        Returns True on success.
        """
        try:
            step1 = _http_post(
                "https://slack.com/api/files.getUploadURLExternal",
                headers={"Authorization": f"Bearer {bot_token}"},
                data={"filename": filename, "length": len(content_bytes)},
                timeout=15,
            ).json()
            if not step1.get("ok"):
                logger.warning(f"[SlackUpload] getUploadURLExternal failed: {step1.get('error')}")
                return False

            upload_url = step1["upload_url"]
            file_id = step1["file_id"]

            step2 = _http_post(upload_url, files={"file": (filename, content_bytes)}, timeout=30)
            if step2.status_code != 200:
                logger.warning(f"[SlackUpload] upload POST failed: status={step2.status_code}")
                return False

            step3 = _http_post(
                "https://slack.com/api/files.completeUploadExternal",
                headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
                json={
                    "files": [{"id": file_id, "title": filename}],
                    "channel_id": channel_id,
                    "initial_comment": initial_comment,
                },
                timeout=15,
            ).json()
            if not step3.get("ok"):
                logger.warning(f"[SlackUpload] completeUploadExternal failed: {step3.get('error')}")
                return False
            return True
        except Exception:
            logger.exception("[SlackUpload] File upload failed")
            return False

    def _create_support_ticket(self, team_id, slack_user_id, team_name, message,
                                vul_name=None, host_name=None, requested_by=None, severity=None):
        """
        Insert a support request document into MongoDB so it appears in
        dashboard counts and /support status. Called when a team member
        runs /support raise via Slack. vul_name/host_name are set when the
        user specified a vuln short-id; requested_by should be a resolved
        email (falls back to the raw Slack ID if resolution failed).
        """
        from datetime import datetime as _dt
        from vaptfix.mongo_client import MongoContext
        import pymongo as _pymongo

        try:
            admin = User.objects.filter(slack_team_id=team_id).first()
            if not admin:
                logger.warning("[SlackCmd] _create_support_ticket: no admin found for team_id=%s", team_id)
                return False

            conditions = [{"admin_id": str(admin.id)}]
            if admin.email:
                conditions.append({"admin_email": admin.email})

            with MongoContext() as db:
                latest = db["nessus_reports"].find_one(
                    {"$or": conditions},
                    {"report_id": 1, "admin_id": 1, "admin_email": 1},
                    sort=[("uploaded_at", _pymongo.DESCENDING)],
                )
                report_id   = str(latest.get("report_id", "")) if latest else ""
                admin_id    = str(admin.id)

                doc = {
                    "report_id":    report_id,
                    "user_id":      slack_user_id,
                    "admin_id":     admin_id,
                    "vul_name":     vul_name,
                    "host_name":    host_name,
                    "severity":     (severity or "").strip().title() or None,
                    "assigned_team": team_name,
                    "step_number":  0,
                    "description":  message,
                    "status":       "open",
                    "source":       "slack",
                    "requested_by": requested_by or f"slack:{slack_user_id}",
                    "requested_at": _dt.utcnow(),
                }
                db["support_requests"].insert_one(doc)
                logger.info("[SlackCmd] Support ticket created for team=%s", team_name)
                return True
        except Exception as exc:
            logger.error("[SlackCmd] _create_support_ticket failed: %s", exc)
            return False

    # ── Team command handlers ──────────────────────────────────────────────

    def _cmd_viewassigned(self, text, team_id, user_id, team_name):
        """
        /viewassigned — Show all assets & vulns assigned to your team
        /viewassigned vulns — Show only vulnerabilities with IDs (c1, h1...)
        /viewassigned assets — Show only assigned assets (hosts)
        /viewassigned vulns 2 — Page 2 (reliable text-based paging — a
        trailing page number always works, independent of the Next/Previous
        buttons which need Slack's separate Interactivity feature enabled).
        """
        tokens = text.strip().lower().split()
        page = 1
        if tokens and tokens[-1].isdigit():
            page = max(1, int(tokens[-1]))
            tokens = tokens[:-1]
        arg = " ".join(tokens)

        vulns, _, raw_data = self._get_team_vulns(team_name, team_id, user_id)
        if arg == "assets":
            # Build asset list from vulns — avoids a separate API call with wrong JWT
            hosts = sorted({v.get("host_name", "") for v in vulns if v.get("host_name")})
            data  = {"by_team": [{"team": team_name, "asset_count": len(hosts), "assets": hosts}]}
            return self._format_team_assets(data, team_name)
        return self._format_viewassigned(vulns, team_name, raw_data, offset=(page - 1) * 10)

    def _cmd_mitigationstatus(self, text, team_id, user_id, team_name):
        """
        /mitigationstatus — Check mitigation status for all vulns assigned to your team
        Shows: open | in-progress | closed | overdue counts and fix rate
        """
        vulns, _, _ = self._get_team_vulns(team_name, team_id, user_id)
        return self._format_mitigationstatus(vulns, team_name)

    def _cmd_startfix(self, text, team_id, user_id, team_name):
        """
        /startfix — Start fix workflow (Critical → High → Medium → Low, most common first)
        /startfix [vuln-id] — Jump to a specific vulnerability e.g. /startfix h1
        Shows whether an automated-fix script exists (/autofix) alongside the
        manual step-by-step guide (/manualfix) — both backed by the real
        automation_scripts / fix_vulnerability_steps data, not placeholder text.
        """
        vuln_id = text.strip().lower()
        vulns, report_id, _ = self._get_team_vulns(team_name, team_id, user_id)
        if not vulns:
            return self._text_block(f"✅ No vulnerabilities currently assigned to *{team_name}* team.")
        if vuln_id:
            target = next((v for v in vulns if v.get("short_id") == vuln_id), None)
            if not target:
                return self._text_block(
                    f"❌ Vulnerability `{vuln_id}` not found.\n"
                    "Use `/viewassigned vulns` to see all IDs."
                )
            fix_vuln_id, create_resp = self._get_or_create_fix_vuln_id(target, report_id, team_id, user_id)
            if not fix_vuln_id:
                return self._text_block(
                    f"❌ Could not start fix workflow: {create_resp.get('detail') or create_resp.get('error') or 'unknown error'}\n"
                    "_Make sure your admin added you via `/adduser` with the correct team._"
                )
            automation = None
            plugin_id = target.get("plugin_id")
            if plugin_id:
                automation = self._call_user_api(
                    f"/api/user/automation-scripts/match/{plugin_id}/", team_id, user_id,
                )
            steps_data = self._call_user_api(
                f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id, user_id,
            )
            return self._format_startfix_real(target, fix_vuln_id, automation, steps_data)
        return self._format_startfix_list(vulns, team_name)

    def _cmd_mitigated(self, text, team_id, user_id, team_name):
        """
        /mitigated [vuln-id] — Mark ALL remaining steps done e.g. /mitigated h1
            (calls the real step-complete API with complete_all=true)
        /mitigated [vuln-id] [step-id] — Mark a specific step done e.g. /mitigated h1 s3
        Admin is notified automatically for verification.
        """
        parts = text.strip().lower().split()
        if not parts:
            return self._text_block(
                "*Usage:*\n"
                "• `/mitigated [vuln-id]` — Mark full vuln as done  _e.g. `/mitigated h1`_\n"
                "• `/mitigated [vuln-id] [step-id]` — Mark a step done  _e.g. `/mitigated h1 s3`_\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        vuln_id = parts[0]
        step_id = parts[1] if len(parts) > 1 else None
        target, report_id = self._resolve_vuln_id(vuln_id, team_name, team_id, user_id)
        if not target:
            return self._text_block(
                f"❌ Vulnerability `{vuln_id}` not found in *{team_name}*.\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        plugin_name = target.get("plugin_name") or ""
        host_name   = target.get("host_name") or ""
        sev         = target.get("risk_factor") or target.get("sev_label") or "Medium"
        icon        = self._SEV_ICONS.get(sev, "⚪")

        fix_vuln_id, create_resp = self._get_or_create_fix_vuln_id(target, report_id, team_id, user_id)
        if not fix_vuln_id:
            return self._text_block(
                f"❌ Could not update fix status: {create_resp.get('detail') or create_resp.get('error') or 'unknown error'}"
            )

        if step_id:
            step_num = step_id.lstrip("s")
            try:
                step_num_int = int(step_num)
            except ValueError:
                return self._text_block(f"❌ Invalid step id `{step_id}`. Use e.g. `s1`, `s2`.")
            step_resp = self._call_user_api(
                f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id, user_id,
                method="post", json_body={"step_number": step_num_int},
            )
            if step_resp.get("detail") and not step_resp.get("message"):
                return self._text_block(f"❌ `{step_resp.get('detail')}`")
            self._notify_admin(
                team_id, user_id,
                f"🔧 *Step Update* — *{team_name}*\n"
                f"Vulnerability: `{plugin_name}` {icon} {sev} on `{host_name}`\n"
                f"Step {step_num} marked complete by team."
            )
            return self._text_block(
                f"✅ *Step {step_num} marked complete*\n"
                f"Vuln: `{plugin_name}` | Host: `{host_name}`\n"
                f"_Admin notified. Continue with next step or run `/retest {vuln_id}` when fully done._"
            )

        # Full vuln — complete_all=true uses the real API's bulk-complete option
        all_resp = self._call_user_api(
            f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id, user_id,
            method="post", json_body={"step_number": 1, "complete_all": True},
        )
        if all_resp.get("detail") and not all_resp.get("message"):
            return self._text_block(f"❌ `{all_resp.get('detail')}`")

        self._notify_admin(
            team_id, user_id,
            f"✅ *Mitigation Complete* — *{team_name}*\n"
            f"Vulnerability: `{plugin_name}` {icon} {sev} on `{host_name}`\n"
            f"Team has marked this as fully mitigated. Please verify in dashboard."
        )
        return [
            {"type": "header", "text": {"type": "plain_text", "text": "✅ Marked as Mitigated", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": (
                f"*Vulnerability:* `{plugin_name}`\n"
                f"*Host:* `{host_name}`\n"
                f"*Severity:* {icon} {sev}\n"
                f"*Team:* {team_name}\n\n"
                f"_All steps marked complete in the system. Admin notified. "
                f"Run `/retest {vuln_id}` to request formal retesting._"
            )}},
        ]

    def _cmd_retest(self, text, team_id, user_id, team_name):
        """
        /retest [vuln-id] — Submit a fixed vulnerability for admin retesting e.g. /retest h1
        Calls the real send-verification API (requires all steps completed first via
        /mitigated) and notifies the admin in Slack.
        """
        vuln_id = text.strip().lower()
        if not vuln_id:
            return self._text_block(
                "*Usage:* `/retest [vuln-id]`  _e.g. `/retest h1`_\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        target, report_id = self._resolve_vuln_id(vuln_id, team_name, team_id, user_id)
        if not target:
            return self._text_block(
                f"❌ Vulnerability `{vuln_id}` not found.\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        plugin_name = target.get("plugin_name") or ""
        host_name   = target.get("host_name") or ""
        sev         = target.get("risk_factor") or target.get("sev_label") or "Medium"
        icon        = self._SEV_ICONS.get(sev, "⚪")

        fix_vuln_id, create_resp = self._get_or_create_fix_vuln_id(target, report_id, team_id, user_id)
        if not fix_vuln_id:
            return self._text_block(
                f"❌ Could not submit retest: {create_resp.get('detail') or create_resp.get('error') or 'unknown error'}"
            )
        verify_resp = self._call_user_api(
            f"/api/user/register/fix-vulnerability/{fix_vuln_id}/send-verification/", team_id, user_id,
            method="post",
        )
        if verify_resp.get("status") not in ("open/review", "closed"):
            err = verify_resp.get("message") or verify_resp.get("detail") or verify_resp.get("error") or "unknown error"
            return self._text_block(
                f"❌ `{err}`\n"
                f"_Run `/mitigated {vuln_id}` first to mark all fix steps complete._"
            )

        self._notify_admin(
            team_id, user_id,
            f"🔁 *Retest Request* — *{team_name}*\n"
            f"Vulnerability: `{plugin_name}` {icon} {sev} on `{host_name}`\n"
            f"Team reports fix is complete and requests admin verification/retesting."
        )
        return [
            {"type": "header", "text": {"type": "plain_text", "text": "🔁 Retest Request Submitted", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": (
                f"*Vulnerability:* `{plugin_name}`\n"
                f"*Host:* `{host_name}`\n"
                f"*Severity:* {icon} {sev}\n\n"
                "_Verification request recorded in VaptFix. Admin notified — "
                "they will schedule verification and confirm the fix._"
            )}},
        ]

    def _cmd_manualfix(self, text, team_id, user_id, team_name):
        """
        /manualfix [vuln-id] — Full step-by-step manual fix detail (Action,
        Where/How to Run, Command, Expected Output, Verification, Tools,
        Important Considerations) — same content as the web dashboard's
        Manual Fix tab — plus two buttons to mark progress:
        "Mark Step Done" (one at a time) and "Mark All Steps Done".
        e.g. /manualfix h1
        """
        vuln_id = text.strip().lower()
        if not vuln_id:
            return self._text_block(
                "*Usage:* `/manualfix [vuln-id]`  _e.g. `/manualfix h1`_\n"
                "Run `/startfix [vuln-id]` first to see what's available."
            )
        target, report_id = self._resolve_vuln_id(vuln_id, team_name, team_id, user_id)
        if not target:
            return self._text_block(
                f"❌ Vulnerability `{vuln_id}` not found.\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        fix_vuln_id, create_resp = self._get_or_create_fix_vuln_id(target, report_id, team_id, user_id)
        if not fix_vuln_id:
            return self._text_block(
                f"❌ Could not fetch fix steps: {create_resp.get('detail') or create_resp.get('error') or 'unknown error'}"
            )
        steps_data = self._call_user_api(
            f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id, user_id,
        )
        if steps_data.get("detail"):
            return self._text_block(f"❌ `{steps_data.get('detail')}`")
        return self._format_steps_status(steps_data, vuln_id, fix_vuln_id, team_name)

    def _cmd_autofix(self, text, team_id, user_id, team_name):
        """
        /autofix [vuln-id] — Shows the ready-made automated-fix script for this
        vulnerability (from the automation_scripts library), with the exact
        commands to run and before/after considerations. e.g. /autofix h1
        """
        vuln_id = text.strip().lower()
        if not vuln_id:
            return self._text_block(
                "*Usage:* `/autofix [vuln-id]`  _e.g. `/autofix h1`_\n"
                "Run `/startfix [vuln-id]` first to see what's available."
            )
        target, _ = self._resolve_vuln_id(vuln_id, team_name, team_id, user_id)
        if not target:
            return self._text_block(
                f"❌ Vulnerability `{vuln_id}` not found.\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        plugin_id = target.get("plugin_id")
        if not plugin_id:
            return self._text_block(
                f"❌ No Nessus plugin ID found for this vulnerability — cannot check for an automated fix.\n"
                f"Use `/manualfix {vuln_id}` instead."
            )
        host_os = target.get("host_os")  # "Windows" / "Linux" / "Cisco" / None
        os_params = {"os": host_os} if host_os else None
        automation = self._call_user_api(
            f"/api/user/automation-scripts/match/{plugin_id}/", team_id, user_id, params=os_params,
        )
        if automation.get("detail") and "matched" not in automation:
            return self._text_block(f"❌ `{automation.get('detail')}`")
        if not automation.get("matched"):
            available = automation.get("available_os") or []
            hint = (
                f" (available for: {', '.join(available)} — this host is {host_os or 'unknown OS'})"
                if available else ""
            )
            return self._text_block(
                f"📭 No automated-fix script available for this vulnerability{hint}.\n"
                f"Use `/manualfix {vuln_id}` for the step-by-step guide instead."
            )
        script_resp = self._call_user_api_raw(
            f"/api/user/automation-scripts/download/{plugin_id}/", team_id, user_id, params=os_params,
        )
        script_text  = ""
        script_bytes = b""
        if script_resp is not None and script_resp.status_code == 200:
            script_bytes = script_resp.content
            try:
                script_text = script_bytes.decode("utf-8", errors="replace")
            except Exception:
                script_text = ""

        # Upload the full (non-truncated) script as a real, downloadable
        # file attachment in this team's channel — separate from the inline
        # preview shown below, which stays truncated for long scripts.
        uploaded = False
        if script_bytes:
            channel_name = next((cn for cn, tn in self.TEAM_CHANNELS.items() if tn == team_name), None)
            bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
            if channel_name and bot_token:
                channel_id = self._get_channel_id_by_name(bot_token, channel_name)
                if channel_id:
                    filename = (
                        automation.get("fix_script_name")
                        or automation.get("script_name")
                        or f"plugin_{plugin_id}_fix.py"
                    )
                    uploaded = self._upload_file_to_slack(
                        bot_token, channel_id, filename, script_bytes,
                        initial_comment=(
                            f"🤖 Automated fix script for `{vuln_id}` — {automation.get('vulnerability', '')}"
                        ),
                    )

        return self._format_autofix(automation, script_text, vuln_id, uploaded=uploaded)

    def _cmd_scriptfeedback(self, text, team_id, user_id, team_name):
        """
        /scriptfeedback [vuln-id] up|down — Report whether the automated-fix
        script worked, after running it via /autofix. e.g. /scriptfeedback h1 up
        """
        parts = text.strip().lower().split()
        if len(parts) < 2 or parts[1] not in ("up", "down"):
            return self._text_block(
                "*Usage:* `/scriptfeedback [vuln-id] up|down`  _e.g. `/scriptfeedback h1 up`_\n"
                "_Run this after trying the script from `/autofix`._"
            )
        vuln_id, direction = parts[0], parts[1]
        target, _ = self._resolve_vuln_id(vuln_id, team_name, team_id, user_id)
        if not target:
            return self._text_block(
                f"❌ Vulnerability `{vuln_id}` not found.\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        plugin_id = target.get("plugin_id")
        if not plugin_id:
            return self._text_block("❌ No plugin ID found for this vulnerability.")
        resp = self._call_user_api(
            "/api/user/automation-scripts/feedback/", team_id, user_id,
            method="post", json_body={"plugin_id": plugin_id, "working": direction == "up"},
        )
        if not resp.get("success"):
            return self._text_block(f"❌ `{resp.get('error') or resp.get('detail') or 'Could not submit feedback.'}`")
        icon = "👍" if direction == "up" else "👎"
        return self._text_block(f"{icon} Thanks! Feedback recorded for `{target.get('plugin_name', vuln_id)}`.")

    def _cmd_support(self, text, team_id, user_id, team_name):
        """
        /support raise "message" — Open a new support ticket with your description
        /support status — View your team's support request status
        """
        parts = text.strip().split(None, 1)
        sub   = parts[0].lower() if parts else ""
        if sub == "status":
            # Query MongoDB directly — avoids JWT admin-mismatch issue
            from vaptfix.mongo_client import MongoContext
            import pymongo as _pymongo
            _, report_id, _ = self._get_team_vulns(team_name, team_id, user_id)
            with MongoContext() as db:
                query = {"assigned_team": team_name}
                if report_id:
                    query["report_id"] = report_id
                tickets = list(db["support_requests"].find(
                    query,
                    sort=[("requested_at", _pymongo.DESCENDING)],
                ))
                for t in tickets:
                    t["_id"] = str(t.get("_id", ""))
            data = {"results": tickets}
            return self._format_team_support_status(data, team_name)
        if sub == "raise":
            rest = parts[1].strip() if len(parts) > 1 else ""
            if not rest:
                return self._text_block(
                    '*Usage:* `/support raise "your message here"`\n'
                    '_Example:_ `/support raise "Need help with SSL cert fix on 192.168.1.1"`\n'
                    '_Or tie it to a vuln:_ `/support raise m5 "Need help with this fix"`'
                )

            # Optional leading vuln short-id (e.g. "m5") so the ticket shows
            # the real vuln/host instead of always being a generic request.
            target = None
            tokens = rest.split(None, 1)
            first_token = tokens[0].lower() if tokens else ""
            if re.fullmatch(r"[chml]\d+", first_token):
                target, _ = self._resolve_vuln_id(first_token, team_name, team_id, user_id)
                rest = tokens[1].strip() if len(tokens) > 1 else ""

            message = rest.strip().strip('"').strip("'")
            if not message:
                return self._text_block(
                    '*Usage:* `/support raise ["vuln-id"] "your message here"`\n'
                    '_Example:_ `/support raise m5 "Need help with this fix"`'
                )

            vul_name  = target.get("plugin_name") if target else None
            host_name = target.get("host_name") if target else None
            severity  = (target.get("risk_factor") or target.get("severity") or "") if target else ""

            # Resolve the caller's real email instead of storing the raw
            # Slack user ID — matches how web-raised tickets show requester.
            requested_by = f"slack:{user_id}"
            bot_token = self._get_bot_token(team_id, slack_user_id=user_id)
            if bot_token:
                info = _http_get(
                    "https://slack.com/api/users.info",
                    params={"user": user_id},
                    headers={"Authorization": f"Bearer {bot_token}"},
                    timeout=10,
                ).json()
                if info.get("ok"):
                    email = info.get("user", {}).get("profile", {}).get("email", "")
                    if email:
                        requested_by = email

            # Write to MongoDB so it shows in dashboard counts + /support status
            self._create_support_ticket(
                team_id, user_id, team_name, message,
                vul_name=vul_name, host_name=host_name, requested_by=requested_by,
                severity=severity,
            )
            vuln_line = f"*Vulnerability:* {vul_name} (`{host_name}`)\n" if vul_name else ""
            self._notify_admin(
                team_id, user_id,
                f"🎫 *Support Request* — *{team_name}*\n"
                + (f"Vulnerability: {vul_name} on `{host_name}`\n" if vul_name else "")
                + f"Message: {message}\n"
                f"Please review and respond via dashboard."
            )
            return [
                {"type": "header", "text": {"type": "plain_text", "text": "🎫 Support Request Raised", "emoji": True}},
                {"type": "section", "text": {"type": "mrkdwn", "text": (
                    vuln_line
                    + f"*Message:* {message}\n"
                    f"*Team:* {team_name}\n\n"
                    "_Admin has been notified. Use `/support status` to track updates._"
                )}},
            ]
        return self._text_block(
            "*Support Commands:*\n"
            '• `/support raise ["vuln-id"] "message"` — Open a new support ticket\n'
            "• `/support status` — View your team's support tickets"
        )

    def _cmd_extend(self, text, team_id, user_id, team_name):
        """
        /extend [vuln-id] [days] [reason] — Request a deadline extension e.g. /extend h1 7 Need more time
        /extend status — Check status of your team's extension requests
        Writes to the real timeline_extension_requests collection (via the
        member-scoped create API) so it actually shows up in the admin's
        /request, /approve, /reject commands — previously this only sent a
        Slack notification and never touched the database.
        """
        parts = text.strip().split(None, 1)
        sub   = parts[0].lower() if parts else ""
        if sub == "status":
            data = self._call_user_api(
                "/api/user/dashboard/mitigation-timeline-extension/report/", team_id, user_id,
            )
            return self._format_team_extend_status(data, team_name)
        if not sub:
            return self._text_block(
                "*Extension Commands:*\n"
                "• `/extend [vuln-id] [days] [reason]` — Request deadline extension\n"
                "  _Example:_ `/extend h1 7 Need more time for patch testing`\n"
                "• `/extend status` — Check your extension request status"
            )
        vuln_id = sub
        rest    = parts[1].strip() if len(parts) > 1 else ""
        if not rest:
            return self._text_block(
                f"*Usage:* `/extend {vuln_id} [days] [reason]`\n"
                f"_Example:_ `/extend {vuln_id} 7 Need more time for patch testing`"
            )
        # First word = number of extra days if it's a plain integer; otherwise
        # scan the whole text for a number, defaulting to 7 if none is given.
        rest_parts = rest.split(None, 1)
        if rest_parts[0].isdigit():
            days   = int(rest_parts[0])
            reason = rest_parts[1].strip() if len(rest_parts) > 1 else ""
        else:
            _num   = re.search(r"\d+", rest)
            days   = int(_num.group()) if _num else 7
            reason = rest
        if not reason:
            return self._text_block(
                f"*Usage:* `/extend {vuln_id} [days] [reason]`\n"
                f"_Example:_ `/extend {vuln_id} 7 Need more time for patch testing`"
            )
        target, _ = self._resolve_vuln_id(vuln_id, team_name, team_id, user_id)
        if not target:
            return self._text_block(
                f"❌ Vulnerability `{vuln_id}` not found.\n"
                "Use `/viewassigned vulns` to see IDs."
            )
        plugin_name = target.get("plugin_name") or ""
        host_name   = target.get("host_name") or ""
        sev         = target.get("risk_factor") or target.get("sev_label") or "Medium"
        icon        = self._SEV_ICONS.get(sev, "⚪")

        resp = self._call_user_api(
            "/api/user/dashboard/mitigation-timeline-extension/request/", team_id, user_id,
            method="post",
            json_body={
                "severity": sev,
                "asset": host_name,
                "vulnerability_name": plugin_name,
                "requested_extension_days": days,
                "reason": reason,
            },
        )
        if not resp.get("request_id"):
            return self._text_block(f"❌ Could not submit extension request: {resp.get('detail') or 'unknown error'}")

        self._notify_admin(
            team_id, user_id,
            f"⏳ *Timeline Extension Request* — *{team_name}*\n"
            f"Vulnerability: `{plugin_name}` {icon} {sev} on `{host_name}`\n"
            f"Requested: +{days} day(s) | Reason: {reason}\n"
            f"Use `/request` to review, then `/approve [request-id]` or `/reject [request-id]`."
        )
        return [
            {"type": "header", "text": {"type": "plain_text", "text": "⏳ Extension Request Submitted", "emoji": True}},
            {"type": "section", "text": {"type": "mrkdwn", "text": (
                f"*Vulnerability:* `{plugin_name}`\n"
                f"*Severity:* {icon} {sev}\n"
                f"*Requested:* +{days} day(s)\n"
                f"*Reason:* {reason}\n\n"
                "_Recorded in VaptFix — admin can review it via `/request` and approve/reject it. "
                "Use `/extend status` to track the decision._"
            )}},
        ]

    def _cmd_scriptstats(self, text, team_id, user_id, team_name):
        """
        /scriptstats — View which of your team's vulns have automated fix
        scripts available (from the real automation_scripts library).
        /scriptstats [vuln-id] — Stats for one specific vulnerability e.g. /scriptstats h1
        """
        vuln_id = text.strip().lower()
        vulns, _, _ = self._get_team_vulns(team_name, team_id, user_id)
        if not vulns:
            return self._text_block(f"✅ No vulnerabilities currently assigned to *{team_name}* team.")

        if vuln_id:
            target = next((v for v in vulns if v.get("short_id") == vuln_id), None)
            if not target:
                return self._text_block(
                    f"❌ Vulnerability `{vuln_id}` not found.\n"
                    "Use `/viewassigned vulns` to see IDs."
                )
            plugin_id = target.get("plugin_id")
            if not plugin_id:
                return self._text_block(f"❌ No Nessus plugin ID found for `{vuln_id}`.")
            host_os = target.get("host_os")
            automation = self._call_user_api(
                f"/api/user/automation-scripts/match/{plugin_id}/", team_id, user_id,
                params={"os": host_os} if host_os else None,
            )
            return self._format_single_scriptstats(automation, target, vuln_id)

        plugin_ids = sorted({v.get("plugin_id") for v in vulns if v.get("plugin_id")})
        if not plugin_ids:
            return self._text_block("No Nessus plugin IDs found for your team's vulnerabilities.")
        bulk = self._call_user_api(
            "/api/user/automation-scripts/match/bulk/", team_id, user_id,
            method="post", json_body={"plugin_ids": plugin_ids},
        )
        results = bulk.get("results") or []
        matched_by_pid = {r.get("plugin_id"): r for r in results if r.get("matched")}
        return self._format_scriptstats(vulns, matched_by_pid, team_name)

    # ── Formatters ────────────────────────────────────────────────────────

    def _text_block(self, text):
        return [{"type": "section", "text": {"type": "mrkdwn", "text": text}}]

    def _bar(self, value, max_val, width=10):
        filled = round((value / max_val) * width) if max_val else 0
        return "█" * filled + "░" * (width - filled)


    def _format_teamoverview(self, data):
        # API returns teams as a dict {"Team Name": {total, open, closed, by_risk}} or list
        teams_raw = data.get("teams") or data.get("results") or (data if isinstance(data, list) else None)
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "👥 Team Overview", "emoji": True}},
            self._ctx("Per-team breakdown — total, open, and fixed vulns with severity distribution across all teams."),
            {"type": "divider"},
        ]
        if isinstance(teams_raw, dict):
            teams_list = list(teams_raw.items())[:10]
        elif isinstance(teams_raw, list):
            teams_list = [(t.get("team_name") or t.get("name") or "Unknown", t) for t in teams_raw[:10]]
        else:
            teams_list = []

        if not teams_list:
            return blocks + self._text_block("No team data available.")

        for name, stats in teams_list:
            total  = stats.get("total", 0)
            open_v = stats.get("open", 0)
            closed = stats.get("closed", 0)
            rate   = round((closed / total) * 100) if total else 0
            by_risk = stats.get("by_risk") or {}
            risk_parts = [f"{sev}: {cnt}" for sev, cnt in by_risk.items() if cnt]
            risk_str = ("  _" + " | ".join(risk_parts) + "_") if risk_parts else ""
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{name}*\nTotal: {total} | Open: {open_v} | Fixed: {closed} ({rate}%){risk_str}"}})
        return blocks

    def _format_vulnstats(self, data):
        # API returns {total, vulnerabilities: [{vulnerability_name, risk_factor, assigned_team, ...}]}
        vulns = data.get("vulnerabilities") or data.get("results") or (data if isinstance(data, list) else [])
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0,
                  "open": 0, "in_progress": 0, "open_review": 0, "fixed": 0}
        if isinstance(vulns, list):
            for v in vulns:
                # API uses risk_factor; fallback to severity for other shapes
                sev = (v.get("risk_factor") or v.get("severity") or "").lower()
                # normalize: "closed" -> "fixed" (this dict's label), "open/review" -> "open_review"
                raw_st = (v.get("status") or "open").strip().lower()
                st = "fixed" if raw_st == "closed" else raw_st.replace(" ", "_").replace("/", "_").replace("-", "_")
                if sev in counts:
                    counts[sev] += 1
                if st in counts:
                    counts[st] += 1
        else:
            for k in counts:
                counts[k] = data.get(k, 0)

        total = data.get("total") or counts["critical"] + counts["high"] + counts["medium"] + counts["low"] or 0
        max_v = max(total, 1)

        bar_text = (
            f"```"
            f"\nCritical  {self._bar(counts['critical'], max_v)}  {counts['critical']}"
            f"\nHigh      {self._bar(counts['high'], max_v)}  {counts['high']}"
            f"\nMedium    {self._bar(counts['medium'], max_v)}  {counts['medium']}"
            f"\nLow       {self._bar(counts['low'], max_v)}  {counts['low']}"
            f"```"
        )
        return [
            {"type": "header", "text": {"type": "plain_text", "text": "🛡 Vulnerability Statistics", "emoji": True}},
            self._ctx("Total vuln counts by severity (Critical/High/Medium/Low) and by status (Open/In Progress/Open-Review/Fixed)."),
            {"type": "divider"},
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*By Severity*\n{bar_text}"}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Open*\n{counts['open']}"},
                {"type": "mrkdwn", "text": f"*In Progress*\n{counts['in_progress']}"},
                {"type": "mrkdwn", "text": f"*Open/Review*\n{counts['open_review']}"},
                {"type": "mrkdwn", "text": f"*Fixed*\n{counts['fixed']}"},
                {"type": "mrkdwn", "text": f"*Total*\n{total}"},
            ]},
        ]

    def _format_externalusers(self, data):
        users = data if isinstance(data, list) else (data.get("results") or data.get("users") or [])
        count = len(users)
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🌐 External Users", "emoji": True}},
            self._ctx("All external users — name, email, assigned assets/vulns, access deadline, and status."),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total External Users:* {count}"}},
            {"type": "divider"},
        ]
        if not users:
            return blocks + self._text_block("No external users found.")
        for u in users[:8]:
            name     = f"{u.get('firstname') or u.get('first_name', '')} {u.get('lastname') or u.get('last_name', '')}".strip() or "Unknown"
            email    = u.get("email", "—")
            assets   = u.get("assigned_assets") or u.get("asset_count") or "—"
            vulns    = u.get("assigned_vulns") or u.get("vuln_count") or "—"
            deadline = u.get("deadline") or u.get("access_deadline") or "—"
            access   = u.get("access_status") or u.get("status") or "active"
            icon     = {"active": "🟢", "revoked": "🔴", "pending": "🟡"}.get(str(access).lower(), "⚪")
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": (
                    f"{icon} *{name}* — `{email}`\n"
                    f"Assets: {assets} | Vulns: {vulns} | Deadline: {deadline} | Status: {access}"
                )}})
        return blocks

    def _short_display_date(self, val):
        s = str(val or "—").strip()
        if not s or s == "—":
            return "—"
        if "T" in s:
            s = s.split("T", 1)[0]
        elif " " in s and len(s) > 10:
            s = s.split(" ", 1)[0]
        try:
            from datetime import datetime
            for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%m/%d/%Y"):
                try:
                    dt = datetime.strptime(s[:10], fmt)
                    return dt.strftime("%b %d, %Y")
                except ValueError:
                    continue
        except Exception:
            pass
        return s[:10] if len(s) >= 10 else s

    def _normalize_support_team(self, raw):
        return (raw or "").strip().lower().replace("-", " ").replace("_", " ")

    def _match_support_status_filter(self, record, st_filter):
        st = (record.get("status") or "open").strip().lower()
        if st_filter == "all":
            return True
        if st_filter == "open":
            return st != "closed"
        if st_filter == "closed":
            return st == "closed"
        return True

    def _match_support_team_filter(self, record, team_filter):
        if team_filter == "all":
            return True
        target = self._SUPPORT_TEAM_MATCH.get(team_filter, "")
        raw = self._normalize_support_team(record.get("assigned_team"))
        return raw == target or (target and target in raw)

    def _fetch_support_report_data(self, team_id, user_id):
        report_id = self._get_workspace_report_id(team_id)
        if not report_id:
            return None
        return self._call_api(
            f"/api/admin/adminregister/support-requests/report/{report_id}/", team_id,
            slack_user_id=user_id,
        )

    def _resolve_support_row_severity(self, record):
        """Display-time severity — uses API value or description short-id fallback."""
        sev = (record.get("severity") or record.get("risk_factor") or "").strip()
        if sev:
            return sev.title()
        desc = record.get("description") or ""
        match = re.search(r"\b([chml])\d+\b", str(desc).lower())
        if match:
            return {"c": "Critical", "h": "High", "m": "Medium", "l": "Low"}[match.group(1)]
        return ""

    def _support_tab_blocks(self, team_id, user_id, st_filter="all", team_filter="all", offset=0):
        data = self._fetch_support_report_data(team_id, user_id)
        if not data:
            return self._text_block("❌ No report found for this workspace.")
        if data.get("detail"):
            return self._text_block(f"❌ {data['detail']}")
        return self._format_support_tab(
            data, st_filter=st_filter, team_filter=team_filter, offset=offset,
        )

    def _format_supportdata(self, data, st_filter="all", team_filter="all", offset=0):
        """Backward-compatible entry — renders Register-style Support tab."""
        return self._format_support_tab(
            data, st_filter=st_filter, team_filter=team_filter, offset=offset,
        )

    def _format_support_tab(self, data, st_filter="all", team_filter="all", offset=0):
        """
        Support tab UI (Slack Block Kit) — mirrors Register tab layout:
        status + team filters, 5 rows/page, View on the right, divider after each row.
        """
        PAGE_SIZE = 5
        raw_results = data.get("results") or []

        st_counts = {
            "all": len([r for r in raw_results if self._match_support_team_filter(r, team_filter)]),
            "open": sum(
                1 for r in raw_results
                if self._match_support_team_filter(r, team_filter)
                and self._match_support_status_filter(r, "open")
            ),
            "closed": sum(
                1 for r in raw_results
                if self._match_support_team_filter(r, team_filter)
                and self._match_support_status_filter(r, "closed")
            ),
        }
        team_counts = {
            key: sum(
                1 for r in raw_results
                if self._match_support_status_filter(r, st_filter)
                and (key == "all" or self._match_support_team_filter(r, key))
            )
            for key, _ in self._SUPPORT_TEAM_FILTERS
        }

        all_items = self._assign_severity_short_ids([
            dict(r, severity=self._resolve_support_row_severity(r) or r.get("severity", ""))
            for r in raw_results
        ])
        filtered = [
            r for r in all_items
            if self._match_support_status_filter(r, st_filter)
            and self._match_support_team_filter(r, team_filter)
        ]
        count = len(filtered)

        offset = max(0, min(offset, max(count - 1, 0)))
        page_items = filtered[offset: offset + PAGE_SIZE]
        start_num = offset + 1 if page_items else 0
        end_num = offset + len(page_items)

        def sev_icon_for(sev_raw):
            sev_norm = (sev_raw or "").strip().lower()
            return self._SEV_EMOJI_MAP.get(sev_norm, "⚪")

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🎫 Support Requests", "emoji": True}},
            self._ctx("Streamlining the resolution of critical infrastructure vulnerabilities."),
            {"type": "divider"},
        ]

        # Status filter row
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": f"{label} {st_counts[k]}",
                        "emoji": True,
                    },
                    "action_id": f"sup_st_{k}",
                    "value": f"{k}|{team_filter}|0",
                    **({"style": "primary"} if k == st_filter else {}),
                }
                for k, label in self._SUPPORT_STATUS_FILTERS
            ],
        })

        # Team filter row
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {
                        "type": "plain_text",
                        "text": f"{label} {team_counts[k]}" if k == "all" else label,
                        "emoji": True,
                    },
                    "action_id": f"sup_team_{k}",
                    "value": f"{st_filter}|{k}|0",
                    **({"style": "primary"} if k == team_filter else {}),
                }
                for k, label in self._SUPPORT_TEAM_FILTERS
            ],
        })

        blocks.append({"type": "divider"})

        if not page_items:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*No support requests found.*"},
            })
        else:
            for idx, r in enumerate(page_items):
                sno_txt = str(start_num + idx).zfill(2)
                sid = r.get("short_id", "?")
                vuln = r.get("vul_name") or "General Request"
                host = r.get("host_name") or "—"
                team = r.get("assigned_team") or "—"
                requester = r.get("requested_by") or "Unknown"
                st = r.get("status") or "open"
                st_display = (st or "open").strip().lower().capitalize()
                sev_display = self._resolve_support_row_severity(r)
                sev_norm = sev_display.lower()
                sev_label = sev_display.upper() if sev_display else "—"
                raised = self._short_display_date(r.get("requested_at"))
                safe_sid = "".join(ch if ch.isalnum() else "_" for ch in str(sid))[:40]

                blocks.append({
                    "type": "context",
                    "elements": [
                        self._status_icon_image_element(st),
                        {
                            "type": "mrkdwn",
                            "text": f"*`{sno_txt}`*  `{sid}`  *{vuln}*",
                        },
                    ],
                })
                blocks.append({
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"`{host}`  |  {sev_icon_for(sev_norm)} *{sev_label}*",
                    },
                    "accessory": {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "View", "emoji": True},
                        "action_id": f"sup_view_{safe_sid}",
                        "value": f"{sid}|{st_filter}|{team_filter}|{offset}",
                    },
                })
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": (
                            f"*Requested By:* {requester}  |  "
                            f"*Raised:* {raised}  |  "
                            f"*Status:* *{st_display}*  |  "
                            f"*Team:* {team}"
                        ),
                    }],
                })
                blocks.append({"type": "divider"})

        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Showing {start_num}-{end_num} of {count} results",
            },
        })

        value_prefix = f"{st_filter}|{team_filter}|"
        pg_block = self._numbered_pagination_block(
            offset, PAGE_SIZE, count, "sup_list_pg", value_prefix=value_prefix,
        )
        if pg_block:
            blocks.append(pg_block)

        return blocks

    def _format_support_detail(self, record, st_filter="all", team_filter="all", offset=0):
        """Single support-request detail — opened from the View button."""
        vuln = record.get("vul_name") or "General Request"
        host = record.get("host_name") or "—"
        team = record.get("assigned_team") or "—"
        requester = record.get("requested_by") or "Unknown"
        st = record.get("status") or "open"
        sev = self._resolve_support_row_severity(record) or (record.get("severity") or "—")
        sev = sev.strip().upper() if sev and sev != "—" else sev
        desc = (record.get("description") or "—").strip() or "—"
        raised = self._short_display_date(record.get("requested_at"))
        sid = record.get("short_id", "?")
        messages = record.get("messages") or []

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🎫 Support Request Detail", "emoji": True}},
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*ID*\n`{sid}`"},
                    {"type": "mrkdwn", "text": f"*Status*\n{st.capitalize()}"},
                    {"type": "mrkdwn", "text": f"*Vulnerability*\n{vuln}"},
                    {"type": "mrkdwn", "text": f"*Asset*\n`{host}`"},
                    {"type": "mrkdwn", "text": f"*Criticality*\n{sev}"},
                    {"type": "mrkdwn", "text": f"*Team*\n{team}"},
                    {"type": "mrkdwn", "text": f"*Requested By*\n{requester}"},
                    {"type": "mrkdwn", "text": f"*Support Raised*\n{raised}"},
                ],
            },
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Description*\n_{desc}_"}},
        ]

        if messages:
            blocks.append({"type": "divider"})
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*Messages*"}})
            for m in messages[:8]:
                sender = m.get("sender_email") or m.get("sender") or "—"
                text = (m.get("text") or "").strip()
                sent = self._short_display_date(m.get("sent_at"))
                blocks.append({
                    "type": "context",
                    "elements": [{
                        "type": "mrkdwn",
                        "text": f"*{sender}* ({sent}): {text[:300]}",
                    }],
                })

        blocks.append({"type": "divider"})
        blocks.append({
            "type": "actions",
            "elements": [{
                "type": "button",
                "text": {"type": "plain_text", "text": "← Back to list", "emoji": True},
                "action_id": "sup_back_list",
                "value": f"{st_filter}|{team_filter}|{offset}",
            }],
        })
        return blocks

    def _lookup_support_by_short_id(self, sid, team_id, user_id):
        data = self._fetch_support_report_data(team_id, user_id)
        if not data:
            return None, data
        rows = self._assign_severity_short_ids(data.get("results") or [])
        target = next((r for r in rows if r.get("short_id") == sid), None)
        return target, data

    def _format_extension_requests(self, data):
        raw_results = data.get("results") or []
        results = self._assign_severity_short_ids(raw_results)
        count   = data.get("count", len(results))
        blocks  = [
            {"type": "header", "text": {"type": "plain_text", "text": "⏳ Timeline Extension Requests", "emoji": True}},
            self._ctx("All team requests to extend mitigation deadlines. Use `/approve` or `/reject` to respond."),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total Requests:* {count}"}},
            {"type": "divider"},
        ]
        status_icons = {"review": "🔵", "approved": "✅", "rejected": "❌"}
        for r in results[:8]:
            sid   = r.get("short_id", "?")
            team  = r.get("requested_by") or "Unknown"
            vuln  = r.get("vul_name") or "Unknown"
            sev   = (r.get("severity") or "").capitalize()
            st    = r.get("status", "review")
            days  = r.get("extension_days", 0)
            reason = r.get("reason", "—")
            icon  = status_icons.get(st, "🔵")
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": (
                    f"{icon} `{sid}` *{vuln}* [{sev}]\n"
                    f"Team: {team} | +{days} days | Reason: {reason}"
                )}})
            # Buttons always shown (matches the design — even an
            # already-approved/rejected row keeps its Approve/Reject
            # actions, letting the admin change their decision).
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve", "emoji": True},
                        "action_id": "av_approve_row", "value": sid, "style": "primary",
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject", "emoji": True},
                        "action_id": "av_reject_row", "value": sid, "style": "danger",
                    },
                ],
            })
        return blocks

    def _format_status_update(self, data, action, display_id, target=None, reason=None):
        if data.get("detail"):
            return self._text_block(f"❌ {data['detail']}")
        icon  = "✅" if action == "approved" else "❌"
        label = "Approved" if action == "approved" else "Rejected"
        lines = [f"{icon} Request `{display_id}` has been *{label}*."]
        if target:
            vuln = target.get("vul_name") or ""
            team = target.get("requested_by") or ""
            sev  = (target.get("severity") or "").capitalize()
            days = target.get("extension_days")
            bits = []
            if vuln:
                bits.append(f"*{vuln}*" + (f" [{sev}]" if sev else ""))
            if team:
                bits.append(f"Team: {team}")
            if days:
                bits.append(f"+{days} days")
            if bits:
                lines.append(" | ".join(bits))
        if action == "rejected" and reason:
            lines.append(f"Reason: {reason}")
        return [{"type": "section", "text": {"type": "mrkdwn", "text": "\n".join(lines)}}]

    # Same emoji-approximation convention as _ASSET_SEV_EMOJI (Block Kit has
    # no custom colors — closest Slack-native match to the design's exact
    # RGB severity pills).
    _SEV_EMOJI_MAP = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}

    def _status_icon_kind(self, st):
        st_norm = (st or "open").strip().lower()
        if st_norm == "closed":
            return "closed"
        if "progress" in st_norm:
            return "progress"
        if "review" in st_norm:
            return "review"
        return "open"

    def _status_icon_for(self, st):
        """Emoji fallback — Open=❗ / Open-Review=👀 / In Progress=🔄 / Closed=🔒"""
        kind = self._status_icon_kind(st)
        return {
            "closed": "🔒",
            "progress": "🔄",
            "review": "👀",
            "open": "❗",
        }.get(kind, "❗")

    def _status_icon_image_url(self, st):
        """Public PNG URL Slack can fetch for context/image elements."""
        kind = self._status_icon_kind(st)
        backend = getattr(settings, "VAPTFIX_BACKEND_URL", None) or getattr(
            settings, "BACKEND_BASE_URL", "https://vaptbackend.secureitlab.com"
        )
        return f"{backend.rstrip('/')}/api/admin/users/slack/status-icon/{kind}/"

    def _status_icon_image_element(self, st):
        return {
            "type": "image",
            "image_url": self._status_icon_image_url(st),
            "alt_text": self._status_icon_kind(st),
        }

    def _format_vulndata_list(self, data, offset=0):
        # LatestSuperAdminVulnerabilityRegisterAPIView returns the list under
        # "rows" (not "results"/"vulnerabilities"), with fields vul_name/asset
        # — reading the wrong keys silently produced "Total: 0" every time.
        PAGE_SIZE = 5
        raw_items = data if isinstance(data, list) else (data.get("rows") or data.get("results") or data.get("vulnerabilities") or [])
        items = self._assign_severity_short_ids(raw_items)
        count = len(items)

        offset = max(0, min(offset, max(count - 1, 0)))
        page_items = items[offset:offset + PAGE_SIZE]
        start_num  = offset + 1 if page_items else 0
        end_num    = offset + len(page_items)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🔍 Vulnerability Data", "emoji": True}},
            self._ctx("All vulnerabilities in your latest report. Use `/vulndata [id]` for details, `/vulndata automation` for script stats."),
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Total:* {count} vulnerabilities — showing {start_num}-{end_num}"}},
            {"type": "divider"},
        ]
        for v in page_items:
            sid  = v.get("short_id", "?")
            name = v.get("vul_name") or v.get("vulnerability_name") or v.get("plugin_name") or "Unknown"
            host = v.get("asset") or v.get("host_name") or "—"
            sev  = (v.get("severity") or v.get("risk_factor") or "").capitalize() or "—"
            st   = v.get("status") or "open"
            sev_icon = self._SEV_EMOJI_MAP.get(sev.lower(), "⚪")
            safe_sid = "".join(ch if ch.isalnum() else "_" for ch in str(sid))[:40]
            blocks.append({
                "type": "context",
                "elements": [
                    self._status_icon_image_element(st),
                    {"type": "mrkdwn", "text": f"`{sid}` *{name}*"},
                ],
            })
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"`{host}`  |  {sev_icon} *{sev}*  |  Status: {st.capitalize()}",
                },
                "accessory": {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View", "emoji": True},
                    "action_id": f"view_allvuln_detail_{safe_sid}",
                    "value": sid,
                },
            })
            blocks.append({"type": "divider"})

        pg_block = self._numbered_pagination_block(offset, PAGE_SIZE, count, "view_vulndata_pg")
        if pg_block:
            blocks.append(pg_block)

        return blocks

    def _format_register_tab(self, data, sev_filter="all", st_filter="all", offset=0):
        """
        New "Register" tab UI (Slack Block Kit) — severity + status filters,
        FIX/VIEW buttons, and pagination (5 rows per page).
        """
        PAGE_SIZE = 5

        raw_items = (
            data
            if isinstance(data, list)
            else (data.get("rows") or data.get("results") or data.get("vulnerabilities") or [])
        )

        def _norm_sev(v):
            return (v.get("severity") or v.get("risk_factor") or "").strip().lower()

        def _norm_status(v):
            return (v.get("status") or "open").strip().lower()

        def _match_sev(v):
            return True if sev_filter == "all" else (_norm_sev(v) == sev_filter)

        def _match_status(v):
            st = _norm_status(v)
            if st_filter == "all":
                return True
            if st_filter == "in_progress":
                return "progress" in st
            if st_filter == "open":
                # Covers "open" and "open/review"
                return st == "open" or st.startswith("open/")
            if st_filter == "closed":
                return st == "closed"
            return st == st_filter

        # Counts for filter buttons:
        # - Severity counts based on active status filter
        # - Status counts based on active severity filter
        sev_base = [v for v in raw_items if _match_status(v)]
        st_base = [v for v in raw_items if _match_sev(v)]

        def _count_by(predicate):
            return sum(1 for v in predicate)

        sev_counts = {
            "all": len(sev_base),
            "critical": sum(1 for v in sev_base if _norm_sev(v) == "critical"),
            "high": sum(1 for v in sev_base if _norm_sev(v) == "high"),
            "medium": sum(1 for v in sev_base if _norm_sev(v) == "medium"),
            "low": sum(1 for v in sev_base if _norm_sev(v) == "low"),
        }
        st_counts = {
            "all": len(st_base),
            "open": sum(1 for v in st_base if (_norm_status(v) == "open" or _norm_status(v).startswith("open/"))),
            "closed": sum(1 for v in st_base if _norm_status(v) == "closed"),
            "in_progress": sum(1 for v in st_base if "progress" in _norm_status(v)),
        }

        # Assign short IDs ONCE on the FULL unfiltered dataset so that a
        # clicked row always resolves to the same record even after applying
        # filters/pagination.
        normalized_all = [
            dict(v, severity=(v.get("severity") or v.get("risk_factor") or ""))
            for v in raw_items
        ]
        all_items = self._assign_severity_short_ids(normalized_all, name_key="vul_name")

        filtered = [v for v in all_items if _match_sev(v) and _match_status(v)]
        count = len(filtered)

        offset = max(0, min(offset, max(count - 1, 0)))
        page_items = filtered[offset : offset + PAGE_SIZE]
        start_num = offset + 1 if page_items else 0
        end_num = offset + len(page_items)

        def truncate(s, max_len=28):
            s = (s or "").strip()
            return (s[: max_len - 3] + "...") if len(s) > max_len else s

        def sev_icon_for(sev_norm):
            return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev_norm, "⚪")

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "📋 Register", "emoji": True}},
            {"type": "divider"},
        ]

        # Severity filter row — EACH button needs a UNIQUE action_id
        # (Slack rejects an actions block where buttons share action_id).
        sev_buttons = [
            ("all", "All"),
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
        ]
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": label, "emoji": True},
                        "action_id": f"reg_sev_{k}",
                        "value": f"{k}|{st_filter}|0",
                        **({"style": "primary"} if k == sev_filter else {}),
                    }
                    for (k, label) in sev_buttons
                ],
            }
        )

        # Status filter row (with counts) — unique action_ids
        st_buttons = [
            ("all", f"All {st_counts['all']}"),
            ("open", f"Open {st_counts['open']}"),
            ("closed", f"Closed {st_counts['closed']}"),
            ("in_progress", f"In Progress {st_counts['in_progress']}"),
        ]
        blocks.append(
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": label, "emoji": True},
                        "action_id": f"reg_st_{k}",
                        "value": f"{sev_filter}|{k}|0",
                        **({"style": "primary"} if k == st_filter else {}),
                    }
                    for (k, label) in st_buttons
                ],
            }
        )

        blocks.append({"type": "divider"})

        if not page_items:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*No vulnerabilities found.*"}})
        else:
            for idx, v in enumerate(page_items):
                # Line bar above every vulnerability except the first
                if idx > 0:
                    blocks.append({"type": "divider"})

                sno = start_num + idx
                sno_txt = str(sno).zfill(2)
                sid = v.get("short_id", "?")
                name = v.get("vul_name") or v.get("vulnerability_name") or v.get("plugin_name") or "Unknown"
                asset = v.get("asset") or v.get("host_name") or "—"
                sev_norm = _norm_sev(v)
                sev_label = (v.get("severity") or v.get("risk_factor") or sev_norm).strip().upper() or "—"
                first_obs = v.get("first_observation") or v.get("firstObs") or "—"
                second_obs = v.get("second_observation") or v.get("secondObs") or "—"
                st = v.get("status") or "open"
                st_display = _norm_status(v).replace("_", " ").capitalize()

                has_fix = bool(v.get("fix_vulnerability_id") or v.get("hasFix"))
                action_text = "FIX" if has_fix else "VIEW"
                safe_sid = "".join(ch if ch.isalnum() else "_" for ch in str(sid))[:40]

                def _short_date(val):
                    s = str(val or "—").strip()
                    if not s or s == "—":
                        return "—"
                    if "T" in s:
                        return s.split("T", 1)[0]
                    if " " in s and len(s) > 10:
                        return s.split(" ", 1)[0]
                    return s

                first_s = _short_date(first_obs)
                second_s = _short_date(second_obs)

                btn = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": action_text, "emoji": True},
                    "action_id": f"reg_view_{safe_sid}",
                    "value": sid,
                }
                if action_text == "FIX":
                    btn["style"] = "primary"

                # Top: Fix-tab style PNG status icon + S.No + id + FULL vuln name
                # (no "..." truncate — full name is always readable here)
                blocks.append(
                    {
                        "type": "context",
                        "elements": [
                            self._status_icon_image_element(st),
                            {
                                "type": "mrkdwn",
                                "text": f"*`{sno_txt}`*  `{sid}`  *{name}*",
                            },
                        ],
                    }
                )
                # Middle: asset + severity, FIX/VIEW on the RIGHT
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"`{asset}`  |  {sev_icon_for(sev_norm)} *{sev_label}*",
                        },
                        "accessory": btn,
                    }
                )
                # Bottom (niche): First Obs | Second Obs | Status
                blocks.append(
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": (
                                    f"*First Obs:* {first_s}  |  "
                                    f"*Second Obs:* {second_s}  |  "
                                    f"*Status:* *{st_display}*"
                                ),
                            },
                        ],
                    }
                )

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Showing {start_num}-{end_num} of {count} results",
                },
            }
        )

        value_prefix = f"{sev_filter}|{st_filter}|"
        pg_block = self._numbered_pagination_block(offset, PAGE_SIZE, count, "reg_list_pg", value_prefix=value_prefix)
        if pg_block:
            blocks.append(pg_block)

        return blocks

    def _format_script_tab(self, data, offset=0):
        """
        Script sub-tab under Register — mirrors slack/script.html:
        S.No | Vulnerability Name | Severity | Downloads | Team + pagination.
        Data from GET /api/admin/automation-scripts/stats/
        """
        PAGE_SIZE = 5
        raw = data.get("stats") if isinstance(data, dict) else (data if isinstance(data, list) else [])
        items = raw or []
        count = len(items)
        offset = max(0, min(offset, max(count - 1, 0))) if count else 0
        page_items = items[offset:offset + PAGE_SIZE]
        start_num = offset + 1 if page_items else 0
        end_num = offset + len(page_items)

        def sev_icon(sev):
            s = (sev or "").strip().lower()
            return self._SEV_EMOJI_MAP.get(s, "⚪")

        def team_label(team):
            t = (team or "").strip() or "—"
            return t

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "📜 Script", "emoji": True}},
            self._ctx("Automation scripts library — downloads and assigned team."),
            {"type": "divider"},
        ]

        if not page_items:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": "*No scripts found.*"}})
        else:
            for idx, s in enumerate(page_items):
                if idx > 0:
                    blocks.append({"type": "divider"})
                sno = str(start_num + idx).zfill(2)
                name = s.get("vulnerability") or "Unknown"
                sev = (s.get("severity") or "").strip() or "—"
                sev_u = sev.upper() if sev != "—" else "—"
                downloads = s.get("download_count", 0)
                team = team_label(s.get("team"))
                blocks.append(
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*`{sno}`*  *{name}*\n"
                                f"{sev_icon(sev)} *{sev_u}*  |  "
                                f"*Downloads:* {downloads}  |  "
                                f"*Team:* {team}"
                            ),
                        },
                    }
                )

        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"Showing {start_num}-{end_num} of {count} results",
                },
            }
        )
        pg_block = self._numbered_pagination_block(offset, PAGE_SIZE, count, "script_list_pg")
        if pg_block:
            blocks.append(pg_block)
        return blocks

    def _format_vulndata_detail(self, data, fix_vuln_id):
        name  = data.get("vulnerability_name") or data.get("name") or fix_vuln_id
        sev   = (data.get("severity") or "").capitalize()
        steps = data.get("steps") or []
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🔍 {name}", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{sev}"},
                {"type": "mrkdwn", "text": f"*Status*\n{data.get('status', 'open')}"},
            ]},
            {"type": "divider"},
        ]
        for i, step in enumerate(steps[:10], 1):
            step_name = step.get("step_description") or step.get("name") or f"Step {i}"
            step_st   = step.get("status") or "pending"
            icon      = "✅" if step_st == "completed" else "⬜"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"{icon} *Step {i}:* {step_name}"}})
        return blocks

    def _format_vulndata_single(self, v, steps_data=None, offset=0):
        """
        Full detail for one vuln resolved from a short ID (h1/m5/c3...) via
        /vulndata [id] — the base fields come from the admin-wide
        latest-report row (host/port/protocol/observation dates); when a fix
        record exists (fix_vulnerability_id present on the row, added to
        LatestSuperAdminVulnerabilityRegisterAPIView earlier), we also fetch
        and show the same mitigation steps a team member works through —
        VIEW ONLY. Admin can see exactly what's being done, but there are no
        Mark Step Done / Send for Verification buttons here — the backend
        already blocks admin POSTs to step-complete (403), and this Slack
        view mirrors that: read-only by design, not just by omission.
        """
        sid   = v.get("short_id", "?")
        name  = v.get("vul_name", "Unknown")
        host  = v.get("asset", "—")
        sev   = v.get("severity", "—") or "—"
        port  = v.get("port", "—")
        proto = v.get("protocol", "—") or "—"
        st    = v.get("status") or "open"
        icon  = self._status_icon_for(st)
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🔍 {sid.upper()} — {name}"[:150], "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{sev}"},
                {"type": "mrkdwn", "text": f"*Status*\n{icon} {st.capitalize()}"},
                {"type": "mrkdwn", "text": f"*Host*\n`{host}`"},
                {"type": "mrkdwn", "text": f"*Port / Protocol*\n{port}/{proto}"},
            ]},
            self._ctx(
                f"First seen: {v.get('first_observation', '—')} | Last check: {v.get('second_observation', '—')}"
            ),
        ]

        if not steps_data or steps_data.get("detail"):
            blocks.append({"type": "divider"})
            if v.get("fix_vulnerability_id") and steps_data and steps_data.get("detail"):
                # A fix record DOES exist (team has been assigned/started) but
                # the steps lookup itself failed — surface the real reason
                # instead of the generic "not started" message, which was
                # misleading here.
                blocks.append(self._text_block(
                    f"_Could not load mitigation steps: {steps_data.get('detail')}_"
                )[0])
            else:
                blocks.append(self._text_block(
                    "_No fix has been started for this vulnerability yet — no steps to show._"
                )[0])
            return blocks

        steps     = steps_data.get("steps") or []
        completed = steps_data.get("completed_steps", 0)
        total     = steps_data.get("total_steps", 0)
        os_v      = steps_data.get("operating_system") or "—"
        os_key    = "linux" if os_v and os_v.lower() in ("linux", "unix") else "windows"

        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": f"*📋 Mitigation Steps (view only)* — {completed}/{total} done | OS: {os_v}"}})

        PAGE_SIZE = 3
        page_steps = steps[offset:offset + PAGE_SIZE]
        for step in page_steps:
            step_num  = step.get("step_number")
            step_name = step.get("step_name") or f"Step {step_num}"
            status_v  = step.get("status", "pending")
            done      = status_v == "completed"
            badge     = "✅ Done" if done else ("🔒 Locked" if step.get("is_locked") else "▶️ Pending")
            os_data   = step.get(os_key) or {}
            action    = (os_data.get("action") or "").strip()

            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{step_num}. {step_name}* — {badge}"}})
            if action:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Action:*\n{action[:400]}"}})

        current_page = offset // PAGE_SIZE + 1
        if offset + PAGE_SIZE < len(steps):
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🔎 View Next Steps", "emoji": True},
                    "action_id": "view_vulndata_steps_page",
                    "value": f"{sid}|{current_page + 1}",
                }],
            })

        return blocks

    def _format_vulndata_automation_detail(self, v, automation):
        """
        Automation Fix side of the Vuln Details toggle — read-only, matches
        Manual's "view only" rule (no run/mark-fixed actions for admins).
        Uses the admin-only /api/admin/automation-scripts/match/<plugin_id>/
        endpoint, which has the same rich fields as the website. The actual
        script file isn't embedded here (no admin download route exists) —
        `/autofix` is still the way to get it, same as the team-facing view.
        """
        sid  = v.get("short_id", "?")
        name = v.get("vul_name", "Unknown")
        if not automation.get("matched"):
            return [
                {"type": "header", "text": {"type": "plain_text", "text": f"🤖 {sid.upper()} — {name}"[:150], "emoji": True}},
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": "_No automated fix script available for this vulnerability._"}},
            ]

        libs = automation.get("libraries") or []
        libs_str = ", ".join(f"`{l}`" for l in libs) if isinstance(libs, list) else str(libs or "—")

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🤖 Automated Fix: {name}"[:150], "emoji": True}},
            self._ctx("Read-only — ready-made fix script from the automation library. Use `/autofix` to download it."),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{automation.get('severity') or '—'}"},
                {"type": "mrkdwn", "text": f"*OS*\n{automation.get('os') or '—'}"},
                {"type": "mrkdwn", "text": f"*Language*\n{automation.get('language') or '—'}"},
                {"type": "mrkdwn", "text": f"*Automation Possible*\n{automation.get('automation_possible') or '—'}"},
            ]},
            {"type": "divider"},
        ]

        def add_section(label, key):
            val = automation.get(key)
            if val:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{label}*\n{str(val)[:800]}"}})

        add_section("What this does", "script_description")
        add_section("Recommended Approach", "recommended_approach")
        add_section("What can be automated", "what_can_be_automated")
        add_section("What must remain manual", "what_must_remain_manual")
        if libs:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Libraries needed*\n{libs_str}"}})
        if automation.get("command_download_libraries"):
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Install command*\n`{automation['command_download_libraries']}`"}})
        add_section("Before running", "considerations_before")

        blocks.append(self._ctx(
            f"Script: `{automation.get('fix_script_name') or '—'}` — run `/autofix {sid}` to get it."
        ))
        return blocks

    def _format_vulndata_automation(self, data):
        items      = data if isinstance(data, list) else (data.get("results") or data.get("vulnerabilities") or [])
        auto_count = sum(1 for v in items if v.get("is_automated") or v.get("has_script"))
        manual     = len(items) - auto_count
        return [
            {"type": "header", "text": {"type": "plain_text", "text": "🤖 Automation Breakdown", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Total Vulns*\n{len(items)}"},
                {"type": "mrkdwn", "text": f"*Automated*\n{auto_count}"},
                {"type": "mrkdwn", "text": f"*Manual Only*\n{manual}"},
            ]},
        ]

    def _format_verifications(self, results):
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": "🔍 Pending Verifications", "emoji": True}},
            self._ctx("Vulnerabilities a team has marked fixed via /retest — awaiting your approval to close. Use /approvefix [fix_vuln_id]."),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total Pending:* {len(results)}"}},
            {"type": "divider"},
        ]
        if not results:
            return blocks + self._text_block("✅ Nothing pending verification right now.")
        for r in results[:10]:
            sev  = (r.get("severity") or "").capitalize()
            icon = self._SEV_ICONS.get(sev, "⚪")
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
                f"{icon} *{r.get('vulnerability_name', 'Unknown')}*\n"
                f"Host: `{r.get('asset', '—')}` | Team: {r.get('assigned_team', '—')} | "
                f"Steps done: {r.get('completed_steps', 0)}\n"
                f"`/approvefix {r.get('fix_vulnerability_id', '')}`"
            )}})
        if len(results) > 10:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_...and {len(results) - 10} more._"}})
        return blocks

    # ── Team channel formatters ────────────────────────────────────────────

    def _ctx(self, text):
        """Small context/description line shown under the header in Slack."""
        return {"type": "context", "elements": [{"type": "mrkdwn", "text": text}]}

    def _format_viewassigned(self, vulns, team_name, raw_data=None, offset=0):
        if not vulns:
            raw_data = raw_data or {}

            # Distinct, clear message when the admin simply never added this
            # person to THIS team at all — as opposed to being on the team
            # with nothing assigned yet. Previously both cases showed the
            # same generic "no vulns assigned" text with a confusing debug
            # line (e.g. "admin=not_found"), which looked like an error.
            if raw_data.get("not_member_of_team"):
                member_teams = raw_data.get("member_teams") or []
                your_teams = (
                    f"Your team(s): {', '.join(member_teams)}."
                    if member_teams else
                    "You don't appear to be assigned to any team yet."
                )
                return [
                    {"type": "header", "text": {"type": "plain_text", "text": f"📋 {team_name}", "emoji": True}},
                    {"type": "section", "text": {"type": "mrkdwn", "text": (
                        f"🚫 You're not a member of *{team_name}*.\n\n"
                        f"{your_teams}\n\n"
                        f"Use commands in your own team's channel instead, or ask your admin "
                        f"to add you to *{team_name}* via `/adduser` if this is a mistake."
                    )}},
                ]

            diag = ""
            if raw_data:
                report_id  = raw_data.get("report_id", "") or "none"
                card_count = raw_data.get("card_count", "?")
                has_cards  = raw_data.get("has_cards", "?")
                detail     = raw_data.get("detail", "")
                diag = (
                    f"\n\n_Debug:_ report=`{report_id}` | cards={card_count} | cards_mode={has_cards}"
                    + (f" | error=`{detail}`" if detail else "")
                )
            return [
                {"type": "header", "text": {"type": "plain_text", "text": f"📋 {team_name}", "emoji": True}},
                self._ctx("Shows all vulnerabilities & assets assigned to your team with short IDs (c1, h1, m1, l1...). Use these IDs with /startfix, /mitigated, /retest, /extend"),
                {"type": "section", "text": {"type": "mrkdwn",
                    "text": (
                        "📭 No vulnerabilities currently assigned to *" + team_name + "* team.\n\n"
                        "_Possible reasons:_\n"
                        "• Admin hasn't assigned vulns to this team yet in the dashboard\n"
                        "• No active report uploaded for this workspace\n\n"
                        "Contact your admin to assign vulnerabilities via the VaptFix dashboard."
                        + diag
                    )}},
            ]
        PAGE_SIZE = 10
        total  = len(vulns)
        open_c = sum(1 for v in vulns if v.get("status") == "open")
        closed = sum(1 for v in vulns if v.get("status") == "closed")

        offset = max(0, min(offset, max(total - 1, 0)))
        page_vulns = vulns[offset:offset + PAGE_SIZE]
        start_num  = offset + 1 if page_vulns else 0
        end_num    = offset + len(page_vulns)

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"📋 {team_name} — Assigned Work", "emoji": True}},
            self._ctx("All vulnerabilities assigned to your team. Use IDs (c1, h1...) with /startfix, /mitigated, /retest, /extend"),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Total Vulns*\n{total}"},
                {"type": "mrkdwn", "text": f"*Open*\n{open_c}"},
                {"type": "mrkdwn", "text": f"*Fixed*\n{closed}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"_Showing {start_num}-{end_num} of {total}. IDs: use with `/startfix`, `/mitigated`, `/retest`, `/extend`_"}},
            {"type": "divider"},
        ]
        for v in page_vulns:
            sid    = v.get("short_id", "?")
            name   = v.get("plugin_name") or "Unknown"
            host   = v.get("host_name") or "—"
            sev    = v.get("risk_factor") or v.get("sev_label") or "Low"
            status = v.get("status") or "open"
            icon   = self._SEV_ICONS.get(sev, "⚪")
            st_icon = "✅" if status == "closed" else "🔓"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"{icon} `{sid}` *{name}*\n      Host: `{host}` | {st_icon} {status.capitalize()}"}})

        current_page = offset // PAGE_SIZE + 1
        nav_buttons = []
        if offset > 0:
            nav_buttons.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "◀ Previous", "emoji": True},
                # Distinct action_id from "Next" — Slack rejects the whole
                # message with "invalid_blocks" when two buttons in the same
                # actions block share an action_id (only differing by value).
                "action_id": "view_vulns_prev",
                "value": f"{team_name}|{max(0, offset - PAGE_SIZE)}",
            })
        if end_num < total:
            nav_buttons.append({
                "type": "button",
                "text": {"type": "plain_text", "text": "Next ▶", "emoji": True},
                "action_id": "view_vulns_next",
                "value": f"{team_name}|{offset + PAGE_SIZE}",
            })
        if nav_buttons:
            blocks.append({"type": "actions", "elements": nav_buttons})

        # Reliable text-command paging alongside the buttons — buttons need
        # Slack's Interactivity feature wired up correctly; this always works
        # since it's just a normal slash command.
        page_hints = []
        if offset > 0:
            page_hints.append(f"`/viewassigned vulns {current_page - 1}` for previous")
        if end_num < total:
            page_hints.append(f"`/viewassigned vulns {current_page + 1}` for next")
        if page_hints:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_Or type: {' | '.join(page_hints)}_"}})

        return blocks

    def _format_team_assets(self, data, team_name):
        by_team = data.get("by_team") or []
        team_entry = next(
            (t for t in by_team if (t.get("team") or "").lower() == team_name.lower()), None
        )
        if not team_entry:
            return self._text_block(f"No assets currently assigned to *{team_name}* team.")
        count  = team_entry.get("asset_count") or team_entry.get("count") or 0
        assets = team_entry.get("assets") or team_entry.get("hosts") or []
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🖥 {team_name} — Assets", "emoji": True}},
            self._ctx("All host/IP assets currently assigned to your team from the latest report"),
            {"type": "section", "text": {"type": "mrkdwn", "text": f"*Total Assets:* {count}"}},
            {"type": "divider"},
        ]
        for a in assets[:10]:
            host = a if isinstance(a, str) else (a.get("host_name") or a.get("host") or str(a))
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"🔹 `{host}`"}})
        if count > 10:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_...and {count - 10} more._"}})
        return blocks

    def _format_mitigationstatus(self, vulns, team_name):
        # "open/review" = team ran /retest, awaiting superadmin approval via
        # /approvefix. Previously this fell through every bucket below (the
        # "/" was never stripped) and silently vanished from the stats.
        counts     = {"open": 0, "closed": 0, "in_progress": 0, "overdue": 0, "open_review": 0}
        sev_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for v in vulns:
            st = (v.get("status") or "open").strip().lower().replace(" ", "_").replace("/", "_").replace("-", "_")
            if st in counts:
                counts[st] += 1
            sev = (v.get("risk_factor") or v.get("sev_label") or "").strip().title()
            if sev in sev_counts:
                sev_counts[sev] += 1
        total = len(vulns)
        rate  = round((counts["closed"] / total) * 100) if total else 0
        bar   = self._bar(counts["closed"], max(total, 1), width=10)
        return [
            {"type": "header", "text": {"type": "plain_text", "text": f"📊 {team_name} — Mitigation Status", "emoji": True}},
            self._ctx("Current fix progress for all your team's vulnerabilities — open, closed, in-progress, overdue, open/review counts"),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Total*\n{total}"},
                {"type": "mrkdwn", "text": f"*Fix Rate*\n{rate}%"},
                {"type": "mrkdwn", "text": f"*Open*\n{counts['open']}"},
                {"type": "mrkdwn", "text": f"*Closed*\n{counts['closed']}"},
                {"type": "mrkdwn", "text": f"*In Progress*\n{counts['in_progress']}"},
                {"type": "mrkdwn", "text": f"*Overdue*\n{counts['overdue']}"},
                {"type": "mrkdwn", "text": f"*Open/Review*\n{counts['open_review']}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Progress:* `{bar}` {rate}%"}},
            {"type": "section", "text": {"type": "mrkdwn", "text": (
                f"*By Severity:* "
                f"🔴 Critical: {sev_counts['Critical']} | "
                f"🟠 High: {sev_counts['High']} | "
                f"🟡 Medium: {sev_counts['Medium']} | "
                f"🟢 Low: {sev_counts['Low']}"
            )}},
        ]

    def _format_startfix_list(self, vulns, team_name):
        next_vuln = next((v for v in vulns if v.get("status") != "closed"), None)
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🔧 {team_name} — Fix Workflow", "emoji": True}},
            self._ctx("Priority fix order: Critical → High → Medium → Low. Run /startfix [id] e.g. /startfix h1 for step-by-step fix guide"),
        ]
        if next_vuln:
            sid  = next_vuln.get("short_id", "?")
            name = next_vuln.get("plugin_name") or "Unknown"
            sev  = next_vuln.get("risk_factor") or next_vuln.get("sev_label") or ""
            host = next_vuln.get("host_name") or "—"
            icon = self._SEV_ICONS.get(sev, "⚪")
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
                f"*▶ Next Priority:* {icon} `{sid}` — *{name}*\n"
                f"Host: `{host}` | Severity: {sev}\n"
                f"Run `/startfix {sid}` for fix steps."
            )}})
            blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn",
            "text": "*All Assigned Vulnerabilities (Priority Order):*"}})
        for v in vulns[:10]:
            sid    = v.get("short_id", "?")
            name   = v.get("plugin_name") or "Unknown"
            sev    = v.get("risk_factor") or v.get("sev_label") or "Low"
            status = v.get("status") or "open"
            icon   = self._SEV_ICONS.get(sev, "⚪")
            st_icon = "✅" if status == "closed" else "🔓"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"{st_icon} {icon} `{sid}` {name}"}})
        if len(vulns) > 10:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_...{len(vulns) - 10} more. Use `/viewassigned` for full list._"}})
        return blocks

    def _format_startfix_real(self, vuln, fix_vuln_id, automation=None, steps_data=None):
        """
        Real /startfix detail screen — no hardcoded steps. Points to /manualfix
        (always) and /autofix (only when automation_scripts has a match).
        """
        name = vuln.get("plugin_name") or "Unknown"
        sev  = vuln.get("risk_factor") or vuln.get("sev_label") or "Medium"
        host = vuln.get("host_name") or "—"
        port = vuln.get("port") or "—"
        sid  = vuln.get("short_id", "?")
        icon = self._SEV_ICONS.get(sev, "⚪")
        fields = [
            {"type": "mrkdwn", "text": f"*ID*\n`{sid}`"},
            {"type": "mrkdwn", "text": f"*Severity*\n{icon} {sev}"},
            {"type": "mrkdwn", "text": f"*Host*\n`{host}`"},
            {"type": "mrkdwn", "text": f"*Port*\n{port}"},
        ]
        if steps_data and steps_data.get("total_steps") is not None:
            fields.append({"type": "mrkdwn", "text": (
                f"*Steps*\n{steps_data.get('completed_steps', 0)}/{steps_data.get('total_steps', 0)} done"
            )})
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🔧 Fix: {name[:60]}", "emoji": True}},
            self._ctx(f"Fix ID `{fix_vuln_id}` — use with /manualfix, /autofix, /mitigated, /retest"),
            {"type": "section", "fields": fields},
            {"type": "divider"},
        ]
        if automation and automation.get("matched") and automation.get("automation_possible"):
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
                f"🤖 *Automated fix available.*\nRun `/autofix {sid}` to get the ready-made fix script."
            )}})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
            f"📖 *Manual step-by-step guide available.*\nRun `/manualfix {sid}` for exact commands for your OS."
        )}})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
            f"When done: `/mitigated {sid}` to mark complete, then `/retest {sid}` to notify admin."
        )}})
        return blocks

    def _format_steps_status(self, data, vuln_id, fix_vuln_id, team_name, offset=0):
        """
        Full per-step detail — same content as the web dashboard's Manual Fix
        tab (Action LOCATE/REMOVE/REPLACE/WHERE, Assigned Team, Where/How to
        Run, Command, Expected Output, Verification Check, Tools, Important
        Considerations) — all of it already comes from the step-complete API,
        just not previously surfaced in Slack.

        `offset` paginates through steps (PAGE_SIZE at a time) via a real
        "View Next Steps" button — not a "run the command again" instruction,
        which would have just shown the same first steps every time.
        """
        PAGE_SIZE = 2
        name      = data.get("vulnerability_name") or "Unknown"
        asset     = data.get("asset") or "—"
        os_v      = data.get("operating_system") or "—"
        completed = data.get("completed_steps", 0)
        total     = data.get("total_steps", 0)
        all_done  = data.get("all_steps_completed", False)
        steps     = data.get("steps") or []

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"📋 Steps: {name[:55]}", "emoji": True}},
            self._ctx(f"Full step-by-step detail for {asset} — same content as the dashboard's Manual Fix tab."),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Asset*\n`{asset}`"},
                {"type": "mrkdwn", "text": f"*OS*\n{os_v}"},
                {"type": "mrkdwn", "text": f"*Progress*\n{completed}/{total} done"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"`{self._bar(completed, max(total, 1))}` {round((completed/total)*100) if total else 0}%"}},
        ]

        if not steps:
            blocks.append({"type": "divider"})
            blocks.append(self._text_block("No mitigation steps found for this vulnerability.")[0])
            return blocks

        os_key = "linux" if os_v and os_v.lower() in ("linux", "unix") else "windows"

        # Page start: on the first page, jump straight to the current/next
        # actionable step instead of always starting at step 1.
        if offset:
            start_idx = min(offset, len(steps))
        else:
            current = next((s for s in steps if s.get("is_current")), None)
            start_idx = steps.index(current) if current else 0

        detail_steps = steps[start_idx:start_idx + PAGE_SIZE]
        next_offset  = start_idx + PAGE_SIZE
        remaining    = len(steps) - next_offset

        for step in detail_steps:
            step_num  = step.get("step_number")
            step_name = step.get("step_name") or f"Step {step_num}"
            status_v  = step.get("status", "pending")
            locked    = step.get("is_locked")
            done      = status_v == "completed"
            badge     = "✅ Done" if done else ("🔒 Locked" if locked else "▶️ Pending")

            os_data     = step.get(os_key) or {}
            action      = (os_data.get("action") or "").strip()
            assigned    = step.get("assigned_team") or "—"
            where_label = os_data.get("where_to_run_label", "Terminal")
            how_to_run  = os_data.get("how_to_run", "")
            # Prefer commands_for_action (still a clean list of {label, commands})
            # over command_to_run — the backend's own string-flattening of that
            # same list (in _ensure_execution_guidance_fields) does a naive
            # str(dict) per entry when it can't join it as commands, which
            # produces literal Python-repr text like "{'label': ..., ...}".
            # Reading the structured list ourselves avoids that entirely.
            command = os_data.get("commands_for_action")
            if not command:
                command = os_data.get("command_to_run") or ""
            if isinstance(command, list):
                command = "\n".join(
                    "\n".join(c.get("commands", []) if isinstance(c, dict) else [str(c)])
                    for c in command
                )
            expected  = os_data.get("expected_output", "")
            verify    = os_data.get("verification_check", "")
            tools     = os_data.get("artifacts_tools_used") or []
            if isinstance(tools, str):
                tools = [tools] if tools else []
            important = os_data.get("important_consideration", "")

            blocks.append({"type": "divider"})
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*{step_num}. {step_name}* — {badge}"}})
            blocks.append({"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Assigned Team*\n{assigned}"},
                {"type": "mrkdwn", "text": f"*Where to Run*\n{where_label}"},
            ]})
            if action:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Action:*\n{action[:600]}"}})
            if how_to_run:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*How to Run:*\n{how_to_run[:300]}"}})
            if command and str(command).strip().lower() not in ("n/a", "na", ""):
                blocks.append({"type": "section", "text": {"type": "mrkdwn",
                    "text": f"*Command to Run:*\n```{str(command).strip()[:600]}```"}})
            if expected:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Expected Output:*\n{expected[:300]}"}})
            if verify:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Verification Check:*\n{verify[:300]}"}})
            if tools:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Tools:* {', '.join(tools)}"}})
            if important:
                blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"⚠️ *Important:* {important[:300]}"}})

        if remaining > 0:
            blocks.append({"type": "divider"})
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_{remaining} more step(s) below._"}})
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text",
                              "text": f"🔎 View Next {min(PAGE_SIZE, remaining)} Step(s)", "emoji": True},
                    "action_id": "view_more_steps",
                    "value": f"{fix_vuln_id}|{vuln_id}|{team_name}|{next_offset}",
                }],
            })

        blocks.append({"type": "divider"})
        button_value = f"{fix_vuln_id}|{vuln_id}|{team_name}"
        if all_done:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
                "✅ All steps complete."
            )}})
            blocks.append({
                "type": "actions",
                "elements": [{
                    "type": "button",
                    "text": {"type": "plain_text", "text": "📨 Send for Verification", "emoji": True},
                    "style": "primary",
                    "action_id": "send_verification",
                    "value": button_value,
                }],
            })
        else:
            next_step_num = completed + 1
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": f"▶️ Mark Step {next_step_num} Done", "emoji": True},
                        "action_id": "mitigate_step",
                        "value": button_value,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Mark All Steps Done", "emoji": True},
                        "style": "primary",
                        "action_id": "mitigate_all",
                        "value": button_value,
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Mark all steps done?"},
                            "text": {"type": "plain_text",
                                     "text": "This completes every remaining step for this vulnerability at once."},
                            "confirm": {"type": "plain_text", "text": "Yes, mark all done"},
                            "deny": {"type": "plain_text", "text": "Cancel"},
                        },
                    },
                ],
            })
        return blocks

    def _format_autofix(self, automation, script_text, vuln_id, uploaded=False):
        """
        Format the automation_scripts match + downloaded script into Slack
        blocks — surfaces every field the API/Google-Sheet-synced document
        provides, not just the core script content.
        """
        vuln_name   = automation.get("vulnerability") or "Unknown"
        severity    = (automation.get("severity") or "").capitalize()
        os_v        = automation.get("os") or "—"
        available   = automation.get("available_os") or []
        language    = automation.get("language") or "—"
        script_name = automation.get("script_name") or automation.get("fix_script_name") or "fix_script"
        desc        = automation.get("script_description") or ""
        before      = automation.get("considerations_before") or ""
        after       = automation.get("considerations_after") or ""
        run_cmd     = automation.get("command_run_script") or ""
        dl_cmd      = automation.get("command_download_libraries") or ""
        libraries   = automation.get("libraries") or ""
        possible    = (automation.get("automation_possible") or "").strip()
        tested      = (automation.get("tested_manually") or "").strip()
        can_auto    = automation.get("what_can_be_automated") or ""
        must_manual = automation.get("what_must_remain_manual") or ""
        approach    = automation.get("recommended_approach") or ""

        possible_badge = {
            "yes": "✅ Yes", "partial": "⚠️ Partial", "no": "❌ No",
        }.get(possible.lower(), possible or "—")
        tested_badge = {"yes": "✅ Yes", "no": "❌ No"}.get(tested.lower(), tested or "—")

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🤖 Automated Fix: {vuln_name[:55]}", "emoji": True}},
            self._ctx("Ready-made fix script from the automation library. Test in a safe environment first."),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Severity*\n{severity or '—'}"},
                {"type": "mrkdwn", "text": f"*OS*\n{os_v}"},
                {"type": "mrkdwn", "text": f"*Language*\n{language}"},
                {"type": "mrkdwn", "text": f"*Script*\n`{script_name}`"},
                {"type": "mrkdwn", "text": f"*Automation Possible*\n{possible_badge}"},
                {"type": "mrkdwn", "text": f"*Tested Manually*\n{tested_badge}"},
            ]},
        ]
        if len(available) > 1:
            others = [o for o in available if o.lower() != (os_v or "").lower()]
            if others:
                blocks.append({"type": "section", "text": {"type": "mrkdwn",
                    "text": f"_A fix script is also available for: {', '.join(others)}._"}})
        blocks.append({"type": "divider"})

        if desc:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*What this does:*\n{desc[:500]}"}})
        if approach:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Recommended Approach:*\n{approach[:400]}"}})
        if can_auto:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"✅ *What can be automated:*\n{can_auto[:400]}"}})
        if must_manual:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"✋ *What must remain manual:*\n{must_manual[:400]}"}})
        if libraries or dl_cmd:
            lib_text = f"*Libraries needed:* {libraries}" if libraries else ""
            if dl_cmd:
                lib_text += f"\n*Install command:*\n```{dl_cmd}```"
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": lib_text.strip()}})
        if before:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"⚠️ *Before running:*\n{before[:400]}"}})

        if script_text:
            snippet = script_text[:2500]
            truncated = len(script_text) > 2500
            if uploaded:
                trailer = "\n_📎 Full script uploaded above as a downloadable file._"
            elif truncated:
                trailer = "\n_...truncated — full script also on the VaptFix dashboard._"
            else:
                trailer = ""
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Script (`{script_name}`):*\n```{snippet}```" + trailer}})
        else:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": "_Script file could not be fetched — download it from the VaptFix dashboard instead._"}})

        if run_cmd:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*Run with:*\n```{run_cmd}```"}})
        if after:
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"✔️ *After running:*\n{after[:400]}"}})

        blocks.append({"type": "divider"})
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": (
            f"After running, tell us if it worked: `/scriptfeedback {vuln_id} up` or `/scriptfeedback {vuln_id} down`\n"
            f"Then: `/mitigated {vuln_id}` to mark complete, `/retest {vuln_id}` to notify admin."
        )}})
        return blocks

    def _format_team_support_status(self, data, team_name):
        # data is from SupportRequestByReportAPIView — full list filtered by team
        all_results = data.get("results") or []
        # Filter for this team only
        team_results = [
            r for r in all_results
            if (r.get("assigned_team") or "").strip().lower() == team_name.strip().lower()
        ] if all_results else []

        total   = len(team_results)
        pending = sum(1 for r in team_results if (r.get("status") or "open") != "closed")
        closed  = sum(1 for r in team_results if (r.get("status") or "") == "closed")

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🎫 {team_name} — Support Requests", "emoji": True}},
            self._ctx('All support tickets raised by your team. Use /support raise "message" to open a new ticket'),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Total*\n{total}"},
                {"type": "mrkdwn", "text": f"*Open*\n{pending}"},
                {"type": "mrkdwn", "text": f"*Closed*\n{closed}"},
            ]},
        ]

        if not team_results:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": (
                    "📭 No support requests yet.\n"
                    '_Open a ticket:_ `/support raise "your message here"`'
                )}})
            return blocks

        blocks.append({"type": "divider"})
        st_icons = {"open": "🔵", "closed": "✅", "pending": "🔵", "review": "🟡"}
        for r in team_results[:8]:
            vuln  = r.get("vul_name") or "General Request"
            host  = r.get("host_name") or ""
            desc  = r.get("description") or "—"
            st    = (r.get("status") or "open").lower()
            by    = r.get("requested_by") or "Team"
            icon  = st_icons.get(st, "🔵")
            host_str = f" | Host: `{host}`" if host else ""
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": (
                    f"{icon} *{vuln}*{host_str}\n"
                    f"_{desc}_\n"
                    f"By: {by} | Status: *{st.capitalize()}*"
                )}})

        if total > 8:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_...and {total - 8} more tickets. View all in dashboard._"}})
        return blocks

    def _format_team_extend_status(self, data, team_name):
        results = data.get("results") or []
        team_results = [
            r for r in results
            if (r.get("requested_by") or "").lower() == team_name.lower()
        ] or results
        status_icons = {"review": "🔵", "approved": "✅", "rejected": "❌"}
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"⏳ {team_name} — Extension Requests", "emoji": True}},
            self._ctx("Timeline extension requests for your team. Use /extend [id] reason to request a new extension"),
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"*Total Requests:* {len(team_results)}"}},
            {"type": "divider"},
        ]
        if not team_results:
            return blocks + self._text_block("No extension requests found.")
        for r in team_results[:6]:
            vuln   = r.get("vul_name") or "Unknown"
            sev    = (r.get("severity") or "").capitalize()
            st     = r.get("status", "review")
            days   = r.get("extension_days", 0)
            reason = r.get("reason", "—")
            icon   = status_icons.get(st, "🔵")
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"{icon} *{vuln}* [{sev}] — +{days} days\n_Status: {st}_ | Reason: {reason}"}})
        return blocks

    def _format_scriptstats(self, vulns, matched_by_pid, team_name):
        """
        vulns: this team's vuln list (from _get_team_vulns, has plugin_id/short_id)
        matched_by_pid: {plugin_id: automation_doc} for plugin_ids WITH a script
        """
        total      = len(vulns)
        auto_count = sum(1 for v in vulns if v.get("plugin_id") in matched_by_pid)
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": f"🤖 {team_name} — Script Stats", "emoji": True}},
            self._ctx("Script download stats — shows which vulnerabilities have automated fix scripts available for your team"),
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*Total Vulns*\n{total}"},
                {"type": "mrkdwn", "text": f"*With Scripts*\n{auto_count}"},
                {"type": "mrkdwn", "text": f"*Manual Only*\n{total - auto_count}"},
            ]},
            {"type": "divider"},
        ]
        for v in vulns[:10]:
            sid      = v.get("short_id", "?")
            name     = v.get("plugin_name") or "Unknown"
            doc      = matched_by_pid.get(v.get("plugin_id"))
            has_scr  = bool(doc)
            dl_count = doc.get("download_count", 0) if doc else 0
            icon     = "🤖" if has_scr else "📝"
            detail   = f"Downloads: {dl_count}  _(`/autofix {sid}`)_" if has_scr else f"Manual fix only  _(`/manualfix {sid}`)_"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"{icon} `{sid}` *{name}*\n      {detail}"}})
        if total > 10:
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                "text": f"_...and {total - 10} more. Use `/scriptstats [vuln-id]` for a specific one._"}})
        return blocks

    def _format_single_scriptstats(self, automation, target, vuln_id):
        name = target.get("plugin_name") or "Unknown"
        if not automation.get("matched"):
            return [
                {"type": "header", "text": {"type": "plain_text", "text": f"📝 Script Stats: {name[:55]}", "emoji": True}},
                {"type": "section", "text": {"type": "mrkdwn", "text": (
                    f"No automated fix script available for `{vuln_id}`.\n"
                    f"Use `/manualfix {vuln_id}` for the step-by-step guide instead."
                )}},
            ]
        return [
            {"type": "header", "text": {"type": "plain_text", "text": f"🤖 Script Stats: {name[:55]}", "emoji": True}},
            {"type": "section", "fields": [
                {"type": "mrkdwn", "text": f"*OS*\n{automation.get('os', '—')}"},
                {"type": "mrkdwn", "text": f"*Downloads*\n{automation.get('download_count', 0)}"},
            ]},
            {"type": "section", "text": {"type": "mrkdwn",
                "text": f"Run `/autofix {vuln_id}` to get the script."}},
        ]


class SlackInteractivityView(APIView):
    """
    Handles Slack Block Kit button clicks (block_actions payloads) — e.g. the
    "Mark Step Done" / "Mark All Steps Done" buttons on /manualfix.

    This is a SEPARATE Slack feature from slash commands — Slack apps have a
    distinct "Interactivity & Shortcuts" setting with its own Request URL.
    Acks Slack immediately; does the real work in a background thread and
    updates the original message in place via response_url (same
    ack-then-respond-async pattern as SlackSlashCommandView).
    """
    permission_classes = [AllowAny]
    authentication_classes = []

    DEBUG_LOG_PATH = "/tmp/slack_interactivity_debug.log"

    def _debug_write(self, msg):
        """
        Belt-and-suspenders diagnostic: write straight to a dedicated file,
        bypassing Django's logging config and Python's stdout entirely —
        neither logger.warning nor print() were showing up in
        gunicorn-error.log (likely because gunicorn wasn't started with
        --capture-output, so worker stdout/stderr isn't routed there).
        A plain file write can't get lost in that ambiguity.
        """
        try:
            from datetime import datetime as _dt
            with open(self.DEBUG_LOG_PATH, "a") as f:
                f.write(f"{_dt.utcnow().isoformat()} {msg}\n")
        except Exception:
            pass

    def post(self, request):
        try:
            payload = json.loads(request.POST.get("payload", "{}"))
        except (ValueError, TypeError):
            self._debug_write("post(): failed to parse payload JSON")
            return Response({}, status=200)

        ptype = payload.get("type")

        if ptype == "view_submission":
            # Add User / Delete User modal submits. Ack immediately with a
            # "Processing…" view (must happen within Slack's ~3s window),
            # then do the real work (Slack user lookup + backend API calls —
            # too slow to guarantee inside that window) in a background
            # thread and swap the modal's content via views.update once
            # done — same ack-then-async pattern as block_actions below,
            # just using views.update instead of response_url.
            view = payload.get("view") or {}
            callback_id = view.get("callback_id", "")
            titles = {
                "modal_adduser_submit": "Add User",
                "modal_deleteuser_submit": "Delete User",
                "modal_reject_submit": "Reject Request",
            }
            if callback_id not in titles:
                return Response({}, status=200)
            title = titles[callback_id]
            processing_view = SlackSlashCommandView()._build_result_modal(
                title, [{"type": "section", "text": {"type": "mrkdwn", "text": "⏳ Processing…"}}]
            )
            threading.Thread(target=self._handle_view_submission, args=(payload,), daemon=True).start()
            return Response({"response_action": "update", "view": processing_view}, status=200)

        if ptype != "block_actions":
            self._debug_write(f"post(): ignored type={ptype}")
            return Response({}, status=200)

        actions = payload.get("actions") or []
        if not actions:
            self._debug_write("post(): block_actions payload had no actions[]")
            return Response({}, status=200)

        action        = actions[0]
        action_id     = action.get("action_id", "")
        value         = action.get("value", "")
        team_id       = (payload.get("team") or {}).get("id", "")
        slack_user_id = (payload.get("user") or {}).get("id", "")
        response_url  = payload.get("response_url", "")
        trigger_id    = payload.get("trigger_id", "")
        channel_id    = (payload.get("channel") or {}).get("id", "")

        self._debug_write(
            f"post(): received action_id={action_id} value={value!r} "
            f"team_id={team_id} user_id={slack_user_id} has_response_url={bool(response_url)}"
        )
        print(
            f"[SlackInteractivity] received action_id={action_id} value={value!r} "
            f"team_id={team_id} user_id={slack_user_id} has_response_url={bool(response_url)}",
            flush=True,
        )

        threading.Thread(
            target=self._handle_action,
            args=(action_id, value, team_id, slack_user_id, response_url, trigger_id, channel_id),
            daemon=True,
        ).start()

        # Slack just needs a 200 within 3s for block_actions — no visible body needed.
        return Response({}, status=200)

    def _post_response_url(self, response_url, payload, action_id=""):
        """
        POST to Slack's response_url and actually check the result — the
        previous version fired-and-forgot this call, so if Slack rejected
        the payload (e.g. invalid Block Kit structure) the button click
        would silently do nothing with zero trace in our own logs.
        """
        if not response_url:
            self._debug_write(f"_post_response_url: action={action_id} has NO response_url!")
            return
        try:
            resp = _http_post(response_url, json=payload, timeout=10)
            ok = resp is not None and resp.status_code == 200 and (resp.text or "").strip() == "ok"
            if not ok:
                msg = (
                    f"_post_response_url: action={action_id} "
                    f"got status={getattr(resp, 'status_code', None)} body={getattr(resp, 'text', None)!r}"
                )
                logger.warning(f"[SlackInteractivity] {msg}")
                self._debug_write(msg)
                try:
                    self._debug_write(f"_post_response_url: action={action_id} SENT_PAYLOAD={json.dumps(payload)}")
                except Exception:
                    pass
            else:
                self._debug_write(f"_post_response_url: action={action_id} OK (Slack accepted it)")
        except Exception as exc:
            logger.exception(f"[SlackInteractivity] response_url POST failed for action={action_id}")
            self._debug_write(f"_post_response_url: action={action_id} raised {exc!r}")

    def _handle_action(self, action_id, value, team_id, slack_user_id, response_url, trigger_id="", channel_id=""):
        self._debug_write(f"_handle_action: START action={action_id} value={value!r}")
        try:
            parts       = value.split("|")
            fix_vuln_id = parts[0] if len(parts) > 0 else ""
            vuln_id     = parts[1] if len(parts) > 1 else ""
            team_name   = parts[2] if len(parts) > 2 else ""

            slash = SlackSlashCommandView()

            if action_id in ("view_vulns_prev", "view_vulns_next"):
                # value format here is "team_name|offset" (no fix_vuln_id) —
                # re-parse directly rather than reusing the generic `parts`.
                vp = value.split("|")
                page_team_name = vp[0] if len(vp) > 0 else ""
                page_offset = int(vp[1]) if len(vp) > 1 and vp[1].isdigit() else 0
                vulns, _, raw_data = slash._get_team_vulns(page_team_name, team_id, slack_user_id)
                blocks = slash._format_viewassigned(vulns, page_team_name, raw_data, offset=page_offset)
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id.startswith("view_vulndata_pg_"):
                # value format here is just "offset" — admin-channel command,
                # re-fetched with the admin token (not a team member token).
                # Nav rows are prepended so paginating from the All
                # Vulnerabilities tab doesn't wipe out the tab bar — harmless
                # when reached via plain /vulndata too.
                page_offset = int(value) if value.isdigit() else 0
                vd_data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_admin_demo")
                    + slash._allvuln_subnav_block(active_sub="av_sub_list")
                    + slash._format_vulndata_list(vd_data, offset=page_offset)
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            # ── Register tab (new design) filters + pagination ────────────────
            if action_id.startswith("reg_sev_") or action_id.startswith("reg_st_"):
                # value format: "<sev>|<status>|0" — each button has unique action_id
                parts = value.split("|")
                if len(parts) >= 3:
                    sev_filter = parts[0] or "all"
                    st_filter = parts[1] or "all"
                    page_offset = int(parts[2]) if parts[2].isdigit() else 0
                else:
                    sev_filter = "all"
                    st_filter = "all"
                    page_offset = 0
                vd_data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                section = slash._format_register_tab(vd_data, sev_filter=sev_filter, st_filter=st_filter, offset=page_offset)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_register")
                    + slash._register_subnav_block(active_sub="reg_sub_register")
                    + section
                )
                self._post_response_url(
                    response_url,
                    {"replace_original": True, "blocks": blocks},
                    action_id,
                )
                return

            if action_id.startswith("reg_list_pg_"):
                # value format: "<sev>|<status>|<offset>"
                parts = value.split("|")
                if len(parts) >= 3:
                    sev_filter = parts[0] or "all"
                    st_filter = parts[1] or "all"
                    page_offset = int(parts[2]) if parts[2].isdigit() else 0
                else:
                    sev_filter = "all"
                    st_filter = "all"
                    page_offset = 0
                vd_data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                section = slash._format_register_tab(vd_data, sev_filter=sev_filter, st_filter=st_filter, offset=page_offset)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_register")
                    + slash._register_subnav_block(active_sub="reg_sub_register")
                    + section
                )
                self._post_response_url(
                    response_url,
                    {"replace_original": True, "blocks": blocks},
                    action_id,
                )
                return

            if action_id.startswith("script_list_pg_"):
                page_offset = int(value) if value.isdigit() else 0
                data = slash._call_api(
                    "/api/admin/automation-scripts/stats/", team_id, slack_user_id=slack_user_id,
                )
                section = slash._format_script_tab(data if isinstance(data, dict) else {}, offset=page_offset)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_register")
                    + slash._register_subnav_block(active_sub="reg_sub_script")
                    + section
                )
                self._post_response_url(
                    response_url,
                    {"replace_original": True, "blocks": blocks},
                    action_id,
                )
                return

            if action_id.startswith("reg_view_"):
                # value is the short_id (c1/h2/m3/l4...)
                sid = value
                vd_data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                rows = slash._assign_severity_short_ids(vd_data.get("rows") or [])
                target = next((r for r in rows if r.get("short_id") == sid), None)
                if not target:
                    content = slash._text_block(f"❌ Vulnerability `{sid}` not found.")
                else:
                    content = slash._allvuln_detail_blocks(target, "manual", team_id)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_register")
                    + slash._register_subnav_block(active_sub="reg_sub_register")
                    + content
                )
                self._post_response_url(
                    response_url,
                    {"replace_original": True, "blocks": blocks},
                    action_id,
                )
                return

            # ── Support tab filters, pagination, view detail ─────────────────
            if action_id.startswith("sup_st_"):
                parts = value.split("|")
                st_filter = parts[0] if len(parts) > 0 and parts[0] else "all"
                team_filter = parts[1] if len(parts) > 1 and parts[1] else "all"
                page_offset = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                section = slash._support_tab_blocks(
                    team_id, slack_user_id,
                    st_filter=st_filter, team_filter=team_filter, offset=page_offset,
                )
                blocks = slash._nav_buttons_block(active_action_id="nav_support") + section
                self._post_response_url(
                    response_url, {"replace_original": True, "blocks": blocks}, action_id,
                )
                return

            if action_id.startswith("sup_team_"):
                parts = value.split("|")
                st_filter = parts[0] if len(parts) > 0 and parts[0] else "all"
                team_filter = parts[1] if len(parts) > 1 and parts[1] else "all"
                page_offset = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                section = slash._support_tab_blocks(
                    team_id, slack_user_id,
                    st_filter=st_filter, team_filter=team_filter, offset=page_offset,
                )
                blocks = slash._nav_buttons_block(active_action_id="nav_support") + section
                self._post_response_url(
                    response_url, {"replace_original": True, "blocks": blocks}, action_id,
                )
                return

            if action_id.startswith("sup_list_pg_"):
                parts = value.split("|")
                st_filter = parts[0] if len(parts) > 0 and parts[0] else "all"
                team_filter = parts[1] if len(parts) > 1 and parts[1] else "all"
                page_offset = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                section = slash._support_tab_blocks(
                    team_id, slack_user_id,
                    st_filter=st_filter, team_filter=team_filter, offset=page_offset,
                )
                blocks = slash._nav_buttons_block(active_action_id="nav_support") + section
                self._post_response_url(
                    response_url, {"replace_original": True, "blocks": blocks}, action_id,
                )
                return

            if action_id == "sup_back_list":
                parts = value.split("|")
                st_filter = parts[0] if len(parts) > 0 and parts[0] else "all"
                team_filter = parts[1] if len(parts) > 1 and parts[1] else "all"
                page_offset = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
                section = slash._support_tab_blocks(
                    team_id, slack_user_id,
                    st_filter=st_filter, team_filter=team_filter, offset=page_offset,
                )
                blocks = slash._nav_buttons_block(active_action_id="nav_support") + section
                self._post_response_url(
                    response_url, {"replace_original": True, "blocks": blocks}, action_id,
                )
                return

            if action_id.startswith("sup_view_"):
                parts = value.split("|")
                sid = parts[0] if len(parts) > 0 else value
                st_filter = parts[1] if len(parts) > 1 and parts[1] else "all"
                team_filter = parts[2] if len(parts) > 2 and parts[2] else "all"
                page_offset = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                target, _data = slash._lookup_support_by_short_id(sid, team_id, slack_user_id)
                if not target:
                    content = slash._text_block(f"❌ Support request `{sid}` not found.")
                else:
                    content = slash._format_support_detail(
                        target,
                        st_filter=st_filter,
                        team_filter=team_filter,
                        offset=page_offset,
                    )
                blocks = slash._nav_buttons_block(active_action_id="nav_support") + content
                self._post_response_url(
                    response_url, {"replace_original": True, "blocks": blocks}, action_id,
                )
                return

            if action_id in dict(slash._REGISTER_SUBTABS):
                content_blocks = slash._register_subtab_blocks(action_id, team_id, slack_user_id)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_register")
                    + slash._register_subnav_block(active_sub=action_id)
                    + content_blocks
                )
                self._post_response_url(
                    response_url,
                    {"replace_original": True, "blocks": blocks},
                    action_id,
                )
                return

            if action_id == "view_vulndata_steps_page":
                # value format here is "short_id|page" — admin-channel
                # read-only step pager for /vulndata [id], mirrors the text
                # fallback (`/vulndata h1 2`) as a real button.
                vp = value.split("|")
                v_short_id = vp[0] if len(vp) > 0 else ""
                v_page = int(vp[1]) if len(vp) > 1 and vp[1].isdigit() else 1
                vd_data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                rows = slash._assign_severity_short_ids(vd_data.get("rows") or [])
                target = next((r for r in rows if r.get("short_id") == v_short_id), None)
                if not target:
                    blocks = slash._text_block(f"❌ Vulnerability `{v_short_id}` not found. Run `/vulndata` again.")
                else:
                    steps_data = None
                    fix_vuln_id = target.get("fix_vulnerability_id")
                    if fix_vuln_id:
                        steps_data = slash._call_api(
                            f"/api/admin/adminregister/fix-vulnerability/{fix_vuln_id}/step-complete/",
                            team_id, slack_user_id=slack_user_id,
                        )
                    blocks = slash._format_vulndata_single(target, steps_data, offset=(v_page - 1) * 3)
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id in dict(slash._NAV_ITEMS):
                # Admin-dashboard-channel navbar — clicking a tab replaces
                # THIS SAME message with that section's content, nav row
                # rebuilt on top so it stays clickable for further navigation
                # (no need to ever type /dashboard, /vulnstats, etc. again).
                section_blocks = slash._nav_section_blocks(action_id, team_id, slack_user_id)
                blocks = slash._nav_buttons_block(active_action_id=action_id) + section_blocks
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id in ("team_sub_adduser", "team_sub_deleteuser"):
                # These need input, so they open a modal instead of replacing
                # the message. trigger_id is only valid for a few seconds —
                # this thread starts right after Slack's own ack, so it's fine.
                bot_token = slash._get_bot_token(team_id, slack_user_id=slack_user_id)
                if not bot_token or not trigger_id:
                    self._debug_write(f"_handle_action: {action_id} missing bot_token or trigger_id")
                    return
                view = (
                    slash._build_adduser_modal() if action_id == "team_sub_adduser"
                    else slash._build_deleteuser_modal()
                )
                resp = _http_post(
                    "https://slack.com/api/views.open",
                    headers={"Authorization": f"Bearer {bot_token}"},
                    json={"trigger_id": trigger_id, "view": view},
                    timeout=10,
                )
                self._debug_write(f"_handle_action: {action_id} views.open -> {getattr(resp, 'text', None)}")
                return

            if action_id in dict(slash._TEAM_SUBTABS):
                # team_sub_team / team_sub_externaluser — plain content swap,
                # keeping both nav rows (top-level + sub-tabs) on top.
                content_blocks = slash._team_subtab_blocks(action_id, team_id, slack_user_id)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_team")
                    + slash._team_subnav_block(active_sub=action_id)
                    + content_blocks
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id in ("av_approve_row", "av_reject_row"):
                # Timeline Extension row's Approve/Reject click — navigate to
                # that tab's own paginated list, landing on the page that
                # actually contains this specific request.
                ext_data = slash._call_api(
                    "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                    slack_user_id=slack_user_id,
                )
                all_requests = slash._assign_severity_short_ids(ext_data.get("results") or [])
                is_approve = action_id == "av_approve_row"
                # Page offset must be computed against the SAME filtered
                # list the builder below will actually paginate (it drops
                # rejected/approved opposite-status items) — otherwise the
                # jump lands on the wrong page.
                filtered = [r for r in all_requests if r.get("status", "review") != ("rejected" if is_approve else "approved")]
                page_offset = slash._extension_page_for_sid(filtered, value)
                content = (
                    slash._build_approve_list_blocks(all_requests, offset=page_offset) if is_approve
                    else slash._build_reject_list_blocks(all_requests, offset=page_offset)
                )
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_admin_demo")
                    + slash._allvuln_subnav_block(active_sub="av_sub_approve" if is_approve else "av_sub_reject")
                    + content
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id in ("av_approve_list_prev", "av_approve_list_next", "av_reject_list_prev", "av_reject_list_next"):
                page_offset = int(value) if value.isdigit() else 0
                ext_data = slash._call_api(
                    "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                    slack_user_id=slack_user_id,
                )
                all_requests = slash._assign_severity_short_ids(ext_data.get("results") or [])
                is_approve = action_id.startswith("av_approve_list")
                content = (
                    slash._build_approve_list_blocks(all_requests, offset=page_offset) if is_approve
                    else slash._build_reject_list_blocks(all_requests, offset=page_offset)
                )
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_admin_demo")
                    + slash._allvuln_subnav_block(active_sub="av_sub_approve" if is_approve else "av_sub_reject")
                    + content
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id == "av_list_approve_row":
                # Approve needs no extra input — do it immediately and
                # redraw the same Approve-list page.
                parts_v = value.split("|")
                sid = parts_v[0] if parts_v else value
                page_offset = int(parts_v[1]) if len(parts_v) > 1 and parts_v[1].isdigit() else 0
                slash._cmd_approve(sid, team_id, slack_user_id)
                ext_data = slash._call_api(
                    "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                    slack_user_id=slack_user_id,
                )
                all_requests = slash._assign_severity_short_ids(ext_data.get("results") or [])
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_admin_demo")
                    + slash._allvuln_subnav_block(active_sub="av_sub_approve")
                    + slash._build_approve_list_blocks(all_requests, offset=page_offset)
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id == "av_list_reject_row":
                # Reject needs a reason — Slack can't do an inline text input
                # in a message, so this opens a small modal already knowing
                # exactly which request (no dropdown needed).
                parts_v = value.split("|")
                sid = parts_v[0] if parts_v else value
                bot_token = slash._get_bot_token(team_id, slack_user_id=slack_user_id)
                if not bot_token or not trigger_id:
                    self._debug_write(f"_handle_action: {action_id} missing bot_token or trigger_id")
                    return
                ext_data = slash._call_api(
                    "/api/admin/admindashboard/dashboard/mitigation-timeline-extension/report/", team_id,
                    slack_user_id=slack_user_id,
                )
                all_requests = slash._assign_severity_short_ids(ext_data.get("results") or [])
                target = next((r for r in all_requests if r.get("short_id") == sid), None)
                vuln_label = (target.get("vul_name") if target else None) or sid
                view = slash._build_reject_modal(sid, vuln_label)
                resp = _http_post(
                    "https://slack.com/api/views.open",
                    headers={"Authorization": f"Bearer {bot_token}"},
                    json={"trigger_id": trigger_id, "view": view},
                    timeout=10,
                )
                self._debug_write(f"_handle_action: {action_id} views.open -> {getattr(resp, 'text', None)}")
                return

            if (
                action_id in ("view_allvuln_detail", "av_detail_manual", "av_detail_automation")
                or action_id.startswith("view_allvuln_detail_")
            ):
                sid = value
                vd_data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                rows = slash._assign_severity_short_ids(vd_data.get("rows") or [])
                target = next((r for r in rows if r.get("short_id") == sid), None)
                if not target:
                    content = slash._text_block(f"❌ Vulnerability `{sid}` not found. Reopen All Vulnerabilities and try again.")
                else:
                    sub = "automation" if action_id == "av_detail_automation" else "manual"
                    content = slash._allvuln_detail_blocks(target, sub, team_id)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_admin_demo")
                    + slash._allvuln_subnav_block(active_sub="av_sub_details")
                    + content
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id in dict(slash._ALLVULN_SUBTABS):
                # av_sub_list / av_sub_stats / av_sub_details / av_sub_support /
                # av_sub_timeline — plain content swap, keeping both nav rows
                # (top-level + sub-tabs) on top.
                content_blocks = slash._allvuln_subtab_blocks(action_id, team_id, slack_user_id)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_admin_demo")
                    + slash._allvuln_subnav_block(active_sub=action_id)
                    + content_blocks
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id in dict(slash._FIX_SUBTABS):
                # fix_sub_assets / fix_sub_vulns — plain content swap.
                content_blocks = slash._fix_subtab_blocks(action_id, team_id, slack_user_id)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_fix")
                    + slash._fix_subnav_block(active_sub=action_id)
                    + content_blocks
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id == "view_fix_asset" or action_id.startswith("view_fix_asset_vulns_pg_"):
                # value is "host|offset" for both.
                parts_v = value.split("|", 1)
                host = parts_v[0] if parts_v else value
                page_offset = int(parts_v[1]) if len(parts_v) > 1 and parts_v[1].isdigit() else 0
                data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                rows = data.get("rows") or data.get("results") or (data if isinstance(data, list) else [])
                content = slash._format_asset_vulns(rows, host, offset=page_offset)
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_fix")
                    + slash._fix_subnav_block(active_sub="fix_sub_assets")
                    + content
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id == "view_fix_asset_back":
                data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                rows = data.get("rows") or data.get("results") or (data if isinstance(data, list) else [])
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_fix")
                    + slash._fix_subnav_block(active_sub="fix_sub_assets")
                    + slash._format_asset_list(rows)
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id.startswith("view_fix_assets_pg_"):
                page_offset = int(value) if value.isdigit() else 0
                data = slash._call_api(
                    "/api/admin/adminregister/register/latest/vulns/", team_id, slack_user_id=slack_user_id,
                )
                rows = data.get("rows") or data.get("results") or (data if isinstance(data, list) else [])
                blocks = (
                    slash._nav_buttons_block(active_action_id="nav_fix")
                    + slash._fix_subnav_block(active_sub="fix_sub_assets")
                    + slash._format_asset_list(rows, offset=page_offset)
                )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id == "view_more_steps":
                offset = int(parts[3]) if len(parts) > 3 and parts[3].isdigit() else 0
                steps_data = slash._call_user_api(
                    f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id, slack_user_id,
                )
                if steps_data.get("detail"):
                    blocks = slash._text_block(f"❌ `{steps_data.get('detail')}`")
                else:
                    blocks = slash._format_steps_status(steps_data, vuln_id, fix_vuln_id, team_name, offset=offset)
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": blocks,
                }, action_id)
                return

            if action_id == "send_verification":
                resp = slash._call_user_api(
                    f"/api/user/register/fix-vulnerability/{fix_vuln_id}/send-verification/",
                    team_id, slack_user_id, method="post",
                )
                if resp.get("status") not in ("open/review", "closed"):
                    self._post_response_url(response_url, {
                        "response_type": "ephemeral",
                        "text": f"❌ {resp.get('message') or resp.get('detail') or 'Could not send verification.'}",
                    }, action_id)
                    return
                if team_name:
                    slash._notify_admin(
                        team_id, slack_user_id,
                        f"🔁 *Retest Request* — *{team_name}*\n"
                        f"Vulnerability `{vuln_id}` — team requests admin verification/retesting (via button)."
                    )
                self._post_response_url(response_url, {
                    "replace_original": True,
                    "blocks": [
                        {"type": "header", "text": {"type": "plain_text", "text": "🔁 Retest Request Submitted", "emoji": True}},
                        {"type": "section", "text": {"type": "mrkdwn", "text": (
                            f"*Vulnerability ID:* `{vuln_id}`\n\n"
                            "_Verification request recorded in VaptFix. Admin notified — "
                            "they will schedule verification and confirm the fix._"
                        )}},
                    ],
                }, action_id)
                return

            if action_id == "mitigate_all":
                json_body = {"complete_all": True}
                admin_msg = (
                    f"✅ *Mitigation Complete* — *{team_name}*\n"
                    f"Vulnerability `{vuln_id}` — all steps marked complete by team (via button)."
                )
            elif action_id == "mitigate_step":
                json_body = {}
                admin_msg = (
                    f"🔧 *Step Update* — *{team_name}*\n"
                    f"Vulnerability `{vuln_id}` — a step was marked complete by team (via button)."
                )
            else:
                self._post_response_url(response_url, {"response_type": "ephemeral", "text": "❌ Unknown action."}, action_id)
                return

            resp = slash._call_user_api(
                f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/",
                team_id, slack_user_id, method="post", json_body=json_body,
            )

            if not resp.get("message"):
                self._post_response_url(response_url, {
                    "response_type": "ephemeral",
                    "text": f"❌ {resp.get('detail') or 'Could not update step.'}",
                }, action_id)
                return

            if team_name:
                slash._notify_admin(team_id, slack_user_id, admin_msg)

            # Re-fetch fresh step data and redraw the message in place — the
            # progress bar, step statuses, and the next button's label
            # ("Mark Step N+1 Done") all update to reflect what just happened.
            steps_data = slash._call_user_api(
                f"/api/user/register/fix-vulnerability/{fix_vuln_id}/step-complete/", team_id, slack_user_id,
            )
            if steps_data.get("detail"):
                blocks = slash._text_block(f"❌ `{steps_data.get('detail')}`")
            else:
                blocks = slash._format_steps_status(steps_data, vuln_id, fix_vuln_id, team_name)

            self._post_response_url(response_url, {
                "replace_original": True,
                "blocks": blocks,
            }, action_id)

        except Exception as exc:
            logger.exception(f"[SlackInteractivity] {action_id} failed: {exc}")
            self._post_response_url(response_url, {
                "response_type": "ephemeral",
                "text": f"❌ Action failed: {exc}",
            }, action_id)

    def _handle_view_submission(self, payload):
        """
        Handles the Add User / Delete User modal submits — reuses the exact
        same _cmd_adduser/_cmd_deleteuser(_permanent) logic the text commands
        use, then swaps the modal (still open, showing "Processing…") over
        to the result via views.update — matches the design's inline
        success-box, instead of posting a separate channel message.
        """
        view          = payload.get("view") or {}
        callback_id   = view.get("callback_id", "")
        view_id       = view.get("id", "")
        team_id       = (payload.get("team") or {}).get("id", "")
        slack_user_id = (payload.get("user") or {}).get("id", "")
        values        = (view.get("state") or {}).get("values") or {}

        titles = {
            "modal_adduser_submit": "Add User",
            "modal_deleteuser_submit": "Delete User",
            "modal_reject_submit": "Reject Request",
        }
        if callback_id not in titles:
            return

        slash = SlackSlashCommandView()
        title = titles[callback_id]

        try:
            if callback_id == "modal_adduser_submit":
                target_uid = ((values.get("user_block") or {}).get("user_select") or {}).get("selected_user", "")
                user_type = ((values.get("type_block") or {}).get("type_select") or {}).get(
                    "selected_option", {}).get("value", "external")
                selected = ((values.get("team_block") or {}).get("team_checks") or {}).get("selected_options") or []
                team_codes = [o.get("value") for o in selected if o.get("value")]
                if not target_uid or not team_codes:
                    blocks = slash._text_block("❌ User and at least one team are required.")
                else:
                    text = f"<@{target_uid}> {user_type} " + " ".join(team_codes)
                    blocks = slash._cmd_adduser(text, team_id, slack_user_id)
            elif callback_id == "modal_deleteuser_submit":
                target_uid = ((values.get("user_block") or {}).get("user_select") or {}).get("selected_user", "")
                action = ((values.get("action_block") or {}).get("action_select") or {}).get(
                    "selected_option", {}).get("value", "deactivate")
                if not target_uid:
                    blocks = slash._text_block("❌ User is required.")
                elif action == "delete_permanent":
                    blocks = slash._cmd_deleteuser_permanent(f"<@{target_uid}>", team_id, slack_user_id)
                else:
                    blocks = slash._cmd_deleteuser(f"<@{target_uid}>", team_id, slack_user_id)
            else:
                # modal_reject_submit — sid was already known when the modal
                # was opened (from the clicked row), carried via
                # private_metadata since there's no dropdown anymore.
                sid = view.get("private_metadata", "")
                if not sid:
                    blocks = slash._text_block("❌ Missing request id.")
                else:
                    reason = ((values.get("reason_block") or {}).get("reason_input") or {}).get("value") or ""
                    blocks = slash._cmd_reject(f"{sid} {reason}".strip(), team_id, slack_user_id)
        except Exception:
            logger.exception(f"[SlackInteractivity] view_submission {callback_id} failed")
            blocks = slash._text_block("❌ Something went wrong processing this request.")

        bot_token = slash._get_bot_token(team_id, slack_user_id=slack_user_id)
        if not bot_token or not view_id:
            self._debug_write(f"_handle_view_submission: {callback_id} missing bot_token or view_id")
            return
        resp = _http_post(
            "https://slack.com/api/views.update",
            headers={"Authorization": f"Bearer {bot_token}"},
            json={
                # No "hash" here on purpose: the payload's view.hash is for
                # the view as it looked BEFORE our own response_action:
                # "update" swapped it to "Processing…" — reusing it makes
                # Slack reject this call with hash_conflict, which was
                # silently leaving the modal stuck on "Processing…" forever.
                "view_id": view_id,
                "view": slash._build_result_modal(title, blocks),
            },
            timeout=10,
        )
        self._debug_write(f"_handle_view_submission: {callback_id} views.update -> {getattr(resp, 'text', None)}")
