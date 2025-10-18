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
import requests
import secrets
import traceback
import json
from urllib.parse import urljoin
import logging
import uuid
from django.conf import settings
from django.http import HttpResponse, JsonResponse
from urllib.parse import urlencode
class SlackAccessTokenSerializer(serializers.Serializer):
    access_token = serializers.CharField(required=True)
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    ChangePasswordSerializer,
    UserPasswordResetSerializer,
    SendPasswordResetEmailSerializer,
    SetPasswordSerializer,
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

            logger.info(f"User registered successfully: {user.email}")
            response_body = {
                "message": "User registered successfully",
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
class UserLoginView(generics.GenericAPIView):
    serializer_class = UserLoginSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            # This will automatically validate reCAPTCHA through the serializer
            serializer.is_valid(raise_exception=True)

            user = serializer.validated_data["user"]
            login(request, user)

            # Generate JWT tokens
            refresh = RefreshToken.for_user(user)

            logger.info(f"User logged in successfully: {user.email}")

            return Response({
                "message": "Login successful",
                "user": UserProfileSerializer(user).data,
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response({
                "error": "Login failed. Please check your credentials."
            }, status=status.HTTP_400_BAD_REQUEST)


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


class UserProfileUpdateView(generics.UpdateAPIView):
    serializer_class = UserProfileUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]
    renderer_classes = [UserRenderer]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        try:
            partial = kwargs.pop('partial', True)
            instance = self.get_object()
            serializer = self.get_serializer(
                instance,
                data=request.data,
                partial=partial,
                context={"request": request}
            )
            serializer.is_valid(raise_exception=True)
            self.perform_update(serializer)

            # Get updated user data
            updated_user = self.get_object()
            
            return Response({
                "message": "Profile updated successfully",
                "user": UserProfileSerializer(updated_user).data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f"Profile update error: {str(e)}")
            return Response({
                "error": "Failed to update profile"
            }, status=status.HTTP_400_BAD_REQUEST)

    def patch(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)


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

            reset_link = f"https://vapt-frontend-liart.vercel.app/set-password/{uid}/{token}/"

            data = {
                "to_email": user_email,
                "subject": "Reset Your Password",
                "body": f"Click the link to reset your password: {reset_link}"
            }

            if Util.send_mail(data):
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


class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [AllowAny]

    def post(self, request, uid, token, format=None):
        try:
            serializer = UserPasswordResetSerializer(
                data=request.data, 
                context={"uid": uid, "token": token}
            )
            if serializer.is_valid(raise_exception=True):
                return Response(
                    {"msg": "Password reset successfully"}, 
                    status=status.HTTP_200_OK
                )
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return Response(
                {"error": "Password reset failed"}, 
                status=status.HTTP_400_BAD_REQUEST
            )


@api_view(["POST"])
@permission_classes([AllowAny]) 
def logout_view(request):
    return Response({"message": "Logout successful"}, status=200)
    
    
class SetPasswordView(generics.UpdateAPIView):
    serializer_class = SetPasswordSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        user = self.get_object()
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid():
            user.set_password(serializer.validated_data["new_password"])
            user.save()
            return Response({"message": "Password set successfully"}, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
class GoogleOAuthView(generics.GenericAPIView):
    serializer_class = GoogleOAuthSerializer
    permission_classes = [AllowAny]
    renderer_classes = [UserRenderer]

    def post(self, request, *args, **kwargs):
        try:
            serializer = self.get_serializer(data=request.data)
            
            if serializer.is_valid(raise_exception=True):
                # Get Google user data using either access_token or id_token
                access_token = serializer.validated_data.get('access_token')
                id_token = serializer.validated_data.get('id_token')
                google_user_data = serializer.get_google_user_data(
                    access_token=access_token if access_token else None,
                    id_token=id_token if id_token else None,
                )
                
                # Create or get user
                user = serializer.create_or_get_user(google_user_data)
                
                # Login user
                login(request, user)
                
                # Generate JWT tokens
                refresh = RefreshToken.for_user(user)
                
                logger.info(f"Google OAuth login successful: {user.email}")
                
                return Response({
                    "message": "Google login successful",
                    "user": UserProfileSerializer(user).data,
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    # Simplified: backend does not track "is_new_user" here reliably
                    "is_new_user": False
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.error(f"Google OAuth error: {str(e)}")
            return Response({
                "error": "Google authentication failed. Please try again."
            }, status=status.HTTP_400_BAD_REQUEST)
            
import base64
import json

# class MicrosoftTeamsOAuthUrlView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def get(self, request):
#         try:
#             redirect_uri = request.GET.get("redirect_uri")
#             if not redirect_uri:
#                 return Response({"error": "Missing redirect_uri parameter"}, status=400)

#             # ✅ Combine state + redirect_uri into one base64-encoded value
#             state_data = {
#                 "redirect_uri": redirect_uri,
#                 "nonce": secrets.token_urlsafe(8),
#             }
#             state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

#             client_id = settings.MICROSOFT_CLIENT_ID
#             scope = (
#                 "https://graph.microsoft.com/User.Read "
#                 "https://graph.microsoft.com/Group.ReadWrite.All "
#                 "https://graph.microsoft.com/ChannelMessage.Send "
#                 "offline_access openid email profile"
#             )

#             auth_url = (
#                 f"{settings.MICROSOFT_AUTH_URL}?"
#                 f"client_id={client_id}"
#                 f"&response_type=code"
#                 f"&redirect_uri={redirect_uri}"
#                 f"&response_mode=query"
#                 f"&scope={scope}"
#                 f"&state={state}"
#             )

#             return Response({"auth_url": auth_url})
#         except Exception as e:
#             return Response({"error": str(e)}, status=500)


# class MicrosoftTeamsCallbackView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def get(self, request):
#         try:
#             code = request.GET.get("code")
#             state = request.GET.get("state")

#             if not code:
#                 return Response({"error": "Authorization code not provided"}, status=400)

#             if not state:
#                 return Response({"error": "Missing state parameter"}, status=400)

#             # ✅ Decode redirect_uri from state
#             import base64, json
#             try:
#                 state_json = json.loads(base64.urlsafe_b64decode(state + "==").decode())
#                 redirect_uri = state_json.get("redirect_uri")
#             except Exception:
#                 redirect_uri = None

#             if not redirect_uri:
#                 return Response({"error": "Missing redirect_uri in state"}, status=400)

#             # 🔁 Exchange code for token
#             token_url = settings.MICROSOFT_TOKEN_URL
#             data = {
#                 "grant_type": "authorization_code",
#                 "client_id": settings.MICROSOFT_CLIENT_ID,
#                 "client_secret": settings.MICROSOFT_CLIENT_SECRET,
#                 "code": code,
#                 "redirect_uri": redirect_uri,
#             }
#             headers = {"Content-Type": "application/x-www-form-urlencoded"}
#             response = requests.post(token_url, data=data, headers=headers)

#             if response.status_code != 200:
#                 return Response(
#                     {"error": "Token exchange failed", "details": response.json()},
#                     status=response.status_code,
#                 )

#             token_data = response.json()
#             access_token = token_data.get("access_token")

#             user_info = requests.get(
#                 "https://graph.microsoft.com/v1.0/me",
#                 headers={"Authorization": f"Bearer {access_token}"}
#             ).json()

#             return Response({
#                 "message": "Microsoft Teams login successful",
#                 "user_info": user_info,
#                 "token_data": token_data,
#                 "redirect_uri_used": redirect_uri
#             })

#         except Exception as e:
#             return Response({"error": f"Callback failed: {str(e)}"}, status=500)


class MicrosoftTeamsOAuthUrlView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            # ✅ 1. Get frontend redirect URI from query param
            frontend_redirect = request.GET.get("redirect_uri")
            if not frontend_redirect:
                return JsonResponse({"error": "Missing redirect_uri"}, status=400)

            # ✅ 2. Encode redirect_uri + random nonce into state
            state_data = {
                "redirect_uri": frontend_redirect,
                "nonce": secrets.token_urlsafe(8)
            }
            state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

            # ✅ 3. Backend redirect URI — must match Azure registration exactly
            backend_redirect = settings.MICROSOFT_REDIRECT_URI

            # ✅ 4. Define scopes (URL-encoded)
            scope = (
                "https://graph.microsoft.com/User.Read "
                "https://graph.microsoft.com/Group.ReadWrite.All "
                "https://graph.microsoft.com/ChannelMessage.Send "
                "offline_access openid email profile"
            )
            scope = scope.replace(" ", "%20")

            # ✅ 5. Build Microsoft OAuth Authorization URL
            auth_url = (
                f"{settings.MICROSOFT_AUTH_URL}?"
                f"client_id={settings.MICROSOFT_CLIENT_ID}"
                f"&response_type=code"
                f"&redirect_uri={backend_redirect}"
                f"&response_mode=query"
                f"&scope={scope}"
                f"&state={state}"
            )

            # ✅ 6. Log for debugging
            print("🔗 Microsoft Auth URL Generated:")
            print(auth_url)
            print("🧩 Encoded state:", state)

            # ✅ 7. Return both auth URL and state in JSON
            return JsonResponse({
                "auth_url": auth_url,
                "state": state
            })

        except Exception as e:
            print("❌ Error generating Microsoft Auth URL:", str(e))
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
# class MicrosoftTeamsCallbackView(APIView):
#     permission_classes = [AllowAny]

#     def get(self, request):
#         try:
#             code = request.GET.get("code")
#             state = request.GET.get("state")

#             if not code:
#                 return JsonResponse({"error": "Missing code"}, status=400)
#             if not state:
#                 return JsonResponse({"error": "Missing state"}, status=400)

#             # ✅ Decode the frontend redirect from state
#             try:
#                 state_json = json.loads(base64.urlsafe_b64decode(state + "==").decode())
#                 frontend_redirect = state_json.get("redirect_uri")
#             except Exception:
#                 frontend_redirect = None

#             # ✅ Exchange code for token
#             token_data = {
#                 "grant_type": "authorization_code",
#                 "client_id": settings.MICROSOFT_CLIENT_ID,
#                 "client_secret": settings.MICROSOFT_CLIENT_SECRET,
#                 "code": code,
#                 "redirect_uri": settings.MICROSOFT_REDIRECT_URI,  # backend redirect
#             }

#             response = requests.post(
#                 settings.MICROSOFT_TOKEN_URL,
#                 data=token_data,
#                 headers={"Content-Type": "application/x-www-form-urlencoded"}
#             )
#             token_json = response.json()
#             if response.status_code != 200:
#                 return JsonResponse({
#                     "error": "Token exchange failed",
#                     "details": token_json
#                 }, status=response.status_code)

#             access_token = token_json.get("access_token")

#             # ✅ Fetch user info from Microsoft Graph
#             user_info = requests.get(
#                 "https://graph.microsoft.com/v1.0/me",
#                 headers={"Authorization": f"Bearer {access_token}"}
#             ).json()

#             # ✅ Respond to popup (close it automatically)
#             html = f"""
#             <html><body>
#             <script>
#               if (window.opener) {{
#                 window.opener.postMessage({{
#                   type: "teams-login-success",
#                   code: "{code}",
#                   token_data: {json.dumps(token_json)},
#                   user_info: {json.dumps(user_info)}
#                 }}, "{frontend_redirect}");
#                 window.close();
#               }} else {{
#                 document.body.innerHTML = "<h3>Login successful. You can close this window.</h3>";
#               }}
#             </script>
#             </body></html>
#             """
#             return HttpResponse(html)
#         except Exception as e:
#             return JsonResponse({"error": str(e)}, status=500)
        
        
# class MicrosoftTeamsOAuthUrlView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def get(self, request):
#         try:
#             redirect_uri = request.GET.get("redirect_uri")
#             if not redirect_uri:
#                 return Response({"error": "Missing redirect_uri parameter"}, status=400)

#             # ✅ Combine state + redirect_uri into one base64-encoded value
#             state_data = {
#                 "redirect_uri": redirect_uri,
#                 "nonce": secrets.token_urlsafe(8),
#             }
#             state = base64.urlsafe_b64encode(json.dumps(state_data).encode()).decode()

#             client_id = settings.MICROSOFT_CLIENT_ID
#             scope = (
#                 "https://graph.microsoft.com/User.Read "
#                 "https://graph.microsoft.com/Group.ReadWrite.All "
#                 "https://graph.microsoft.com/ChannelMessage.Send "
#                 "offline_access openid email profile"
#             )

#             auth_url = (
#                 f"{settings.MICROSOFT_AUTH_URL}?"
#                 f"client_id={client_id}"
#                 f"&response_type=code"
#                 f"&redirect_uri={redirect_uri}"
#                 f"&response_mode=query"
#                 f"&scope={scope}"
#                 f"&state={state}"
#             )

#             return Response({"auth_url": auth_url})
#         except Exception as e:
#             return Response({"error": str(e)}, status=500)
        
        
# class MicrosoftTeamsCallbackView(APIView):
#     permission_classes = [permissions.AllowAny]

#     def get(self, request):
#         try:
#             code = request.GET.get("code")
#             state = request.GET.get("state")

#             if not code:
#                 return JsonResponse({"error": "Authorization code not provided"}, status=400)
#             if not state:
#                 return JsonResponse({"error": "Missing state parameter"}, status=400)

#             # Decode redirect_uri from state
#             try:
#                 state_json = json.loads(base64.urlsafe_b64decode(state + "==").decode())
#                 redirect_uri = state_json.get("redirect_uri")
#             except Exception:
#                 redirect_uri = None

#             if not redirect_uri:
#                 return JsonResponse({"error": "Missing redirect_uri in state"}, status=400)

#             # Exchange code for access token
#             token_url = settings.MICROSOFT_TOKEN_URL
#             data = {
#                 "grant_type": "authorization_code",
#                 "client_id": settings.MICROSOFT_CLIENT_ID,
#                 "client_secret": settings.MICROSOFT_CLIENT_SECRET,
#                 "code": code,
#                 "redirect_uri": redirect_uri,
#             }
#             headers = {"Content-Type": "application/x-www-form-urlencoded"}
#             response = requests.post(token_url, data=data, headers=headers)
#             if response.status_code != 200:
#                 return JsonResponse({
#                     "error": "Token exchange failed",
#                     "details": response.json()
#                 }, status=response.status_code)

#             token_data = response.json()
#             access_token = token_data.get("access_token")

#             # Fetch Microsoft Graph user info
#             user_info = requests.get(
#                 "https://graph.microsoft.com/v1.0/me",
#                 headers={"Authorization": f"Bearer {access_token}"}
#             ).json()

#             # Determine response type
#             accept_header = request.headers.get("Accept", "")
#             if "application/json" in accept_header:
#                 # Return JSON for Postman/API
#                 return JsonResponse({
#                     "message": "Microsoft Teams login successful",
#                     "user_info": user_info,
#                     "token_data": token_data
#                 })

#             # HTML for browser popup: auto-close + postMessage
#             html = f"""
#             <html>
#               <body>
#                 <script>
#                   if (window.opener) {{
#                     window.opener.postMessage({{
#                       message: "Microsoft Teams login successful",
#                       user_info: {json.dumps(user_info)},
#                       token_data: {json.dumps(token_data)}
#                     }}, "*");
#                     window.close();
#                   }} else {{
#                     document.body.innerHTML = "<p>Login successful. You can close this window.</p>";
#                   }}
#                 </script>
#               </body>
#             </html>
#             """
#             return HttpResponse(html)

#         except Exception as e:
#             return JsonResponse({"error": f"Callback failed: {str(e)}"}, status=500)

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
                
                login(request, user)
                refresh = RefreshToken.for_user(user)
                
                logger.info(f"Microsoft Teams OAuth login successful: {user.email}")
                
                return Response({
                    "message": "Microsoft Teams login successful",
                    "user": UserProfileSerializer(user).data,
                    "tokens": {
                        "refresh": str(refresh),
                        "access": str(refresh.access_token),
                    },
                    "access_token":str(access_token),
                    "is_new_user": False
                }, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.error(f"Microsoft Teams OAuth error: {str(e)}")
            return Response({
                "error": "Microsoft Teams authentication failed. Please try again."
            }, status=status.HTTP_400_BAD_REQUEST)

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
                        import re
                        match = re.search(r"teams\('([^']+)'\)", team_location)
                        if match:
                            team_id = match.group(1)
                    
                    return Response({
                        "message": "Team created successfully",
                        "status": "completed",
                        "team": {
                            "id": team_id,
                            "displayName": team_name,
                            "description": description,
                            "visibility": visibility,
                            "location": team_location
                        }
                    }, status=status.HTTP_201_CREATED)
                    
                elif response.status_code == 202:
                    # Team creation is being processed asynchronously
                    team_location = response.headers.get('Location')
                    
                    # Extract team ID from location header for 202 responses
                    team_id = None
                    if team_location:
                        import re
                        # Pattern for location like: /teams('team-id')/operations('operation-id')
                        team_match = re.search(r"teams\('([^']+)'\)", team_location)
                        if team_match:
                            team_id = team_match.group(1)
                    
                    return Response({
                        "message": "Team creation initiated. Processing may take a few minutes.",
                        "status": "processing",
                        "team_id": team_id,
                        "location": team_location,
                        "note": "You can check the status using the location URL"
                    }, status=status.HTTP_202_ACCEPTED)
                    
                elif response.status_code == 200:
                    # Sometimes Microsoft Graph returns 200 for successful operations
                    try:
                        response_data = response.json()
                        team_id = response_data.get('id')
                        
                        return Response({
                            "message": "Team created successfully",
                            "status": "completed",
                            "team": {
                                "id": team_id,
                                "displayName": team_name,
                                "description": description,
                                "visibility": visibility,
                                "data": response_data
                            }
                        }, status=status.HTTP_201_CREATED)
                    except:
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
     
          
class SlackOAuthUrlView(APIView):
    """
    Dynamically generates Slack OAuth authorization URL for both local (ngrok) and production.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = SlackOAuthUrlSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        base_url = serializer.validated_data.get("base_url")
        state = serializer.validated_data.get("state") or str(uuid.uuid4())

        # ✅ Auto-detect ngrok public URL if base_url not provided
        if not base_url:
            try:
                ngrok_resp = requests.get("http://127.0.0.1:4040/api/tunnels").json()
                https_tunnel = next(
                    (t for t in ngrok_resp.get("tunnels", []) if t["public_url"].startswith("https://")),
                    None
                )
                if https_tunnel:
                    base_url = https_tunnel["public_url"]
                else:
                    base_url = request.build_absolute_uri("/").rstrip("/")
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
    Exchanges code for token and returns both bot + user info cleanly.
    Also saves Slack user in database (no model change).
    """
    permission_classes = [AllowAny]

    def get(self, request):
        serializer = SlackCallbackSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        code = serializer.validated_data.get("code")
        state = serializer.validated_data.get("state", "")

        try:
            # ✅ Auto-detect base URL (for ngrok / local / production)
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

            # ✅ Exchange code for token
            token_url = "https://slack.com/api/oauth.v2.access"
            token_data = {
                "client_id": settings.SLACK_CLIENT_ID,
                "client_secret": settings.SLACK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            }

            token_response = requests.post(token_url, data=token_data)
            token_json = token_response.json()

            # ❌ Handle failure
            if not token_json.get("ok"):
                logger.error(f"Slack OAuth token exchange failed: {token_json}")
                return Response(
                    {"success": False, "error": token_json.get("error", "OAuth failed")},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # ✅ Extract tokens & info
            bot_access_token = token_json.get("access_token")
            bot_refresh_token = token_json.get("refresh_token")
            team_info = token_json.get("team", {})
            authed_user = token_json.get("authed_user", {})

            # ✅ Fetch Slack user info
            user_info_response = requests.get(
                "https://slack.com/api/users.info",
                params={"user": authed_user.get("id")},
                headers={"Authorization": f"Bearer {bot_access_token}"}
            )
            user_info_json = user_info_response.json()
            user_data = user_info_json.get("user", {}) if user_info_json.get("ok") else {}

            # ✅ Extract local user info
            email = user_data.get("profile", {}).get("email")
            name = user_data.get("real_name") or user_data.get("name") or "Slack User"
            firstname = name.split()[0]
            lastname = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

            # ✅ Create or update local user (no model modification)
            user, created = User.objects.get_or_create(
                email=email,
                defaults={
                    "firstname": firstname,
                    "lastname": lastname,
                    "password": ""  # OAuth user - no password needed
                }
            )

            # ✅ (Optional) Log for debugging
            logger.info(f"Slack user {'created' if created else 'found'}: {email}")

            # ✅ Return the SAME response structure you asked for
            response_data = {
                "success": True,
                "message": "Slack Login successful",
                "data": {
                    "team": {
                        "id": team_info.get("id"),
                        "name": team_info.get("name"),
                    },
                    "bot": {
                        "access_token": bot_access_token,
                        "refresh_token": bot_refresh_token,
                        "expires_in": token_json.get("expires_in"),
                        "bot_user_id": token_json.get("bot_user_id"),
                    },
                    "authed_user": {
                        "id": authed_user.get("id"),
                        "access_token": authed_user.get("access_token"),
                        "refresh_token": authed_user.get("refresh_token"),
                        "expires_in": authed_user.get("expires_in"),
                        "email": user_data.get("profile", {}).get("email"),
                        "name": user_data.get("name"),
                    },
                    "local_user": {  # ✅ Added for clarity
                        "id": user.id,
                        "email": user.email,
                        "firstname": user.firstname,
                        "lastname": user.lastname,
                        "created": created,
                    },
                    "state": state,
                },
            }

            return Response(response_data, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Slack OAuth callback exception: {str(e)}")
            return Response(
                {"success": False, "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
            

class SlackOAuthCallbackView(APIView):
    """
    Handles Slack OAuth callback (GET).
    Exchanges code for tokens, saves Slack user in DB,
    and returns a small HTML that closes the popup window
    and notifies the main frontend (via window.postMessage).
    """
    permission_classes = [AllowAny]

    def get(self, request):
        try:
            code = request.GET.get("code")
            state = request.GET.get("state", "")

            # ✅ Auto-detect base URL (ngrok / production safe)
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

            # ✅ Step 1: Exchange code for access tokens
            token_url = "https://slack.com/api/oauth.v2.access"
            token_data = {
                "client_id": settings.SLACK_CLIENT_ID,
                "client_secret": settings.SLACK_CLIENT_SECRET,
                "code": code,
                "redirect_uri": redirect_uri,
            }

            token_res = requests.post(token_url, data=token_data)
            token_json = token_res.json()

            if not token_json.get("ok"):
                error = token_json.get("error", "OAuth failed")
                logger.error(f"Slack OAuth error: {error}")
                return self._html_response(success=False, error=error)

            # ✅ Step 2: Extract Slack tokens
            bot_token = token_json.get("access_token")
            team_info = token_json.get("team", {})
            authed_user = token_json.get("authed_user", {})

            # ✅ Step 3: Fetch user profile from Slack
            user_info = requests.get(
                "https://slack.com/api/users.info",
                params={"user": authed_user.get("id")},
                headers={"Authorization": f"Bearer {bot_token}"},
            ).json()

            user_data = user_info.get("user", {}) if user_info.get("ok") else {}
            email = user_data.get("profile", {}).get("email")
            name = user_data.get("real_name") or user_data.get("name") or "Slack User"
            firstname = name.split()[0]
            lastname = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

            # ✅ Step 4: Create or update local user (no model change)
            user, created = User.objects.get_or_create(
                email=email,
                defaults={"firstname": firstname, "lastname": lastname, "password": ""},
            )

            # ✅ Step 5: Prepare data to send to frontend
            data = {
                "success": True,
                "message": "Slack login successful",
                "user_email": email,
                "user_name": name,
                "team": team_info.get("name"),
                "team_id": team_info.get("id"),
                "bot_access_token": bot_token,
                "user_access_token": authed_user.get("access_token"),
            }

            # ✅ Step 6: Return HTML to close popup and send data
            return self._html_response(success=True, data=data)

        except Exception as e:
            logger.exception("Slack OAuth callback exception")
            return self._html_response(success=False, error=str(e))

    def _html_response(self, success=True, data=None, error=None):
        """
        Returns a small HTML that:
          - Sends result to the main window via postMessage
          - Closes the popup automatically
        """
        payload = {"success": success}
        if success:
            payload.update(data or {})
        else:
            payload.update({"error": error})

        html = f"""
        <html>
        <head>
            <title>Slack OAuth</title>
            <script>
                (function() {{
                    var payload = {json.dumps(payload)};
                    console.log("Slack OAuth finished:", payload);
                    if (window.opener) {{
                        window.opener.postMessage({{
                            type: "slack-auth-complete",
                            payload: payload
                        }}, "*");
                    }}
                    window.close();
                }})();
            </script>
        </head>
        <body style="background: #fff; font-family: sans-serif; text-align:center; padding-top:40px;">
            <h2>Slack login successful 🎉</h2>
            <p>You can close this window.</p>
        </body>
        </html>
        """
        return HttpResponse(html)
      
  
            
class SlackLoginView(APIView):
    """
    Slack Login API
    Takes bot_access_token and user_access_token from callback response,
    fetches Slack user info, and saves user to database.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        # ✅ Validate incoming tokens
        serializer = SlackLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        bot_token = serializer.validated_data["bot_access_token"]
        user_token = serializer.validated_data["user_access_token"]

        # ✅ Step 1: Get Slack user info
        user_info_response = requests.get(
            "https://slack.com/api/users.identity",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        user_info = user_info_response.json()

        if not user_info.get("ok"):
            return Response(
                {"success": False, "error": user_info.get("error", "Unable to fetch Slack user info")},
                status=status.HTTP_400_BAD_REQUEST
            )

        # ✅ Step 2: Extract Slack user data
        user_data = user_info.get("user", {})
        team_data = user_info.get("team", {})

        email = user_data.get("email")
        name = user_data.get("name") or "Slack User"
        firstname = name.split()[0]
        lastname = " ".join(name.split()[1:]) if len(name.split()) > 1 else ""

        # ✅ Step 3: Create or update local user (no model change)
        user, created = User.objects.get_or_create(
            email=email,
            defaults={
                "firstname": firstname,
                "lastname": lastname,
                "password": ""
            }
        )

        # ✅ Step 4: Optionally store Slack tokens (if SlackAuth model exists)
        try:
            SlackAuth = apps.get_model("users", "SlackAuth")
            SlackAuth.objects.create(
                user=user,
                bot_token=bot_token,
                user_token=user_token,
                team_id=team_data.get("id"),
                team_name=team_data.get("name"),
            )
        except LookupError:
            pass  # skip if SlackAuth model not present

        # ✅ Step 5: Return clean response
        return Response({
            "success": True,
            "message": "Slack user login successful",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": f"{user.firstname} {user.lastname}"
            },
            "team": team_data,
            "tokens": {
                "bot_access_token": bot_token,
                "user_access_token": user_token
            }
        }, status=status.HTTP_200_OK)
        
                        
          
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
            

class SlackLoginView(APIView):
    """
    Slack Login API
    Logs in the user using bot and user access tokens.
    Fetches all Slack user info and stores user locally.
    """
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = SlackLoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(
                {"success": False, "errors": serializer.errors},
                status=status.HTTP_400_BAD_REQUEST,
            )

        validated_data = serializer.validated_data
        user, created = serializer.create_or_update_user(validated_data)

        profile = validated_data["user_info"].get("user", {}).get("profile", {})
        team = validated_data["team_info"].get("team", {})

        response_data = {
            "success": True,
            "message": "Slack user login successful",
            "bot_data": {
                "ok": validated_data["bot_auth"].get("ok"),
                "bot_user_id": validated_data["bot_auth"].get("user_id"),
                "team_id": validated_data["bot_auth"].get("team_id"),
                "team": validated_data["bot_auth"].get("team"),
            },
            "user_data": {
                "ok": validated_data["user_auth"].get("ok"),
                "user_id": validated_data["user_auth"].get("user_id"),
                "team_id": validated_data["user_auth"].get("team_id"),
                "user_name": validated_data.get("name"),
                "email": validated_data.get("email"),
                "image_512": profile.get("image_512"),
                "title": profile.get("title"),
                "phone": profile.get("phone"),
            },
            "team_info": {
                "ok": validated_data["team_info"].get("ok"),
                "team": team,
            },
            "local_user": {
                "id": user.id,
                "email": user.email,
                "name": user.first_name,
                "created": created,
            },
        }

        return Response(response_data, status=status.HTTP_200_OK)
    
    
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
                    'jira_access_token': tokens['access_token'],
                    'jira_refresh_token': tokens.get('refresh_token', '')
                }
            )

            if not created:
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

