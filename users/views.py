from django.forms import ValidationError
from .renderers import UserRenderer
from rest_framework import status, generics, permissions
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.views import APIView
from django.contrib.auth import login
from .models import User
import requests
import json
import logging
from django.conf import settings
from django.http import JsonResponse
from urllib.parse import urlencode
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
    SlackOAuthSerializer,
    UpdateSlackChannelSerializer,
    DeleteSlackChannelSerializer,
    AddUserToSlackChannelSerializer,
    SlackInviteUserSerializer,
)
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


class SlackOAuthLoginView(generics.GenericAPIView):
    serializer_class = SlackOAuthSerializer
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if serializer.is_valid(raise_exception=True):
            code = serializer.validated_data["code"]
            redirect_uri = serializer.validated_data["redirect_uri"]

            slack_user_data = serializer.get_slack_user_data(code, redirect_uri)
            user = serializer.create_or_get_user(slack_user_data)

            login(request, user)
            refresh = RefreshToken.for_user(user)

            return Response({
                "message": "Slack login successful",
                "user": UserProfileSerializer(user).data,
                "tokens": {
                    "refresh": str(refresh),
                    "access": str(refresh.access_token),
                },
                "slack_access_token": slack_user_data["access_token"],
                "is_new_user": user.last_login is None
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)            
class SlackOAuthUrlView(APIView):
    """Return the Slack OAuth authorization URL"""
    permission_classes = []

    def get(self, request):
        redirect_uri = request.query_params.get(
            'redirect_uri', 'http://localhost:3000/slack/callback'
        )
        client_id = settings.SLACK_CLIENT_ID

        slack_url = (
            f"https://slack.com/oauth/v2/authorize?"
            f"client_id={client_id}"
            f"&scope=chat:write,channels:manage,channels:join,mpim:write,groups:write,im:write,users:read,users:read.email"
            f"&user_scope=identity.basic,identity.email,identity.avatar,identity.team"
            f"&redirect_uri={redirect_uri}"
        )
        return Response({
            "success": True,
            "auth_url": slack_url
        }, status=status.HTTP_200_OK)
                  
class SlackOAuthView(APIView):
    """Handle Slack OAuth authentication"""
    permission_classes = []
    
    def post(self, request):
        try:
            auth_code = request.data.get('code')
            redirect_uri = request.data.get('redirect_uri', 'http://localhost:3000/slack/callback')
            
            if not auth_code:
                return Response({
                    'success': False,
                    'message': 'Authorization code is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Exchange code for access token
            token_url = 'https://slack.com/api/oauth.v2.access'
            token_data = {
                'client_id': settings.SLACK_CLIENT_ID,
                'client_secret': settings.SLACK_CLIENT_SECRET,
                'code': auth_code,
                'redirect_uri': redirect_uri
            }
            
            token_response = requests.post(token_url, data=token_data)
            token_result = token_response.json()
            
            if not token_result.get('ok'):
                logger.error(f"Slack OAuth error: {token_result}")
                return Response({
                    'success': False,
                    'message': f"Slack OAuth failed: {token_result.get('error', 'Unknown error')}"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = token_result.get('access_token')
            team_info = token_result.get('team', {})
            authed_user = token_result.get('authed_user', {})
            
            # Get user info from Slack
            user_info_url = 'https://slack.com/api/users.identity'
            headers = {'Authorization': f'Bearer {access_token}'}
            user_response = requests.get(user_info_url, headers=headers)
            user_data = user_response.json()
            
            if not user_data.get('ok'):
                logger.error(f"Failed to get Slack user info: {user_data}")
                return Response({
                    'success': False,
                    'message': 'Failed to retrieve user information from Slack'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Store Slack tokens in user model or session
            if request.user.is_authenticated:
                # Update existing user's Slack info
                request.user.slack_access_token = access_token
                request.user.slack_team_id = team_info.get('id')
                request.user.slack_team_name = team_info.get('name')
                request.user.slack_user_id = authed_user.get('id')
                request.user.save()
            
            return Response({
                'success': True,
                'message': 'Slack authentication successful',
                'data': {
                    'access_token': access_token,
                    'team_name': team_info.get('name'),
                    'team_id': team_info.get('id'),
                    'user_id': authed_user.get('id'),
                    'user_info': user_data.get('user', {})
                }
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Slack OAuth error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred during Slack authentication: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SlackUserLoginView(APIView):
    """
    Slack user login that returns bot access token and user info.
    Handles both bot token and user identity token to fetch email and profile.
    """
    permission_classes = []

    def post(self, request):
        try:
            auth_code = request.data.get('code')
            redirect_uri = request.data.get('redirect_uri', 'http://localhost:3000/slack/callback')

            if not auth_code:
                return Response({
                    'success': False,
                    'message': 'Authorization code is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Exchange code for access tokens
            token_url = 'https://slack.com/api/oauth.v2.access'
            token_data = {
                'client_id': settings.SLACK_CLIENT_ID,
                'client_secret': settings.SLACK_CLIENT_SECRET,
                'code': auth_code,
                'redirect_uri': redirect_uri
            }

            token_response = requests.post(token_url, data=token_data)
            token_result = token_response.json()

            if not token_result.get('ok'):
                logger.error(f"Slack OAuth error: {token_result}")
                return Response({
                    'success': False,
                    'message': f"Slack OAuth failed: {token_result.get('error', 'Unknown error')}"
                }, status=status.HTTP_400_BAD_REQUEST)

            # Bot token for API actions
            bot_access_token = token_result.get('access_token')
            bot_user_id = token_result.get('bot_user_id', '')
            team_info = token_result.get('team', {})

            # User token for identity info
            authed_user = token_result.get('authed_user', {})
            user_token = authed_user.get('access_token')
            user_profile = {}

            if user_token:
                user_info_response = requests.get(
                    'https://slack.com/api/users.identity',
                    headers={'Authorization': f'Bearer {user_token}'}
                )
                user_info_data = user_info_response.json()
                if user_info_data.get('ok'):
                    user = user_info_data.get('user', {})
                    user_profile = {
                        'id': user.get('id'),
                        'name': user.get('name'),
                        'display_name': user.get('name'),
                        'email': user.get('email', ''),
                        'image': user.get('image_192', '')
                    }
                else:
                    logger.warning(f"Could not get user identity info: {user_info_data.get('error')}")

            return Response({
                'success': True,
                'message': 'Slack login successful',
                'data': {
                    'bot_access_token': bot_access_token,
                    'bot_user_id': bot_user_id,
                    'team': {
                        'id': team_info.get('id'),
                        'name': team_info.get('name')
                    },
                    'user_access_token': user_token,
                    'user': user_profile
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Slack login error: {str(e)}")
            return Response({
                'success': False,
                'message': f'An error occurred during Slack login: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
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
class SlackOAuthCallbackView(APIView):
    """Handle Slack OAuth redirect (GET) directly on backend"""
    permission_classes = []

    def get(self, request):
        try:
            # Slack sends `code` and `state` as query params
            auth_code = request.query_params.get('code')
            if not auth_code:
                return Response({'success': False, 'message': 'Missing authorization code'}, status=status.HTTP_400_BAD_REQUEST)

            # Use the exact callback base URL (no query string) used during authorization
            redirect_uri = request.build_absolute_uri(request.path)

            token_url = 'https://slack.com/api/oauth.v2.access'
            token_data = {
                'client_id': settings.SLACK_CLIENT_ID,
                'client_secret': settings.SLACK_CLIENT_SECRET,
                'code': auth_code,
                'redirect_uri': redirect_uri
            }

            token_result = requests.post(token_url, data=token_data).json()
            if not token_result.get('ok'):
                logger.error(f"Slack OAuth error: {token_result}")
                return Response({'success': False, 'message': token_result.get('error', 'OAuth failed')}, status=status.HTTP_400_BAD_REQUEST)

            access_token = token_result.get('access_token')
            team_info = token_result.get('team', {})
            authed_user = token_result.get('authed_user', {})

            # Fetch user identity
            user_info = requests.get(
                'https://slack.com/api/users.identity',
                headers={'Authorization': f'Bearer {access_token}'}
            ).json()
            if not user_info.get('ok'):
                logger.error(f"Failed to get Slack user info: {user_info}")
                return Response({'success': False, 'message': 'Failed to retrieve user info from Slack'}, status=status.HTTP_400_BAD_REQUEST)

            # Optionally persist tokens to authenticated user
            if request.user.is_authenticated:
                request.user.slack_access_token = access_token
                request.user.slack_team_id = team_info.get('id')
                request.user.slack_team_name = team_info.get('name')
                request.user.slack_user_id = authed_user.get('id')
                request.user.save()

            return Response({
                'success': True,
                'message': 'Slack authentication successful',
                'data': {
                    'access_token': access_token,
                    'team_name': team_info.get('name'),
                    'team_id': team_info.get('id'),
                    'user_id': authed_user.get('id'),
                    'user_info': user_info.get('user', {})
                }
            }, status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f"Slack OAuth callback error: {str(e)}")
            return Response({'success': False, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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