# from .renderers import UserRenderer
# from rest_framework import status, generics, permissions
# from rest_framework.response import Response
# from rest_framework.decorators import api_view, permission_classes
# from rest_framework.permissions import AllowAny, IsAuthenticated
# from rest_framework_simplejwt.tokens import RefreshToken
# from rest_framework.views import APIView
# from django.contrib.auth import login
# from .models import User
# from .serializers import (
#     UserRegistrationSerializer,
#     UserLoginSerializer,
#     UserProfileSerializer,
#     UserProfileUpdateSerializer,
#     ChangePasswordSerializer,
#     UserPasswordResetSerializer,
#     SendPasswordResetEmailSerializer,
# )
# from .renderers import UserRenderer
# import logging
# from django.utils.decorators import method_decorator
# from django.views.decorators.csrf import csrf_exempt
# logger = logging.getLogger(__name__)
# from rest_framework import generics, status
# # from .utils import Util

# @method_decorator(csrf_exempt, name='dispatch')
# class UserRegistrationView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = UserRegistrationSerializer
#     permission_classes = [AllowAny]
#     renderer_classes = [UserRenderer]

#     def create(self, request, *args, **kwargs):
#         try:
#             serializer = self.get_serializer(data=request.data)
#             serializer.is_valid(raise_exception=True)
#             user = serializer.save()

#             # Generate JWT tokens
#             refresh = RefreshToken.for_user(user)

#             return Response({
#                 "message": "User registered successfully",
#                 "user": UserProfileSerializer(user).data,
#                 "tokens": {
#                     "refresh": str(refresh),
#                     "access": str(refresh.access_token),
#                 }
#             }, status=status.HTTP_201_CREATED)
#         except Exception as e:
#             logger.error(f"Registration error: {str(e)}")
#             return Response({
#                 "error": "Registration failed. Please try again."
#             }, status=status.HTTP_400_BAD_REQUEST)


# class UserLoginView(generics.GenericAPIView):
#     serializer_class = UserLoginSerializer
#     permission_classes = [AllowAny]
#     renderer_classes = [UserRenderer]

#     def post(self, request, *args, **kwargs):
#         try:
#             serializer = self.get_serializer(data=request.data)
#             serializer.is_valid(raise_exception=True)

#             user = serializer.validated_data["user"]
#             login(request, user)

#             # Generate JWT tokens
#             refresh = RefreshToken.for_user(user)

#             return Response({
#                 "message": "Login successful",
#                 "user": UserProfileSerializer(user).data,
#                 "tokens": {
#                     "refresh": str(refresh),
#                     "access": str(refresh.access_token),
#                 }
#             }, status=status.HTTP_200_OK)
#         except Exception as e:
#             logger.error(f"Login error: {str(e)}")
#             return Response({
#                 "error": "Login failed. Please check your credentials."
#             }, status=status.HTTP_400_BAD_REQUEST)




# class UserProfileView(generics.RetrieveAPIView):
#     serializer_class = UserProfileSerializer
#     permission_classes = [permissions.IsAuthenticated]
#     renderer_classes = [UserRenderer]

#     def get_object(self):
#         return self.request.user

#     def retrieve(self, request, *args, **kwargs):
#         try:
#             instance = self.get_object()
#             serializer = self.get_serializer(instance)
#             return Response({
#                 "message": "Profile retrieved successfully",
#                 "user": serializer.data
#             }, status=status.HTTP_200_OK)
#         except Exception as e:
#             logger.error(f"Profile retrieval error: {str(e)}")
#             return Response({
#                 "error": "Failed to retrieve profile"
#             }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


# class ChangePasswordView(generics.UpdateAPIView):
#     serializer_class = ChangePasswordSerializer
#     permission_classes = [IsAuthenticated]
#     renderer_classes = [UserRenderer]

#     def get_object(self):
#         return self.request.user

#     def update(self, request, *args, **kwargs):
#         try:
#             user = self.get_object()
#             serializer = self.get_serializer(data=request.data, context={"request": request})

#             if serializer.is_valid():
#                 # Set the new password
#                 user.set_password(serializer.validated_data["new_password"])
#                 user.save()

#                 return Response({
#                     "message": "Password changed successfully"
#                 }, status=status.HTTP_200_OK)

#             return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
#         except Exception as e:
#             logger.error(f"Password change error: {str(e)}")
#             return Response({
#                 "error": "Failed to change password"
#             }, status=status.HTTP_400_BAD_REQUEST)


# @method_decorator(csrf_exempt, name="dispatch")
# class SendPasswordResetEmailView(generics.GenericAPIView):
#     serializer_class = SendPasswordResetEmailSerializer
#     permission_classes = [AllowAny]
#     authentication_classes = []
#     renderer_classes = [UserRenderer]

#     def post(self, request, *args, **kwargs):
#         try:
#             serializer = self.get_serializer(data=request.data)
#             serializer.is_valid(raise_exception=True)

#             user_email = serializer.validated_data["email"]

#             # Build reset link with uid + token
#             from django.utils.http import urlsafe_base64_encode
#             from django.utils.encoding import force_bytes
#             from django.contrib.auth.tokens import PasswordResetTokenGenerator
#             from django.contrib.auth import get_user_model

#             User = get_user_model()
#             user = User.objects.get(email=user_email)
#             uid = urlsafe_base64_encode(force_bytes(user.pk))  # This will use the UUID id
#             token = PasswordResetTokenGenerator().make_token(user)

#             reset_link = f"https://vapt-frontend-zeta.vercel.app/reset-password/{uid}/{token}/"

#             data = {
#                 "to_email": user_email,
#                 "subject": "Reset Your Password",
#                 "body": f"Click the link to reset your password: {reset_link}"
#             }

#             if Util.send_mail(data):
#                 return Response(
#                     {"msg": "Password reset link sent. Please check your email."},
#                     status=status.HTTP_200_OK
#                 )
#             return Response(
#                 {"error": "Failed to send email"}, 
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )
#         except User.DoesNotExist:
#             return Response(
#                 {"error": "User with this email does not exist"},
#                 status=status.HTTP_404_NOT_FOUND
#             )
#         except Exception as e:
#             logger.error(f"Password reset email error: {str(e)}")
#             return Response(
#                 {"error": "Failed to send password reset email"}, 
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


# class UserPasswordResetView(APIView):
#     renderer_classes = [UserRenderer]
#     permission_classes = [AllowAny]

#     def post(self, request, uid, token, format=None):
#         try:
#             serializer = UserPasswordResetSerializer(
#                 data=request.data, 
#                 context={"uid": uid, "token": token}
#             )
#             if serializer.is_valid(raise_exception=True):
#                 return Response(
#                     {"msg": "Password reset successfully"}, 
#                     status=status.HTTP_200_OK
#                 )
#         except Exception as e:
#             logger.error(f"Password reset error: {str(e)}")
#             return Response(
#                 {"error": "Password reset failed"}, 
#                 status=status.HTTP_400_BAD_REQUEST
#             )


# @api_view(["POST"])
# @permission_classes([AllowAny])  # you can also use IsAuthenticated
# def logout_view(request):
#     refresh_token = request.data.get("refresh")
#     if not refresh_token:
#         return Response({"error": "Refresh token is required"}, status=400)
#     try:
#         token = RefreshToken(refresh_token)
#         token.blacklist()
#         return Response({"message": "Logout successful"}, status=200)
#     except Exception as e:
#         return Response({"error": f"Invalid or expired token: {str(e)}"}, status=400)



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
from .serializers import (
    UserRegistrationSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    UserProfileUpdateSerializer,
    ChangePasswordSerializer,
    UserPasswordResetSerializer,
    SendPasswordResetEmailSerializer,
    SetPasswordSerializer,
)
from .renderers import UserRenderer
import logging
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
logger = logging.getLogger(__name__)
from rest_framework import generics, status
from .utils import Util

# @method_decorator(csrf_exempt, name='dispatch')
# class UserRegistrationView(generics.CreateAPIView):
#     queryset = User.objects.all()
#     serializer_class = UserRegistrationSerializer
#     permission_classes = [AllowAny]
#     renderer_classes = [UserRenderer]

#     def create(self, request, *args, **kwargs):
#         try:
#             serializer = self.get_serializer(data=request.data)
            
#             # This will automatically validate reCAPTCHA through the serializer
#             serializer.is_valid(raise_exception=True)
#             user = serializer.save()

#             # Generate JWT tokens
#             refresh = RefreshToken.for_user(user)

#             logger.info(f"User registered successfully: {user.email}")
            
#             return Response({
#                 "message": "User registered successfully",
#                 "user": UserProfileSerializer(user).data,
#                 "tokens": {
#                     "refresh": str(refresh),
#                     "access": str(refresh.access_token),
#                 }
#             }, status=status.HTTP_201_CREATED)
            
#         except Exception as e:
#             logger.error(f"Registration error: {serializer.errors if 'serializer' in locals() and hasattr(serializer, 'errors') else str(e)}")
#             return Response({
#                 "error": "Registration failed. Please try again."
#             }, status=status.HTTP_400_BAD_REQUEST)

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

            reset_link = f"https://vapt-frontend-zeta.vercel.app/reset-password/{uid}/{token}/"

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
@permission_classes([AllowAny])  # you can also use IsAuthenticated
def logout_view(request):
    # With blacklist disabled, we cannot invalidate tokens server-side.
    # Treat logout as a client-side token discard.
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
