from rest_framework import generics, permissions, status,filters
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from bson import ObjectId
from django.shortcuts import get_object_or_404
from .models import UserDetail
from .serializers import UserDetailSerializer, UserDetailCreateSerializer,UserDetailUpdateSerializer,UserDetailRoleUpdateSerializer
from django.utils import timezone
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from django.conf import settings
import logging

logger = logging.getLogger('users_details')
User = get_user_model()
class UserDetailCreateView(generics.CreateAPIView):
    serializer_class = UserDetailCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def send_welcome_email(self, email, first_name, last_name, roles):
        """Enhanced SendGrid Email Sending with Better Error Handling"""
        
        # Validate inputs
        if not email or not isinstance(email, str):
            return False, "Invalid email address"
        
        if not settings.SENDGRID_API_KEY:
            logger.error("SENDGRID_API_KEY is not configured")
            return False, "SendGrid API key not configured"
        
        subject = "Your Account Has Been Created"
        full_name = f"{first_name} {last_name}".strip() or "User"
        
        # Format roles properly
        roles_str = ', '.join(roles) if isinstance(roles, list) else str(roles)
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
                <h2 style="color: #2c3e50;">Welcome {full_name}!</h2>
                <p>Your account has been created successfully in our VAPTFIX.</p>
                
                <div style="background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0;">
                    <p style="margin: 10px 0;"><strong>Assigned Roles:</strong> {roles_str}</p>
                </div>
                
                <p>You can now access the system and perform tasks according to your assigned roles.</p>
                
                <p style="margin-top: 30px;">
                    Best regards,<br>
                    <strong>Security Management Team</strong>
                </p>
            </div>
        </body>
        </html>
        """
        
        try:
            # Create the email message
            message = Mail(
                from_email=settings.DEFAULT_FROM_EMAIL,
                to_emails=email,
                subject=subject,
                html_content=html_content
            )
            
            # Initialize SendGrid client
            sg = SendGridAPIClient(settings.SENDGRID_API_KEY)
            
            # Send the email
            response = sg.send(message)
            
            logger.info(f"Email sent successfully to {email}. Status code: {response.status_code}")
            
            # Check if email was accepted
            if response.status_code in [200, 201, 202]:
                return True, None
            else:
                error_msg = f"SendGrid returned status code: {response.status_code}"
                logger.warning(error_msg)
                return False, error_msg
                
        except Exception as e:
            error_msg = str(e)
            logger.error(f"Failed to send email to {email}: {error_msg}", exc_info=True)
            return False, error_msg

    def create(self, request, *args, **kwargs):
        try:
            # Validate and create user detail
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_detail = serializer.save()
            
            # Extract data to send email
            email = user_detail.email
            first_name = user_detail.first_name or ""
            last_name = user_detail.last_name or ""
            roles = user_detail.Member_role or []
            # location = user_detail.select_location or "N/A"
            
            logger.info(f"Creating user detail for {email} with roles: {roles}")
            
            # Send Email
            email_sent, error = self.send_welcome_email(
                email=email,
                first_name=first_name,
                last_name=last_name,
                roles=roles,
                # location=location
            )
            
            response_data = {
                "message": "User detail created successfully",
                "email_sent": email_sent,
                "data": UserDetailSerializer(user_detail).data
            }
            
            # Only include error if email failed
            if not email_sent:
                response_data["email_error"] = error
                logger.warning(f"User created but email failed for {email}: {error}")
            else:
                logger.info(f"User created and email sent successfully for {email}")
            
            return Response(response_data, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating user detail: {str(e)}", exc_info=True)
            return Response(
                {"error": "Failed to create user detail", "detail": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            
            
            
# class UserDetailListView(generics.ListAPIView):
#     serializer_class = UserDetailSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_queryset(self):
#         admin_id = self.request.query_params.get("admin_id")
#         location_id = self.request.query_params.get("location_id")

#         queryset = UserDetail.objects.all().order_by("-created_at")
#         if admin_id:
#             queryset = queryset.filter(admin__id=admin_id)
#         if location_id:
#             try:
#                 queryset = queryset.filter(location__id=ObjectId(location_id))
#             except Exception:
#                 pass
#         return queryset


class UserDetailListView(generics.ListAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Restrict to only the logged-in admin's own team members
        return UserDetail.objects.filter(admin=self.request.user).order_by("-created_at")


class UserDetailView(generics.RetrieveAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        obj_id = ObjectId(detail_id)
        return get_object_or_404(UserDetail, _id=obj_id)

class UserDetailUpdateView(generics.UpdateAPIView):
    """
    Update a UserDetail. Uses UserDetailUpdateSerializer for input/validation
    and returns the full serialized UserDetail (UserDetailSerializer) on success.
    Supports PUT (full update) and PATCH (partial update).
    """
    serializer_class = UserDetailUpdateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        obj_id = ObjectId(detail_id)
        return get_object_or_404(UserDetail, _id=obj_id)

    # override update to return consistent response format
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop("partial", False)  # supports partial updates
        instance = self.get_object()

        # permission: only owner admin or staff can update (adjust if needed)
        if not (request.user == instance.admin or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to update this member."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)  # calls serializer.update

        # Refresh instance from DB to get latest values
        instance.refresh_from_db()

        return Response({
            "message": "User detail updated successfully",
            "data": UserDetailSerializer(instance).data
        }, status=status.HTTP_200_OK)

    # allow PATCH requests too
    def partial_update(self, request, *args, **kwargs):
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)





class UserDetailRoleDeleteView(generics.DestroyAPIView):
    """
    Delete a specific role from UserDetail.Member_role list.
    If Member_role becomes empty after deletion, delete the entire UserDetail record.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return None
        return get_object_or_404(UserDetail, _id=obj_id)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response({"detail": "Invalid detail_id"}, status=status.HTTP_400_BAD_REQUEST)

        # Permission check: Only the admin who owns this record or staff can delete
        try:
            is_owner = (request.user.id == instance.admin.id)
        except Exception:
            is_owner = False

        if not (is_owner or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to delete this member's role."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Read confirmation and role from request body
        confirm = request.data.get("confirm", False)
        provided_role = request.data.get("member_role")

        # Handle both boolean and string "true"/"false"
        if isinstance(confirm, str):
            confirm = confirm.lower() == "true"

        if not confirm:
            return Response(
                {"detail": "Deletion not confirmed. Please set confirm to true."},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not provided_role:
            return Response(
                {"detail": "member_role is required in request body."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Allowed roles
        allowed_roles = {
            "Patch Management",
            "Configuration Management",
            "Network Security",
            "Architectural Flaws",
        }
        if provided_role not in allowed_roles:
            return Response(
                {"detail": f"Invalid member_role. Must be one of: {', '.join(allowed_roles)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get current Member_role (ensure list)
        member_roles = instance.Member_role or []
        if not isinstance(member_roles, list):
            member_roles = [member_roles] if member_roles else []

        # Check if role exists
        if provided_role not in member_roles:
            return Response(
                {"detail": f"Role '{provided_role}' not found in member's roles. Current roles: {member_roles}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Remove role
        member_roles.remove(provided_role)

        # Build member full name
        member_name = f"{instance.first_name} {instance.last_name}"

        # If no roles left, delete the user detail record
        if len(member_roles) == 0:
            instance.delete()
            return Response(
                {
                    "message": f"Role '{provided_role}' removed successfully from {member_name}. No roles remaining; the member record was deleted.",
                    "action": "record_deleted",
                    "deleted_role": provided_role
                },
                status=status.HTTP_200_OK
            )

        # Otherwise update and return remaining roles
        instance.Member_role = member_roles
        instance.save()
        return Response(
            {
                "message": f"Role '{provided_role}' removed successfully from {member_name}.",
                "action": "role_removed",
                "deleted_role": provided_role,
                "remaining_roles": member_roles
            },
            status=status.HTTP_200_OK
        )
      
class UserDetailCompleteDeleteView(generics.DestroyAPIView):
    """
    Delete the entire UserDetail record (not just a single role).
    
    Requirements:
      - request.user is the admin for that UserDetail (or is_staff)
      - frontend sends {"confirm": true} in the request body
    """
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return None
        return get_object_or_404(UserDetail, _id=obj_id)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        # Permission check
        if not (request.user.id == instance.admin.id or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to delete this member."},
                status=status.HTTP_403_FORBIDDEN
            )

        # Read confirmation from request body
        confirm = request.data.get("confirm", False)

        # Handle both boolean and string "true"/"false"
        if isinstance(confirm, str):
            confirm = confirm.lower() == "true"

        if not confirm:
            return Response(
                {"detail": "Deletion not confirmed. Please set confirm to true."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Delete the entire record
        member_name = f"{instance.first_name} {instance.last_name}"
        member_roles = instance.Member_role
        instance.delete()
        
        return Response(
            {
                "message": f"Member {member_name} deleted successfully.",
                "action": "Record Deleted",
                "deleted_roles": member_roles
            },
            status=status.HTTP_200_OK
        )
       
class UserDetailSearchView(generics.ListAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]
    queryset = UserDetail.objects.all().order_by("-created_at")
    filter_backends = [filters.SearchFilter]
    search_fields = ["first_name", "last_name", "email", "Member_role", "user_type"]

    def get_queryset(self):
        # Restrict to only the logged-in admin's own team members
        return UserDetail.objects.filter(admin=self.request.user).order_by("-created_at")
    
    
class UserDetailRoleUpdateView(generics.GenericAPIView):
    """
    PATCH endpoint to add or replace roles.

    - Add (default): {"new_roles": ["Configuration Management", "Patch Management"] }
    - Replace first occurrence: {"operation":"replace","old_role":"Network Security","new_roles":["Patch Management"]}

    If "confirm" explicitly provided and False -> rejected. If omitted or True -> proceeds.
    """
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserDetailRoleUpdateSerializer

    # canonical allowed roles (Title Case stored)
    allowed_roles = [
        "Patch Management",
        "Configuration Management",
        "Network Security",
        "Architectural Flaws",
    ]
    _allowed_map = {r.lower(): r for r in allowed_roles}

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        try:
            obj_id = ObjectId(detail_id)
        except Exception:
            return None
        return get_object_or_404(UserDetail, _id=obj_id)

    def patch(self, request, *args, **kwargs):
        instance = self.get_object()
        if not instance:
            return Response({"detail": "Invalid detail_id"}, status=status.HTTP_400_BAD_REQUEST)

        # Permission check: Only owner admin or staff
        try:
            is_owner = (request.user.id == instance.admin.id)
        except Exception:
            is_owner = False

        if not (is_owner or request.user.is_staff):
            return Response(
                {"detail": "You do not have permission to update this member's role."},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        old_role_raw = serializer.validated_data.get("old_role", None)
        new_roles_raw = serializer.validated_data["new_roles"]
        operation = serializer.validated_data.get("operation", "add")
        confirm = serializer.validated_data.get("confirm", None)

        # handle confirm: if explicitly False -> reject
        if confirm is False:
            return Response(
                {"detail": "Update not confirmed. Please set confirm=true or omit confirm."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Normalize new_roles: map case-insensitively to canonical values
        normalized_new = []
        invalid_new = []
        for r in new_roles_raw:
            key = (r or "").strip().lower()
            canonical = self._allowed_map.get(key)
            if not canonical:
                invalid_new.append(r)
            else:
                normalized_new.append(canonical)

        if invalid_new:
            return Response(
                {"detail": f"Invalid new_roles: {invalid_new}. Allowed: {', '.join(self.allowed_roles)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Normalize old_role if provided
        old_role = None
        if old_role_raw:
            key = old_role_raw.strip().lower()
            old_role = self._allowed_map.get(key)
            if not old_role:
                return Response(
                    {"detail": f"Invalid old_role '{old_role_raw}'. Allowed: {', '.join(self.allowed_roles)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # If operation == "replace" require old_role
        if operation == "replace" and not old_role:
            return Response(
                {"detail": "old_role is required when operation is 'replace'."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Ensure Member_role is a list
        roles = instance.Member_role or []
        if not isinstance(roles, list):
            roles = [roles] if roles else []

        roles_lower = [r.lower() for r in roles]

        if operation == "replace":
            # Replace first occurrence of old_role (case-insensitive)
            if old_role.lower() not in roles_lower:
                return Response(
                    {"detail": f"Old role '{old_role}' not found. Current roles: {roles}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            updated_roles = []
            replaced = False
            seen_lower = set()

            for r in roles:
                if (not replaced) and (r.lower() == old_role.lower()):
                    # insert all normalized_new (avoid duplicates)
                    for nr in normalized_new:
                        if nr.lower() not in seen_lower:
                            updated_roles.append(nr)
                            seen_lower.add(nr.lower())
                    replaced = True
                else:
                    if r.lower() not in seen_lower:
                        updated_roles.append(r)
                        seen_lower.add(r.lower())

            action = "roles_replaced"
            message = f"Role '{old_role}' replaced with {normalized_new}."
        else:
            # operation == "add" (default) — append normalized_new, avoid duplicates
            updated_roles = []
            seen_lower = set()
            for r in roles:
                if r.lower() not in seen_lower:
                    updated_roles.append(r)
                    seen_lower.add(r.lower())
            for nr in normalized_new:
                if nr.lower() not in seen_lower:
                    updated_roles.append(nr)
                    seen_lower.add(nr.lower())

            action = "roles_added"
            message = f"Added roles {normalized_new}."

        # Save and respond
        instance.Member_role = updated_roles
        instance.save()

        member_name = f"{instance.first_name or ''} {instance.last_name or ''}".strip()
        return Response(
            {
                "message": f"Roles {normalized_new} added successfully to {member_name}.",
                "action": action,
                "updated_roles": updated_roles,
                "member_name": member_name,
            },
            status=status.HTTP_200_OK
        )
        
        
class UserDetailByAdminAPIView(generics.ListAPIView):
    """
    List all UserDetails created by a specific admin.
    Only the logged-in admin can view their own team members.
    """
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        admin_id = self.kwargs.get("admin_id")

        # Restrict: logged-in user can only view their own team members
        if str(self.request.user.id) != str(admin_id):
            return UserDetail.objects.none()

        return UserDetail.objects.filter(admin=self.request.user).order_by("-created_at")

    def list(self, request, *args, **kwargs):
        admin_id = self.kwargs.get("admin_id")

        # Return 403 if trying to access another admin's data
        if str(request.user.id) != str(admin_id):
            return Response(
                {"detail": "You can only view your own team members."},
                status=status.HTTP_403_FORBIDDEN
            )

        queryset = self.get_queryset()

        if not queryset.exists():
            return Response(
                {
                    "count": 0,
                    "results": [],
                    "message": "No users found for this admin"
                },
                status=status.HTTP_200_OK
            )

        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                "count": queryset.count(),
                "admin_id": admin_id,
                "results": serializer.data
            },
            status=status.HTTP_200_OK
        )