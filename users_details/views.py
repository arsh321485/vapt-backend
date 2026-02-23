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
import requests

logger = logging.getLogger('users_details')


ROLE_TO_SLACK_CHANNEL = {
    "Patch Management": "patch-management",
    "Configuration Management": "configuration-management",
    "Network Security": "network-security",
    "Architectural Flaws": "architectural-flaws",
}


def sync_member_to_slack_channels(bot_token, slack_user_id, member_roles):
    """
    Invite a Slack user to the channels matching their Member_roles.
    Returns (results list, added_channel_ids list).
    """
    if not bot_token or not slack_user_id:
        return [], []

    headers = {"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"}
    results = []
    added_channel_ids = []

    # Fetch existing channel list once
    resp = requests.get(
        "https://slack.com/api/conversations.list",
        headers=headers,
        params={"types": "public_channel", "limit": 200},
    )
    channel_map = {ch["name"]: ch["id"] for ch in resp.json().get("channels", [])}

    for role in member_roles:
        slack_name = ROLE_TO_SLACK_CHANNEL.get(role)
        if not slack_name:
            continue
        channel_id = channel_map.get(slack_name)
        if not channel_id:
            results.append({"role": role, "status": "channel_not_found"})
            continue
        invite_resp = requests.post(
            "https://slack.com/api/conversations.invite",
            headers=headers,
            json={"channel": channel_id, "users": slack_user_id},
        )
        invite_data = invite_resp.json()
        if invite_data.get("ok") or invite_data.get("error") == "already_in_channel":
            results.append({"role": role, "status": "invited", "channel_id": channel_id})
            added_channel_ids.append(channel_id)
        else:
            results.append({"role": role, "status": "failed", "error": invite_data.get("error")})

    return results, added_channel_ids


def sync_member_to_teams_channels(access_token, team_id, user_email, member_roles):
    """
    Add a user to the VAPTFIX team. Once added to the team, the user automatically
    gets access to all standard channels (Patch Management, Configuration Management,
    Network Security, Architectural Flaws).

    For private/shared channels, members are added individually.
    """
    if not access_token or not team_id:
        return []

    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    results = []

    try:
        # Get user's Azure AD ID by email
        user_resp = requests.get(
            f"https://graph.microsoft.com/v1.0/users/{user_email}",
            headers=headers, timeout=10
        )
        if user_resp.status_code != 200:
            return [{"error": f"Could not find user {user_email} in Azure AD", "detail": user_resp.text}]

        user_id = user_resp.json().get('id')

        # Add user as team member — this gives access to ALL standard channels automatically
        team_member_payload = {
            "@odata.type": "#microsoft.graph.aadUserConversationMember",
            "roles": [],
            "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')"
        }
        team_member_resp = requests.post(
            f"https://graph.microsoft.com/v1.0/teams/{team_id}/members",
            headers=headers, json=team_member_payload, timeout=10
        )
        if team_member_resp.status_code in (200, 201):
            results.append({"action": "added_to_team", "status": "success"})
        elif team_member_resp.status_code == 409:
            results.append({"action": "added_to_team", "status": "already_member"})
        else:
            results.append({"action": "added_to_team", "status": "failed", "error": team_member_resp.text})

        # For standard channels, team membership = channel access (no individual add needed)
        # Only add to private/shared channels individually
        channels_resp = requests.get(
            f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels",
            headers=headers, timeout=10
        )
        if channels_resp.status_code == 200:
            channels = channels_resp.json().get('value', [])
            for role in member_roles:
                # Find the matching channel
                matching_channel = next((ch for ch in channels if ch['displayName'] == role), None)
                if not matching_channel:
                    results.append({"channel": role, "status": "channel_not_found"})
                    continue

                membership_type = matching_channel.get('membershipType', 'standard')
                if membership_type == 'standard':
                    # Standard channels: user gets access via team membership
                    results.append({"channel": role, "status": "auto_access_via_team_membership"})
                else:
                    # Private/shared channels: add member individually
                    add_payload = {
                        "@odata.type": "#microsoft.graph.aadUserConversationMember",
                        "roles": [],
                        "user@odata.bind": f"https://graph.microsoft.com/v1.0/users('{user_id}')"
                    }
                    add_resp = requests.post(
                        f"https://graph.microsoft.com/v1.0/teams/{team_id}/channels/{matching_channel['id']}/members",
                        headers=headers, json=add_payload, timeout=10
                    )
                    if add_resp.status_code in (200, 201):
                        results.append({"channel": role, "status": "added"})
                    elif add_resp.status_code == 409:
                        results.append({"channel": role, "status": "already_member"})
                    else:
                        results.append({"channel": role, "status": "failed", "error": add_resp.text})

    except Exception as e:
        results.append({"error": str(e)})

    return results
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
            # Check for duplicate: same admin + same email
            admin_id = request.data.get("admin_id")
            email = request.data.get("email")
            if admin_id and email:
                if UserDetail.objects.filter(admin__id=admin_id, email=email).exists():
                    return Response(
                        {"error": f"User with email '{email}' already exists for this admin."},
                        status=status.HTTP_409_CONFLICT
                    )

            # Validate and create user detail
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            user_detail = serializer.save()

            # Extract data to send email
            email = user_detail.email
            first_name = user_detail.first_name or ""
            last_name = user_detail.last_name or ""
            roles = user_detail.Member_role or []

            logger.info(f"Creating user detail for {email} with roles: {roles}")

            # Send Email
            email_sent, error = self.send_welcome_email(
                email=email,
                first_name=first_name,
                last_name=last_name,
                roles=roles,
            )

            # Sync with Microsoft Teams channels if access_token and team_id provided
            teams_sync_result = []
            ms_access_token = request.data.get("access_token")
            team_id = user_detail.team_id or request.data.get("team_id")
            if ms_access_token and team_id and roles:
                teams_sync_result = sync_member_to_teams_channels(
                    access_token=ms_access_token,
                    team_id=team_id,
                    user_email=email,
                    member_roles=roles
                )

            # Sync with Slack channels if slack_bot_token and slack_user_id provided
            slack_sync_result = []
            slack_bot_token = request.data.get("slack_bot_token")
            slack_user_id = request.data.get("slack_user_id")
            if slack_bot_token and slack_user_id and roles:
                slack_results, channel_ids = sync_member_to_slack_channels(
                    bot_token=slack_bot_token,
                    slack_user_id=slack_user_id,
                    member_roles=roles,
                )
                slack_sync_result = slack_results
                if channel_ids:
                    user_detail.slack_channel_ids = channel_ids
                    user_detail.save()

            response_data = {
                "message": "User detail created successfully",
                "email_sent": email_sent,
                "data": UserDetailSerializer(user_detail).data
            }

            if teams_sync_result:
                response_data["teams_sync"] = teams_sync_result

            if slack_sync_result:
                response_data["slack_sync"] = slack_sync_result

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

        # Sync new roles with Teams channels if access_token and team_id provided
        teams_sync_result = []
        ms_access_token = request.data.get("access_token")
        team_id = instance.team_id or request.data.get("team_id")
        if ms_access_token and team_id and normalized_new:
            teams_sync_result = sync_member_to_teams_channels(
                access_token=ms_access_token,
                team_id=team_id,
                user_email=instance.email,
                member_roles=normalized_new
            )

        # Sync new roles with Slack channels if slack_bot_token and slack_user_id provided
        slack_sync_result = []
        slack_bot_token = request.data.get("slack_bot_token")
        slack_user_id = request.data.get("slack_user_id")
        if slack_bot_token and slack_user_id and normalized_new:
            slack_results, channel_ids = sync_member_to_slack_channels(
                bot_token=slack_bot_token,
                slack_user_id=slack_user_id,
                member_roles=normalized_new,
            )
            slack_sync_result = slack_results
            if channel_ids:
                existing_ids = instance.slack_channel_ids or []
                instance.slack_channel_ids = list(set(existing_ids + channel_ids))
                instance.save()

        member_name = f"{instance.first_name or ''} {instance.last_name or ''}".strip()
        response_data = {
            "message": f"Roles {normalized_new} added successfully to {member_name}.",
            "action": action,
            "updated_roles": updated_roles,
            "member_name": member_name,
        }
        if teams_sync_result:
            response_data["teams_sync"] = teams_sync_result

        if slack_sync_result:
            response_data["slack_sync"] = slack_sync_result

        return Response(response_data, status=status.HTTP_200_OK)
        
        
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