from rest_framework import generics, permissions, status,filters
from rest_framework.response import Response
from bson import ObjectId
from django.shortcuts import get_object_or_404
from .models import UserDetail
from .serializers import UserDetailSerializer, UserDetailCreateSerializer,UserDetailUpdateSerializer


class UserDetailCreateView(generics.CreateAPIView):
    serializer_class = UserDetailCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user_detail = serializer.save()
        return Response({
            "message": "User detail created successfully",
            "data": UserDetailSerializer(user_detail).data
        }, status=status.HTTP_201_CREATED)


class UserDetailListView(generics.ListAPIView):
    serializer_class = UserDetailSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        admin_id = self.request.query_params.get("admin_id")
        location_id = self.request.query_params.get("location_id")

        queryset = UserDetail.objects.all().order_by("-created_at")
        if admin_id:
            queryset = queryset.filter(admin__id=admin_id)
        if location_id:
            try:
                queryset = queryset.filter(location__id=ObjectId(location_id))
            except Exception:
                pass
        return queryset


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

# class UserDetailUpdateView(generics.UpdateAPIView):
#     serializer_class = UserDetailCreateSerializer
#     permission_classes = [permissions.IsAuthenticated]

#     def get_object(self):
#         detail_id = self.kwargs.get("detail_id")
#         obj_id = ObjectId(detail_id)
#         return get_object_or_404(UserDetail, _id=obj_id)


# class UserDetailDeleteView(generics.DestroyAPIView):
#     permission_classes = [permissions.IsAuthenticated]

#     def get_object(self):
#         detail_id = self.kwargs.get("detail_id")
#         obj_id = ObjectId(detail_id)
#         return get_object_or_404(UserDetail, _id=obj_id)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()
#         instance.delete()
#         return Response(
#             {"message": "User detail deleted successfully"},
#             status=status.HTTP_200_OK
#         )


# class UserDetailDeleteView(generics.DestroyAPIView):
#     """
#     Delete a UserDetail only when:
#       - request.user is the admin for that UserDetail (or is_staff)
#       - frontend sends {"confirm": true, "member_role": "<role>"} in the request body
#       - the provided member_role matches the instance.Member_role
#     Member_role valid values (one of):
#       - "Patch management"
#       - "Configuration management"
#       - "Network security"
#       - "Architectural flaws"
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def get_object(self):
#         detail_id = self.kwargs.get("detail_id")
#         obj_id = ObjectId(detail_id)
#         return get_object_or_404(UserDetail, _id=obj_id)

#     def destroy(self, request, *args, **kwargs):
#         instance = self.get_object()

#         # Only the admin who owns this record or staff can delete
#         if not (request.user == instance.admin or request.user.is_staff):
#             return Response(
#                 {"detail": "You do not have permission to delete this member."},
#                 status=status.HTTP_403_FORBIDDEN
#             )

#         # Read confirmation and role from request body
#         confirm = request.data.get("confirm", False)
#         provided_role = request.data.get("member_role")

#         if not confirm:
#             return Response(
#                 {"detail": "Deletion not confirmed. Please check the confirmation box to delete."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         if not provided_role:
#             return Response(
#                 {"detail": "member_role is required in request body for verification."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         # Ensure provided_role is one of the allowed 4 roles (protects against typos)
#         allowed_roles = {
#             "Patch management",
#             "Configuration management",
#             "Network security",
#             "Architectural flaws",
#         }
#         if provided_role not in allowed_roles:
#             return Response(
#                 {"detail": "Invalid member_role provided."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         # Check that the instance.Member_role equals provided_role
#         # If Member_role is a string (single role), compare directly.
#         # If Member_role is a list (multiple roles), check membership.
#         instance_role = instance.Member_role

#         # normalize for safe comparison if needed (exact match preferred)
#         if isinstance(instance_role, (list, tuple)):
#             match = provided_role in instance_role
#         else:
#             match = str(instance_role).strip() == str(provided_role).strip()

#         if not match:
#             return Response(
#                 {"detail": "Provided member_role does not match the member's role. Deletion aborted."},
#                 status=status.HTTP_400_BAD_REQUEST
#             )

#         # Passed all checks -> delete
#         instance.delete()
#         return Response(
#             {"message": "User detail deleted successfully"},
#             status=status.HTTP_200_OK
#         )
        
 
class UserDetailDeleteView(generics.DestroyAPIView):
    """
    Delete a specific role from UserDetail's Member_role list.
    If Member_role becomes empty after deletion, delete the entire UserDetail record.
    
    Requirements:
      - request.user is the admin for that UserDetail (or is_staff)
      - frontend sends {"confirm": true, "member_role": "<role>"} in the request body
      - the provided member_role exists in the instance.Member_role list
      
    Member_role valid values (one of):
      - "Patch management"
      - "Configuration management"
      - "Network security"
      - "Architectural flaws"
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

        # Permission check: Only the admin who owns this record or staff can delete
        if not (request.user.id == instance.admin.id or request.user.is_staff):
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

        # Ensure provided_role is one of the allowed 4 roles
        allowed_roles = {
            "Patch management",
            "Configuration management",
            "Network security",
            "Architectural flaws",
        }
        if provided_role not in allowed_roles:
            return Response(
                {"detail": f"Invalid member_role. Must be one of: {', '.join(allowed_roles)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get current Member_role (should be a list)
        member_roles = instance.Member_role

        # Ensure it's a list
        if not isinstance(member_roles, list):
            # Convert to list if it's a string (backward compatibility)
            member_roles = [member_roles] if member_roles else []

        # Check if the provided role exists in the member's roles
        if provided_role not in member_roles:
            return Response(
                {
                    "detail": f"Role '{provided_role}' not found in member's roles. Current roles: {member_roles}"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        # Remove the specific role from the list
        member_roles.remove(provided_role)

        # If no roles left, delete the entire record
        if len(member_roles) == 0:
            member_name = f"{instance.first_name} {instance.last_name}"
            instance.delete()
            return Response(
                {
                    "message": f"Role '{provided_role}' removed. No roles remaining, so {member_name}'s record was deleted.",
                    "action": "record_deleted",
                    "deleted_role": provided_role
                },
                status=status.HTTP_200_OK
            )
        else:
            # Update the Member_role field with remaining roles
            instance.Member_role = member_roles
            instance.save()
            return Response(
                {
                    "message": f"Role '{provided_role}' removed successfully.",
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

    # optional: filter by admin_id & location_id along with search
    def get_queryset(self):
        queryset = super().get_queryset()
        admin_id = self.request.query_params.get("admin_id")
        location_id = self.request.query_params.get("location_id")

        if admin_id:
            queryset = queryset.filter(admin__id=admin_id)
        if location_id:
            try:
                queryset = queryset.filter(location__id=ObjectId(location_id))
            except Exception:
                pass

        return queryset