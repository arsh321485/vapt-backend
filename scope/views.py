from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.parsers import MultiPartParser, FormParser
from django.utils import timezone
from django.shortcuts import get_object_or_404

from .models import Scope, ScopeEntry
from .serializers import (
    ScopeSerializer,
    ScopeListSerializer,
    ScopeUpdateSerializer,
    ScopeEntrySerializer,
    ScopeEntryUpdateSerializer,
    ScopeLockSerializer,
    BulkEntrySerializer,
    FileUploadSerializer,
    ContactSuperAdminSerializer,
    ContactSupportSerializer,
)
from .permissions import (
    IsScopeOwnerOrSuperAdmin,
    CanLockScope,
    IsSuperAdmin,
)
from .utils import (
    parse_file_content,
    parse_targets_string,
    process_entries,
    send_scope_lock_notification,
    send_contact_superadmin_email,
    get_superadmin_emails,
)


class ScopeCreateAPIView(APIView):
    """
    POST /api/admin/scope/create/?current_testing_box=white_box

    Create a new scope with either:
    - File upload (file field)
    - Manual targets (targets field)

    Required: name
    Optional: expand_subnets (default: true)
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request):
        # Get testing_type from query param
        testing_type = request.query_params.get("current_testing_box", "black_box")
        valid_types = ["white_box", "grey_box", "black_box"]

        if testing_type not in valid_types:
            return Response(
                {"detail": f"Invalid testing_type. Must be one of: {', '.join(valid_types)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get name (required)
        name = request.data.get("name", "").strip()
        if not name:
            return Response(
                {"detail": "name is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for duplicate scope name for this admin
        if Scope.objects.filter(admin=request.user, name__iexact=name).exists():
            return Response(
                {"detail": f"A scope with the project name '{name}' already exists for your account"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get expand_subnets option
        expand_subnets_str = request.data.get("expand_subnets", "true")
        expand_subnets = str(expand_subnets_str).lower() in ["true", "1", "yes"]

        # Check for file or targets
        file_obj = request.FILES.get("file")
        targets_str = request.data.get("targets", "")

        if not file_obj and not targets_str:
            return Response(
                {"detail": "Either 'file' or 'targets' is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        values = []
        source_type = None

        # Process file upload
        if file_obj:
            source_type = "file"
            # Validate file
            serializer = FileUploadSerializer(data={"file": file_obj, "expand_subnets": expand_subnets})
            if not serializer.is_valid():
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

            try:
                values = parse_file_content(file_obj, file_obj.name)
            except ValueError as e:
                return Response(
                    {"detail": str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Process manual targets
        else:
            source_type = "manual"
            values = parse_targets_string(targets_str)

        if not values:
            return Response(
                {"detail": "No valid targets found"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process entries with auto-detection
        processed = process_entries(values, expand_subnets=expand_subnets)

        # Create scope
        scope = Scope.objects.create(
            admin=request.user,
            name=name,
            testing_type=testing_type
        )

        # Create entries
        created_entries = []
        errors = []

        for entry_data in processed:
            if entry_data["is_valid"]:
                entry = ScopeEntry.objects.create(
                    scope=scope,
                    value=entry_data["value"],
                    entry_type=entry_data["entry_type"],
                    is_internal=entry_data["is_internal"],
                    subnet_mask=entry_data.get("subnet_mask"),
                )
                created_entries.append(ScopeEntrySerializer(entry).data)

                # Add warning if present
                if entry_data.get("warning"):
                    created_entries[-1]["warning"] = entry_data["warning"]
            else:
                errors.append({
                    "value": entry_data["value"],
                    "error": entry_data["error"]
                })

        return Response({
            "message": "Scope created successfully",
            "scope": ScopeSerializer(scope).data,
            "processing": {
                "source": source_type,
                "total_parsed": len(values),
                "created_count": len(created_entries),
                "error_count": len(errors),
                "expand_subnets": expand_subnets,
                "errors": errors
            }
        }, status=status.HTTP_201_CREATED)


class ScopeListAPIView(APIView):
    """
    GET /api/admin/scope/
    GET /api/admin/scope/?testing_type=white_box

    List scopes for current admin (or all for super admin).
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.is_superuser:
            scopes = Scope.objects.all()
        else:
            scopes = Scope.objects.filter(admin=user)

        # Filter by testing_type if provided
        testing_type = request.query_params.get("testing_type")
        if testing_type:
            scopes = scopes.filter(testing_type=testing_type)

        serializer = ScopeListSerializer(scopes, many=True)
        return Response({
            "count": scopes.count(),
            "scopes": serializer.data
        }, status=status.HTTP_200_OK)


class ScopeDetailAPIView(APIView):
    """
    GET /api/admin/scope/<id>/
    PATCH /api/admin/scope/<id>/
    DELETE /api/admin/scope/<id>/
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def get_object(self, scope_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(self.request, scope)
        return scope

    def get(self, request, scope_id):
        scope = self.get_object(scope_id)
        serializer = ScopeSerializer(scope)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def patch(self, request, scope_id):
        scope = self.get_object(scope_id)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"detail": "Cannot modify a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check for duplicate scope name if name is being updated
        new_name = request.data.get("name", "").strip()
        if new_name and new_name.lower() != scope.name.lower():
            if Scope.objects.filter(admin=scope.admin, name__iexact=new_name).exclude(id=scope_id).exists():
                return Response(
                    {"detail": f"A scope with the name '{new_name}' already exists for this admin"},
                    status=status.HTTP_400_BAD_REQUEST
                )

        serializer = ScopeUpdateSerializer(scope, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(
                ScopeSerializer(scope).data,
                status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, scope_id):
        scope = self.get_object(scope_id)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"detail": "Cannot delete a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        scope.delete()
        return Response(
            {"detail": "Scope deleted successfully"},
            status=status.HTTP_200_OK
        )


class ScopeEntriesAPIView(APIView):
    """
    GET /api/admin/scope/<id>/entries/
    POST /api/admin/scope/<id>/entries/

    List or add entries to a scope.
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def get_scope(self, scope_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(self.request, scope)
        return scope

    def get(self, request, scope_id):
        scope = self.get_scope(scope_id)
        entries = scope.entries.all()

        # Filter by entry_type
        entry_type = request.query_params.get("entry_type")
        if entry_type:
            entries = entries.filter(entry_type=entry_type)

        # Filter by is_internal
        is_internal = request.query_params.get("is_internal")
        if is_internal is not None:
            is_internal_bool = is_internal.lower() in ["true", "1", "yes"]
            entries = entries.filter(is_internal=is_internal_bool)

        serializer = ScopeEntrySerializer(entries, many=True)
        return Response({
            "scope_id": scope_id,
            "count": entries.count(),
            "entries": serializer.data
        }, status=status.HTTP_200_OK)

    def post(self, request, scope_id):
        scope = self.get_scope(scope_id)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"detail": "Cannot add entries to a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = BulkEntrySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        values = serializer.validated_data["values"]
        expand_subnets = serializer.validated_data.get("expand_subnets", True)

        processed = process_entries(values, expand_subnets=expand_subnets)

        created_entries = []
        errors = []

        for entry_data in processed:
            if entry_data["is_valid"]:
                # Check for duplicates
                exists = ScopeEntry.objects.filter(
                    scope=scope,
                    value=entry_data["value"]
                ).exists()

                if exists:
                    errors.append({
                        "value": entry_data["value"],
                        "error": "Duplicate entry in scope"
                    })
                    continue

                entry = ScopeEntry.objects.create(
                    scope=scope,
                    value=entry_data["value"],
                    entry_type=entry_data["entry_type"],
                    is_internal=entry_data["is_internal"],
                    subnet_mask=entry_data.get("subnet_mask"),
                )
                created_entries.append(ScopeEntrySerializer(entry).data)
            else:
                errors.append({
                    "value": entry_data["value"],
                    "error": entry_data["error"]
                })

        return Response({
            "scope_id": scope_id,
            "created_count": len(created_entries),
            "error_count": len(errors),
            "created_entries": created_entries,
            "errors": errors
        }, status=status.HTTP_201_CREATED if created_entries else status.HTTP_400_BAD_REQUEST)


class ScopeEntryDeleteAPIView(APIView):
    """
    DELETE /api/admin/scope/<id>/entries/<entry_id>/
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def delete(self, request, scope_id, entry_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"detail": "Cannot delete entries from a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        entry = get_object_or_404(ScopeEntry, id=entry_id, scope=scope)
        entry.delete()

        return Response(
            {"detail": "Entry deleted successfully"},
            status=status.HTTP_200_OK
        )


class ScopeEntryUpdateAPIView(APIView):
    """
    PATCH /api/admin/scope/<id>/entries/<entry_id>/update/

    Update a specific scope entry.
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def patch(self, request, scope_id, entry_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"detail": "Cannot update entries in a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        entry = get_object_or_404(ScopeEntry, id=entry_id, scope=scope)

        serializer = ScopeEntryUpdateSerializer(entry, data=request.data, partial=True)

        if serializer.is_valid():
            # Check for duplicate value if value is being updated
            new_value = serializer.validated_data.get("value")
            if new_value and new_value != entry.value:
                exists = ScopeEntry.objects.filter(
                    scope=scope,
                    value=new_value
                ).exclude(id=entry_id).exists()

                if exists:
                    return Response(
                        {"detail": "An entry with this value already exists in the scope"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            serializer.save()
            return Response({
                "detail": "Entry updated successfully",
                "entry": ScopeEntrySerializer(entry).data
            }, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ScopeFileUploadAPIView(APIView):
    """
    POST /api/admin/scope/<id>/upload/

    Upload file to add entries to existing scope.
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]
    parser_classes = [MultiPartParser, FormParser]

    def post(self, request, scope_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"detail": "Cannot upload to a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        serializer = FileUploadSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        uploaded_file = serializer.validated_data["file"]
        expand_subnets = serializer.validated_data.get("expand_subnets", True)

        try:
            values = parse_file_content(uploaded_file, uploaded_file.name)

            if not values:
                return Response(
                    {"detail": "No valid values found in file"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            processed = process_entries(values, expand_subnets=expand_subnets)

            created_entries = []
            errors = []

            for entry_data in processed:
                if entry_data["is_valid"]:
                    exists = ScopeEntry.objects.filter(
                        scope=scope,
                        value=entry_data["value"]
                    ).exists()

                    if exists:
                        errors.append({
                            "value": entry_data["value"],
                            "error": "Duplicate entry in scope"
                        })
                        continue

                    entry = ScopeEntry.objects.create(
                        scope=scope,
                        value=entry_data["value"],
                        entry_type=entry_data["entry_type"],
                        is_internal=entry_data["is_internal"],
                        subnet_mask=entry_data.get("subnet_mask"),
                    )
                    created_entries.append(ScopeEntrySerializer(entry).data)
                else:
                    errors.append({
                        "value": entry_data["value"],
                        "error": entry_data["error"]
                    })

            return Response({
                "scope_id": scope_id,
                "filename": uploaded_file.name,
                "total_parsed": len(values),
                "created_count": len(created_entries),
                "error_count": len(errors),
                "created_entries": created_entries,
                "errors": errors
            }, status=status.HTTP_201_CREATED if created_entries else status.HTTP_400_BAD_REQUEST)

        except ValueError as e:
            return Response(
                {"detail": str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )


class ScopeLockAPIView(APIView):
    """
    POST /api/admin/scope/<id>/lock/

    Lock or unlock a scope (Super Admin only).
    When locked, an email notification is sent to the scope owner.
    """
    permission_classes = [permissions.IsAuthenticated, CanLockScope]

    def post(self, request, scope_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        serializer = ScopeLockSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        action = serializer.validated_data["action"]

        if action == "lock":
            if scope.is_locked:
                return Response(
                    {"detail": "Scope is already locked"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            scope.is_locked = True
            scope.locked_by = request.user.email
            scope.locked_at = timezone.now()
            scope.save()

            # Send email notification to the scope owner
            send_scope_lock_notification(
                scope_owner_email=scope.admin.email,
                scope_name=scope.name,
                locked_by_email=request.user.email
            )

            return Response({
                "detail": "Scope locked successfully. Email notification sent to admin.",
                "scope": ScopeSerializer(scope).data
            }, status=status.HTTP_200_OK)

        else:  # unlock
            if not scope.is_locked:
                return Response(
                    {"detail": "Scope is not locked"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            scope.is_locked = False
            scope.locked_by = None
            scope.locked_at = None
            scope.save()

            return Response({
                "detail": "Scope unlocked successfully",
                "scope": ScopeSerializer(scope).data
            }, status=status.HTTP_200_OK)


class TestingTypesAPIView(APIView):
    """
    GET /api/admin/scope/testing-types/

    Get list of testing types used by current admin.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        user = request.user

        if user.is_superuser:
            scopes = Scope.objects.all()
        else:
            scopes = Scope.objects.filter(admin=user)

        # Get distinct testing types
        testing_types = scopes.values_list("testing_type", flat=True).distinct()

        return Response({
            "testing_types": list(testing_types),
            "all_types": ["white_box", "grey_box", "black_box"]
        }, status=status.HTTP_200_OK)


class ScopesByAdminAPIView(APIView):
    """
    GET /api/admin/scope/admin/<admin_id>/

    List scopes by admin ID (super admin only).
    """
    permission_classes = [permissions.IsAuthenticated, IsSuperAdmin]

    def get(self, request, admin_id):
        scopes = Scope.objects.filter(admin_id=admin_id)
        serializer = ScopeListSerializer(scopes, many=True)
        count = scopes.count()

        if count == 0:
            return Response({
                "message": "No scopes found for this admin",
                "admin_id": admin_id,
                "count": 0,
                "scopes": []
            }, status=status.HTTP_200_OK)

        return Response({
            "message": "Scopes retrieved successfully",
            "admin_id": admin_id,
            "count": count,
            "scopes": serializer.data
        }, status=status.HTTP_200_OK)


class ScopeNamesByAdminAPIView(APIView):
    """
    GET /api/admin/scope/names/<admin_id>/

    Get list of scope names for a specific admin.
    Super admin can view any admin's scope names.
    Regular admin can only view their own scope names.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, admin_id):
        # Regular admin can only fetch their own scope names
        if not request.user.is_superuser and str(request.user.id) != str(admin_id):
            return Response(
                {"message": "You can only view your own scope Project names"},
                status=status.HTTP_403_FORBIDDEN
            )

        scopes = Scope.objects.filter(admin_id=admin_id).values_list("name", flat=True).distinct()
        scope_list = list(scopes)
        count = len(scope_list)

        if count == 0:
            return Response({
                "message": "No scope Project names found for this admin",
                "admin_id": admin_id,
                "count": 0,
                "scope_names": []
            }, status=status.HTTP_200_OK)

        return Response({
            "message": "Scope Project names retrieved successfully",
            "admin_id": admin_id,
            "count": count,
            "scope_names": scope_list
        }, status=status.HTTP_200_OK)


class ScopeTestingTypeAPIView(APIView):
    """
    GET /api/admin/scope/testing-type/<admin_id>/<scope_name>/

    Get testing type(s) for a specific scope name and admin.
    Returns the testing type associated with the scope.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, admin_id, scope_name):
        # Regular admin can only fetch their own data
        if not request.user.is_superuser and str(request.user.id) != str(admin_id):
            return Response(
                {"message": "You can only view your own scope data"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Find scope by admin and name (case-insensitive)
        scope = Scope.objects.filter(
            admin_id=admin_id,
            name__iexact=scope_name
        ).first()

        if not scope:
            return Response(
                {"message": f"Scope '{scope_name}' not found for this admin"},
                status=status.HTTP_404_NOT_FOUND
            )

        return Response({
            "message": "Scope testing type retrieved successfully",
            "admin_id": admin_id,
            "scope_name": scope.name,
            "testing_type": scope.testing_type,
            "scope_id": str(scope.id)
        }, status=status.HTTP_200_OK)


class ScopeDataByNameAPIView(APIView):
    """
    GET /api/admin/scope/data/<admin_id>/<scope_name>/

    Get full scope data by admin ID and scope name.
    Returns complete scope details including entries.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, admin_id, scope_name):
        # Regular admin can only fetch their own data
        if not request.user.is_superuser and str(request.user.id) != str(admin_id):
            return Response(
                {"detail": "You can only view your own scope data"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Find scope by admin and name (case-insensitive)
        scope = Scope.objects.filter(
            admin_id=admin_id,
            name__iexact=scope_name
        ).first()

        if not scope:
            return Response(
                {"detail": f"Scope '{scope_name}' not found for this admin"},
                status=status.HTTP_404_NOT_FOUND
            )

        serializer = ScopeSerializer(scope)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ScopeHierarchyAPIView(APIView):
    """
    GET /api/admin/scope/hierarchy/<admin_id>/

    Get hierarchical scope data for an admin:
    - List of scope names
    - For each scope: name, testing_type, id, entry_count

    Optional query params:
    - scope_name: Filter to get details for specific scope
    - include_entries: Set to 'true' to include full entry data
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, admin_id):
        # Regular admin can only fetch their own data
        if not request.user.is_superuser and str(request.user.id) != str(admin_id):
            return Response(
                {"detail": "You can only view your own scope data"},
                status=status.HTTP_403_FORBIDDEN
            )

        scope_name = request.query_params.get("scope_name")
        include_entries = request.query_params.get("include_entries", "").lower() == "true"

        scopes = Scope.objects.filter(admin_id=admin_id)

        # Filter by scope name if provided
        if scope_name:
            scopes = scopes.filter(name__iexact=scope_name)

        if not scopes.exists():
            return Response({
                "admin_id": admin_id,
                "count": 0,
                "scopes": []
            }, status=status.HTTP_200_OK)

        # Build response
        scope_data = []
        for scope in scopes:
            data = {
                "id": str(scope.id),
                "name": scope.name,
                "testing_type": scope.testing_type,
                "is_locked": scope.is_locked,
                "locked_by": scope.locked_by,
                "entry_count": scope.entries.count(),
                "created_at": scope.created_at,
                "updated_at": scope.updated_at
            }

            if include_entries:
                data["entries"] = ScopeEntrySerializer(scope.entries.all(), many=True).data

            scope_data.append(data)

        return Response({
            "admin_id": admin_id,
            "count": len(scope_data),
            "scope_names": list(scopes.values_list("name", flat=True)),
            "scopes": scope_data
        }, status=status.HTTP_200_OK)


class ContactSuperAdminAPIView(APIView):
    """
    POST /api/admin/scope/<scope_id>/contact-superadmin/

    Allow admin to contact super admin about scope issues.
    Useful when scope is locked and admin needs assistance.
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def post(self, request, scope_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        serializer = ContactSuperAdminSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        subject = serializer.validated_data["subject"]
        message = serializer.validated_data["message"]

        # Get super admin emails
        superadmin_emails = get_superadmin_emails()

        if not superadmin_emails:
            return Response(
                {"detail": "No super admin available to contact"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Get admin name
        admin_name = getattr(request.user, 'name', None) or \
                     getattr(request.user, 'full_name', None) or \
                     request.user.email

        # Send email to all super admins
        sent_count = 0
        for superadmin_email in superadmin_emails:
            success = send_contact_superadmin_email(
                admin_email=request.user.email,
                admin_name=admin_name,
                scope_name=scope.name,
                scope_id=str(scope.id),
                subject=subject,
                message=message,
                superadmin_email=superadmin_email
            )
            if success:
                sent_count += 1

        if sent_count > 0:
            return Response({
                "detail": f"Your message has been sent to {sent_count} super admin(s)",
                "scope_id": scope_id,
                "scope_name": scope.name
            }, status=status.HTTP_200_OK)
        else:
            return Response(
                {"detail": "Failed to send message. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ContactSupportAPIView(APIView):
    """
    POST /api/admin/scope/contact-support/

    Allow admin to contact super admin for general support.
    Optionally can include a scope_id for context.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = ContactSupportSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        subject = serializer.validated_data["subject"]
        message = serializer.validated_data["message"]
        scope_id = serializer.validated_data.get("scope_id", "").strip()

        # Get scope info if scope_id provided
        scope_name = "N/A"
        if scope_id:
            try:
                scope = Scope.objects.get(id=scope_id)
                # Verify user owns this scope or is super admin
                if not request.user.is_superuser and scope.admin != request.user:
                    return Response(
                        {"detail": "You don't have permission to reference this scope"},
                        status=status.HTTP_403_FORBIDDEN
                    )
                scope_name = scope.name
            except Scope.DoesNotExist:
                scope_id = "Invalid scope ID"
                scope_name = "Unknown"

        # Get super admin emails
        superadmin_emails = get_superadmin_emails()

        if not superadmin_emails:
            return Response(
                {"detail": "No super admin available to contact"},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Get admin name
        admin_name = getattr(request.user, 'name', None) or \
                     getattr(request.user, 'full_name', None) or \
                     request.user.email

        # Send email to all super admins
        sent_count = 0
        for superadmin_email in superadmin_emails:
            success = send_contact_superadmin_email(
                admin_email=request.user.email,
                admin_name=admin_name,
                scope_name=scope_name,
                scope_id=scope_id if scope_id else "General Support",
                subject=subject,
                message=message,
                superadmin_email=superadmin_email
            )
            if success:
                sent_count += 1

        if sent_count > 0:
            return Response({
                "detail": f"Your message has been sent to {sent_count} super admin(s)",
                "subject": subject
            }, status=status.HTTP_200_OK)
        else:
            return Response(
                {"detail": "Failed to send message. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
