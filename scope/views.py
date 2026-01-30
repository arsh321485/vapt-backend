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
                {"message": f"Invalid testing_type. Must be one of: {', '.join(valid_types)}"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Get name (required)
        name = request.data.get("name", "").strip()
        if not name:
            return Response(
                {"message": "Scope name is required"},
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
                {"message": "Either 'file' or 'targets' is required"},
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
                    {"message": str(e)},
                    status=status.HTTP_400_BAD_REQUEST
                )

        # Process manual targets
        else:
            source_type = "manual"
            values = parse_targets_string(targets_str)

        if not values:
            return Response(
                {"message": "No valid targets found"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Process entries with auto-detection
        processed = process_entries(values, expand_subnets=expand_subnets)

        # Get valid entry values for duplicate check
        new_entry_values = set(
            entry["value"].lower() for entry in processed if entry["is_valid"]
        )

        if not new_entry_values:
            return Response(
                {"message": "No valid targets found in the uploaded file"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check for duplicate file content in existing scopes with same name + testing_type
        existing_scopes = Scope.objects.filter(
            admin=request.user,
            name__iexact=name,
            testing_type=testing_type
        )

        for existing_scope in existing_scopes:
            existing_entry_values = set(
                entry.value.lower() for entry in existing_scope.entries.all()
            )
            # Check if the new entries exactly match an existing scope's entries
            if new_entry_values == existing_entry_values:
                return Response(
                    {"message": f"This file has already been uploaded for scope '{name}' with {testing_type.replace('_', ' ')} testing"},
                    status=status.HTTP_400_BAD_REQUEST
                )

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
                {"message": "Cannot modify a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Check for duplicate file content if name or testing_type is being updated
        new_name = request.data.get("name", "").strip() or scope.name
        new_testing_type = request.data.get("testing_type", scope.testing_type)

        # Check if the combination is changing
        name_changed = new_name.lower() != scope.name.lower()
        testing_type_changed = new_testing_type != scope.testing_type

        if name_changed or testing_type_changed:
            # Get current scope's entry values
            current_entry_values = set(
                entry.value.lower() for entry in scope.entries.all()
            )

            # Check if moving to a name+testing_type that already has same entries
            existing_scopes = Scope.objects.filter(
                admin=scope.admin,
                name__iexact=new_name,
                testing_type=new_testing_type
            ).exclude(id=scope_id)

            for existing_scope in existing_scopes:
                existing_entry_values = set(
                    entry.value.lower() for entry in existing_scope.entries.all()
                )
                if current_entry_values == existing_entry_values:
                    return Response(
                        {"message": f"A scope with the same targets already exists for '{new_name}' with {new_testing_type.replace('_', ' ')} testing"},
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
                {"message": "Cannot delete a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        scope.delete()
        return Response(
            {"message": "Scope deleted successfully"},
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
                {"message": "Cannot add entries to a locked scope"},
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


class ScopeEntryDetailAPIView(APIView):
    """
    GET /api/admin/scope/<scope_id>/entries/<entry_id>/detail/

    Retrieve a single scope entry by ID.
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def get(self, request, scope_id, entry_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        entry = get_object_or_404(ScopeEntry, id=entry_id, scope=scope)

        return Response({
            "message": "Entry retrieved successfully",
            "entry": ScopeEntrySerializer(entry).data,
            "scope_info": {
                "scope_id": str(scope.id),
                "scope_name": scope.name,
                "testing_type": scope.testing_type
            }
        }, status=status.HTTP_200_OK)


class ScopeEntryDeleteAPIView(APIView):
    """
    DELETE /api/admin/scope/<scope_id>/entries/<entry_id>/

    Delete a single scope entry.
    """
    permission_classes = [permissions.IsAuthenticated, IsScopeOwnerOrSuperAdmin]

    def delete(self, request, scope_id, entry_id):
        scope = get_object_or_404(Scope, id=scope_id)
        self.check_object_permissions(request, scope)

        if not request.user.is_superuser and scope.is_locked:
            return Response(
                {"message": "Cannot delete entries from a locked scope"},
                status=status.HTTP_403_FORBIDDEN
            )

        entry = get_object_or_404(ScopeEntry, id=entry_id, scope=scope)
        deleted_value = entry.value
        entry.delete()

        return Response({
            "message": "Entry deleted successfully",
            "deleted_entry": {
                "id": entry_id,
                "value": deleted_value
            }
        }, status=status.HTTP_200_OK)


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
                {"message": "Cannot update entries in a locked scope"},
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
                        {"message": "An entry with this value already exists in the scope"},
                        status=status.HTTP_400_BAD_REQUEST
                    )

            serializer.save()
            return Response({
                "message": "Entry updated successfully",
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
                {"message": "Cannot upload to a locked scope"},
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
                    {"message": "No valid values found in file"},
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
                {"message": str(e)},
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
                    {"message": "Scope is already locked"},
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
                "message": "Scope locked successfully. Email notification sent to admin.",
                "scope": ScopeSerializer(scope).data
            }, status=status.HTTP_200_OK)

        else:  # unlock
            if not scope.is_locked:
                return Response(
                    {"message": "Scope is not locked"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            scope.is_locked = False
            scope.locked_by = None
            scope.locked_at = None
            scope.save()

            return Response({
                "message": "Scope unlocked successfully",
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

        scopes = Scope.objects.filter(admin_id=admin_id).values_list("name", flat=True)
        # Use dict to get unique names (case-insensitive) while preserving original case
        unique_names = {}
        for name in scopes:
            name_lower = name.lower()
            if name_lower not in unique_names:
                unique_names[name_lower] = name
        scope_list = list(unique_names.values())
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
    Returns all testing types associated with the scope name.
    Same scope name can have multiple testing types (white_box, grey_box, black_box).
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, admin_id, scope_name):
        # Regular admin can only fetch their own data
        if not request.user.is_superuser and str(request.user.id) != str(admin_id):
            return Response(
                {"message": "You can only view your own scope data"},
                status=status.HTTP_403_FORBIDDEN
            )

        # Find all scopes by admin and name (case-insensitive)
        scopes = Scope.objects.filter(
            admin_id=admin_id,
            name__iexact=scope_name
        )

        if not scopes.exists():
            return Response(
                {"message": f"Scope '{scope_name}' not found for this admin"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Group by testing_type and get unique testing types
        testing_type_data = {}
        for scope in scopes:
            tt = scope.testing_type
            if tt not in testing_type_data:
                testing_type_data[tt] = {
                    "testing_type": tt,
                    "scope_count": 0,
                    "scope_ids": []
                }
            testing_type_data[tt]["scope_count"] += 1
            testing_type_data[tt]["scope_ids"].append(str(scope.id))

        return Response({
            "message": "Scope testing types retrieved successfully",
            "admin_id": admin_id,
            "scope_name": scopes.first().name,
            "testing_types": list(testing_type_data.values()),
            "available_types": list(testing_type_data.keys())
        }, status=status.HTTP_200_OK)


class ScopeDataByNameAPIView(APIView):
    """
    GET /api/admin/scope/data/<admin_id>/<scope_name>/?testing_type=white_box

    Get full scope data by admin ID and scope name.
    Returns all scopes matching the criteria with their entries.

    Required query params:
    - testing_type: Filter by testing type (white_box, grey_box, black_box)
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, admin_id, scope_name):
        # Regular admin can only fetch their own data
        if not request.user.is_superuser and str(request.user.id) != str(admin_id):
            return Response(
                {"message": "You can only view your own scope data"},
                status=status.HTTP_403_FORBIDDEN
            )

        # testing_type is required to get specific scope data
        testing_type = request.query_params.get("testing_type")
        if not testing_type:
            return Response(
                {"message": "testing_type query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Find all scopes by admin, name, and testing_type
        scopes = Scope.objects.filter(
            admin_id=admin_id,
            name__iexact=scope_name,
            testing_type=testing_type
        ).order_by("-created_at")

        if not scopes.exists():
            return Response(
                {"message": f"Scope '{scope_name}' with {testing_type.replace('_', ' ')} testing not found for this admin"},
                status=status.HTTP_404_NOT_FOUND
            )

        # Collect all entries from all matching scopes, grouped by category
        all_entries = {
            "internal_targets": [],
            "external_targets": [],
            "web_app_targets": [],
            "mobile_app_targets": []
        }

        scope_ids = []
        for scope in scopes:
            scope_ids.append(str(scope.id))
            for entry in scope.entries.all():
                entry_data = ScopeEntrySerializer(entry).data
                entry_data["scope_id"] = str(scope.id)

                # Classify entry into appropriate category
                if entry.entry_type == "internal_ip":
                    all_entries["internal_targets"].append(entry_data)
                elif entry.entry_type == "external_ip":
                    all_entries["external_targets"].append(entry_data)
                elif entry.entry_type == "web_url":
                    all_entries["web_app_targets"].append(entry_data)
                elif entry.entry_type == "mobile_url":
                    all_entries["mobile_app_targets"].append(entry_data)
                elif entry.entry_type == "subnet":
                    # Subnets are classified based on is_internal flag
                    entry_data["is_subnet"] = True
                    if entry.is_internal:
                        all_entries["internal_targets"].append(entry_data)
                    else:
                        all_entries["external_targets"].append(entry_data)

        return Response({
            "message": "Scope data retrieved successfully",
            "admin_id": admin_id,
            "scope_name": scopes.first().name,
            "testing_type": testing_type,
            "scope_count": scopes.count(),
            "scope_ids": scope_ids,
            "entries": all_entries,
            "total_entries": sum(len(v) for v in all_entries.values())
        }, status=status.HTTP_200_OK)


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
                {"message": "You can only view your own scope data"},
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
                "message": "No scopes found for this admin",
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

        # Get unique scope names (case-insensitive)
        unique_names = {}
        for name in scopes.values_list("name", flat=True):
            name_lower = name.lower()
            if name_lower not in unique_names:
                unique_names[name_lower] = name

        return Response({
            "message": "Scope hierarchy retrieved successfully",
            "admin_id": admin_id,
            "count": len(scope_data),
            "scope_names": list(unique_names.values()),
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
                {"message": "No super admin available to contact"},
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
                "message": f"Your message has been sent to {sent_count} super admin(s)",
                "scope_id": scope_id,
                "scope_name": scope.name
            }, status=status.HTTP_200_OK)
        else:
            return Response(
                {"message": "Failed to send message. Please try again later."},
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
                        {"message": "You don't have permission to reference this scope"},
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
                {"message": "No super admin available to contact"},
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
                "message": f"Your message has been sent to {sent_count} super admin(s)",
                "subject": subject
            }, status=status.HTTP_200_OK)
        else:
            return Response(
                {"message": "Failed to send message. Please try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
