from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from bson import ObjectId
from bson.errors import InvalidId
import tempfile
import os

from .models import Scope, ScopeFileUpload
from .serializers import (
    ScopeSerializer,
    ScopeCreateSerializer,
    ScopeListSerializer,
    ScopeStatsSerializer
)
from .utils import extract_targets_from_text, classify_target, expand_subnet, is_valid_subnet, get_subnet_count
from .file_parser import parse_file


class ScopeCreateView(APIView):
    """
    Unified endpoint for creating scope targets.
    Handles: Single target, Bulk text, and File upload
    
    POST /api/admin/scope/create/
    
    Single Target (JSON):
    {
        "target_value": "192.168.1.1",
        "notes": "Optional notes",
        "is_active": true
    }
    
    Bulk Text (form-data):
    - targets: "192.168.1.1\n10.0.0.1\n8.8.8.8"
    
    File Upload (form-data):
    - file: [Excel/CSV/Word/Text file]
    
    Single Target (form-data):
    - target_value: "192.168.1.1"
    - notes: "Optional notes"
    - is_active: true
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        # Check if request has any data
        if not request.data and not request.FILES:
            return Response(
                {
                    'success': False,
                    'error': 'No data provided. Please provide target_value (JSON), targets (form-data), or file (form-data).'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check content type to determine request type
        content_type = request.content_type or ''
        
        # Case 1: JSON request with single target_value
        if 'application/json' in content_type:
            target_value = request.data.get('target_value')
            
            if not target_value:
                return Response(
                    {
                        'success': False,
                        'error': 'target_value is required for single target creation.'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Use serializer for single creation
            serializer = ScopeCreateSerializer(data=request.data)
            if serializer.is_valid():
                # Calculate subnet_count if it's a subnet
                target_value = request.data.get('target_value')
                if is_valid_subnet(target_value):
                    subnet_count = get_subnet_count(target_value)
                    serializer.validated_data['subnet_count'] = subnet_count
                
                # Gate: Use current_testing_box parameter if provided, otherwise use provided testing_type or admin's
                current_testing_box = request.query_params.get('current_testing_box') or request.data.get('current_testing_box')
                if not serializer.validated_data.get('testing_type'):
                    if current_testing_box:
                        # Validate current_testing_box
                        if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                            serializer.validated_data['testing_type'] = current_testing_box
                        else:
                            return Response(
                                {
                                    'success': False,
                                    'error': f'Invalid current_testing_box: {current_testing_box}. Must be white_box, grey_box, or black_box.'
                                },
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        # Get admin's testing_type from their profile (use first one if list)
                        admin_testing_type = getattr(request.user, 'testing_type', None)
                        if admin_testing_type:
                            if isinstance(admin_testing_type, list) and len(admin_testing_type) > 0:
                                serializer.validated_data['testing_type'] = admin_testing_type[0]  # Use first one
                            elif isinstance(admin_testing_type, str):
                                serializer.validated_data['testing_type'] = admin_testing_type
                        # If still no testing_type, leave it as None (will be filtered by gate)

                scope = serializer.save(admin=request.user)
                return Response({
                    'success': True,
                    'message': 'Target created successfully.',
                    'admin_id': str(request.user.id),
                    'admin_email': request.user.email,
                    'data': {
                        '_id': str(scope._id),
                        'target_type': scope.target_type,
                        'target_value': scope.target_value,
                        'notes': scope.notes,
                        'is_active': scope.is_active,
                        'testing_type': scope.testing_type,
                        'subnet_count': scope.subnet_count,
                        'created_at': scope.created_at
                    }
                }, status=status.HTTP_201_CREATED)
            else:
                return Response({
                    'success': False,
                    'error': 'Validation failed.',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Case 2: Form-data request
        # Check for file upload first
        uploaded_file = request.FILES.get('file')
        targets_text = request.data.get('targets')
        target_value = request.data.get('target_value')  # Single target in form-data
        
        # Case 2a: File upload
        if uploaded_file:
            if targets_text or target_value:
                return Response(
                    {
                        'success': False,
                        'error': 'Cannot provide both file and targets/target_value. Use only one method.'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return self._handle_file_upload(request, uploaded_file)
        
        # Case 2b: Bulk text (targets with multiple lines)
        elif targets_text:
            if target_value:
                return Response(
                    {
                        'success': False,
                        'error': 'Cannot provide both targets and target_value. Use targets for bulk, target_value for single.'
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            return self._handle_bulk_text(request, targets_text)
        
        # Case 2c: Single target in form-data
        elif target_value:
            # Use serializer for single creation
            data = {
                'target_value': target_value,
                'notes': request.data.get('notes', ''),
                'is_active': request.data.get('is_active', True)
            }
            # Get testing_type from form-data if provided (single value only)
            testing_type = request.data.get('testing_type')
            if testing_type:
                # Accept single string value only
                if isinstance(testing_type, str) and testing_type in ['white_box', 'grey_box', 'black_box']:
                    data['testing_type'] = testing_type
                elif isinstance(testing_type, list) and len(testing_type) > 0:
                    # If list provided, use first one
                    data['testing_type'] = testing_type[0] if testing_type[0] in ['white_box', 'grey_box', 'black_box'] else None
                else:
                    return Response(
                        {
                            'success': False,
                            'error': 'testing_type must be a single value: white_box, grey_box, or black_box'
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )
            
            # Calculate subnet_count if it's a subnet
            if is_valid_subnet(target_value):
                data['subnet_count'] = get_subnet_count(target_value)
            
            serializer = ScopeCreateSerializer(data=data)
            if serializer.is_valid():
                # Gate: Use current_testing_box parameter if provided
                current_testing_box = request.query_params.get('current_testing_box') or request.data.get('current_testing_box')
                if not serializer.validated_data.get('testing_type'):
                    if current_testing_box:
                        if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                            serializer.validated_data['testing_type'] = current_testing_box
                        else:
                            return Response(
                                {
                                    'success': False,
                                    'error': f'Invalid current_testing_box: {current_testing_box}. Must be white_box, grey_box, or black_box.'
                                },
                                status=status.HTTP_400_BAD_REQUEST
                            )
                    else:
                        # Get admin's testing_type (use first one if list)
                        admin_testing_type = getattr(request.user, 'testing_type', None)
                        if admin_testing_type:
                            if isinstance(admin_testing_type, list) and len(admin_testing_type) > 0:
                                serializer.validated_data['testing_type'] = admin_testing_type[0]
                            elif isinstance(admin_testing_type, str):
                                serializer.validated_data['testing_type'] = admin_testing_type

                        scope = serializer.save(admin=request.user)
                        return Response({
                            'success': True,
                            'message': 'Target created successfully.',
                            'admin_id': str(request.user.id),
                            'admin_email': request.user.email,
                            'data': {
                                '_id': str(scope._id),
                                'target_type': scope.target_type,
                                'target_value': scope.target_value,
                                'notes': scope.notes,
                                'is_active': scope.is_active,
                                'testing_type': scope.testing_type,
                                'subnet_count': scope.subnet_count,
                                'created_at': scope.created_at
                            }
                        }, status=status.HTTP_201_CREATED)
            else:
                return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
        # No valid input provided
        else:
            return Response(
                {
                    'success': False,
                    'error': 'Please provide one of: target_value (JSON or form-data), targets (form-data), or file (form-data).'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
    
    def _handle_file_upload(self, request, uploaded_file):
        """Handle file upload and create targets."""
        extracted_targets = []
        errors = []
        
        # Create file upload record
        file_upload = ScopeFileUpload.objects.create(
            admin=request.user,
            file_name=uploaded_file.name,
            file_size=uploaded_file.size,
            file_type=os.path.splitext(uploaded_file.name)[1].lower()
        )
        
        # Save file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(uploaded_file.name)[1]) as tmp_file:
            for chunk in uploaded_file.chunks():
                tmp_file.write(chunk)
            tmp_file_path = tmp_file.name
        
        try:
            # Check if expand_subnets parameter is provided
            expand_subnets = request.data.get('expand_subnets', 'true').lower() == 'true'
            # Parse file
            extracted_targets = parse_file(tmp_file_path, expand_subnets=expand_subnets)
        except Exception as e:
            errors.append(f"Error parsing file: {str(e)}")
        finally:
            # Clean up temp file
            if os.path.exists(tmp_file_path):
                os.remove(tmp_file_path)
        
        if not extracted_targets and not errors:
            file_upload.delete()  # Delete file record if no targets found
            return Response(
                {
                    'success': False,
                    'error': 'No valid targets found in file. Please ensure the file contains valid IP addresses or URLs.',
                    'errors': errors if errors else None
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if errors and not extracted_targets:
            file_upload.delete()  # Delete file record if parsing failed
            return Response(
                {
                    'success': False,
                    'error': 'Failed to parse file.',
                    'errors': errors
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Update file upload with targets count
        file_upload.targets_count = len(extracted_targets)
        file_upload.save()
        
        return self._create_targets(request, extracted_targets, errors, file_upload)
    
    def _handle_bulk_text(self, request, targets_text):
        """Handle bulk text input and create targets."""
        if not targets_text or not targets_text.strip():
            return Response(
                {
                    'success': False,
                    'error': 'Targets text cannot be empty.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Check if expand_subnets parameter is provided
        expand_subnets = request.data.get('expand_subnets', 'true').lower() == 'true'
        extracted_targets = extract_targets_from_text(targets_text, expand_subnets=expand_subnets)
        
        if not extracted_targets:
            return Response(
                {'error': 'No valid targets found. Please provide valid IP addresses or URLs (one per line).'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        return self._create_targets(request, extracted_targets, [], None)
    
    def _create_targets(self, request, extracted_targets, errors, file_upload=None):
        """Create scope entries from extracted targets."""
        created = []
        skipped = []
        
        # Gate: Get current_testing_box from query params or request data
        current_testing_box = request.query_params.get('current_testing_box') or request.data.get('current_testing_box')
        
        # Get admin's testing_type to use as default (single value only)
        admin_testing_type = getattr(request.user, 'testing_type', None)
        default_testing_type = None
        if admin_testing_type:
            if isinstance(admin_testing_type, list) and len(admin_testing_type) > 0:
                default_testing_type = admin_testing_type[0]  # Use first one
            elif isinstance(admin_testing_type, str):
                default_testing_type = admin_testing_type
        
        # Use current_testing_box if provided, otherwise use default
        final_testing_type = current_testing_box if current_testing_box else default_testing_type
        
        # Validate final_testing_type
        if final_testing_type and final_testing_type not in ['white_box', 'grey_box', 'black_box']:
            return Response(
                {
                    'success': False,
                    'error': f'Invalid testing_type: {final_testing_type}. Must be white_box, grey_box, or black_box.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        for target_data in extracted_targets:
            target_value = target_data['target_value']
            target_type = target_data['target_type']
            
            # Clean target_value - remove /32 suffix if present (individual IPs shouldn't have it)
            clean_target_value = target_value
            if '/' in target_value and target_value.endswith('/32'):
                clean_target_value = target_value.replace('/32', '')
            
            # Get subnet_count ONLY if it's actually a subnet (has CIDR notation, not /32)
            # Individual IPs should NOT have subnet_count
            subnet_count = None
            # Check if it's a real subnet (not /32 which is just a single IP)
            if is_valid_subnet(clean_target_value) and '/' in clean_target_value and not clean_target_value.endswith('/32'):
                # Only set subnet_count for actual subnets (CIDR notation)
                subnet_count = target_data.get('subnet_count')
                if subnet_count is None:
                    subnet_count = get_subnet_count(clean_target_value)
            
            # Use final_testing_type (single value)
            testing_type = final_testing_type
            
            # Check if already exists (use clean value)
            if Scope.objects.filter(admin=request.user, target_value=clean_target_value).exists():
                skipped.append({
                    'target_value': clean_target_value,
                    'target_type': target_type,
                    'reason': 'Already exists'
                })
                continue
            
            try:
                # Ensure target_value is stored as string exactly (no conversion)
                clean_target_value_str = str(clean_target_value).strip()
                
                scope = Scope.objects.create(
                    admin=request.user,
                    target_type=target_type,
                    target_value=clean_target_value_str,  # Store as string exactly
                    subnet_count=subnet_count,  # Will be None for individual IPs
                    testing_type=testing_type,  # Add testing_type
                    file_upload=file_upload
                )
                created.append({
                    '_id': str(scope._id),
                    'target_type': scope.target_type,
                    'target_value': scope.target_value,
                    'testing_type': scope.testing_type,  # Include testing_type in response
                    'subnet_count': scope.subnet_count,
                    'created_at': scope.created_at.isoformat() if scope.created_at else None
                })
            except Exception as e:
                skipped.append({
                    'target_value': target_value,
                    'target_type': target_type,
                    'reason': str(e)
                })
        
        # Determine response message
        if len(created) == 1:
            message = '1 target created successfully.'
        else:
            message = f'{len(created)} targets created successfully.'
        
        if skipped:
            message += f' {len(skipped)} target(s) skipped.'
        
        response_data = {
            'success': True,
            'message': message,
            'admin_id': str(request.user.id),
            'admin_email': request.user.email,
            'created_count': len(created),
            'skipped_count': len(skipped),
            'created': created,
            'skipped': skipped if skipped else None
        }
        
        # Add file upload ID if file was uploaded
        if file_upload:
            response_data['file_upload_id'] = str(file_upload._id)
            response_data['file_name'] = file_upload.file_name
            response_data['file_type'] = file_upload.file_type
        
        if errors:
            response_data['errors'] = errors
        
        return Response(response_data, status=status.HTTP_201_CREATED)


class ScopeListView(generics.ListAPIView):
    """
    List all scope targets for the authenticated admin or a specific admin.
    GET /api/admin/scope/
    Query params:
    - admin_id: Filter by specific admin ID (optional, defaults to authenticated user)
    - target_type: Filter by type (internal_ip, external_ip, web_url, mobile_url, subnet)
    - is_active: Filter by active status (true/false)
    - search: Search in target_value
    - file_upload_id: Filter by file upload ID
    - testing_type: Filter by testing type (white_box, grey_box, black_box) - can be comma-separated
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ScopeListSerializer
    
    def list(self, request, *args, **kwargs):
        """Override list to add proper response message."""
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            response = self.get_paginated_response(serializer.data)
            # Add message to paginated response
            response.data['success'] = True
            response.data['message'] = f'Retrieved {len(serializer.data)} target(s) successfully.'
            return response
        
        serializer = self.get_serializer(queryset, many=True)
        
        # Build message
        count = len(serializer.data)
        admin_id = request.query_params.get('admin_id')
        target_type = request.query_params.get('target_type')
        search = request.query_params.get('search')
        
        message = f'Retrieved {count} target(s) successfully.'
        if admin_id:
            message = f'Retrieved {count} target(s) for admin ID "{admin_id}" successfully.'
        if target_type:
            message = f'Retrieved {count} {target_type} target(s) successfully.'
        if search:
            message = f'Retrieved {count} target(s) matching "{search}" successfully.'
        
        return Response({
            'success': True,
            'message': message,
            'count': count,
            'data': serializer.data
        }, status=status.HTTP_200_OK)
    
    def get_queryset(self):
        # Get admin_id from query params, default to authenticated user
        admin_id = self.request.query_params.get('admin_id')
        
        if admin_id:
            # If admin_id is provided, check if user has permission
            # For now, only allow if it's the same user or user is staff/superuser
            try:
                from users.models import User
                target_admin = User.objects.get(id=admin_id)
                # Only allow if same user or staff/superuser
                if target_admin.id != self.request.user.id and not (self.request.user.is_staff or self.request.user.is_superuser):
                    # Return empty queryset if no permission
                    return Scope.objects.none()
                queryset = Scope.objects.filter(admin=target_admin)
            except User.DoesNotExist:
                return Scope.objects.none()
        else:
            # Default to authenticated user's targets
            queryset = Scope.objects.filter(admin=self.request.user)
        
        # Filter by target_type
        target_type = self.request.query_params.get('target_type')
        if target_type:
            queryset = queryset.filter(target_type=target_type)
        
        # Filter by is_active
        is_active = self.request.query_params.get('is_active')
        if is_active is not None:
            is_active_bool = is_active.lower() == 'true'
            queryset = queryset.filter(is_active=is_active_bool)
        
        # Search in target_value
        search = self.request.query_params.get('search')
        if search:
            queryset = queryset.filter(target_value__icontains=search)
        
        # Filter by file_upload_id
        file_upload_id = self.request.query_params.get('file_upload_id')
        if file_upload_id:
            try:
                file_upload_obj_id = ObjectId(file_upload_id)
                queryset = queryset.filter(file_upload__id=file_upload_obj_id)
            except (InvalidId, TypeError):
                pass  # Invalid ID, ignore filter
        
        # GATE: Filter by current_testing_box (gate mechanism)
        current_testing_box = self.request.query_params.get('current_testing_box')
        if current_testing_box:
            # Validate and filter by single testing box
            if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                queryset = queryset.filter(testing_type=current_testing_box)
            else:
                # Invalid testing box, return empty queryset
                return Scope.objects.none()
        
        # Filter by testing_type (legacy support - single value only now)
        testing_type_param = self.request.query_params.get('testing_type')
        if testing_type_param:
            # Single value only
            if testing_type_param in ['white_box', 'grey_box', 'black_box']:
                queryset = queryset.filter(testing_type=testing_type_param)
        
        return queryset.order_by('-created_at')


class ScopeDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
    Retrieve, update, or delete a scope target.
    GET /api/admin/scope/<id>/
    PUT /api/admin/scope/<id>/
    PATCH /api/admin/scope/<id>/
    DELETE /api/admin/scope/<id>/
    """
    permission_classes = [IsAuthenticated]
    serializer_class = ScopeSerializer
    lookup_field = '_id'
    
    def get_queryset(self):
        queryset = Scope.objects.filter(admin=self.request.user)
        
        # GATE: Filter by current_testing_box if provided
        current_testing_box = self.request.query_params.get('current_testing_box')
        if current_testing_box:
            if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                queryset = queryset.filter(testing_type=current_testing_box)
            else:
                return Scope.objects.none()
        
        return queryset
    
    def get_object(self):
        pk = self.kwargs.get('pk')
        try:
            obj_id = ObjectId(pk)
        except (InvalidId, TypeError):
            from rest_framework.exceptions import NotFound
            raise NotFound("Invalid scope ID")
        
        queryset = self.get_queryset()
        obj = queryset.filter(_id=obj_id).first()
        if not obj:
            from rest_framework.exceptions import NotFound
            raise NotFound("Scope target not found")
        return obj
    
    def retrieve(self, request, *args, **kwargs):
        """GET - Retrieve a single scope target."""
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        # Ensure target_value is a string for the message
        target_value_str = str(instance.target_value) if instance.target_value else "N/A"
        return Response({
            'success': True,
            'message': f'Scope target "{target_value_str}" retrieved successfully.',
            'data': serializer.data
        }, status=status.HTTP_200_OK)
    
    def update(self, request, *args, **kwargs):
        """PUT - Full update of a scope target."""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        old_target_value = instance.target_value
        
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        # Get updated instance
        instance.refresh_from_db()
        
        # Build message based on what was updated
        update_type = "partially updated" if partial else "fully updated"
        target_value_str = str(instance.target_value) if instance.target_value else "N/A"
        message = f'Scope target "{target_value_str}" {update_type} successfully.'
        
        return Response({
            'success': True,
            'message': message,
            'data': serializer.data
        }, status=status.HTTP_200_OK)
    
    def partial_update(self, request, *args, **kwargs):
        """PATCH - Partial update of a scope target."""
        kwargs['partial'] = True
        return self.update(request, *args, **kwargs)
    
    def destroy(self, request, *args, **kwargs):
        """DELETE - Delete a scope target."""
        instance = self.get_object()
        # Ensure target_value is a string before deletion
        target_value = str(instance.target_value) if instance.target_value else "N/A"
        self.perform_destroy(instance)
        
        return Response({
            'success': True,
            'message': f'Scope target "{target_value}" deleted successfully.',
            'deleted_id': str(instance._id)
        }, status=status.HTTP_200_OK)


class ScopeBulkDeleteView(APIView):
    """
    Bulk delete scope targets.
    DELETE /api/admin/scope/bulk-delete/
    
    Body (JSON):
    {
        "ids": ["id1", "id2", ...]  // List of scope IDs to delete
    }
    """
    permission_classes = [IsAuthenticated]
    
    def delete(self, request):
        ids = request.data.get('ids', [])
        
        if not ids:
            return Response(
                {'error': 'No IDs provided.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Convert string IDs to ObjectId
        object_ids = []
        invalid_ids = []
        
        for id_str in ids:
            try:
                object_ids.append(ObjectId(id_str))
            except (InvalidId, TypeError):
                invalid_ids.append(id_str)
        
        if invalid_ids:
            return Response(
                {
                    'error': f'Invalid IDs: {invalid_ids}',
                    'invalid_ids': invalid_ids
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        
        # Build queryset for deletion
        queryset = Scope.objects.filter(
            admin=request.user,
            _id__in=object_ids
        )
        
        # GATE: Filter by current_testing_box if provided
        current_testing_box = request.query_params.get('current_testing_box') or request.data.get('current_testing_box')
        if current_testing_box:
            if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                queryset = queryset.filter(testing_type=current_testing_box)
            else:
                return Response({
                    'success': False,
                    'error': f'Invalid current_testing_box: {current_testing_box}'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Only delete scopes belonging to the authenticated user (and matching gate)
        deleted_count = queryset.delete()[0]
        
        return Response({
            'success': True,
            'message': f'Deleted {deleted_count} target(s).',
            'deleted_count': deleted_count
        }, status=status.HTTP_200_OK)


class ScopeStatsView(APIView):
    """
    Get statistics for scope targets.
    GET /api/admin/scope/stats/
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get admin_id from query params, default to authenticated user
        admin_id = request.query_params.get('admin_id')
        
        # Determine target admin
        if admin_id:
            try:
                from users.models import User
                target_admin = User.objects.get(id=admin_id)
                # Only allow if same user or staff/superuser
                if target_admin.id != request.user.id and not (request.user.is_staff or request.user.is_superuser):
                    return Response(
                        {'error': 'You do not have permission to view statistics for this admin.'},
                        status=status.HTTP_403_FORBIDDEN
                    )
            except User.DoesNotExist:
                return Response(
                    {'error': 'Admin not found.'},
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            target_admin = request.user
        
        # Get base queryset
        base_queryset = Scope.objects.filter(admin=target_admin)
        
        # GATE: Filter by current_testing_box if provided
        current_testing_box = request.query_params.get('current_testing_box')
        if current_testing_box:
            if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                base_queryset = base_queryset.filter(testing_type=current_testing_box)
            else:
                # Invalid testing box, return empty stats
                return Response({
                    'success': True,
                    'message': f'Invalid current_testing_box: {current_testing_box}',
                    'admin_id': str(target_admin.id),
                    'admin_email': target_admin.email,
                    'total_targets': 0,
                    'internal_ips': 0,
                    'external_ips': 0,
                    'web_urls': 0,
                    'mobile_urls': 0,
                    'subnets': 0,
                    'active_targets': 0,
                    'inactive_targets': 0,
                }, status=status.HTTP_200_OK)
        
        # Fetch all records and count in Python to avoid Djongo boolean filter issues
        all_targets = list(base_queryset.values('target_type', 'is_active'))
        
        # Count in Python
        total_targets = len(all_targets)
        internal_ips = sum(1 for t in all_targets if t['target_type'] == 'internal_ip')
        external_ips = sum(1 for t in all_targets if t['target_type'] == 'external_ip')
        web_urls = sum(1 for t in all_targets if t['target_type'] == 'web_url')
        mobile_urls = sum(1 for t in all_targets if t['target_type'] == 'mobile_url')
        subnets = sum(1 for t in all_targets if t['target_type'] in ['internal_subnet', 'external_subnet'])
        active_targets = sum(1 for t in all_targets if t['is_active'] is True)
        inactive_targets = sum(1 for t in all_targets if t['is_active'] is False)
        
        # Build response message
        message = f"Statistics retrieved successfully for admin '{target_admin.email}'."
        if admin_id:
            message = f"Statistics retrieved successfully for admin ID '{admin_id}' ({target_admin.email})."
        
        stats = {
            'success': True,
            'message': message,
            'admin_id': str(target_admin.id),
            'admin_email': target_admin.email,
            'total_targets': total_targets,
            'internal_ips': internal_ips,
            'external_ips': external_ips,
            'web_urls': web_urls,
            'mobile_urls': mobile_urls,
            'subnets': subnets,
            'active_targets': active_targets,
            'inactive_targets': inactive_targets,
        }
        
        serializer = ScopeStatsSerializer(stats)
        return Response(serializer.data, status=status.HTTP_200_OK)


class ScopeByTypeView(APIView):
    """
    Get scope targets grouped by type.
    GET /api/admin/scope/by-type/
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        # Get admin_id from query params, default to authenticated user
        admin_id = request.query_params.get('admin_id')
        
        # Determine target admin
        if admin_id:
            try:
                from users.models import User
                target_admin = User.objects.get(id=admin_id)
                # Only allow if same user or staff/superuser
                if target_admin.id != request.user.id and not (request.user.is_staff or request.user.is_superuser):
                    return Response(
                        {
                            'success': False,
                            'error': 'You do not have permission to view targets for this admin.'
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
            except User.DoesNotExist:
                return Response(
                    {
                        'success': False,
                        'error': 'Admin not found.'
                    },
                    status=status.HTTP_404_NOT_FOUND
                )
        else:
            target_admin = request.user
        
        # Get base queryset (avoid boolean filter by fetching all and filtering in Python)
        base_queryset = Scope.objects.filter(admin=target_admin)
        
        # GATE: Filter by current_testing_box if provided
        current_testing_box = request.query_params.get('current_testing_box')
        if current_testing_box:
            if current_testing_box in ['white_box', 'grey_box', 'black_box']:
                base_queryset = base_queryset.filter(testing_type=current_testing_box)
            else:
                # Invalid testing box, return empty response
                return Response({
                    'success': False,
                    'message': f'Invalid current_testing_box: {current_testing_box}',
                    'error': 'Invalid testing box. Must be white_box, grey_box, or black_box.'
                }, status=status.HTTP_400_BAD_REQUEST)
        
        all_targets = list(base_queryset.values('_id', 'target_type', 'target_value', 'notes', 'created_at', 'subnet_count', 'is_active'))
        
        # Filter active targets and group by type
        active_targets = [t for t in all_targets if t['is_active'] is True]
        
        # Convert ObjectId to string and format data
        def format_target(target):
            return {
                '_id': str(target['_id']),  # Convert ObjectId to string
                'target_value': target['target_value'],
                'notes': target['notes'],
                'subnet_count': target.get('subnet_count'),
                'created_at': target['created_at'].isoformat() if target['created_at'] else None
            }
        
        internal_ips = [format_target(t) for t in active_targets if t['target_type'] == 'internal_ip']
        external_ips = [format_target(t) for t in active_targets if t['target_type'] == 'external_ip']
        web_urls = [format_target(t) for t in active_targets if t['target_type'] == 'web_url']
        mobile_urls = [format_target(t) for t in active_targets if t['target_type'] == 'mobile_url']
        internal_subnets = [format_target(t) for t in active_targets if t['target_type'] == 'internal_subnet']
        external_subnets = [format_target(t) for t in active_targets if t['target_type'] == 'external_subnet']
        
        # Build response message
        message = f"Targets retrieved successfully for admin '{target_admin.email}'."
        if admin_id:
            message = f"Targets retrieved successfully for admin ID '{admin_id}' ({target_admin.email})."
        
        return Response({
            'success': True,
            'message': message,
            'admin_id': str(target_admin.id),
            'admin_email': target_admin.email,
            'internal_ips': internal_ips,
            'external_ips': external_ips,
            'web_urls': web_urls,
            'mobile_urls': mobile_urls,
            'internal_subnets': internal_subnets,
            'external_subnets': external_subnets,
            'counts': {
                'internal_ips': len(internal_ips),
                'external_ips': len(external_ips),
                'web_urls': len(web_urls),
                'mobile_urls': len(mobile_urls),
                'internal_subnets': len(internal_subnets),
                'external_subnets': len(external_subnets),
                'total': len(active_targets)
            }
        }, status=status.HTTP_200_OK)
