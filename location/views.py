from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from .serializers import VALID_COUNTRIES
from bson import ObjectId
from django.shortcuts import get_object_or_404
from .models import Location
from .serializers import (
    LocationSerializer,
    LocationCreateSerializer,
    LocationUpdateSerializer
)
import logging
from .permissions import IsOwnerOrAdmin

logger = logging.getLogger(__name__)

class LocationCreateView(generics.CreateAPIView):
    serializer_class = LocationCreateSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)

        if not serializer.is_valid():
            # ✅ THIS sends exact validation error to frontend
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

        location = serializer.save()
        location_data = LocationSerializer(location).data

        return Response(
            {
                "message": "Location created successfully",
                "location": location_data
            },
            status=status.HTTP_201_CREATED
        )


class LocationListView(generics.ListAPIView):
    """List all locations or locations for specific admin"""
    serializer_class = LocationSerializer
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        queryset = Location.objects.all().order_by('-created_at')
        admin_id = self.request.query_params.get('admin_id')
        
        if admin_id:
            queryset = queryset.filter(admin__id=admin_id)
        
        return queryset
    
    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)
            
            return Response({
                "message": "Locations retrieved successfully",
                "count": len(serializer.data),
                "locations": serializer.data
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f"Location list error: {str(e)}")
            return Response({
                "error": "Failed to retrieve locations"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LocationDetailView(generics.RetrieveAPIView):
    serializer_class = LocationSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        location_id = self.kwargs.get('location_id')
        try:
            obj_id = ObjectId(location_id)  # convert string → ObjectId
        except Exception:
            logger.error(f"Invalid ObjectId format: {location_id}")
            raise
        return get_object_or_404(Location, _id=obj_id)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response({
            "message": "Location retrieved successfully",
            "location": serializer.data
        }, status=status.HTTP_200_OK)


class LocationUpdateView(generics.UpdateAPIView):
    """
    Update a Location's location_name.
    URL: PATCH /api/locations/<location_id>/
    """
    serializer_class = LocationUpdateSerializer
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    def get_object(self):
        location_id = self.kwargs.get('location_id')
        # Validate and convert to ObjectId
        try:
            obj_id = ObjectId(location_id)
        except Exception as e:
            logger.error(f"Invalid ObjectId format: {location_id} - {e}")
            # Raise 404 so API doesn't leak internal detail
            raise
        # Use _id field because that's your primary key
        return get_object_or_404(Location, _id=obj_id)

    def patch(self, request, *args, **kwargs):
        return self.partial_update(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        # allow full updates if desired (but serializer only has 'location_name')
        return self.update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            # permission check
            self.check_object_permissions(request, instance)

            serializer = self.get_serializer(instance, data=request.data, partial=True, context={'request': request})
            serializer.is_valid(raise_exception=True)
            location = serializer.save()

            # Return full serialized representation (including admin info if needed)
            full_data = LocationSerializer(location).data
            return Response({
                "message": "Location updated successfully",
                "location": full_data
            }, status=status.HTTP_200_OK)
        except Location.DoesNotExist:
            return Response({"error": "Location not found"}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.exception("Error updating location")
            # More helpful error if serializer provided details will already be raised above
            return Response({"error": "Failed to update location"}, status=status.HTTP_400_BAD_REQUEST)

class LocationDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = LocationSerializer  # for retrieve
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    def get_object(self):
        location_id = self.kwargs.get('location_id')
        try:
            obj_id = ObjectId(location_id)
        except Exception:
            logger.error(f"Invalid ObjectId format: {location_id}")
            raise
        return get_object_or_404(Location, _id=obj_id)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response({
            "message": "Location deleted successfully"
        }, status=status.HTTP_200_OK)
        
        
class LocationListByAdminView(generics.ListAPIView):
    """List all locations for a specific admin"""
    serializer_class = LocationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        admin_id = self.kwargs.get('admin_id')  # get admin_id from URL
        return Location.objects.filter(admin__id=admin_id).order_by('-created_at')

    def list(self, request, *args, **kwargs):
        try:
            queryset = self.get_queryset()
            serializer = self.get_serializer(queryset, many=True)

            return Response({
                "message": "Locations retrieved successfully",
                "count": len(serializer.data),
                "locations": serializer.data
            }, status=status.HTTP_200_OK)

        except Exception as e:
            logger.error(f"Location list error: {str(e)}")
            return Response({
                "error": "Failed to retrieve locations"
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        

class CountryListView(APIView):
    permission_classes = [permissions.AllowAny]  # or IsAuthenticated if required

    def get(self, request):
        countries = sorted(list(VALID_COUNTRIES))  # Sorted alphabetically
        return Response({
            "message": "Country list retrieved successfully",
            "count": len(countries),
            "countries": countries
        }, status=status.HTTP_200_OK)