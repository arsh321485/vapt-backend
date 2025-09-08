from rest_framework import generics, permissions, status,filters
from rest_framework.response import Response
from bson import ObjectId
from django.shortcuts import get_object_or_404
from .models import UserDetail
from .serializers import UserDetailSerializer, UserDetailCreateSerializer


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
    serializer_class = UserDetailCreateSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        obj_id = ObjectId(detail_id)
        return get_object_or_404(UserDetail, _id=obj_id)


class UserDetailDeleteView(generics.DestroyAPIView):
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        detail_id = self.kwargs.get("detail_id")
        obj_id = ObjectId(detail_id)
        return get_object_or_404(UserDetail, _id=obj_id)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "User detail deleted successfully"},
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