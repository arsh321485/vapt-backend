from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from bson import ObjectId
from django.shortcuts import get_object_or_404
from .models import RiskCriteria
from .serializers import (
    RiskCriteriaSerializer,
    RiskCriteriaCreateSerializer,
    RiskCriteriaUpdateSerializer,
)
import logging

logger = logging.getLogger(__name__)


class RiskCriteriaCreateView(generics.CreateAPIView):
    serializer_class = RiskCriteriaCreateSerializer
    permission_classes = [IsAuthenticated]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        # admin is always the authenticated user — not taken from request body
        risk_criteria = serializer.save(admin=request.user)
        data = RiskCriteriaSerializer(risk_criteria).data
        return Response(
            {"message": "Risk Criteria created successfully", "risk_criteria": data},
            status=status.HTTP_201_CREATED,
        )


class RiskCriteriaListView(generics.ListAPIView):
    serializer_class = RiskCriteriaSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # Always filter by the authenticated admin — no query param needed
        return RiskCriteria.objects.filter(admin=self.request.user).order_by('-created_at')

    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        serializer = self.get_serializer(queryset, many=True)
        return Response(
            {
                "message": "Risk Criteria retrieved successfully",
                "count": len(serializer.data),
                "risk_criteria": serializer.data,
            },
            status=status.HTTP_200_OK,
        )


class RiskCriteriaDetailView(generics.RetrieveAPIView):
    serializer_class = RiskCriteriaSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        risk_id = self.kwargs.get('risk_id')
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        # Filter by both _id AND authenticated admin
        return get_object_or_404(RiskCriteria, _id=obj_id, admin=self.request.user)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
            {"message": "Risk Criteria retrieved successfully", "risk_criteria": serializer.data},
            status=status.HTTP_200_OK,
        )


class RiskCriteriaUpdateView(generics.UpdateAPIView):
    serializer_class = RiskCriteriaUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        risk_id = self.kwargs.get('risk_id')
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        # Filter by both _id AND authenticated admin
        return get_object_or_404(RiskCriteria, _id=obj_id, admin=self.request.user)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        risk_criteria = serializer.save()
        data = RiskCriteriaSerializer(risk_criteria).data
        return Response(
            {"message": "Risk Criteria updated successfully", "risk_criteria": data},
            status=status.HTTP_200_OK,
        )


class RiskCriteriaDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    def get_object(self):
        risk_id = self.kwargs.get('risk_id')
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        # Filter by both _id AND authenticated admin
        return get_object_or_404(RiskCriteria, _id=obj_id, admin=self.request.user)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Risk Criteria deleted successfully"},
            status=status.HTTP_200_OK,
        )
