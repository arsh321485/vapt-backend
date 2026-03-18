import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from .models import ProjectDetail, TestingMethodology
from .serializers import ProjectDetailSerializer, TestingMethodologySerializer
from users.utils import Util

logger = logging.getLogger(__name__)


class ProjectDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if ProjectDetail.objects.filter(admin=request.user).exists():
            return Response(
                {"error": "Project details already submitted."},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = ProjectDetailSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        serializer.save(admin=request.user)
        return Response({
            "message": "Project details saved successfully.",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)

    def get(self, request):
        try:
            detail = ProjectDetail.objects.get(admin=request.user)
        except ProjectDetail.DoesNotExist:
            return Response(
                {"error": "Project details not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = ProjectDetailSerializer(detail)
        return Response({
            "message": "Project details retrieved successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)


class TestingMethodologyView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        if TestingMethodology.objects.filter(admin=request.user).exists():
            return Response(
                {"error": "Testing methodology already submitted."},
                status=status.HTTP_400_BAD_REQUEST
            )
        serializer = TestingMethodologySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        methodology = serializer.save(admin=request.user)

        # Send emails after both forms are submitted
        try:
            project_detail = ProjectDetail.objects.get(admin=request.user)
            Util.send_scoping_sales_email(project_detail, methodology)
            Util.send_scoping_admin_confirmation_email(
                request.user.email,
                project_detail.organization_name
            )
        except ProjectDetail.DoesNotExist:
            logger.warning(f"No project detail found for {request.user.email} on methodology submit")
        except Exception as e:
            logger.error(f"Scoping email failed for {request.user.email}: {str(e)}")

        return Response({
            "message": "Testing methodology saved successfully.",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)

    def get(self, request):
        try:
            methodology = TestingMethodology.objects.get(admin=request.user)
        except TestingMethodology.DoesNotExist:
            return Response(
                {"error": "Testing methodology not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = TestingMethodologySerializer(methodology)
        return Response({
            "message": "Testing methodology retrieved successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
