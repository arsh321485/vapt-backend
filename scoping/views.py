import logging
from django.utils import timezone
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

from .models import ProjectDetail, TestingMethodology
from .serializers import ProjectDetailSerializer, TestingMethodologySerializer
from users.utils import Util

logger = logging.getLogger(__name__)


class ScopingSubmitView(APIView):
    """
    POST /api/scoping/submit/
    Called when admin clicks "Submit Scoping Form" button.
    Validates both forms are filled, marks as submitted, sends emails.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # Check ProjectDetail exists
        try:
            project_detail = ProjectDetail.objects.get(admin=request.user)
        except ProjectDetail.DoesNotExist:
            return Response(
                {"error": "Project details not found. Please complete Step 1 first."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Check at least one TestingMethodology exists
        methodologies = TestingMethodology.objects.filter(admin=request.user)
        if not methodologies.exists():
            return Response(
                {"error": "Testing methodology not found. Please complete Step 2 first."},
                status=status.HTTP_400_BAD_REQUEST
            )

        # Prevent duplicate email — already submitted
        if project_detail.is_submitted:
            return Response(
                {"message": "Scoping form already submitted.", "already_submitted": True},
                status=status.HTTP_200_OK
            )

        # Mark as submitted and record exact submission time in DB.
        # Using DB (not cache) so all Gunicorn workers see the same value.
        project_detail.is_submitted = True
        project_detail.submitted_at = timezone.now()
        project_detail.save()

        # Send emails
        try:
            Util.send_scoping_sales_email(project_detail, methodologies)
            Util.send_scoping_admin_confirmation_email(
                request.user.email,
                project_detail.organization_name
            )
            logger.info(f"Scoping submit emails sent for {request.user.email}")
        except Exception as e:
            logger.error(f"Scoping submit email failed for {request.user.email}: {str(e)}")

        return Response({
            "message": "Scoping form submitted successfully. Our sales team will contact you soon.",
            "already_submitted": False
        }, status=status.HTTP_200_OK)


class UploadStatusView(APIView):
    """
    GET /api/admin/scoping/upload-status/
    Frontend polls this to check if superadmin has uploaded a report file for this admin.
    Only checks uploads that happened AFTER scoping form was submitted.
    When file is uploaded → frontend redirects to admin login page.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            from upload_report.models import UploadReport

            # Read submission record from DB — works across all Gunicorn workers.
            # NOTE: Djongo cannot parse boolean fields in WHERE clause (known bug),
            # so we filter only by admin and check is_submitted in Python.
            project_detail = ProjectDetail.objects.filter(
                admin=request.user
            ).values('is_submitted', 'submitted_at', 'created_at').first()

            logger.warning(f"[UploadStatus] user={request.user.email} project_detail={project_detail}")

            if not project_detail or not project_detail['is_submitted']:
                logger.warning(f"[UploadStatus] No submitted ProjectDetail found for {request.user.email}")
                return Response({"file_uploaded": False}, status=status.HTTP_200_OK)

            since = project_detail['submitted_at'] or project_detail['created_at']
            logger.warning(f"[UploadStatus] since={since}")

            if since:
                qs = UploadReport.objects.filter(admin=request.user, uploaded_at__gte=since)
                file_uploaded = qs.exists()
                logger.warning(f"[UploadStatus] UploadReport count (gte since)={qs.count()} file_uploaded={file_uploaded}")
            else:
                qs = UploadReport.objects.filter(admin=request.user)
                file_uploaded = qs.exists()
                logger.warning(f"[UploadStatus] UploadReport count (any)={qs.count()} file_uploaded={file_uploaded}")

            # Extra debug: show all reports for this admin
            all_reports = list(UploadReport.objects.filter(admin=request.user).values('_id', 'uploaded_at', 'status'))
            logger.warning(f"[UploadStatus] All UploadReports for this admin: {all_reports}")

        except Exception as e:
            logger.error(f"[UploadStatus] EXCEPTION: {e}", exc_info=True)
            file_uploaded = False

        return Response({
            "file_uploaded": file_uploaded
        }, status=status.HTTP_200_OK)


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
        serializer = TestingMethodologySerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        testing_type = serializer.validated_data.get('testing_type')

        # Check if this testing_type already submitted for this admin
        if TestingMethodology.objects.filter(admin=request.user, testing_type=testing_type).exists():
            return Response(
                {"error": f"Testing methodology for '{testing_type}' already submitted."},
                status=status.HTTP_400_BAD_REQUEST
            )

        methodology = serializer.save(admin=request.user)

        return Response({
            "message": f"Testing methodology for '{testing_type}' saved successfully.",
            "data": serializer.data
        }, status=status.HTTP_201_CREATED)

    def get(self, request):
        testing_type = request.query_params.get('testing_type')

        methodologies = TestingMethodology.objects.filter(admin=request.user).order_by('testing_type')

        if testing_type:
            valid_types = ['black_box', 'grey_box', 'white_box']
            if testing_type not in valid_types:
                return Response(
                    {"error": f"Invalid testing_type. Valid values: {valid_types}"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            methodologies = methodologies.filter(testing_type=testing_type)
            if not methodologies.exists():
                return Response(
                    {"error": f"Testing methodology for '{testing_type}' not found."},
                    status=status.HTTP_404_NOT_FOUND
                )
            serializer = TestingMethodologySerializer(methodologies.first())
            return Response({
                "message": f"Testing methodology for '{testing_type}' retrieved successfully.",
                "data": serializer.data
            }, status=status.HTTP_200_OK)

        if not methodologies.exists():
            return Response(
                {"error": "Testing methodology not found."},
                status=status.HTTP_404_NOT_FOUND
            )
        serializer = TestingMethodologySerializer(methodologies, many=True)
        return Response({
            "message": "Testing methodologies retrieved successfully.",
            "data": serializer.data
        }, status=status.HTTP_200_OK)
