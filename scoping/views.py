import datetime as _dt
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
        def _fmt_seconds(seconds):
            sec = max(0, int(seconds or 0))
            mins, rem = divmod(sec, 60)
            if mins > 0:
                return f"{mins} min {rem} sec"
            return f"{rem} sec"

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
            else:
                qs = UploadReport.objects.filter(admin=request.user)

            reports = list(qs.order_by("uploaded_at"))
            file_uploaded = len(reports) > 0
            logger.warning(f"[UploadStatus] UploadReport count={len(reports)} file_uploaded={file_uploaded}")

            if not file_uploaded:
                return Response({"file_uploaded": False}, status=status.HTTP_200_OK)

            processing_started_at = reports[0].uploaded_at

            # File exists — now check if all vulnerability cards are generated
            try:
                from vaptfix.mongo_client import get_shared_client, get_shared_db

                mongo_client = get_shared_client()
                db = get_shared_db(mongo_client)

                # Check each uploaded report's card generation status
                all_cards_ready = True
                total_reports = len(reports)
                ready_reports = 0
                total_vulns = 0
                generated_cards = 0
                total_upload_processing_seconds = 0
                cards_started_at = None

                for report in reports:
                    report_id = str(report._id)

                    # Get nessus report from MongoDB (includes timing fields for ETA)
                    nessus_doc = db["nessus_reports"].find_one(
                        {"report_id": report_id},
                        {"total_vulnerabilities": 1, "report_type": 1, "cards_generation_complete": 1,
                         "upload_processing_seconds": 1, "cards_generation_started_at": 1}
                    )

                    if not nessus_doc:
                        # Document not yet created — agent still initializing
                        all_cards_ready = False
                        break

                    # Accumulate timing data
                    total_upload_processing_seconds += int(nessus_doc.get("upload_processing_seconds") or 0)
                    if cards_started_at is None:
                        cards_started_at = nessus_doc.get("cards_generation_started_at")

                    report_total_vulns = int(nessus_doc.get("total_vulnerabilities", 0) or 0)
                    total_vulns += report_total_vulns

                    # Check completion flag set by _auto_generate_cards_bg
                    if nessus_doc.get("cards_generation_complete", False):
                        logger.warning(f"[UploadStatus] report_id={report_id} cards_generation_complete=True")
                        ready_reports += 1
                        if report_total_vulns > 0:
                            generated_cards += report_total_vulns
                        continue

                    # Flag not set — fallback: check if any cards exist (uploaded before this fix)
                    cards_count = db["vulnerability_cards"].count_documents({"report_id": report_id})
                    logger.warning(f"[UploadStatus] report_id={report_id} cards_generation_complete=False, cards_count={cards_count}")
                    generated_cards += cards_count

                    if report_total_vulns > 0 and cards_count >= report_total_vulns:
                        # All cards generated — mark as complete so future checks are faster
                        db["nessus_reports"].update_one(
                            {"report_id": report_id},
                            {"$set": {"cards_generation_complete": True}}
                        )
                        ready_reports += 1
                        continue

                    # No flag, no cards — still generating
                    all_cards_ready = False
                    break

                agent_eta_seconds = max(45, 45 + (total_vulns * 2))
                estimated_total_seconds = total_upload_processing_seconds + agent_eta_seconds

                # Elapsed: use cards_generation_started_at (naive UTC from MongoDB) to avoid
                # timezone-aware vs naive mismatch that caused negative elapsed → 630 min bug
                if cards_started_at:
                    elapsed_seconds = max(0, int((_dt.datetime.utcnow() - cards_started_at).total_seconds()))
                elif processing_started_at:
                    # Fallback: strip tzinfo to compare both as naive UTC
                    _started = processing_started_at.replace(tzinfo=None) if processing_started_at.tzinfo else processing_started_at
                    elapsed_seconds = max(0, int((_dt.datetime.utcnow() - _started).total_seconds()))
                else:
                    elapsed_seconds = 0

                remaining_seconds = max(0, estimated_total_seconds - elapsed_seconds)

                if not all_cards_ready:
                    return Response({
                        "file_uploaded": False,
                        "cards_generating": True,
                        "reports_total": total_reports,
                        "reports_ready": ready_reports,
                        "cards_total": total_vulns,
                        "cards_generated": generated_cards,
                        "processing_started_at": processing_started_at,
                        "elapsed_seconds": elapsed_seconds,
                        "elapsed_time_text": _fmt_seconds(elapsed_seconds),
                        "estimated_total_seconds": estimated_total_seconds,
                        "estimated_total_text": _fmt_seconds(estimated_total_seconds),
                        "remaining_seconds": remaining_seconds,
                        "remaining_time_text": _fmt_seconds(remaining_seconds),
                    }, status=status.HTTP_200_OK)

            except Exception as card_err:
                logger.error(f"[UploadStatus] Card check error: {card_err}", exc_info=True)
                # If card check fails, don't block — allow redirect

        except Exception as e:
            logger.error(f"[UploadStatus] EXCEPTION: {e}", exc_info=True)
            file_uploaded = False

        return Response({
            "file_uploaded": file_uploaded,
            "processing_started_at": processing_started_at if file_uploaded else None,
            "elapsed_seconds": elapsed_seconds if file_uploaded else 0,
            "elapsed_time_text": _fmt_seconds(elapsed_seconds) if file_uploaded else "0 sec",
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
