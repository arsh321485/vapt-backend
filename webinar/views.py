import threading
import logging
from datetime import datetime

import pymongo
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

from vaptfix.mongo_client import MongoContext
from .serializers import WebinarRegistrationSerializer, TEAM_SIZE_CHOICES

logger = logging.getLogger(__name__)

WEBINAR_COLLECTION = "webinar"

_index_ensured = False
_index_lock = threading.Lock()


def _get_webinar_collection():
    """Registrations live in the shared "vaptfix" database, "webinar" collection."""
    with MongoContext() as db:
        collection = db[WEBINAR_COLLECTION]

    global _index_ensured
    if not _index_ensured:
        with _index_lock:
            if not _index_ensured:
                try:
                    collection.create_index(
                        "work_email", unique=True, name="idx_webinar_email_unique"
                    )
                except Exception as e:
                    logger.warning("Webinar index ensure skipped due to error: %s", e)
                _index_ensured = True

    return collection


class WebinarFormOptionsAPIView(APIView):
    """
    GET /api/webinar/form-options/

    Public endpoint — returns the "Team Size Attending" dropdown options
    for the webinar registration form.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        return Response(
            {"team_size_options": TEAM_SIZE_CHOICES},
            status=status.HTTP_200_OK,
        )


class WebinarRegistrationCreateAPIView(APIView):
    """
    POST /api/webinar/register/

    Public endpoint — submits a webinar registration. No authentication
    required. Data is stored in the "vaptfix" MongoDB database, "webinar"
    collection.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = WebinarRegistrationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        collection = _get_webinar_collection()

        if collection.find_one({"work_email": serializer.validated_data["work_email"]}):
            return Response(
                {"work_email": ["This email is already registered for the webinar."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        doc = {
            **serializer.validated_data,
            "registered_at": datetime.utcnow(),
        }

        try:
            result = collection.insert_one(doc)
        except pymongo.errors.DuplicateKeyError:
            return Response(
                {"work_email": ["This email is already registered for the webinar."]},
                status=status.HTTP_400_BAD_REQUEST,
            )

        return Response(
            {
                "message": "Thank you! Your webinar registration has been submitted successfully.",
                "id": str(result.inserted_id),
            },
            status=status.HTTP_201_CREATED,
        )
