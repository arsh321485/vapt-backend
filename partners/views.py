from datetime import datetime

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny

from vaptfix.mongo_client import MongoContext
from location.serializers import VALID_COUNTRIES
from .serializers import (
    PartnerApplicationSerializer,
    COMPANY_SIZE_CHOICES,
    PARTNER_TYPE_CHOICES,
    COUNTRY_CALLING_CODES,
)

PARTNERS_COLLECTION = "partners"


class PartnerFormOptionsAPIView(APIView):
    """
    GET /api/partners/form-options/

    Public endpoint — returns the dropdown options for the Partners page
    form (countries, company size ranges, partner types) in one call.
    """
    permission_classes = [AllowAny]

    def get(self, request):
        phone_country_codes = [
            {"country": country, "code": code}
            for country, code in sorted(COUNTRY_CALLING_CODES.items())
        ]
        return Response(
            {
                "countries": sorted(list(VALID_COUNTRIES)),
                "company_size_options": COMPANY_SIZE_CHOICES,
                "partner_type_options": PARTNER_TYPE_CHOICES,
                "phone_country_codes": phone_country_codes,
            },
            status=status.HTTP_200_OK,
        )


class PartnerApplicationCreateAPIView(APIView):
    """
    POST /api/partners/apply/

    Public endpoint — submits a Partner Program application from the
    marketing site's Partners page. No authentication required.
    """
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PartnerApplicationSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        doc = {
            **serializer.validated_data,
            "status": "pending",
            "submitted_at": datetime.utcnow(),
        }

        with MongoContext() as db:
            result = db[PARTNERS_COLLECTION].insert_one(doc)

        return Response(
            {
                "message": "Partner application submitted successfully",
                "id": str(result.inserted_id),
            },
            status=status.HTTP_201_CREATED,
        )
