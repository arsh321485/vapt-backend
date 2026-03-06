from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from bson import ObjectId
from django.shortcuts import get_object_or_404
from django.http import Http404
from .models import RiskCriteria
from .serializers import (
    RiskCriteriaSerializer,
    RiskCriteriaCreateSerializer,
    RiskCriteriaUpdateSerializer,
)
import logging
import calendar
import re
from datetime import date, timedelta

logger = logging.getLogger(__name__)


def parse_days(value):
    """
    Parse values like: "1", "2", "day 1", "day 3", "1 week", "2 weeks", "1 week 2 days"
    Returns total number of days as int, or raises ValueError.
    """
    if value is None:
        raise ValueError("Empty value")

    value = str(value).strip().lower()

    # Pure integer: "2", "7"
    if value.isdigit():
        return int(value)

    total_days = 0
    matched = False

    # Match weeks: "1 week", "2 weeks"
    week_match = re.search(r'(\d+)\s*week', value)
    if week_match:
        total_days += int(week_match.group(1)) * 7
        matched = True

    # Match days: "day 1", "1 day", "3 days"
    day_match = re.search(r'(\d+)\s*day|day\s*(\d+)', value)
    if day_match:
        num = day_match.group(1) or day_match.group(2)
        total_days += int(num)
        matched = True

    if not matched:
        raise ValueError(f"Cannot parse day value: '{value}'")

    return total_days


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

        obj = get_object_or_404(RiskCriteria, _id=obj_id)
        if str(obj.admin_id) != str(self.request.user.id):
            raise Http404
        return obj

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

        obj = get_object_or_404(RiskCriteria, _id=obj_id)
        if str(obj.admin_id) != str(self.request.user.id):
            raise Http404
        return obj

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

        obj = get_object_or_404(RiskCriteria, _id=obj_id)
        if str(obj.admin_id) != str(self.request.user.id):
            raise Http404
        return obj

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Risk Criteria deleted successfully"},
            status=status.HTTP_200_OK,
        )


class RiskCriteriaCalendarView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, risk_id, *args, **kwargs):
        # Validate and fetch risk criteria
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        risk = get_object_or_404(RiskCriteria, pk=obj_id)
        if str(risk.admin_id) != str(request.user.id):
            raise Http404

        # Parse day values — supports "2", "day 3", "1 week", "2 weeks", etc.
        try:
            critical_days = parse_days(risk.critical)
            high_days = parse_days(risk.high)
            medium_days = parse_days(risk.medium)
            low_days = parse_days(risk.low)
        except (ValueError, TypeError) as e:
            return Response(
                {"message": f"Risk criteria day values are invalid: {e}"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # base_date = updated_at if criteria was updated, else created_at
        base_date = (risk.updated_at or risk.created_at).date()

        # Calculate deadline dates
        deadlines = {
            "critical": {"days": critical_days, "deadline_date": str(base_date + timedelta(days=critical_days))},
            "high":     {"days": high_days,     "deadline_date": str(base_date + timedelta(days=high_days))},
            "medium":   {"days": medium_days,   "deadline_date": str(base_date + timedelta(days=medium_days))},
            "low":      {"days": low_days,       "deadline_date": str(base_date + timedelta(days=low_days))},
        }

        # Parse requested month (default: current month)
        month_param = request.query_params.get("month")
        try:
            if month_param:
                year, month = map(int, month_param.split("-"))
            else:
                today = date.today()
                year, month = today.year, today.month
        except (ValueError, AttributeError):
            return Response(
                {"message": "Invalid month format. Use YYYY-MM (e.g. 2026-03)"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Build deadline date -> severity mapping
        deadline_map = {}
        for severity, info in deadlines.items():
            d = info["deadline_date"]
            deadline_map.setdefault(d, []).append(severity)

        # Build full calendar for requested month
        num_days = calendar.monthrange(year, month)[1]
        days = []
        for day in range(1, num_days + 1):
            day_str = str(date(year, month, day))
            days.append({
                "date": day_str,
                "severities": deadline_map.get(day_str, []),
            })

        return Response(
            {
                "message": "Calendar data retrieved successfully",
                "risk_criteria_id": str(risk._id),
                "base_date": str(base_date),
                "deadlines": deadlines,
                "calendar": {
                    "month": f"{year:04d}-{month:02d}",
                    "days": days,
                },
            },
            status=status.HTTP_200_OK,
        )
