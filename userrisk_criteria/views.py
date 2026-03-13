from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from django.http import Http404
from bson import ObjectId
import logging
import calendar
import re
from datetime import date, timedelta

from risk_criteria.models import RiskCriteria
from risk_criteria.serializers import RiskCriteriaSerializer, RiskCriteriaUpdateSerializer
from users_details.models import UserDetail

logger = logging.getLogger(__name__)


def _get_admin_for_user(request_user):
    """Return the admin User for the logged-in team member, or None."""
    detail = UserDetail.objects.filter(email=request_user.email).first()
    if not detail or not detail.admin:
        return None
    return detail.admin


def parse_days(value):
    if value is None:
        raise ValueError("Empty value")
    value = str(value).strip().lower()
    if value.isdigit():
        return int(value)
    total_days = 0
    matched = False
    week_match = re.search(r'(\d+)\s*week', value)
    if week_match:
        total_days += int(week_match.group(1)) * 7
        matched = True
    day_match = re.search(r'(\d+)\s*day|day\s*(\d+)', value)
    if day_match:
        num = day_match.group(1) or day_match.group(2)
        total_days += int(num)
        matched = True
    if not matched:
        raise ValueError(f"Cannot parse day value: '{value}'")
    return total_days


class UserRiskCriteriaListView(generics.ListAPIView):
    serializer_class = RiskCriteriaSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        admin = _get_admin_for_user(self.request.user)
        if not admin:
            return RiskCriteria.objects.none()
        return RiskCriteria.objects.filter(admin_id=str(admin.id)).order_by('-created_at')

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


class UserRiskCriteriaDetailView(generics.RetrieveAPIView):
    serializer_class = RiskCriteriaSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        risk_id = self.kwargs.get('risk_id')
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        admin = _get_admin_for_user(self.request.user)
        if not admin:
            raise Http404

        try:
            obj = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404

        if str(obj.admin_id).strip() != str(admin.id).strip():
            logger.warning(
                f"User {self.request.user.email} tried to access risk {risk_id} "
                f"belonging to admin {obj.admin_id}, their admin is {admin.id}"
            )
            raise Http404
        return obj

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(
            {"message": "Risk Criteria retrieved successfully", "risk_criteria": serializer.data},
            status=status.HTTP_200_OK,
        )


class UserRiskCriteriaUpdateView(generics.UpdateAPIView):
    serializer_class = RiskCriteriaUpdateSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        risk_id = self.kwargs.get('risk_id')
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        admin = _get_admin_for_user(self.request.user)
        if not admin:
            raise Http404

        try:
            obj = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404

        if str(obj.admin_id).strip() != str(admin.id).strip():
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


class UserRiskCriteriaDeleteView(generics.DestroyAPIView):
    permission_classes = [IsAuthenticated]

    def get_object(self):
        risk_id = self.kwargs.get('risk_id')
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        admin = _get_admin_for_user(self.request.user)
        if not admin:
            raise Http404

        try:
            obj = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404

        if str(obj.admin_id).strip() != str(admin.id).strip():
            raise Http404
        return obj

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Risk Criteria deleted successfully"},
            status=status.HTTP_200_OK,
        )


class UserRiskCriteriaCalendarView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, risk_id, *args, **kwargs):
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        admin = _get_admin_for_user(request.user)
        if not admin:
            raise Http404

        try:
            risk = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404

        if str(risk.admin_id).strip() != str(admin.id).strip():
            raise Http404

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

        base_date = (risk.updated_at or risk.created_at).date()
        today = date.today()

        def _remaining(deadline_date):
            delta = (deadline_date - today).days
            if delta < 0:
                return {"days": abs(delta), "status": "overdue"}
            weeks, days = divmod(delta, 7)
            if weeks > 0 and days > 0:
                label = f"{weeks} week{'s' if weeks > 1 else ''} {days} day{'s' if days > 1 else ''}"
            elif weeks > 0:
                label = f"{weeks} week{'s' if weeks > 1 else ''}"
            else:
                label = f"{days} day{'s' if days > 1 else ''}"
            return {"days": delta, "label": label, "status": "active"}

        deadlines = {}
        for severity, n_days in [("critical", critical_days), ("high", high_days),
                                  ("medium", medium_days), ("low", low_days)]:
            deadline_date = base_date + timedelta(days=n_days)
            remaining = _remaining(deadline_date)
            deadlines[severity] = {
                "days":            n_days,
                "deadline_date":   str(deadline_date),
                "remaining_days":  remaining["days"],
                "remaining_label": remaining.get("label", "Overdue"),
                "status":          remaining["status"],
            }

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

        deadline_map = {}
        for severity, info in deadlines.items():
            d = info["deadline_date"]
            deadline_map.setdefault(d, []).append(severity)

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
