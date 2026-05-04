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
from datetime import date, timedelta, datetime, timezone
from vaptfix.mongo_client import MongoContext

logger = logging.getLogger(__name__)
TIMELINE_EXTENSION_COLLECTION = "timeline_extension_requests"


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

def _normalize_severity(value: str):
    sev = (value or "").strip().lower()
    if sev.startswith("crit"):
        return "critical"
    if sev.startswith("high"):
        return "high"
    if sev.startswith("med"):
        return "medium"
    if sev.startswith("low"):
        return "low"
    return None

def _remaining_from_base(base_datetime, configured_days, now_utc):
    """
    Real-time countdown by elapsed 24h blocks from base_datetime.
    - 0 to <24h elapsed: remaining stays as configured_days
    - at 24h elapsed: remaining decrements by 1
    """
    elapsed_seconds = (now_utc - base_datetime).total_seconds()
    elapsed_days = int(max(0, elapsed_seconds // 86400))
    remaining_days = configured_days - elapsed_days

    if remaining_days < 0:
        overdue_days = abs(remaining_days)
        return {"remaining_days": overdue_days, "remaining_label": "Overdue", "status": "overdue"}

    weeks, days = divmod(remaining_days, 7)
    if weeks > 0 and days > 0:
        label = f"{weeks} week{'s' if weeks > 1 else ''} {days} day{'s' if days > 1 else ''}"
    elif weeks > 0:
        label = f"{weeks} week{'s' if weeks > 1 else ''}"
    else:
        label = f"{days} day{'s' if days != 1 else ''}"
    return {"remaining_days": remaining_days, "remaining_label": label, "status": "active"}


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
        # Use explicit admin_id string to avoid djongo FK resolution issues
        return RiskCriteria.objects.filter(admin_id=str(self.request.user.id)).order_by('-created_at')

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

        try:
            obj = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404
        if str(obj.admin_id).strip() != str(self.request.user.id).strip():
            logger.warning(f"admin_id mismatch: obj.admin_id={obj.admin_id!r} user.id={self.request.user.id!r}")
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

        try:
            obj = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404
        if str(obj.admin_id).strip() != str(self.request.user.id).strip():
            raise Http404
        return obj

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        risk_criteria = serializer.save()

        try:
            from notifications.utils import create_notification
            _rc_meta = {
                "updated_criteria": {
                    "critical": risk_criteria.critical,
                    "high":     risk_criteria.high,
                    "medium":   risk_criteria.medium,
                    "low":      risk_criteria.low,
                }
            }
            _title = "Deadline Updated: Risk Criteria Revised"
            _msg   = (
                "[Deadline Updated] The deadline configuration for your vulnerability risk criteria "
                "has been revised. Deadlines for all active vulnerabilities may be affected. "
                f"Critical: {risk_criteria.critical}, High: {risk_criteria.high}, "
                f"Medium: {risk_criteria.medium}, Low: {risk_criteria.low}."
            )
            create_notification(request.user, 'admin', 'deadline_updated', _title, _msg, _rc_meta)
            create_notification(request.user, 'user',  'deadline_updated', _title, _msg, _rc_meta, recipient_email='')
        except Exception:
            pass

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

        try:
            obj = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404
        if str(obj.admin_id).strip() != str(self.request.user.id).strip():
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

        try:
            risk = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404
        if str(risk.admin_id).strip() != str(request.user.id).strip():
            logger.warning(f"admin_id mismatch: risk.admin_id={risk.admin_id!r} user.id={request.user.id!r}")
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

        # base_datetime = updated_at if criteria was updated, else created_at (full datetime for real-time countdown)
        base_datetime = risk.updated_at or risk.created_at
        if base_datetime.tzinfo is None:
            base_datetime = base_datetime.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        # Calculate deadline dates with remaining days
        deadlines = {}
        for severity, n_days in [("critical", critical_days), ("high", high_days),
                                  ("medium", medium_days), ("low", low_days)]:
            deadline_date = (base_datetime + timedelta(days=n_days)).date()
            remaining = _remaining_from_base(base_datetime, n_days, now)
            deadlines[severity] = {
                "days":           n_days,
                "deadline_date":  str(deadline_date),
                "remaining_days": remaining["remaining_days"],
                "remaining_label": remaining["remaining_label"],
                "status":         remaining["status"],
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

        # Add approved extension events (team-wise)
        team_filter = (request.query_params.get("team") or "").strip().lower()
        severity_filter = (request.query_params.get("severity") or "").strip().lower()
        extension_events = []
        with MongoContext() as db:
            ext_query = {"admin_id": str(request.user.id), "status": "approved"}
            report_id = (request.query_params.get("report_id") or "").strip()
            if report_id:
                ext_query["report_id"] = report_id

            seen = set()
            for req in db[TIMELINE_EXTENSION_COLLECTION].find(ext_query).sort("request_date", -1):
                severity = _normalize_severity(req.get("severity"))
                team_name = (req.get("team_name") or "").strip()
                if not severity:
                    continue
                if severity_filter and _normalize_severity(severity_filter) != severity:
                    continue
                if team_filter and team_name.lower() != team_filter:
                    continue

                if severity == "critical":
                    base_days = critical_days
                elif severity == "high":
                    base_days = high_days
                elif severity == "medium":
                    base_days = medium_days
                elif severity == "low":
                    base_days = low_days
                else:
                    continue

                ext_days = int(req.get("requested_extension_days") or 0)
                effective_days = int(req.get("effective_deadline_days") or (base_days + ext_days))
                event_date = (base_datetime + timedelta(days=effective_days)).date()
                event_date_str = str(event_date)
                dedup_key = (
                    severity,
                    team_name.lower(),
                    (req.get("asset") or "").strip().lower(),
                    (req.get("vulnerability_name") or "").strip().lower(),
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)

                event = {
                    "request_id": str(req.get("_id")),
                    "severity": severity,
                    "title": f"{severity.title()} Level Deadline - {team_name or 'Team'}",
                    "assigned_to_team": team_name,
                    "asset": req.get("asset"),
                    "vulnerability_name": req.get("vulnerability_name"),
                    "status": req.get("status", "approved"),
                    "due": event_date_str,
                    "extended_by_days": ext_days,
                    "requested_date": str(req.get("request_date")) if req.get("request_date") else None,
                    "historical_detail": {
                        "vulnerability_identified": req.get("request_date"),
                        "assigned_to_team": team_name,
                        "remediation_in_progress_due": event_date_str,
                    },
                    "extension_requested": {
                        "reason": req.get("reason") or "",
                        "note": f"{ext_days} days extension granted" if ext_days > 0 else "No extension requested"
                    }
                }
                extension_events.append(event)
                deadline_map.setdefault(event_date_str, []).append(f"{severity}:{team_name}")

        # Build full calendar for requested month
        num_days = calendar.monthrange(year, month)[1]
        days = []
        for day in range(1, num_days + 1):
            day_str = str(date(year, month, day))
            day_events = [e for e in extension_events if e["due"] == day_str]
            days.append({
                "date": day_str,
                "severities": deadline_map.get(day_str, []),
                "events": day_events,
            })

        return Response(
            {
                "message": "Calendar data retrieved successfully",
                "risk_criteria_id": str(risk._id),
                "base_date": str(base_datetime.date()),
                "deadlines": deadlines,
                "extension_events": extension_events,
                "calendar": {
                    "month": f"{year:04d}-{month:02d}",
                    "days": days,
                },
            },
            status=status.HTTP_200_OK,
        )


class RiskCriteriaCalendarWeekView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, risk_id, *args, **kwargs):
        # Validate and fetch risk criteria
        try:
            obj_id = ObjectId(risk_id)
        except Exception:
            from rest_framework.exceptions import ValidationError
            raise ValidationError("Invalid Risk Criteria ID")

        try:
            risk = RiskCriteria.objects.get(_id=obj_id)
        except RiskCriteria.DoesNotExist:
            raise Http404
        if str(risk.admin_id).strip() != str(request.user.id).strip():
            raise Http404

        date_param = request.query_params.get("date")
        try:
            target_date = date.fromisoformat(date_param) if date_param else date.today()
        except Exception:
            return Response({"message": "Invalid date format. Use YYYY-MM-DD"}, status=status.HTTP_400_BAD_REQUEST)

        # Parse criteria days
        try:
            critical_days = parse_days(risk.critical)
            high_days = parse_days(risk.high)
            medium_days = parse_days(risk.medium)
            low_days = parse_days(risk.low)
        except (ValueError, TypeError) as e:
            return Response({"message": f"Risk criteria day values are invalid: {e}"}, status=status.HTTP_400_BAD_REQUEST)

        base_datetime = risk.updated_at or risk.created_at
        if base_datetime.tzinfo is None:
            base_datetime = base_datetime.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)

        deadlines = {}
        for severity, n_days in [("critical", critical_days), ("high", high_days), ("medium", medium_days), ("low", low_days)]:
            deadline_date = (base_datetime + timedelta(days=n_days)).date()
            remaining = _remaining_from_base(base_datetime, n_days, now)
            deadlines[severity] = {
                "days": n_days,
                "deadline_date": str(deadline_date),
                "remaining_days": remaining["remaining_days"],
                "remaining_label": remaining["remaining_label"],
                "status": remaining["status"],
            }

        deadline_map = {}
        for severity, info in deadlines.items():
            deadline_map.setdefault(info["deadline_date"], []).append(severity)

        team_filter = (request.query_params.get("team") or "").strip().lower()
        severity_filter = (request.query_params.get("severity") or "").strip().lower()
        extension_events = []
        with MongoContext() as db:
            ext_query = {"admin_id": str(request.user.id), "status": "approved"}
            report_id = (request.query_params.get("report_id") or "").strip()
            if report_id:
                ext_query["report_id"] = report_id
            seen = set()
            for req in db[TIMELINE_EXTENSION_COLLECTION].find(ext_query).sort("request_date", -1):
                severity = _normalize_severity(req.get("severity"))
                team_name = (req.get("team_name") or "").strip()
                if not severity:
                    continue
                if severity_filter and _normalize_severity(severity_filter) != severity:
                    continue
                if team_filter and team_name.lower() != team_filter:
                    continue
                if severity == "critical":
                    base_days = critical_days
                elif severity == "high":
                    base_days = high_days
                elif severity == "medium":
                    base_days = medium_days
                elif severity == "low":
                    base_days = low_days
                else:
                    continue
                ext_days = int(req.get("requested_extension_days") or 0)
                effective_days = int(req.get("effective_deadline_days") or (base_days + ext_days))
                event_date = (base_datetime + timedelta(days=effective_days)).date()
                event_date_str = str(event_date)
                dedup_key = (
                    severity,
                    team_name.lower(),
                    (req.get("asset") or "").strip().lower(),
                    (req.get("vulnerability_name") or "").strip().lower(),
                )
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                event = {
                    "request_id": str(req.get("_id")),
                    "severity": severity,
                    "title": f"{severity.title()} Level Deadline - {team_name or 'Team'}",
                    "assigned_to_team": team_name,
                    "asset": req.get("asset"),
                    "vulnerability_name": req.get("vulnerability_name"),
                    "status": req.get("status", "approved"),
                    "due": event_date_str,
                    "extended_by_days": ext_days,
                    "requested_date": str(req.get("request_date")) if req.get("request_date") else None,
                    "historical_detail": {
                        "vulnerability_identified": req.get("request_date"),
                        "assigned_to_team": team_name,
                        "remediation_in_progress_due": event_date_str,
                    },
                    "extension_requested": {
                        "reason": req.get("reason") or "",
                        "note": f"{ext_days} days extension granted" if ext_days > 0 else "No extension requested",
                    },
                }
                extension_events.append(event)
                deadline_map.setdefault(event_date_str, []).append(f"{severity}:{team_name}")

        week_start = target_date - timedelta(days=target_date.weekday())
        week_days = []
        for i in range(7):
            d = week_start + timedelta(days=i)
            d_str = str(d)
            week_days.append({
                "date": d_str,
                "severities": deadline_map.get(d_str, []),
                "events": [e for e in extension_events if e["due"] == d_str],
            })

        return Response({
            "message": "Week calendar data retrieved successfully",
            "risk_criteria_id": str(risk._id),
            "base_date": str(base_datetime.date()),
            "deadlines": deadlines,
            "week": {
                "start_date": str(week_start),
                "end_date": str(week_start + timedelta(days=6)),
                "days": week_days,
            },
            "extension_events": extension_events,
        }, status=status.HTTP_200_OK)


class RiskCriteriaCalendarDayView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, risk_id, *args, **kwargs):
        date_param = request.query_params.get("date")
        try:
            target_date = date.fromisoformat(date_param) if date_param else date.today()
        except Exception:
            return Response({"message": "Invalid date format. Use YYYY-MM-DD"}, status=status.HTTP_400_BAD_REQUEST)

        # Reuse week payload logic and return one day.
        week_response = RiskCriteriaCalendarWeekView().get(request, risk_id, *args, **kwargs)
        if week_response.status_code != status.HTTP_200_OK:
            return week_response

        payload = dict(week_response.data)
        day_str = str(target_date)
        day_entry = None
        for d in payload.get("week", {}).get("days", []):
            if d.get("date") == day_str:
                day_entry = d
                break
        if not day_entry:
            day_entry = {"date": day_str, "severities": [], "events": []}

        return Response({
            "message": "Day calendar data retrieved successfully",
            "risk_criteria_id": payload.get("risk_criteria_id"),
            "base_date": payload.get("base_date"),
            "deadlines": payload.get("deadlines"),
            "day": day_entry,
        }, status=status.HTTP_200_OK)
