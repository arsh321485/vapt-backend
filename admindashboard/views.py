from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated  
import re

from .serializers import (
    TotalAssetsSerializer, AvgScoreSerializer,
    VulnerabilitiesSerializer, 
    MitigationTimelineSerializer, MeanTimeRemediateSerializer
)
from .utils import MongoContext, safe_float_from
from .utils import MongoContext, parse_timeline_to_hours, humanize_hours

NESSUS_COLLECTION = "nessus_reports"

try:
    from risk_criteria.models import RiskCriteria
except Exception:
    RiskCriteria = None

try:
    from users.models import User
except Exception:
    User = None

def _load_report(db, report_id):
    coll = db[NESSUS_COLLECTION]
    return coll.find_one({"report_id": str(report_id)})

def _get_latest_riskcriteria_for_admin_email(email):
    if not RiskCriteria or not User:
        return None
    try:
        user = User.objects.filter(email=email).first()
        if not user:
            return None
        rc = RiskCriteria.objects.filter(admin=user).order_by('-created_at').first()
        return rc
    except Exception:
        return None

def _get_latest_riskcriteria_for_user(user):
    if not RiskCriteria or not user:
        return None
    try:
        return RiskCriteria.objects.filter(admin=user).order_by('-created_at').first()
    except Exception:
        return None

def parse_timeline_to_days(value: str) -> int:
    """
    Converts timeline string to DAYS
    Examples:
      "1 Day"   -> 1
      "2 Days"  -> 2
      "1 Week"  -> 7
      "2 Weeks" -> 14
      "" or "Select" -> 0
    """
    if not value:
        return 0

    value = value.strip().lower()

    if value in ("select", ""):
        return 0

    match = re.search(r"(\d+)", value)
    if not match:
        return 0

    num = int(match.group(1))

    if "week" in value:
        return num * 7

    return num  # days


def days_to_hours(days: int) -> int:
    return days * 24

class ReportTotalAssetsAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                # Load report
                doc = coll.find_one(
                    {"report_id": str(report_id)},
                    {"vulnerabilities_by_host": 1}
                )

                if not doc:
                    return Response(
                        {"detail": "report not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # ------- COUNT UNIQUE HOST NAMES -------
                hosts = set()

                for h in (doc.get("vulnerabilities_by_host") or []):
                    host_name = (h.get("host_name") or h.get("host") or "").strip()
                    if host_name:
                        hosts.add(host_name)

                total_assets = len(hosts)

                # Return result
                serializer = TotalAssetsSerializer({"total_assets": total_assets})
                return Response(serializer.data, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class ReportAvgScoreAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail":"report not found"}, status=status.HTTP_404_NOT_FOUND)
                cvss_vals = []
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        num = safe_float_from(cv_raw)
                        if num is not None:
                            cvss_vals.append(num)
                avg = round(sum(cvss_vals)/len(cvss_vals), 2) if cvss_vals else None
                return Response(AvgScoreSerializer({"avg_score": avg}).data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportVulnerabilitiesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail":"report not found"}, status=status.HTTP_404_NOT_FOUND)
                counts = {"critical":0,"high":0,"medium":0,"low":0}
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        risk = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
                        if risk.startswith("crit"):
                            counts["critical"] += 1
                        elif risk.startswith("high"):
                            counts["high"] += 1
                        elif risk.startswith("med"):
                            counts["medium"] += 1
                        elif risk.startswith("low"):
                            counts["low"] += 1
                return Response(VulnerabilitiesSerializer(counts).data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportMitigationTimelineAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail": "report not found"}, status=404)

                admin_email = doc.get("admin_email", "")
                rc = None

                if admin_email:
                    rc = _get_latest_riskcriteria_for_admin_email(admin_email)

                if not rc:
                    rc = _get_latest_riskcriteria_for_user(request.user)

                if not rc:
                    return Response({"detail": "Risk criteria not found"}, status=404)

                # Convert timelines → days
                critical_days = parse_timeline_to_days(rc.critical)
                high_days     = parse_timeline_to_days(rc.high)
                medium_days   = parse_timeline_to_days(rc.medium)
                low_days      = parse_timeline_to_days(rc.low)

                total_days = critical_days + high_days + medium_days + low_days
                total_hours = days_to_hours(total_days)

                payload = {
                    "critical": rc.critical,
                    "critical_days": critical_days,
                    "high": rc.high,
                    "high_days": high_days,
                    "medium": rc.medium,
                    "medium_days": medium_days,
                    "low": rc.low,
                    "low_days": low_days,
                    "mitigation_timeline_total_days": total_days,
                    "mitigation_timeline_total_hours": total_hours
                }

                return Response(payload, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )


class ReportMeanTimeRemediateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                doc = _load_report(db, report_id)
                if not doc:
                    return Response({"detail": "report not found"}, status=404)

                admin_email = doc.get("admin_email", "")
                rc = None

                if admin_email:
                    rc = _get_latest_riskcriteria_for_admin_email(admin_email)

                if not rc:
                    rc = _get_latest_riskcriteria_for_user(request.user)

                if not rc:
                    return Response({"detail": "Risk criteria not found"}, status=404)

                # Convert to days
                critical_days = parse_timeline_to_days(rc.critical)
                high_days     = parse_timeline_to_days(rc.high)
                medium_days   = parse_timeline_to_days(rc.medium)
                low_days      = parse_timeline_to_days(rc.low)

                # MTTR formula
                mttr_days = round(
                    (critical_days + high_days + medium_days + low_days) / 4,
                    2
                )
                mttr_hours = days_to_hours(mttr_days)

                payload = {
                    "report_id": str(report_id),

                    "risk_criteria_days": {
                        "critical": critical_days,
                        "high": high_days,
                        "medium": medium_days,
                        "low": low_days,
                    },

                    "mean_time_to_remediate_days": mttr_days,
                    "mean_time_to_remediate_hours": mttr_hours
                }

                return Response(payload, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )
