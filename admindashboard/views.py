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
SUPPORT_REQUEST_COLLECTION = "support_requests"
FIX_VULN_COLLECTION = "fix_vulnerabilities"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"

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

def days_to_week_label(days: int) -> str:
    """
    Convert days into week labels if exact multiple of 7
    """
    if not days or days <= 0:
        return "0 day"

    if days % 7 == 0:
        weeks = days // 7
        return f"{weeks} week" if weeks == 1 else f"{weeks} weeks"

    return f"{days} days"


def hours_to_wdh(hours: int) -> dict:
    weeks = hours // 168
    hours = hours % 168

    days = hours // 24
    hours = hours % 24

    return {
        "weeks": weeks,
        "days": days,
        "hours": hours
    }


def format_wdh_label(wdh: dict) -> str:
    parts = []

    if wdh["weeks"]:
        parts.append(f'{wdh["weeks"]} week' if wdh["weeks"] == 1 else f'{wdh["weeks"]} weeks')
    if wdh["days"]:
        parts.append(f'{wdh["days"]} day' if wdh["days"] == 1 else f'{wdh["days"]} days')
    if wdh["hours"]:
        parts.append(f'{wdh["hours"]} hour' if wdh["hours"] == 1 else f'{wdh["hours"]} hours')

    return ", ".join(parts) if parts else "0 hour"


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

                # 🔹 Convert timelines → days
                critical_days = parse_timeline_to_days(rc.critical)
                high_days     = parse_timeline_to_days(rc.high)
                medium_days   = parse_timeline_to_days(rc.medium)
                low_days      = parse_timeline_to_days(rc.low)

                # 🔹 Total
                total_days  = critical_days + high_days + medium_days + low_days
                total_hours = days_to_hours(total_days)

                payload = {
                    "critical": {
                        "raw": rc.critical,
                        "days": critical_days,
                        "label": days_to_week_label(critical_days)
                    },
                    "high": {
                        "raw": rc.high,
                        "days": high_days,
                        "label": days_to_week_label(high_days)
                    },
                    "medium": {
                        "raw": rc.medium,
                        "days": medium_days,
                        "label": days_to_week_label(medium_days)
                    },
                    "low": {
                        "raw": rc.low,
                        "days": low_days,
                        "label": days_to_week_label(low_days)
                    },
                    "total": {
                        "days": total_days,
                        "hours": total_hours,
                        "label": days_to_week_label(total_days)
                    }
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

                # 🔹 Convert timelines → days
                critical_days = parse_timeline_to_days(rc.critical)
                high_days     = parse_timeline_to_days(rc.high)
                medium_days   = parse_timeline_to_days(rc.medium)
                low_days      = parse_timeline_to_days(rc.low)

                # 🔹 Convert days → hours
                critical_hours = days_to_hours(critical_days)
                high_hours     = days_to_hours(high_days)
                medium_hours   = days_to_hours(medium_days)
                low_hours      = days_to_hours(low_days)

                # 🔹 MTTR calculation (AVERAGE)
                total_hours = (
                    critical_hours +
                    high_hours +
                    medium_hours +
                    low_hours
                )

                mttr_hours = round(total_hours / 4)

                # 🔹 Convert MTTR → week/day/hour
                mttr_wdh = hours_to_wdh(mttr_hours)

                payload = {
                    "report_id": str(report_id),

                    "risk_criteria": {
                        "critical": {
                            "raw": rc.critical,
                            "days": critical_days,
                            "hours": critical_hours
                        },
                        "high": {
                            "raw": rc.high,
                            "days": high_days,
                            "hours": high_hours
                        },
                        "medium": {
                            "raw": rc.medium,
                            "days": medium_days,
                            "hours": medium_hours
                        },
                        "low": {
                            "raw": rc.low,
                            "days": low_days,
                            "hours": low_hours
                        }
                    },

                    "mean_time_to_remediate": {
                        "hours": mttr_hours,
                        "weeks": mttr_wdh["weeks"],
                        "days": mttr_wdh["days"],
                        "hours_remaining": mttr_wdh["hours"],
                        "label": format_wdh_label(mttr_wdh)
                    }
                }

                return Response(payload, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )


# ============================================================================
# ADMIN-LEVEL DASHBOARD VIEWS
# These views fetch data from the MOST RECENTLY uploaded report for the admin
# ============================================================================

def _load_latest_report_for_admin(db, admin_email):
    """Load the most recently uploaded report for a specific admin by email."""
    coll = db[NESSUS_COLLECTION]
    # Sort by uploaded_at descending and get the first (most recent) document
    return coll.find_one(
        {"admin_email": admin_email},
        sort=[("uploaded_at", -1)]
    )


class AdminTotalAssetsAPIView(APIView):
    """
    Returns total unique assets (hosts) from the most recently uploaded report for the logged-in admin.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                # Get the most recent report for this admin
                doc = _load_latest_report_for_admin(db, admin_email)

                if not doc:
                    return Response({
                        "total_assets": 0,
                        "report_id": None
                    }, status=status.HTTP_200_OK)

                hosts = set()
                for h in (doc.get("vulnerabilities_by_host") or []):
                    host_name = (h.get("host_name") or h.get("host") or "").strip()
                    if host_name:
                        hosts.add(host_name)

                total_assets = len(hosts)
                report_id = doc.get("report_id") or str(doc.get("_id", ""))

                return Response({
                    "total_assets": total_assets,
                    "report_id": report_id
                }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminAvgScoreAPIView(APIView):
    """
    Returns average CVSS score from the most recently uploaded report for the logged-in admin.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email)

                if not doc:
                    return Response({"avg_score": None, "report_id": None}, status=status.HTTP_200_OK)

                cvss_vals = []
                for host in doc.get("vulnerabilities_by_host") or []:
                    for v in (host.get("vulnerabilities") or []):
                        cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        num = safe_float_from(cv_raw)
                        if num is not None:
                            cvss_vals.append(num)

                avg = round(sum(cvss_vals) / len(cvss_vals), 2) if cvss_vals else None
                report_id = doc.get("report_id") or str(doc.get("_id", ""))

                return Response({"avg_score": avg, "report_id": report_id}, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminVulnerabilitiesAPIView(APIView):
    """
    Returns vulnerability counts by severity from the most recently uploaded report for the logged-in admin.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email)

                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                report_id = None

                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))
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

                counts["report_id"] = report_id
                return Response(counts, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminMitigationTimelineAPIView(APIView):
    """
    Returns mitigation timeline based on admin's RiskCriteria settings.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email
            report_id = None

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email)
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

            rc = _get_latest_riskcriteria_for_user(request.user)

            if not rc:
                return Response({"detail": "Risk criteria not found", "report_id": report_id}, status=404)

            critical_days = parse_timeline_to_days(rc.critical)
            high_days = parse_timeline_to_days(rc.high)
            medium_days = parse_timeline_to_days(rc.medium)
            low_days = parse_timeline_to_days(rc.low)

            total_days = critical_days + high_days + medium_days + low_days
            total_hours = days_to_hours(total_days)

            payload = {
                "report_id": report_id,
                "critical": {
                    "raw": rc.critical,
                    "days": critical_days,
                    "label": days_to_week_label(critical_days)
                },
                "high": {
                    "raw": rc.high,
                    "days": high_days,
                    "label": days_to_week_label(high_days)
                },
                "medium": {
                    "raw": rc.medium,
                    "days": medium_days,
                    "label": days_to_week_label(medium_days)
                },
                "low": {
                    "raw": rc.low,
                    "days": low_days,
                    "label": days_to_week_label(low_days)
                },
                "total": {
                    "days": total_days,
                    "hours": total_hours,
                    "label": days_to_week_label(total_days)
                }
            }

            return Response(payload, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )


class AdminMeanTimeRemediateAPIView(APIView):
    """
    Returns Mean Time to Remediate (MTTR) based on admin's RiskCriteria settings.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email
            report_id = None

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email)
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

            rc = _get_latest_riskcriteria_for_user(request.user)

            if not rc:
                return Response({"detail": "Risk criteria not found", "report_id": report_id}, status=404)

            critical_days = parse_timeline_to_days(rc.critical)
            high_days = parse_timeline_to_days(rc.high)
            medium_days = parse_timeline_to_days(rc.medium)
            low_days = parse_timeline_to_days(rc.low)

            critical_hours = days_to_hours(critical_days)
            high_hours = days_to_hours(high_days)
            medium_hours = days_to_hours(medium_days)
            low_hours = days_to_hours(low_days)

            total_hours = critical_hours + high_hours + medium_hours + low_hours
            mttr_hours = round(total_hours / 4)
            mttr_wdh = hours_to_wdh(mttr_hours)

            payload = {
                "report_id": report_id,
                "risk_criteria": {
                    "critical": {
                        "raw": rc.critical,
                        "days": critical_days,
                        "hours": critical_hours
                    },
                    "high": {
                        "raw": rc.high,
                        "days": high_days,
                        "hours": high_hours
                    },
                    "medium": {
                        "raw": rc.medium,
                        "days": medium_days,
                        "hours": medium_hours
                    },
                    "low": {
                        "raw": rc.low,
                        "days": low_days,
                        "hours": low_hours
                    }
                },
                "mean_time_to_remediate": {
                    "hours": mttr_hours,
                    "weeks": mttr_wdh["weeks"],
                    "days": mttr_wdh["days"],
                    "hours_remaining": mttr_wdh["hours"],
                    "label": format_wdh_label(mttr_wdh)
                }
            }

            return Response(payload, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )


class AdminVulnerabilitiesFixedAPIView(APIView):
    """
    Returns count of fixed vulnerabilities by severity for the logged-in admin.
    Queries the fix_vulnerabilities collection where status is 'close'.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                # Get report_id from latest report
                doc = _load_latest_report_for_admin(db, admin_email)
                report_id = None
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                fix_coll = db[FIX_VULN_COLLECTION]

                # Count fixed vulnerabilities by severity
                fixed_vulns = list(fix_coll.find({
                    "created_by": admin_id,
                    "status": "close"
                }))

                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

                for vuln in fixed_vulns:
                    risk = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
                    if risk.startswith("crit"):
                        counts["critical"] += 1
                    elif risk.startswith("high"):
                        counts["high"] += 1
                    elif risk.startswith("med"):
                        counts["medium"] += 1
                    elif risk.startswith("low"):
                        counts["low"] += 1

                total = counts["critical"] + counts["high"] + counts["medium"] + counts["low"]

                return Response({
                    "report_id": report_id,
                    "total_fixed": total,
                    "critical_fixed": counts["critical"],
                    "high_fixed": counts["high"],
                    "medium_fixed": counts["medium"],
                    "low_fixed": counts["low"]
                }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminSupportRequestsAPIView(APIView):
    """
    Returns count of support requests (pending and closed) for the logged-in admin.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                # Get report_id from latest report
                doc = _load_latest_report_for_admin(db, admin_email)
                report_id = None
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                support_coll = db[SUPPORT_REQUEST_COLLECTION]

                # Count pending support requests
                pending_count = support_coll.count_documents({
                    "admin_id": admin_id,
                    "status": {"$ne": "closed"}
                })

                # Count closed support requests
                closed_count = support_coll.count_documents({
                    "admin_id": admin_id,
                    "status": "closed"
                })

                total = pending_count + closed_count

                return Response({
                    "report_id": report_id,
                    "total": total,
                    "pending": pending_count,
                    "closed": closed_count
                }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminDashboardSummaryAPIView(APIView):
    """
    Returns a complete dashboard summary for the logged-in admin.
    Fetches data from the MOST RECENTLY uploaded report only.
    Combines all dashboard metrics in a single API call for efficiency.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email
            admin_id = str(request.user.id)

            with MongoContext() as db:
                # Load the most recent report for this admin
                doc = _load_latest_report_for_admin(db, admin_email)

                # Initialize default values
                total_assets = 0
                avg_score = None
                vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                report_id = None

                if doc:
                    report_id = doc.get("report_id")

                    # ---- Total Assets ----
                    hosts = set()
                    for h in (doc.get("vulnerabilities_by_host") or []):
                        host_name = (h.get("host_name") or h.get("host") or "").strip()
                        if host_name:
                            hosts.add(host_name)
                    total_assets = len(hosts)

                    # ---- Average CVSS Score ----
                    cvss_vals = []
                    for host in doc.get("vulnerabilities_by_host") or []:
                        for v in (host.get("vulnerabilities") or []):
                            cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                            num = safe_float_from(cv_raw)
                            if num is not None:
                                cvss_vals.append(num)
                    avg_score = round(sum(cvss_vals) / len(cvss_vals), 2) if cvss_vals else None

                    # ---- Vulnerability Counts ----
                    for host in doc.get("vulnerabilities_by_host") or []:
                        for v in (host.get("vulnerabilities") or []):
                            risk = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
                            if risk.startswith("crit"):
                                vuln_counts["critical"] += 1
                            elif risk.startswith("high"):
                                vuln_counts["high"] += 1
                            elif risk.startswith("med"):
                                vuln_counts["medium"] += 1
                            elif risk.startswith("low"):
                                vuln_counts["low"] += 1

                # ---- Fixed Vulnerabilities ----
                fix_coll = db[FIX_VULN_COLLECTION]
                fixed_vulns = list(fix_coll.find({
                    "created_by": admin_id,
                    "status": "close"
                }))

                fixed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in fixed_vulns:
                    risk = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
                    if risk.startswith("crit"):
                        fixed_counts["critical"] += 1
                    elif risk.startswith("high"):
                        fixed_counts["high"] += 1
                    elif risk.startswith("med"):
                        fixed_counts["medium"] += 1
                    elif risk.startswith("low"):
                        fixed_counts["low"] += 1

                total_fixed = sum(fixed_counts.values())

                # ---- Support Requests ----
                support_coll = db[SUPPORT_REQUEST_COLLECTION]
                pending_requests = support_coll.count_documents({
                    "admin_id": admin_id,
                    "status": {"$ne": "closed"}
                })
                closed_requests = support_coll.count_documents({
                    "admin_id": admin_id,
                    "status": "closed"
                })

            # ---- Mitigation Timeline & MTTR ----
            rc = _get_latest_riskcriteria_for_user(request.user)
            mitigation_timeline = None
            mean_time_to_remediate = None

            if rc:
                critical_days = parse_timeline_to_days(rc.critical)
                high_days = parse_timeline_to_days(rc.high)
                medium_days = parse_timeline_to_days(rc.medium)
                low_days = parse_timeline_to_days(rc.low)

                total_days = critical_days + high_days + medium_days + low_days

                mitigation_timeline = {
                    "critical": {"raw": rc.critical, "days": critical_days, "label": days_to_week_label(critical_days)},
                    "high": {"raw": rc.high, "days": high_days, "label": days_to_week_label(high_days)},
                    "medium": {"raw": rc.medium, "days": medium_days, "label": days_to_week_label(medium_days)},
                    "low": {"raw": rc.low, "days": low_days, "label": days_to_week_label(low_days)},
                }

                critical_hours = days_to_hours(critical_days)
                high_hours = days_to_hours(high_days)
                medium_hours = days_to_hours(medium_days)
                low_hours = days_to_hours(low_days)

                total_hours = critical_hours + high_hours + medium_hours + low_hours
                mttr_hours = round(total_hours / 4)
                mttr_wdh = hours_to_wdh(mttr_hours)

                mean_time_to_remediate = {
                    "hours": mttr_hours,
                    "weeks": mttr_wdh["weeks"],
                    "days": mttr_wdh["days"],
                    "hours_remaining": mttr_wdh["hours"],
                    "label": format_wdh_label(mttr_wdh)
                }

            return Response({
                "report_id": report_id,
                "total_assets": total_assets,
                "avg_score": avg_score,
                "vulnerabilities": vuln_counts,
                "vulnerabilities_fixed": {
                    "total": total_fixed,
                    "critical": fixed_counts["critical"],
                    "high": fixed_counts["high"],
                    "medium": fixed_counts["medium"],
                    "low": fixed_counts["low"]
                },
                "support_requests": {
                    "total": pending_requests + closed_requests,
                    "pending": pending_requests,
                    "closed": closed_requests
                },
                "mitigation_timeline": mitigation_timeline,
                "mean_time_to_remediate": mean_time_to_remediate
            }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminReportStatusAPIView(APIView):
    """
    Returns whether the admin has any uploaded reports.
    Frontend should use this to decide whether to show dashboard or waiting screen.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email)

                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))
                    return Response({
                        "has_report": True,
                        "show_dashboard": True,
                        "admin_id": admin_id,
                        "admin_email": admin_email,
                        "report_id": report_id,
                        "message": "Report available"
                    }, status=status.HTTP_200_OK)
                else:
                    return Response({
                        "has_report": False,
                        "show_dashboard": False,
                        "admin_id": admin_id,
                        "admin_email": admin_email,
                        "report_id": None,
                        "message": "No report uploaded yet. Please wait for Super Admin to upload a report."
                    }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
