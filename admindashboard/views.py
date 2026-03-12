from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from datetime import date, timedelta
import re

DASHBOARD_CACHE_TTL = 300  # 5 minutes

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
VULN_CARD_COLLECTION = "vulnerability_cards"

TEAM_NAMES = [
    "Patch Management",
    "Configuration Management",
    "Network Security",
    "Architectural Flaws",
]

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
        cache_key = f"dash:total_assets:{report_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                # Load report — only fetch the host list (projection)
                doc = coll.find_one(
                    {"report_id": str(report_id)},
                    {"vulnerabilities_by_host.host_name": 1, "vulnerabilities_by_host.host": 1}
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
                cache.set(cache_key, serializer.data, DASHBOARD_CACHE_TTL)
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
        cache_key = f"dash:avg_score:{report_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)
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
                data = AvgScoreSerializer({"avg_score": avg}).data
                cache.set(cache_key, data, DASHBOARD_CACHE_TTL)
                return Response(data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportVulnerabilitiesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        cache_key = f"dash:vulns:{report_id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached)
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
                data = VulnerabilitiesSerializer(counts).data
                cache.set(cache_key, data, DASHBOARD_CACHE_TTL)
                return Response(data)
        except RuntimeError as rte:
            return Response({"detail": str(rte)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail":"error", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ReportMitigationTimelineAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        cache_key = f"dash:timeline:{report_id}:{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=200)
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

                cache.set(cache_key, payload, DASHBOARD_CACHE_TTL)
                return Response(payload, status=200)

        except Exception as exc:
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=500
            )


class ReportMeanTimeRemediateAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        cache_key = f"dash:mttr:{report_id}:{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=200)
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

                cache.set(cache_key, payload, DASHBOARD_CACHE_TTL)
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

def _load_latest_report_for_admin(db, admin_email, admin_id=None):
    """Load the most recently uploaded report for a specific admin.
    Tries admin_id first (more reliable for newer reports), falls back to admin_email.
    """
    coll = db[NESSUS_COLLECTION]
    if admin_id:
        doc = coll.find_one(
            {"admin_id": str(admin_id)},
            sort=[("uploaded_at", -1)]
        )
        if doc:
            return doc
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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

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


class AdminAssetsByTeamAPIView(APIView):
    """
    GET /api/admin/admindashboard/dashboard/assets-by-team/
    Returns unique asset (host) count per team for the admin's latest report.

    Strategy:
    1. Build vulnerability_name -> assigned_team map from vulnerability_cards
    2. Loop nessus_reports.vulnerabilities_by_host — for each host, resolve its name
       using fallbacks (host_name → host → host-ip → host-fqdn)
    3. For each of that host's vulnerabilities, look up its team from the map
    4. Add host to that team's set (deduplicated — one host counted once per team)
    5. total_assets = all unique hosts in nessus doc (fallback: doc.total_hosts)

    This grows correctly as more cards are generated:
    - 15 cards now  → teams assigned to those 15 vulns → their affected hosts counted
    - 83 cards later → all vulns mapped → full accurate counts per team
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email
            admin_id    = str(request.user.id)

            with MongoContext() as db:
                # Get the latest report for this admin
                doc = _load_latest_report_for_admin(db, admin_email, admin_id)
                if not doc:
                    return Response({"total_assets": 0, "by_team": []}, status=status.HTTP_200_OK)

                report_id = doc.get("report_id") or str(doc.get("_id", ""))
                team_names_lower = {name.lower(): name for name in TEAM_NAMES}

                # Step 1: Build vuln_name -> assigned_team map from vulnerability_cards
                plugin_team_map = {}
                for card in db[VULN_CARD_COLLECTION].find(
                    {"report_id": str(report_id)},
                    {"vulnerability_name": 1, "assigned_team": 1}
                ):
                    pname = (card.get("vulnerability_name") or "").strip()
                    raw_team = (card.get("assigned_team") or "").strip()
                    matched_team = team_names_lower.get(raw_team.lower())
                    if pname and matched_team:
                        plugin_team_map[pname] = matched_team

                # Step 2: Loop nessus hosts, resolve host_name, group by team
                team_hosts = {name: set() for name in TEAM_NAMES}
                all_hosts = set()

                for host in (doc.get("vulnerabilities_by_host") or []):
                    host_info = host.get("host_information") or {}
                    host_name = (
                        host.get("host_name")
                        or host.get("host")
                        or host_info.get("host-ip")
                        or host_info.get("host-fqdn")
                        or host_info.get("HOST_END")
                        or ""
                    )
                    if isinstance(host_name, str):
                        host_name = host_name.strip()
                    if not host_name:
                        continue

                    all_hosts.add(host_name)

                    for v in (host.get("vulnerabilities") or []):
                        pname = (
                            v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                        ).strip()
                        matched_team = plugin_team_map.get(pname)
                        if matched_team:
                            team_hosts[matched_team].add(host_name)

                total_assets = len(all_hosts) or doc.get("total_hosts", 0)

                by_team = [
                    {"team": team, "asset_count": len(hosts)}
                    for team, hosts in sorted(team_hosts.items())
                ]

                return Response({
                    "report_id": report_id,
                    "total_assets": total_assets,
                    "by_team": by_team
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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))
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

            # Remaining days calculation
            base_date = (rc.updated_at or rc.created_at).date()
            today = date.today()

            def _remaining(n_days):
                deadline = base_date + timedelta(days=n_days)
                delta = (deadline - today).days
                if delta < 0:
                    return {"remaining_days": abs(delta), "remaining_label": "Overdue", "status": "overdue"}
                weeks, days_left = divmod(delta, 7)
                if weeks > 0 and days_left > 0:
                    label = f"{weeks} week{'s' if weeks > 1 else ''} {days_left} day{'s' if days_left > 1 else ''}"
                elif weeks > 0:
                    label = f"{weeks} week{'s' if weeks > 1 else ''}"
                else:
                    label = f"{days_left} day{'s' if days_left > 1 else ''}"
                return {"remaining_days": delta, "remaining_label": label, "status": "active"}

            payload = {
                "report_id": report_id,
                "base_date": str(base_date),
                "critical": {
                    "raw": rc.critical,
                    "days": critical_days,
                    "label": days_to_week_label(critical_days),
                    **_remaining(critical_days),
                },
                "high": {
                    "raw": rc.high,
                    "days": high_days,
                    "label": days_to_week_label(high_days),
                    **_remaining(high_days),
                },
                "medium": {
                    "raw": rc.medium,
                    "days": medium_days,
                    "label": days_to_week_label(medium_days),
                    **_remaining(medium_days),
                },
                "low": {
                    "raw": rc.low,
                    "days": low_days,
                    "label": days_to_week_label(low_days),
                    **_remaining(low_days),
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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))
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
    Returns count of fixed (closed) vulnerabilities by severity for the logged-in admin.
    Queries the fix_vulnerabilities_closed collection, filtered by report.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                # Get report_id from latest report
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))
                report_id = None
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                # Build query for closed (fixed) vulnerabilities
                closed_query = {
                    "created_by": admin_id,
                    "status": "closed"
                }
                if report_id:
                    closed_query["report_id"] = str(report_id)

                # Count closed vulnerabilities by severity
                fixed_vulns = list(closed_coll.find(closed_query))

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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))
                report_id = None
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                support_coll = db[SUPPORT_REQUEST_COLLECTION]

                # Build base query filtered by admin and report
                base_query = {"admin_id": admin_id}
                if report_id:
                    base_query["report_id"] = str(report_id)

                # Count pending support requests
                pending_count = support_coll.count_documents({
                    **base_query,
                    "status": {"$ne": "closed"}
                })

                # Count closed support requests
                closed_count = support_coll.count_documents({
                    **base_query,
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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

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


class AdminDistributionByTeamAPIView(APIView):
    """
    Returns vulnerability distribution by assigned team for the logged-in admin.
    Checks vulnerability_cards for assigned_team per vulnerability.

    GET /api/admin/dashboard/distribution-by-team/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

                if not doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = doc.get("report_id") or str(doc.get("_id", ""))
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                # Normalize team names for case-insensitive matching
                team_names_lower = {name.lower(): name for name in TEAM_NAMES}

                # Count distribution directly from vulnerability_cards
                # Each card = one unique vulnerability — avoids inflating counts from multi-host repeats
                counts = {name: 0 for name in TEAM_NAMES}
                counts["Unassigned"] = 0
                total = 0

                for card in vuln_card_coll.find({"report_id": report_id}):
                    raw_team = (card.get("assigned_team", "") or "").strip()
                    matched_team = team_names_lower.get(raw_team.lower())
                    if matched_team:
                        counts[matched_team] += 1
                    else:
                        counts["Unassigned"] += 1
                    total += 1

                distribution = [
                    {
                        "team": team,
                        "count": count,
                        "percentage": round((count / total * 100), 2) if total else 0,
                    }
                    for team, count in counts.items()
                ]

                return Response(
                    {
                        "report_id": report_id,
                        "total_vulnerabilities": total,
                        "distribution": distribution,
                    },
                    status=status.HTTP_200_OK,
                )

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AdminDistributionByTeamDetailAPIView(APIView):
    """
    Returns detailed vulnerability distribution by team with status (open/closed)
    and risk_factor (Critical/High/Medium/Low) breakdown.

    GET /api/admin/dashboard/distribution-by-team/detail/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id    = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

                if not doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = doc.get("report_id") or str(doc.get("_id", ""))

                team_names_lower = {name.lower(): name for name in TEAM_NAMES}
                risk_levels = ["Critical", "High", "Medium", "Low"]

                # ── plugin_name → risk_factor from nessus ───────────────────────
                plugin_risk = {}
                for host in doc.get("vulnerabilities_by_host", []):
                    for v in host.get("vulnerabilities", []):
                        pname = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )
                        if pname and pname not in plugin_risk:
                            risk_raw = (
                                v.get("risk_factor")
                                or v.get("severity")
                                or v.get("risk")
                                or ""
                            ).strip()
                            if risk_raw.lower().startswith("crit"):
                                plugin_risk[pname] = "Critical"
                            elif risk_raw.lower().startswith("high"):
                                plugin_risk[pname] = "High"
                            elif risk_raw.lower().startswith("med"):
                                plugin_risk[pname] = "Medium"
                            elif risk_raw.lower().startswith("low"):
                                plugin_risk[pname] = "Low"
                            else:
                                plugin_risk[pname] = None

                # ── closed plugin_names set for this report ─────────────────────
                closed_plugins = set()
                for doc_c in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": report_id, "created_by": admin_id}
                ):
                    closed_plugins.add(doc_c.get("plugin_name", ""))

                # ── initialize team buckets ─────────────────────────────────────
                all_teams = TEAM_NAMES + ["Unassigned"]

                def empty_bucket():
                    return {
                        "total": 0,
                        "open": 0,
                        "closed": 0,
                        "by_risk": {r: 0 for r in risk_levels},
                    }

                teams = {t: empty_bucket() for t in all_teams}

                # ── iterate vulnerability_cards (one unique vuln per card) ───────
                for card in db[VULN_CARD_COLLECTION].find({"report_id": report_id}):
                    plugin_name = card.get("vulnerability_name", "")
                    raw_team    = (card.get("assigned_team", "") or "").strip()
                    team_key    = team_names_lower.get(raw_team.lower(), "") or "Unassigned"

                    risk_label  = plugin_risk.get(plugin_name)
                    is_closed   = plugin_name in closed_plugins
                    vuln_status = "closed" if is_closed else "open"

                    bucket = teams[team_key]
                    bucket["total"] += 1
                    bucket[vuln_status] += 1
                    if risk_label:
                        bucket["by_risk"][risk_label] += 1

                return Response(
                    {
                        "report_id": report_id,
                        "teams": teams,
                    },
                    status=status.HTTP_200_OK,
                )

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class AdminDetailedVulnerabilitiesAPIView(APIView):
    """
    Returns a detailed list of all vulnerabilities for the logged-in admin's latest report.

    Fields per row:
      - vulnerability_name  (from vulnerability_cards)
      - assets / host_name  (from vulnerability_cards)
      - assigned_team       (from vulnerability_cards)
      - risk_factor         (from nessus_reports)
      - found_date          (vulnerability_cards.created_at)
      - status              (open / closed — from fix_vulnerabilities_closed)

    GET /api/admin/dashboard/detailed-vulnerabilities/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id    = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

                if not doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = doc.get("report_id") or str(doc.get("_id", ""))

                # ── plugin_name → risk_factor from nessus ───────────────────────
                plugin_risk = {}
                for host in doc.get("vulnerabilities_by_host", []):
                    for v in host.get("vulnerabilities", []):
                        pname = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )
                        if pname and pname not in plugin_risk:
                            risk_raw = (
                                v.get("risk_factor")
                                or v.get("severity")
                                or v.get("risk")
                                or ""
                            ).strip()
                            if risk_raw.lower().startswith("crit"):
                                plugin_risk[pname] = "Critical"
                            elif risk_raw.lower().startswith("high"):
                                plugin_risk[pname] = "High"
                            elif risk_raw.lower().startswith("med"):
                                plugin_risk[pname] = "Medium"
                            elif risk_raw.lower().startswith("low"):
                                plugin_risk[pname] = "Low"
                            else:
                                plugin_risk[pname] = None

                # ── closed plugin_names for this report ─────────────────────────
                closed_plugins = set()
                for doc_c in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": report_id, "created_by": admin_id}
                ):
                    closed_plugins.add(doc_c.get("plugin_name", ""))

                # ── card lookup ──────────────────────────────────────────────────
                # Primary key: (plugin_name, host_name) for exact per-host match.
                # Fallback key: plugin_name only (for cards with empty host_name).
                card_by_host = {}   # (plugin_name, host_name) -> {assigned_team, found_date}
                card_by_name = {}   # plugin_name -> {assigned_team, found_date} (fallback)
                for card in db[VULN_CARD_COLLECTION].find({"report_id": report_id}):
                    vname = (card.get("vulnerability_name") or "").strip()
                    hname = (card.get("host_name") or "").strip()
                    if not vname:
                        continue
                    info = {
                        "assigned_team": (card.get("assigned_team") or "").strip(),
                        "found_date":    card.get("created_at"),
                    }
                    if hname:
                        card_by_host[(vname, hname)] = info
                    # Always populate fallback (last card wins, all same vuln → same team)
                    if vname not in card_by_name:
                        card_by_name[vname] = info

                # ── build one row per (vulnerability, host) from nessus ──────────
                vulnerabilities = []
                seen = set()    # avoid duplicate (plugin_name, host_name) rows

                for host in doc.get("vulnerabilities_by_host", []):
                    h_name = (host.get("host_name") or host.get("host") or "").strip()
                    for v in host.get("vulnerabilities", []):
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )
                        if not plugin_name:
                            continue

                        row_key = (plugin_name, h_name)
                        if row_key in seen:
                            continue
                        seen.add(row_key)

                        # Exact (vuln, host) match first; fall back to vuln-only
                        info = card_by_host.get((plugin_name, h_name)) \
                               or card_by_name.get(plugin_name) \
                               or {}

                        found_date    = info.get("found_date")
                        risk_factor   = plugin_risk.get(plugin_name)
                        vuln_status   = "closed" if plugin_name in closed_plugins else "open"
                        assigned_team = (info.get("assigned_team") or "").strip()

                        vulnerabilities.append({
                            "vulnerability_name": plugin_name,
                            "assets":             h_name,
                            "assigned_team":      assigned_team,
                            "risk_factor":        risk_factor or "",
                            "found_date":         found_date.isoformat() if hasattr(found_date, "isoformat") else str(found_date) if found_date else None,
                            "status":             vuln_status,
                        })

                return Response(
                    {
                        "report_id": report_id,
                        "total":     len(vulnerabilities),
                        "vulnerabilities": vulnerabilities,
                    },
                    status=status.HTTP_200_OK,
                )

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

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
