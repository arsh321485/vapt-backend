from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.core.cache import cache
from datetime import date, timedelta, datetime, timezone
import re
import math
import logging
from bson import ObjectId

logger = logging.getLogger(__name__)

from .serializers import (
    TotalAssetsSerializer, AvgScoreSerializer,
    VulnerabilitiesSerializer,
    MitigationTimelineSerializer, MeanTimeRemediateSerializer
)
from .utils import MongoContext, safe_float_from
from .utils import MongoContext, parse_timeline_to_hours, humanize_hours
from vaptfix.mongo_client import ensure_performance_indexes

NESSUS_COLLECTION = "nessus_reports"
SUPPORT_REQUEST_COLLECTION = "support_requests"
FIX_VULN_COLLECTION = "fix_vulnerabilities"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
FIX_VULN_STEPS_COLLECTION = "fix_vulnerability_steps"
VULN_CARD_COLLECTION = "vulnerability_cards"
TIMELINE_EXTENSION_COLLECTION = "timeline_extension_requests"


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
    return coll.find_one({"report_id": str(report_id)}, {"admin_email": 1, "admin_id": 1})

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
                coll = db[NESSUS_COLLECTION]
                doc = coll.find_one(
                    {"report_id": str(report_id)},
                    {"vulnerabilities_by_host.vulnerabilities.cvss_v3_base_score": 1,
                     "vulnerabilities_by_host.vulnerabilities.cvss": 1,
                     "vulnerabilities_by_host.vulnerabilities.cvss_score": 1}
                )
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
                coll = db[NESSUS_COLLECTION]
                doc = coll.find_one(
                    {"report_id": str(report_id)},
                    {"vulnerabilities_by_host.vulnerabilities.risk_factor": 1,
                     "vulnerabilities_by_host.vulnerabilities.severity": 1}
                )
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

def _load_latest_report_for_admin(db, admin_email, admin_id=None, projection=None):
    """Load the most recently uploaded report for a specific admin.
    Tries admin_id first (more reliable for newer reports), falls back to admin_email.
    Pass projection to limit fields returned and speed up the query.
    """
    coll = db[NESSUS_COLLECTION]
    if admin_id:
        doc = coll.find_one(
            {"admin_id": str(admin_id)},
            projection,
            sort=[("uploaded_at", -1)]
        )
        if doc:
            return doc
    return coll.find_one(
        {"admin_email": admin_email},
        projection,
        sort=[("uploaded_at", -1)]
    )

def _load_latest_report_meta_for_admin(db, admin_email, admin_id=None):
    """Load only metadata needed for report scoping (report_id/_id)."""
    coll = db[NESSUS_COLLECTION]
    projection = {"report_id": 1}
    if admin_id:
        doc = coll.find_one(
            {"admin_id": str(admin_id)},
            projection,
            sort=[("uploaded_at", -1)]
        )
        if doc:
            return doc
    return coll.find_one(
        {"admin_email": admin_email},
        projection,
        sort=[("uploaded_at", -1)]
    )


def _extract_total_steps(mitigation_table):
    """Return dynamic step count from mitigation table."""
    if not isinstance(mitigation_table, list):
        return 0
    step_nums = set()
    for row in mitigation_table:
        if not isinstance(row, dict):
            continue
        try:
            step_num = int(row.get("step_no", 0))
        except (TypeError, ValueError):
            continue
        if step_num > 0:
            step_nums.add(step_num)
    return len(step_nums)


def _normalize_team(raw_team):
    raw = (raw_team or "").strip()
    return raw if raw else ""


def _normalize_risk(raw_risk):
    risk = (raw_risk or "").strip()
    return risk.title() if risk else ""


def _normalize_severity_key(raw):
    sev = (raw or "").strip().lower()
    if sev.startswith("crit"):
        return "critical"
    if sev.startswith("high"):
        return "high"
    if sev.startswith("med"):
        return "medium"
    if sev.startswith("low"):
        return "low"
    return None


def _to_iso(dt_val):
    if hasattr(dt_val, "isoformat"):
        # Real bug report: these values come straight from raw MongoDB
        # dicts, written with plain datetime.utcnow() — always genuinely
        # UTC, but naive (no tzinfo). Serializing a naive datetime with
        # .isoformat() produces a string with no offset/'Z' suffix, which
        # a browser's `new Date(...)` then silently interprets as its OWN
        # local time instead of UTC — showing the wrong time with no
        # conversion at all. Attach UTC explicitly so the ISO string is
        # unambiguous and the frontend converts it correctly.
        if dt_val.tzinfo is None:
            dt_val = dt_val.replace(tzinfo=timezone.utc)
        return dt_val.isoformat()
    return str(dt_val) if dt_val else None


class AdminInProcessRemediationTimelineAPIView(APIView):
    """
    Returns vulnerabilities where remediation is started but not completed:
    completed_steps > 0 and completed_steps < total_steps
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cache_key = f"admin_inprocess_timeline_{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                ensure_performance_indexes(db)
                report_doc = _load_latest_report_meta_for_admin(db, admin_email, admin_id)
                if not report_doc:
                    return Response({"report_id": None, "total": 0, "items": []}, status=status.HTTP_200_OK)

                report_id = str(report_doc.get("report_id") or report_doc.get("_id", ""))

                card_by_host = {}
                card_by_name = {}
                for card in db[VULN_CARD_COLLECTION].find(
                    {"report_id": report_id},
                    {
                        "vulnerability_name": 1,
                        "host_name": 1,
                        "mitigation_table": 1,
                        "risk_factor": 1,
                        "assigned_team": 1,
                    },
                ):
                    vuln_name = (card.get("vulnerability_name") or "").strip()
                    host_name = (card.get("host_name") or "").strip()
                    if not vuln_name:
                        continue
                    if host_name:
                        card_by_host[(vuln_name, host_name)] = card
                    if vuln_name not in card_by_name:
                        card_by_name[vuln_name] = card

                # Include both:
                # 1) admin-created records (created_by = admin_id)
                # 2) user-created records under this admin (admin_id = admin_id)
                fix_docs = list(
                    db[FIX_VULN_COLLECTION].find(
                        {
                            "report_id": report_id,
                            "$or": [
                                {"created_by": admin_id},
                                {"admin_id": admin_id},
                            ],
                        },
                        {
                            "_id": 1,
                            "plugin_name": 1,
                            "host_name": 1,
                            "steps_to_fix": 1,
                            "risk_factor": 1,
                            "severity": 1,
                            "assigned_team": 1,
                            "created_at": 1,
                        },
                    )
                )
                closed_docs = list(
                    db[FIX_VULN_CLOSED_COLLECTION].find(
                        {
                            "report_id": report_id,
                            "$or": [
                                {"created_by": admin_id},
                                {"admin_id": admin_id},
                            ],
                        },
                        {
                            "fix_vulnerability_id": 1,
                            "plugin_name": 1,
                            "host_name": 1,
                        },
                    )
                )

                steps_coll = db[FIX_VULN_STEPS_COLLECTION]
                closed_fix_ids = set()
                closed_keys = set()
                for cdoc in closed_docs:
                    cfid = str(cdoc.get("fix_vulnerability_id") or "").strip()
                    if cfid:
                        closed_fix_ids.add(cfid)
                    cpname = (cdoc.get("plugin_name") or "").strip()
                    chost = (cdoc.get("host_name") or "").strip()
                    if cpname and chost:
                        closed_keys.add((cpname, chost))

                all_fix_ids = [
                    str(fix_doc.get("_id", "")).strip()
                    for fix_doc in fix_docs
                    if str(fix_doc.get("_id", "")).strip()
                ]
                completed_steps_map = {}
                if all_fix_ids:
                    grouped_counts = steps_coll.aggregate([
                        {
                            "$match": {
                                "fix_vulnerability_id": {"$in": all_fix_ids},
                                "status": "completed",
                            }
                        },
                        {
                            "$group": {
                                "_id": "$fix_vulnerability_id",
                                "count": {"$sum": 1},
                            }
                        },
                    ])
                    completed_steps_map = {
                        str(row.get("_id") or ""): int(row.get("count") or 0)
                        for row in grouped_counts
                    }

                dedup_items = {}

                for fix_doc in fix_docs:
                    fix_id = str(fix_doc.get("_id", ""))
                    if not fix_id:
                        continue

                    vuln_name = (fix_doc.get("plugin_name") or "").strip()
                    asset = (fix_doc.get("host_name") or "").strip()
                    if not vuln_name:
                        continue

                    # Do not show vulnerabilities that are already closed.
                    if fix_id in closed_fix_ids or (vuln_name, asset) in closed_keys:
                        continue

                    card = card_by_host.get((vuln_name, asset)) or card_by_name.get(vuln_name) or {}
                    mitigation_table = card.get("mitigation_table") or fix_doc.get("steps_to_fix") or []
                    total_steps = _extract_total_steps(mitigation_table) or 6

                    completed_steps = completed_steps_map.get(fix_id, 0)

                    # Include only started-but-not-complete vulnerabilities.
                    if completed_steps <= 0 or completed_steps >= total_steps:
                        continue

                    progress_percent = int(round((completed_steps / total_steps) * 100))
                    item = {
                        "fix_vulnerability_id": fix_id,
                        "vulnerability_name": vuln_name,
                        "asset": asset,
                        "completed_steps": completed_steps,
                        "total_steps": total_steps,
                        "progress_percent": progress_percent,
                        "timeline_status": "in_process",
                        "risk_factor": _normalize_risk(card.get("risk_factor") or fix_doc.get("risk_factor") or fix_doc.get("severity")),
                        "assigned_team": _normalize_team(card.get("assigned_team") or fix_doc.get("assigned_team")),
                    }

                    # Deduplicate repeated rows for same vuln+asset; keep most progressed/latest.
                    dedup_key = (vuln_name, asset)
                    created_at = fix_doc.get("created_at")
                    if hasattr(created_at, "timestamp"):
                        created_rank = created_at.timestamp()
                    else:
                        created_rank = 0
                    rank = (completed_steps, created_rank)
                    prev = dedup_items.get(dedup_key)
                    if not prev or rank > prev["rank"]:
                        dedup_items[dedup_key] = {"rank": rank, "item": item}

                items = [v["item"] for v in dedup_items.values()]
                items.sort(key=lambda x: (-x["progress_percent"], x["vulnerability_name"], x["asset"]))
                data = {"report_id": report_id, "total": len(items), "items": items}
                cache.set(cache_key, data, 300)
                return Response(data, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminMitigationTimelineExtensionAPIView(APIView):
    """
    Team-wise severity counts for mitigation timeline extension card.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email
            team_order = TEAM_NAMES

            with MongoContext() as db:
                report_doc = _load_latest_report_meta_for_admin(db, admin_email, admin_id)
                if not report_doc:
                    return Response({
                        "report_id": None,
                        "teams": [{"team": t, "critical": 0, "high": 0, "medium": 0, "low": 0} for t in team_order],
                    }, status=status.HTTP_200_OK)

                report_id = str(report_doc.get("report_id") or report_doc.get("_id", ""))

                buckets = {t: {"team": t, "critical": 0, "high": 0, "medium": 0, "low": 0} for t in team_order}
                team_lookup = {t.lower(): t for t in team_order}

                # Count only APPROVED timeline extension requests (extension time).
                # This replaces the previous vulnerability_cards based counting.
                coll = db[TIMELINE_EXTENSION_COLLECTION]
                seen = set()
                for doc in coll.find(
                    {
                        "admin_id": admin_id,
                        "report_id": report_id,
                        "status": "approved",
                    }
                ):
                    severity_key = _normalize_severity_key(doc.get("severity"))
                    if not severity_key:
                        continue

                    team_name = (doc.get("team_name") or "").strip()
                    team = team_lookup.get(team_name.lower()) if team_name else None
                    if not team:
                        continue

                    asset = (doc.get("asset") or "").strip().lower()
                    vuln_name = (doc.get("vulnerability_name") or "").strip().lower()
                    dedup_key = (team_name.lower(), severity_key, asset, vuln_name)
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    buckets[team][severity_key] += 1

                return Response(
                    {"report_id": report_id, "teams": [buckets[t] for t in team_order]},
                    status=status.HTTP_200_OK,
                )

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class AdminMitigationTimelineExtensionReportAPIView(APIView):
    """List mitigation timeline extension requests for admin."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email
            team_filter = (request.query_params.get("team") or "").strip().lower()
            severity_filter = _normalize_severity_key(request.query_params.get("severity"))
            status_filter = (request.query_params.get("status") or "").strip().lower()
            explicit_report_id = (request.query_params.get("report_id") or "").strip()

            with MongoContext() as db:
                coll = db[TIMELINE_EXTENSION_COLLECTION]
                report_id = explicit_report_id
                if not report_id:
                    latest = _load_latest_report_meta_for_admin(db, admin_email, admin_id)
                    report_id = str(latest.get("report_id") or latest.get("_id", "")) if latest else None

                query = {"admin_id": admin_id}
                if report_id:
                    query["report_id"] = report_id
                if status_filter in {"review", "approved", "rejected"}:
                    query["status"] = status_filter

                docs = list(coll.find(query).sort("request_date", -1))
                results = []
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

                for doc in docs:
                    severity_key = _normalize_severity_key(doc.get("severity"))
                    if not severity_key:
                        continue
                    team_name = (doc.get("team_name") or "").strip()
                    if team_filter and team_name.lower() != team_filter:
                        continue
                    if severity_filter and severity_key != severity_filter:
                        continue

                    severity_counts[severity_key] += 1
                    results.append({
                        "request_id": str(doc.get("_id")),
                        "report_id": doc.get("report_id"),
                        "severity": severity_key,
                        "asset": doc.get("asset"),
                        "vul_name": doc.get("vulnerability_name"),
                        "status": doc.get("status", "review"),
                        "requested_by": doc.get("team_name"),
                        # Same fields added to the user-side report view —
                        # kept consistent so admin can see who actually
                        # submitted it (not just which team) and their own
                        # past reject reason when reviewing history.
                        "requested_by_email": doc.get("requested_by_email") or "",
                        "request_date": _to_iso(doc.get("request_date")),
                        "extension_days": int(doc.get("requested_extension_days") or 0),
                        "reason": doc.get("reason") or "",
                        "admin_comment": doc.get("admin_comment") or "",
                    })

                return Response({
                    "report_id": report_id,
                    "count": len(results),
                    "severity_counts": severity_counts,
                    "results": results,
                })
        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response({"detail": "error occurred", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminMitigationTimelineExtensionStatusAPIView(APIView):
    """Approve or reject mitigation timeline extension request."""
    permission_classes = [IsAuthenticated]

    def patch(self, request, request_id):
        try:
            admin_id = str(request.user.id)
            new_status = (request.data.get("status") or "").strip().lower()
            admin_comment = (request.data.get("admin_comment") or "").strip()
            if new_status not in {"approved", "rejected"}:
                return Response({"detail": "status must be approved or rejected"}, status=status.HTTP_400_BAD_REQUEST)

            with MongoContext() as db:
                coll = db[TIMELINE_EXTENSION_COLLECTION]
                try:
                    obj_id = ObjectId(request_id)
                except Exception:
                    return Response({"detail": "invalid request_id"}, status=status.HTTP_400_BAD_REQUEST)

                doc = coll.find_one({"_id": obj_id, "admin_id": admin_id})
                if not doc:
                    return Response({"detail": "request not found"}, status=status.HTTP_404_NOT_FOUND)

                if (doc.get("status") or "review") != "review":
                    return Response({"detail": "request already actioned"}, status=status.HTTP_400_BAD_REQUEST)

                update_payload = {
                    "status": new_status,
                    "admin_action_by": admin_id,
                    "admin_action_at": datetime.utcnow(),
                    "admin_comment": admin_comment,
                }

                risk_criteria_updated = False
                updated_risk = None

                if new_status == "approved":
                    severity_key = _normalize_severity_key(doc.get("severity"))
                    extension_days = int(doc.get("requested_extension_days") or 0)
                    original_days = int(doc.get("original_deadline_days") or 0)
                    # IMPORTANT: approving extension must NOT mutate global RiskCriteria.
                    # We only persist request-level effective deadline.
                    if severity_key:
                        updated_risk = {
                            "severity": severity_key,
                            "previous_timeline_days": original_days,
                            "extension_days": extension_days,
                            "new_timeline_days": original_days + extension_days,
                        }
                    update_payload["risk_criteria_updated"] = risk_criteria_updated
                    update_payload["effective_deadline_days"] = original_days + extension_days

                coll.update_one({"_id": obj_id}, {"$set": update_payload})
                updated = coll.find_one({"_id": obj_id})

                try:
                    from notifications.utils import create_notification
                    _requested_by_email = doc.get("requested_by_email", "")
                    _vuln_name  = doc.get("vulnerability_name", "")
                    _asset      = doc.get("asset", "")
                    _severity   = doc.get("severity", "")
                    _ext_days   = int(doc.get("requested_extension_days") or 0)
                    _n_meta = {
                        "request_id":   str(obj_id),
                        "severity":     _severity,
                        "asset":        _asset,
                        "vulnerability_name": _vuln_name,
                        "extension_days": _ext_days,
                        "admin_comment": admin_comment,
                        "status":       new_status,
                        "decided_by":   getattr(request.user, "email", ""),
                    }
                    if new_status == "approved":
                        _notif_type = 'extension_approved'
                        _n_title = f"Extension Approved: {_vuln_name[:80]}"
                        _n_msg   = (
                            f"Your deadline extension request of {_ext_days} days for "
                            f"'{_vuln_name}' on {_asset} has been approved."
                            f"{(' Comment: ' + admin_comment) if admin_comment else ''}"
                        )
                    else:
                        _notif_type = 'extension_rejected'
                        _n_title = f"Extension Rejected: {_vuln_name[:80]}"
                        _n_msg   = (
                            f"Your deadline extension request of {_ext_days} days for "
                            f"'{_vuln_name}' on {_asset} has been rejected."
                            f"{(' Reason: ' + admin_comment) if admin_comment else ''}"
                        )
                    if _requested_by_email:
                        create_notification(
                            request.user, 'user', _notif_type,
                            _n_title, _n_msg, _n_meta,
                            recipient_email=_requested_by_email
                        )
                except Exception:
                    pass

                return Response({
                    "message": "Request status updated",
                    "request_id": str(updated.get("_id")),
                    "status": updated.get("status"),
                    "risk_criteria_updated": risk_criteria_updated,
                    "updated_risk_criteria": updated_risk,
                })

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response({"detail": "error occurred", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class AdminTotalAssetsAPIView(APIView):
    """
    Returns total unique assets (hosts) from the most recently uploaded report for the logged-in admin.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cache_key = f"admin_total_assets_{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id),
                    projection={"vulnerabilities_by_host.host_name": 1,
                                "vulnerabilities_by_host.host": 1, "report_id": 1})

                if not doc:
                    return Response({"total_assets": 0, "report_id": None}, status=status.HTTP_200_OK)

                hosts = set()
                for h in (doc.get("vulnerabilities_by_host") or []):
                    host_name = (h.get("host_name") or h.get("host") or "").strip()
                    if host_name:
                        hosts.add(host_name)

                total_assets = len(hosts)
                report_id = doc.get("report_id") or str(doc.get("_id", ""))

                data = {"total_assets": total_assets, "report_id": report_id}
                cache.set(cache_key, data, 300)
                return Response(data, status=status.HTTP_200_OK)

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
                doc = _load_latest_report_for_admin(db, admin_email, admin_id,
                    projection={"vulnerabilities_by_host.host_name": 1,
                                "vulnerabilities_by_host.host": 1,
                                "vulnerabilities_by_host.host_information": 1,
                                "vulnerabilities_by_host.vulnerabilities.plugin_name": 1,
                                "vulnerabilities_by_host.vulnerabilities.pluginname": 1,
                                "vulnerabilities_by_host.vulnerabilities.name": 1,
                                "total_hosts": 1, "report_id": 1})
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

                # Real bug report: held/deleted individual vulnerabilities were
                # never excluded here — a host whose ONLY vuln for a given team
                # got deleted/held from the All Vulns/All Assets tab kept
                # counting as one of that team's assets. Whole-asset hold/
                # delete needs no separate check — that already $pulls the
                # host out of vulnerabilities_by_host, so it's absent from
                # the loop below automatically.
                held_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["hold_vulnerabilities"].find({"report_id": str(report_id)})
                }
                deleted_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["deleted_vulnerabilities"].find({"report_id": str(report_id)})
                }

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
                        if (pname, host_name) in held_vuln_keys or (pname, host_name) in deleted_vuln_keys:
                            continue
                        matched_team = plugin_team_map.get(pname)
                        if matched_team:
                            team_hosts[matched_team].add(host_name)

                total_assets = len(all_hosts) or doc.get("total_hosts", 0)

                by_team = [
                    {"team": team, "asset_count": len(hosts)}
                    for team, hosts in sorted(team_hosts.items())
                ]

                return Response({"report_id": report_id, "total_assets": total_assets, "by_team": by_team}, status=status.HTTP_200_OK)

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
        cache_key = f"admin_avg_score_{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id),
                    projection={"vulnerabilities_by_host.host_name": 1,
                                "vulnerabilities_by_host.host": 1,
                                "vulnerabilities_by_host.vulnerabilities.plugin_name": 1,
                                "vulnerabilities_by_host.vulnerabilities.cvss_v3_base_score": 1,
                                "vulnerabilities_by_host.vulnerabilities.cvss": 1,
                                "vulnerabilities_by_host.vulnerabilities.cvss_score": 1, "report_id": 1})

                if not doc:
                    return Response({"avg_score": None, "report_id": None}, status=status.HTTP_200_OK)

                report_id = doc.get("report_id") or str(doc.get("_id", ""))

                # Real bug report: avg_score never excluded held/deleted
                # vulnerabilities, so removing a high-CVSS finding from All
                # Vulns/All Assets didn't move this number even though every
                # other part of Summary (vulnerabilities, Team Performance,
                # etc.) already correctly reflected the change.
                excluded_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["hold_vulnerabilities"].find({"report_id": report_id})
                } | {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["deleted_vulnerabilities"].find({"report_id": report_id})
                }

                cvss_vals = []
                for host in doc.get("vulnerabilities_by_host") or []:
                    host_name = (host.get("host_name") or host.get("host") or "").strip()
                    for v in (host.get("vulnerabilities") or []):
                        plugin_name = (v.get("plugin_name") or "").strip()
                        if (plugin_name, host_name) in excluded_vuln_keys:
                            continue
                        cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        num = safe_float_from(cv_raw)
                        if num is not None:
                            cvss_vals.append(num)

                avg = round(sum(cvss_vals) / len(cvss_vals), 2) if cvss_vals else None

                data = {"avg_score": avg, "report_id": report_id}
                cache.set(cache_key, data, 300)
                return Response(data, status=status.HTTP_200_OK)

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
        cache_key = f"admin_vulnerabilities_{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)
        try:
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id),
                    projection={"vulnerabilities_by_host.host_name": 1,
                                "vulnerabilities_by_host.vulnerabilities.risk_factor": 1,
                                "vulnerabilities_by_host.vulnerabilities.severity": 1,
                                "vulnerabilities_by_host.vulnerabilities.plugin_name": 1, "report_id": 1})

                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                report_id = None

                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                    # Build set of closed (plugin_name, host_name) for this report
                    closed_vulns = set()
                    for closed_doc in db["fix_vulnerabilities_closed"].find(
                        {"report_id": report_id},
                        {"plugin_name": 1, "host_name": 1}
                    ):
                        p = (closed_doc.get("plugin_name") or "").strip().lower()
                        h = (closed_doc.get("host_name") or "").strip().lower()
                        if p:
                            closed_vulns.add((p, h))

                    # Real bug report: this view checked closed vulnerabilities
                    # but never hold_vulnerabilities/deleted_vulnerabilities, so
                    # a vuln deleted/held from the All Vulns/All Assets tab kept
                    # counting here even though the Team Performance API already
                    # correctly excludes it. Same (plugin_name, host_name)
                    # exclusion as AdminAssetsAPIView, normalized the same
                    # lowercase way as closed_vulns above for a consistent key.
                    excluded_vulns = set(closed_vulns)
                    for held_doc in db["hold_vulnerabilities"].find(
                        {"report_id": report_id}, {"plugin_name": 1, "host_name": 1}
                    ):
                        p = (held_doc.get("plugin_name") or "").strip().lower()
                        h = (held_doc.get("host_name") or "").strip().lower()
                        if p:
                            excluded_vulns.add((p, h))
                    for del_doc in db["deleted_vulnerabilities"].find(
                        {"report_id": report_id}, {"plugin_name": 1, "host_name": 1}
                    ):
                        p = (del_doc.get("plugin_name") or "").strip().lower()
                        h = (del_doc.get("host_name") or "").strip().lower()
                        if p:
                            excluded_vulns.add((p, h))

                    for host in doc.get("vulnerabilities_by_host") or []:
                        host_name = (host.get("host_name") or "").strip().lower()
                        for v in (host.get("vulnerabilities") or []):
                            plugin_name = (v.get("plugin_name") or "").strip().lower()

                            # Skip closed/held/deleted vulnerabilities
                            if (plugin_name, host_name) in excluded_vulns:
                                continue

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
                cache.set(cache_key, counts, 300)
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

            report_uploaded_at = None
            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))
                    report_uploaded_at = doc.get("uploaded_at")

            rc = _get_latest_riskcriteria_for_user(request.user)

            if not rc:
                return Response({"detail": "Risk criteria not found", "report_id": report_id}, status=404)

            critical_days = parse_timeline_to_days(rc.critical)
            high_days = parse_timeline_to_days(rc.high)
            medium_days = parse_timeline_to_days(rc.medium)
            low_days = parse_timeline_to_days(rc.low)

            total_days = critical_days + high_days + medium_days + low_days
            total_hours = days_to_hours(total_days)

            # Countdown starts from when criteria was set/updated
            base_datetime = rc.updated_at or rc.created_at
            if base_datetime.tzinfo is None:
                base_datetime = base_datetime.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            def _remaining(n_days):
                deadline_date = (base_datetime + timedelta(days=n_days)).date()
                now_date = now.date()
                diff = (deadline_date - now_date).days
                if diff < 0:
                    overdue_days = abs(diff)
                    return {"remaining_days": overdue_days, "remaining_label": "Overdue", "status": "overdue"}
                remaining_days = diff
                if remaining_days == 0:
                    deadline_dt = base_datetime + timedelta(days=n_days)
                    total_seconds = (deadline_dt - now).total_seconds()
                    remaining_hours = max(1, math.ceil(total_seconds / 3600)) if total_seconds > 0 else 0
                    label = f"{remaining_hours} hour{'s' if remaining_hours != 1 else ''}"
                    return {"remaining_days": 0, "remaining_label": label, "status": "active"}
                weeks, days_left = divmod(remaining_days, 7)
                if weeks > 0 and days_left > 0:
                    label = f"{weeks} week{'s' if weeks > 1 else ''} {days_left} day{'s' if days_left > 1 else ''}"
                elif weeks > 0:
                    label = f"{weeks} week{'s' if weeks > 1 else ''}"
                else:
                    label = f"{days_left} day{'s' if days_left > 1 else ''}"
                return {"remaining_days": remaining_days, "remaining_label": label, "status": "active"}

            payload = {
                "report_id": report_id,
                "base_date": str(base_datetime.date()),
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
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))
                report_id = None
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                # Build query for closed (fixed) vulnerabilities
                closed_query = {
                    "status": "closed",
                    "$or": [
                        {"created_by": admin_id},  # legacy/admin-created closures
                        {"admin_id": admin_id},    # user-created closures under this admin
                    ],
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
                doc = _load_latest_report_meta_for_admin(db, admin_email, str(request.user.id))
                report_id = None
                if doc:
                    report_id = doc.get("report_id") or str(doc.get("_id", ""))

                support_coll = db[SUPPORT_REQUEST_COLLECTION]

                # Build base query filtered by admin and report
                base_query = {"admin_id": admin_id}
                if report_id:
                    base_query["report_id"] = str(report_id)

                status_counts = list(support_coll.aggregate([
                    {"$match": base_query},
                    {
                        "$group": {
                            "_id": {"$cond": [{"$eq": ["$status", "closed"]}, "closed", "pending"]},
                            "count": {"$sum": 1},
                        }
                    },
                ]))
                counts_map = {str(row.get("_id")): int(row.get("count") or 0) for row in status_counts}
                pending_count = counts_map.get("pending", 0)
                closed_count = counts_map.get("closed", 0)

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


# class AdminDashboardSummaryAPIView(APIView):
#     """
#     Returns a complete dashboard summary for the logged-in admin.
#     Fetches data from the MOST RECENTLY uploaded report only.
#     Combines all dashboard metrics in a single API call for efficiency.
#     """
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         try:
#             admin_email = request.user.email
#             admin_id = str(request.user.id)

#             with MongoContext() as db:
#                 doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

#                 # Initialize default values
#                 total_assets = 0
#                 avg_score = None
#                 vuln_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#                 report_id = None

#                 if doc:
#                     report_id = doc.get("report_id")

#                     # ---- Total Assets ----
#                     hosts = set()
#                     for h in (doc.get("vulnerabilities_by_host") or []):
#                         host_name = (h.get("host_name") or h.get("host") or "").strip()
#                         if host_name:
#                             hosts.add(host_name)
#                     total_assets = len(hosts)

#                     # ---- Average CVSS Score ----
#                     cvss_vals = []
#                     for host in doc.get("vulnerabilities_by_host") or []:
#                         for v in (host.get("vulnerabilities") or []):
#                             cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
#                             num = safe_float_from(cv_raw)
#                             if num is not None:
#                                 cvss_vals.append(num)
#                     avg_score = round(sum(cvss_vals) / len(cvss_vals), 2) if cvss_vals else None

#                     # ---- Vulnerability Counts ----
#                     for host in doc.get("vulnerabilities_by_host") or []:
#                         for v in (host.get("vulnerabilities") or []):
#                             risk = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
#                             if risk.startswith("crit"):
#                                 vuln_counts["critical"] += 1
#                             elif risk.startswith("high"):
#                                 vuln_counts["high"] += 1
#                             elif risk.startswith("med"):
#                                 vuln_counts["medium"] += 1
#                             elif risk.startswith("low"):
#                                 vuln_counts["low"] += 1

#                 # ---- Fixed Vulnerabilities ----
#                 fix_coll = db[FIX_VULN_COLLECTION]
#                 fixed_vulns = list(fix_coll.find({
#                     "created_by": admin_id,
#                     "status": "close"
#                 }))

#                 fixed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#                 for vuln in fixed_vulns:
#                     risk = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
#                     if risk.startswith("crit"):
#                         fixed_counts["critical"] += 1
#                     elif risk.startswith("high"):
#                         fixed_counts["high"] += 1
#                     elif risk.startswith("med"):
#                         fixed_counts["medium"] += 1
#                     elif risk.startswith("low"):
#                         fixed_counts["low"] += 1

#                 total_fixed = sum(fixed_counts.values())

#                 # ---- Support Requests ----
#                 support_coll = db[SUPPORT_REQUEST_COLLECTION]
#                 pending_requests = support_coll.count_documents({
#                     "admin_id": admin_id,
#                     "status": {"$ne": "closed"}
#                 })
#                 closed_requests = support_coll.count_documents({
#                     "admin_id": admin_id,
#                     "status": "closed"
#                 })

#             # ---- Mitigation Timeline & MTTR ----
#             rc = _get_latest_riskcriteria_for_user(request.user)
#             mitigation_timeline = None
#             mean_time_to_remediate = None

#             if rc:
#                 critical_days = parse_timeline_to_days(rc.critical)
#                 high_days = parse_timeline_to_days(rc.high)
#                 medium_days = parse_timeline_to_days(rc.medium)
#                 low_days = parse_timeline_to_days(rc.low)

#                 total_days = critical_days + high_days + medium_days + low_days

#                 mitigation_timeline = {
#                     "critical": {"raw": rc.critical, "days": critical_days, "label": days_to_week_label(critical_days)},
#                     "high": {"raw": rc.high, "days": high_days, "label": days_to_week_label(high_days)},
#                     "medium": {"raw": rc.medium, "days": medium_days, "label": days_to_week_label(medium_days)},
#                     "low": {"raw": rc.low, "days": low_days, "label": days_to_week_label(low_days)},
#                 }

#                 critical_hours = days_to_hours(critical_days)
#                 high_hours = days_to_hours(high_days)
#                 medium_hours = days_to_hours(medium_days)
#                 low_hours = days_to_hours(low_days)

#                 total_hours = critical_hours + high_hours + medium_hours + low_hours
#                 mttr_hours = round(total_hours / 4)
#                 mttr_wdh = hours_to_wdh(mttr_hours)

#                 mean_time_to_remediate = {
#                     "hours": mttr_hours,
#                     "weeks": mttr_wdh["weeks"],
#                     "days": mttr_wdh["days"],
#                     "hours_remaining": mttr_wdh["hours"],
#                     "label": format_wdh_label(mttr_wdh)
#                 }

#             summary = {
#                 "report_id": report_id,
#                 "total_assets": total_assets,
#                 "avg_score": avg_score,
#                 "vulnerabilities": vuln_counts,
#                 "vulnerabilities_fixed": {
#                     "total": total_fixed,
#                     "critical": fixed_counts["critical"],
#                     "high": fixed_counts["high"],
#                     "medium": fixed_counts["medium"],
#                     "low": fixed_counts["low"]
#                 },
#                 "support_requests": {
#                     "total": pending_requests + closed_requests,
#                     "pending": pending_requests,
#                     "closed": closed_requests
#                 },
#                 "mitigation_timeline": mitigation_timeline,
#                 "mean_time_to_remediate": mean_time_to_remediate
#             }
#             return Response(summary, status=status.HTTP_200_OK)

#         except Exception as e:
#             import traceback
#             traceback.print_exc()
#             return Response(
#                 {"detail": "error occurred", "error": str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


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

                # Build set of closed (plugin_name, host_name) pairs — per-host match only
                admin_id = str(request.user.id)
                closed_vuln_keys = set()
                for doc_c in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": report_id, "$or": [{"created_by": admin_id}, {"admin_id": admin_id}]}
                ):
                    pname = (doc_c.get("plugin_name") or "").strip()
                    hname = (doc_c.get("host_name") or "").strip()
                    if pname:
                        closed_vuln_keys.add((pname, hname))

                # Real bug report: this view (source of the "download-data"
                # report's team_distribution) never checked hold_vulnerabilities/
                # deleted_vulnerabilities, nor whole-asset holds — same gap as
                # AdminDetailedVulnerabilitiesAPIView, fixed the same way
                # AdminDistributionByTeamDetailAPIView (the "Team Performance"
                # view already confirmed correct) already does it: cards come
                # from vulnerability_cards, a static snapshot never updated by
                # hold/unhold/delete, so both an asset-level hold ($pull from
                # vulnerabilities_by_host) and a per-vulnerability hold/delete
                # need an explicit check here.
                active_host_names = {
                    (h.get("host_name") or h.get("host") or "").strip()
                    for h in doc.get("vulnerabilities_by_host", [])
                }
                held_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["hold_vulnerabilities"].find({"report_id": report_id})
                }
                deleted_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["deleted_vulnerabilities"].find({"report_id": report_id})
                }

                # Count distribution directly from vulnerability_cards (excluding closed)
                # Each card = one unique vulnerability — avoids inflating counts from multi-host repeats
                counts = {name: 0 for name in TEAM_NAMES}
                counts["Unassigned"] = 0
                total = 0

                for card in vuln_card_coll.find({"report_id": report_id}):
                    plugin_name = (card.get("vulnerability_name") or "").strip()
                    host_name   = (card.get("host_name") or "").strip()
                    if host_name not in active_host_names:
                        continue
                    key = (plugin_name, host_name)
                    if key in closed_vuln_keys or key in held_vuln_keys or key in deleted_vuln_keys:
                        continue
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

                # ── closed (plugin_name, host_name) pairs — per-host match only ──
                # Match both admin-closed (created_by=admin) and user-closed (admin_id=admin)
                closed_vuln_keys = set()
                for doc_c in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": report_id, "$or": [{"created_by": admin_id}, {"admin_id": admin_id}]}
                ):
                    pname = (doc_c.get("plugin_name") or "").strip()
                    hname = (doc_c.get("host_name") or "").strip()
                    if pname:
                        closed_vuln_keys.add((pname, hname))

                # ── currently-active hosts — vulnerability_cards is populated once
                # at card-generation time and never touched by hold/unhold/delete
                # (those only update nessus_reports + their own hold_assets /
                # deleted_assets / hold_vulnerabilities / deleted_vulnerabilities
                # collections), so without this check a held or deleted asset's
                # cards would still be counted here.
                active_host_names = set()
                for host in doc.get("vulnerabilities_by_host", []):
                    hn = (host.get("host_name") or host.get("host") or "").strip()
                    if hn:
                        active_host_names.add(hn)

                held_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["hold_vulnerabilities"].find({"report_id": report_id})
                }
                deleted_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["deleted_vulnerabilities"].find({"report_id": report_id})
                }

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
                    plugin_name = (card.get("vulnerability_name") or "").strip()
                    host_name   = (card.get("host_name") or "").strip()

                    # Whole asset held/deleted → its cards no longer belong to
                    # the active report. Per-vulnerability held/deleted → this
                    # specific (host, vuln) pair was pulled out on its own.
                    if host_name not in active_host_names:
                        continue
                    key = (plugin_name, host_name)
                    if key in held_vuln_keys or key in deleted_vuln_keys:
                        continue

                    risk_label  = plugin_risk.get(plugin_name)
                    # Real bug report: Info-severity (and any other
                    # unrecognized risk_factor) findings still counted
                    # toward a team's "total"/"open" here even though they
                    # never match any of the 4 risk_levels buckets above —
                    # inflated the OPEN count (e.g. 14 shown, but
                    # critical+high+medium+low only summed to 13) with an
                    # Info finding invisible anywhere in the severity
                    # breakdown. Info must never be counted, same explicit
                    # repeated rule as everywhere else — skip the card
                    # entirely instead of just leaving it out of by_risk.
                    if not risk_label:
                        continue

                    raw_team    = (card.get("assigned_team", "") or "").strip()
                    team_key    = team_names_lower.get(raw_team.lower(), "") or "Unassigned"

                    is_closed   = (plugin_name, host_name) in closed_vuln_keys
                    vuln_status = "closed" if is_closed else "open"

                    bucket = teams[team_key]
                    bucket["total"] += 1
                    bucket[vuln_status] += 1
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
      - status              (open / in_progress / open/review / closed —
                             from fix_vulnerabilities + fix_vulnerabilities_closed)

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

                # ── closed (plugin_name, host_name) pairs — per-host match only ──
                # Match both admin-closed (created_by=admin) and user-closed (admin_id=admin)
                closed_vuln_keys = set()
                for doc_c in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": report_id, "$or": [{"created_by": admin_id}, {"admin_id": admin_id}]}
                ):
                    pname = (doc_c.get("plugin_name") or "").strip()
                    hname = (doc_c.get("host_name") or "").strip()
                    if pname:
                        closed_vuln_keys.add((pname, hname))

                # Real bug report: this view (source of the "download-data"
                # report's vulnerabilities_detail list) never checked
                # hold_vulnerabilities/deleted_vulnerabilities, so a vuln
                # deleted/held from the All Vulns/All Assets tab kept showing
                # up here even though Team Performance
                # (AdminDistributionByTeamDetailAPIView) already excludes it.
                # A whole-asset hold/delete needs no separate check here —
                # this view's row-building loop below reads straight from
                # vulnerabilities_by_host, and asset-level hold/delete
                # ($pull in AssetHoldAPIView/AssetDeleteAPIView) already
                # physically removes that host from vulnerabilities_by_host,
                # so it's absent from this loop automatically.
                excluded_vuln_keys = {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["hold_vulnerabilities"].find({"report_id": report_id})
                } | {
                    ((d.get("plugin_name") or "").strip(), (d.get("host_name") or "").strip())
                    for d in db["deleted_vulnerabilities"].find({"report_id": report_id})
                }

                # ── active fix status ("in_progress" / "open/review") ────────────
                # This previously only checked the closed collection, so any vuln
                # a team had started (or sent for verification) but wasn't closed
                # yet showed as plain "open" — indistinguishable from untouched.
                active_status_by_key = {}
                for doc_a in db[FIX_VULN_COLLECTION].find(
                    {"report_id": report_id, "$or": [{"created_by": admin_id}, {"admin_id": admin_id}]},
                    {"plugin_name": 1, "host_name": 1, "status": 1},
                ):
                    pname = (doc_a.get("plugin_name") or "").strip()
                    hname = (doc_a.get("host_name") or "").strip()
                    st    = (doc_a.get("status") or "").strip()
                    if pname and st and st != "open":
                        active_status_by_key[(pname, hname)] = st

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

                # ── build one row per (vulnerability, host, port) from nessus ─────
                vulnerabilities = []
                seen = set()    # avoid duplicate (plugin_name, host_name, port) rows

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
                        if (plugin_name, h_name) in excluded_vuln_keys:
                            continue

                        port = v.get("port", "")
                        row_key = (plugin_name, h_name, str(port))
                        if row_key in seen:
                            continue
                        seen.add(row_key)

                        # Exact (vuln, host) match first; fall back to vuln-only
                        info = card_by_host.get((plugin_name, h_name)) \
                               or card_by_name.get(plugin_name) \
                               or {}

                        found_date    = info.get("found_date")
                        risk_factor   = plugin_risk.get(plugin_name)
                        if (plugin_name, h_name) in closed_vuln_keys:
                            vuln_status = "closed"
                        else:
                            vuln_status = active_status_by_key.get((plugin_name, h_name), "open")
                        assigned_team = (info.get("assigned_team") or "").strip()

                        vulnerabilities.append({
                            "vulnerability_name": plugin_name,
                            "assets":             h_name,
                            "port":               port,
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
    Returns whether the admin has any uploaded reports AND whether they've
    configured Risk Criteria — the same two-step onboarding gate the Slack
    bot enforces (see users.views._get_admin_onboarding_state). Frontend
    should use `state` to decide which screen to show:
      "no_report"           -> waiting screen (Super Admin hasn't uploaded yet)
      "needs_risk_criteria" -> risk criteria setup form
      "ready"               -> normal dashboard
    `has_report`/`show_dashboard` are kept as-is for any existing caller
    that only checked those two fields before this was extended.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            admin_id = str(request.user.id)
            admin_email = request.user.email

            with MongoContext() as db:
                doc = _load_latest_report_for_admin(db, admin_email, str(request.user.id))

            if not doc:
                return Response({
                    "state": "no_report",
                    "has_report": False,
                    "has_risk_criteria": False,
                    "show_dashboard": False,
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "report_id": None,
                    "message": "No report uploaded yet. Please wait for Super Admin to upload a report."
                }, status=status.HTTP_200_OK)

            report_id = doc.get("report_id") or str(doc.get("_id", ""))
            has_risk_criteria = bool(RiskCriteria and RiskCriteria.objects.filter(admin=request.user).exists())

            if not has_risk_criteria:
                return Response({
                    "state": "needs_risk_criteria",
                    "has_report": True,
                    "has_risk_criteria": False,
                    "show_dashboard": False,
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "report_id": report_id,
                    "message": "Report available — set your Risk Criteria to continue."
                }, status=status.HTTP_200_OK)

            return Response({
                "state": "ready",
                "has_report": True,
                "has_risk_criteria": True,
                "show_dashboard": True,
                "admin_id": admin_id,
                "admin_email": admin_email,
                "report_id": report_id,
                "message": "Report available"
            }, status=status.HTTP_200_OK)

        except Exception as e:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "error occurred", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


def _freemium_upgrade_prompt(admin) -> dict:
    """
    Surfaces the "upgrade to unlock N more assets" signal for the Freemium
    dashboard banner — eligible once an admin has closed every currently
    VISIBLE finding on a report that still has locked_hosts waiting (set
    aside at upload time by billing.enforcement.select_freemium_active_hosts,
    never discarded; restored automatically on upgrade by
    upload_report.views.unlock_freemium_hosts_for_admin — no re-upload).

    "Visible finding closed" reuses the exact same (plugin_name, host_name)
    active-minus-closed set logic AdminVulnerabilitiesAPIView already uses,
    so this never disagrees with what the admin sees elsewhere on the
    dashboard about what's still open.
    """
    from billing.enforcement import is_freemium, _is_unlimited_admin

    if _is_unlimited_admin(admin) or not is_freemium(admin):
        return {"eligible": False}

    with MongoContext() as db:
        reports = list(db["nessus_reports"].find(
            {
                "$or": [{"admin_id": str(admin.id)}, {"admin_email": admin.email}],
                "locked_hosts": {"$exists": True, "$ne": []},
            },
            {"report_id": 1, "vulnerabilities_by_host": 1, "locked_hosts": 1},
        ))
        if not reports:
            return {"eligible": False}

        total_locked_assets = 0
        any_fully_closed = False
        for report in reports:
            report_id = report.get("report_id")
            locked_hosts = report.get("locked_hosts") or []
            total_locked_assets += len({h.get("host_name") for h in locked_hosts if h.get("host_name")})

            active_pairs = set()
            for host in report.get("vulnerabilities_by_host") or []:
                host_name = (host.get("host_name") or "").strip().lower()
                for v in (host.get("vulnerabilities") or []):
                    p = (v.get("plugin_name") or "").strip().lower()
                    if p:
                        active_pairs.add((p, host_name))

            if not active_pairs:
                continue  # nothing visible on this report to have "closed" yet

            closed_pairs = set()
            for closed_doc in db["fix_vulnerabilities_closed"].find(
                {"report_id": report_id}, {"plugin_name": 1, "host_name": 1}
            ):
                p = (closed_doc.get("plugin_name") or "").strip().lower()
                h = (closed_doc.get("host_name") or "").strip().lower()
                if p:
                    closed_pairs.add((p, h))

            if active_pairs <= closed_pairs:
                any_fully_closed = True

    if not any_fully_closed:
        return {"eligible": False, "locked_assets": total_locked_assets}

    return {
        "eligible": True,
        "locked_assets": total_locked_assets,
        "message": (
            f"You've closed every visible finding — upgrade to Premium to unlock "
            f"{total_locked_assets} more asset(s) from this file, no re-upload needed."
        ),
        "upgrade_url": "https://vaptfix.ai/pricingplan",
    }


class AdminDashboardSummaryAPIView(APIView):
    """
    Single API that returns all 7 admin dashboard metrics in one response.
    GET /api/admin/dashboard/summary/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from concurrent.futures import ThreadPoolExecutor

        cache_key = f"admin_dashboard_summary_{request.user.id}"
        cached = cache.get(cache_key)
        if cached is not None:
            return Response(cached, status=status.HTTP_200_OK)

        views_map = {
            "total_assets":          AdminTotalAssetsAPIView,
            "avg_score":             AdminAvgScoreAPIView,
            "vulnerabilities":       AdminVulnerabilitiesAPIView,
            "mitigation_timeline":   AdminMitigationTimelineAPIView,
            "mean_time_remediate":   AdminMeanTimeRemediateAPIView,
            "vulnerabilities_fixed": AdminVulnerabilitiesFixedAPIView,
            "support_requests":      AdminSupportRequestsAPIView,
        }

        results = {}
        with ThreadPoolExecutor(max_workers=7) as executor:
            futures = {key: executor.submit(cls().get, request) for key, cls in views_map.items()}
            for key, future in futures.items():
                try:
                    results[key] = future.result().data
                except Exception as exc:
                    results[key] = {"error": str(exc)}

        try:
            results["freemium_upgrade"] = _freemium_upgrade_prompt(request.user)
        except Exception as exc:
            logger.warning(f"[AdminDashboardSummary] freemium_upgrade check failed: {exc}")
            results["freemium_upgrade"] = {"eligible": False}

        # Explicit billing breakdown, always present (not gated behind
        # freemium_upgrade.eligible, which only turns true once every
        # visible finding is closed) — the pricing/Review-plan page needs
        # to know the full original file size right after upload, not only
        # once the admin has worked through their 5 visible assets.
        try:
            from billing.asset_service import get_admin_asset_breakdown_counts
            results.update(get_admin_asset_breakdown_counts(str(request.user.id)))
        except Exception as exc:
            logger.warning(f"[AdminDashboardSummary] asset breakdown counts failed: {exc}")

        cache.set(cache_key, results, 300)
        return Response(results, status=status.HTTP_200_OK)
