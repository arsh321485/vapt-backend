from django.shortcuts import render

# Create your views here.
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
import pymongo
import threading
import uuid
from urllib.parse import urlparse
import re
from rest_framework.parsers import JSONParser
from bson import ObjectId

from upload_report.models import UploadReport

# ── Collection names ────────────────────────────────────────────────────────
NESSUS_COLLECTION          = "nessus_reports"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
VULN_CARD_COLLECTION       = "vulnerability_cards"

TEAM_NAMES = [
    "Patch Management",
    "Network Security",
    "Architectural Flaws",
    "Configuration Management",
]

# ── Shared MongoDB connection pool ──────────────────────────────────────────
_mongo_client: pymongo.MongoClient = None
_mongo_lock = threading.Lock()


def _get_mongo_client() -> pymongo.MongoClient:
    global _mongo_client
    if _mongo_client is None:
        with _mongo_lock:
            if _mongo_client is None:
                uri = getattr(settings, "MONGO_DB_URL", None)
                if not uri:
                    uri = (
                        settings.DATABASES.get("default", {})
                        .get("CLIENT", {})
                        .get("host")
                    )
                if not uri:
                    raise RuntimeError(
                        "MongoDB URI not configured. "
                        "Set MONGO_DB_URL or DATABASES['default']['CLIENT']['host']."
                    )
                _mongo_client = pymongo.MongoClient(
                    uri,
                    serverSelectionTimeoutMS=5000,
                    connectTimeoutMS=5000,
                    socketTimeoutMS=10000,
                    maxPoolSize=50,
                    minPoolSize=5,
                    retryWrites=True,
                )
    return _mongo_client


def _get_db(client: pymongo.MongoClient):
    dbname = getattr(settings, "MONGO_DB_NAME", None)
    if not dbname:
        uri = getattr(settings, "MONGO_DB_URL", None) or (
            settings.DATABASES.get("default", {}).get("CLIENT", {}).get("host", "")
        )
        try:
            parsed = urlparse(uri)
            path = (parsed.path or "").lstrip("/")
            if path:
                dbname = re.split(r"[/?]", path)[0]
        except Exception:
            dbname = None
        if not dbname:
            try:
                d = client.get_default_database()
                if d:
                    dbname = d.name
            except Exception:
                dbname = None
    return client[dbname or "vaptfix"]


class MongoContext:
    """Context manager using a shared MongoDB connection pool."""

    def __enter__(self):
        return _get_db(_get_mongo_client())

    def __exit__(self, exc_type, exc, tb):
        pass  # Connection is pooled — do not close


def _normalize_iso(dt):
    """Return ISO string for datetime-like or string; else None."""
    if not dt:
        return None
    if isinstance(dt, datetime):
        d = dt
        if is_naive(d):
            d = make_aware(d)
        return d.isoformat()
    return str(dt)


# ── API View ─────────────────────────────────────────────────────────────────

class MitigationStrategyByTeamAPIView(APIView):
    """
    Returns vulnerabilities from latest nessus report, grouped by assigned_team.
    Team is fetched from vulnerability_cards collection (matched by report_id + vulnerability_name + host_name).

    GET /api/admin/adminmitigation-strategy/by-team/
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        try:
            current_admin_id    = str(request.user.id)
            current_admin_email = getattr(request.user, "email", None)

            with MongoContext() as db:
                nessus_coll     = db[NESSUS_COLLECTION]
                closed_coll     = db[FIX_VULN_CLOSED_COLLECTION]
                vuln_card_coll  = db[VULN_CARD_COLLECTION]

                # Latest report for this admin
                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                latest_doc = nessus_coll.find_one(
                    {"$or": query_conditions},
                    sort=[("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))
                admin_id  = latest_doc.get("admin_id", current_admin_id)

                # upload_reports status
                report_status = "unknown"
                try:
                    upload_obj = UploadReport.objects.filter(
                        _id=ObjectId(report_id)
                    ).first()
                    if upload_obj:
                        report_status = upload_obj.status or "unknown"
                except Exception:
                    pass

                # Build closed vulnerability keys set
                closed_vulns = set()
                for doc in closed_coll.find(
                    {"report_id": report_id, "created_by": admin_id}
                ):
                    closed_vulns.add((
                        doc.get("plugin_name", ""),
                        doc.get("host_name", ""),
                        str(doc.get("port", "")),
                    ))

                # Bulk-fetch all vulnerability_cards for this report
                vuln_cards = {}
                for card in vuln_card_coll.find({"report_id": report_id}):
                    key = (
                        card.get("vulnerability_name", ""),
                        card.get("host_name", ""),
                    )
                    vuln_cards[key] = card

                # Initialize team buckets
                teams = {name: [] for name in TEAM_NAMES}
                teams["Unassigned"] = []

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""
                    host_info = host.get("host_information") or {}
                    os_value  = (
                        host_info.get("os")
                        or host_info.get("operating-system")
                        or host_info.get("operating_system")
                        or host_info.get("OS")
                        or ""
                    )

                    for v in host.get("vulnerabilities", []):
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )
                        port     = v.get("port", "")
                        protocol = v.get("protocol", "")
                        risk_raw = (
                            v.get("risk_factor")
                            or v.get("severity")
                            or v.get("risk")
                            or ""
                        )
                        risk_factor = (
                            risk_raw.strip().title()
                            if isinstance(risk_raw, str)
                            else ""
                        )
                        vuln_status = (
                            "closed"
                            if (plugin_name, host_name, str(port)) in closed_vulns
                            else "open"
                        )

                        # Lookup assigned_team from vulnerability_cards
                        card = (
                            vuln_cards.get((plugin_name, host_name))
                            or vuln_cards.get((plugin_name, ""))
                        )
                        assigned_team = (card or {}).get("assigned_team", "") or ""

                        row = {
                            "id":            str(uuid.uuid4()),
                            "host_name":     host_name,
                            "os":            os_value,
                            "plugin_name":   plugin_name,
                            "risk_factor":   risk_factor,
                            "port":          port,
                            "protocol":      protocol,
                            "status":        vuln_status,
                            "assigned_team": assigned_team,
                        }

                        if assigned_team in teams:
                            teams[assigned_team].append(row)
                        else:
                            teams["Unassigned"].append(row)

                teams_response = {
                    team_name: {
                        "count": len(vulns),
                        "vulnerabilities": vulns,
                    }
                    for team_name, vulns in teams.items()
                }

                return Response(
                    {
                        "report_id":     report_id,
                        "report_status": report_status,
                        "admin_id":      current_admin_id,
                        "admin_email":   current_admin_email,
                        "uploaded_at":   _normalize_iso(latest_doc.get("uploaded_at")),
                        "teams":         teams_response,
                    },
                    status=status.HTTP_200_OK,
                )

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response(
                {"detail": "Cannot connect to MongoDB", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "Unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
