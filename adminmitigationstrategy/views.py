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

class MitigationStrategyLatestAPIView(APIView):
    """
    Returns vulnerabilities from the LATEST nessus report for the current Admin,
    enriched with OS info and upload_reports status.

    Mirrors the logic of LatestSuperAdminVulnerabilityRegisterAPIView in adminregister,
    adding:
      - os         : from nessus_reports.vulnerabilities_by_host[].host_information
      - report_status : from upload_reports.status (Django model)

    GET /api/admin/adminmitigation-strategy/latest/

    Response rows include:
        host_name, os, plugin_name, risk_factor, port, protocol, vuln_status
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        try:
            current_admin_id    = str(request.user.id)
            current_admin_email = getattr(request.user, "email", None)

            with MongoContext() as db:
                nessus_coll = db[NESSUS_COLLECTION]
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                # Find the LATEST report for this admin (by admin_id OR admin_email)
                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                latest_doc = nessus_coll.find_one(
                    {"$or": query_conditions},
                    sort=[("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {
                            "detail": "No reports found for your account",
                            "admin_id": current_admin_id,
                            "admin_email": current_admin_email,
                        },
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id   = latest_doc.get("report_id")
                uploaded_at = latest_doc.get("uploaded_at")
                admin_id    = latest_doc.get("admin_id")
                admin_email = latest_doc.get("admin_email")

                # ── Get upload_reports.status via Django ORM ──────────────
                report_status = "unknown"
                try:
                    upload_obj = UploadReport.objects.filter(
                        _id=ObjectId(report_id)
                    ).first()
                    if upload_obj:
                        report_status = upload_obj.status or "unknown"
                except Exception:
                    report_status = "unknown"

                # ── Build set of closed vulnerability keys ────────────────
                closed_vulns = set()
                for doc in closed_coll.find(
                    {"report_id": str(report_id), "created_by": admin_id}
                ):
                    key = (
                        doc.get("plugin_name", ""),
                        doc.get("host_name", ""),
                        str(doc.get("port", "")),
                    )
                    closed_vulns.add(key)

                # ── Extract ALL vulnerabilities (first pass) ──────────────
                all_rows = []

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""
                    host_info = host.get("host_information") or {}

                    os_value = (
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

                        all_rows.append(
                            {
                                "id":          str(uuid.uuid4()),
                                "host_name":   host_name,
                                "os":          os_value,
                                "plugin_name": plugin_name,
                                "risk_factor": risk_factor,
                                "port":        port,
                                "protocol":    protocol,
                                "status":      vuln_status,
                            }
                        )

                # ── Filter rules ──────────────────────────────────────────
                # Critical  → include ALL
                # High / Medium / Low → include only REPEATED
                #   (plugin_name appears on more than one host)

                # Count how many distinct hosts each plugin_name appears on
                from collections import Counter
                plugin_host_count = Counter(
                    r["plugin_name"]
                    for r in all_rows
                    if r["risk_factor"].lower() != "critical"
                )

                rows = [
                    r for r in all_rows
                    if r["risk_factor"].lower() == "critical"
                    or plugin_host_count.get(r["plugin_name"], 0) > 1
                ]

                return Response(
                    {
                        "report_id":     str(report_id),
                        "report_status": report_status,
                        "admin_id":      current_admin_id,
                        "admin_email":   current_admin_email,
                        "uploaded_by": {
                            "admin_id":    admin_id,
                            "admin_email": admin_email,
                        },
                        "uploaded_at": _normalize_iso(uploaded_at),
                        "count":       len(rows),
                        "vulnerabilities": rows,
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


class MitigationStrategyByHostAPIView(APIView):
    """
    Returns vulnerabilities for a specific host from the latest nessus report,
    with OS and upload_reports status.

    GET /api/admin/adminmitigation-strategy/host/<host_name>/vulnerabilities/
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request, host_name):
        try:
            current_admin_id    = str(request.user.id)
            current_admin_email = getattr(request.user, "email", None)

            with MongoContext() as db:
                nessus_coll = db[NESSUS_COLLECTION]
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

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

                report_id = latest_doc.get("report_id")
                admin_id  = latest_doc.get("admin_id")

                # upload_reports status
                report_status = "unknown"
                try:
                    upload_obj = UploadReport.objects.filter(
                        _id=ObjectId(report_id)
                    ).first()
                    if upload_obj:
                        report_status = upload_obj.status or "unknown"
                except Exception:
                    report_status = "unknown"

                # Closed vulnerability keys
                closed_vulns = set()
                for doc in closed_coll.find(
                    {"report_id": str(report_id), "created_by": admin_id}
                ):
                    closed_vulns.add(
                        (
                            doc.get("plugin_name", ""),
                            doc.get("host_name", ""),
                            str(doc.get("port", "")),
                        )
                    )

                rows = []
                os_value = ""

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    h_name = host.get("host_name") or host.get("host") or ""
                    if h_name != host_name:
                        continue

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

                        rows.append(
                            {
                                "id":          str(uuid.uuid4()),
                                "host_name":   host_name,
                                "os":          os_value,
                                "plugin_name": plugin_name,
                                "risk_factor": risk_factor,
                                "port":        port,
                                "protocol":    protocol,
                                "status":      vuln_status,
                            }
                        )
                    break  # found the host, no need to continue

                if not rows and not os_value:
                    return Response(
                        {"detail": f"Host '{host_name}' not found in the latest report"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                return Response(
                    {
                        "report_id":     str(report_id),
                        "report_status": report_status,
                        "admin_id":      current_admin_id,
                        "host_name":     host_name,
                        "os":            os_value,
                        "count":         len(rows),
                        "vulnerabilities": rows,
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
