from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
import pymongo
from urllib.parse import urlparse
import re

from .serializers import AdminRegisterSimpleVulnSerializer

NESSUS_COLLECTION = "nessus_reports"

# Robust MongoContext: same as before but compact
class MongoContext:
    def __init__(self):
        self.uri = getattr(settings, "MONGO_DB_URL", None)
        if not self.uri:
            self.uri = settings.DATABASES.get('default', {}).get('CLIENT', {}).get('host')
        self.client = None
        self.db = None

    def __enter__(self):
        if not self.uri:
            raise RuntimeError("MongoDB URI not configured. Set MONGO_DB_URL or DATABASES['default']['CLIENT']['host'].")
        self.client = pymongo.MongoClient(self.uri, serverSelectionTimeoutMS=5000)

        dbname = getattr(settings, "MONGO_DB_NAME", None)
        if not dbname:
            try:
                parsed = urlparse(self.uri)
                path = (parsed.path or "").lstrip("/")
                if path:
                    dbname = re.split(r"[/?]", path)[0]
            except Exception:
                dbname = None

        if not dbname:
            try:
                d = self.client.get_default_database()
                if d: dbname = d.name
            except Exception:
                dbname = None

        if not dbname:
            dbname = "vaptfix"

        self.db = self.client[dbname]
        return self.db

    def __exit__(self, exc_type, exc, tb):
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

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

class VulnerabilityRegisterAPIView(APIView):
    """
    Returns a list of vulnerabilities for a report_id but only the 6 fields required by the UI.
    GET /api/adminregister/report/<report_id>/vulns-simple/
    """
    permission_classes = [permissions.IsAuthenticated]  # change to AllowAny if wanted

    def get(self, request, report_id):
        try:
            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                doc = coll.find_one({"report_id": str(report_id)})
                if not doc:
                    return Response({"detail": "report not found"}, status=status.HTTP_404_NOT_FOUND)

                uploaded_at = doc.get("uploaded_at")

                out = []
                # iterate hosts -> vulnerabilities
                for host in doc.get("vulnerabilities_by_host", []) or []:
                    host_name = host.get("host_name") or host.get("host") or ""
                    for v in (host.get("vulnerabilities") or []):
                        # map fields defensively
                        plugin_name = v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                        # severity/risk
                        risk_raw = v.get("risk_factor") or v.get("severity") or v.get("risk") or ""
                        severity = risk_raw.strip().title() if isinstance(risk_raw, str) else risk_raw

                        # prefer per-vuln created/updated if present, otherwise fallback
                        first_obs = v.get("created_at") or v.get("first_observation") or uploaded_at
                        second_obs = v.get("updated_at") or v.get("second_observation") or None

                        item = {
                            "vul_name": plugin_name,
                            "asset": host_name,
                            "severity": severity or "",
                            "first_observation": _normalize_iso(first_obs),
                            "second_observation": _normalize_iso(second_obs),
                            "status": "open",
                        }
                        out.append(item)

                # optional: you can sort by first_observation or severity here if desired
                serializer = AdminRegisterSimpleVulnSerializer(out, many=True)
                return Response({"report_id": str(report_id), "count": len(out), "rows": serializer.data}, status=status.HTTP_200_OK)

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response({"detail":"cannot connect to MongoDB", "error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as rexc:
            return Response({"detail": str(rexc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail":"unexpected error", "error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
