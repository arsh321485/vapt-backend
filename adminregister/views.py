from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
import pymongo
from urllib.parse import urlparse
import re
from rest_framework.parsers import JSONParser

from .serializers import AdminRegisterSimpleVulnSerializer,FixVulnerabilitySerializer
FIX_VULN_COLLECTION = "fix_vulnerabilities"
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

# ===============================
# TEAM ASSIGNMENT HELPERS
# ===============================
HOST_TEAM_MAP = {
    "192.168.0.2": "Patch Management",
    "192.168.0.5": "Network Security",
    "192.168.0.6": "Configuration Management",
    "192.168.0.9": "Architectural Flaws",
}

def get_assigned_team_by_host(host_name: str) -> str:
    return HOST_TEAM_MAP.get(host_name, "Patch Management")

def get_team_members(db, team_name):
    members = []

    cursor = db["users_details_userdetail"].find({
        "Member_role": {
            "$elemMatch": {
                "$regex": f"^{team_name}$",
                "$options": "i"
            }
        }
    })

    for u in cursor:
        members.append({
            "user_id": str(u["_id"]),
            "name": f"{u.get('first_name', '')} {u.get('last_name', '')}",
            "email": u.get("email")
        })

    return members

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
        
        
class FixVulnerabilityCreateAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request):
        serializer = FixVulnerabilitySerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        host_name = serializer.validated_data["host_name"]

        with MongoContext() as db:
            nessus_coll = db[NESSUS_COLLECTION]
            fix_coll = db[FIX_VULN_COLLECTION]

            nessus_doc = nessus_coll.find_one({
                "vulnerabilities_by_host.host_name": host_name
            })

            if not nessus_doc:
                return Response(
                    {"detail": "Host not found in Nessus report"},
                    status=status.HTTP_404_NOT_FOUND
                )

            vuln_data = None
            for host in nessus_doc.get("vulnerabilities_by_host", []):
                if host.get("host_name") == host_name:
                    vuln_data = host.get("vulnerabilities", [])[0]
                    break

            if not vuln_data:
                return Response(
                    {"detail": "No vulnerabilities found for this host"},
                    status=status.HTTP_404_NOT_FOUND
                )

            plugin_name = vuln_data.get("plugin_name", "")
            risk_factor = vuln_data.get("risk_factor", "")
            description_points = vuln_data.get("description", "")

            # ✅ ASSIGN TEAM BY HOST
            assigned_team = get_assigned_team_by_host(host_name)
            assigned_team_members = get_team_members(db, assigned_team)

            mitigation_steps = []
            for i in range(1, 7):
                mitigation_steps.append({
                    "step": f"Step {i}",
                    "assigned_to": assigned_team,
                    "deadline": None,
                    "artifacts_tools_used": "Dummy Tool",
                    "description": f"Dummy description for step {i}",
                    "system_file_path": "C:\\dummy\\path"
                })

            doc = {
                "host_name": host_name,
                "risk_factor": risk_factor,
                "plugin_name": plugin_name,

                "vulnerability_type": "Dummy Vulnerability Type",
                "affected_ports": "Dummy Port Range",
                "file": "Dummy File",

                "description_points": description_points,
                "vendor_fix_available": True,

                "assigned_team": assigned_team,
                "assigned_team_members": assigned_team_members,

                "mitigation_steps": mitigation_steps,
                "status": "open",

                "created_at": datetime.utcnow(),
                "created_by": str(request.user.id)
            }

            result = fix_coll.insert_one(doc)
            doc["_id"] = str(result.inserted_id)

            return Response(
                {
                    "assigned_team": assigned_team,
                    "assigned_team_members": assigned_team_members,
                    "data": doc
                },
                status=status.HTTP_201_CREATED
            )
