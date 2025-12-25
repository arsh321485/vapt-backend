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
from bson import ObjectId
from rest_framework.permissions import IsAuthenticated

from .serializers import AdminRegisterSimpleVulnSerializer,FixVulnerabilitySerializer,RaiseSupportRequestSerializer,CreateTicketSerializer
SUPPORT_REQUEST_COLLECTION = "support_requests"
FIX_VULN_COLLECTION = "fix_vulnerabilities"
NESSUS_COLLECTION = "nessus_reports"
TICKETS_COLLECTION = "tickets"

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

def get_team_members(db, team_name: str, admin_id: str):
    members = []

    cursor = db["users_details_userdetail"].find({
        "admin_id": admin_id, 
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
            "name": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip(),
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

    def post(self, request, report_id, host_name):

        with MongoContext() as db:
            nessus_coll = db[NESSUS_COLLECTION]
            fix_coll = db[FIX_VULN_COLLECTION]

            # 1️⃣ FETCH REPORT
            nessus_doc = nessus_coll.find_one({
                "report_id": str(report_id)
            })

            if not nessus_doc:
                return Response(
                    {"detail": "Report not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # 2️⃣ FETCH HOST
            vuln_data = None
            for host in nessus_doc.get("vulnerabilities_by_host", []):
                if host.get("host_name") == host_name:
                    vuln_data = host.get("vulnerabilities", [])[0]
                    break

            if not vuln_data:
                return Response(
                    {"detail": "No vulnerabilities found for this asset"},
                    status=status.HTTP_404_NOT_FOUND
                )

            plugin_name = vuln_data.get("plugin_name", "")
            risk_factor = vuln_data.get("risk_factor", "")
            description_points = vuln_data.get("description", "")

            # 3️⃣ ASSIGN TEAM
            assigned_team = get_assigned_team_by_host(host_name)
            admin_id = str(request.user.id)

            assigned_team_members = get_team_members(
                db=db,
                team_name=assigned_team,
                admin_id=admin_id
            )

            # 4️⃣ MITIGATION STEPS
            mitigation_steps = [
                {
                    "step": f"Step {i}",
                    "assigned_to": assigned_team,
                    "deadline": None,
                    "artifacts_tools_used": "Dummy Tool",
                    "description": f"Dummy description for step {i}",
                    "system_file_path": "C:\\dummy\\path"
                }
                for i in range(1, 7)
            ]

            # 5️⃣ SAVE FIX VULNERABILITY
            doc = {
                "report_id": report_id,
                "host_name": host_name,
                "risk_factor": risk_factor,
                "plugin_name": plugin_name,

                "description_points": description_points,
                "vendor_fix_available": True,

                "assigned_team": assigned_team,
                "assigned_team_members": assigned_team_members,

                "mitigation_steps": mitigation_steps,
                "status": "open",

                "created_at": datetime.utcnow(),
                "created_by": admin_id
            }

            result = fix_coll.insert_one(doc)
            doc["_id"] = str(result.inserted_id)

            return Response(
                {
                    "message": "Fix vulnerability created successfully",
                    "data": doc
                },
                status=status.HTTP_201_CREATED
            )
          
class RaiseSupportRequestAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request, report_id, vulnerability_id):
        serializer = RaiseSupportRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        step_requested = serializer.validated_data["step"]
        description = serializer.validated_data["description"]

        admin_id = str(request.user.id)

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            support_coll = db["support_requests"]

            # ✅ Prevent duplicate support request
            existing_request = support_coll.find_one({
                "vulnerability_id": vulnerability_id,
                "admin_id": admin_id
            })

            if existing_request:
                return Response(
                    {"detail": "Support request already raised for this vulnerability"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ✅ Fetch fix vulnerability
            vuln = fix_coll.find_one({"_id": ObjectId(vulnerability_id)})
            if not vuln:
                return Response(
                    {"detail": "Vulnerability not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            assigned_team = vuln.get("assigned_team")

            support_doc = {
                "report_id": report_id,
                "admin_id": admin_id,

                "vulnerability_id": vulnerability_id,
                "vul_name": vuln.get("plugin_name"),
                "host_name": vuln.get("host_name"),

                "assigned_team": assigned_team,
                "assigned_team_members": vuln.get("assigned_team_members", []),
                "steps": vuln.get("mitigation_steps", []),

                "step_requested": step_requested,
                "description": description,

                "status": "open",
                "requested_by": assigned_team,
                "requested_at": datetime.utcnow()
            }

            result = support_coll.insert_one(support_doc)
            support_doc["_id"] = str(result.inserted_id)

            return Response(
                {
                    "message": "Support request raised successfully",
                    "data": support_doc
                },
                status=status.HTTP_201_CREATED
            )
  
class RaiseSupportRequestByVulnerabilityAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, vulnerability_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db["support_requests"]

            support_req = support_coll.find_one({
                "vulnerability_id": vulnerability_id,
                "admin_id": admin_id  # 🔒 only own admin data
            })

            if not support_req:
                return Response(
                    {
                        "exists": False,
                        "detail": "No support request found for this vulnerability"
                    },
                    status=status.HTTP_200_OK
                )

            data = {
                "_id": str(support_req.get("_id")),
                "report_id": support_req.get("report_id"),
                "vulnerability_id": support_req.get("vulnerability_id"),
                "vul_name": support_req.get("vul_name"),
                "host_name": support_req.get("host_name"),
                "assigned_team": support_req.get("assigned_team"),
                "assigned_team_members": support_req.get("assigned_team_members", []),
                "steps": support_req.get("steps", []),
                "step_requested": support_req.get("step_requested"),
                "description": support_req.get("description"),
                "status": support_req.get("status"),
                "requested_by": support_req.get("requested_by"),
                "requested_at": support_req.get("requested_at"),
            }

            return Response(
                {
                    "exists": True,
                    "message": "Raise Support request fetched successfully",
                    "data": data
                },
                status=status.HTTP_200_OK
            )
          


class SupportRequestByReportAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db["support_requests"]

            cursor = support_coll.find(
                {
                    "report_id": report_id,
                    "admin_id": admin_id
                }
            ).sort("requested_at", -1)

            results = []

            for doc in cursor:
                results.append({
                    "_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "admin_id": doc.get("admin_id"),
                    "vulnerability_id": doc.get("vulnerability_id"),
                    "vul_name": doc.get("vul_name"),
                    "host_name": doc.get("host_name"),
                    "assigned_team": doc.get("assigned_team"),
                    "assigned_team_members": doc.get("assigned_team_members", []),
                    # "steps": doc.get("steps", []),
                    "step_requested": doc.get("step_requested"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "requested_by": doc.get("requested_by"),
                    "requested_at": doc.get("requested_at"),
                })

            return Response(
                {
                    "message": "Support requests fetched successfully",
                    "report_id": report_id,
                    "count": len(results),  
                    "results": results
                },
                status=status.HTTP_200_OK
            )
            

class CreateTicketAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request, report_id, fix_vulnerability_id):
        serializer = CreateTicketSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        category = serializer.validated_data["category"]
        subject = serializer.validated_data["subject"]
        description = serializer.validated_data["description"]

        admin_id = str(request.user.id)

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            ticket_coll = db[TICKETS_COLLECTION]

            # 🔍 Fetch Fix Vulnerability (validate ownership + report)
            fix_vuln = fix_coll.find_one({
                "_id": ObjectId(fix_vulnerability_id),
                "report_id": report_id
            })

            if not fix_vuln:
                return Response(
                    {"detail": "Fix vulnerability not found for this report"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # ❌ DUPLICATE CHECK
            existing_ticket = ticket_coll.find_one({
                "fix_vulnerability_id": fix_vulnerability_id,
                "admin_id": admin_id
            })

            if existing_ticket:
                return Response(
                    {"detail": "Ticket already created for this vulnerability"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # ✅ CREATE TICKET
            ticket_doc = {
                "fix_vulnerability_id": fix_vulnerability_id,
                "report_id": report_id,
                "admin_id": admin_id,

                "host_name": fix_vuln.get("host_name"),
                "plugin_name": fix_vuln.get("plugin_name"),

                "category": category,
                "subject": subject,
                "description": description,

                "status": "open",
                "created_at": datetime.utcnow()
            }

            result = ticket_coll.insert_one(ticket_doc)
            ticket_doc["_id"] = str(result.inserted_id)

            return Response(
                {
                    "message": "Ticket created successfully",
                    "data": ticket_doc
                },
                status=status.HTTP_201_CREATED
            )


class TicketByReportAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]

            cursor = ticket_coll.find(
                {
                    "report_id": report_id,
                    "admin_id": admin_id
                }
            ).sort("created_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "fix_vulnerability_id": doc.get("fix_vulnerability_id"),
                    "host_name": doc.get("host_name"),
                    "plugin_name": doc.get("plugin_name"),
                    "category": doc.get("category"),
                    "subject": doc.get("subject"),
                    "description": doc.get("description"),
                    "status": doc.get("status", "open"),
                    "created_at": doc.get("created_at"),
                })

            return Response(
                {
                    "message": "Tickets fetched successfully",
                    "report_id": report_id,
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )
            
            
class TicketOpenListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]

            cursor = ticket_coll.find(
                {
                    "report_id": report_id,
                    "admin_id": admin_id,
                    "status": "open"
                }
            ).sort("created_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "_id": str(doc["_id"]),
                    "report_id": doc.get("report_id"),
                    "fix_vulnerability_id": doc.get("fix_vulnerability_id"),
                    "host_name": doc.get("host_name"),
                    "plugin_name": doc.get("plugin_name"),
                    "category": doc.get("category"),
                    "subject": doc.get("subject"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "created_at": doc.get("created_at"),
                })

            return Response(
                {
                    "message": "Open tickets fetched successfully",
                    "report_id": report_id,
                    "status": "open",
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )
            
            
class TicketClosedListAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]

            cursor = ticket_coll.find(
                {
                    "report_id": report_id,
                    "admin_id": admin_id,
                    "status": "closed"
                }
            ).sort("closed_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "_id": str(doc["_id"]),
                    "report_id": doc.get("report_id"),
                    "fix_vulnerability_id": doc.get("fix_vulnerability_id"),
                    "host_name": doc.get("host_name"),
                    "plugin_name": doc.get("plugin_name"),
                    "category": doc.get("category"),
                    "subject": doc.get("subject"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "created_at": doc.get("created_at"),
                    "closed_at": doc.get("closed_at"),
                    "close_comment": doc.get("close_comment"),
                })

            return Response(
                {
                    "message": "Closed tickets fetched successfully",
                    "report_id": report_id,
                    "status": "closed",
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )


class TicketDetailAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request, ticket_id):
        admin_id = str(request.user.id)

        try:
            ticket_obj_id = ObjectId(ticket_id)
        except Exception:
            return Response(
                {"detail": "Invalid ticket_id"},
                status=status.HTTP_400_BAD_REQUEST
            )

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]

            ticket = ticket_coll.find_one({
                "_id": ticket_obj_id,
                "admin_id": admin_id
            })

            if not ticket:
                return Response(
                    {"detail": "Ticket not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            response_data = {
                "_id": str(ticket["_id"]),
                "report_id": ticket.get("report_id"),
                "fix_vulnerability_id": ticket.get("fix_vulnerability_id"),

                "host_name": ticket.get("host_name"),
                "plugin_name": ticket.get("plugin_name"),

                "category": ticket.get("category"),
                "subject": ticket.get("subject"),
                "description": ticket.get("description"),

                "status": ticket.get("status"),
                "created_at": ticket.get("created_at"),
                "closed_at": ticket.get("closed_at"),
                "close_comment": ticket.get("close_comment"),
            }

            return Response(
                {
                    "message": "Ticket fetched successfully",
                    "data": response_data
                },
                status=status.HTTP_200_OK
            )