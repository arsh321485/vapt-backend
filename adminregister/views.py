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
FIX_VULN_STEPS_COLLECTION = "fix_vulnerability_steps"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
FIX_STEP_FEEDBACK_COLLECTION = "fix_step_feedback"
FIX_FINAL_FEEDBACK_COLLECTION = "fix_vulnerability_final_feedback"


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


  
# class VulnerabilityRegisterAPIView(APIView):
#     """
#     Returns a list of vulnerabilities for a report_id
#     GET /api/adminregister/report/<report_id>/vulns-simple/
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def get(self, request, report_id):
#         try:
#             with MongoContext() as db:
#                 coll = db[NESSUS_COLLECTION]

#                 doc = coll.find_one({"report_id": str(report_id)})
#                 if not doc:
#                     return Response(
#                         {"detail": "report not found"},
#                         status=status.HTTP_404_NOT_FOUND
#                     )

#                 uploaded_at = doc.get("uploaded_at")
#                 rows = []

#                 # ===============================
#                 # LOOP: HOST -> VULNERABILITIES
#                 # ===============================
#                 for host in doc.get("vulnerabilities_by_host", []):
#                     host_name = host.get("host_name") or host.get("host") or ""

#                     # ✅ FIXED KEY
#                     for v in host.get("vulnerabilities", []):

#                         plugin_name = (
#                             v.get("plugin_name")
#                             or v.get("pluginname")
#                             or v.get("name")
#                             or ""
#                         )

#                         risk_raw = (
#                             v.get("risk_factor")
#                             or v.get("severity")
#                             or v.get("risk")
#                             or ""
#                         )

#                         severity = (
#                             risk_raw.strip().title()
#                             if isinstance(risk_raw, str)
#                             else ""
#                         )

#                         first_obs = v.get("created_at") or uploaded_at
#                         second_obs = v.get("updated_at")

#                         rows.append({
#                             "vul_name": plugin_name,
#                             "asset": host_name,
#                             "severity": severity,
#                             "first_observation": _normalize_iso(first_obs),
#                             "second_observation": _normalize_iso(second_obs),
#                             "status": "open",
#                         })

#                 serializer = AdminRegisterSimpleVulnSerializer(rows, many=True)

#                 return Response(
#                     {
#                         "report_id": str(report_id),
#                         "count": len(rows),
#                         "rows": serializer.data
#                     },
#                     status=status.HTTP_200_OK
#                 )

#         except pymongo.errors.ServerSelectionTimeoutError as e:
#             return Response(
#                 {"detail": "cannot connect to MongoDB", "error": str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

#         except Exception as exc:
#             return Response(
#                 {"detail": "unexpected error", "error": str(exc)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


class LatestSuperAdminVulnerabilityRegisterAPIView(APIView):
    """
    Returns vulnerabilities from the LATEST file uploaded by Super Admin for the current Admin.

    - Each Admin sees only their own data (filtered by admin_id)
    - Shows vulnerabilities from the most recent file uploaded for this Admin
    - When Super Admin uploads a new file for an Admin, it automatically reflects here
    - Older files for the same Admin are ignored

    GET /api/adminregister/register/latest/vulns/
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            # Get the current authenticated user's admin ID and email
            current_admin_id = str(request.user.id)
            current_admin_email = getattr(request.user, 'email', None)

            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                # Build query to match by admin_id OR admin_email
                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                # Find the LATEST report for this specific Admin
                # Uses $or to match by either admin_id or admin_email
                latest_doc = coll.find_one(
                    {"$or": query_conditions},
                    sort=[("uploaded_at", pymongo.DESCENDING)]
                )

                if not latest_doc:
                    return Response(
                        {
                            "detail": "No reports found for your account",
                            "admin_id": current_admin_id,
                            "admin_email": current_admin_email
                        },
                        status=status.HTTP_404_NOT_FOUND
                    )

                report_id = latest_doc.get("report_id")
                uploaded_at = latest_doc.get("uploaded_at")
                admin_id = latest_doc.get("admin_id")
                admin_email = latest_doc.get("admin_email")

                rows = []

                # Extract vulnerabilities from the latest report
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""

                    for v in host.get("vulnerabilities", []):
                        plugin_id = v.get("plugin_id", "")
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )

                        risk_raw = (
                            v.get("risk_factor")
                            or v.get("severity")
                            or v.get("risk")
                            or ""
                        )

                        severity = (
                            risk_raw.strip().title()
                            if isinstance(risk_raw, str)
                            else ""
                        )

                        port = v.get("port", "")
                        protocol = v.get("protocol", "")

                        first_obs = v.get("created_at") or uploaded_at
                        second_obs = v.get("updated_at")

                        rows.append({
                            "plugin_id": plugin_id,  # Unique identifier for Fix Now
                            "vul_name": plugin_name,
                            "asset": host_name,
                            "severity": severity,
                            "port": port,
                            "protocol": protocol,
                            "first_observation": _normalize_iso(first_obs),
                            "second_observation": _normalize_iso(second_obs),
                            "status": "open",
                        })

                # Current user's admin info
                current_admin_id = str(request.user.id)
                current_admin_email = getattr(request.user, 'email', '')

                return Response(
                    {
                        "report_id": str(report_id),
                        "admin_id": current_admin_id,
                        "admin_email": current_admin_email,
                        "uploaded_by": {
                            "admin_id": admin_id,
                            "admin_email": admin_email
                        },
                        "uploaded_at": _normalize_iso(uploaded_at),
                        "count": len(rows),
                        "rows": rows
                    },
                    status=status.HTTP_200_OK
                )

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response(
                {"detail": "cannot connect to MongoDB", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VulnerabilitiesByHostListAPIView(APIView):
    """
    Returns a list of unique hosts with vulnerability counts grouped by risk factor.

    GET /api/admin/adminregister/register/hosts/

    Response:
        - List of hosts with counts per risk level (Critical, High, Medium, Low)
        - Total vulnerability count per host
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            current_admin_id = str(request.user.id)
            current_admin_email = getattr(request.user, 'email', None)

            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                # Build query to match by admin_id OR admin_email
                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                # Find the LATEST report for this admin
                latest_doc = coll.find_one(
                    {"$or": query_conditions},
                    sort=[("uploaded_at", pymongo.DESCENDING)]
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                report_id = latest_doc.get("report_id")
                uploaded_at = latest_doc.get("uploaded_at")

                # Group vulnerabilities by host
                hosts_data = {}

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""

                    if not host_name:
                        continue

                    # Initialize host entry if not exists
                    if host_name not in hosts_data:
                        hosts_data[host_name] = {
                            "host_name": host_name,
                            "critical": 0,
                            "high": 0,
                            "medium": 0,
                            "low": 0,
                            "info": 0,
                            "total": 0
                        }

                    # Count vulnerabilities by risk factor
                    for v in host.get("vulnerabilities", []):
                        risk_raw = (
                            v.get("risk_factor")
                            or v.get("severity")
                            or v.get("risk")
                            or ""
                        )

                        risk = risk_raw.strip().lower() if isinstance(risk_raw, str) else ""

                        if risk == "critical":
                            hosts_data[host_name]["critical"] += 1
                        elif risk == "high":
                            hosts_data[host_name]["high"] += 1
                        elif risk == "medium":
                            hosts_data[host_name]["medium"] += 1
                        elif risk == "low":
                            hosts_data[host_name]["low"] += 1
                        else:
                            hosts_data[host_name]["info"] += 1

                        hosts_data[host_name]["total"] += 1

                # Convert to list and sort by total vulnerabilities (descending)
                hosts_list = sorted(
                    hosts_data.values(),
                    key=lambda x: (x["critical"], x["high"], x["medium"], x["total"]),
                    reverse=True
                )

                return Response(
                    {
                        "report_id": str(report_id),
                        "uploaded_at": _normalize_iso(uploaded_at),
                        "total_hosts": len(hosts_list),
                        "hosts": hosts_list
                    },
                    status=status.HTTP_200_OK
                )

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response(
                {"detail": "cannot connect to MongoDB", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class VulnerabilitiesByHostDetailAPIView(APIView):
    """
    Returns vulnerabilities for a specific host, grouped by risk factor.

    GET /api/admin/adminregister/register/host/<host_name>/vulns/

    Response:
        - Host information
        - Vulnerabilities categorized by: Critical, High, Medium, Low
        - Each vulnerability includes: name, description, port, status
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        try:
            current_admin_id = str(request.user.id)
            current_admin_email = getattr(request.user, 'email', None)

            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]

                # Build query to match by admin_id OR admin_email
                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                # Find the LATEST report for this admin
                latest_doc = coll.find_one(
                    {"$or": query_conditions},
                    sort=[("uploaded_at", pymongo.DESCENDING)]
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                report_id = latest_doc.get("report_id")
                uploaded_at = latest_doc.get("uploaded_at")

                # Initialize categories
                vulnerabilities_by_risk = {
                    "critical": [],
                    "high": [],
                    "medium": [],
                    "low": [],
                    "info": []
                }

                host_found = False

                # Find vulnerabilities for the specified host
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    current_host = host.get("host_name") or host.get("host") or ""

                    # Match the host name (case-insensitive)
                    if current_host.lower() != host_name.lower():
                        continue

                    host_found = True

                    for v in host.get("vulnerabilities", []):
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )

                        risk_raw = (
                            v.get("risk_factor")
                            or v.get("severity")
                            or v.get("risk")
                            or ""
                        )

                        risk = risk_raw.strip().lower() if isinstance(risk_raw, str) else ""

                        # Build vulnerability object
                        vuln_data = {
                            "plugin_id": v.get("plugin_id", ""),
                            "plugin_name": plugin_name,
                            "risk_factor": risk_raw.strip().title() if isinstance(risk_raw, str) else "",
                            "port": v.get("port", ""),
                            "protocol": v.get("protocol", ""),
                            "synopsis": v.get("synopsis", ""),
                            "description": v.get("description", ""),
                            "solution": v.get("solution", ""),
                            "cvss_score": v.get("cvss_v3_base_score", "") or v.get("cvss_base_score", ""),
                            "first_observation": _normalize_iso(v.get("created_at") or uploaded_at),
                            "status": "open"
                        }

                        # Categorize by risk factor
                        if risk == "critical":
                            vulnerabilities_by_risk["critical"].append(vuln_data)
                        elif risk == "high":
                            vulnerabilities_by_risk["high"].append(vuln_data)
                        elif risk == "medium":
                            vulnerabilities_by_risk["medium"].append(vuln_data)
                        elif risk == "low":
                            vulnerabilities_by_risk["low"].append(vuln_data)
                        else:
                            vulnerabilities_by_risk["info"].append(vuln_data)

                if not host_found:
                    return Response(
                        {"detail": f"Host '{host_name}' not found in the latest report"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Count totals
                total_count = sum(len(v) for v in vulnerabilities_by_risk.values())

                return Response(
                    {
                        "report_id": str(report_id),
                        "uploaded_at": _normalize_iso(uploaded_at),
                        "host_name": host_name,
                        "total_vulnerabilities": total_count,
                        "counts": {
                            "critical": len(vulnerabilities_by_risk["critical"]),
                            "high": len(vulnerabilities_by_risk["high"]),
                            "medium": len(vulnerabilities_by_risk["medium"]),
                            "low": len(vulnerabilities_by_risk["low"]),
                            "info": len(vulnerabilities_by_risk["info"])
                        },
                        "vulnerabilities": vulnerabilities_by_risk
                    },
                    status=status.HTTP_200_OK
                )

        except pymongo.errors.ServerSelectionTimeoutError as e:
            return Response(
                {"detail": "cannot connect to MongoDB", "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        except Exception as exc:
            import traceback
            traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    
class FixVulnerabilityCreateAPIView(APIView):
    """
    Create a fix record for a selected vulnerability.
    Data is fetched ONLY from the latest Super Admin uploaded report.

    POST /api/admin/adminregister/fix-vulnerability/report/{report_id}/asset/{host_name}/create/

    Required body:
        - plugin_id: Unique vulnerability identifier (required for distinguishing same-name vulnerabilities)
        - plugin_name: Vulnerability name
        - risk_factor: Severity level
        - port: (optional) Port number for additional uniqueness

    Response includes:
        - Vulnerability name
        - Asset (host)
        - Severity
        - Description
        - Assigned team and team members
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request, report_id, host_name):
        admin_id = str(request.user.id)
        admin_email = getattr(request.user, 'email', None)

        plugin_id_req = request.data.get("plugin_id")
        plugin_name_req = request.data.get("plugin_name")
        risk_factor_req = request.data.get("risk_factor")
        port_req = request.data.get("port", "")

        # Validate required fields
        if not plugin_id_req:
            return Response(
                {"detail": "plugin_id is required to uniquely identify the vulnerability"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not plugin_name_req or not risk_factor_req:
            return Response(
                {"detail": "plugin_name and risk_factor are required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        with MongoContext() as db:
            nessus_coll = db[NESSUS_COLLECTION]
            fix_coll = db[FIX_VULN_COLLECTION]

            # 1️⃣ VALIDATE: Report must be from the LATEST upload for this admin
            query_conditions = [{"admin_id": admin_id}]
            if admin_email:
                query_conditions.append({"admin_email": admin_email})

            latest_doc = nessus_coll.find_one(
                {"$or": query_conditions},
                sort=[("uploaded_at", pymongo.DESCENDING)]
            )

            if not latest_doc:
                return Response(
                    {"detail": "No reports found for your account"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Check if the requested report_id matches the latest upload
            if latest_doc.get("report_id") != str(report_id):
                return Response(
                    {
                        "detail": "Data must come from the latest uploaded report only",
                        "latest_report_id": latest_doc.get("report_id")
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 2️⃣ DUPLICATE CHECK using plugin_id + host_name + port (unique combination)
            duplicate_query = {
                "report_id": str(report_id),
                "host_name": host_name,
                "plugin_id": plugin_id_req
            }

            # If port is provided, include it in duplicate check
            if port_req:
                duplicate_query["port"] = port_req

            existing_fix = fix_coll.find_one(duplicate_query)

            if existing_fix:
                return Response(
                    {
                        "detail": "Fix vulnerability already exists for this plugin_id",
                        "fix_vulnerability_id": str(existing_fix["_id"]),
                        "plugin_id": plugin_id_req,
                        "port": existing_fix.get("port", "")
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            selected_vuln = None

            # 3️⃣ MATCH HOST → PLUGIN_ID → PLUGIN_NAME → RISK from the latest report
            for host in latest_doc.get("vulnerabilities_by_host", []):
                if (host.get("host_name") or host.get("host")) != host_name:
                    continue

                for vuln in host.get("vulnerabilities", []):
                    db_plugin_id = str(vuln.get("plugin_id", ""))
                    db_plugin = (
                        vuln.get("plugin_name")
                        or vuln.get("pluginname")
                        or vuln.get("name")
                        or ""
                    )
                    db_risk = (
                        vuln.get("risk_factor")
                        or vuln.get("severity")
                        or vuln.get("risk")
                        or ""
                    )
                    db_port = str(vuln.get("port", ""))

                    # Match by plugin_id (primary) and optionally port
                    if db_plugin_id == str(plugin_id_req):
                        # If port was provided, also match port
                        if port_req and db_port != str(port_req):
                            continue
                        selected_vuln = vuln
                        break

                if selected_vuln:
                    break

            if not selected_vuln:
                return Response(
                    {
                        "detail": "Matching vulnerability not found in the latest upload",
                        "plugin_id": plugin_id_req,
                        "host_name": host_name
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # 4️⃣ ASSIGN TEAM
            assigned_team = get_assigned_team_by_host(host_name)
            assigned_team_members = get_team_members(
                db=db,
                team_name=assigned_team,
                admin_id=admin_id
            )

            # 5️⃣ Extract vulnerability details
            description = selected_vuln.get("description", "")
            description_points = selected_vuln.get("description_points", [])
            if isinstance(description_points, list):
                description_points = "\n".join(description_points)

            synopsis = selected_vuln.get("synopsis", "")
            solution = selected_vuln.get("solution", "")
            port = selected_vuln.get("port", "")
            protocol = selected_vuln.get("protocol", "")

            # Build affected ports/ranges
            affected_ports = f"{port}/{protocol}" if port and protocol else "N/A"

            # 6️⃣ CREATE FIX VULNERABILITY
            doc = {
                "report_id": str(report_id),
                "host_name": host_name,
                "plugin_id": plugin_id_req,  # Unique identifier
                "plugin_name": plugin_name_req,
                "risk_factor": risk_factor_req,
                "port": port,  # Store port for uniqueness
                "protocol": protocol,

                # Detailed description
                "description": description,
                "description_points": description_points,
                "synopsis": synopsis,
                "solution": solution,

                # Port/protocol info
                "vulnerability_type": "Network Vulnerability",
                "affected_ports_ranges": affected_ports,
                "file_path": "N/A",

                "vendor_fix_available": bool(solution),
                "assigned_team": assigned_team,
                "assigned_team_members": assigned_team_members,

                "status": "open",
                "created_at": datetime.utcnow(),
                "created_by": admin_id
            }

            result = fix_coll.insert_one(doc)
            doc["_id"] = str(result.inserted_id)

            # Get admin email
            admin_email = getattr(request.user, 'email', '')

            # 7️⃣ Format response for Fix Now card
            response_data = {
                "_id": str(result.inserted_id),
                "report_id": str(report_id),
                "admin_id": admin_id,
                "admin_email": admin_email,
                "plugin_id": plugin_id_req,
                "vulnerability_name": plugin_name_req,
                "asset": host_name,
                "severity": risk_factor_req,
                "port": port,
                "description": description or description_points or synopsis,
                "assigned_team": assigned_team,
                "assigned_team_members": assigned_team_members,
                "solution": solution,
                "status": "open",
                "created_at": doc["created_at"].isoformat() if doc["created_at"] else None
            }

            return Response(
                {
                    "message": "Fix vulnerability created successfully",
                    "data": response_data
                },
                status=status.HTTP_201_CREATED
            )

#
class FixVulnerabilityStepsAPIView(APIView):
    """
    Returns Steps to Fix for the selected vulnerability.

    GET: Fetch all steps with:
        - Step description
        - Assigned team name
        - Assigned team member name
        - Deadline (if available)
        - Step status (pending/completed)
        - Feedback (if any)

    POST: Create/Update a step

    Steps are linked to the Fix Vulnerability record.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    # Default step descriptions
    DEFAULT_STEP_DESCRIPTIONS = {
        1: "Initial Assessment - Identify and document the vulnerability scope",
        2: "Risk Analysis - Evaluate potential impact and prioritize remediation",
        3: "Solution Planning - Design and document the fix approach",
        4: "Implementation - Apply the fix or mitigation",
        5: "Testing & Validation - Verify the fix resolves the vulnerability",
        6: "Documentation & Closure - Complete documentation and close the issue"
    }

    # =====================
    # GET → Fetch steps
    # =====================
    def get(self, request, fix_vuln_id):
        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]

            # 🔍 Check active OR closed
            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            status_value = "open"

            if not fix_doc:
                fix_doc = closed_coll.find_one(
                    {"fix_vulnerability_id": fix_vuln_id}
                )
                if not fix_doc:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                status_value = "closed"

            # Get assigned team and members from fix vulnerability
            assigned_team = fix_doc.get("assigned_team", "")
            assigned_team_members = fix_doc.get("assigned_team_members", [])

            # Fetch existing steps
            existing_steps = list(
                steps_coll.find(
                    {"fix_vulnerability_id": fix_vuln_id}
                ).sort("step_number", 1)
            )

            # Create a map of step_number -> step data
            step_map = {s.get("step_number"): s for s in existing_steps}

            # Build complete steps list (1-6) with all required info
            steps = []
            previous_completed = True  # Step 1 has no previous step

            for step_num in range(1, 7):
                existing_step = step_map.get(step_num, {})
                current_status = existing_step.get("status", "pending")

                # Get feedback for this step
                step_feedback = feedback_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_num
                })

                # Determine if step is locked (previous step not completed)
                is_locked = not previous_completed and current_status != "completed"

                step_data = {
                    "step_number": step_num,
                    "step_description": existing_step.get(
                        "step_description",
                        self.DEFAULT_STEP_DESCRIPTIONS.get(step_num, f"Step {step_num}")
                    ),
                    "assigned_team": assigned_team,
                    "assigned_team_members": [
                        {
                            "user_id": m.get("user_id"),
                            "name": m.get("name"),
                            "email": m.get("email")
                        }
                        for m in assigned_team_members
                    ],
                    "deadline": existing_step.get("deadline"),
                    "status": current_status,
                    "is_locked": is_locked,  # True if previous step not completed
                    "comment": existing_step.get("comment", ""),
                    "created_at": _normalize_iso(existing_step.get("created_at")),
                    "updated_at": _normalize_iso(existing_step.get("updated_at")),
                    "feedback": None
                }

                # Include feedback if exists
                if step_feedback:
                    step_data["feedback"] = {
                        "feedback_id": str(step_feedback.get("_id")),
                        "feedback_comment": step_feedback.get("feedback_comment", ""),
                        "fix_status": step_feedback.get("fix_status", ""),
                        "submitted_at": _normalize_iso(step_feedback.get("submitted_at")),
                        "submitted_by": step_feedback.get("submitted_by")
                    }

                steps.append(step_data)

                # Update previous_completed for next iteration
                previous_completed = (current_status == "completed")

            # Count completed steps and determine next step
            completed_count = sum(1 for s in steps if s["status"] == "completed")
            next_step = completed_count + 1 if completed_count < 6 else None

            # Get admin info from request
            admin_id = str(request.user.id)
            admin_email = getattr(request.user, 'email', '')

            return Response(
                {
                    "report_id": fix_doc.get("report_id", ""),
                    "fix_vulnerability_id": fix_vuln_id,
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "vulnerability_name": fix_doc.get("plugin_name", ""),
                    "asset": fix_doc.get("host_name", ""),
                    "severity": fix_doc.get("risk_factor", ""),
                    "assigned_team": assigned_team,
                    "status": status_value,
                    "completed_steps": completed_count,
                    "total_steps": 6,
                    "next_step": next_step,
                    "steps": steps
                },
                status=status.HTTP_200_OK
            )

    # =====================
    # POST → Create / Update step (SEQUENTIAL)
    # =====================
    def post(self, request, fix_vuln_id):
        admin_id = str(request.user.id)

        step_number = request.data.get("step_number")
        comment = request.data.get("comment", "")
        step_status = request.data.get("status", "completed")
        step_description = request.data.get("step_description")
        deadline = request.data.get("deadline")
        assigned_member_id = request.data.get("assigned_member_id")

        if step_number not in [1, 2, 3, 4, 5, 6]:
            return Response(
                {"detail": "step_number must be between 1 and 6"},
                status=status.HTTP_400_BAD_REQUEST
            )

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if not fix_doc:
                return Response(
                    {"detail": "Fix vulnerability not found or already closed"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # =====================
            # SEQUENTIAL VALIDATION
            # =====================
            # Check if previous steps are completed (Steps must be done one by one)
            if step_number > 1:
                # Count how many steps before this one are completed
                previous_completed = steps_coll.count_documents({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": {"$lt": step_number},
                    "status": "completed"
                })

                required_completed = step_number - 1

                if previous_completed < required_completed:
                    # Find which step needs to be completed first
                    next_required = previous_completed + 1
                    return Response(
                        {
                            "detail": f"Steps must be completed sequentially. Please complete Step {next_required} first.",
                            "current_step": step_number,
                            "next_required_step": next_required,
                            "completed_steps": previous_completed
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

            # Build update document
            update_fields = {
                "status": step_status,
                "comment": comment,
                "updated_by": admin_id,
                "updated_at": datetime.utcnow()
            }

            # Add optional fields if provided
            if step_description:
                update_fields["step_description"] = step_description
            else:
                update_fields["step_description"] = self.DEFAULT_STEP_DESCRIPTIONS.get(
                    step_number, f"Step {step_number}"
                )

            if deadline:
                update_fields["deadline"] = deadline

            if assigned_member_id:
                # Find the member from assigned_team_members
                assigned_member = None
                for member in fix_doc.get("assigned_team_members", []):
                    if member.get("user_id") == assigned_member_id:
                        assigned_member = member
                        break
                if assigned_member:
                    update_fields["assigned_member"] = assigned_member

            # 🔁 UPSERT STEP (create OR update)
            steps_coll.update_one(
                {
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_number
                },
                {
                    "$set": update_fields,
                    "$setOnInsert": {
                        "created_at": datetime.utcnow(),
                        "created_by": admin_id
                    }
                },
                upsert=True
            )

            # ✅ Count completed steps
            completed_steps = steps_coll.count_documents({
                "fix_vulnerability_id": fix_vuln_id,
                "status": "completed"
            })

            # 🔒 AUTO CLOSE ON STEP 6
            if completed_steps == 6:
                closed_doc = fix_doc.copy()

                # 🔑 keep reference of original fix
                closed_doc["fix_vulnerability_id"] = str(fix_doc["_id"])
                closed_doc.pop("_id", None)

                closed_doc.update({
                    "status": "closed",
                    "closed_at": datetime.utcnow(),
                    "closed_by": admin_id
                })

                closed_coll.insert_one(closed_doc)
                fix_coll.delete_one({"_id": ObjectId(fix_vuln_id)})

                return Response(
                    {
                        "message": "All steps completed. Fix vulnerability closed.",
                        "status": "closed",
                        "completed_steps": completed_steps,
                        "step_saved": {
                            "step_number": step_number,
                            "status": step_status,
                            "assigned_team": fix_doc.get("assigned_team", "")
                        }
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "message": f"Step {step_number} saved successfully",
                    "status": "open",
                    "completed_steps": completed_steps,
                    "step_saved": {
                        "step_number": step_number,
                        "status": step_status,
                        "assigned_team": fix_doc.get("assigned_team", "")
                    }
                },
                status=status.HTTP_200_OK
            )
  

# FIX STEP FEEDBACK API (per step feedback)
class FixStepFeedbackAPIView(APIView):
    """
    Submit and retrieve feedback for fix steps.

    POST: Submit feedback for a specific step
        Required fields:
            - step_number: Step ID (1-6)
            - feedback_comment: Feedback text
            - fix_status: "fixed" | "partially_fixed" | "not_fixed"

    GET: Retrieve all feedback for a fix vulnerability

    Feedback is saved per step and appears on the Fix Now vulnerability card.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    VALID_FIX_STATUSES = ["fixed", "partially_fixed", "not_fixed"]

    def post(self, request, fix_vuln_id):
        """Submit feedback for a specific step."""
        admin_id = str(request.user.id)

        step_number = request.data.get("step_number")
        feedback_comment = request.data.get("feedback_comment", "").strip()
        fix_status = request.data.get("fix_status", "").lower()

        # Validation
        if step_number not in [1, 2, 3, 4, 5, 6]:
            return Response(
                {"detail": "step_number must be between 1 and 6"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if not feedback_comment:
            return Response(
                {"detail": "feedback_comment is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if fix_status not in self.VALID_FIX_STATUSES:
            return Response(
                {
                    "detail": f"fix_status must be one of: {', '.join(self.VALID_FIX_STATUSES)}"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]

            # Check if fix vulnerability exists (active or closed)
            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if not fix_doc:
                fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not fix_doc:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            # Check if step exists
            step_doc = steps_coll.find_one({
                "fix_vulnerability_id": fix_vuln_id,
                "step_number": step_number
            })

            if not step_doc:
                return Response(
                    {"detail": f"Step {step_number} does not exist for this vulnerability"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Check for existing feedback on this step (update or create)
            existing_feedback = feedback_coll.find_one({
                "fix_vulnerability_id": fix_vuln_id,
                "step_number": step_number
            })

            if existing_feedback:
                # Update existing feedback
                feedback_coll.update_one(
                    {"_id": existing_feedback["_id"]},
                    {
                        "$set": {
                            "feedback_comment": feedback_comment,
                            "fix_status": fix_status,
                            "updated_by": admin_id,
                            "updated_at": datetime.utcnow()
                        }
                    }
                )

                return Response(
                    {
                        "message": "Feedback updated successfully",
                        "data": {
                            "feedback_id": str(existing_feedback["_id"]),
                            "fix_vulnerability_id": fix_vuln_id,
                            "step_number": step_number,
                            "feedback_comment": feedback_comment,
                            "fix_status": fix_status,
                            "updated_at": datetime.utcnow().isoformat()
                        }
                    },
                    status=status.HTTP_200_OK
                )

            # Create new feedback
            feedback_doc = {
                "fix_vulnerability_id": fix_vuln_id,
                "step_number": step_number,
                "feedback_comment": feedback_comment,
                "fix_status": fix_status,
                "submitted_by": admin_id,
                "submitted_at": datetime.utcnow()
            }

            result = feedback_coll.insert_one(feedback_doc)

            return Response(
                {
                    "message": "Feedback submitted successfully",
                    "data": {
                        "feedback_id": str(result.inserted_id),
                        "fix_vulnerability_id": fix_vuln_id,
                        "step_number": step_number,
                        "feedback_comment": feedback_comment,
                        "fix_status": fix_status,
                        "submitted_at": feedback_doc["submitted_at"].isoformat()
                    }
                },
                status=status.HTTP_201_CREATED
            )

    def get(self, request, fix_vuln_id):
        """Retrieve all feedback for a fix vulnerability."""
        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]

            # Check if fix vulnerability exists
            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            vuln_status = "open"

            if not fix_doc:
                fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not fix_doc:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                vuln_status = "closed"

            # Fetch all feedback for this vulnerability
            feedback_cursor = feedback_coll.find({
                "fix_vulnerability_id": fix_vuln_id
            }).sort("step_number", 1)

            feedback_list = []
            for fb in feedback_cursor:
                feedback_list.append({
                    "feedback_id": str(fb["_id"]),
                    "step_number": fb.get("step_number"),
                    "feedback_comment": fb.get("feedback_comment", ""),
                    "fix_status": fb.get("fix_status", ""),
                    "submitted_by": fb.get("submitted_by"),
                    "submitted_at": _normalize_iso(fb.get("submitted_at")),
                    "updated_at": _normalize_iso(fb.get("updated_at"))
                })

            return Response(
                {
                    "fix_vulnerability_id": fix_vuln_id,
                    "vulnerability_name": fix_doc.get("plugin_name", ""),
                    "asset": fix_doc.get("host_name", ""),
                    "status": vuln_status,
                    "feedback_count": len(feedback_list),
                    "feedback": feedback_list
                },
                status=status.HTTP_200_OK
            )


class FixVulnerabilityFinalFeedbackAPIView(APIView):
    """
    Submit and retrieve FINAL feedback for a closed vulnerability.

    RULES:
    - Feedback can ONLY be submitted after vulnerability is CLOSED
    - All 6 steps must be completed
    - Feedback is blocked if vulnerability is still open

    POST: Submit final feedback
        Required fields:
            - feedback_comment: Final feedback/comment
            - fix_result: "resolved" | "partially_resolved" | "not_resolved"

    GET: Retrieve final feedback for a closed vulnerability
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    VALID_FIX_RESULTS = ["resolved", "partially_resolved", "not_resolved"]

    def post(self, request, fix_vuln_id):
        """Submit final feedback - ONLY after vulnerability is CLOSED."""
        admin_id = str(request.user.id)

        feedback_comment = request.data.get("feedback_comment", "").strip()
        fix_result = request.data.get("fix_result", "").lower()

        # Validate required fields
        if not feedback_comment:
            return Response(
                {"detail": "feedback_comment is required"},
                status=status.HTTP_400_BAD_REQUEST
            )

        if fix_result not in self.VALID_FIX_RESULTS:
            return Response(
                {
                    "detail": f"fix_result must be one of: {', '.join(self.VALID_FIX_RESULTS)}"
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            final_feedback_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

            # =====================
            # VALIDATION: Must be CLOSED
            # =====================
            # Check if vulnerability is still open (not allowed)
            open_vuln = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if open_vuln:
                return Response(
                    {
                        "detail": "Feedback can only be submitted after vulnerability is CLOSED",
                        "status": "open",
                        "message": "Please complete all 6 steps first"
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if vulnerability is closed
            closed_vuln = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
            if not closed_vuln:
                return Response(
                    {"detail": "Fix vulnerability not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # =====================
            # VALIDATION: All 6 steps completed
            # =====================
            completed_steps = steps_coll.count_documents({
                "fix_vulnerability_id": fix_vuln_id,
                "status": "completed"
            })

            if completed_steps < 6:
                pending_steps = 6 - completed_steps
                return Response(
                    {
                        "detail": f"All 6 steps must be completed before submitting feedback. {pending_steps} step(s) still pending.",
                        "completed_steps": completed_steps,
                        "pending_steps": pending_steps
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if feedback already exists
            existing_feedback = final_feedback_coll.find_one({
                "fix_vulnerability_id": fix_vuln_id
            })

            if existing_feedback:
                # Update existing feedback
                final_feedback_coll.update_one(
                    {"_id": existing_feedback["_id"]},
                    {
                        "$set": {
                            "feedback_comment": feedback_comment,
                            "fix_result": fix_result,
                            "updated_by": admin_id,
                            "updated_at": datetime.utcnow()
                        }
                    }
                )

                # Get admin email
                admin_email = getattr(request.user, 'email', '')

                return Response(
                    {
                        "message": "Final feedback updated successfully",
                        "data": {
                            "feedback_id": str(existing_feedback["_id"]),
                            "fix_vulnerability_id": fix_vuln_id,
                            "admin_id": admin_id,
                            "admin_email": admin_email,
                            "severity": closed_vuln.get("risk_factor", ""),
                            "feedback_comment": feedback_comment,
                            "fix_result": fix_result,
                            "updated_at": datetime.utcnow().isoformat()
                        }
                    },
                    status=status.HTTP_200_OK
                )

            # Get admin email
            admin_email = getattr(request.user, 'email', '')

            # Create new final feedback
            feedback_doc = {
                "fix_vulnerability_id": fix_vuln_id,
                "vulnerability_name": closed_vuln.get("plugin_name", ""),
                "host_name": closed_vuln.get("host_name", ""),
                "severity": closed_vuln.get("risk_factor", ""),
                "feedback_comment": feedback_comment,
                "fix_result": fix_result,
                "submitted_by": admin_id,
                "submitted_at": datetime.utcnow()
            }

            result = final_feedback_coll.insert_one(feedback_doc)

            return Response(
                {
                    "message": "Final feedback submitted successfully",
                    "data": {
                        "feedback_id": str(result.inserted_id),
                        "fix_vulnerability_id": fix_vuln_id,
                        "admin_id": admin_id,
                        "admin_email": admin_email,
                        "vulnerability_name": closed_vuln.get("plugin_name", ""),
                        "host_name": closed_vuln.get("host_name", ""),
                        "severity": closed_vuln.get("risk_factor", ""),
                        "feedback_comment": feedback_comment,
                        "fix_result": fix_result,
                        "submitted_at": feedback_doc["submitted_at"].isoformat()
                    }
                },
                status=status.HTTP_201_CREATED
            )

    def get(self, request, fix_vuln_id):
        """Retrieve final feedback for a closed vulnerability."""
        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            final_feedback_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

            # Check vulnerability status
            open_vuln = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if open_vuln:
                return Response(
                    {
                        "fix_vulnerability_id": fix_vuln_id,
                        "status": "open",
                        "message": "Vulnerability is still open. No final feedback available.",
                        "final_feedback": None
                    },
                    status=status.HTTP_200_OK
                )

            closed_vuln = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
            if not closed_vuln:
                return Response(
                    {"detail": "Fix vulnerability not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Get admin info from request
            admin_id = str(request.user.id)
            admin_email = getattr(request.user, 'email', '')

            # Get final feedback
            feedback = final_feedback_coll.find_one({
                "fix_vulnerability_id": fix_vuln_id
            })

            if not feedback:
                return Response(
                    {
                        "fix_vulnerability_id": fix_vuln_id,
                        "admin_id": admin_id,
                        "admin_email": admin_email,
                        "vulnerability_name": closed_vuln.get("plugin_name", ""),
                        "host_name": closed_vuln.get("host_name", ""),
                        "severity": closed_vuln.get("risk_factor", ""),
                        "status": "closed",
                        "message": "No final feedback submitted yet",
                        "final_feedback": None
                    },
                    status=status.HTTP_200_OK
                )

            return Response(
                {
                    "fix_vulnerability_id": fix_vuln_id,
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "vulnerability_name": closed_vuln.get("plugin_name", ""),
                    "host_name": closed_vuln.get("host_name", ""),
                    "severity": closed_vuln.get("risk_factor", ""),
                    "status": "closed",
                    "closed_at": _normalize_iso(closed_vuln.get("closed_at")),
                    "final_feedback": {
                        "feedback_id": str(feedback["_id"]),
                        "feedback_comment": feedback.get("feedback_comment", ""),
                        "fix_result": feedback.get("fix_result", ""),
                        "submitted_by": feedback.get("submitted_by"),
                        "submitted_at": _normalize_iso(feedback.get("submitted_at")),
                        "updated_at": _normalize_iso(feedback.get("updated_at"))
                    }
                },
                status=status.HTTP_200_OK
            )


class FixVulnerabilityDetailAPIView(APIView):
    """
    Get complete details of a fix vulnerability for the Fix Now card.

    Returns:
        - Vulnerability name
        - Asset
        - Severity
        - Description
        - Assigned team
        - Assigned team members
        - All steps with status and feedback
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vuln_id):
        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]
            final_feedback_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

            # Check active or closed
            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            vuln_status = "open"

            if not fix_doc:
                fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not fix_doc:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                vuln_status = "closed"

            # Fetch steps
            steps_cursor = steps_coll.find({
                "fix_vulnerability_id": fix_vuln_id
            }).sort("step_number", 1)

            step_map = {s.get("step_number"): s for s in steps_cursor}

            # Build steps with feedback
            steps = []
            for step_num in range(1, 7):
                step_data = step_map.get(step_num, {})

                # Get feedback for this step
                feedback = feedback_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_num
                })

                steps.append({
                    "step_number": step_num,
                    "step_description": step_data.get(
                        "step_description",
                        FixVulnerabilityStepsAPIView.DEFAULT_STEP_DESCRIPTIONS.get(step_num, f"Step {step_num}")
                    ),
                    "status": step_data.get("status", "pending"),
                    "deadline": step_data.get("deadline"),
                    "comment": step_data.get("comment", ""),
                    "feedback": {
                        "feedback_id": str(feedback["_id"]) if feedback else None,
                        "feedback_comment": feedback.get("feedback_comment", "") if feedback else "",
                        "fix_status": feedback.get("fix_status", "") if feedback else ""
                    } if feedback else None
                })

            completed_count = sum(1 for s in steps if s["status"] == "completed")

            # Get final feedback (only for closed vulnerabilities)
            final_feedback = None
            if vuln_status == "closed":
                final_fb = final_feedback_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id
                })
                if final_fb:
                    final_feedback = {
                        "feedback_id": str(final_fb["_id"]),
                        "feedback_comment": final_fb.get("feedback_comment", ""),
                        "fix_result": final_fb.get("fix_result", ""),
                        "submitted_by": final_fb.get("submitted_by"),
                        "submitted_at": _normalize_iso(final_fb.get("submitted_at"))
                    }

            response_data = {
                "fix_vulnerability_id": fix_vuln_id,
                "vulnerability_name": fix_doc.get("plugin_name", ""),
                "asset": fix_doc.get("host_name", ""),
                "severity": fix_doc.get("risk_factor", ""),
                "description": fix_doc.get("description", "") or fix_doc.get("description_points", "") or fix_doc.get("synopsis", ""),
                "solution": fix_doc.get("solution", ""),
                "assigned_team": fix_doc.get("assigned_team", ""),
                "assigned_team_members": fix_doc.get("assigned_team_members", []),
                "status": vuln_status,
                "completed_steps": completed_count,
                "total_steps": 6,
                "steps": steps,
                "created_at": _normalize_iso(fix_doc.get("created_at")),
                "closed_at": _normalize_iso(fix_doc.get("closed_at")) if vuln_status == "closed" else None,
                "final_feedback": final_feedback,
                "can_submit_feedback": vuln_status == "closed" and final_feedback is None
            }

            return Response(
                {
                    "message": "Fix vulnerability details fetched successfully",
                    "data": response_data
                },
                status=status.HTTP_200_OK
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