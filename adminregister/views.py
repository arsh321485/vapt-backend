from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
import pymongo
import uuid
import re
from rest_framework.parsers import JSONParser
from bson import ObjectId
from rest_framework.permissions import IsAuthenticated

from .serializers import AdminRegisterSimpleVulnSerializer,FixVulnerabilityCreateSerializer,RaiseSupportRequestSerializer,CreateTicketSerializer
SUPPORT_REQUEST_COLLECTION = "support_requests"
FIX_VULN_COLLECTION = "fix_vulnerabilities"
NESSUS_COLLECTION = "nessus_reports"
VULN_CARD_COLLECTION = "vulnerability_cards"
TICKETS_COLLECTION = "tickets"
FIX_VULN_STEPS_COLLECTION = "fix_vulnerability_steps"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
FIX_STEP_FEEDBACK_COLLECTION = "fix_step_feedback"
FIX_FINAL_FEEDBACK_COLLECTION = "fix_vulnerability_final_feedback"


from vaptfix.mongo_client import MongoContext

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

def _resolve_requester(doc):
    """
    Returns requester display name for a support_requests document.
    - user_id present → UserDetail first_name + last_name
    - admin_id only   → User email
    - fallback        → stored requested_by value
    """
    from django.contrib.auth import get_user_model

    user_id  = doc.get("user_id")
    admin_id = doc.get("admin_id")

    if user_id:
        try:
            from users_details.models import UserDetail
            ud = UserDetail.objects.filter(admin_id=str(user_id)).first()
            if ud:
                full_name = f"{ud.first_name} {ud.last_name}".strip()
                if full_name:
                    return full_name
        except Exception:
            pass

    if admin_id:
        try:
            User = get_user_model()
            u = User.objects.filter(pk=str(admin_id)).only("email").first()
            if u:
                return u.email
        except Exception:
            pass

    return doc.get("requested_by", "")


# ===============================
# TEAM ASSIGNMENT HELPERS
# ===============================
def get_team_members(db, team_name: str, admin_id: str):
    members = []

    # admin ForeignKey is stored as 'admin_id' in MongoDB by djongo
    # also try 'admin' in case of raw UUID storage differences
    role_query = {
        "$elemMatch": {
            "$regex": f"^{re.escape(team_name)}$",
            "$options": "i"
        }
    }
    query = {
        "$or": [
            {"admin_id": admin_id},
            {"admin_id": str(admin_id)},
        ],
        "Member_role": role_query,
    }

    cursor = db["users_details_userdetail"].find(query)

    for u in cursor:
        members.append({
            "user_id": str(u.get("_id", "")),
            "name": f"{u.get('first_name', '')} {u.get('last_name', '')}".strip(),
            "email": u.get("email", "")
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
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

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

                # Build a set of closed vulnerability keys (plugin_name, host_name, port)
                # Scope by report_id only — same as userregister — avoids created_by mismatch
                closed_vulns = set()
                for doc in closed_coll.find({"report_id": str(report_id)}):
                    key = (
                        doc.get("plugin_name", ""),
                        doc.get("host_name", ""),
                        str(doc.get("port", ""))
                    )
                    closed_vulns.add(key)

                rows = []

                # Extract vulnerabilities from the latest report
                # Show both Open and Closed vulnerabilities with correct status
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""

                    for v in host.get("vulnerabilities", []):

                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )

                        port = v.get("port", "")

                        # Determine status: only the exact record (plugin+host+port) is closed
                        vuln_status = (
                            "closed"
                            if (plugin_name, host_name, str(port)) in closed_vulns
                            else "open"
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

                        protocol = v.get("protocol", "")

                        first_obs = v.get("created_at") or uploaded_at
                        second_obs = v.get("updated_at")

                        rows.append({
                            "id": str(uuid.uuid4()),
                            "vul_name": plugin_name,
                            "asset": host_name,
                            "severity": severity,
                            "port": port,
                            "protocol": protocol,
                            "first_observation": _normalize_iso(first_obs),
                            "second_observation": _normalize_iso(second_obs),
                            "status": vuln_status,
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




# class VulnerabilitiesByHostListAPIView(APIView):
#     """
#     Returns a list of unique hosts with vulnerability counts grouped by risk factor.

#     GET /api/admin/adminregister/register/hosts/

#     Response:
#         - List of hosts with counts per risk level (Critical, High, Medium, Low)
#         - Total vulnerability count per host
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def get(self, request):
#         try:
#             current_admin_id = str(request.user.id)
#             current_admin_email = getattr(request.user, 'email', None)

#             with MongoContext() as db:
#                 coll = db[NESSUS_COLLECTION]

#                 # Build query to match by admin_id OR admin_email
#                 query_conditions = [{"admin_id": current_admin_id}]
#                 if current_admin_email:
#                     query_conditions.append({"admin_email": current_admin_email})

#                 # Find the LATEST report for this admin
#                 latest_doc = coll.find_one(
#                     {"$or": query_conditions},
#                     sort=[("uploaded_at", pymongo.DESCENDING)]
#                 )

#                 if not latest_doc:
#                     return Response(
#                         {"detail": "No reports found for your account"},
#                         status=status.HTTP_404_NOT_FOUND
#                     )

#                 report_id = latest_doc.get("report_id")
#                 uploaded_at = latest_doc.get("uploaded_at")

#                 # Group vulnerabilities by host
#                 hosts_data = {}

#                 for host in latest_doc.get("vulnerabilities_by_host", []):
#                     host_name = host.get("host_name") or host.get("host") or ""

#                     if not host_name:
#                         continue

#                     # Initialize host entry if not exists
#                     if host_name not in hosts_data:
#                         hosts_data[host_name] = {
#                             "host_name": host_name,
#                             "critical": 0,
#                             "high": 0,
#                             "medium": 0,
#                             "low": 0,
#                             "info": 0,
#                             "total": 0
#                         }

#                     # Count vulnerabilities by risk factor
#                     for v in host.get("vulnerabilities", []):
#                         risk_raw = (
#                             v.get("risk_factor")
#                             or v.get("severity")
#                             or v.get("risk")
#                             or ""
#                         )

#                         risk = risk_raw.strip().lower() if isinstance(risk_raw, str) else ""

#                         if risk == "critical":
#                             hosts_data[host_name]["critical"] += 1
#                         elif risk == "high":
#                             hosts_data[host_name]["high"] += 1
#                         elif risk == "medium":
#                             hosts_data[host_name]["medium"] += 1
#                         elif risk == "low":
#                             hosts_data[host_name]["low"] += 1
#                         else:
#                             hosts_data[host_name]["info"] += 1

#                         hosts_data[host_name]["total"] += 1

#                 # Convert to list and sort by total vulnerabilities (descending)
#                 hosts_list = sorted(
#                     hosts_data.values(),
#                     key=lambda x: (x["critical"], x["high"], x["medium"], x["total"]),
#                     reverse=True
#                 )

#                 return Response(
#                     {
#                         "report_id": str(report_id),
#                         "uploaded_at": _normalize_iso(uploaded_at),
#                         "total_hosts": len(hosts_list),
#                         "hosts": hosts_list
#                     },
#                     status=status.HTTP_200_OK
#                 )

#         except pymongo.errors.ServerSelectionTimeoutError as e:
#             return Response(
#                 {"detail": "cannot connect to MongoDB", "error": str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

#         except Exception as exc:
#             import traceback
#             traceback.print_exc()
#             return Response(
#                 {"detail": "unexpected error", "error": str(exc)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )


# class VulnerabilitiesByHostDetailAPIView(APIView):
#     """
#     Returns vulnerabilities for a specific host, grouped by risk factor.

#     GET /api/admin/adminregister/register/host/<host_name>/vulns/

#     Response:
#         - Host information
#         - Vulnerabilities categorized by: Critical, High, Medium, Low
#         - Each vulnerability includes: name, description, port, status
#     """
#     permission_classes = [permissions.IsAuthenticated]

#     def get(self, request, host_name):
#         try:
#             current_admin_id = str(request.user.id)
#             current_admin_email = getattr(request.user, 'email', None)

#             with MongoContext() as db:
#                 coll = db[NESSUS_COLLECTION]

#                 # Build query to match by admin_id OR admin_email
#                 query_conditions = [{"admin_id": current_admin_id}]
#                 if current_admin_email:
#                     query_conditions.append({"admin_email": current_admin_email})

#                 # Find the LATEST report for this admin
#                 latest_doc = coll.find_one(
#                     {"$or": query_conditions},
#                     sort=[("uploaded_at", pymongo.DESCENDING)]
#                 )

#                 if not latest_doc:
#                     return Response(
#                         {"detail": "No reports found for your account"},
#                         status=status.HTTP_404_NOT_FOUND
#                     )

#                 report_id = latest_doc.get("report_id")
#                 uploaded_at = latest_doc.get("uploaded_at")

#                 # Initialize categories
#                 vulnerabilities_by_risk = {
#                     "critical": [],
#                     "high": [],
#                     "medium": [],
#                     "low": [],
#                     "info": []
#                 }

#                 host_found = False

#                 # Find vulnerabilities for the specified host
#                 for host in latest_doc.get("vulnerabilities_by_host", []):
#                     current_host = host.get("host_name") or host.get("host") or ""

#                     # Match the host name (case-insensitive)
#                     if current_host.lower() != host_name.lower():
#                         continue

#                     host_found = True

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

#                         risk = risk_raw.strip().lower() if isinstance(risk_raw, str) else ""

#                         # Build vulnerability object
#                         vuln_data = {
#                             "plugin_id": v.get("plugin_id", ""),
#                             "plugin_name": plugin_name,
#                             "risk_factor": risk_raw.strip().title() if isinstance(risk_raw, str) else "",
#                             "port": v.get("port", ""),
#                             "protocol": v.get("protocol", ""),
#                             "synopsis": v.get("synopsis", ""),
#                             "description": v.get("description", ""),
#                             "solution": v.get("solution", ""),
#                             "cvss_score": v.get("cvss_v3_base_score", "") or v.get("cvss_base_score", ""),
#                             "first_observation": _normalize_iso(v.get("created_at") or uploaded_at),
#                             "status": "open"
#                         }

#                         # Categorize by risk factor
#                         if risk == "critical":
#                             vulnerabilities_by_risk["critical"].append(vuln_data)
#                         elif risk == "high":
#                             vulnerabilities_by_risk["high"].append(vuln_data)
#                         elif risk == "medium":
#                             vulnerabilities_by_risk["medium"].append(vuln_data)
#                         elif risk == "low":
#                             vulnerabilities_by_risk["low"].append(vuln_data)
#                         else:
#                             vulnerabilities_by_risk["info"].append(vuln_data)

#                 if not host_found:
#                     return Response(
#                         {"detail": f"Host '{host_name}' not found in the latest report"},
#                         status=status.HTTP_404_NOT_FOUND
#                     )

#                 # Count totals
#                 total_count = sum(len(v) for v in vulnerabilities_by_risk.values())

#                 return Response(
#                     {
#                         "report_id": str(report_id),
#                         "uploaded_at": _normalize_iso(uploaded_at),
#                         "host_name": host_name,
#                         "total_vulnerabilities": total_count,
#                         "counts": {
#                             "critical": len(vulnerabilities_by_risk["critical"]),
#                             "high": len(vulnerabilities_by_risk["high"]),
#                             "medium": len(vulnerabilities_by_risk["medium"]),
#                             "low": len(vulnerabilities_by_risk["low"]),
#                             "info": len(vulnerabilities_by_risk["info"])
#                         },
#                         "vulnerabilities": vulnerabilities_by_risk
#                     },
#                     status=status.HTTP_200_OK
#                 )

#         except pymongo.errors.ServerSelectionTimeoutError as e:
#             return Response(
#                 {"detail": "cannot connect to MongoDB", "error": str(e)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

#         except Exception as exc:
#             import traceback
#             traceback.print_exc()
#             return Response(
#                 {"detail": "unexpected error", "error": str(exc)},
#                 status=status.HTTP_500_INTERNAL_SERVER_ERROR
#             )

    
class FixVulnerabilityCreateAPIView(APIView):
    """
    Create and List fix records for selected vulnerabilities.
    Data is fetched ONLY from the latest Super Admin uploaded report.

    POST /api/admin/adminregister/fix-vulnerability/report/{report_id}/asset/{host_name}/create/
        Required body:
            - id: Unique vulnerability identifier (UUID from LatestSuperAdminVulnerabilityRegisterAPIView)
            - plugin_name: Vulnerability name
            - risk_factor: Severity level
        Optional body:
            - port: Port number for additional uniqueness
            - status: Vulnerability status (default: fetched from latest report = "open")
        Auto-fetched from DB (not from request body):
            - vulnerability_type: from vulnerability_cards
            - affected_ports_ranges: from nessus_reports plugin_outputs -> plugin_output (array)
            - file_path: from nessus_reports plugin_outputs -> plugin_output_url (array)

    GET /api/admin/adminregister/fix-vulnerability/report/{report_id}/asset/{host_name}/create/
        Returns all fix vulnerabilities for the given report and host.
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def _get_status_from_latest_report(self, db, admin_id, admin_email, report_id, host_name, plugin_name):
        """
        Fetch the status field from the LatestSuperAdminVulnerabilityRegisterAPIView data.
        Looks up the vulnerability in the latest Nessus report and returns its status.
        """
        nessus_coll = db[NESSUS_COLLECTION]

        query_conditions = [{"admin_id": admin_id}]
        if admin_email:
            query_conditions.append({"admin_email": admin_email})

        latest_doc = nessus_coll.find_one(
            {"$or": query_conditions},
            sort=[("uploaded_at", pymongo.DESCENDING)]
        )

        if not latest_doc:
            return "open"

        # Search for the vulnerability status in the latest report
        for host in latest_doc.get("vulnerabilities_by_host", []):
            current_host = host.get("host_name") or host.get("host") or ""
            if current_host != host_name:
                continue

            for vuln in host.get("vulnerabilities", []):
                db_name = (
                    vuln.get("plugin_name")
                    or vuln.get("pluginname")
                    or vuln.get("name")
                    or ""
                )
                if db_name == str(plugin_name):
                    return vuln.get("status", "open")

        return "open"

    def post(self, request, report_id, host_name):
        admin_id = str(request.user.id)
        admin_email = getattr(request.user, 'email', None)

        # Validate using serializer
        serializer = FixVulnerabilityCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        validated = serializer.validated_data

        id_req = validated["id"]
        plugin_name_req = validated["plugin_name"]
        risk_factor_req = validated["risk_factor"]
        port_req = validated.get("port", "")

        # Optional fields from request body
        req_status = validated.get("status", "")

        with MongoContext() as db:
            nessus_coll = db[NESSUS_COLLECTION]
            fix_coll = db[FIX_VULN_COLLECTION]

            # 1. VALIDATE: Report must be from the LATEST upload for this admin
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

            # 2. CLOSED CHECK - block creation if vulnerability is already closed
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            closed_query = {
                "report_id": str(report_id),
                "host_name": host_name,
                "plugin_name": plugin_name_req,
            }
            if port_req:
                closed_query["port"] = str(port_req)

            existing_closed = closed_coll.find_one(closed_query)
            if existing_closed:
                return Response(
                    {
                        "detail": "Cannot create fix — vulnerability is already Closed",
                        "fix_vulnerability_id": existing_closed.get("fix_vulnerability_id", ""),
                        "plugin_name": plugin_name_req,
                        "status": "closed",
                    },
                    status=status.HTTP_400_BAD_REQUEST
                )

            # 3. DUPLICATE CHECK using (report_id, host_name, plugin_name, port) — stable fields
            # NOTE: do NOT use "id" field — it is a fresh UUID generated every time by
            # LatestSuperAdminVulnerabilityRegisterAPIView, so it will never match on second visit.
            duplicate_query = {
                "report_id":   str(report_id),
                "host_name":   host_name,
                "plugin_name": plugin_name_req,
            }
            if port_req:
                duplicate_query["port"] = str(port_req)

            existing_fix = fix_coll.find_one(duplicate_query)

            if existing_fix:
                # Return existing fix record instead of error (idempotent)
                return Response(
                    {
                        "message": "Fix vulnerability  already exists",
                        "data": {
                            "_id": str(existing_fix["_id"]),
                            "report_id": existing_fix.get("report_id"),
                            "admin_id": admin_id,
                            "admin_email": admin_email,
                            "id": existing_fix.get("id"),
                            "vulnerability_name": existing_fix.get("plugin_name"),
                            "asset": existing_fix.get("host_name"),
                            "severity": existing_fix.get("risk_factor"),
                            "port": existing_fix.get("port", ""),
                            "description": existing_fix.get("description", "") or existing_fix.get("synopsis", ""),
                            "assigned_team": existing_fix.get("assigned_team", ""),
                            "assigned_team_members": existing_fix.get("assigned_team_members", []),
                            "solution": existing_fix.get("solution", ""),
                            "status": existing_fix.get("status", "open"),
                            "vulnerability_type": existing_fix.get("vulnerability_type", ""),
                            "affected_ports_ranges": existing_fix.get("affected_ports_ranges", []),
                            "file_path": existing_fix.get("file_path", []),
                            "vendor_fix_available": existing_fix.get("vendor_fix_available", False),
                            "created_at": _normalize_iso(existing_fix.get("created_at")),
                        }
                    },
                    status=status.HTTP_200_OK
                )

            selected_vuln = None

            # 3. MATCH HOST -> PLUGIN_NAME from the latest report
            for host in latest_doc.get("vulnerabilities_by_host", []):
                if (host.get("host_name") or host.get("host")) != host_name:
                    continue

                for vuln in host.get("vulnerabilities", []):
                    db_plugin_name = (
                        vuln.get("plugin_name")
                        or vuln.get("pluginname")
                        or vuln.get("name")
                        or ""
                    )
                    db_port = str(vuln.get("port", ""))

                    # Match by plugin_name (primary) and optionally port
                    if db_plugin_name == str(plugin_name_req):
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
                        "id": id_req,
                        "host_name": host_name
                    },
                    status=status.HTTP_404_NOT_FOUND
                )

            # 4. ASSIGN TEAM — get assigned_team from vulnerability_cards for this vulnerability+host
            vuln_card_doc = db[VULN_CARD_COLLECTION].find_one({
                "report_id": str(report_id),
                "vulnerability_name": plugin_name_req,
                "host_name": host_name,
            })
            # Fallback: match by report_id + vulnerability_name only (any host)
            if not vuln_card_doc:
                vuln_card_doc = db[VULN_CARD_COLLECTION].find_one({
                    "report_id": str(report_id),
                    "vulnerability_name": plugin_name_req,
                })
            assigned_team = (vuln_card_doc or {}).get("assigned_team") or ""

            # Get vendor_fix_available from vulnerability_cards (stored as "Yes"/"No")
            _vfa_raw = (vuln_card_doc or {}).get("vendor_fix_available", "No")
            if isinstance(_vfa_raw, str):
                vendor_fix_available = _vfa_raw.strip().lower() == "yes"
            else:
                vendor_fix_available = bool(_vfa_raw)

            if assigned_team:
                assigned_team_members = get_team_members(
                    db=db,
                    team_name=assigned_team,
                    admin_id=admin_id
                )
            else:
                assigned_team_members = []

            # 5. Extract vulnerability details
            description = selected_vuln.get("description", "")
            description_points = selected_vuln.get("description_points", [])
            if isinstance(description_points, list):
                description_points = "\n".join(description_points)

            synopsis = selected_vuln.get("synopsis", "")
            solution = selected_vuln.get("solution", "")
            port = selected_vuln.get("port", "")
            protocol = selected_vuln.get("protocol", "")

            # Extract affected_ports_ranges and file_path as arrays from nessus plugin_outputs
            plugin_outputs = selected_vuln.get("plugin_outputs", [])
            affected_ports = [
                po.get("plugin_output")
                for po in plugin_outputs
                if po.get("plugin_output")
            ]
            file_path = [
                po.get("plugin_output_url")
                for po in plugin_outputs
                if po.get("plugin_output_url")
            ]

            # Get vulnerability_type from vulnerability_cards
            vulnerability_type = (vuln_card_doc or {}).get("vulnerability_type") or ""

            # Fetch status from LatestSuperAdmin report if not explicitly provided
            if req_status:
                vuln_status = req_status
            else:
                vuln_status = self._get_status_from_latest_report(
                    db, admin_id, admin_email, report_id, host_name, plugin_name_req
                )

            # 6. CREATE FIX VULNERABILITY
            doc = {
                "report_id": str(report_id),
                "host_name": host_name,
                "id": id_req,
                "plugin_name": plugin_name_req,
                "risk_factor": risk_factor_req,
                "port": port,
                "protocol": protocol,

                # Detailed description
                "description": description,
                "description_points": description_points,
                "synopsis": synopsis,
                "solution": solution,

                # Fields from nessus_reports and vulnerability_cards
                "status": vuln_status,
                "vulnerability_type": vulnerability_type,
                "affected_ports_ranges": affected_ports,
                "file_path": file_path,

                "vendor_fix_available": vendor_fix_available,
                "assigned_team": assigned_team,
                "assigned_team_members": assigned_team_members,

                "created_at": datetime.utcnow(),
                "created_by": admin_id
            }

            result = fix_coll.insert_one(doc)
            doc["_id"] = str(result.inserted_id)

            # Get admin email
            admin_email = getattr(request.user, 'email', '')

            # 7. Format response for Fix Now card
            response_data = {
                "_id": str(result.inserted_id),
                "report_id": str(report_id),
                "admin_id": admin_id,
                "admin_email": admin_email,
                "id": id_req,
                "vulnerability_name": plugin_name_req,
                "asset": host_name,
                "severity": risk_factor_req,
                "port": port,
                "description": description or description_points or synopsis,
                "assigned_team": assigned_team,
                "assigned_team_members": assigned_team_members,
                "solution": solution,
                "status": vuln_status,
                "vulnerability_type": vulnerability_type,
                "affected_ports_ranges": affected_ports,
                "file_path": file_path,
                "vendor_fix_available": vendor_fix_available,
                "created_at": doc["created_at"].isoformat() if doc["created_at"] else None
            }

            return Response(
                {
                    "message": "Fix vulnerability created successfully",
                    "data": response_data
                },
                status=status.HTTP_201_CREATED
            )

    def get(self, request, report_id, host_name):
        """
        GET API: Retrieve all fix vulnerabilities for a given report and host.
        Enriches each record with live data from nessus_reports and vulnerability_cards.

        From nessus_reports:
          - status, asset, vulnerability_name, description
          - affected_ports_ranges (plugin_outputs -> plugin_output, array)
          - file_path (plugin_outputs -> plugin_output_url, array)

        From vulnerability_cards:
          - assigned_team, vulnerability_type, vendor_fix_available
          - steps_to_fix (mitigation_table, array), deadline
          - artifacts_tools, post_mitigation_troubleshooting_guide, steps_to_fix_count
        """
        admin_id = str(request.user.id)
        admin_email = getattr(request.user, 'email', '')

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            nessus_coll = db[NESSUS_COLLECTION]
            vuln_card_coll = db[VULN_CARD_COLLECTION]

            # 1. Fetch all fix docs for this report + host + admin
            fix_docs = list(fix_coll.find({
                "report_id": str(report_id),
                "host_name": host_name,
                "created_by": admin_id
            }).sort("created_at", -1))

            # 2. Load nessus report for this admin + report_id
            nessus_doc = nessus_coll.find_one({
                "report_id": str(report_id),
                "$or": [{"admin_id": admin_id}, {"admin_email": admin_email}]
            })

            # Build lookup: plugin_name -> vuln data (for the matching host only)
            nessus_vuln_lookup = {}
            if nessus_doc:
                for host in nessus_doc.get("vulnerabilities_by_host", []):
                    h_name = host.get("host_name") or host.get("host") or ""
                    if h_name != host_name:
                        continue
                    for vuln in host.get("vulnerabilities", []):
                        pname = (
                            vuln.get("plugin_name")
                            or vuln.get("pluginname")
                            or vuln.get("name")
                            or ""
                        ).strip()
                        if pname and pname not in nessus_vuln_lookup:
                            nessus_vuln_lookup[pname] = vuln

            # 3. Batch-load vulnerability cards for this report + admin
            plugin_names = [doc.get("plugin_name", "") for doc in fix_docs if doc.get("plugin_name")]
            vuln_card_lookup = {}
            if plugin_names:
                for card in vuln_card_coll.find({
                    "report_id": str(report_id),
                    "admin_email": admin_email,
                    "vulnerability_name": {"$in": plugin_names}
                }):
                    vname = card.get("vulnerability_name", "")
                    if vname:
                        vuln_card_lookup[vname] = card

            # 4. Build enriched results
            results = []
            for doc in fix_docs:
                plugin_name = doc.get("plugin_name", "")
                nessus_vuln = nessus_vuln_lookup.get(plugin_name, {})
                vuln_card = vuln_card_lookup.get(plugin_name, {})

                # Extract affected_ports_ranges and file_path as arrays from plugin_outputs
                plugin_outputs = nessus_vuln.get("plugin_outputs", [])
                affected_ports_list = [
                    po.get("plugin_output")
                    for po in plugin_outputs
                    if po.get("plugin_output")
                ]
                file_path_list = [
                    po.get("plugin_output_url")
                    for po in plugin_outputs
                    if po.get("plugin_output_url")
                ]

                results.append({
                    "_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "id": doc.get("id"),
                    # From nessus_reports
                    "status": nessus_vuln.get("status") or doc.get("status", "open"),
                    "asset": host_name,
                    "vulnerability_name": plugin_name,
                    "description": nessus_vuln.get("description") or doc.get("description_points", "") or doc.get("synopsis", ""),
                    "affected_ports_ranges": affected_ports_list,
                    "file_path": file_path_list,
                    # From vulnerability_cards
                    "assigned_team": vuln_card.get("assigned_team") or doc.get("assigned_team", ""),
                    "vulnerability_type": vuln_card.get("vulnerability_type"),
                    "vendor_fix_available": vuln_card.get("vendor_fix_available") or doc.get("vendor_fix_available", False),
                    "steps_to_fix": vuln_card.get("mitigation_table", []),
                    "deadline": vuln_card.get("deadline"),
                    "artifacts_tools": vuln_card.get("artifacts_tools"),
                    "post_mitigation_troubleshooting_guide": vuln_card.get("post_mitigation_troubleshooting_guide"),
                    "steps_to_fix_count": vuln_card.get("steps_to_fix_count"),
                    # Other fields from fix doc
                    "severity": doc.get("risk_factor"),
                    "port": doc.get("port", ""),
                    "protocol": doc.get("protocol", ""),
                    "synopsis": doc.get("synopsis", ""),
                    "solution": doc.get("solution", ""),
                    "assigned_team_members": doc.get("assigned_team_members", []),
                    "created_at": _normalize_iso(doc.get("created_at")),
                    "created_by": doc.get("created_by")
                })

            return Response(
                {
                    "message": "Fix vulnerabilities fetched successfully",
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )

class FixVulnerabilityCardAPIView(APIView):
    """
    GET /api/admin/adminregister/fix-vulnerability/<fix_vuln_id>/card/
        Returns single fix card details by its _id.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vuln_id):
        admin_id = str(request.user.id)
        admin_email = getattr(request.user, 'email', '')

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

            # Check active collection
            doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            card_status = "open"

            if not doc:
                # Check closed collection
                doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not doc:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )
                card_status = "closed"

            response_data = {
                "_id": str(doc.get("_id", fix_vuln_id)),
                "report_id": doc.get("report_id"),
                "admin_id": admin_id,
                "admin_email": admin_email,
                "id": doc.get("id"),
                "vulnerability_name": doc.get("plugin_name"),
                "asset": doc.get("host_name"),
                "severity": doc.get("risk_factor"),
                "port": doc.get("port", ""),
                "protocol": doc.get("protocol", ""),
                "description": doc.get("description", "") or doc.get("description_points", "") or doc.get("synopsis", ""),
                "synopsis": doc.get("synopsis", ""),
                "solution": doc.get("solution", ""),
                "status": card_status,
                "vulnerability_type": doc.get("vulnerability_type", "Network Vulnerability"),
                "affected_ports_ranges": doc.get("affected_ports_ranges", "N/A"),
                "file_path": doc.get("file_path", "N/A"),
                "vendor_fix_available": doc.get("vendor_fix_available", False),
                "assigned_team": doc.get("assigned_team", ""),
                "assigned_team_members": doc.get("assigned_team_members", []),
                "created_at": _normalize_iso(doc.get("created_at")),
                "created_by": doc.get("created_by")
            }

            return Response(
                {
                    "message": "Fix card details fetched successfully",
                    "data": response_data
                },
                status=status.HTTP_200_OK
            )


class ClosedVulnerabilitiesByAssetAPIView(APIView):
    """
    GET /api/admin/adminregister/closed-vulnerabilities/report/<report_id>/asset/<host_name>/
        Returns all closed fix vulnerabilities for a given report and asset,
        with all related data (steps, step feedback, final feedback).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id, host_name):
        admin_id = str(request.user.id)
        admin_email = getattr(request.user, 'email', '')

        with MongoContext() as db:
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]
            final_feedback_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

            # Fetch all closed vulnerabilities for this report + asset
            closed_cursor = closed_coll.find({
                "report_id": str(report_id),
                "host_name": host_name,
                "closed_by": admin_id
            }).sort("closed_at", -1)

            results = []
            for doc in closed_cursor:
                fix_vuln_id = doc.get("fix_vulnerability_id", str(doc.get("_id", "")))

                # Fetch steps for this vulnerability
                existing_steps = list(
                    steps_coll.find({
                        "fix_vulnerability_id": fix_vuln_id
                    }).sort("step_number", 1)
                )

                steps = []
                for step in existing_steps:
                    step_num = step.get("step_number")

                    # Get feedback for this step
                    feedback = feedback_coll.find_one({
                        "fix_vulnerability_id": fix_vuln_id,
                        "step_number": step_num
                    })

                    step_entry = {
                        "_id": str(step.get("_id", "")),
                        "step_number": step_num,
                        "step_description": step.get(
                            "step_description",
                            FixVulnerabilityStepsAPIView.DEFAULT_STEP_DESCRIPTIONS.get(
                                step_num, f"Step {step_num}"
                            )
                        ),
                        "status": step.get("status", "pending"),
                        "deadline": step.get("deadline"),
                        "comment": step.get("comment", ""),
                        "created_at": _normalize_iso(step.get("created_at")),
                        "updated_at": _normalize_iso(step.get("updated_at")),
                        "feedback": None
                    }

                    if feedback:
                        step_entry["feedback"] = {
                            "feedback_id": str(feedback["_id"]),
                            "feedback_comment": feedback.get("feedback_comment", ""),
                            "fix_status": feedback.get("fix_status", ""),
                            "submitted_at": _normalize_iso(feedback.get("submitted_at")),
                            "submitted_by": feedback.get("submitted_by")
                        }

                    steps.append(step_entry)

                completed_count = sum(1 for s in steps if s["status"] == "completed")

                # Get final feedback
                final_feedback = None
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

                results.append({
                    "_id": str(doc.get("_id", "")),
                    "fix_vulnerability_id": fix_vuln_id,
                    "id": doc.get("id"),
                    "report_id": doc.get("report_id"),
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "vulnerability_name": doc.get("plugin_name", ""),
                    "asset": doc.get("host_name", ""),
                    "severity": doc.get("risk_factor", ""),
                    "port": doc.get("port", ""),
                    "protocol": doc.get("protocol", ""),
                    "description": doc.get("description", "") or doc.get("description_points", "") or doc.get("synopsis", ""),
                    "synopsis": doc.get("synopsis", ""),
                    "solution": doc.get("solution", ""),
                    "status": "closed",
                    "vulnerability_type": doc.get("vulnerability_type", "Network Vulnerability"),
                    "affected_ports_ranges": doc.get("affected_ports_ranges", "N/A"),
                    "file_path": doc.get("file_path", "N/A"),
                    "vendor_fix_available": doc.get("vendor_fix_available", False),
                    "assigned_team": doc.get("assigned_team", ""),
                    "assigned_team_members": doc.get("assigned_team_members", []),
                    "completed_steps": completed_count,
                    "total_steps": 6,
                    "steps": steps,
                    "final_feedback": final_feedback,
                    "created_at": _normalize_iso(doc.get("created_at")),
                    "closed_at": _normalize_iso(doc.get("closed_at")),
                    "closed_by": doc.get("closed_by")
                })

            return Response(
                {
                    "message": "Closed vulnerabilities fetched successfully",
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "count": len(results),
                    "results": results
                },
                status=status.HTTP_200_OK
            )


#
class FixVulnerabilityStepsAPIView(APIView):
    """
    Returns Steps to Fix for the selected vulnerability.

    Steps are fetched from vulnerability_cards.mitigation_table (matched by plugin_name),
    grouped by Step No. Each step includes both Windows and Linux variants.
    Total step count is dynamic (from mitigation_table), not hardcoded.

    GET: Fetch all steps with:
        - Step data (Windows + Linux variants from mitigation_table)
        - Assigned team name / member
        - Deadline (if available)
        - Step status (pending/completed)
        - is_locked / is_current flags for UI navigation
        - Feedback (if any)
        - operating_system detected from nessus host_information

    POST: Complete/Update a step (sequential enforcement)
        Required:
            - step_number: int
        Optional:
            - status: "completed" | "pending"  (default: "completed")
            - comment: string
            - step_description: string override
            - deadline: string
            - assigned_member_id: string

    Auto-closes vulnerability after ALL steps are completed (dynamic count).
    Feedback is only submittable after vulnerability is closed.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    # Fallback descriptions used when mitigation_table is empty
    DEFAULT_STEP_DESCRIPTIONS = {
        1: "Initial Assessment - Identify and document the vulnerability scope",
        2: "Risk Analysis - Evaluate potential impact and prioritize remediation",
        3: "Solution Planning - Design and document the fix approach",
        4: "Implementation - Apply the fix or mitigation",
        5: "Testing & Validation - Verify the fix resolves the vulnerability",
        6: "Documentation & Closure - Complete documentation and close the issue",
    }

    def _parse_mitigation_steps(self, mitigation_table):
        """
        Group mitigation_table rows by step_no (snake_case keys, as stored by _parse_markdown_table).
        Returns (steps_dict, ordered_step_numbers).

        All fields from each row are returned dynamically.
        steps_dict[step_num] = {
            "step_name": ...,
            "criticality": ...,
            "effort_estimate": ...,
            "windows": { all OS-specific fields from Windows row },
            "linux":   { all OS-specific fields from Linux row },
        }
        """
        # Keys that are step-level meta (not OS-specific data)
        META_KEYS = {"step_no", "step_name", "criticality", "effort_estimate", "operating_system"}

        steps_dict = {}
        step_order = []

        for row in mitigation_table:
            try:
                step_num = int(row.get("step_no", 0))
            except (ValueError, TypeError):
                continue
            if step_num <= 0:
                continue

            os_raw = (row.get("operating_system") or "").strip().lower()
            os_key = "linux" if "linux" in os_raw else "windows"

            # Return ALL fields dynamically — every column the AI generated
            os_data = {k: v for k, v in row.items() if k not in META_KEYS}

            if step_num not in steps_dict:
                steps_dict[step_num] = {
                    "step_name": row.get("step_name", f"Step {step_num}"),
                    "criticality": row.get("criticality", ""),
                    "effort_estimate": row.get("effort_estimate", ""),
                    "windows": {},
                    "linux": {},
                }
                step_order.append(step_num)

            steps_dict[step_num][os_key] = os_data

        step_order.sort()
        return steps_dict, step_order

    def _get_host_os(self, db, report_id, host_name):
        """
        Detect OS from nessus_reports for the matching host.
        Reads host_information.OS (and fallbacks) from vulnerabilities_by_host.
        Returns "Windows", "Linux", or None.
        """
        nessus_doc = db[NESSUS_COLLECTION].find_one({"report_id": str(report_id)})
        if not nessus_doc:
            return None

        host_name_lower = (host_name or "").strip().lower()

        for h in nessus_doc.get("vulnerabilities_by_host", []):
            h_name = (h.get("host_name") or h.get("host") or "").strip().lower()
            if h_name != host_name_lower:
                continue

            host_info = h.get("host_information", {}) or {}

            # 1. Check OS field (nessus stores it as "OS", "operating-system", or "os")
            os_raw = (
                host_info.get("OS")
                or host_info.get("operating-system")
                or host_info.get("os")
                or ""
            ).strip()

            if os_raw:
                os_lower = os_raw.lower()
                if "windows" in os_lower:
                    return "Windows"
                if "linux" in os_lower or "unix" in os_lower:
                    return "Linux"
                # Return raw value so caller can still use it for filtering
                return os_raw

            # 2. CPE field
            for cpe_key in ("cpe", "cpe-0", "cpe-1", "cpe-2"):
                cpe = (host_info.get(cpe_key) or "").lower()
                if cpe:
                    if "microsoft" in cpe or "windows" in cpe:
                        return "Windows"
                    if "linux" in cpe or "ubuntu" in cpe or "debian" in cpe or "centos" in cpe or "redhat" in cpe:
                        return "Linux"

            # 3. NetBIOS name → Windows
            if host_info.get("netbios-name") or host_info.get("smb-name"):
                return "Windows"

            # 4. plugin_output string of OS-detection plugins
            # NOTE: parser stores plugin_output as a plain string per vulnerability
            for v in h.get("vulnerabilities", []):
                pname = (v.get("plugin_name") or v.get("pluginname") or "").lower()
                if "os identification" in pname or "os detection" in pname or "operating system" in pname:
                    output = (v.get("plugin_output") or "").lower()
                    if "windows" in output:
                        return "Windows"
                    if "linux" in output or "unix" in output:
                        return "Linux"

            # 5. Heuristic: count Windows vs Linux plugin name hints
            windows_hints = 0
            linux_hints   = 0
            for v in h.get("vulnerabilities", []):
                pname = (v.get("plugin_name") or v.get("pluginname") or "").lower()
                if any(k in pname for k in ("windows", "smb", "microsoft", "wmi", "winreg", "ntlm", "rdp", "mssql", "iis")):
                    windows_hints += 1
                if any(k in pname for k in ("linux", "ssh", "unix", "nfs", "iptables", "debian", "ubuntu", "centos", "bash")):
                    linux_hints += 1
            if windows_hints > linux_hints and windows_hints > 0:
                return "Windows"
            if linux_hints > windows_hints and linux_hints > 0:
                return "Linux"

            break

        return None

    # =====================
    # GET → Fetch steps
    # =====================
    def get(self, request, fix_vuln_id):
        try:
          with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]

            # Check active OR closed
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

            report_id = fix_doc.get("report_id", "")
            host_name = fix_doc.get("host_name", "")
            plugin_name = fix_doc.get("plugin_name", "")

            # Fetch vulnerability_cards: match by report_id + vulnerability_name + host_name
            # Fallback: match without host_name if not found
            vuln_card = (
                db[VULN_CARD_COLLECTION].find_one({
                    "report_id": report_id,
                    "vulnerability_name": plugin_name,
                    "host_name": host_name,
                })
                or db[VULN_CARD_COLLECTION].find_one({
                    "report_id": report_id,
                    "vulnerability_name": plugin_name,
                })
                or {}
            )

            assigned_team = vuln_card.get("assigned_team") or fix_doc.get("assigned_team", "")
            assigned_team_members = fix_doc.get("assigned_team_members", [])
            mitigation_table = vuln_card.get("mitigation_table", [])
            deadline = vuln_card.get("deadline")
            artifacts_tools = vuln_card.get("artifacts_tools")
            post_mitigation_troubleshooting_guide = vuln_card.get("post_mitigation_troubleshooting_guide", [])

            # Parse mitigation_table into structured per-step data
            steps_dict, step_order = self._parse_mitigation_steps(mitigation_table)

            # Detect host OS: stored OS takes priority (ensures GET/POST consistency),
            # then ?os= param, then nessus detection
            os_param = request.query_params.get("os", "").strip().lower()
            if os_param in ("windows", "linux"):
                operating_system = "Windows" if os_param == "windows" else "Linux"
            elif fix_doc.get("operating_system"):
                operating_system = fix_doc["operating_system"]
            else:
                operating_system = self._get_host_os(db, report_id, host_name) or "Windows"

            # Fallback to 6 default steps if mitigation_table is empty
            if not step_order:
                step_order = list(range(1, 7))
                steps_dict = {
                    n: {
                        "step_name": self.DEFAULT_STEP_DESCRIPTIONS[n],
                        "criticality": "",
                        "effort_estimate": "",
                        "windows": {},
                        "linux": {},
                    }
                    for n in step_order
                }
            else:
                # OS-based step filtering: only show steps for the host's OS
                if operating_system:
                    os_key = "linux" if operating_system.lower() in ("linux", "unix") else "windows"
                    os_filtered = [s for s in step_order if steps_dict[s].get(os_key)]
                    if os_filtered:
                        step_order = os_filtered

            total_steps = len(step_order)

            # Saved step records from DB, indexed by step_number
            saved_steps = {
                s["step_number"]: s
                for s in steps_coll.find({"fix_vulnerability_id": fix_vuln_id})
            }

            # Build step list
            steps = []
            previous_completed = True  # step 1 has no predecessor

            for display_idx, step_num in enumerate(step_order, start=1):
                step_meta = steps_dict[step_num]
                saved = saved_steps.get(step_num)
                current_status = saved.get("status", "pending") if saved else "pending"

                is_locked = not previous_completed and current_status != "completed"
                is_current = previous_completed and current_status == "pending"

                step_feedback = feedback_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_num,
                })

                step_data = {
                    "_id": str(saved["_id"]) if saved else "",
                    "step_number": display_idx,
                    "step_name": step_meta["step_name"],
                    "criticality": step_meta["criticality"],
                    "effort_estimate": step_meta["effort_estimate"],
                    "windows": step_meta["windows"],
                    "linux": step_meta["linux"],
                    "assigned_team": assigned_team,
                    "assigned_team_members": [
                        {
                            "user_id": m.get("user_id"),
                            "name": m.get("name"),
                            "email": m.get("email"),
                        }
                        for m in assigned_team_members
                    ],
                    "deadline": (saved.get("deadline") if saved else None) or deadline,
                    "status": current_status,
                    "is_locked": is_locked,
                    "is_current": is_current,
                    "comment": saved.get("comment", "") if saved else "",
                    "created_at": _normalize_iso(saved.get("created_at")) if saved else None,
                    "updated_at": _normalize_iso(saved.get("updated_at")) if saved else None,
                    "feedback": None,
                }

                if step_feedback:
                    step_data["feedback"] = {
                        "feedback_id": str(step_feedback.get("_id")),
                        "feedback_comment": step_feedback.get("feedback_comment", ""),
                        "fix_status": step_feedback.get("fix_status", ""),
                        "submitted_at": _normalize_iso(step_feedback.get("submitted_at")),
                        "submitted_by": step_feedback.get("submitted_by"),
                    }

                steps.append(step_data)
                previous_completed = (current_status == "completed")

            completed_count = sum(1 for s in steps if s["status"] == "completed")
            next_step = (completed_count + 1) if completed_count < total_steps else None

            admin_id = str(request.user.id)
            admin_email = getattr(request.user, "email", "")

            return Response(
                {
                    "message": "Steps fetched successfully",
                    "report_id": report_id,
                    "fix_vulnerability_id": fix_vuln_id,
                    "admin_id": admin_id,
                    "admin_email": admin_email,
                    "vulnerability_name": plugin_name,
                    "asset": host_name,
                    "severity": fix_doc.get("risk_factor", ""),
                    "operating_system": operating_system,
                    "assigned_team": assigned_team,
                    "deadline": deadline,
                    "artifacts_tools": artifacts_tools,
                    "post_mitigation_troubleshooting_guide": post_mitigation_troubleshooting_guide if isinstance(post_mitigation_troubleshooting_guide, list) else ([post_mitigation_troubleshooting_guide] if post_mitigation_troubleshooting_guide else []),
                    "status": status_value,
                    "completed_steps": completed_count,
                    "total_steps": total_steps,
                    "next_step": next_step,
                    "steps": steps,
                },
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    # =====================
    # POST → Complete next step (AUTO-SEQUENTIAL)
    # step_number and step_name are auto-fetched from vulnerability_cards mitigation_table
    # Frontend only passes: status (optional), comment (optional)
    # Body: { "comment": "...", "status": "completed" }
    # =====================
    def post(self, request, fix_vuln_id):
        admin_id = str(request.user.id)

        comment = request.data.get("comment", "")
        step_status = request.data.get("status", "completed")
        deadline = request.data.get("deadline")
        assigned_member_id = request.data.get("assigned_member_id")

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            steps_coll = db[FIX_VULN_STEPS_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if not fix_doc:
                return Response(
                    {"detail": "Fix vulnerability not found or already closed"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Fetch mitigation_table from vulnerability_cards
            plugin_name = fix_doc.get("plugin_name", "")
            report_id = fix_doc.get("report_id", "")
            host_name = fix_doc.get("host_name", "")
            vuln_card = (
                db[VULN_CARD_COLLECTION].find_one({
                    "report_id": report_id,
                    "vulnerability_name": plugin_name,
                    "host_name": host_name,
                })
                or db[VULN_CARD_COLLECTION].find_one({
                    "report_id": report_id,
                    "vulnerability_name": plugin_name,
                })
                or {}
            )
            mitigation_table = vuln_card.get("mitigation_table", [])
            steps_dict, step_order = self._parse_mitigation_steps(mitigation_table)

            # OS-based step filtering: ?os= param → stored OS → nessus detection
            os_param = (
                request.query_params.get("os", "")
                or request.data.get("os", "")
            ).strip().lower()
            if os_param in ("windows", "linux"):
                host_os = "Windows" if os_param == "windows" else "Linux"
            elif fix_doc.get("operating_system"):
                host_os = fix_doc["operating_system"]
            else:
                host_os = self._get_host_os(db, report_id, host_name) or "Windows"

            if host_os and step_order:
                os_key = "linux" if host_os.lower() in ("linux", "unix") else "windows"
                os_filtered = [s for s in step_order if steps_dict[s].get(os_key)]
                if os_filtered:
                    step_order = os_filtered

            total_steps = len(step_order) if step_order else 6

            # Persist detected OS into fix_doc so GET always uses the same OS
            if not fix_doc.get("operating_system"):
                fix_coll.update_one(
                    {"_id": ObjectId(fix_vuln_id)},
                    {"$set": {"operating_system": host_os}},
                )

            # Auto-determine current step: count completed steps → next in order
            completed_count = steps_coll.count_documents({
                "fix_vulnerability_id": fix_vuln_id,
                "status": "completed",
            })

            if completed_count >= total_steps:
                return Response(
                    {
                        "detail": "All steps are already completed.",
                        "completed_steps": completed_count,
                        "total_steps": total_steps,
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # internal_step_number = actual DB step number (e.g. 1,3,5,7 for Windows)
            # display_step_number  = sequential for frontend (1,2,3,4...)
            internal_step_number = step_order[completed_count] if step_order else (completed_count + 1)
            display_step_number  = completed_count + 1
            step_number = internal_step_number  # used for DB operations
            step_name = (
                steps_dict[internal_step_number]["step_name"]
                if internal_step_number in steps_dict
                else self.DEFAULT_STEP_DESCRIPTIONS.get(internal_step_number, f"Step {display_step_number}")
            )

            # Build update document
            update_fields = {
                "status": step_status,
                "step_name": step_name,
                "comment": comment,
                "updated_by": admin_id,
                "updated_at": datetime.utcnow(),
            }

            if deadline:
                update_fields["deadline"] = deadline

            if assigned_member_id:
                for member in fix_doc.get("assigned_team_members", []):
                    if member.get("user_id") == assigned_member_id:
                        update_fields["assigned_member"] = member
                        break

            # UPSERT STEP (create OR update)
            steps_coll.update_one(
                {
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_number,
                },
                {
                    "$set": update_fields,
                    "$setOnInsert": {
                        "created_at": datetime.utcnow(),
                        "created_by": admin_id,
                    },
                },
                upsert=True,
            )

            step_doc = steps_coll.find_one({
                "fix_vulnerability_id": fix_vuln_id,
                "step_number": step_number,
            })
            step_id = str(step_doc["_id"]) if step_doc else ""

            # Recount completed steps after upsert
            completed_steps = steps_coll.count_documents({
                "fix_vulnerability_id": fix_vuln_id,
                "status": "completed",
            })

            # AUTO CLOSE when all steps completed
            if completed_steps >= total_steps:
                closed_doc = fix_doc.copy()
                closed_doc["fix_vulnerability_id"] = str(fix_doc["_id"])
                closed_doc.pop("_id", None)
                closed_doc.update({
                    "status": "closed",
                    "closed_at": datetime.utcnow(),
                    "closed_by": admin_id,
                })
                closed_coll.insert_one(closed_doc)
                fix_coll.delete_one({"_id": ObjectId(fix_vuln_id)})

                # Auto-close any open ticket linked to this fix vulnerability
                db[TICKETS_COLLECTION].update_many(
                    {"fix_vulnerability_id": fix_vuln_id, "status": "open"},
                    {"$set": {
                        "status": "closed",
                        "closed_at": datetime.utcnow(),
                        "close_comment": "Auto-closed: vulnerability patched",
                    }},
                )

                return Response(
                    {
                        "message": "All steps completed. Fix vulnerability closed.",
                        "status": "closed",
                        "completed_steps": completed_steps,
                        "total_steps": total_steps,
                        "step_saved": {
                            "fix_vulnerability_id": fix_vuln_id,
                            "fix_vulnerability_step_id": step_id,
                            "step_number": display_step_number,
                            "step_name": step_name,
                            "status": step_status,
                            "assigned_team": fix_doc.get("assigned_team", ""),
                        },
                    },
                    status=status.HTTP_200_OK,
                )

            # Prepare next step info for UI
            next_display_step = completed_steps + 1 if completed_steps < total_steps else None
            next_internal     = step_order[completed_steps] if step_order and completed_steps < len(step_order) else None
            next_step_name = (
                steps_dict[next_internal]["step_name"]
                if next_internal and next_internal in steps_dict
                else None
            )

            return Response(
                {
                    "message": f"Step {display_step_number} saved successfully",
                    "status": "open",
                    "completed_steps": completed_steps,
                    "total_steps": total_steps,
                    "next_step": next_display_step,
                    "next_step_name": next_step_name,
                    "step_saved": {
                        "fix_vulnerability_id": fix_vuln_id,
                        "fix_vulnerability_step_id": step_id,
                        "step_number": display_step_number,
                        "step_name": step_name,
                        "status": step_status,
                        "assigned_team": fix_doc.get("assigned_team", ""),
                    },
                },
                status=status.HTTP_200_OK,
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


# class FixVulnerabilityDetailAPIView(APIView):
#     """
#     Get complete details of a fix vulnerability for the Fix Now card.

#     Returns:
#         - Vulnerability name
#         - Asset
#         - Severity
#         - Description
#         - Assigned team
#         - Assigned team members
#         - All steps with status and feedback
#     """
#     permission_classes = [IsAuthenticated]

#     def get(self, request, fix_vuln_id):
#         with MongoContext() as db:
#             fix_coll = db[FIX_VULN_COLLECTION]
#             closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
#             steps_coll = db[FIX_VULN_STEPS_COLLECTION]
#             feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]
#             final_feedback_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

#             # Check active or closed
#             fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
#             vuln_status = "open"

#             if not fix_doc:
#                 fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
#                 if not fix_doc:
#                     return Response(
#                         {"detail": "Fix vulnerability not found"},
#                         status=status.HTTP_404_NOT_FOUND
#                     )
#                 vuln_status = "closed"

#             # Fetch steps
#             steps_cursor = steps_coll.find({
#                 "fix_vulnerability_id": fix_vuln_id
#             }).sort("step_number", 1)

#             step_map = {s.get("step_number"): s for s in steps_cursor}

#             # Build steps with feedback
#             steps = []
#             for step_num in range(1, 7):
#                 step_data = step_map.get(step_num, {})

#                 # Get feedback for this step
#                 feedback = feedback_coll.find_one({
#                     "fix_vulnerability_id": fix_vuln_id,
#                     "step_number": step_num
#                 })

#                 steps.append({
#                     "step_number": step_num,
#                     "step_description": step_data.get(
#                         "step_description",
#                         FixVulnerabilityStepsAPIView.DEFAULT_STEP_DESCRIPTIONS.get(step_num, f"Step {step_num}")
#                     ),
#                     "status": step_data.get("status", "pending"),
#                     "deadline": step_data.get("deadline"),
#                     "comment": step_data.get("comment", ""),
#                     "feedback": {
#                         "feedback_id": str(feedback["_id"]) if feedback else None,
#                         "feedback_comment": feedback.get("feedback_comment", "") if feedback else "",
#                         "fix_status": feedback.get("fix_status", "") if feedback else ""
#                     } if feedback else None
#                 })

#             completed_count = sum(1 for s in steps if s["status"] == "completed")

#             # Get final feedback (only for closed vulnerabilities)
#             final_feedback = None
#             if vuln_status == "closed":
#                 final_fb = final_feedback_coll.find_one({
#                     "fix_vulnerability_id": fix_vuln_id
#                 })
#                 if final_fb:
#                     final_feedback = {
#                         "feedback_id": str(final_fb["_id"]),
#                         "feedback_comment": final_fb.get("feedback_comment", ""),
#                         "fix_result": final_fb.get("fix_result", ""),
#                         "submitted_by": final_fb.get("submitted_by"),
#                         "submitted_at": _normalize_iso(final_fb.get("submitted_at"))
#                     }

#             response_data = {
#                 "fix_vulnerability_id": fix_vuln_id,
#                 "vulnerability_name": fix_doc.get("plugin_name", ""),
#                 "asset": fix_doc.get("host_name", ""),
#                 "severity": fix_doc.get("risk_factor", ""),
#                 "description": fix_doc.get("description", "") or fix_doc.get("description_points", "") or fix_doc.get("synopsis", ""),
#                 "solution": fix_doc.get("solution", ""),
#                 "assigned_team": fix_doc.get("assigned_team", ""),
#                 "assigned_team_members": fix_doc.get("assigned_team_members", []),
#                 "status": vuln_status,
#                 "completed_steps": completed_count,
#                 "total_steps": 6,
#                 "steps": steps,
#                 "created_at": _normalize_iso(fix_doc.get("created_at")),
#                 "closed_at": _normalize_iso(fix_doc.get("closed_at")) if vuln_status == "closed" else None,
#                 "final_feedback": final_feedback,
#                 "can_submit_feedback": vuln_status == "closed" and final_feedback is None
#             }

#             return Response(
#                 {
#                     "message": "Fix vulnerability details fetched successfully",
#                     "data": response_data
#                 },
#                 status=status.HTTP_200_OK
#             )


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
                "requested_by": _resolve_requester(support_req),
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
                    "requested_by": _resolve_requester(doc),
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


class SupportRequestByHostNameAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db["support_requests"]

            cursor = support_coll.find(
                {
                    "host_name": host_name,
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
                    "step_requested": doc.get("step_requested"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "requested_by": _resolve_requester(doc),
                    "requested_at": doc.get("requested_at"),
                })

            return Response(
                {
                    "message": "Support requests fetched successfully",
                    "host_name": host_name,
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
            fix_coll = db[FIX_VULN_COLLECTION]

            tickets = list(ticket_coll.find(
                {"report_id": report_id}
            ).sort("created_at", -1))

            # Batch-fetch fix vulnerabilities for assigned_team data
            fix_vuln_ids = [
                ObjectId(doc["fix_vulnerability_id"])
                for doc in tickets
                if doc.get("fix_vulnerability_id")
            ]
            fix_map = {}
            if fix_vuln_ids:
                for fix_doc in fix_coll.find({"_id": {"$in": fix_vuln_ids}}):
                    fix_map[str(fix_doc["_id"])] = fix_doc

            results = []
            for doc in tickets:
                fix_doc = fix_map.get(doc.get("fix_vulnerability_id"), {})
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
                    "assigned_team": fix_doc.get("assigned_team", ""),
                    "assigned_team_members": fix_doc.get("assigned_team_members", []),
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
        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]
            fix_coll    = db[FIX_VULN_COLLECTION]

            # Fetch ALL open tickets for this report (admin + user created)
            tickets = list(ticket_coll.find(
                {"report_id": report_id, "status": "open"}
            ).sort("created_at", -1))

            if not tickets:
                return Response(
                    {"message": "Open tickets fetched successfully", "report_id": report_id,
                     "status": "open", "count": 0, "results": []},
                    status=status.HTTP_200_OK,
                )

            # Collect unique fix_vulnerability_ids from tickets
            fix_vuln_ids_in_tickets = list({
                doc.get("fix_vulnerability_id")
                for doc in tickets
                if doc.get("fix_vulnerability_id")
            })

            active_obj_ids = []
            for fid in fix_vuln_ids_in_tickets:
                try:
                    active_obj_ids.append(ObjectId(fid))
                except Exception:
                    pass

            # Method 1: absent from fix_vulnerabilities = closed/deleted
            active_ids = set()
            if active_obj_ids:
                for fix_doc in fix_coll.find({"_id": {"$in": active_obj_ids}}, {"_id": 1}):
                    active_ids.add(str(fix_doc["_id"]))

            # Method 2: present in fix_vulnerabilities_closed by host_name+plugin_name+report_id
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            closed_keys = set()  # (host_name, plugin_name) tuples found in closed collection
            if tickets:
                or_conditions = [
                    {
                        "report_id": doc.get("report_id"),
                        "host_name": doc.get("host_name"),
                        "plugin_name": doc.get("plugin_name"),
                    }
                    for doc in tickets
                    if doc.get("host_name") and doc.get("plugin_name")
                ]
                if or_conditions:
                    for cdoc in closed_coll.find(
                        {"$or": or_conditions},
                        {"host_name": 1, "plugin_name": 1},
                    ):
                        closed_keys.add((cdoc.get("host_name"), cdoc.get("plugin_name")))

            # stale = absent from active OR host+plugin found in closed collection
            stale_ids = set()
            for doc in tickets:
                fid = doc.get("fix_vulnerability_id")
                if not fid:
                    continue
                key = (doc.get("host_name"), doc.get("plugin_name"))
                if fid not in active_ids or key in closed_keys:
                    stale_ids.add(fid)

            # Auto-close stale open tickets in DB
            if stale_ids:
                ticket_coll.update_many(
                    {"fix_vulnerability_id": {"$in": list(stale_ids)}, "status": "open"},
                    {"$set": {
                        "status": "closed",
                        "closed_at": datetime.utcnow(),
                        "close_comment": "Auto-closed: vulnerability patched",
                    }},
                )

            # Batch-fetch active fix_vulns for assigned_team data
            fix_map = {}
            if active_obj_ids:
                for fix_doc in fix_coll.find({"_id": {"$in": active_obj_ids}}):
                    fix_map[str(fix_doc["_id"])] = fix_doc

            results = []
            for doc in tickets:
                fid = doc.get("fix_vulnerability_id")
                if fid in stale_ids:
                    continue
                fix_doc = fix_map.get(fid, {})
                results.append({
                    "_id": str(doc["_id"]),
                    "report_id": doc.get("report_id"),
                    "fix_vulnerability_id": fid,
                    "host_name": doc.get("host_name"),
                    "plugin_name": doc.get("plugin_name"),
                    "category": doc.get("category"),
                    "subject": doc.get("subject"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "created_at": doc.get("created_at"),
                    "assigned_team": fix_doc.get("assigned_team", ""),
                    "assigned_team_members": fix_doc.get("assigned_team_members", []),
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
        with MongoContext() as db:
            ticket_coll  = db[TICKETS_COLLECTION]
            closed_coll  = db[FIX_VULN_CLOSED_COLLECTION]

            # Get ALL tickets for this report (any status)
            all_tickets = list(ticket_coll.find(
                {"report_id": report_id}
            ))

            if not all_tickets:
                return Response(
                    {"message": "Closed tickets fetched successfully", "report_id": report_id,
                     "status": "closed", "count": 0, "results": []},
                    status=status.HTTP_200_OK,
                )

            # Collect all fix_vulnerability_ids
            all_fix_ids = [
                doc.get("fix_vulnerability_id")
                for doc in all_tickets
                if doc.get("fix_vulnerability_id")
            ]

            # Check which are in fix_vulnerabilities_closed
            closed_fix_ids = set()
            if all_fix_ids:
                for cdoc in closed_coll.find(
                    {"fix_vulnerability_id": {"$in": all_fix_ids}},
                    {"fix_vulnerability_id": 1},
                ):
                    val = cdoc.get("fix_vulnerability_id")
                    if val:
                        closed_fix_ids.add(val)

            # Auto-update ticket status to "closed" in DB if not already
            if closed_fix_ids:
                ticket_coll.update_many(
                    {
                        "fix_vulnerability_id": {"$in": list(closed_fix_ids)},
                        "status": {"$ne": "closed"},
                    },
                    {"$set": {
                        "status": "closed",
                        "closed_at": datetime.utcnow(),
                        "close_comment": "Auto-closed: vulnerability patched",
                    }},
                )

            # Fetch assigned_team data from fix_vulnerabilities_closed
            closed_fix_map = {}
            if closed_fix_ids:
                for cdoc in closed_coll.find(
                    {"fix_vulnerability_id": {"$in": list(closed_fix_ids)}}
                ):
                    fid = cdoc.get("fix_vulnerability_id")
                    if fid and fid not in closed_fix_map:
                        closed_fix_map[fid] = cdoc

            results = []
            for doc in all_tickets:
                fid = doc.get("fix_vulnerability_id")
                if fid not in closed_fix_ids:
                    continue
                fix_doc = closed_fix_map.get(fid, {})
                results.append({
                    "_id":                   str(doc["_id"]),
                    "report_id":             doc.get("report_id"),
                    "fix_vulnerability_id":  fid,
                    "host_name":             doc.get("host_name"),
                    "plugin_name":           doc.get("plugin_name"),
                    "category":              doc.get("category"),
                    "subject":               doc.get("subject"),
                    "description":           doc.get("description"),
                    "status":                "closed",
                    "created_at":            doc.get("created_at"),
                    "closed_at":             doc.get("closed_at"),
                    "close_comment":         doc.get("close_comment"),
                    "assigned_team":         fix_doc.get("assigned_team", ""),
                    "assigned_team_members": fix_doc.get("assigned_team_members", []),
                })

            # Sort by closed_at descending
            results.sort(key=lambda x: x.get("closed_at") or "", reverse=True)

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

    def get(self, request, fix_vulnerability_id, ticket_id):
        admin_id = str(request.user.id)

        try:
            ticket_obj_id = ObjectId(ticket_id)
        except Exception:
            return Response(
                {"detail": "Invalid ticket_id"},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            ObjectId(fix_vulnerability_id)
        except Exception:
            return Response(
                {"detail": "Invalid fix_vulnerability_id"},
                status=status.HTTP_400_BAD_REQUEST
            )

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]

            ticket = ticket_coll.find_one({
                "_id": ticket_obj_id,
                "admin_id": admin_id,
                "fix_vulnerability_id": fix_vulnerability_id
            })

            if not ticket:
                return Response(
                    {"detail": "Ticket not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Fetch severity from the fix vulnerability
            fix_coll = db[FIX_VULN_COLLECTION]
            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vulnerability_id)})
            severity = fix_doc.get("risk_factor", "") if fix_doc else ""

            response_data = {
                "_id": str(ticket["_id"]),
                "report_id": ticket.get("report_id"),
                "fix_vulnerability_id": ticket.get("fix_vulnerability_id"),

                "host_name": ticket.get("host_name"),
                "plugin_name": ticket.get("plugin_name"),
                "severity": severity,

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


class VulnerabilityTimelineAPIView(APIView):
    """
    GET /api/admin/adminregister/fix-vulnerability/<fix_vuln_id>/timeline/

    Returns ordered timeline events for a vulnerability card:
      1. Vulnerability identified  → vulnerability_cards.created_at
      2. Assigned to Team          → vulnerability_cards.created_at + assigned_team
      3. Deadline                  → vulnerability_cards.deadline
      4. Step N Done (per step)    → fix_vulnerability_steps.updated_at (status=completed)
      5. Exception Requested       → support_requests.requested_at (if exists)
      6. Create Ticket             → tickets.created_at (if exists)
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vuln_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

            # Find fix vulnerability — active or closed
            fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if not fix_doc:
                fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not fix_doc:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

            report_id = fix_doc.get("report_id", "")
            plugin_name = fix_doc.get("plugin_name", "")
            host_name = fix_doc.get("host_name", "")

            # Fetch vulnerability_card for this vuln
            vuln_card = (
                db[VULN_CARD_COLLECTION].find_one({
                    "report_id": report_id,
                    "vulnerability_name": plugin_name,
                    "host_name": host_name,
                })
                or db[VULN_CARD_COLLECTION].find_one({
                    "report_id": report_id,
                    "vulnerability_name": plugin_name,
                })
                or {}
            )

            assigned_team = vuln_card.get("assigned_team") or fix_doc.get("assigned_team", "")
            vuln_created_at = _normalize_iso(vuln_card.get("created_at"))
            deadline = vuln_card.get("deadline")

            timeline = []

            # 1. Vulnerability Identified
            timeline.append({
                "event": "Vulnerability identified",
                "type": "vulnerability_identified",
                "date": vuln_created_at,
                "status": "done" if vuln_created_at else "pending",
                "icon": "arrow",
            })

            # 2. Assigned to Team
            timeline.append({
                "event": "Assigned to Team",
                "type": "assigned_to_team",
                "date": vuln_created_at,
                "status": "done" if assigned_team else "pending",
                "icon": "arrow",
                "assigned_team": assigned_team,
            })

            # 3. Deadline
            timeline.append({
                "event": "Deadline",
                "type": "deadline",
                "date": _normalize_iso(deadline) if deadline else None,
                "status": "scheduled",
                "icon": "arrow",
            })

            # 4. Steps Done — only completed steps, ordered by step_number
            completed_steps = list(
                db[FIX_VULN_STEPS_COLLECTION].find({
                    "fix_vulnerability_id": fix_vuln_id,
                    "status": "completed",
                }).sort("step_number", 1)
            )

            for step in completed_steps:
                step_num = step.get("step_number")
                step_date = _normalize_iso(
                    step.get("updated_at") or step.get("created_at")
                )
                timeline.append({
                    "event": f"Step {step_num} Done",
                    "type": "step_done",
                    "date": step_date,
                    "status": "done",
                    "icon": "check",
                    "step_number": step_num,
                })

            # 5. Exception Requested (support_requests)
            support_req = db[SUPPORT_REQUEST_COLLECTION].find_one({
                "vulnerability_id": fix_vuln_id,
                "admin_id": admin_id,
            })
            if support_req:
                timeline.append({
                    "event": "Exception Requested",
                    "type": "exception_requested",
                    "date": _normalize_iso(support_req.get("requested_at")),
                    "status": "pending",
                    "icon": "question",
                })

            # 6. Create Ticket (tickets)
            ticket = db[TICKETS_COLLECTION].find_one({
                "fix_vulnerability_id": fix_vuln_id,
                "admin_id": admin_id,
            })
            if ticket:
                timeline.append({
                    "event": "Create Ticket",
                    "type": "create_ticket",
                    "date": _normalize_iso(ticket.get("created_at")),
                    "status": "pending",
                    "icon": "question",
                })

            return Response(
                {
                    "fix_vulnerability_id": fix_vuln_id,
                    "vulnerability_name": plugin_name,
                    "asset": host_name,
                    "report_id": report_id,
                    "timeline": timeline,
                },
                status=status.HTTP_200_OK
            )