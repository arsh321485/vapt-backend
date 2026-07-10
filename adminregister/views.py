from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from django.conf import settings
from django.core.cache import cache
from datetime import datetime, date, timedelta
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


def _clear_admin_dashboard_cache(admin_user_id):
    for key in (
        f"admin_total_assets_{admin_user_id}",
        f"admin_avg_score_{admin_user_id}",
        f"admin_vulnerabilities_{admin_user_id}",
        f"admin_inprocess_timeline_{admin_user_id}",
        f"admin_dashboard_summary_{admin_user_id}",
    ):
        cache.delete(key)


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

def _normalize_host_os(host):
    """
    Normalize a nessus host's host_information.OS into the canonical
    Windows/Linux/Cisco values used elsewhere (automation-scripts API,
    Slack bot's _get_team_vulns) — same detection, duplicated here since
    this view builds its rows in a single pass over vulnerabilities_by_host
    rather than sharing a helper module with users/views.py.
    """
    os_raw = (
        (host.get("host_information") or {}).get("OS")
        or (host.get("host_information") or {}).get("operating-system")
        or (host.get("host_information") or {}).get("operating_system")
        or (host.get("host_information") or {}).get("os")
        or ""
    ).strip().lower()
    if not os_raw:
        return None
    if "windows" in os_raw:
        return "Windows"
    if "linux" in os_raw or "ubuntu" in os_raw or "unix" in os_raw:
        return "Linux"
    if "cisco" in os_raw or "ios" in os_raw:
        return "Cisco"
    return None


def _resolve_requester(doc):
    """
    Returns requester display name for a support_requests document.
    - user_id that matches a real Django User pk → that user's email
      (web-dashboard-raised tickets store a real pk here)
    - stored requested_by → used next, since Slack-raised tickets store
      the raw Slack user ID (e.g. "U0BEVRYB67R") in user_id, which never
      matches a Django pk. Falling straight through to admin_id in that
      case wrongly displayed the ADMIN's email as the requester for every
      Slack-raised ticket, even when Slack had already resolved the real
      requester's email into requested_by at creation time.
    - admin_id → last-resort fallback only when nothing else is available
    """
    from django.contrib.auth import get_user_model

    user_id  = doc.get("user_id")
    admin_id = doc.get("admin_id")
    stored   = doc.get("requested_by", "") or ""

    if user_id:
        try:
            User = get_user_model()
            u = User.objects.filter(pk=str(user_id)).only("email").first()
            if u:
                return u.email
        except Exception as e:
            logger.warning("Suppressed error: %s", e)

    if stored:
        return stored

    if admin_id:
        try:
            User = get_user_model()
            u = User.objects.filter(pk=str(admin_id)).only("email").first()
            if u:
                return u.email
        except Exception as e:
            logger.warning("Suppressed error: %s", e)

    return ""


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

                # Build fix_doc lookup (plugin_name, host_name, port) -> fix_doc
                # Include both active and closed docs so verification_sent_at is available
                fix_doc_lookup = {}
                closed_vulns = set()
                for fdoc in closed_coll.find({"report_id": str(report_id)}):
                    key = (
                        fdoc.get("plugin_name", ""),
                        fdoc.get("host_name", ""),
                        str(fdoc.get("port", "")),
                    )
                    fix_doc_lookup[key] = fdoc
                    closed_vulns.add(key)
                for fdoc in db[FIX_VULN_COLLECTION].find({"report_id": str(report_id)}):
                    key = (
                        fdoc.get("plugin_name", ""),
                        fdoc.get("host_name", ""),
                        str(fdoc.get("port", "")),
                    )
                    fix_doc_lookup[key] = fdoc  # active overrides closed if both exist

                rows = []

                # Extract vulnerabilities from the latest report
                # Show both Open and Closed vulnerabilities with correct status
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""
                    host_os = _normalize_host_os(host)

                    for v in host.get("vulnerabilities", []):

                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )

                        port = v.get("port", "")

                        _fix = fix_doc_lookup.get((plugin_name, host_name, str(port)), {})
                        vuln_status = _fix.get("status") or (
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

                        first_obs  = v.get("created_at") or uploaded_at
                        second_obs = _fix.get("verification_sent_at") or v.get("updated_at")

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
                            # Mongo _id of the fix_vulnerability doc (distinct from
                            # "id" above, a throwaway UUID for list rendering only) —
                            # the frontend needs this to call
                            # fix-vulnerability/{fix_vulnerability_id}/step-complete/
                            # directly instead of going through create/ first.
                            "fix_vulnerability_id": str(_fix["_id"]) if _fix.get("_id") else None,
                            "operating_system": host_os,
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
                        "message": "Fix vulnerability already closed",
                        "data": {
                            "_id": existing_closed.get("fix_vulnerability_id", str(existing_closed.get("_id", ""))),
                            "fix_vulnerability_id": existing_closed.get("fix_vulnerability_id", ""),
                            "report_id": existing_closed.get("report_id"),
                            "admin_id": admin_id,
                            "admin_email": admin_email,
                            "id": existing_closed.get("id"),
                            "vulnerability_name": existing_closed.get("plugin_name"),
                            "asset": existing_closed.get("host_name"),
                            "severity": existing_closed.get("risk_factor"),
                            "port": existing_closed.get("port", ""),
                            "description": existing_closed.get("description", ""),
                            "assigned_team": existing_closed.get("assigned_team", ""),
                            "assigned_team_members": existing_closed.get("assigned_team_members", []),
                            "solution": existing_closed.get("solution", ""),
                            "status": "closed",
                            "vulnerability_type": existing_closed.get("vulnerability_type", ""),
                            "affected_ports_ranges": existing_closed.get("affected_ports_ranges", []),
                            "file_path": existing_closed.get("file_path", []),
                            "vendor_fix_available": existing_closed.get("vendor_fix_available", False),
                            "created_at": _normalize_iso(existing_closed.get("created_at")),
                            "closed_at": _normalize_iso(existing_closed.get("closed_at")),
                        }
                    },
                    status=status.HTTP_200_OK
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
            _clear_admin_dashboard_cache(admin_id)

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

            # Fetch all closed vulnerabilities for this report + asset (by anyone, not just admin)
            closed_cursor = closed_coll.find({
                "report_id": str(report_id),
                "host_name": host_name,
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

    def _infer_where_to_run(self, commands_for_action: str, system_file_path: str = "", operating_system: str = "") -> str:
        cmd = (commands_for_action or "").strip().lower()
        path = (system_file_path or "").strip().lower()
        os_label = (operating_system or "").strip().lower()

        if not cmd:
            return "not_applicable"
        if any(k in cmd for k in ("select ", "update ", "insert ", "delete ", "create table", "alter table", "drop table")):
            return "sql_console"
        if any(k in cmd for k in ("http://", "https://", "open browser", "navigate to", "web console")):
            return "browser"
        if any(k in cmd for k in ("click ", "go to settings", "open control panel", "open services.msc", "group policy")):
            return "application_ui"
        if any(k in cmd for k in ("get-", "set-", "new-", "remove-", "restart-service", "powershell", "ps1")):
            return "powershell"
        if any(k in cmd for k in ("cmd.exe", "sc.exe", "net start", "net stop", "copy ", "xcopy ")):
            return "cmd"
        if any(k in cmd for k in ("apt ", "yum ", "dnf ", "systemctl ", "chmod ", "chown ", "grep ", "sed ", "awk ", "sudo ")):
            return "bash"
        if os_label == "windows" or "c:\\" in path:
            return "terminal"
        if os_label == "linux" or path.startswith("/"):
            return "terminal"
        return "terminal"

    def _where_to_run_label(self, where_to_run: str) -> str:
        labels = {
            "powershell": "PowerShell",
            "cmd": "Command Prompt (CMD)",
            "bash": "Bash Shell",
            "terminal": "Terminal",
            "sql_console": "SQL Console",
            "browser": "Web Browser",
            "application_ui": "Application UI",
            "not_applicable": "Not Applicable",
        }
        return labels.get(where_to_run, "Terminal")

    def _how_to_run_instruction(self, where_to_run: str) -> str:
        instructions = {
            "powershell":     "Right-click the Start button → select 'Windows PowerShell (Admin)' → paste the command below and press Enter:",
            "cmd":            "Press Win+R on your keyboard → type 'cmd' → press Enter to open Command Prompt → paste the command below:",
            "bash":           "Open the Terminal application on your computer → paste the command below and press Enter:",
            "terminal":       "Open Command Prompt (Windows) or Terminal (Mac/Linux) → paste the command below and press Enter:",
            "sql_console":    "Open your database management tool (e.g. SQL Server Management Studio or MySQL Workbench) → paste the query below and click Run:",
            "browser":        "Open any web browser (Chrome, Firefox, Edge) → go to the URL shown below:",
            "application_ui": "Follow the manual steps described in the action above using your application's settings panel.",
            "not_applicable": "No command needed — follow the manual steps described in the action above.",
        }
        return instructions.get(where_to_run, "Open Command Prompt or Terminal → paste the command below and press Enter:")

    def _infer_assigned_team(self, vulnerability_name: str) -> str:
        name = (vulnerability_name or "").lower()
        if any(k in name for k in (
            "ssl", "tls", "certificate", "port", "firewall", "network", "dns",
            "http", "ftp", "smtp", "redis", "memcached", "open port", "unencrypted",
            "cleartext", "cipher", "protocol", "snmp", "telnet", "ssh",
        )):
            return "Network Security"
        if any(k in name for k in (
            "patch", "update", "version", "outdated", "cve-", "upgrade",
            "end-of-life", "unsupported", "obsolete",
        )):
            return "Patch Management"
        if any(k in name for k in (
            "injection", "xss", "csrf", "cross-site", "sql injection",
            "authentication", "authorization", "session", "cookie", "oauth",
            "architectural", "design flaw", "logic flaw",
        )):
            return "Architectural Flaws"
        return "Configuration Management"

    def _ensure_execution_guidance_fields(self, os_data: dict) -> dict:
        _raw_cmd = os_data.get("commands_for_action") or ""
        if isinstance(_raw_cmd, list):
            _raw_cmd = "\n".join(str(c) for c in _raw_cmd if c)
        commands = str(_raw_cmd).strip()
        where_to_run = os_data.get("where_to_run", "terminal")

        if not os_data.get("how_to_run"):
            os_data["how_to_run"] = self._how_to_run_instruction(where_to_run)

        if not os_data.get("command_to_run"):
            os_data["command_to_run"] = commands or ""

        if not os_data.get("expected_output"):
            if commands and commands.lower() not in ("n/a", "na", ""):
                os_data["expected_output"] = (
                    "If you see no red error messages after running the command, it worked. "
                    "You are done with this step."
                )
            else:
                os_data["expected_output"] = (
                    "Once you finish the steps described above, this task is complete. "
                    "Move on to the next step."
                )

        if not os_data.get("verification_check"):
            os_data["verification_check"] = (
                "Check that the change is in place and there are no error messages or warnings."
            )
        if not os_data.get("on_success_next_step"):
            os_data["on_success_next_step"] = "Great job! Move on to the next step."
        if not os_data.get("on_failure_what_to_do"):
            os_data["on_failure_what_to_do"] = (
                "Double-check the command, file path, and your permissions, then try again. "
                "If it still doesn't work, contact your IT admin for help."
            )
        return os_data

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
            except (ValueError, TypeError) as e:
                logger.warning("Suppressed error: %s", e)
            if step_num <= 0:
                continue

            os_raw = (row.get("operating_system") or "").strip().lower()
            os_key = "linux" if "linux" in os_raw else "windows"

            # Return ALL fields dynamically — every column the AI generated
            os_data = {k: v for k, v in row.items() if k not in META_KEYS}
            where_to_run = os_data.get("where_to_run") or self._infer_where_to_run(
                os_data.get("commands_for_action", ""),
                os_data.get("system_file_path", ""),
                row.get("operating_system", ""),
            )
            os_data["where_to_run"] = where_to_run
            os_data["where_to_run_label"] = os_data.get("where_to_run_label") or self._where_to_run_label(where_to_run)
            os_data = self._ensure_execution_guidance_fields(os_data)

            if step_num not in steps_dict:
                steps_dict[step_num] = {
                    "step_name": row.get("step_name", f"Step {step_num}"),
                    "criticality": row.get("criticality", ""),
                    "effort_estimate": row.get("effort_estimate", ""),
                    "sub_tasks": [],
                    "windows": {},
                    "linux": {},
                }
                step_order.append(step_num)

            # Promote sub_tasks to step level (take from first OS row that has them)
            if not steps_dict[step_num]["sub_tasks"] and os_data.get("sub_tasks"):
                steps_dict[step_num]["sub_tasks"] = os_data["sub_tasks"]

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
            admin_id = str(request.user.id)
            admin_email = getattr(request.user, "email", "")

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
            if not assigned_team:
                assigned_team = self._infer_assigned_team(plugin_name)
            assigned_team_members = fix_doc.get("assigned_team_members", [])
            mitigation_table = vuln_card.get("mitigation_table", [])
            artifacts_tools = vuln_card.get("artifacts_tools")

            # Deadline: RiskCriteria + severity takes priority (base = vuln_card.created_at)
            deadline = None
            _base_dt = vuln_card.get("created_at")
            if not isinstance(_base_dt, datetime):
                _base_dt = datetime.now()

            # Step 1: RiskCriteria (primary source)
            try:
                from risk_criteria.models import RiskCriteria
                from admindashboard.views import parse_timeline_to_days
                rc = RiskCriteria.objects.filter(admin=request.user).order_by('-created_at').first()
                if rc:
                    severity = (fix_doc.get("risk_factor") or "").strip().lower()
                    if severity.startswith("crit"):
                        _days = parse_timeline_to_days(rc.critical)
                    elif severity.startswith("high"):
                        _days = parse_timeline_to_days(rc.high)
                    elif severity.startswith("med"):
                        _days = parse_timeline_to_days(rc.medium)
                    elif severity.startswith("low"):
                        _days = parse_timeline_to_days(rc.low)
                    else:
                        _days = 0
                    if _days > 0:
                        deadline = (_base_dt + timedelta(days=_days)).strftime("%Y-%m-%d")
            except Exception as e:
                logger.warning("Suppressed error: %s", e)

            # Step 2: Stored deadline fallback (proper ISO date or duration string)
            if not deadline:
                _raw_deadline = vuln_card.get("deadline") or fix_doc.get("deadline")
                if _raw_deadline:
                    try:
                        datetime.fromisoformat(str(_raw_deadline).replace("Z", "+00:00"))
                        deadline = str(_raw_deadline)
                    except (ValueError, TypeError):
                        dur = str(_raw_deadline).strip().lower()
                        num_match = re.search(r"(\d+)", dur)
                        if num_match:
                            num = int(num_match.group(1))
                            if "hour" in dur:
                                deadline = (_base_dt + timedelta(hours=num)).strftime("%Y-%m-%d")
                            elif "week" in dur:
                                deadline = (_base_dt + timedelta(days=num * 7)).strftime("%Y-%m-%d")
                            else:
                                deadline = (_base_dt + timedelta(days=num)).strftime("%Y-%m-%d")

            post_mitigation_troubleshooting_guide = vuln_card.get("post_mitigation_troubleshooting_guide", [])

            # Parse mitigation_table into structured per-step data
            steps_dict, step_order = self._parse_mitigation_steps(mitigation_table)

            # Detect host OS priority:
            # 1. vuln_card.os_category (set when AI generated the card)
            # 2. ?os= query param
            # 3. fix_doc.operating_system (persisted from first POST)
            # 4. nessus host_information detection
            _card_os = (vuln_card.get("os_category") or "").strip().lower()
            os_param = request.query_params.get("os", "").strip().lower()
            if _card_os in ("windows", "linux"):
                operating_system = "Windows" if _card_os == "windows" else "Linux"
            elif os_param in ("windows", "linux"):
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
                        "windows": self._ensure_execution_guidance_fields({
                            "where_to_run": "terminal",
                            "where_to_run_label": self._where_to_run_label("terminal"),
                        }),
                        "linux": self._ensure_execution_guidance_fields({
                            "where_to_run": "terminal",
                            "where_to_run_label": self._where_to_run_label("terminal"),
                        }),
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

            # Find user fix docs for same vulnerability (not created by admin)
            # so admin can see which steps users have completed
            user_fix_ids = []
            user_closed_any = False
            for udoc in fix_coll.find({
                "report_id": report_id,
                "host_name": host_name,
                "plugin_name": plugin_name,
                "created_by": {"$ne": admin_id},
            }):
                user_fix_ids.append(str(udoc["_id"]))
            for cdoc in closed_coll.find({
                "report_id": report_id,
                "host_name": host_name,
                "plugin_name": plugin_name,
            }):
                fid = cdoc.get("fix_vulnerability_id", "")
                if fid and fid not in user_fix_ids:
                    user_fix_ids.append(fid)
                # If any user closed this vulnerability, admin status = closed too
                if cdoc.get("closed_by") != admin_id:
                    user_closed_any = True

            # Reflect user closure in admin status
            if user_closed_any:
                status_value = "closed"

            # Build saved_steps from user step records — completed status takes priority
            saved_steps = {}
            lookup_ids = user_fix_ids if user_fix_ids else [fix_vuln_id]
            for s in steps_coll.find({"fix_vulnerability_id": {"$in": lookup_ids}}):
                snum = s["step_number"]
                if snum not in saved_steps or s.get("status") == "completed":
                    saved_steps[snum] = s

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

                _os_key = "linux" if operating_system and operating_system.lower() in ("linux", "unix") else "windows"
                os_payload = self._ensure_execution_guidance_fields(dict(step_meta.get(_os_key) or {}))
                step_data = {
                    "_id": str(saved["_id"]) if saved else "",
                    "step_number": display_idx,
                    "step_name": step_meta["step_name"],
                    "criticality": step_meta["criticality"],
                    "effort_estimate": step_meta["effort_estimate"],
                    "sub_tasks": step_meta.get("sub_tasks", []),
                    _os_key: os_payload,
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
    # POST → Blocked for Admin (read-only)
    # Only users can complete steps via UserFixVulnerabilityStepsAPIView
    # =====================
    def post(self, request, fix_vuln_id):
        return Response(
            {"detail": "Admin can only read steps. Step completion is done by users only."},
            status=status.HTTP_403_FORBIDDEN,
        )

    def _post_disabled(self, request, fix_vuln_id):
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

            # Determine actual total steps for this vulnerability from mitigation_table
            report_id   = fix_doc.get("report_id", "")
            plugin_name = fix_doc.get("plugin_name", "")
            host_name   = fix_doc.get("host_name", "")
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
            mitigation_table = vuln_card.get("mitigation_table") or []
            if mitigation_table:
                step_nums = set()
                for row in mitigation_table:
                    try:
                        step_nums.add(int(row.get("step_no", 0)))
                    except (ValueError, TypeError) as e:
                        logger.warning("Suppressed error: %s", e)
                step_nums.discard(0)
                total_steps = max(step_nums) if step_nums else 6
            else:
                total_steps = 6

            # Validate step_number against actual total steps
            if not isinstance(step_number, int) or step_number < 1 or step_number > total_steps:
                return Response(
                    {"detail": f"step_number must be between 1 and {total_steps} for this vulnerability"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Check if step exists in saved steps
            step_doc = steps_coll.find_one({
                "fix_vulnerability_id": fix_vuln_id,
                "step_number": step_number
            })

            if not step_doc:
                return Response(
                    {"detail": f"Step {step_number} does not exist for this vulnerability"},
                    status=status.HTTP_404_NOT_FOUND
                )

            # Step must be completed before feedback can be submitted
            if step_doc.get("status") != "completed":
                return Response(
                    {"detail": f"Step {step_number} must be completed before submitting feedback"},
                    status=status.HTTP_400_BAD_REQUEST
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
        """Final feedback submission is restricted to users only."""
        return Response(
            {"detail": "Admin can only read feedback. Feedback submission is done by users only."},
            status=status.HTTP_403_FORBIDDEN,
        )

    def _post_disabled(self, request, fix_vuln_id):
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
        """Retrieve final feedback for a closed vulnerability (admin read-only)."""
        admin_id = str(request.user.id)
        admin_email = getattr(request.user, 'email', '')

        with MongoContext() as db:
            fix_coll = db[FIX_VULN_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
            final_feedback_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

            # Find admin's fix doc to get vulnerability details
            admin_fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
            if not admin_fix_doc:
                admin_fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
            if not admin_fix_doc:
                return Response(
                    {"detail": "Fix vulnerability not found"},
                    status=status.HTTP_404_NOT_FOUND
                )

            report_id   = admin_fix_doc.get("report_id", "")
            plugin_name = admin_fix_doc.get("plugin_name", "")
            host_name   = admin_fix_doc.get("host_name", "")

            # Find user's closed doc for the same vulnerability
            user_closed_doc = closed_coll.find_one({
                "report_id":   report_id,
                "plugin_name": plugin_name,
                "host_name":   host_name,
                "closed_by":   {"$ne": admin_id},
            })

            # Determine overall status
            vuln_status = "closed" if user_closed_doc else "open"
            closed_vuln = user_closed_doc or admin_fix_doc

            if vuln_status == "open":
                return Response(
                    {
                        "fix_vulnerability_id": fix_vuln_id,
                        "status": "open",
                        "message": "Vulnerability is still open. No final feedback available.",
                        "final_feedback": None
                    },
                    status=status.HTTP_200_OK
                )

            # Look up feedback using user's fix_vulnerability_id
            user_fix_vuln_id = user_closed_doc.get("fix_vulnerability_id", fix_vuln_id)
            feedback = final_feedback_coll.find_one(
                {"fix_vulnerability_id": user_fix_vuln_id}
            )
            # Fallback: search by vulnerability_name + host_name
            if not feedback:
                feedback = final_feedback_coll.find_one({
                    "vulnerability_name": plugin_name,
                    "host_name": host_name,
                })

            if not feedback:
                return Response(
                    {
                        "fix_vulnerability_id": fix_vuln_id,
                        "admin_id": admin_id,
                        "admin_email": admin_email,
                        "vulnerability_name": plugin_name,
                        "host_name": host_name,
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
                    "vulnerability_name": plugin_name,
                    "host_name": host_name,
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

    def post(self, request, report_id, vulnerability_id):
        return Response(
            {"detail": "Admin cannot raise support requests. Only users can raise support requests."},
            status=status.HTTP_403_FORBIDDEN,
        )

    def get(self, request, report_id, vulnerability_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db["support_requests"]

            cursor = support_coll.find({
                "vulnerability_id": vulnerability_id,
                "admin_id": admin_id,
            }).sort("requested_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "_id":                   str(doc.get("_id")),
                    "report_id":             doc.get("report_id"),
                    "vulnerability_id":      doc.get("vulnerability_id"),
                    "vul_name":              doc.get("vul_name"),
                    "host_name":             doc.get("host_name"),
                    "assigned_team":         doc.get("assigned_team"),
                    "assigned_team_members": doc.get("assigned_team_members", []),
                    "step_number":           doc.get("step_number"),
                    "step_requested":        doc.get("step_requested"),
                    "description":           doc.get("description"),
                    "status":                doc.get("status"),
                    "requested_by":          _resolve_requester(doc),
                    "requested_at":          _normalize_iso(doc.get("requested_at")),
                })

        return Response(
            {
                "message": "Support requests fetched successfully",
                "vulnerability_id": vulnerability_id,
                "count": len(results),
                "results": results,
            },
            status=status.HTTP_200_OK,
        )
  
class RaiseSupportRequestByVulnerabilityAPIView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, vulnerability_id):
        admin_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db["support_requests"]

            cursor = support_coll.find({
                "vulnerability_id": vulnerability_id,
                "admin_id": admin_id,
            }).sort("step_number", 1)

            results = []
            for doc in cursor:
                results.append({
                    "_id":                   str(doc.get("_id")),
                    "report_id":             doc.get("report_id"),
                    "vulnerability_id":      doc.get("vulnerability_id"),
                    "vul_name":              doc.get("vul_name"),
                    "host_name":             doc.get("host_name"),
                    "assigned_team":         doc.get("assigned_team"),
                    "assigned_team_members": doc.get("assigned_team_members", []),
                    "step_number":           doc.get("step_number"),
                    "description":           doc.get("description"),
                    "status":                doc.get("status"),
                    "requested_by":          _resolve_requester(doc),
                    "requested_at":          _normalize_iso(doc.get("requested_at")),
                })

        return Response(
            {
                "exists": len(results) > 0,
                "message": "Support requests fetched successfully",
                "vulnerability_id": vulnerability_id,
                "count": len(results),
                "results": results,
            },
            status=status.HTTP_200_OK,
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

            support_docs = list(cursor)

            # Build vulnerability_id -> severity map from fix_vulnerabilities for fallback.
            fix_coll = db[FIX_VULN_COLLECTION]
            object_ids = []
            for sdoc in support_docs:
                raw_vid = str(sdoc.get("vulnerability_id") or "").strip()
                if not raw_vid:
                    continue
                try:
                    object_ids.append(ObjectId(raw_vid))
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

            fix_severity_by_id = {}
            str_ids = [str(oid) for oid in object_ids]
            if object_ids:
                # Check open fix_vulnerabilities
                for fdoc in fix_coll.find({"_id": {"$in": object_ids}}):
                    fid = str(fdoc.get("_id"))
                    sev = (fdoc.get("risk_factor") or fdoc.get("severity") or "").strip().title()
                    fix_severity_by_id[fid] = sev
                # Also check fix_vulnerabilities_closed (vulns deleted from open after closing)
                for fdoc in db[FIX_VULN_CLOSED_COLLECTION].find({"fix_vulnerability_id": {"$in": str_ids}}):
                    fid = fdoc.get("fix_vulnerability_id", "")
                    if fid and fid not in fix_severity_by_id:
                        sev = (fdoc.get("risk_factor") or fdoc.get("severity") or "").strip().title()
                        fix_severity_by_id[fid] = sev

            # Build closed vulnerability ID set from fix_vulnerabilities_closed
            all_vuln_ids = [
                str(d.get("vulnerability_id") or "").strip()
                for d in support_docs
                if d.get("vulnerability_id")
            ]
            closed_vuln_ids = set()
            if all_vuln_ids:
                with MongoContext() as db2:
                    for cdoc in db2[FIX_VULN_CLOSED_COLLECTION].find(
                        {"fix_vulnerability_id": {"$in": all_vuln_ids}},
                        {"fix_vulnerability_id": 1}
                    ):
                        closed_vuln_ids.add(cdoc.get("fix_vulnerability_id", ""))

            results = []

            for doc in support_docs:
                vulnerability_id = str(doc.get("vulnerability_id") or "").strip()
                severity = (
                    (doc.get("severity") or doc.get("risk_factor") or "").strip().title()
                    or fix_severity_by_id.get(vulnerability_id, "")
                )
                effective_status = (
                    "closed" if vulnerability_id in closed_vuln_ids
                    else doc.get("status")
                )
                results.append({
                    "_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "admin_id": doc.get("admin_id"),
                    "vulnerability_id": doc.get("vulnerability_id"),
                    "vul_name": doc.get("vul_name"),
                    "host_name": doc.get("host_name"),
                    "severity": severity,
                    "assigned_team": doc.get("assigned_team"),
                    "assigned_team_members": doc.get("assigned_team_members", []),
                    # "steps": doc.get("steps", []),
                    "step_requested": doc.get("step_requested"),
                    "description": doc.get("description"),
                    "status": effective_status,
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
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

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

            # Deadline: RiskCriteria + severity takes priority (base = vuln_card.created_at)
            deadline = None
            base_dt = vuln_card.get("created_at")
            if not isinstance(base_dt, datetime):
                base_dt = datetime.now()

            # Step 1: RiskCriteria (primary source)
            try:
                from risk_criteria.models import RiskCriteria
                from admindashboard.views import parse_timeline_to_days
                rc = RiskCriteria.objects.filter(admin=request.user).order_by('-created_at').first()
                if rc:
                    severity = (fix_doc.get("risk_factor") or "").strip().lower()
                    if severity.startswith("crit"):
                        days = parse_timeline_to_days(rc.critical)
                    elif severity.startswith("high"):
                        days = parse_timeline_to_days(rc.high)
                    elif severity.startswith("med"):
                        days = parse_timeline_to_days(rc.medium)
                    elif severity.startswith("low"):
                        days = parse_timeline_to_days(rc.low)
                    else:
                        days = 0
                    if days > 0:
                        deadline = base_dt + timedelta(days=days)
            except Exception as e:
                logger.warning("Suppressed error: %s", e)

            # Step 2: Stored deadline fallback (only proper ISO date, not duration strings)
            if not deadline:
                _raw_deadline = vuln_card.get("deadline") or fix_doc.get("deadline")
                if _raw_deadline:
                    try:
                        deadline = datetime.fromisoformat(str(_raw_deadline).replace("Z", "+00:00"))
                    except (ValueError, TypeError):
                        # It's a duration string like "24 hours", "1 Day" — parse as last resort
                        dur = str(_raw_deadline).strip().lower()
                        num_match = re.search(r"(\d+)", dur)
                        if num_match:
                            num = int(num_match.group(1))
                            if "hour" in dur:
                                deadline = base_dt + timedelta(hours=num)
                            elif "week" in dur:
                                deadline = base_dt + timedelta(days=num * 7)
                            else:
                                deadline = base_dt + timedelta(days=num)

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

            # 4. Steps Done — collect from user fix docs for same vulnerability
            user_fix_ids = []
            for udoc in db[FIX_VULN_COLLECTION].find({
                "report_id":   report_id,
                "host_name":   host_name,
                "plugin_name": plugin_name,
                "created_by":  {"$ne": admin_id},
            }):
                user_fix_ids.append(str(udoc["_id"]))
            for cdoc in db[FIX_VULN_CLOSED_COLLECTION].find({
                "report_id":   report_id,
                "host_name":   host_name,
                "plugin_name": plugin_name,
            }):
                fid = cdoc.get("fix_vulnerability_id", "")
                if fid and fid not in user_fix_ids:
                    user_fix_ids.append(fid)

            lookup_ids = user_fix_ids if user_fix_ids else [fix_vuln_id]
            completed_steps = list(
                db[FIX_VULN_STEPS_COLLECTION].find({
                    "fix_vulnerability_id": {"$in": lookup_ids},
                    "status": "completed",
                }).sort("step_number", 1)
            )

            for display_idx, step in enumerate(completed_steps, start=1):
                step_date = _normalize_iso(
                    step.get("updated_at") or step.get("created_at")
                )
                timeline.append({
                    "event": f"Step {display_idx} Done",
                    "type": "step_done",
                    "date": step_date,
                    "status": "done",
                    "icon": "check",
                    "step_number": display_idx,
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


# ─────────────────────────────────────────────────────────────────────────
# Download Report — consolidated JSON + standalone HTML file
# ─────────────────────────────────────────────────────────────────────────

# Approximate the same palette as the website's team-pill CSS classes
# (team-pill-network/patch/configuration/architectural) so the server-
# rendered team-distribution donut looks consistent with the dashboard.
_REPORT_TEAM_COLORS = {
    "Network Security":         "#0f696e",
    "Patch Management":         "#c98a1f",
    "Configuration Management": "#0f696e",
    "Architectural Flaws":      "#7c3aed",
    "Unassigned":               "#9ca3af",
}
_REPORT_SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high":     "#f2994a",
    "medium":   "#e3b124",
    "low":      "#0f696e",
}


def _build_report_data(request):
    """
    Aggregates everything the downloadable report needs by calling the
    existing admin dashboard views in-process (no HTTP round trip) — reuses
    the same data/queries the website's own dashboard already relies on,
    so the numbers are always consistent with what the admin sees on-screen.
    """
    from admindashboard.views import (
        AdminDashboardSummaryAPIView,
        AdminDistributionByTeamAPIView,
        AdminDetailedVulnerabilitiesAPIView,
    )
    from upload_report.views import AdminLatestReportAPIView

    admin_email = request.user.email
    admin_id = str(request.user.id)

    with MongoContext() as db:
        latest_doc = db[NESSUS_COLLECTION].find_one(
            {"$or": [{"admin_id": admin_id}, {"admin_email": admin_email}]},
            {"report_id": 1, "uploaded_at": 1, "file_name": 1},
            sort=[("uploaded_at", pymongo.DESCENDING)],
        )

    if not latest_doc:
        return None

    # The nessus_reports doc's own "file_name" field isn't reliably populated —
    # the website's own report page treats /api/admin/upload_report/latest-report/
    # (the real uploaded file's Django-tracked name) as the highest-priority
    # source for the displayed file name, so we match that here too.
    latest_upload = AdminLatestReportAPIView().get(request).data

    summary = AdminDashboardSummaryAPIView().get(request).data
    distribution_data = AdminDistributionByTeamAPIView().get(request).data
    detailed_data = AdminDetailedVulnerabilitiesAPIView().get(request).data

    vulns = summary.get("vulnerabilities") or {}
    critical = int(vulns.get("critical") or 0)
    high = int(vulns.get("high") or 0)
    medium = int(vulns.get("medium") or 0)
    low = int(vulns.get("low") or 0)
    total = critical + high + medium + low

    weighted = critical * 8 + high * 5 + medium * 3 + low * 1
    risk_score = round((weighted / (total * 8)) * 100) if total else 0

    return {
        "report_id": str(latest_upload.get("report_id") or latest_doc.get("report_id", "")),
        "report_generated_on": _normalize_iso(latest_upload.get("uploaded_at") or latest_doc.get("uploaded_at")),
        "vul_management_program": latest_upload.get("file_name") or latest_doc.get("file_name") or "—",
        "total_assets": (summary.get("total_assets") or {}).get("total_assets", 0),
        "risk_score": risk_score,
        "vulnerabilities": {"critical": critical, "high": high, "medium": medium, "low": low},
        "vulnerabilities_fixed": summary.get("vulnerabilities_fixed") or {},
        "team_distribution": distribution_data.get("distribution") or [],
        "vulnerabilities_detail": detailed_data.get("vulnerabilities") or [],
    }


class AdminReportDownloadDataAPIView(APIView):
    """
    GET /api/admin/adminregister/report/download-data/
    Consolidated JSON for the downloadable report — same figures the
    dashboard already shows, aggregated into one call.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        data = _build_report_data(request)
        if data is None:
            return Response({"detail": "No reports found for your account"}, status=status.HTTP_404_NOT_FOUND)
        return Response(data, status=status.HTTP_200_OK)


def _render_report_html(data):
    total = sum(data["vulnerabilities"].values())
    crit, high, med, low = (
        data["vulnerabilities"]["critical"], data["vulnerabilities"]["high"],
        data["vulnerabilities"]["medium"], data["vulnerabilities"]["low"],
    )

    # Same running-percentage conic-gradient formula the Vue page uses for
    # its severity donut — kept identical so this looks the same as the
    # in-browser "Download as HTML" export.
    def _pct(n):
        return (n / total * 100) if total else 0
    c1 = _pct(crit)
    c2 = c1 + _pct(high)
    c3 = c2 + _pct(med)
    severity_gradient = (
        f"conic-gradient({_REPORT_SEVERITY_COLORS['critical']} 0% {c1:.2f}%, "
        f"{_REPORT_SEVERITY_COLORS['high']} {c1:.2f}% {c2:.2f}%, "
        f"{_REPORT_SEVERITY_COLORS['medium']} {c2:.2f}% {c3:.2f}%, "
        f"{_REPORT_SEVERITY_COLORS['low']} {c3:.2f}% 100%)"
    )

    team_dist = [d for d in data["team_distribution"] if d.get("count")]
    team_total = sum(d.get("count", 0) for d in team_dist) or 1
    running = 0
    team_stops = []
    for d in team_dist:
        start = running / team_total * 100
        running += d.get("count", 0)
        end = running / team_total * 100
        color = _REPORT_TEAM_COLORS.get(d.get("team"), "#9ca3af")
        team_stops.append(f"{color} {start:.2f}% {end:.2f}%")
    team_gradient = f"conic-gradient({', '.join(team_stops)})" if team_stops else "#e5e7eb"

    closed = int((data["vulnerabilities_fixed"] or {}).get("total_fixed") or 0)
    remediation_pct = round((closed / total) * 100) if total else 0

    severity_legend_rows = "".join(
        f'<div class="legend-row"><span class="legend-color" style="background:{_REPORT_SEVERITY_COLORS[sev]}"></span>'
        f'<span class="legend-label">{sev.capitalize()}</span>'
        f'<strong class="legend-pct">{round(_pct(n))}%</strong></div>'
        for sev, n in [("critical", crit), ("high", high), ("medium", med), ("low", low)]
    )

    def esc(v):
        return str(v if v is not None else "—").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def team_pill_class(team_name):
        key = (team_name or "").strip().lower()
        if "network" in key:
            return "team-pill-network"
        if "patch" in key:
            return "team-pill-patch"
        if "configuration" in key:
            return "team-pill-configuration"
        if "architectural" in key:
            return "team-pill-architectural"
        return "team-pill-configuration"

    table_rows = "".join(
        f'<tr><td>{i + 1}</td><td class="vname">{esc(v.get("vulnerability_name"))}</td>'
        f'<td>{esc(v.get("assets"))}</td>'
        f'<td><span class="team-pill {team_pill_class(v.get("assigned_team"))}">{esc(v.get("assigned_team") or "Unassigned")}</span></td>'
        f'<td><span class="sev-pill sev-{esc(v.get("risk_factor")).lower()}">{esc(v.get("risk_factor"))}</span></td>'
        f'<td>{esc((v.get("found_date") or "—")[:10] if v.get("found_date") else "—")}</td>'
        f'<td><span class="status-pill status-{esc(v.get("status")).lower().replace("/", "-")}">{esc(v.get("status"))}</span></td></tr>'
        for i, v in enumerate(data["vulnerabilities_detail"])
    )

    team_legend_rows = "".join(
        f'<div class="legend-row"><span class="legend-color" style="background:{_REPORT_TEAM_COLORS.get(d.get("team"), "#9ca3af")}"></span>'
        f'<span class="legend-label">{esc(d.get("team"))}</span>'
        f'<strong class="legend-pct">{d.get("count", 0)}</strong></div>'
        for d in team_dist
    ) or '<div class="legend-row"><span class="legend-label">No team-assigned vulnerabilities yet.</span></div>'

    watermark_svg = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="580" height="420" viewBox="0 0 580 420">'
        '<text x="290" y="210" transform="rotate(-38 290 210)" font-family="Inter,Arial,sans-serif" '
        'font-size="52" font-weight="700" fill="rgba(140,145,155,0.135)" text-anchor="middle" '
        'dominant-baseline="middle">vaptfix.ai</text></svg>'
    )
    import base64
    watermark_data_uri = "data:image/svg+xml;base64," + base64.b64encode(watermark_svg.encode()).decode()

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vulnerability Management Report</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
  * {{ box-sizing: border-box; }}
  body {{ font-family: 'Inter', sans-serif; background: #f8f9fc; margin: 0; padding: 0; }}
  .wrap {{ max-width: 1400px; margin: 0 auto; padding: 48px 56px; position: relative; }}
  .watermark {{ position: absolute; inset: 0; z-index: 50; pointer-events: none;
    background-image: url("{watermark_data_uri}"); background-repeat: repeat; background-size: 580px 420px; }}
  .content {{ position: relative; z-index: 1; }}
  .eyebrow {{ margin: 0; color: #0f696e; font-size: 11px; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }}
  .page-title {{ margin: 2px 0 10px; color: #241447; font-size: 44px; font-weight: 800; letter-spacing: -.02em; line-height: 1.05; }}
  .meta-items {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 24px; }}
  .meta-item {{ flex: 1 1 200px; }}
  .meta-item span {{ display: block; font-size: 10px; color: #8b95a7; text-transform: uppercase; font-weight: 700; letter-spacing: .08em; }}
  .meta-item strong {{ font-size: 14px; color: #20293a; font-weight: 700; line-height: 1.3; }}
  .top-grid {{ display: flex; flex-wrap: wrap; gap: 14px; margin-bottom: 14px; }}
  .top-grid .card:first-child {{ flex: 2 1 380px; }}
  .top-grid .card:last-child {{ flex: 1 1 220px; }}
  .card {{ background: #fff; border: 1px solid #e8e8ef; border-radius: 18px; padding: 18px; }}
  .card h3 {{ margin: 0 0 10px; color: #222848; font-size: 22px; font-weight: 700; }}
  .icon-mark {{ color: #0f696e; font-size: 18px; margin-right: 8px; vertical-align: middle; }}
  .executive-card p {{ margin: 0 0 10px; color: #5a6477; line-height: 1.58; font-size: 14px; }}
  .score-grid {{ margin-top: 14px; display: flex; gap: 10px; }}
  .score-grid .score-box {{ flex: 1 1 0; }}
  .score-box {{ background: #f4f5f8; border-radius: 10px; padding: 12px; }}
  .score-box span {{ display: block; font-size: 11px; color: #8b95a7; text-transform: uppercase; font-weight: 700; letter-spacing: .06em; }}
  .score-box strong {{ font-size: 34px; color: #1f2a42; line-height: 1.08; }}
  .dark-card {{ background: #25124d; color: #fff; text-align: center; display: flex; flex-direction: column; gap: 10px; justify-content: center; }}
  .dark-card h3 {{ color: #fff; font-size: 22px; }}
  .progress-ring {{ margin: 8px auto; width: 140px; height: 140px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center; position: relative; }}
  .progress-ring::before {{ content: ''; width: 104px; height: 104px; border-radius: 50%; background: #25124d; }}
  .progress-text {{ position: absolute; font-size: 38px; font-weight: 800; color: #fff; }}
  .progress-meta {{ color: #d6d3e8; font-size: 13px; display: flex; justify-content: space-between; gap: 10px; }}
  .severity-stats-grid {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; }}
  .severity-stats-grid .stat-card {{ flex: 1 1 140px; }}
  .stat-card {{ background: #fff; border: 1px solid #ececf2; border-radius: 14px; padding: 10px 12px; min-height: 118px;
    display: flex; flex-direction: column; justify-content: space-between; box-shadow: 0 1px 4px rgba(36,20,71,.08); }}
  .stat-card span {{ font-size: 10px; color: #8b95a7; text-transform: uppercase; font-weight: 800; letter-spacing: .07em; }}
  .stat-card strong {{ font-size: 36px; font-weight: 800; line-height: 1; }}
  .stat-card small {{ color: #8b95a7; font-size: 11px; }}
  .stat-card.critical {{ border-bottom: 3px solid #b91c1c; }} .stat-card.critical strong {{ color: #b91c1c; }}
  .stat-card.high strong {{ color: #d97706; }}
  .stat-card.medium strong {{ color: #ca8a04; }}
  .stat-card.low {{ border-bottom: 3px solid #0f696e; }} .stat-card.low strong {{ color: #0f696e; }}
  .chart-grid {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 14px; }}
  .chart-grid .card {{ flex: 1 1 300px; }}
  .mini-meta {{ margin: -4px 0 10px; font-size: 11px; color: #8b95a7; }}
  .severity-visual {{ display: flex; flex-wrap: wrap; align-items: center; gap: 12px; }}
  .severity-visual > div:last-child {{ flex: 1 1 160px; }}
  .donut {{ width: 200px; height: 200px; flex: 0 0 200px; border-radius: 50%; display: flex; align-items: center; justify-content: center; }}
  .donut-center {{ width: 132px; height: 132px; border-radius: 50%; background: #fff; display: flex; flex-direction: column;
    align-items: center; justify-content: center; box-shadow: inset 0 0 0 1px #e5e7eb; }}
  .donut-center strong {{ font-size: 36px; line-height: 1; color: #1f2a42; }}
  .donut-center span {{ font-size: 11px; letter-spacing: .08em; color: #8b95a7; font-weight: 700; }}
  .legend-row {{ display: flex; align-items: center; gap: 8px; font-size: 13px; color: #2e3648; margin-bottom: 8px; }}
  .legend-color {{ width: 10px; height: 10px; border-radius: 3px; display: inline-block; }}
  .legend-label {{ flex: 1; }}
  .legend-pct {{ font-size: 16px; color: #273247; }}
  .table-wrap {{ margin-top: 10px; overflow-x: auto; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th {{ background: #f4f5f8; font-size: 10px; text-transform: uppercase; letter-spacing: .08em; color: #8b95a7; font-weight: 800; padding: 12px 10px; text-align: left; }}
  td {{ border-bottom: 1px solid #edf0f4; padding: 12px 10px; color: #2d3748; font-size: 13px; }}
  .vname {{ font-weight: 600; color: #1f2a42; }}
  .sev-pill, .status-pill {{ font-size: 10px; font-weight: 800; border-radius: 6px; padding: 4px 8px; text-transform: uppercase; }}
  .sev-critical {{ background: #fee2e2; color: #b91c1c; }} .sev-high {{ background: #ffedd5; color: #c2410c; }}
  .sev-medium {{ background: #fef3c7; color: #a16207; }} .sev-low {{ background: #ccfbf1; color: #0f766e; }}
  .status-pill {{ font-weight: 700; }} .status-open {{ color: #b91c1c; }} .status-closed {{ color: #0f766e; }}
  .status-in_progress, .status-open-review {{ color: #a16207; }}
  .team-pill {{ font-size: 12px; font-weight: 700; border-radius: 999px; padding: 4px 10px; border: 1px solid transparent; display: inline-block; }}
  .team-pill-network {{ color: #0f696e; background: #e6f7f8; border-color: #8dd9dd; }}
  .team-pill-patch {{ color: #8a4f00; background: #fff3dd; border-color: #ffd089; }}
  .team-pill-configuration {{ color: #0f696e; background: #e6f7f8; border-color: #8dd9dd; }}
  .team-pill-architectural {{ color: #6b21a8; background: #f3e8ff; border-color: #d8b4fe; }}
  @media (max-width: 900px) {{ .top-grid, .chart-grid, .severity-stats-grid {{ flex-direction: column; }} }}
  @media print {{
    .wrap {{ padding: 20px; max-width: none; }}
    table {{ page-break-inside: auto; }}
    tr {{ page-break-inside: avoid; page-break-after: auto; }}
    /* A4 print width is much narrower than the 1400px browser layout was
       designed for — flex-wrap's content-based wrapping (fine in a browser)
       collapses these to a single column here. Force them to stay in their
       intended columns by wrapping off + flex-basis:0 (divide available
       width purely by the grow ratio, regardless of content size). */
    .top-grid {{ flex-wrap: nowrap; }}
    .top-grid .card:first-child {{ flex: 2 1 0; min-width: 0; }}
    .top-grid .card:last-child {{ flex: 1 1 0; min-width: 0; }}
    .severity-stats-grid {{ flex-wrap: nowrap; }}
    .severity-stats-grid .stat-card {{ flex: 1 1 0; min-width: 0; }}
    .chart-grid {{ flex-wrap: nowrap; }}
    .chart-grid .card {{ flex: 1 1 0; min-width: 0; }}
    .severity-visual {{ flex-wrap: nowrap; }}
    .donut {{ width: 130px; height: 130px; flex: 0 0 130px; }}
    .donut-center {{ width: 86px; height: 86px; }}
    .donut-center strong {{ font-size: 26px; }}
  }}
</style>
</head>
<body>
<div class="wrap">
  <div class="watermark"></div>
  <div class="content">
    <p class="eyebrow">Comprehensive Audit</p>
    <h1 class="page-title">Vulnerability Management Program Report</h1>
    <div class="meta-items">
      <div class="meta-item"><span>Report Generated On</span><strong>{esc(data['report_generated_on'])}</strong></div>
      <div class="meta-item"><span>Vul Management Program</span><strong>{esc(data['vul_management_program'])}</strong></div>
      <div class="meta-item"><span>Total Assets</span><strong>{esc(data['total_assets'])}</strong></div>
    </div>

    <div class="top-grid">
      <div class="card">
        <h3><span class="icon-mark">◫</span> Executive Summary</h3>
        <p>The security assessment identified a total of {total} distinct security findings across {esc(data['total_assets'])} assets.</p>
        <div class="score-grid">
          <div class="score-box"><span>Risk Score</span><strong>{data['risk_score']}/100</strong></div>
          <div class="score-box"><span>Sensitivity</span><strong>{'HIGH' if (crit or high or med) else 'MODERATE'}</strong></div>
        </div>
      </div>
      <div class="card dark-card">
        <h3>Remediation Progress</h3>
        <div class="progress-ring" style="background: conic-gradient(#0f696e {remediation_pct}%, rgba(255,255,255,.2) 0);"><span class="progress-text">{remediation_pct}%</span></div>
        <div class="progress-meta"><span>Closed: {closed}</span><span>Open: {total - closed}</span></div>
      </div>
    </div>

    <div class="severity-stats-grid">
      <div class="stat-card critical"><span>Critical</span><strong>{crit}</strong></div>
      <div class="stat-card high"><span>High</span><strong>{high}</strong></div>
      <div class="stat-card medium"><span>Medium</span><strong>{med}</strong></div>
      <div class="stat-card low"><span>Low</span><strong>{low}</strong></div>
    </div>

    <div class="chart-grid">
      <div class="card">
        <h3>Severity Distribution</h3>
        <p class="mini-meta">Total Findings: {total}</p>
        <div class="severity-visual">
          <div class="donut" style="background:{severity_gradient}"><div class="donut-center"><strong>{total}</strong><span>ISSUES</span></div></div>
          <div>{severity_legend_rows}</div>
        </div>
      </div>
      <div class="card">
        <h3>Findings by Team</h3>
        <p class="mini-meta">Assigned: {team_total if team_dist else 0}</p>
        <div class="severity-visual">
          <div class="donut" style="background:{team_gradient}"><div class="donut-center"><strong>{team_total if team_dist else 0}</strong><span>ASSIGNED</span></div></div>
          <div>{team_legend_rows}</div>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Detailed Vulnerability Log</h3>
      <div class="table-wrap">
        <table>
          <thead><tr><th>#</th><th>Vulnerability</th><th>Asset</th><th>Team</th><th>Severity</th><th>Found Date</th><th>Status</th></tr></thead>
          <tbody>{table_rows or '<tr><td colspan="7">No vulnerabilities found.</td></tr>'}</tbody>
        </table>
      </div>
    </div>
  </div>
</div>
</body>
</html>"""


def _render_report_pdf(html):
    """
    Converts the same HTML _render_report_html() produces into PDF bytes
    using WeasyPrint — no new heavy dependency (it's already pinned in
    requirements.txt). Requires WeasyPrint's system libs (Pango/Cairo/
    GDK-Pixbuf) to be installed on the host; raises on import/render
    failure so callers can surface a clear error instead of a silent 500.
    """
    from weasyprint import HTML as WeasyHTML
    return WeasyHTML(string=html).write_pdf()


class AdminReportDownloadAPIView(APIView):
    """
    GET /api/admin/adminregister/report/download/?type=html|pdf
    Returns the report as a downloadable, self-contained file — same data
    as download-data/ above, rendered server-side (no browser needed) so
    it can also be generated for Slack's /downloadreport. Defaults to
    html (unchanged from before) when ?type= is omitted. Deliberately not
    named "format" — that's a reserved DRF query param for its own
    renderer content-negotiation and silently breaks if reused.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        from django.http import HttpResponse

        data = _build_report_data(request)
        if data is None:
            return Response({"detail": "No reports found for your account"}, status=status.HTTP_404_NOT_FOUND)

        html = _render_report_html(data)
        # NOTE: intentionally "type", not "format" — DRF reserves ?format=
        # for its own renderer content-negotiation (e.g. ?format=json),
        # which silently swallowed our custom value and produced a bare
        # "Not found" before this view's code ever ran.
        fmt = (request.query_params.get("type") or "html").strip().lower()

        if fmt == "pdf":
            try:
                pdf_bytes = _render_report_pdf(html)
            except Exception as exc:
                import traceback
                tb = traceback.format_exc()
                traceback.print_exc()
                return Response(
                    {"detail": "PDF generation unavailable on this server", "error": str(exc), "traceback": tb},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            response = HttpResponse(pdf_bytes, content_type="application/pdf")
            filename = f"vaptfix-report-{data['report_id'] or 'latest'}.pdf"
            response["Content-Disposition"] = f'attachment; filename="{filename}"'
            return response

        response = HttpResponse(html, content_type="text/html")
        filename = f"vaptfix-report-{data['report_id'] or 'latest'}.html"
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response