from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import JSONParser
from datetime import datetime, timedelta
from django.utils.timezone import is_naive, make_aware
from bson import ObjectId
import pymongo
import uuid
import re

import logging
from vaptfix.mongo_client import MongoContext

logger = logging.getLogger(__name__)
def _parse_timeline_to_days(value: str) -> int:
    """Convert timeline string to days. e.g. '5 Days'->5, '1 Week'->7"""
    if not value:
        return 0
    value = value.strip().lower()
    if value in ("select", ""):
        return 0
    import re as _re
    match = _re.search(r"(\d+)", value)
    if not match:
        return 0
    num = int(match.group(1))
    if "week" in value:
        return num * 7
    return num

# ─── Collection names (same as adminregister) ────────────────────────────────
NESSUS_COLLECTION          = "nessus_reports"
VULN_CARD_COLLECTION       = "vulnerability_cards"
FIX_VULN_COLLECTION        = "fix_vulnerabilities"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
FIX_VULN_STEPS_COLLECTION  = "fix_vulnerability_steps"
FIX_STEP_FEEDBACK_COLLECTION   = "fix_step_feedback"
FIX_FINAL_FEEDBACK_COLLECTION  = "fix_vulnerability_final_feedback"
SUPPORT_REQUEST_COLLECTION = "support_requests"
TICKETS_COLLECTION         = "tickets"

# ─── Model imports ────────────────────────────────────────────────────────────
try:
    from users_details.models import UserDetail
except Exception:
    UserDetail = None


# ─── Helpers ─────────────────────────────────────────────────────────────────

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


def _get_user_context(user_email):
    """
    Returns (teams_list, admin_user) for the logged-in team member.
    Looks up UserDetail by email.
    """
    if not UserDetail:
        return [], None
    detail = UserDetail.objects.select_related('admin').filter(email=user_email).first()
    if not detail:
        return [], None
    teams = detail.Member_role if isinstance(detail.Member_role, list) else []
    if not teams and detail.team_name:
        teams = [detail.team_name]
    return teams, detail.admin


def _normalize_teams(teams):
    """Lowercase map for case-insensitive team matching."""
    return {t.lower(): t for t in teams}


def _resolve_requester(doc):
    """
    Returns requester display name for a support_requests document.
    - user_id present → the user who raised the request (email from auth User)
    - admin_id only   → admin email
    - fallback        → stored requested_by value
    """
    from django.contrib.auth import get_user_model

    user_id  = doc.get("user_id")
    admin_id = doc.get("admin_id")

    if user_id:
        try:
            User = get_user_model()
            u = User.objects.filter(pk=str(user_id)).only("email").first()
            if u:
                return u.email
        except Exception as e:
            logger.warning("Suppressed error: %s", e)

    if admin_id:
        try:
            User = get_user_model()
            u = User.objects.filter(pk=str(admin_id)).only("email").first()
            if u:
                return u.email
        except Exception as e:
            logger.warning("Suppressed error: %s", e)

    return doc.get("requested_by", "")


def _load_latest_report(db, admin_id, admin_email):
    """Load admin's most recently uploaded nessus report."""
    coll = db[NESSUS_COLLECTION]
    doc = coll.find_one({"admin_id": str(admin_id)}, sort=[("uploaded_at", -1)])
    if not doc and admin_email:
        doc = coll.find_one({"admin_email": admin_email}, sort=[("uploaded_at", -1)])
    return doc


def _get_team_plugin_names(db, report_id, teams_lower):
    """
    Returns a set of plugin_names assigned to the user's teams
    from vulnerability_cards collection.
    """
    team_plugins = set()
    plugin_team_map = {}  # plugin_name -> matched_team (original case)
    for card in db[VULN_CARD_COLLECTION].find(
        {"report_id": str(report_id)},
        {"vulnerability_name": 1, "assigned_team": 1}
    ):
        pname    = (card.get("vulnerability_name") or "").strip()
        raw_team = (card.get("assigned_team") or "").strip()
        matched  = teams_lower.get(raw_team.lower())
        if pname and matched:
            team_plugins.add(pname)
            plugin_team_map[pname] = matched
    return team_plugins, plugin_team_map


# ─────────────────────────────────────────────────────────────────────────────
# 1. USER LATEST VULNERABILITY REGISTER (team-filtered)
# ─────────────────────────────────────────────────────────────────────────────

class UserLatestVulnerabilityRegisterAPIView(APIView):
    """
    Returns vulnerabilities from admin's latest nessus report,
    filtered by the logged-in user's assigned teams.

    GET /api/user/register/latest/vulns/
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team. Ask your admin to assign you a team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            selected_team = request.query_params.get("team", "").strip()
            active_teams  = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower   = _normalize_teams(active_teams)

            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", None)

            with MongoContext() as db:
                latest_doc = _load_latest_report(db, admin_user.id, admin_email)

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin account"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                report_id   = latest_doc.get("report_id")
                uploaded_at = latest_doc.get("uploaded_at")

                # Step 1: Build plugin_name -> assigned_team map (team-filtered)
                _, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)

                # Step 2: Build closed vuln set (plugin_name, host_name, port)
                closed_vulns = set()
                for doc in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": str(report_id)}
                ):
                    key = (
                        doc.get("plugin_name", ""),
                        doc.get("host_name", ""),
                        str(doc.get("port", ""))
                    )
                    closed_vulns.add(key)

                # Step 3: Build rows — only team-assigned vulnerabilities
                rows = []
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""

                    for v in host.get("vulnerabilities", []):
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )

                        # Only include if assigned to user's team
                        assigned_team = plugin_team_map.get(plugin_name)
                        if not assigned_team:
                            continue

                        port     = v.get("port", "")
                        protocol = v.get("protocol", "")

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
                        severity = risk_raw.strip().title() if isinstance(risk_raw, str) else ""

                        first_obs  = v.get("created_at") or uploaded_at
                        second_obs = v.get("updated_at")

                        rows.append({
                            "id": str(uuid.uuid4()),
                            "vul_name": plugin_name,
                            "asset": host_name,
                            "severity": severity,
                            "port": port,
                            "protocol": protocol,
                            "assigned_team": assigned_team,
                            "first_observation": _normalize_iso(first_obs),
                            "second_observation": _normalize_iso(second_obs),
                            "status": vuln_status,
                        })

                return Response(
                    {
                        "report_id": str(report_id),
                        "teams": active_teams,
                        "uploaded_at": _normalize_iso(uploaded_at),
                        "count": len(rows),
                        "rows": rows,
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# 2. FIX VULNERABILITY CREATE + LIST
# ─────────────────────────────────────────────────────────────────────────────

class UserFixVulnerabilityCreateAPIView(APIView):
    """
    POST/GET /api/user/register/fix-vulnerability/report/<report_id>/asset/<host_name>/create/
    Same as adminregister but uses admin's nessus report via user context.
    Validates that the vulnerability belongs to user's team.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request, report_id, host_name):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            user_id     = str(request.user.id)
            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", None)
            teams_lower = _normalize_teams(teams)

            plugin_name_req = request.data.get("plugin_name", "").strip()
            risk_factor_req = request.data.get("risk_factor", "").strip()
            id_req          = request.data.get("id", str(uuid.uuid4()))
            port_req        = request.data.get("port", "")
            req_status      = request.data.get("status", "")

            if not plugin_name_req or not risk_factor_req:
                return Response(
                    {"detail": "plugin_name and risk_factor are required."},
                    status=status.HTTP_400_BAD_REQUEST
                )

            with MongoContext() as db:
                # Load admin's latest report
                latest_doc = _load_latest_report(db, admin_user.id, admin_email)
                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin account"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                if latest_doc.get("report_id") != str(report_id):
                    return Response(
                        {
                            "detail": "Data must come from the latest uploaded report only",
                            "latest_report_id": latest_doc.get("report_id")
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Validate vulnerability belongs to user's team
                _, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)
                assigned_team = plugin_team_map.get(plugin_name_req)
                if not assigned_team:
                    return Response(
                        {"detail": "This vulnerability is not assigned to your team."},
                        status=status.HTTP_403_FORBIDDEN
                    )

                fix_coll    = db[FIX_VULN_COLLECTION]
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                # Closed check
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

                # Duplicate check — use stable fields (plugin_name), NOT id which is a fresh UUID each visit
                dup_query = {
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "plugin_name": plugin_name_req,
                }
                if port_req:
                    dup_query["port"] = str(port_req)
                existing_fix = fix_coll.find_one(dup_query)
                if existing_fix:
                    return Response(
                        {
                            "message": "Fix vulnerability created successfully",
                            "data": {
                                "_id": str(existing_fix["_id"]),
                                "report_id": existing_fix.get("report_id"),
                                "id": existing_fix.get("id"),
                                "vulnerability_name": existing_fix.get("plugin_name"),
                                "asset": existing_fix.get("host_name"),
                                "severity": existing_fix.get("risk_factor"),
                                "port": existing_fix.get("port", ""),
                                "description": existing_fix.get("description", "") or existing_fix.get("description_points", "") or existing_fix.get("synopsis", ""),
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

                # Find vulnerability in nessus report
                selected_vuln = None
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
                        if db_plugin_name == plugin_name_req:
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
                            "host_name": host_name
                        },
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Get vuln card details
                vuln_card_doc = (
                    db[VULN_CARD_COLLECTION].find_one({
                        "report_id": str(report_id),
                        "vulnerability_name": plugin_name_req,
                        "host_name": host_name,
                    })
                    or db[VULN_CARD_COLLECTION].find_one({
                        "report_id": str(report_id),
                        "vulnerability_name": plugin_name_req,
                    })
                )

                _vfa_raw = (vuln_card_doc or {}).get("vendor_fix_available", "No")
                vendor_fix_available = (
                    _vfa_raw.strip().lower() == "yes"
                    if isinstance(_vfa_raw, str)
                    else bool(_vfa_raw)
                )
                vulnerability_type = (vuln_card_doc or {}).get("vulnerability_type") or ""

                # Get assigned team members from users_details
                assigned_team_members = []
                try:
                    from users_details.models import UserDetail as UD
                    members_qs = UD.objects.filter(
                        admin=admin_user,
                        Member_role__contains=assigned_team
                    )
                    for m in members_qs:
                        assigned_team_members.append({
                            "user_id": str(m.pk),
                            "name": f"{m.first_name} {m.last_name}".strip(),
                            "email": m.email,
                        })
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

                description       = selected_vuln.get("description", "")
                description_points = selected_vuln.get("description_points", [])
                if isinstance(description_points, list):
                    description_points = "\n".join(description_points)
                synopsis  = selected_vuln.get("synopsis", "")
                solution  = selected_vuln.get("solution", "")
                port      = selected_vuln.get("port", "")
                protocol  = selected_vuln.get("protocol", "")

                plugin_outputs  = selected_vuln.get("plugin_outputs", [])
                affected_ports  = [po.get("plugin_output") for po in plugin_outputs if po.get("plugin_output")]
                file_path       = [po.get("plugin_output_url") for po in plugin_outputs if po.get("plugin_output_url")]

                vuln_status = req_status if req_status else "open"

                doc = {
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "id": id_req,
                    "plugin_name": plugin_name_req,
                    "risk_factor": risk_factor_req,
                    "port": port,
                    "protocol": protocol,
                    "description": description,
                    "description_points": description_points,
                    "synopsis": synopsis,
                    "solution": solution,
                    "status": vuln_status,
                    "vulnerability_type": vulnerability_type,
                    "affected_ports_ranges": affected_ports,
                    "file_path": file_path,
                    "vendor_fix_available": vendor_fix_available,
                    "assigned_team": assigned_team,
                    "assigned_team_members": assigned_team_members,
                    "created_at": datetime.utcnow(),
                    "created_by": user_id,
                    "admin_id": admin_id,
                }

                result = fix_coll.insert_one(doc)

                return Response(
                    {
                        "message": "Fix vulnerability created successfully",
                        "data": {
                            "_id": str(result.inserted_id),
                            "report_id": str(report_id),
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
                            "created_at": doc["created_at"].isoformat(),
                        }
                    },
                    status=status.HTTP_201_CREATED
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request, report_id, host_name):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )
            user_id     = str(request.user.id)
            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", "")
            teams_lower = _normalize_teams(teams)

            with MongoContext() as db:
                fix_coll      = db[FIX_VULN_COLLECTION]
                nessus_coll   = db[NESSUS_COLLECTION]
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                # Team plugin filter
                _, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)

                fix_docs = list(fix_coll.find({
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "created_by": user_id,
                }).sort("created_at", -1))

                nessus_doc = nessus_coll.find_one({
                    "report_id": str(report_id),
                    "$or": [{"admin_id": admin_id}, {"admin_email": admin_email}]
                })

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
                                or vuln.get("name") or ""
                            ).strip()
                            if pname and pname not in nessus_vuln_lookup:
                                nessus_vuln_lookup[pname] = vuln

                plugin_names = [d.get("plugin_name", "") for d in fix_docs if d.get("plugin_name")]
                vuln_card_lookup = {}
                if plugin_names:
                    for card in vuln_card_coll.find({
                        "report_id": str(report_id),
                        "vulnerability_name": {"$in": plugin_names}
                    }):
                        vname = card.get("vulnerability_name", "")
                        if vname:
                            vuln_card_lookup[vname] = card

                results = []
                for doc in fix_docs:
                    plugin_name  = doc.get("plugin_name", "")
                    nessus_vuln  = nessus_vuln_lookup.get(plugin_name, {})
                    vuln_card    = vuln_card_lookup.get(plugin_name, {})
                    plugin_outputs = nessus_vuln.get("plugin_outputs", [])

                    results.append({
                        "_id": str(doc.get("_id")),
                        "report_id": doc.get("report_id"),
                        "id": doc.get("id"),
                        "status": nessus_vuln.get("status") or doc.get("status", "open"),
                        "asset": host_name,
                        "vulnerability_name": plugin_name,
                        "assigned_team": vuln_card.get("assigned_team") or doc.get("assigned_team", ""),
                        "description": nessus_vuln.get("description") or doc.get("description_points", "") or doc.get("synopsis", ""),
                        "affected_ports_ranges": [po.get("plugin_output") for po in plugin_outputs if po.get("plugin_output")],
                        "file_path": [po.get("plugin_output_url") for po in plugin_outputs if po.get("plugin_output_url")],
                        "vulnerability_type": vuln_card.get("vulnerability_type"),
                        "vendor_fix_available": vuln_card.get("vendor_fix_available") or doc.get("vendor_fix_available", False),
                        "steps_to_fix": vuln_card.get("mitigation_table", []),
                        "deadline": vuln_card.get("deadline"),
                        "artifacts_tools": vuln_card.get("artifacts_tools"),
                        "post_mitigation_troubleshooting_guide": vuln_card.get("post_mitigation_troubleshooting_guide"),
                        "steps_to_fix_count": vuln_card.get("steps_to_fix_count"),
                        "severity": doc.get("risk_factor"),
                        "port": doc.get("port", ""),
                        "protocol": doc.get("protocol", ""),
                        "solution": doc.get("solution", ""),
                        "assigned_team_members": doc.get("assigned_team_members", []),
                        "created_at": _normalize_iso(doc.get("created_at")),
                    })

                return Response(
                    {
                        "report_id": str(report_id),
                        "host_name": host_name,
                        "count": len(results),
                        "results": results,
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# 3. FIX VULNERABILITY CARD DETAIL
# ─────────────────────────────────────────────────────────────────────────────

class UserFixVulnerabilityCardAPIView(APIView):
    """
    GET /api/user/register/fix-vulnerability/<fix_vuln_id>/card/
    Returns single fix card details by its _id.
    Same as adminregister — data is shared (same MongoDB collection).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vuln_id):
        try:
            with MongoContext() as db:
                fix_coll    = db[FIX_VULN_COLLECTION]
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                card_status = "open"

                if not doc:
                    doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                    if not doc:
                        return Response(
                            {"detail": "Fix vulnerability not found"},
                            status=status.HTTP_404_NOT_FOUND
                        )
                    card_status = "closed"

                return Response(
                    {
                        "message": "Fix card details fetched successfully",
                        "data": {
                            "_id": str(doc.get("_id", fix_vuln_id)),
                            "report_id": doc.get("report_id"),
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
                            "created_by": doc.get("created_by"),
                        }
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# 4. FIX VULNERABILITY STEPS
# ─────────────────────────────────────────────────────────────────────────────

class UserFixVulnerabilityStepsAPIView(APIView):
    """
    GET  /api/user/register/fix-vulnerability/<fix_vuln_id>/step-complete/
    POST /api/user/register/fix-vulnerability/<fix_vuln_id>/step-complete/
    Same logic as adminregister — reads/writes to same collections.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

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

    def _ensure_execution_guidance_fields(self, os_data: dict) -> dict:
        commands = (os_data.get("commands_for_action") or "").strip()
        if not os_data.get("expected_output"):
            if commands:
                os_data["expected_output"] = "Command completes successfully without errors."
            else:
                os_data["expected_output"] = "Action is completed successfully in the selected run context."
        if not os_data.get("verification_check"):
            os_data["verification_check"] = "Verify no error is shown and expected service/state is updated."
        if not os_data.get("on_success_next_step"):
            os_data["on_success_next_step"] = "Proceed to the next remediation sub-task."
        if not os_data.get("on_failure_what_to_do"):
            os_data["on_failure_what_to_do"] = "Check command/path/permissions, then retry. Escalate to admin if issue persists."
        return os_data

    def _parse_mitigation_steps(self, mitigation_table):
        META_KEYS = {"step_no", "step_name", "criticality", "effort_estimate", "operating_system"}
        steps_dict = {}
        step_order  = []

        for row in mitigation_table:
            try:
                step_num = int(row.get("step_no", 0))
            except (ValueError, TypeError) as e:
                logger.warning("Suppressed error: %s", e)
            if step_num <= 0:
                continue

            os_raw = (row.get("operating_system") or "").strip().lower()
            os_key = "linux" if "linux" in os_raw else "windows"
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

    def get(self, request, fix_vuln_id):
        try:
            with MongoContext() as db:
                fix_coll     = db[FIX_VULN_COLLECTION]
                steps_coll   = db[FIX_VULN_STEPS_COLLECTION]
                closed_coll  = db[FIX_VULN_CLOSED_COLLECTION]
                feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]

                fix_doc      = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                status_value = "open"

                if not fix_doc:
                    fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                    if not fix_doc:
                        return Response(
                            {"detail": "Fix vulnerability not found"},
                            status=status.HTTP_404_NOT_FOUND
                        )
                    status_value = "closed"

                report_id   = fix_doc.get("report_id", "")
                host_name   = fix_doc.get("host_name", "")
                plugin_name = fix_doc.get("plugin_name", "")

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

                assigned_team    = vuln_card.get("assigned_team") or fix_doc.get("assigned_team", "")
                assigned_members = fix_doc.get("assigned_team_members", [])
                mitigation_table = vuln_card.get("mitigation_table", [])
                artifacts_tools  = vuln_card.get("artifacts_tools")
                post_guide       = vuln_card.get("post_mitigation_troubleshooting_guide", [])

                # Deadline: exact same logic as adminregister.FixVulnerabilityStepsAPIView
                deadline = None
                _base_dt = vuln_card.get("created_at")
                if not isinstance(_base_dt, datetime):
                    _base_dt = datetime.now()

                # Find admin_id: UserDetail (team member's own admin) takes priority
                _admin_id_str = None
                try:
                    # Priority 1: team member's admin via UserDetail
                    if UserDetail:
                        _ud = UserDetail.objects.filter(email=request.user.email).first()
                        if _ud and _ud.admin:
                            _admin_id_str = str(_ud.admin.id)
                    # Priority 2: fix_doc.created_by fallback
                    if not _admin_id_str:
                        _created_by = fix_doc.get("created_by")
                        if _created_by:
                            _admin_id_str = str(_created_by)
                except Exception as _e:
                    logger.error(f"[UserFixSteps] admin_id lookup error: {_e}", exc_info=True)

                # Step 1: RiskCriteria via direct MongoDB (bypasses djongo ORM ForeignKey bug)
                try:
                    _rc_doc = db["risk_criteria_riskcriteria"].find_one(
                        {"admin_id": _admin_id_str},
                        sort=[("created_at", pymongo.DESCENDING)],
                    ) if _admin_id_str else None
                    if _rc_doc:
                        severity = (fix_doc.get("risk_factor") or "").strip().lower()
                        if severity.startswith("crit"):
                            _days = _parse_timeline_to_days(_rc_doc.get("critical", ""))
                        elif severity.startswith("high"):
                            _days = _parse_timeline_to_days(_rc_doc.get("high", ""))
                        elif severity.startswith("med"):
                            _days = _parse_timeline_to_days(_rc_doc.get("medium", ""))
                        elif severity.startswith("low"):
                            _days = _parse_timeline_to_days(_rc_doc.get("low", ""))
                        else:
                            _days = 0
                        if _days > 0:
                            deadline = (_base_dt + timedelta(days=_days)).strftime("%Y-%m-%d")
                except Exception as e:
                    logger.error(f"[UserFixSteps] Deadline error: {e}", exc_info=True)

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

                if not step_order:
                    step_order  = list(range(1, 7))
                    steps_dict  = {
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
                saved_steps = {
                    s["step_number"]: s
                    for s in steps_coll.find({"fix_vulnerability_id": fix_vuln_id})
                }
                steps              = []
                previous_completed = True

                for display_idx, step_num in enumerate(step_order, start=1):
                    step_meta      = steps_dict[step_num]
                    saved          = saved_steps.get(step_num)
                    current_status = saved.get("status", "pending") if saved else "pending"

                    is_locked  = not previous_completed and current_status != "completed"
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
                            {"user_id": m.get("user_id"), "name": m.get("name"), "email": m.get("email")}
                            for m in assigned_members
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
                next_step       = (completed_count + 1) if completed_count < total_steps else None

                return Response(
                    {
                        "message": "Steps fetched successfully",
                        "report_id": report_id,
                        "fix_vulnerability_id": fix_vuln_id,
                        "vulnerability_name": plugin_name,
                        "asset": host_name,
                        "severity": fix_doc.get("risk_factor", ""),
                        "operating_system": operating_system,
                        "assigned_team": assigned_team,
                        "deadline": deadline,
                        "artifacts_tools": artifacts_tools,
                        "post_mitigation_troubleshooting_guide": post_guide if isinstance(post_guide, list) else ([post_guide] if post_guide else []),
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
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def post(self, request, fix_vuln_id):
        try:
            user_id  = str(request.user.id)
            comment  = request.data.get("comment", "")
            step_status    = request.data.get("status", "completed")
            deadline       = request.data.get("deadline")
            assigned_member_id = request.data.get("assigned_member_id")

            with MongoContext() as db:
                fix_coll    = db[FIX_VULN_COLLECTION]
                steps_coll  = db[FIX_VULN_STEPS_COLLECTION]
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                if not fix_doc:
                    return Response(
                        {"detail": "Fix vulnerability not found or already closed"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                plugin_name = fix_doc.get("plugin_name", "")
                report_id   = fix_doc.get("report_id", "")
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
                step_name   = (
                    steps_dict[internal_step_number]["step_name"]
                    if internal_step_number in steps_dict
                    else self.DEFAULT_STEP_DESCRIPTIONS.get(internal_step_number, f"Step {display_step_number}")
                )

                update_fields = {
                    "status": step_status,
                    "step_name": step_name,
                    "comment": comment,
                    "updated_by": user_id,
                    "updated_at": datetime.utcnow(),
                }
                if deadline:
                    update_fields["deadline"] = deadline
                if assigned_member_id:
                    for member in fix_doc.get("assigned_team_members", []):
                        if member.get("user_id") == assigned_member_id:
                            update_fields["assigned_member"] = member
                            break

                steps_coll.update_one(
                    {"fix_vulnerability_id": fix_vuln_id, "step_number": step_number},
                    {
                        "$set": update_fields,
                        "$setOnInsert": {
                            "created_at": datetime.utcnow(),
                            "created_by": user_id,
                        },
                    },
                    upsert=True,
                )

                step_doc = steps_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_number,
                })
                step_id = str(step_doc["_id"]) if step_doc else ""

                completed_steps = steps_coll.count_documents({
                    "fix_vulnerability_id": fix_vuln_id,
                    "status": "completed",
                })

                if completed_steps >= total_steps:
                    closed_doc = fix_doc.copy()
                    closed_doc["fix_vulnerability_id"] = str(fix_doc["_id"])
                    closed_doc.pop("_id", None)
                    closed_doc.update({
                        "status": "closed",
                        "closed_at": datetime.utcnow(),
                        "closed_by": user_id,
                        "operating_system": host_os,
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

                    try:
                        from notifications.utils import create_notification
                        _vuln_name  = fix_doc.get("plugin_name", "")
                        _asset      = fix_doc.get("host_name", "")
                        _team       = fix_doc.get("assigned_team", "")
                        _admin_id   = fix_doc.get("admin_id", "") or fix_doc.get("created_by", "")
                        if _admin_id:
                            _n_title = f"Vulnerability Fixed: {_vuln_name[:80]}"
                            _n_msg = (
                                f"Vulnerability Closed: {_vuln_name} on {_asset} has been "
                                f"successfully remediated and closed. Team: {_team}."
                            )
                            _n_meta = {
                                "vulnerability_name":  _vuln_name,
                                "asset":               _asset,
                                "assigned_team":       _team,
                                "fix_vulnerability_id": fix_vuln_id,
                            }
                            create_notification(_admin_id, 'admin', 'vuln_closed', _n_title, _n_msg, _n_meta)
                            create_notification(_admin_id, 'user', 'vuln_closed', _n_title, _n_msg, _n_meta, recipient_email=request.user.email)
                    except Exception:
                        pass

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

                # next_step as sequential display number
                next_display_step = completed_steps + 1 if completed_steps < total_steps else None
                next_internal     = step_order[completed_steps] if step_order and completed_steps < len(step_order) else None
                next_step_name    = (
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

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# 5. FIX STEP FEEDBACK
# ─────────────────────────────────────────────────────────────────────────────

class UserFixStepFeedbackAPIView(APIView):
    """
    POST/GET /api/user/register/fix-vulnerability/<fix_vuln_id>/feedback/
    Same as adminregister — reads/writes to same fix_step_feedback collection.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    VALID_FIX_STATUSES = ["fixed", "partially_fixed", "not_fixed"]

    def post(self, request, fix_vuln_id):
        try:
            user_id          = str(request.user.id)
            step_number      = request.data.get("step_number")
            feedback_comment = request.data.get("feedback_comment", "").strip()
            fix_status       = request.data.get("fix_status", "").lower()

            if fix_status not in self.VALID_FIX_STATUSES:
                return Response(
                    {"detail": f"fix_status must be one of: {', '.join(self.VALID_FIX_STATUSES)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            with MongoContext() as db:
                fix_coll      = db[FIX_VULN_COLLECTION]
                closed_coll   = db[FIX_VULN_CLOSED_COLLECTION]
                feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]
                steps_coll    = db[FIX_VULN_STEPS_COLLECTION]

                fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                if not fix_doc:
                    fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                    if not fix_doc:
                        return Response(
                            {"detail": "Fix vulnerability not found"},
                            status=status.HTTP_404_NOT_FOUND
                        )

                # Determine actual total steps from mitigation_table
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

                existing = feedback_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_number
                })

                if existing:
                    feedback_coll.update_one(
                        {"_id": existing["_id"]},
                        {"$set": {
                            "feedback_comment": feedback_comment,
                            "fix_status": fix_status,
                            "updated_by": user_id,
                            "updated_at": datetime.utcnow(),
                        }}
                    )
                    return Response(
                        {
                            "message": "Feedback updated successfully",
                            "data": {
                                "feedback_id": str(existing["_id"]),
                                "fix_vulnerability_id": fix_vuln_id,
                                "step_number": step_number,
                                "feedback_comment": feedback_comment,
                                "fix_status": fix_status,
                                "updated_at": datetime.utcnow().isoformat(),
                            }
                        },
                        status=status.HTTP_200_OK
                    )

                feedback_doc = {
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_number,
                    "feedback_comment": feedback_comment,
                    "fix_status": fix_status,
                    "submitted_by": user_id,
                    "submitted_at": datetime.utcnow(),
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
                            "submitted_at": feedback_doc["submitted_at"].isoformat(),
                        }
                    },
                    status=status.HTTP_201_CREATED
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request, fix_vuln_id):
        try:
            with MongoContext() as db:
                fix_coll      = db[FIX_VULN_COLLECTION]
                closed_coll   = db[FIX_VULN_CLOSED_COLLECTION]
                feedback_coll = db[FIX_STEP_FEEDBACK_COLLECTION]

                fix_doc     = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                vuln_status = "open"

                if not fix_doc:
                    fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                    if not fix_doc:
                        return Response(
                            {"detail": "Fix vulnerability not found"},
                            status=status.HTTP_404_NOT_FOUND
                        )
                    vuln_status = "closed"

                feedback_list = [
                    {
                        "feedback_id": str(fb["_id"]),
                        "step_number": fb.get("step_number"),
                        "feedback_comment": fb.get("feedback_comment", ""),
                        "fix_status": fb.get("fix_status", ""),
                        "submitted_by": fb.get("submitted_by"),
                        "submitted_at": _normalize_iso(fb.get("submitted_at")),
                        "updated_at": _normalize_iso(fb.get("updated_at")),
                    }
                    for fb in feedback_coll.find(
                        {"fix_vulnerability_id": fix_vuln_id}
                    ).sort("step_number", 1)
                ]

                return Response(
                    {
                        "fix_vulnerability_id": fix_vuln_id,
                        "vulnerability_name": fix_doc.get("plugin_name", ""),
                        "asset": fix_doc.get("host_name", ""),
                        "status": vuln_status,
                        "feedback_count": len(feedback_list),
                        "feedback": feedback_list,
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# 6. FINAL FEEDBACK
# ─────────────────────────────────────────────────────────────────────────────

class UserFixVulnerabilityFinalFeedbackAPIView(APIView):
    """
    POST/GET /api/user/register/fix-vulnerability/<fix_vuln_id>/final-feedback/
    Only submittable after vulnerability is CLOSED (all steps done).
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    VALID_FIX_RESULTS = ["resolved", "partially_resolved", "not_resolved"]

    def post(self, request, fix_vuln_id):
        try:
            user_id          = str(request.user.id)
            feedback_comment = request.data.get("feedback_comment", "").strip()
            fix_result       = request.data.get("fix_result", "").lower()

            if not feedback_comment:
                return Response(
                    {"detail": "feedback_comment is required"},
                    status=status.HTTP_400_BAD_REQUEST
                )
            if fix_result not in self.VALID_FIX_RESULTS:
                return Response(
                    {"detail": f"fix_result must be one of: {', '.join(self.VALID_FIX_RESULTS)}"},
                    status=status.HTTP_400_BAD_REQUEST
                )

            with MongoContext() as db:
                fix_coll          = db[FIX_VULN_COLLECTION]
                closed_coll       = db[FIX_VULN_CLOSED_COLLECTION]
                steps_coll        = db[FIX_VULN_STEPS_COLLECTION]
                final_fb_coll     = db[FIX_FINAL_FEEDBACK_COLLECTION]

                open_vuln = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                if open_vuln:
                    return Response(
                        {
                            "detail": "Feedback can only be submitted after vulnerability is CLOSED",
                            "status": "open",
                            "message": "Please complete all steps first",
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                closed_vuln = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not closed_vuln:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                completed_steps = steps_coll.count_documents({
                    "fix_vulnerability_id": fix_vuln_id,
                    "status": "completed",
                })

                # Dynamic total_steps from mitigation_table (not hardcoded 6)
                plugin_name = closed_vuln.get("plugin_name", "")
                report_id   = closed_vuln.get("report_id", "")
                host_name   = closed_vuln.get("host_name", "")
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
                steps_dict, step_order = UserFixVulnerabilityStepsAPIView()._parse_mitigation_steps(mitigation_table)
                host_os = closed_vuln.get("operating_system", "") or "Windows"
                if step_order:
                    os_key = "linux" if host_os.lower() in ("linux", "unix") else "windows"
                    os_filtered = [s for s in step_order if steps_dict[s].get(os_key)]
                    if os_filtered:
                        step_order = os_filtered
                total_steps = len(step_order) if step_order else completed_steps

                if completed_steps < total_steps:
                    return Response(
                        {
                            "detail": f"All {total_steps} steps must be completed before submitting feedback. {total_steps - completed_steps} step(s) still pending.",
                            "completed_steps": completed_steps,
                            "pending_steps": total_steps - completed_steps,
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                existing = final_fb_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if existing:
                    final_fb_coll.update_one(
                        {"_id": existing["_id"]},
                        {"$set": {
                            "feedback_comment": feedback_comment,
                            "fix_result": fix_result,
                            "updated_by": user_id,
                            "updated_at": datetime.utcnow(),
                        }}
                    )
                    return Response(
                        {
                            "message": "Final feedback updated successfully",
                            "data": {
                                "feedback_id": str(existing["_id"]),
                                "fix_vulnerability_id": fix_vuln_id,
                                "feedback_comment": feedback_comment,
                                "fix_result": fix_result,
                                "updated_at": datetime.utcnow().isoformat(),
                            }
                        },
                        status=status.HTTP_200_OK
                    )

                feedback_doc = {
                    "fix_vulnerability_id": fix_vuln_id,
                    "vulnerability_name": closed_vuln.get("plugin_name", ""),
                    "host_name": closed_vuln.get("host_name", ""),
                    "severity": closed_vuln.get("risk_factor", ""),
                    "feedback_comment": feedback_comment,
                    "fix_result": fix_result,
                    "submitted_by": user_id,
                    "submitted_at": datetime.utcnow(),
                }
                result = final_fb_coll.insert_one(feedback_doc)

                return Response(
                    {
                        "message": "Final feedback submitted successfully",
                        "data": {
                            "feedback_id": str(result.inserted_id),
                            "fix_vulnerability_id": fix_vuln_id,
                            "vulnerability_name": closed_vuln.get("plugin_name", ""),
                            "host_name": closed_vuln.get("host_name", ""),
                            "severity": closed_vuln.get("risk_factor", ""),
                            "feedback_comment": feedback_comment,
                            "fix_result": fix_result,
                            "submitted_at": feedback_doc["submitted_at"].isoformat(),
                        }
                    },
                    status=status.HTTP_201_CREATED
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get(self, request, fix_vuln_id):
        try:
            with MongoContext() as db:
                fix_coll      = db[FIX_VULN_COLLECTION]
                closed_coll   = db[FIX_VULN_CLOSED_COLLECTION]
                final_fb_coll = db[FIX_FINAL_FEEDBACK_COLLECTION]

                open_vuln = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                if open_vuln:
                    return Response(
                        {
                            "fix_vulnerability_id": fix_vuln_id,
                            "status": "open",
                            "message": "Vulnerability is still open. No final feedback available.",
                            "final_feedback": None,
                        },
                        status=status.HTTP_200_OK
                    )

                closed_vuln = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not closed_vuln:
                    return Response(
                        {"detail": "Fix vulnerability not found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                feedback = final_fb_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                if not feedback:
                    return Response(
                        {
                            "fix_vulnerability_id": fix_vuln_id,
                            "vulnerability_name": closed_vuln.get("plugin_name", ""),
                            "host_name": closed_vuln.get("host_name", ""),
                            "severity": closed_vuln.get("risk_factor", ""),
                            "status": "closed",
                            "message": "No final feedback submitted yet",
                            "final_feedback": None,
                        },
                        status=status.HTTP_200_OK
                    )

                return Response(
                    {
                        "fix_vulnerability_id": fix_vuln_id,
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
                            "updated_at": _normalize_iso(feedback.get("updated_at")),
                        },
                    },
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─────────────────────────────────────────────────────────────────────────────
# 7. VULNERABILITY TIMELINE
# ─────────────────────────────────────────────────────────────────────────────

class UserVulnerabilityTimelineAPIView(APIView):
    """
    GET /api/user/register/fix-vulnerability/<fix_vuln_id>/timeline/
    Same as adminregister — reads from same collections.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vuln_id):
        try:
            user_id = str(request.user.id)

            with MongoContext() as db:
                fix_coll    = db[FIX_VULN_COLLECTION]
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

                fix_doc = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                if not fix_doc:
                    fix_doc = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
                    if not fix_doc:
                        return Response(
                            {"detail": "Fix vulnerability not found"},
                            status=status.HTTP_404_NOT_FOUND
                        )

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

                assigned_team   = vuln_card.get("assigned_team") or fix_doc.get("assigned_team", "")
                vuln_created_at = _normalize_iso(vuln_card.get("created_at"))

                # Deadline: exact same logic as adminregister.VulnerabilityTimelineAPIView
                deadline = None
                base_dt = vuln_card.get("created_at")
                if not isinstance(base_dt, datetime):
                    base_dt = datetime.now()

                # Find admin_id: UserDetail (team member's own admin) takes priority
                _admin_id_str = None
                try:
                    # Priority 1: team member's admin via UserDetail
                    if UserDetail:
                        _ud = UserDetail.objects.filter(email=request.user.email).first()
                        if _ud and _ud.admin:
                            _admin_id_str = str(_ud.admin.id)
                    # Priority 2: fix_doc.created_by fallback
                    if not _admin_id_str:
                        _created_by = fix_doc.get("created_by")
                        if _created_by:
                            _admin_id_str = str(_created_by)
                except Exception as _e:
                    logger.error(f"[UserTimeline] admin_id lookup error: {_e}", exc_info=True)

                # Step 1: RiskCriteria via direct MongoDB (bypasses djongo ORM ForeignKey bug)
                try:
                    _rc_doc = db["risk_criteria_riskcriteria"].find_one(
                        {"admin_id": _admin_id_str},
                        sort=[("created_at", pymongo.DESCENDING)],
                    ) if _admin_id_str else None
                    if _rc_doc:
                        severity = (fix_doc.get("risk_factor") or "").strip().lower()
                        if severity.startswith("crit"):
                            days = _parse_timeline_to_days(_rc_doc.get("critical", ""))
                        elif severity.startswith("high"):
                            days = _parse_timeline_to_days(_rc_doc.get("high", ""))
                        elif severity.startswith("med"):
                            days = _parse_timeline_to_days(_rc_doc.get("medium", ""))
                        elif severity.startswith("low"):
                            days = _parse_timeline_to_days(_rc_doc.get("low", ""))
                        else:
                            days = 0
                        if days > 0:
                            deadline = base_dt + timedelta(days=days)
                except Exception as e:
                    logger.error(f"[UserTimeline] Deadline error: {e}", exc_info=True)

                # Step 2: Stored deadline fallback (only proper ISO date, not duration strings)
                if not deadline:
                    _raw_deadline = vuln_card.get("deadline") or fix_doc.get("deadline")
                    if _raw_deadline:
                        try:
                            deadline = datetime.fromisoformat(str(_raw_deadline).replace("Z", "+00:00"))
                        except (ValueError, TypeError):
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

                timeline = [
                    {
                        "event": "Vulnerability identified",
                        "type": "vulnerability_identified",
                        "date": vuln_created_at,
                        "status": "done" if vuln_created_at else "pending",
                        "icon": "arrow",
                    },
                    {
                        "event": "Assigned to Team",
                        "type": "assigned_to_team",
                        "date": vuln_created_at,
                        "status": "done" if assigned_team else "pending",
                        "icon": "arrow",
                        "assigned_team": assigned_team,
                    },
                    {
                        "event": "Deadline",
                        "type": "deadline",
                        "date": _normalize_iso(deadline) if deadline else None,
                        "status": "scheduled",
                        "icon": "arrow",
                    },
                ]

                # Completed steps
                for step in db[FIX_VULN_STEPS_COLLECTION].find(
                    {"fix_vulnerability_id": fix_vuln_id, "status": "completed"}
                ).sort("step_number", 1):
                    step_num  = step.get("step_number")
                    step_date = _normalize_iso(step.get("updated_at") or step.get("created_at"))
                    timeline.append({
                        "event": f"Step {step_num} Done",
                        "type": "step_done",
                        "date": step_date,
                        "status": "done",
                        "icon": "check",
                        "step_number": step_num,
                    })

                # Support request
                support_req = db[SUPPORT_REQUEST_COLLECTION].find_one({
                    "vulnerability_id": fix_vuln_id,
                })
                if support_req:
                    timeline.append({
                        "event": "Exception Requested",
                        "type": "exception_requested",
                        "date": _normalize_iso(support_req.get("requested_at")),
                        "status": "pending",
                        "icon": "question",
                    })

                # Ticket
                ticket = db[TICKETS_COLLECTION].find_one({"fix_vulnerability_id": fix_vuln_id})
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
                    status=status.HTTP_200_OK,
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "unexpected error", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─── UserSupportRequestsByReportAPIView ──────────────────────────────────────

class UserSupportRequestsByReportAPIView(APIView):
    """
    GET  /api/user/register/support-requests/report/<report_id>/

    Returns all support requests for a given report that belong to
    the logged-in user's assigned teams (case-insensitive).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response(
                {"detail": "No team assigned to this user"},
                status=status.HTTP_403_FORBIDDEN,
            )
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            support_coll = db[SUPPORT_REQUEST_COLLECTION]

            cursor = support_coll.find(
                {"report_id": str(report_id)}
            ).sort("requested_at", -1)

            # Collect docs that pass team filter
            raw_docs = []
            for doc in cursor:
                doc_team = (doc.get("assigned_team") or "").strip().lower()
                if doc_team not in teams_lower_set:
                    continue
                raw_docs.append(doc)

            # Batch severity fallback map from fix_vulnerabilities.
            fix_coll = db[FIX_VULN_COLLECTION]
            object_ids = []
            for sdoc in raw_docs:
                raw_vid = str(sdoc.get("vulnerability_id") or "").strip()
                if not raw_vid:
                    continue
                try:
                    object_ids.append(ObjectId(raw_vid))
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

            fix_severity_by_id = {}
            if object_ids:
                for fdoc in fix_coll.find({"_id": {"$in": object_ids}}):
                    fid = str(fdoc.get("_id"))
                    sev = (fdoc.get("risk_factor") or fdoc.get("severity") or "").strip().title()
                    fix_severity_by_id[fid] = sev

        # ── Batch-resolve requester names from UserDetail ────────────────────
        # Gather all unique user_ids (user_id preferred, fallback admin_id)
        id_set = set()
        for doc in raw_docs:
            uid = doc.get("user_id") or doc.get("admin_id")
            if uid:
                id_set.add(str(uid))

        # Build id → name map using assigned_team_members embedded in each doc
        # (already contains user_id + name), supplemented by UserDetail lookup
        id_to_name = {}

        # Pass 1: extract from embedded assigned_team_members (no DB hit)
        for doc in raw_docs:
            for member in doc.get("assigned_team_members", []):
                mid = str(member.get("user_id") or "")
                mname = (member.get("name") or "").strip()
                if mid and mname and mid not in id_to_name:
                    id_to_name[mid] = mname

        # Pass 2: for any IDs still missing, query UserDetail
        missing_ids = id_set - set(id_to_name.keys())
        if missing_ids and UserDetail:
            for ud in UserDetail.objects.filter(
                admin_id__in=missing_ids
            ).only("admin_id", "first_name", "last_name"):
                uid_str = str(ud.admin_id)
                full = f"{ud.first_name} {ud.last_name}".strip()
                if full:
                    id_to_name[uid_str] = full

        # Build closed vulnerability ID set from fix_vulnerabilities_closed
        all_vuln_ids = [
            str(d.get("vulnerability_id") or "").strip()
            for d in raw_docs
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
        for doc in raw_docs:
            uid = str(doc.get("user_id") or doc.get("admin_id") or "")
            requester_name = id_to_name.get(uid) or _resolve_requester(doc)
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
                "_id":                   str(doc.get("_id")),
                "report_id":             doc.get("report_id"),
                "vulnerability_id":      doc.get("vulnerability_id"),
                "vul_name":              doc.get("vul_name"),
                "host_name":             doc.get("host_name"),
                "severity":              severity,
                "assigned_team":         doc.get("assigned_team"),
                "assigned_team_members": doc.get("assigned_team_members", []),
                "step_requested":        doc.get("step_requested"),
                "description":           doc.get("description"),
                "status":                effective_status,
                "requested_by":          requester_name,
                "requested_at":          _normalize_iso(doc.get("requested_at")),
            })

        return Response(
            {
                "message": "Support requests fetched successfully",
                "report_id": report_id,
                "count": len(results),
                "results": results,
            },
            status=status.HTTP_200_OK,
        )


class UserSupportRequestsByHostAPIView(APIView):
    """
    GET  /api/user/register/support-requests/host/<host_name>/

    Returns all support requests for a given asset (host_name) that belong to
    the logged-in user's assigned teams (case-insensitive).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, host_name):
        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response(
                {"detail": "No team assigned to this user"},
                status=status.HTTP_403_FORBIDDEN,
            )
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            support_coll = db[SUPPORT_REQUEST_COLLECTION]

            cursor = support_coll.find(
                {"host_name": host_name}
            ).sort("requested_at", -1)

            results = []
            for doc in cursor:
                doc_team = (doc.get("assigned_team") or "").strip().lower()
                if doc_team not in teams_lower_set:
                    continue
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
                "message": "Support requests fetched successfully",
                "host_name": host_name,
                "count": len(results),
                "results": results,
            },
            status=status.HTTP_200_OK,
        )


# ─── Inline serializer ───────────────────────────────────────────────────────
from rest_framework import serializers as drf_serializers

class _RaiseSupportRequestSerializer(drf_serializers.Serializer):
    step_number  = drf_serializers.IntegerField(min_value=1)
    description  = drf_serializers.CharField()


# ─── UserRaiseSupportRequestAPIView ──────────────────────────────────────────

class UserRaiseSupportRequestAPIView(APIView):
    """
    POST  /api/user/register/fix-vulnerability/<fix_vuln_id>/raise-support-request/

    Raise a support request for a fix vulnerability.
    Team validation: the logged-in user must belong to the team assigned
    to that vulnerability (case-insensitive match).
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request, fix_vuln_id):
        serializer = _RaiseSupportRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        step_number = serializer.validated_data["step_number"]
        description = serializer.validated_data["description"]
        user_id     = str(request.user.id)

        # Get user's teams
        teams, admin_user = _get_user_context(request.user.email)
        if not teams:
            return Response(
                {"detail": "No team assigned to this user"},
                status=status.HTTP_403_FORBIDDEN,
            )
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            fix_coll     = db[FIX_VULN_COLLECTION]
            closed_coll  = db[FIX_VULN_CLOSED_COLLECTION]
            support_coll = db[SUPPORT_REQUEST_COLLECTION]

            # ── Fetch fix vulnerability (open or closed) ─────────────────────
            try:
                vuln = fix_coll.find_one({"_id": ObjectId(fix_vuln_id)})
                if not vuln:
                    vuln = closed_coll.find_one({"fix_vulnerability_id": fix_vuln_id})
            except Exception:
                return Response(
                    {"detail": "Invalid vulnerability ID"},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not vuln:
                return Response(
                    {"detail": "Vulnerability not found"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # ── Team validation ──────────────────────────────────────────────
            assigned_team = (vuln.get("assigned_team") or "").strip()
            if assigned_team.lower() not in teams_lower_set:
                return Response(
                    {"detail": "You do not have permission to raise a support request for this vulnerability"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # ── Duplicate check: one request per step per user ───────────────
            existing = support_coll.find_one({
                "vulnerability_id": fix_vuln_id,
                "user_id":          user_id,
                "step_number":      step_number,
            })
            if existing:
                return Response(
                    {"detail": f"Support request already raised for step {step_number}"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # ── Save support request ─────────────────────────────────────────
            report_id = vuln.get("report_id", "")
            support_doc = {
                "report_id":             str(report_id),
                "user_id":               user_id,
                "admin_id":              str(admin_user.id) if admin_user else None,
                "vulnerability_id":      fix_vuln_id,
                "vul_name":              vuln.get("plugin_name"),
                "host_name":             vuln.get("host_name"),
                "assigned_team":         assigned_team,
                "assigned_team_members": vuln.get("assigned_team_members", []),
                "step_number":           step_number,
                "description":           description,
                "status":                "open",
                "requested_by":          request.user.email,
                "requested_at":          datetime.utcnow(),
            }
            result = support_coll.insert_one(support_doc)
            support_doc["_id"] = str(result.inserted_id)
            support_doc["requested_at"] = _normalize_iso(support_doc["requested_at"])

            try:
                import logging as _log
                from notifications.utils import create_notification
                _n_meta = {
                    "support_request_id": support_doc["_id"],
                    "vulnerability_id":   fix_vuln_id,
                    "vul_name":           support_doc.get("vul_name"),
                    "host_name":          support_doc.get("host_name"),
                    "assigned_team":      assigned_team,
                    "step_number":        step_number,
                }
                if admin_user:
                    _admin_title = f"New Support Request: {support_doc.get('vul_name', '')}"
                    _admin_msg   = (
                        f"A support request has been raised for vulnerability "
                        f"'{support_doc.get('vul_name')}' on {support_doc.get('host_name')} "
                        f"by {request.user.email}. Team: {assigned_team}."
                    )
                    create_notification(admin_user, 'admin', 'support_request_created', _admin_title, _admin_msg, _n_meta)

                    _user_title = f"Support Request Submitted: {support_doc.get('vul_name', '')}"
                    _user_msg   = (
                        f"Your support request for '{support_doc.get('vul_name')}' on "
                        f"{support_doc.get('host_name')} (Step {step_number}) has been submitted successfully."
                    )
                    create_notification(admin_user, 'user', 'support_request_received', _user_title, _user_msg, _n_meta, recipient_email=request.user.email)
                else:
                    _log.getLogger(__name__).warning("support_request notification skipped: admin_user is None for user %s", request.user.email)
            except Exception as _e:
                import logging as _log
                _log.getLogger(__name__).error("support_request notification failed: %s", _e, exc_info=True)

            return Response(
                {
                    "message": "Support request raised successfully",
                    "data": support_doc,
                },
                status=status.HTTP_201_CREATED,
            )


# ─── UserRaiseSupportRequestByVulnerabilityAPIView ────────────────────────────

class UserRaiseSupportRequestByVulnerabilityAPIView(APIView):
    """
    GET  /api/user/register/fix-vulnerability/<fix_vuln_id>/raise-support-request/

    Check whether a support request already exists for this vulnerability
    raised by the logged-in user.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vuln_id):
        user_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db[SUPPORT_REQUEST_COLLECTION]

            cursor = support_coll.find({
                "vulnerability_id": fix_vuln_id,
                "user_id":          user_id,
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
                "vulnerability_id": fix_vuln_id,
                "count": len(results),
                "results": results,
            },
            status=status.HTTP_200_OK,
        )


# ═══════════════════════════════════════════════════════════════════════════════
# TICKET VIEWS — team-filtered equivalents of adminregister ticket endpoints
# ═══════════════════════════════════════════════════════════════════════════════

class _CreateTicketSerializer(drf_serializers.Serializer):
    category    = drf_serializers.CharField()
    subject     = drf_serializers.CharField()
    description = drf_serializers.CharField()


def _ticket_row(doc, fix_doc):
    """Serialize one ticket document for list responses."""
    return {
        "_id":                   str(doc.get("_id")),
        "report_id":             doc.get("report_id"),
        "fix_vulnerability_id":  doc.get("fix_vulnerability_id"),
        "host_name":             doc.get("host_name"),
        "plugin_name":           doc.get("plugin_name"),
        "category":              doc.get("category"),
        "subject":               doc.get("subject"),
        "description":           doc.get("description"),
        "status":                doc.get("status", "open"),
        "created_at":            _normalize_iso(doc.get("created_at")),
        "closed_at":             _normalize_iso(doc.get("closed_at")),
        "close_comment":         doc.get("close_comment"),
        "assigned_team":         fix_doc.get("assigned_team", ""),
        "assigned_team_members": fix_doc.get("assigned_team_members", []),
    }


def _batch_fix_map(db, tickets):
    """Return {fix_vuln_id_str: fix_doc} for all tickets in list."""
    ids = []
    for doc in tickets:
        fid = doc.get("fix_vulnerability_id")
        if fid:
            try:
                ids.append(ObjectId(fid))
            except Exception as e:
                logger.warning("Suppressed error: %s", e)
    fix_map = {}
    if ids:
        for fix_doc in db[FIX_VULN_COLLECTION].find({"_id": {"$in": ids}}):
            fix_map[str(fix_doc["_id"])] = fix_doc
    return fix_map


# ─── 1. Create Ticket ─────────────────────────────────────────────────────────

class UserCreateTicketAPIView(APIView):
    """
    POST  /api/user/register/tickets/report/<report_id>/fix/<fix_vuln_id>/create/

    Create a ticket for a fix vulnerability.
    Team validation: vuln must be assigned to the logged-in user's team.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [JSONParser]

    def post(self, request, report_id, fix_vulnerability_id):
        serializer = _CreateTicketSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        category    = serializer.validated_data["category"]
        subject     = serializer.validated_data["subject"]
        description = serializer.validated_data["description"]
        user_id     = str(request.user.id)

        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response(
                {"detail": "No team assigned to this user"},
                status=status.HTTP_403_FORBIDDEN,
            )
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            fix_coll    = db[FIX_VULN_COLLECTION]
            ticket_coll = db[TICKETS_COLLECTION]

            # Fetch fix vulnerability
            try:
                fix_vuln = fix_coll.find_one({
                    "_id": ObjectId(fix_vulnerability_id),
                    "report_id": report_id,
                })
            except Exception:
                return Response(
                    {"detail": "Invalid fix_vulnerability_id"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            if not fix_vuln:
                return Response(
                    {"detail": "Fix vulnerability not found for this report"},
                    status=status.HTTP_404_NOT_FOUND,
                )

            # Team validation
            assigned_team = (fix_vuln.get("assigned_team") or "").strip()
            if assigned_team.lower() not in teams_lower_set:
                return Response(
                    {"detail": "You do not have permission to create a ticket for this vulnerability"},
                    status=status.HTTP_403_FORBIDDEN,
                )

            # Duplicate check
            existing = ticket_coll.find_one({
                "fix_vulnerability_id": fix_vulnerability_id,
                "user_id": user_id,
            })
            if existing:
                return Response(
                    {"detail": "Ticket already created for this vulnerability"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Create ticket
            ticket_doc = {
                "fix_vulnerability_id": fix_vulnerability_id,
                "report_id":            report_id,
                "user_id":              user_id,
                "host_name":            fix_vuln.get("host_name"),
                "plugin_name":          fix_vuln.get("plugin_name"),
                "category":             category,
                "subject":              subject,
                "description":          description,
                "status":               "open",
                "created_at":           datetime.utcnow(),
            }
            result = ticket_coll.insert_one(ticket_doc)
            ticket_doc["_id"]        = str(result.inserted_id)
            ticket_doc["created_at"] = _normalize_iso(ticket_doc["created_at"])

            return Response(
                {"message": "Ticket created successfully", "data": ticket_doc},
                status=status.HTTP_201_CREATED,
            )


# ─── 2. All Tickets by Report ─────────────────────────────────────────────────

class UserTicketByReportAPIView(APIView):
    """
    GET  /api/user/register/tickets/report/<report_id>/

    All tickets for a report whose fix-vuln is assigned to the user's team.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response({"detail": "No team assigned"}, status=status.HTTP_403_FORBIDDEN)
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]
            tickets = list(ticket_coll.find({"report_id": report_id}).sort("created_at", -1))
            fix_map = _batch_fix_map(db, tickets)

        results = []
        for doc in tickets:
            fix_doc = fix_map.get(doc.get("fix_vulnerability_id"), {})
            if (fix_doc.get("assigned_team") or "").strip().lower() not in teams_lower_set:
                continue
            results.append(_ticket_row(doc, fix_doc))

        return Response(
            {"message": "Tickets fetched successfully", "report_id": report_id,
             "count": len(results), "results": results},
            status=status.HTTP_200_OK,
        )


# ─── 3. Open Tickets ──────────────────────────────────────────────────────────

class UserTicketOpenListAPIView(APIView):
    """
    GET  /api/user/register/reports/<report_id>/tickets/open/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response({"detail": "No team assigned"}, status=status.HTTP_403_FORBIDDEN)
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]
            fix_coll    = db[FIX_VULN_COLLECTION]

            tickets = list(ticket_coll.find(
                {"report_id": report_id, "status": "open"}
            ).sort("created_at", -1))

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

            fix_map = _batch_fix_map(db, tickets)

        results = []
        for doc in tickets:
            fid = doc.get("fix_vulnerability_id")
            if fid in stale_ids:
                continue
            fix_doc = fix_map.get(fid, {})
            # Team filter — only show tickets for user's teams
            if (fix_doc.get("assigned_team") or "").strip().lower() not in teams_lower_set:
                continue
            results.append(_ticket_row(doc, fix_doc))

        return Response(
            {"message": "Open tickets fetched successfully", "report_id": report_id,
             "status": "open", "count": len(results), "results": results},
            status=status.HTTP_200_OK,
        )


# ─── 4. Closed Tickets ────────────────────────────────────────────────────────

class UserTicketClosedListAPIView(APIView):
    """
    GET  /api/user/register/reports/<report_id>/tickets/closed/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, report_id):
        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response({"detail": "No team assigned"}, status=status.HTTP_403_FORBIDDEN)
        teams_lower_set = {t.lower() for t in teams}

        with MongoContext() as db:
            ticket_coll = db[TICKETS_COLLECTION]
            closed_coll = db[FIX_VULN_CLOSED_COLLECTION]

            # Get ALL tickets for this report (any status)
            all_tickets = list(ticket_coll.find({"report_id": report_id}))

            if not all_tickets:
                return Response(
                    {"message": "Closed tickets fetched successfully", "report_id": report_id,
                     "status": "closed", "count": 0, "results": []},
                    status=status.HTTP_200_OK,
                )

            all_fix_ids = [
                doc.get("fix_vulnerability_id")
                for doc in all_tickets
                if doc.get("fix_vulnerability_id")
            ]

            # Check which fix_vuln_ids are in fix_vulnerabilities_closed
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
            # Team filter
            if (fix_doc.get("assigned_team") or "").strip().lower() not in teams_lower_set:
                continue
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
                "created_at":            _normalize_iso(doc.get("created_at")),
                "closed_at":             _normalize_iso(doc.get("closed_at")),
                "close_comment":         doc.get("close_comment"),
                "assigned_team":         fix_doc.get("assigned_team", ""),
                "assigned_team_members": fix_doc.get("assigned_team_members", []),
            })

        results.sort(key=lambda x: x.get("closed_at") or "", reverse=True)

        return Response(
            {"message": "Closed tickets fetched successfully", "report_id": report_id,
             "status": "closed", "count": len(results), "results": results},
            status=status.HTTP_200_OK,
        )


# ─── 5. Ticket Detail ─────────────────────────────────────────────────────────

class UserTicketDetailAPIView(APIView):
    """
    GET  /api/user/register/tickets/fix/<fix_vuln_id>/ticket/<ticket_id>/

    Fetch a single ticket. Team ownership is validated via fix_vuln.assigned_team.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, fix_vulnerability_id, ticket_id):
        teams, _admin = _get_user_context(request.user.email)
        if not teams:
            return Response({"detail": "No team assigned"}, status=status.HTTP_403_FORBIDDEN)
        teams_lower_set = {t.lower() for t in teams}

        try:
            ticket_obj_id = ObjectId(ticket_id)
        except Exception:
            return Response({"detail": "Invalid ticket_id"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            fix_obj_id = ObjectId(fix_vulnerability_id)
        except Exception:
            return Response({"detail": "Invalid fix_vulnerability_id"}, status=status.HTTP_400_BAD_REQUEST)

        with MongoContext() as db:
            ticket = db[TICKETS_COLLECTION].find_one({
                "_id": ticket_obj_id,
                "fix_vulnerability_id": fix_vulnerability_id,
            })

            if not ticket:
                return Response({"detail": "Ticket not found"}, status=status.HTTP_404_NOT_FOUND)

            fix_doc = db[FIX_VULN_COLLECTION].find_one({"_id": fix_obj_id}) or {}

        # Team validation
        assigned_team = (fix_doc.get("assigned_team") or "").strip()
        if assigned_team.lower() not in teams_lower_set:
            return Response(
                {"detail": "You do not have permission to view this ticket"},
                status=status.HTTP_403_FORBIDDEN,
            )

        return Response(
            {
                "message": "Ticket fetched successfully",
                "data": {
                    "_id":                   str(ticket["_id"]),
                    "report_id":             ticket.get("report_id"),
                    "fix_vulnerability_id":  ticket.get("fix_vulnerability_id"),
                    "host_name":             ticket.get("host_name"),
                    "plugin_name":           ticket.get("plugin_name"),
                    "severity":              fix_doc.get("risk_factor", ""),
                    "category":              ticket.get("category"),
                    "subject":               ticket.get("subject"),
                    "description":           ticket.get("description"),
                    "status":                ticket.get("status"),
                    "created_at":            _normalize_iso(ticket.get("created_at")),
                    "closed_at":             _normalize_iso(ticket.get("closed_at")),
                    "close_comment":         ticket.get("close_comment"),
                    "assigned_team":         assigned_team,
                    "assigned_team_members": fix_doc.get("assigned_team_members", []),
                },
            },
            status=status.HTTP_200_OK,
        )


class UserClosedVulnerabilitiesAPIView(APIView):
    """
    Returns all closed vulnerabilities for the logged-in member's teams.

    GET /api/user/register/closed-vulns/
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            # Step 1: Get member teams + admin
            teams, admin_user = _get_user_context(request.user.email)
            if not teams:
                return Response(
                    {"detail": "No teams assigned to this member."},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            if not admin_user:
                return Response(
                    {"detail": "Member profile not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", None)

            with MongoContext() as db:
                # Step 2: Get latest nessus report for admin
                latest_doc = _load_latest_report(db, admin_id, admin_email)
                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin."},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))

                # Build host -> OS map from nessus report (fallback for old records)
                host_os_map = {}
                for h in latest_doc.get("vulnerabilities_by_host", []):
                    h_name = h.get("host_name") or h.get("host") or ""
                    host_info = h.get("host_information") or {}
                    os_raw = (
                        host_info.get("OS")
                        or host_info.get("operating-system")
                        or host_info.get("operating_system")
                        or host_info.get("os")
                        or ""
                    ).strip()
                    if h_name and os_raw:
                        os_lower = os_raw.lower()
                        if "windows" in os_lower:
                            host_os_map[h_name] = "Windows"
                        elif "linux" in os_lower or "unix" in os_lower:
                            host_os_map[h_name] = "Linux"
                        else:
                            host_os_map[h_name] = os_raw

                # Step 3: Query fix_vulnerabilities_closed filtered by member's teams
                closed_cursor = db[FIX_VULN_CLOSED_COLLECTION].find(
                    {
                        "report_id":     report_id,
                        "assigned_team": {"$in": teams},
                    },
                    sort=[("closed_at", pymongo.DESCENDING)],
                )

                results = []
                for doc in closed_cursor:
                    host_name = doc.get("host_name", "")
                    # Use stored OS first; fall back to nessus host_information; default Windows
                    os_value = doc.get("operating_system", "") or host_os_map.get(host_name, "") or "Windows"
                    results.append({
                        "fix_vulnerability_id": doc.get("fix_vulnerability_id", str(doc.get("_id", ""))),
                        "plugin_name":          doc.get("plugin_name", ""),
                        "host_name":            host_name,
                        "os":                   os_value,
                        "port":                 doc.get("port", ""),
                        "risk_factor":          doc.get("risk_factor", ""),
                        "assigned_team":        doc.get("assigned_team", ""),
                        "created_at":           _normalize_iso(doc.get("created_at")),
                        "closed_at":            _normalize_iso(doc.get("closed_at")),
                        "closed_by":            doc.get("closed_by", ""),
                    })

                return Response(
                    {
                        "report_id":    report_id,
                        "member_teams": teams,
                        "total_closed": len(results),
                        "closed_vulnerabilities": results,
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
