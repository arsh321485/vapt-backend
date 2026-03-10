from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.parsers import JSONParser
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
from bson import ObjectId
import pymongo
import uuid
import re

from vaptfix.mongo_client import MongoContext

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
    detail = UserDetail.objects.filter(email=user_email).first()
    if not detail:
        return [], None
    teams = detail.Member_role if isinstance(detail.Member_role, list) else []
    if not teams and detail.team_name:
        teams = [detail.team_name]
    return teams, detail.admin


def _normalize_teams(teams):
    """Lowercase map for case-insensitive team matching."""
    return {t.lower(): t for t in teams}


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
                            "detail": "Cannot create fix — vulnerability is already Closed",
                            "fix_vulnerability_id": existing_closed.get("fix_vulnerability_id", ""),
                            "plugin_name": plugin_name_req,
                            "status": "closed",
                        },
                        status=status.HTTP_400_BAD_REQUEST
                    )

                # Duplicate check
                existing_fix = fix_coll.find_one({
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "id": id_req,
                })
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
                except Exception:
                    pass

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

    def _parse_mitigation_steps(self, mitigation_table):
        META_KEYS = {"step_no", "step_name", "criticality", "effort_estimate", "operating_system"}
        steps_dict = {}
        step_order  = []

        for row in mitigation_table:
            try:
                step_num = int(row.get("step_no", 0))
            except (ValueError, TypeError):
                continue
            if step_num <= 0:
                continue

            os_raw = (row.get("operating_system") or "").strip().lower()
            os_key = "linux" if "linux" in os_raw else "windows"
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
                deadline         = vuln_card.get("deadline")
                artifacts_tools  = vuln_card.get("artifacts_tools")
                post_guide       = vuln_card.get("post_mitigation_troubleshooting_guide", [])

                steps_dict, step_order = self._parse_mitigation_steps(mitigation_table)

                # Detect host OS: ?os= query param overrides nessus detection
                os_param = request.query_params.get("os", "").strip().lower()
                if os_param in ("windows", "linux"):
                    operating_system = "Windows" if os_param == "windows" else "Linux"
                else:
                    operating_system = self._get_host_os(db, report_id, host_name) or "Windows"

                if not step_order:
                    step_order  = list(range(1, 7))
                    steps_dict  = {
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

                # DEBUG: collect host_information to diagnose OS detection
                _debug_host_info = {}
                _nessus_doc = db[NESSUS_COLLECTION].find_one({"report_id": str(report_id)})
                if _nessus_doc:
                    _host_name_lower = (host_name or "").strip().lower()
                    for _h in _nessus_doc.get("vulnerabilities_by_host", []):
                        _h_name = (_h.get("host_name") or _h.get("host") or "").strip().lower()
                        if _h_name == _host_name_lower:
                            _debug_host_info = _h.get("host_information", {})
                            break

                return Response(
                    {
                        "message": "Steps fetched successfully",
                        "report_id": report_id,
                        "fix_vulnerability_id": fix_vuln_id,
                        "vulnerability_name": plugin_name,
                        "asset": host_name,
                        "severity": fix_doc.get("risk_factor", ""),
                        "operating_system": operating_system,
                        "debug_host_info": _debug_host_info,
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

                # OS-based step filtering: ?os= query param OR body "os" OR nessus detection
                os_param = (
                    request.query_params.get("os", "")
                    or request.data.get("os", "")
                ).strip().lower()
                if os_param in ("windows", "linux"):
                    host_os = "Windows" if os_param == "windows" else "Linux"
                else:
                    host_os = self._get_host_os(db, report_id, host_name) or "Windows"

                if host_os and step_order:
                    os_key = "linux" if host_os.lower() in ("linux", "unix") else "windows"
                    os_filtered = [s for s in step_order if steps_dict[s].get(os_key)]
                    if os_filtered:
                        step_order = os_filtered

                total_steps = len(step_order) if step_order else 6

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
                    })
                    closed_coll.insert_one(closed_doc)
                    fix_coll.delete_one({"_id": ObjectId(fix_vuln_id)})

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

                step_doc = steps_coll.find_one({
                    "fix_vulnerability_id": fix_vuln_id,
                    "step_number": step_number
                })
                if not step_doc:
                    return Response(
                        {"detail": f"Step {step_number} does not exist for this vulnerability"},
                        status=status.HTTP_404_NOT_FOUND
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
                if completed_steps < 6:
                    return Response(
                        {
                            "detail": f"All 6 steps must be completed before submitting feedback. {6 - completed_steps} step(s) still pending.",
                            "completed_steps": completed_steps,
                            "pending_steps": 6 - completed_steps,
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
                deadline        = vuln_card.get("deadline")

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
