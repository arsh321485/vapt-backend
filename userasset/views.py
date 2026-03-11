from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from urllib.parse import unquote
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
from django.utils import timezone

from .serializers import UserAssetSerializer, UserAssetVulnSerializer
from vaptfix.mongo_client import MongoContext

NESSUS_COLLECTION          = "nessus_reports"
VULN_CARD_COLLECTION       = "vulnerability_cards"
HOLD_COLLECTION            = "hold_assets"
FIX_VULN_COLLECTION        = "fix_vulnerabilities"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
DELETED_ASSETS_COLLECTION  = "deleted_assets"
SUPPORT_REQUEST_COLLECTION = "support_requests"

try:
    from users_details.models import UserDetail
except Exception:
    UserDetail = None


# ─── Helpers ─────────────────────────────────────────────────────────────────

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
    Returns (team_plugins_set, plugin_team_map) from vulnerability_cards.
    Only returns plugins assigned to the user's teams.
    """
    team_plugins = set()
    plugin_team_map = {}
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


def _validate_team_access(db, report_id, host_name, teams_lower):
    """
    Check that the user's team has at least one vulnerability assigned
    for the given host in the given report.
    Returns (has_access, doc, error_response)
    """
    coll = db[NESSUS_COLLECTION]
    doc = coll.find_one({"report_id": str(report_id)})
    if not doc:
        return False, None, Response(
            {"detail": "Report not found"},
            status=status.HTTP_404_NOT_FOUND
        )

    team_plugins, _ = _get_team_plugin_names(db, report_id, teams_lower)

    # Find host entry
    host_entry = None
    for h in (doc.get("vulnerabilities_by_host") or []):
        hn = (h.get("host_name") or h.get("host") or "").strip()
        if hn == host_name:
            host_entry = h
            break

    if not host_entry:
        return False, doc, Response(
            {"detail": "Asset not found in report"},
            status=status.HTTP_404_NOT_FOUND
        )

    # Check if any vulnerability belongs to user's team
    has_team_vuln = any(
        (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
        for v in host_entry.get("vulnerabilities", [])
    )

    if not has_team_vuln:
        return False, doc, Response(
            {"detail": "Access denied. This asset has no vulnerabilities assigned to your team."},
            status=status.HTTP_403_FORBIDDEN
        )

    return True, doc, None


def _iso(v):
    if not v:
        return None
    if isinstance(v, datetime):
        if is_naive(v):
            v = make_aware(v)
        return v.isoformat()
    return str(v)


def _join_description(vuln):
    pts = vuln.get("description_points") or []
    if isinstance(pts, (list, tuple)) and pts:
        return " ".join([str(p).strip() for p in pts if p is not None and str(p).strip()])
    return (vuln.get("description") or vuln.get("synopsis") or "").strip()


def _compute_total_assets(db, report_id, team_plugins=None):
    """
    Returns total asset count for a report.
    If team_plugins is provided, counts only assets that have
    at least one vulnerability assigned to the user's team(s).
    """
    coll = db[NESSUS_COLLECTION]
    doc  = coll.find_one({"report_id": str(report_id)}, {"vulnerabilities_by_host": 1})
    if not doc:
        return 0

    if not team_plugins:
        return len(doc.get("vulnerabilities_by_host", []))

    count = 0
    for host in doc.get("vulnerabilities_by_host", []):
        has_team_vuln = any(
            (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
            for v in host.get("vulnerabilities", [])
        )
        if has_team_vuln:
            count += 1
    return count


def _severity_counts(vulns):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for v in vulns:
        risk = (v.get("risk_factor") or v.get("severity") or "").lower()
        if risk.startswith("crit"):
            counts["critical"] += 1
        elif risk.startswith("high"):
            counts["high"] += 1
        elif risk.startswith("med"):
            counts["medium"] += 1
        elif risk.startswith("low"):
            counts["low"] += 1
    return counts


# ─── 1. Assets list (latest report, team-filtered) ───────────────────────────

class UserAssetsAPIView(APIView):
    """
    GET /api/user/asset/assets/

    Returns assets from the admin's latest report filtered to
    only those that have ≥1 vulnerability assigned to the user's team(s).
    Vulnerability counts are also team-filtered.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team. Ask your admin to assign you a team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)
            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", None)
            search_q    = (request.query_params.get("q") or "").strip().lower()

            with MongoContext() as db:
                doc = _load_latest_report(db, admin_id, admin_email)

                if not doc:
                    return Response({
                        "report_id": None,
                        "member_type": None,
                        "total_assets": 0,
                        "assets": [],
                        "message": "No reports found for your admin account"
                    }, status=status.HTTP_200_OK)

                report_id   = doc.get("report_id") or str(doc.get("_id", ""))
                uploaded_at = doc.get("uploaded_at")
                member_type = doc.get("member_type")

                team_plugins, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)

                assets = {}
                for host in doc.get("vulnerabilities_by_host", []):
                    host_name = (host.get("host_name") or "").strip()
                    if not host_name:
                        continue
                    if search_q and search_q not in host_name.lower():
                        continue

                    team_vulns = [
                        v for v in host.get("vulnerabilities", [])
                        if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                    ]
                    if not team_vulns:
                        continue

                    if host_name not in assets:
                        assets[host_name] = {
                            "asset": host_name,
                            "first_seen": uploaded_at,
                            "last_seen": uploaded_at,
                            "member_type": member_type,
                            "total_vulnerabilities": 0,
                            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                            "host_information": host.get("host_information") or {},
                            "assigned_teams": list({
                                plugin_team_map[v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""]
                                for v in team_vulns
                                if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in plugin_team_map
                            })
                        }

                    entry = assets[host_name]
                    for v in team_vulns:
                        entry["total_vulnerabilities"] += 1
                        risk = (v.get("risk_factor") or v.get("severity") or "").lower()
                        if risk.startswith("crit"):
                            entry["severity_counts"]["critical"] += 1
                        elif risk.startswith("high"):
                            entry["severity_counts"]["high"] += 1
                        elif risk.startswith("med"):
                            entry["severity_counts"]["medium"] += 1
                        elif risk.startswith("low"):
                            entry["severity_counts"]["low"] += 1

                final = [
                    {
                        "asset": a["asset"],
                        "member_type": a["member_type"],
                        "first_seen": _iso(a["first_seen"]),
                        "last_seen": _iso(a["last_seen"]),
                        "total_vulnerabilities": a["total_vulnerabilities"],
                        "severity_counts": a["severity_counts"],
                        "host_information": a["host_information"],
                        "assigned_teams": a.get("assigned_teams", []),
                    }
                    for a in assets.values()
                ]

                serializer = UserAssetSerializer(final, many=True)
                return Response({
                    "report_id": report_id,
                    "member_type": member_type,
                    "teams": teams,
                    "total_assets": len(final),
                    "assets": serializer.data
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 2. Hold-list (latest report, team-filtered) ─────────────────────────────

class UserHoldAssetsAPIView(APIView):
    """
    GET /api/user/asset/assets/hold-list/

    Returns held assets from admin's latest report.
    Only held assets whose host has ≥1 team-assigned vulnerability are shown.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)
            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", None)

            with MongoContext() as db:
                doc = _load_latest_report(db, admin_id, admin_email)
                if not doc:
                    return Response({
                        "report_id": None,
                        "count": 0,
                        "assets": [],
                        "message": "No reports found for your admin account"
                    }, status=status.HTTP_200_OK)

                report_id          = doc.get("report_id") or str(doc.get("_id", ""))
                fallback_type      = doc.get("member_type")
                team_plugins, _    = _get_team_plugin_names(db, report_id, teams_lower)
                held_coll          = db[HOLD_COLLECTION]

                results = []
                for held_doc in held_coll.find({"report_id": str(report_id)}):
                    host_entry = held_doc.get("host_entry") or {}
                    vulns      = host_entry.get("vulnerabilities", [])

                    # Only show held assets with team-assigned vulns
                    team_vulns = [
                        v for v in vulns
                        if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                    ]
                    if not team_vulns:
                        continue

                    results.append({
                        "asset": held_doc.get("host_name"),
                        "member_type": held_doc.get("member_type") or fallback_type,
                        "total_vulnerabilities": len(team_vulns),
                        "severity_counts": _severity_counts(team_vulns),
                        "host_information": host_entry.get("host_information") or {},
                        "held_at": held_doc.get("held_at"),
                        "held_by": held_doc.get("held_by"),
                    })

                return Response({
                    "report_id": report_id,
                    "count": len(results),
                    "assets": results
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 3. Assets from specific report (team-filtered) ──────────────────────────

class UserReportAssetsAPIView(APIView):
    """
    GET /api/user/asset/report/<report_id>/assets/

    Assets list for a specific report, team-filtered.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)
            search_q    = (request.query_params.get("q") or "").strip().lower()

            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                doc  = coll.find_one({"report_id": str(report_id)})
                if not doc:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

                # Verify report belongs to user's admin
                admin_id    = str(admin_user.id)
                admin_email = getattr(admin_user, "email", None)
                if doc.get("admin_id") != admin_id and doc.get("admin_email") != admin_email:
                    return Response(
                        {"detail": "Access denied. Report does not belong to your admin."},
                        status=status.HTTP_403_FORBIDDEN
                    )

                uploaded_at = doc.get("uploaded_at")
                member_type = doc.get("member_type")
                team_plugins, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)

                assets = {}
                for host in doc.get("vulnerabilities_by_host", []):
                    host_name = (host.get("host_name") or "").strip()
                    if not host_name:
                        continue
                    if search_q and search_q not in host_name.lower():
                        continue

                    team_vulns = [
                        v for v in host.get("vulnerabilities", [])
                        if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                    ]
                    if not team_vulns:
                        continue

                    if host_name not in assets:
                        assets[host_name] = {
                            "asset": host_name,
                            "first_seen": uploaded_at,
                            "last_seen": uploaded_at,
                            "member_type": member_type,
                            "total_vulnerabilities": 0,
                            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                            "host_information": host.get("host_information") or {},
                        }

                    entry = assets[host_name]
                    for v in team_vulns:
                        entry["total_vulnerabilities"] += 1
                        risk = (v.get("risk_factor") or v.get("severity") or "").lower()
                        if risk.startswith("crit"):
                            entry["severity_counts"]["critical"] += 1
                        elif risk.startswith("high"):
                            entry["severity_counts"]["high"] += 1
                        elif risk.startswith("med"):
                            entry["severity_counts"]["medium"] += 1
                        elif risk.startswith("low"):
                            entry["severity_counts"]["low"] += 1

                final = [
                    {
                        "asset": a["asset"],
                        "member_type": a["member_type"],
                        "first_seen": _iso(a["first_seen"]),
                        "last_seen": _iso(a["last_seen"]),
                        "total_vulnerabilities": a["total_vulnerabilities"],
                        "severity_counts": a["severity_counts"],
                        "host_information": a["host_information"],
                    }
                    for a in assets.values()
                ]

                serializer = UserAssetSerializer(final, many=True)
                return Response({
                    "report_id": report_id,
                    "member_type": member_type,
                    "teams": teams,
                    "total_assets": len(final),
                    "assets": serializer.data
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 4. Hold-list for specific report ────────────────────────────────────────

class UserHoldAssetsByReportAPIView(APIView):
    """
    GET /api/user/asset/report/<report_id>/assets/hold-list/
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)

            with MongoContext() as db:
                coll     = db[NESSUS_COLLECTION]
                report_doc = coll.find_one({"report_id": str(report_id)})
                if not report_doc:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

                fallback_type   = report_doc.get("member_type")
                team_plugins, _ = _get_team_plugin_names(db, report_id, teams_lower)
                held_coll       = db[HOLD_COLLECTION]

                results = []
                for held_doc in held_coll.find({"report_id": str(report_id)}):
                    host_entry = held_doc.get("host_entry") or {}
                    vulns      = host_entry.get("vulnerabilities", [])
                    team_vulns = [
                        v for v in vulns
                        if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                    ]
                    if not team_vulns:
                        continue

                    results.append({
                        "asset": held_doc.get("host_name"),
                        "member_type": held_doc.get("member_type") or fallback_type,
                        "total_vulnerabilities": len(team_vulns),
                        "severity_counts": _severity_counts(team_vulns),
                        "host_information": host_entry.get("host_information") or {},
                        "held_at": held_doc.get("held_at"),
                        "held_by": held_doc.get("held_by"),
                    })

                return Response({
                    "report_id": str(report_id),
                    "count": len(results),
                    "assets": results
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 5. Vulnerabilities by host (specific report, team-filtered) ─────────────

class UserAssetVulnerabilitiesByHostAPIView(APIView):
    """
    GET /api/user/asset/report/<report_id>/asset/<host_name>/vulnerabilities/
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)

            with MongoContext() as db:
                coll = db[NESSUS_COLLECTION]
                doc  = coll.find_one({"report_id": str(report_id)})
                if not doc:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

                member_type      = doc.get("member_type") or ""
                scan_info        = doc.get("scan_info") or {}
                organisation_name = (
                    scan_info.get("organisation_name")
                    or scan_info.get("organization")
                    or scan_info.get("organisation")
                    or ""
                )

                _, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)

                host_entry = None
                for h in (doc.get("vulnerabilities_by_host") or []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        host_entry = h
                        break

                if not host_entry:
                    return Response({"detail": "Asset not found in report"}, status=status.HTTP_404_NOT_FOUND)

                # Build closed vuln set
                admin_id = str(admin_user.id)
                closed_vulns = set()
                for cdoc in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": str(report_id), "created_by": admin_id}
                ):
                    key = (
                        cdoc.get("plugin_name", ""),
                        cdoc.get("host_name", ""),
                        str(cdoc.get("port", ""))
                    )
                    closed_vulns.add(key)

                out = []
                for v in (host_entry.get("vulnerabilities") or []):
                    plugin_name   = v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                    assigned_team = plugin_team_map.get(plugin_name)
                    if not assigned_team:
                        continue

                    port = str(v.get("port", ""))
                    if (plugin_name, host_name, port) in closed_vulns:
                        continue

                    out.append({
                        "asset": host_name,
                        "exposure": member_type,
                        "owner": organisation_name,
                        "severity": (v.get("risk_factor") or v.get("severity") or "").title(),
                        "vul_name": plugin_name,
                        "vendor_fix_available": "Yes",
                        "cvss_score": str(
                            v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        ),
                        "description": _join_description(v),
                        "status": "open",
                        "assigned_team": assigned_team,
                    })

                serializer = UserAssetVulnSerializer(out, many=True)
                return Response({
                    "report_id": str(report_id),
                    "asset": host_name,
                    "teams": teams,
                    "count": len(out),
                    "vulnerabilities": serializer.data
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 6. Vulnerabilities by host (latest report, team-filtered) ───────────────

class UserAssetVulnerabilitiesAPIView(APIView):
    """
    GET /api/user/asset/assets/<host_name>/vulnerabilities/

    Team-filtered vulnerabilities for a specific asset from admin's latest report.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        host_name = unquote(host_name)
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)
            admin_id    = str(admin_user.id)
            admin_email = getattr(admin_user, "email", None)

            with MongoContext() as db:
                doc = _load_latest_report(db, admin_id, admin_email)
                if not doc:
                    return Response(
                        {"detail": "No reports found for your admin account"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                report_id         = doc.get("report_id") or str(doc.get("_id", ""))
                member_type       = doc.get("member_type") or ""
                scan_info         = doc.get("scan_info") or {}
                organisation_name = (
                    scan_info.get("organisation_name")
                    or scan_info.get("organization")
                    or scan_info.get("organisation")
                    or ""
                )

                _, plugin_team_map = _get_team_plugin_names(db, report_id, teams_lower)

                host_entry = None
                for h in (doc.get("vulnerabilities_by_host") or []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        host_entry = h
                        break

                if not host_entry:
                    return Response(
                        {"detail": "Asset not found in report"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Build closed vuln set
                closed_vulns = set()
                for cdoc in db[FIX_VULN_CLOSED_COLLECTION].find(
                    {"report_id": str(report_id)}
                ):
                    key = (
                        cdoc.get("plugin_name", ""),
                        cdoc.get("host_name", ""),
                        str(cdoc.get("port", ""))
                    )
                    closed_vulns.add(key)

                out = []
                for v in (host_entry.get("vulnerabilities") or []):
                    plugin_name   = v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                    assigned_team = plugin_team_map.get(plugin_name)
                    if not assigned_team:
                        continue

                    port        = str(v.get("port", ""))
                    vuln_status = (
                        "closed"
                        if (plugin_name, host_name, port) in closed_vulns
                        else "open"
                    )

                    out.append({
                        "asset": host_name,
                        "exposure": member_type,
                        "owner": organisation_name,
                        "severity": (v.get("risk_factor") or v.get("severity") or "").title(),
                        "vul_name": plugin_name,
                        "vendor_fix_available": "Yes",
                        "cvss_score": str(
                            v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        ),
                        "description": _join_description(v),
                        "status": vuln_status,
                        "assigned_team": assigned_team,
                    })

                serializer = UserAssetVulnSerializer(out, many=True)
                return Response({
                    "report_id": str(report_id),
                    "asset": host_name,
                    "teams": teams,
                    "count": len(out),
                    "vulnerabilities": serializer.data
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 7. Support requests by host ─────────────────────────────────────────────

class UserSupportRequestByHostAPIView(APIView):
    """
    GET /api/user/asset/support-requests/host/<host_name>/

    Returns support requests raised by the logged-in user for a specific host.
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        user_id = str(request.user.id)

        with MongoContext() as db:
            support_coll = db[SUPPORT_REQUEST_COLLECTION]
            cursor = support_coll.find(
                {"host_name": host_name, "user_id": user_id}
            ).sort("requested_at", -1)

            results = []
            for doc in cursor:
                results.append({
                    "_id": str(doc.get("_id")),
                    "report_id": doc.get("report_id"),
                    "vulnerability_id": doc.get("vulnerability_id"),
                    "vul_name": doc.get("vul_name"),
                    "host_name": doc.get("host_name"),
                    "assigned_team": doc.get("assigned_team"),
                    "step_requested": doc.get("step_requested"),
                    "description": doc.get("description"),
                    "status": doc.get("status"),
                    "requested_at": doc.get("requested_at"),
                })

            return Response({
                "host_name": host_name,
                "count": len(results),
                "results": results
            }, status=status.HTTP_200_OK)


# ─── 8. Closed fix-vulnerabilities by host ───────────────────────────────────

class UserClosedFixVulnerabilitiesByHostAPIView(APIView):
    """
    GET /api/user/asset/fix-vulnerabilities/host/<host_name>/closed/

    Returns closed fix-vulnerabilities for the host that are assigned
    to the logged-in user's team(s).
    """
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, host_name):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Case-insensitive set of user's team names
            teams_lower_set = {t.lower() for t in teams}

            with MongoContext() as db:
                # Get admin's latest report to scope by report_id
                admin_id    = str(admin_user.id)
                admin_email = getattr(admin_user, "email", None)
                latest_doc  = _load_latest_report(db, admin_id, admin_email)
                report_id   = latest_doc.get("report_id") if latest_doc else None

                # Detect OS for this host from nessus report
                operating_system = None
                if latest_doc:
                    host_name_lower = host_name.strip().lower()
                    for h in latest_doc.get("vulnerabilities_by_host", []):
                        hn = (h.get("host_name") or h.get("host") or "").strip().lower()
                        if hn == host_name_lower:
                            host_info = h.get("host_information") or {}
                            os_raw = (
                                host_info.get("OS")
                                or host_info.get("operating-system")
                                or host_info.get("os")
                                or ""
                            ).strip()
                            if os_raw:
                                os_lower = os_raw.lower()
                                if "windows" in os_lower:
                                    operating_system = "Windows"
                                elif "linux" in os_lower or "unix" in os_lower:
                                    operating_system = "Linux"
                                else:
                                    operating_system = os_raw
                            break

                # Query fix_vulnerabilities_closed (fully patched vulns)
                # Scope by host_name + report_id, no created_by filter (same as userregister)
                closed_coll = db[FIX_VULN_CLOSED_COLLECTION]
                query = {"host_name": host_name}
                if report_id:
                    query["report_id"] = str(report_id)

                cursor = closed_coll.find(query).sort("closed_at", -1)

                results = []
                for doc in cursor:
                    doc_team = (doc.get("assigned_team") or "").strip().lower()
                    # Team filter — case-insensitive
                    if doc_team not in teams_lower_set:
                        continue

                    results.append({
                        "fix_vulnerability_id": str(doc.get("fix_vulnerability_id") or doc.get("_id")),
                        "report_id": doc.get("report_id"),
                        "host_name": doc.get("host_name"),
                        "plugin_name": doc.get("plugin_name"),
                        "risk_factor": doc.get("risk_factor"),
                        "description_points": doc.get("description_points"),
                        "vendor_fix_available": doc.get("vendor_fix_available"),
                        "assigned_team": doc.get("assigned_team"),
                        "assigned_team_members": doc.get("assigned_team_members", []),
                        "mitigation_steps": doc.get("mitigation_steps", []),
                        "operating_system": operating_system,
                        "status": "closed",
                        "closed_at": doc.get("closed_at"),
                        "created_at": doc.get("created_at"),
                        "created_by": doc.get("created_by"),
                    })

            return Response({
                "host_name": host_name,
                "status": "closed",
                "count": len(results),
                "results": results
            }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response({"detail": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# ─── 9. Hold asset ───────────────────────────────────────────────────────────

class UserAssetHoldAPIView(APIView):
    """
    POST /api/user/asset/report/<report_id>/assets/<host_name>/hold/

    Moves asset to hold_assets. Only allowed if asset has ≥1 team-assigned vuln.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)

            with MongoContext() as db:
                has_access, doc, err = _validate_team_access(db, report_id, host_name, teams_lower)
                if not has_access:
                    return err

                coll      = db[NESSUS_COLLECTION]
                held_coll = db[HOLD_COLLECTION]
                member_type = doc.get("member_type")

                found = None
                for h in doc.get("vulnerabilities_by_host", []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        found = h
                        break

                if not found:
                    return Response(
                        {"detail": "Asset not found in report"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Remove from report
                coll.update_one(
                    {"report_id": str(report_id)},
                    {"$pull": {"vulnerabilities_by_host": {
                        "$or": [{"host_name": host_name}, {"host": host_name}]
                    }}}
                )

                # Store in hold collection
                held_coll.insert_one({
                    "report_id": str(report_id),
                    "host_name": host_name,
                    "member_type": member_type,
                    "host_entry": found,
                    "held_at": timezone.now(),
                    "held_by": getattr(request.user, "email", None) or getattr(request.user, "username", None),
                })

                team_plugins, _ = _get_team_plugin_names(db, report_id, teams_lower)
                team_vulns = [
                    v for v in found.get("vulnerabilities", [])
                    if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                ]

                asset_data = {
                    "asset": host_name,
                    "member_type": member_type,
                    "total_vulnerabilities": len(team_vulns),
                    "severity_counts": _severity_counts(team_vulns),
                    "host_information": found.get("host_information") or {},
                }

                # Count only team-filtered assets
                total_assets = _compute_total_assets(db, report_id, team_plugins)

                return Response({
                    "detail": "Asset held (removed from report)",
                    "total_assets": total_assets,
                    "asset": asset_data
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "Hold failed", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─── 10. Unhold asset ────────────────────────────────────────────────────────

class UserAssetUnholdAPIView(APIView):
    """
    POST /api/user/asset/report/<report_id>/assets/<host_name>/unhold/

    Restores held asset back to the report.
    Only allowed if asset has ≥1 team-assigned vuln.
    """
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)

            with MongoContext() as db:
                coll      = db[NESSUS_COLLECTION]
                held_coll = db[HOLD_COLLECTION]

                # Verify report exists
                report_doc = coll.find_one({"report_id": str(report_id)})
                if not report_doc:
                    return Response({"detail": "Report not found"}, status=status.HTTP_404_NOT_FOUND)

                # Find held asset
                held = held_coll.find_one({
                    "report_id": str(report_id),
                    "host_name": host_name
                })
                if not held:
                    return Response(
                        {"detail": "No held asset found"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                host_entry  = held.get("host_entry")
                member_type = held.get("member_type")

                if not host_entry:
                    return Response(
                        {"detail": "Hold asset missing host_entry"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

                # Validate team access on held entry
                team_plugins, _ = _get_team_plugin_names(db, report_id, teams_lower)
                team_vulns = [
                    v for v in host_entry.get("vulnerabilities", [])
                    if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                ]
                if not team_vulns:
                    return Response(
                        {"detail": "Access denied. This asset has no vulnerabilities assigned to your team."},
                        status=status.HTTP_403_FORBIDDEN
                    )

                # Restore to report
                res = coll.update_one(
                    {"report_id": str(report_id)},
                    {"$push": {"vulnerabilities_by_host": host_entry}}
                )
                if res.matched_count == 0:
                    return Response(
                        {"detail": "Report not found when restoring"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                # Remove from hold
                held_coll.delete_one({"_id": held["_id"]})

                # Count only team-filtered assets
                total_assets = _compute_total_assets(db, report_id, team_plugins)

                asset_response = {
                    "asset": host_name,
                    "member_type": member_type,
                    "total_vulnerabilities": len(team_vulns),
                    "host_information": host_entry.get("host_information", {}),
                    "severity_counts": _severity_counts(team_vulns),
                }

                return Response({
                    "detail": "Asset unhold (restored to report)",
                    "total_assets": total_assets,
                    "asset": asset_response
                }, status=status.HTTP_200_OK)

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "Unhold failed", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# ─── 11. Delete asset ────────────────────────────────────────────────────────

class UserAssetDeleteAPIView(APIView):
    """
    DELETE /api/user/asset/report/<report_id>/assets/<host_name>/

    Removes the host from the report and stores it in deleted_assets.
    Only allowed if asset has ≥1 team-assigned vuln.
    """
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request, report_id, host_name):
        host_name = unquote(host_name)
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response(
                    {"detail": "User is not linked to any team."},
                    status=status.HTTP_403_FORBIDDEN
                )

            teams_lower = _normalize_teams(teams)

            with MongoContext() as db:
                has_access, doc, err = _validate_team_access(db, report_id, host_name, teams_lower)
                if not has_access:
                    return err

                coll         = db[NESSUS_COLLECTION]
                deleted_coll = db[DELETED_ASSETS_COLLECTION]

                asset_entry = None
                for h in (doc.get("vulnerabilities_by_host") or []):
                    hn = (h.get("host_name") or h.get("host") or "").strip()
                    if hn == host_name:
                        asset_entry = h
                        break

                if not asset_entry:
                    return Response(
                        {"detail": "Asset not found in report"},
                        status=status.HTTP_404_NOT_FOUND
                    )

                team_plugins, _ = _get_team_plugin_names(db, report_id, teams_lower)
                team_vulns = [
                    v for v in asset_entry.get("vulnerabilities", [])
                    if (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "") in team_plugins
                ]

                # Store in deleted_assets history
                deleted_coll.insert_one({
                    "report_id": str(report_id),
                    "admin_id": doc.get("admin_id"),
                    "admin_email": doc.get("admin_email"),
                    "deleted_by_user_id": str(request.user.id),
                    "deleted_by_user_email": getattr(request.user, "email", ""),
                    "host_name": host_name,
                    "member_type": doc.get("member_type"),
                    "total_vulnerabilities": len(asset_entry.get("vulnerabilities", [])),
                    "severity_counts": _severity_counts(asset_entry.get("vulnerabilities", [])),
                    "host_information": asset_entry.get("host_information") or {},
                    "deleted_at": timezone.now(),
                    "deleted_by": getattr(request.user, "email", str(request.user.id)),
                })

                # Remove from report
                res = coll.update_one(
                    {"report_id": str(report_id)},
                    {"$pull": {"vulnerabilities_by_host": {
                        "$or": [{"host_name": host_name}, {"host": host_name}]
                    }}}
                )

                if res.modified_count == 0:
                    return Response(
                        {"detail": "Failed to remove asset"},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR
                    )

                return Response(
                    {"detail": "Asset removed from report"},
                    status=status.HTTP_200_OK
                )

        except Exception as exc:
            import traceback; traceback.print_exc()
            return Response(
                {"detail": "Delete failed", "error": str(exc)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
