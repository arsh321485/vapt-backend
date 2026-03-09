from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
import re

from vaptfix.mongo_client import MongoContext

NESSUS_COLLECTION        = "nessus_reports"
VULN_CARD_COLLECTION     = "vulnerability_cards"
SUPPORT_REQUEST_COLLECTION = "support_requests"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"

try:
    from users_details.models import UserDetail
except Exception:
    UserDetail = None

try:
    from risk_criteria.models import RiskCriteria
except Exception:
    RiskCriteria = None


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

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


def _get_admin_riskcriteria(admin_user):
    if not RiskCriteria or not admin_user:
        return None
    try:
        return RiskCriteria.objects.filter(admin=admin_user).order_by('-created_at').first()
    except Exception:
        return None


def _load_latest_report(db, admin_id, admin_email):
    """Load admin's most recently uploaded nessus report."""
    coll = db[NESSUS_COLLECTION]
    doc = coll.find_one({"admin_id": str(admin_id)}, sort=[("uploaded_at", -1)])
    if not doc and admin_email:
        doc = coll.find_one({"admin_email": admin_email}, sort=[("uploaded_at", -1)])
    return doc


def _build_plugin_risk_map(nessus_doc):
    """
    Build plugin_name -> risk_factor map from nessus report.
    Used to look up severity of vulnerabilities in vulnerability_cards.
    """
    plugin_risk = {}
    for host in (nessus_doc.get("vulnerabilities_by_host") or []):
        for v in (host.get("vulnerabilities") or []):
            pname = (v.get("plugin_name") or v.get("pluginname") or v.get("name") or "").strip()
            if pname and pname not in plugin_risk:
                raw = (v.get("risk_factor") or v.get("severity") or "").strip().lower()
                if raw.startswith("crit"):
                    plugin_risk[pname] = "critical"
                elif raw.startswith("high"):
                    plugin_risk[pname] = "high"
                elif raw.startswith("med"):
                    plugin_risk[pname] = "medium"
                elif raw.startswith("low"):
                    plugin_risk[pname] = "low"
    return plugin_risk


def _parse_timeline_to_days(value):
    if not value:
        return 0
    value = value.strip().lower()
    if value in ("select", ""):
        return 0
    match = re.search(r"(\d+)", value)
    if not match:
        return 0
    num = int(match.group(1))
    return num * 7 if "week" in value else num


def _days_to_hours(days):
    return days * 24


def _days_to_label(days):
    if not days or days <= 0:
        return "0 day"
    if days % 7 == 0:
        w = days // 7
        return f"{w} week" if w == 1 else f"{w} weeks"
    return f"{days} days"


def _hours_to_wdh(hours):
    weeks = hours // 168
    hours = hours % 168
    days  = hours // 24
    hours = hours % 24
    return {"weeks": weeks, "days": days, "hours": hours}


def _format_wdh_label(wdh):
    parts = []
    if wdh["weeks"]:
        parts.append(f'{wdh["weeks"]} week' if wdh["weeks"] == 1 else f'{wdh["weeks"]} weeks')
    if wdh["days"]:
        parts.append(f'{wdh["days"]} day' if wdh["days"] == 1 else f'{wdh["days"]} days')
    if wdh["hours"]:
        parts.append(f'{wdh["hours"]} hour' if wdh["hours"] == 1 else f'{wdh["hours"]} hours')
    return ", ".join(parts) if parts else "0 hour"


def _normalize_teams(teams):
    """Lowercase map for case-insensitive team matching."""
    return {t.lower(): t for t in teams}


# ─────────────────────────────────────────────────────────────────────────────
# 1. TEAMS LIST
# ─────────────────────────────────────────────────────────────────────────────

class UserTeamsAPIView(APIView):
    """GET /api/user/dashboard/teams/"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        teams, _ = _get_user_context(request.user.email)
        return Response({"teams": teams, "count": len(teams)})


# ─────────────────────────────────────────────────────────────────────────────
# 2. TOTAL ASSETS
# ─────────────────────────────────────────────────────────────────────────────

class UserTotalAssetsAPIView(APIView):
    """
    GET /api/user/dashboard/total-assets/
    Counts unique hosts per team by matching nessus_reports vulnerabilities_by_host
    against the plugin_name→team map from vulnerability_cards.
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"total_assets": 0, "teams": [], "by_team": {}})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not nessus_doc:
                    return Response({"total_assets": 0, "teams": active_teams, "by_team": {}})

                report_id = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))

                # Build plugin_name -> matched_team map from vulnerability_cards
                plugin_team_map = {}
                for card in db[VULN_CARD_COLLECTION].find(
                    {"report_id": str(report_id)},
                    {"vulnerability_name": 1, "assigned_team": 1}
                ):
                    pname    = (card.get("vulnerability_name") or "").strip()
                    raw_team = (card.get("assigned_team") or "").strip()
                    matched  = teams_lower.get(raw_team.lower())
                    if pname and matched:
                        plugin_team_map[pname] = matched

                # Count unique hosts per team from nessus doc (with host-ip fallback)
                by_team = {t: set() for t in active_teams}
                for host in (nessus_doc.get("vulnerabilities_by_host") or []):
                    host_info = host.get("host_information") or {}
                    h_name = (
                        host.get("host_name") or host.get("host")
                        or host_info.get("host-ip") or host_info.get("host-fqdn") or ""
                    )
                    if isinstance(h_name, str):
                        h_name = h_name.strip()
                    if not h_name:
                        continue
                    for v in (host.get("vulnerabilities") or []):
                        pname = (
                            v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                        ).strip()
                        matched = plugin_team_map.get(pname)
                        if matched:
                            by_team[matched].add(h_name)

                by_team_count = {t: len(hosts) for t, hosts in by_team.items()}
                all_hosts = set().union(*by_team.values())

                return Response({
                    "report_id": report_id,
                    "total_assets": len(all_hosts),
                    "teams": active_teams,
                    "by_team": by_team_count
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 3. VULNERABILITIES
# ─────────────────────────────────────────────────────────────────────────────

class UserVulnerabilitiesAPIView(APIView):
    """
    GET /api/user/dashboard/vulnerabilities/
    Counts vulnerabilities by severity from vulnerability_cards (team-filtered).
    Severity is looked up from nessus_reports by plugin_name.
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"critical": 0, "high": 0, "medium": 0, "low": 0})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not nessus_doc:
                    return Response({"critical": 0, "high": 0, "medium": 0, "low": 0})

                report_id  = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))
                plugin_risk = _build_plugin_risk_map(nessus_doc)

                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}

                for card in db[VULN_CARD_COLLECTION].find({"report_id": str(report_id)}):
                    raw_team = (card.get("assigned_team") or "").strip()
                    if not teams_lower.get(raw_team.lower()):
                        continue
                    pname = (card.get("vulnerability_name") or "").strip()
                    risk  = plugin_risk.get(pname)
                    if risk in counts:
                        counts[risk] += 1

                return Response({"report_id": report_id, **counts})

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 4. VULNERABILITIES FIXED
# ─────────────────────────────────────────────────────────────────────────────

class UserVulnerabilitiesFixedAPIView(APIView):
    """
    GET /api/user/dashboard/vulnerabilities-fixed/
    Counts closed vulnerabilities for user's teams.
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"total_fixed": 0, "critical_fixed": 0, "high_fixed": 0, "medium_fixed": 0, "low_fixed": 0})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not nessus_doc:
                    return Response({"total_fixed": 0, "critical_fixed": 0, "high_fixed": 0, "medium_fixed": 0, "low_fixed": 0})

                report_id   = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))
                plugin_risk = _build_plugin_risk_map(nessus_doc)
                admin_id    = str(admin_user.id)

                # Get plugin_names that belong to user's teams
                team_plugins = set()
                for card in db[VULN_CARD_COLLECTION].find({"report_id": str(report_id)}):
                    raw_team = (card.get("assigned_team") or "").strip()
                    if teams_lower.get(raw_team.lower()):
                        pname = (card.get("vulnerability_name") or "").strip()
                        if pname:
                            team_plugins.add(pname)

                counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in db[FIX_VULN_CLOSED_COLLECTION].find({
                    "created_by": admin_id,
                    "status": "closed",
                    "report_id": str(report_id)
                }):
                    pname = (vuln.get("plugin_name") or "").strip()
                    if pname not in team_plugins:
                        continue
                    risk = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
                    if risk.startswith("crit"):
                        counts["critical"] += 1
                    elif risk.startswith("high"):
                        counts["high"] += 1
                    elif risk.startswith("med"):
                        counts["medium"] += 1
                    elif risk.startswith("low"):
                        counts["low"] += 1

                total = sum(counts.values())
                return Response({
                    "report_id": report_id,
                    "total_fixed": total,
                    "critical_fixed": counts["critical"],
                    "high_fixed": counts["high"],
                    "medium_fixed": counts["medium"],
                    "low_fixed": counts["low"]
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 5. MITIGATION TIMELINE
# ─────────────────────────────────────────────────────────────────────────────

class UserMitigationTimelineAPIView(APIView):
    """GET /api/user/dashboard/mitigation-timeline/"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            _, admin_user = _get_user_context(request.user.email)
            if not admin_user:
                return Response({"detail": "User not linked to any team"}, status=404)

            rc = _get_admin_riskcriteria(admin_user)
            if not rc:
                return Response({"detail": "Risk criteria not set by admin"}, status=404)

            c = _parse_timeline_to_days(rc.critical)
            h = _parse_timeline_to_days(rc.high)
            m = _parse_timeline_to_days(rc.medium)
            l = _parse_timeline_to_days(rc.low)
            t = c + h + m + l

            return Response({
                "critical": {"raw": rc.critical, "days": c, "label": _days_to_label(c)},
                "high":     {"raw": rc.high,     "days": h, "label": _days_to_label(h)},
                "medium":   {"raw": rc.medium,   "days": m, "label": _days_to_label(m)},
                "low":      {"raw": rc.low,       "days": l, "label": _days_to_label(l)},
                "total":    {"days": t, "hours": _days_to_hours(t), "label": _days_to_label(t)}
            })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 6. MEAN TIME TO REMEDIATE
# ─────────────────────────────────────────────────────────────────────────────

class UserMeanTimeRemediateAPIView(APIView):
    """GET /api/user/dashboard/mean-time-remediate/"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            _, admin_user = _get_user_context(request.user.email)
            if not admin_user:
                return Response({"detail": "User not linked to any team"}, status=404)

            rc = _get_admin_riskcriteria(admin_user)
            if not rc:
                return Response({"detail": "Risk criteria not set by admin"}, status=404)

            c_d = _parse_timeline_to_days(rc.critical)
            h_d = _parse_timeline_to_days(rc.high)
            m_d = _parse_timeline_to_days(rc.medium)
            l_d = _parse_timeline_to_days(rc.low)

            c_h = _days_to_hours(c_d)
            h_h = _days_to_hours(h_d)
            m_h = _days_to_hours(m_d)
            l_h = _days_to_hours(l_d)

            mttr  = round((c_h + h_h + m_h + l_h) / 4)
            wdh   = _hours_to_wdh(mttr)

            return Response({
                "risk_criteria": {
                    "critical": {"raw": rc.critical, "days": c_d, "hours": c_h},
                    "high":     {"raw": rc.high,     "days": h_d, "hours": h_h},
                    "medium":   {"raw": rc.medium,   "days": m_d, "hours": m_h},
                    "low":      {"raw": rc.low,       "days": l_d, "hours": l_h},
                },
                "mean_time_to_remediate": {
                    "hours": mttr,
                    "weeks": wdh["weeks"],
                    "days":  wdh["days"],
                    "hours_remaining": wdh["hours"],
                    "label": _format_wdh_label(wdh)
                }
            })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 7. SUPPORT REQUESTS
# ─────────────────────────────────────────────────────────────────────────────

class UserSupportRequestsAPIView(APIView):
    """
    GET /api/user/dashboard/support-requests/
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"total": 0, "pending": 0, "closed": 0})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not nessus_doc:
                    return Response({"total": 0, "pending": 0, "closed": 0})

                report_id = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))
                admin_id  = str(admin_user.id)

                # Get plugin_names belonging to user's teams
                team_plugins = set()
                for card in db[VULN_CARD_COLLECTION].find({"report_id": str(report_id)}):
                    raw_team = (card.get("assigned_team") or "").strip()
                    if teams_lower.get(raw_team.lower()):
                        pname = (card.get("vulnerability_name") or "").strip()
                        if pname:
                            team_plugins.add(pname)

                # Support requests for those plugins
                support_coll = db[SUPPORT_REQUEST_COLLECTION]
                base_q = {
                    "admin_id": admin_id,
                    "report_id": str(report_id),
                    "vul_name": {"$in": list(team_plugins)}
                }

                pending = support_coll.count_documents({**base_q, "status": {"$ne": "closed"}})
                closed  = support_coll.count_documents({**base_q, "status": "closed"})

                return Response({
                    "report_id": report_id,
                    "total": pending + closed,
                    "pending": pending,
                    "closed": closed
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 8. PATCH MANAGEMENT (per-team cards)
# ─────────────────────────────────────────────────────────────────────────────

class UserPatchManagementAPIView(APIView):
    """
    GET /api/user/dashboard/patch-management/
    Returns per-team vuln counts + SLA days.
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"teams": []})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            rc = _get_admin_riskcriteria(admin_user)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not nessus_doc:
                    return Response({"teams": []})

                report_id   = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))
                plugin_risk = _build_plugin_risk_map(nessus_doc)

                # Initialize per-team buckets
                team_data = {
                    t: {"team": t, "report_id": report_id, "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "assets": set(), "sla": {}}
                    for t in active_teams
                }

                # Build plugin_name -> matched_team map from cards
                plugin_team_map = {}
                for card in db[VULN_CARD_COLLECTION].find({"report_id": str(report_id)}):
                    raw_team = (card.get("assigned_team") or "").strip()
                    matched  = teams_lower.get(raw_team.lower())
                    if not matched:
                        continue
                    pname = (card.get("vulnerability_name") or "").strip()
                    if pname:
                        plugin_team_map[pname] = matched
                    risk = plugin_risk.get(pname)
                    if risk in team_data[matched]["vulnerabilities"]:
                        team_data[matched]["vulnerabilities"][risk] += 1

                # Count assets from nessus doc using host-ip fallback
                for host in (nessus_doc.get("vulnerabilities_by_host") or []):
                    host_info = host.get("host_information") or {}
                    h_name = (
                        host.get("host_name") or host.get("host")
                        or host_info.get("host-ip") or host_info.get("host-fqdn") or ""
                    )
                    if isinstance(h_name, str):
                        h_name = h_name.strip()
                    if not h_name:
                        continue
                    for v in (host.get("vulnerabilities") or []):
                        pname = (
                            v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                        ).strip()
                        matched = plugin_team_map.get(pname)
                        if matched:
                            team_data[matched]["assets"].add(h_name)

                # Build SLA and convert assets set to count
                sla = {}
                if rc:
                    c_d = _parse_timeline_to_days(rc.critical)
                    h_d = _parse_timeline_to_days(rc.high)
                    m_d = _parse_timeline_to_days(rc.medium)
                    l_d = _parse_timeline_to_days(rc.low)
                    sla = {
                        "critical": {"days": c_d, "label": _days_to_label(c_d)},
                        "high":     {"days": h_d, "label": _days_to_label(h_d)},
                        "medium":   {"days": m_d, "label": _days_to_label(m_d)},
                        "low":      {"days": l_d, "label": _days_to_label(l_d)},
                    }

                result = []
                for t in active_teams:
                    td = team_data[t]
                    result.append({
                        "team": td["team"],
                        "report_id": td["report_id"],
                        "total_assets": len(td["assets"]),
                        "vulnerabilities": td["vulnerabilities"],
                        "sla": sla
                    })

                return Response({"teams": result})

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 9. FULL DASHBOARD SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

class UserDashboardSummaryAPIView(APIView):
    """
    GET /api/user/dashboard/summary/
    All metrics in one call. Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)

            if not teams or not admin_user:
                return Response({
                    "user_email": request.user.email,
                    "teams": [],
                    "total_assets": 0,
                    "by_team_assets": {},
                    "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    "vulnerabilities_fixed": {"total_fixed": 0, "critical_fixed": 0, "high_fixed": 0, "medium_fixed": 0, "low_fixed": 0},
                    "mitigation_timeline": None,
                    "mean_time_to_remediate": None,
                    "support_requests": {"total": 0, "pending": 0, "closed": 0},
                    "message": "User is not linked to any team. Ask your admin to assign you a team."
                })

            selected_team = request.query_params.get("team", "").strip()
            active_teams  = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower   = _normalize_teams(active_teams)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)

                if not nessus_doc:
                    return Response({
                        "user_email": request.user.email,
                        "teams": active_teams,
                        "total_assets": 0,
                        "by_team_assets": {},
                        "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        "vulnerabilities_fixed": {"total_fixed": 0, "critical_fixed": 0, "high_fixed": 0, "medium_fixed": 0, "low_fixed": 0},
                        "mitigation_timeline": None,
                        "mean_time_to_remediate": None,
                        "support_requests": {"total": 0, "pending": 0, "closed": 0},
                        "message": "No report uploaded yet."
                    })

                report_id   = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))
                plugin_risk = _build_plugin_risk_map(nessus_doc)
                admin_id    = str(admin_user.id)

                # Per-team buckets
                by_team_hosts  = {t: set() for t in active_teams}
                vuln_counts    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                team_plugins   = set()

                # Build plugin_name -> matched_team from cards; count vulns
                plugin_team_map = {}
                for card in db[VULN_CARD_COLLECTION].find({"report_id": str(report_id)}):
                    raw_team = (card.get("assigned_team") or "").strip()
                    matched  = teams_lower.get(raw_team.lower())
                    if not matched:
                        continue
                    pname = (card.get("vulnerability_name") or "").strip()
                    if pname:
                        team_plugins.add(pname)
                        plugin_team_map[pname] = matched
                    risk = plugin_risk.get(pname)
                    if risk in vuln_counts:
                        vuln_counts[risk] += 1

                # Count assets from nessus doc using host-ip fallback
                for host in (nessus_doc.get("vulnerabilities_by_host") or []):
                    host_info = host.get("host_information") or {}
                    h_name = (
                        host.get("host_name") or host.get("host")
                        or host_info.get("host-ip") or host_info.get("host-fqdn") or ""
                    )
                    if isinstance(h_name, str):
                        h_name = h_name.strip()
                    if not h_name:
                        continue
                    for v in (host.get("vulnerabilities") or []):
                        pname = (
                            v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                        ).strip()
                        matched = plugin_team_map.get(pname)
                        if matched:
                            by_team_hosts[matched].add(h_name)

                all_hosts      = set().union(*by_team_hosts.values())
                by_team_assets = {t: len(hosts) for t, hosts in by_team_hosts.items()}

                # ---- Fixed vulnerabilities ----
                fixed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for vuln in db[FIX_VULN_CLOSED_COLLECTION].find({
                    "created_by": admin_id,
                    "status": "closed",
                    "report_id": str(report_id)
                }):
                    pname = (vuln.get("plugin_name") or "").strip()
                    if pname not in team_plugins:
                        continue
                    risk = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
                    if risk.startswith("crit"):
                        fixed_counts["critical"] += 1
                    elif risk.startswith("high"):
                        fixed_counts["high"] += 1
                    elif risk.startswith("med"):
                        fixed_counts["medium"] += 1
                    elif risk.startswith("low"):
                        fixed_counts["low"] += 1

                # ---- Support requests ----
                base_q = {
                    "admin_id": admin_id,
                    "report_id": str(report_id),
                    "vul_name": {"$in": list(team_plugins)}
                }
                support_coll  = db[SUPPORT_REQUEST_COLLECTION]
                pending_count = support_coll.count_documents({**base_q, "status": {"$ne": "closed"}})
                closed_count  = support_coll.count_documents({**base_q, "status": "closed"})

            # ---- Risk criteria / timeline / MTTR ----
            rc = _get_admin_riskcriteria(admin_user)
            mitigation_timeline    = None
            mean_time_to_remediate = None

            if rc:
                c_d = _parse_timeline_to_days(rc.critical)
                h_d = _parse_timeline_to_days(rc.high)
                m_d = _parse_timeline_to_days(rc.medium)
                l_d = _parse_timeline_to_days(rc.low)
                t_d = c_d + h_d + m_d + l_d

                mitigation_timeline = {
                    "critical": {"raw": rc.critical, "days": c_d, "label": _days_to_label(c_d)},
                    "high":     {"raw": rc.high,     "days": h_d, "label": _days_to_label(h_d)},
                    "medium":   {"raw": rc.medium,   "days": m_d, "label": _days_to_label(m_d)},
                    "low":      {"raw": rc.low,       "days": l_d, "label": _days_to_label(l_d)},
                    "total":    {"days": t_d, "hours": _days_to_hours(t_d), "label": _days_to_label(t_d)},
                }

                c_h  = _days_to_hours(c_d)
                h_h  = _days_to_hours(h_d)
                m_h  = _days_to_hours(m_d)
                l_h  = _days_to_hours(l_d)
                mttr = round((c_h + h_h + m_h + l_h) / 4)
                wdh  = _hours_to_wdh(mttr)

                mean_time_to_remediate = {
                    "hours": mttr,
                    "weeks": wdh["weeks"],
                    "days":  wdh["days"],
                    "hours_remaining": wdh["hours"],
                    "label": _format_wdh_label(wdh)
                }

            return Response({
                "user_email": request.user.email,
                "report_id": report_id,
                "teams": active_teams,
                "selected_team": selected_team or None,
                "total_assets": len(all_hosts),
                "by_team_assets": by_team_assets,
                "vulnerabilities": vuln_counts,
                "vulnerabilities_fixed": {
                    "total_fixed": sum(fixed_counts.values()),
                    "critical_fixed": fixed_counts["critical"],
                    "high_fixed":     fixed_counts["high"],
                    "medium_fixed":   fixed_counts["medium"],
                    "low_fixed":      fixed_counts["low"],
                },
                "mitigation_timeline": mitigation_timeline,
                "mean_time_to_remediate": mean_time_to_remediate,
                "support_requests": {
                    "total":   pending_count + closed_count,
                    "pending": pending_count,
                    "closed":  closed_count,
                },
            })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)
