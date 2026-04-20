from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
import re
import math
from datetime import timedelta, datetime, timezone

from vaptfix.mongo_client import MongoContext

NESSUS_COLLECTION        = "nessus_reports"
VULN_CARD_COLLECTION     = "vulnerability_cards"
SUPPORT_REQUEST_COLLECTION = "support_requests"
FIX_VULN_COLLECTION = "fix_vulnerabilities"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
FIX_VULN_STEPS_COLLECTION = "fix_vulnerability_steps"
TIMELINE_EXTENSION_COLLECTION = "timeline_extension_requests"

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


def _extract_total_steps(mitigation_table):
    if not isinstance(mitigation_table, list):
        return 0
    step_nums = set()
    for row in mitigation_table:
        if not isinstance(row, dict):
            continue
        try:
            step_num = int(row.get("step_no", 0))
        except (TypeError, ValueError):
            continue
        if step_num > 0:
            step_nums.add(step_num)
    return len(step_nums)


def _normalize_severity_key(raw):
    sev = (raw or "").strip().lower()
    if sev.startswith("crit"):
        return "critical"
    if sev.startswith("high"):
        return "high"
    if sev.startswith("med"):
        return "medium"
    if sev.startswith("low"):
        return "low"
    return None


def _to_iso(dt_val):
    if hasattr(dt_val, "isoformat"):
        return dt_val.isoformat()
    return str(dt_val) if dt_val else None


def _build_plugin_severity_map(report_doc):
    plugin_risk = {}
    for host in report_doc.get("vulnerabilities_by_host", []):
        for vuln in host.get("vulnerabilities", []):
            pname = (
                vuln.get("plugin_name")
                or vuln.get("pluginname")
                or vuln.get("name")
                or ""
            ).strip()
            if not pname or pname in plugin_risk:
                continue
            plugin_risk[pname] = _normalize_severity_key(vuln.get("risk_factor") or vuln.get("severity") or "")
    return plugin_risk


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

                # Build plugin_name -> set of matched_teams from vulnerability_cards
                # Using setdefault+set so one plugin can belong to multiple teams
                plugin_team_map = {}
                for card in db[VULN_CARD_COLLECTION].find(
                    {"report_id": str(report_id)},
                    {"vulnerability_name": 1, "assigned_team": 1}
                ):
                    pname    = (card.get("vulnerability_name") or "").strip()
                    raw_team = (card.get("assigned_team") or "").strip()
                    matched  = teams_lower.get(raw_team.lower())
                    if pname and matched:
                        plugin_team_map.setdefault(pname, set()).add(matched)

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
                        for matched in plugin_team_map.get(pname, set()):
                            by_team[matched].add(h_name)

                by_team_count = {t: len(hosts) for t, hosts in by_team.items()}
                # total_assets = unique hosts across all teams (host in multiple teams counted once)
                all_hosts = set().union(*by_team.values()) if by_team else set()
                total_assets = len(all_hosts)

                return Response({
                    "report_id": report_id,
                    "total_assets": total_assets,
                    "teams": active_teams,
                    "by_team": by_team_count
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 3. AVERAGE CVSS SCORE (per total assets)
# ─────────────────────────────────────────────────────────────────────────────

def _safe_float(value):
    """Convert a value to float, return None if not possible."""
    if value is None:
        return None
    try:
        return float(value)
    except Exception:
        return None


class UserAvgScoreAPIView(APIView):
    """
    GET /api/user/dashboard/avg-score/
    Returns average CVSS v3 score from vulnerabilities assigned to user's teams.
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"avg_score": None, "total_assets": 0, "teams": [], "by_team": {}})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            with MongoContext() as db:
                nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not nessus_doc:
                    return Response({"avg_score": None, "total_assets": 0, "teams": active_teams, "by_team": {}})

                report_id = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))

                # Build plugin_name -> set of matched_teams from vulnerability_cards
                plugin_team_map = {}
                for card in db[VULN_CARD_COLLECTION].find(
                    {"report_id": str(report_id)},
                    {"vulnerability_name": 1, "assigned_team": 1}
                ):
                    pname    = (card.get("vulnerability_name") or "").strip()
                    raw_team = (card.get("assigned_team") or "").strip()
                    matched  = teams_lower.get(raw_team.lower())
                    if pname and matched:
                        plugin_team_map.setdefault(pname, set()).add(matched)

                # Collect CVSS scores and unique hosts per team
                by_team = {t: set() for t in active_teams}
                cvss_vals = []

                for host in (nessus_doc.get("vulnerabilities_by_host") or []):
                    host_info = host.get("host_information") or {}
                    h_name = (
                        host.get("host_name") or host.get("host")
                        or host_info.get("host-ip") or host_info.get("host-fqdn") or ""
                    )
                    if isinstance(h_name, str):
                        h_name = h_name.strip()

                    for v in (host.get("vulnerabilities") or []):
                        pname = (
                            v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                        ).strip()
                        matched_teams = plugin_team_map.get(pname, set())
                        if not matched_teams:
                            continue

                        # Collect CVSS score for this vulnerability
                        cv_raw = v.get("cvss_v3_base_score") or v.get("cvss") or v.get("cvss_score") or ""
                        num = _safe_float(cv_raw)
                        if num is not None:
                            cvss_vals.append(num)

                        # Count host per team
                        if h_name:
                            for matched in matched_teams:
                                by_team[matched].add(h_name)

                avg = round(sum(cvss_vals) / len(cvss_vals), 2) if cvss_vals else None
                by_team_count = {t: len(hosts) for t, hosts in by_team.items()}
                all_hosts = set().union(*by_team.values()) if by_team else set()

                return Response({
                    "report_id": report_id,
                    "avg_score": avg,
                    "total_assets": len(all_hosts),
                    "teams": active_teams,
                    "by_team": by_team_count,
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 4. VULNERABILITIES
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
                result = {
                    "report_id": report_id,
                    "total_fixed": total,
                    "critical_fixed": counts["critical"],
                    "high_fixed": counts["high"],
                    "medium_fixed": counts["medium"],
                    "low_fixed": counts["low"]
                }
                return Response(result)

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

            # Real-time countdown using full datetime (not just date)
            base_datetime = rc.updated_at or rc.created_at
            if base_datetime.tzinfo is None:
                base_datetime = base_datetime.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            def _remaining(n_days):
                deadline_dt = base_datetime + timedelta(days=n_days)
                delta = deadline_dt - now
                total_seconds = delta.total_seconds()
                if total_seconds <= 0:
                    overdue_days = math.ceil(abs(total_seconds) / 86400)
                    return {"remaining_days": overdue_days, "remaining_label": "Overdue", "status": "overdue"}
                remaining_days = math.ceil(total_seconds / 86400)
                weeks, days_left = divmod(remaining_days, 7)
                if weeks > 0 and days_left > 0:
                    label = f"{weeks} week{'s' if weeks > 1 else ''} {days_left} day{'s' if days_left > 1 else ''}"
                elif weeks > 0:
                    label = f"{weeks} week{'s' if weeks > 1 else ''}"
                else:
                    label = f"{days_left} day{'s' if days_left > 1 else ''}"
                return {"remaining_days": remaining_days, "remaining_label": label, "status": "active"}

            result = {
                "base_date": str(base_datetime.date()),
                "critical": {"raw": rc.critical, "days": c, "label": _days_to_label(c), **_remaining(c)},
                "high":     {"raw": rc.high,     "days": h, "label": _days_to_label(h), **_remaining(h)},
                "medium":   {"raw": rc.medium,   "days": m, "label": _days_to_label(m), **_remaining(m)},
                "low":      {"raw": rc.low,       "days": l, "label": _days_to_label(l), **_remaining(l)},
                "total":    {"days": t, "hours": _days_to_hours(t), "label": _days_to_label(t)}
            }
            return Response(result)

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

            result = {
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
            }
            return Response(result)

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

                result = {
                    "report_id": report_id,
                    "total": pending + closed,
                    "pending": pending,
                    "closed": closed
                }
                return Response(result)

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


class UserInProcessRemediationTimelineAPIView(APIView):
    """
    GET /api/user/dashboard/remediation-timeline/in-process/
    Shows only started-but-not-completed vulnerabilities:
    completed_steps > 0 and completed_steps < total_steps
    Optional: ?team=Patch+Management
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"report_id": None, "teams": [], "total": 0, "items": []})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            teams_lower = _normalize_teams(active_teams)

            with MongoContext() as db:
                report_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not report_doc:
                    return Response({"report_id": None, "teams": active_teams, "total": 0, "items": []})

                report_id = str(report_doc.get("report_id") or report_doc.get("_id", ""))
                admin_id = str(admin_user.id)

                card_by_host = {}
                card_by_name = {}
                for card in db[VULN_CARD_COLLECTION].find({"report_id": report_id}):
                    vuln_name = (card.get("vulnerability_name") or "").strip()
                    host_name = (card.get("host_name") or "").strip()
                    if not vuln_name:
                        continue
                    if host_name:
                        card_by_host[(vuln_name, host_name)] = card
                    if vuln_name not in card_by_name:
                        card_by_name[vuln_name] = card

                steps_coll = db[FIX_VULN_STEPS_COLLECTION]
                # Include both admin-created and team-user-created records
                # for this admin/report, then apply team filter below.
                fix_docs = list(db[FIX_VULN_COLLECTION].find({
                    "report_id": report_id,
                    "$or": [
                        {"created_by": admin_id},
                        {"admin_id": admin_id},
                    ],
                }))
                closed_docs = list(db[FIX_VULN_CLOSED_COLLECTION].find({
                    "report_id": report_id,
                    "$or": [
                        {"created_by": admin_id},
                        {"admin_id": admin_id},
                    ],
                }))

                closed_fix_ids = set()
                closed_keys = set()
                for cdoc in closed_docs:
                    cfid = str(cdoc.get("fix_vulnerability_id") or "").strip()
                    if cfid:
                        closed_fix_ids.add(cfid)
                    cpname = (cdoc.get("plugin_name") or "").strip()
                    chost = (cdoc.get("host_name") or "").strip()
                    if cpname and chost:
                        closed_keys.add((cpname, chost))

                dedup_items = {}
                for fix_doc in fix_docs:
                    fix_id = str(fix_doc.get("_id", ""))
                    vuln_name = (fix_doc.get("plugin_name") or "").strip()
                    asset = (fix_doc.get("host_name") or "").strip()
                    if not fix_id or not vuln_name:
                        continue

                    # Do not show vulnerabilities that are already closed.
                    if fix_id in closed_fix_ids or (vuln_name, asset) in closed_keys:
                        continue

                    card = card_by_host.get((vuln_name, asset)) or card_by_name.get(vuln_name) or {}
                    assigned_team_raw = (card.get("assigned_team") or fix_doc.get("assigned_team") or "").strip()
                    assigned_team = teams_lower.get(assigned_team_raw.lower())
                    if not assigned_team:
                        continue

                    mitigation_table = card.get("mitigation_table") or fix_doc.get("steps_to_fix") or []
                    total_steps = _extract_total_steps(mitigation_table) or 6

                    completed_steps = steps_coll.count_documents({
                        "fix_vulnerability_id": fix_id,
                        "status": "completed",
                    })

                    if completed_steps <= 0 or completed_steps >= total_steps:
                        continue

                    progress_percent = int(round((completed_steps / total_steps) * 100))
                    risk_raw = card.get("risk_factor") or fix_doc.get("risk_factor") or fix_doc.get("severity") or ""

                    item = {
                        "fix_vulnerability_id": fix_id,
                        "vulnerability_name": vuln_name,
                        "asset": asset,
                        "completed_steps": completed_steps,
                        "total_steps": total_steps,
                        "progress_percent": progress_percent,
                        "timeline_status": "in_process",
                        "risk_factor": str(risk_raw).strip().title() if risk_raw else "",
                        "assigned_team": assigned_team,
                    }

                    # Deduplicate repeated rows for same vuln+asset; keep most progressed/latest.
                    dedup_key = (vuln_name, asset)
                    created_at = fix_doc.get("created_at")
                    if hasattr(created_at, "timestamp"):
                        created_rank = created_at.timestamp()
                    else:
                        created_rank = 0
                    rank = (completed_steps, created_rank)
                    prev = dedup_items.get(dedup_key)
                    if not prev or rank > prev["rank"]:
                        dedup_items[dedup_key] = {"rank": rank, "item": item}

                items = [v["item"] for v in dedup_items.values()]
                items.sort(key=lambda x: (-x["progress_percent"], x["vulnerability_name"], x["asset"]))
                return Response({
                    "report_id": report_id,
                    "teams": active_teams,
                    "total": len(items),
                    "items": items,
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


class UserMitigationTimelineExtensionAPIView(APIView):
    """
    Team-wise severity counts for mitigation timeline extension card (user scope).
    Includes only teams assigned to user and (when present) vulnerabilities
    where the user appears in assigned_team_members.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"report_id": None, "teams": []})

            selected_team = request.query_params.get("team", "").strip()
            active_teams = [selected_team] if selected_team and selected_team in teams else teams
            team_lookup = _normalize_teams(active_teams)

            with MongoContext() as db:
                report_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not report_doc:
                    return Response({
                        "report_id": None,
                        "teams": [{"team": t, "critical": 0, "high": 0, "medium": 0, "low": 0} for t in active_teams],
                    })

                report_id = str(report_doc.get("report_id") or report_doc.get("_id", ""))

                buckets = {t: {"team": t, "critical": 0, "high": 0, "medium": 0, "low": 0} for t in active_teams}

                # Build plugin_name -> normalized severity map from latest report.
                plugin_risk = {}
                for host in report_doc.get("vulnerabilities_by_host", []):
                    for vuln in host.get("vulnerabilities", []):
                        pname = (
                            vuln.get("plugin_name")
                            or vuln.get("pluginname")
                            or vuln.get("name")
                            or ""
                        ).strip()
                        if not pname or pname in plugin_risk:
                            continue
                        raw = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
                        if raw.startswith("crit"):
                            plugin_risk[pname] = "critical"
                        elif raw.startswith("high"):
                            plugin_risk[pname] = "high"
                        elif raw.startswith("med"):
                            plugin_risk[pname] = "medium"
                        elif raw.startswith("low"):
                            plugin_risk[pname] = "low"

                # Count all vulnerabilities assigned to user's teams from vulnerability_cards.
                seen = set()
                for card in db[VULN_CARD_COLLECTION].find({"report_id": report_id}):
                    vuln_name = (card.get("vulnerability_name") or "").strip()
                    host_name = (card.get("host_name") or "").strip()
                    raw_team = (card.get("assigned_team") or "").strip()
                    team = team_lookup.get(raw_team.lower())
                    if not vuln_name or not team:
                        continue

                    key = (vuln_name, host_name)
                    if key in seen:
                        continue
                    seen.add(key)

                    risk = plugin_risk.get(vuln_name)
                    if risk in ("critical", "high", "medium", "low"):
                        buckets[team][risk] += 1

                return Response({"report_id": report_id, "teams": [buckets[t] for t in active_teams]})

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


class UserMitigationTimelineExtensionOptionsAPIView(APIView):
    """
    Form options for extension request.
    GET /api/user/dashboard/mitigation-timeline-extension/options/?severity=high&asset=1.1.1.1
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"report_id": None, "assets": [], "vulnerabilities": []})

            raw_team = (request.query_params.get("team") or "").strip()
            raw_severity = (request.query_params.get("severity") or "").strip()
            if not raw_team:
                return Response({"detail": "team query param is required"}, status=status.HTTP_400_BAD_REQUEST)
            if not raw_severity:
                return Response({"detail": "severity query param is required"}, status=status.HTTP_400_BAD_REQUEST)

            severity_filter = _normalize_severity_key(raw_severity)
            if not severity_filter:
                return Response({"detail": "invalid severity. Use critical/high/medium/low"}, status=status.HTTP_400_BAD_REQUEST)

            asset_filter = (request.query_params.get("asset") or "").strip()
            team_lookup = _normalize_teams(teams)
            selected_team = team_lookup.get(raw_team.lower())
            if not selected_team:
                return Response({"detail": "selected team is not assigned to this user"}, status=status.HTTP_403_FORBIDDEN)

            with MongoContext() as db:
                report_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not report_doc:
                    return Response({"report_id": None, "assets": [], "vulnerabilities": []})

                report_id = str(report_doc.get("report_id") or report_doc.get("_id", ""))
                plugin_severity = _build_plugin_severity_map(report_doc)
                rc = _get_admin_riskcriteria(admin_user)

                assets = set()
                vulnerabilities = set()

                for card in db[VULN_CARD_COLLECTION].find({"report_id": report_id}):
                    team = (card.get("assigned_team") or "").strip()
                    if team.lower() != selected_team.lower():
                        continue

                    vuln_name = (card.get("vulnerability_name") or "").strip()
                    host_name = (card.get("host_name") or "").strip()
                    sev = plugin_severity.get(vuln_name)
                    if sev != severity_filter:
                        continue

                    if host_name:
                        assets.add(host_name)
                    if (not asset_filter or host_name == asset_filter) and vuln_name:
                        vulnerabilities.add(vuln_name)

                original_deadline_days = None
                if rc and severity_filter:
                    if severity_filter == "critical":
                        original_deadline_days = _parse_timeline_to_days(rc.critical)
                    elif severity_filter == "high":
                        original_deadline_days = _parse_timeline_to_days(rc.high)
                    elif severity_filter == "medium":
                        original_deadline_days = _parse_timeline_to_days(rc.medium)
                    else:
                        original_deadline_days = _parse_timeline_to_days(rc.low)

                return Response({
                    "report_id": report_id,
                    "team": selected_team,
                    "severity": severity_filter,
                    "assets": sorted(assets),
                    "vulnerabilities": sorted(vulnerabilities),
                    "original_deadline_days": original_deadline_days,
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


class UserMitigationTimelineExtensionCreateAPIView(APIView):
    """
    Create extension request.
    POST /api/user/dashboard/mitigation-timeline-extension/request/
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"detail": "User is not linked to any team"}, status=status.HTTP_403_FORBIDDEN)

            severity = _normalize_severity_key(request.data.get("severity"))
            asset = (request.data.get("asset") or "").strip()
            vulnerability_name = (request.data.get("vulnerability_name") or "").strip()
            reason = (request.data.get("reason") or "").strip()
            requested_extension_days = int(request.data.get("requested_extension_days") or 0)

            if not severity or not asset or not vulnerability_name or requested_extension_days <= 0 or not reason:
                return Response({"detail": "severity, asset, vulnerability_name, requested_extension_days, reason are required"}, status=status.HTTP_400_BAD_REQUEST)

            team_lookup = _normalize_teams(teams)
            current_email = (request.user.email or "").strip().lower()
            current_user_id = str(request.user.id)

            with MongoContext() as db:
                report_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                if not report_doc:
                    return Response({"detail": "No report found"}, status=status.HTTP_404_NOT_FOUND)
                report_id = str(report_doc.get("report_id") or report_doc.get("_id", ""))
                plugin_severity = _build_plugin_severity_map(report_doc)

                # Validate user has access to selected vulnerability in selected asset/team.
                selected_card = None
                for card in db[VULN_CARD_COLLECTION].find({"report_id": report_id, "host_name": asset, "vulnerability_name": vulnerability_name}):
                    team_name = (card.get("assigned_team") or "").strip()
                    if not team_lookup.get(team_name.lower()):
                        continue
                    members = card.get("assigned_team_members") or []
                    if members:
                        is_assigned = False
                        for m in members:
                            m_uid = str(m.get("user_id") or "").strip()
                            m_email = str(m.get("email") or "").strip().lower()
                            if (m_uid and m_uid == current_user_id) or (m_email and m_email == current_email):
                                is_assigned = True
                                break
                        if not is_assigned:
                            continue
                    selected_card = card
                    break

                if not selected_card:
                    return Response({"detail": "Selected asset/vulnerability is not assigned to your team"}, status=status.HTTP_403_FORBIDDEN)

                detected_severity = plugin_severity.get(vulnerability_name)
                if detected_severity and detected_severity != severity:
                    return Response({"detail": "Selected severity does not match vulnerability severity"}, status=status.HTTP_400_BAD_REQUEST)

                rc = _get_admin_riskcriteria(admin_user)
                if not rc:
                    return Response({"detail": "Risk criteria not set by admin"}, status=status.HTTP_404_NOT_FOUND)

                if severity == "critical":
                    original_days = _parse_timeline_to_days(rc.critical)
                elif severity == "high":
                    original_days = _parse_timeline_to_days(rc.high)
                elif severity == "medium":
                    original_days = _parse_timeline_to_days(rc.medium)
                else:
                    original_days = _parse_timeline_to_days(rc.low)

                coll = db[TIMELINE_EXTENSION_COLLECTION]
                dup = coll.find_one({
                    "admin_id": str(admin_user.id),
                    "report_id": report_id,
                    "asset": asset,
                    "vulnerability_name": vulnerability_name,
                    "severity": severity,
                    "status": "review",
                })
                if dup:
                    return Response({"detail": "Pending request already exists for this vulnerability"}, status=status.HTTP_400_BAD_REQUEST)

                payload = {
                    "report_id": report_id,
                    "admin_id": str(admin_user.id),
                    "team_name": (selected_card.get("assigned_team") or "").strip(),
                    "asset": asset,
                    "vulnerability_name": vulnerability_name,
                    "severity": severity,
                    "requested_by_user_id": current_user_id,
                    "requested_by_email": request.user.email,
                    "request_date": datetime.utcnow(),
                    "original_deadline_days": int(original_days or 0),
                    "requested_extension_days": requested_extension_days,
                    "reason": reason,
                    "status": "review",
                    "risk_criteria_updated": False,
                }
                result = coll.insert_one(payload)

                return Response({
                    "message": "Extension request submitted",
                    "request_id": str(result.inserted_id),
                    "status": "review",
                }, status=status.HTTP_201_CREATED)

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


class UserMitigationTimelineExtensionReportAPIView(APIView):
    """
    View extension requests report for user teams.
    GET /api/user/dashboard/mitigation-timeline-extension/report/
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            teams, admin_user = _get_user_context(request.user.email)
            if not teams or not admin_user:
                return Response({"count": 0, "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0}, "results": []})

            team_lookup = _normalize_teams(teams)
            severity_filter = _normalize_severity_key(request.query_params.get("severity"))
            status_filter = (request.query_params.get("status") or "").strip().lower()

            with MongoContext() as db:
                coll = db[TIMELINE_EXTENSION_COLLECTION]
                report_doc = _load_latest_report(db, admin_user.id, admin_user.email)
                report_id = str(report_doc.get("report_id") or report_doc.get("_id", "")) if report_doc else None

                query = {"admin_id": str(admin_user.id)}
                if report_id:
                    query["report_id"] = report_id
                if status_filter in {"review", "approved", "rejected"}:
                    query["status"] = status_filter

                docs = list(coll.find(query).sort("request_date", -1))

                results = []
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
                for doc in docs:
                    team_name = (doc.get("team_name") or "").strip()
                    if not team_lookup.get(team_name.lower()):
                        continue

                    severity = _normalize_severity_key(doc.get("severity"))
                    if not severity:
                        continue
                    if severity_filter and severity != severity_filter:
                        continue

                    severity_counts[severity] += 1
                    results.append({
                        "request_id": str(doc.get("_id")),
                        "severity": severity,
                        "asset": doc.get("asset"),
                        "vul_name": doc.get("vulnerability_name"),
                        "status": doc.get("status", "review"),
                        "requested_by": team_name,
                        "request_date": _to_iso(doc.get("request_date")),
                        "extension_days": int(doc.get("requested_extension_days") or 0),
                        "reason": doc.get("reason") or "",
                    })

                return Response({
                    "report_id": report_id,
                    "count": len(results),
                    "severity_counts": severity_counts,
                    "results": results,
                })

        except Exception as e:
            import traceback; traceback.print_exc()
            return Response({"detail": str(e)}, status=500)


# ─────────────────────────────────────────────────────────────────────────────
# 9. FULL DASHBOARD SUMMARY
# ─────────────────────────────────────────────────────────────────────────────

# class UserDashboardSummaryAPIView(APIView):
#     """
#     GET /api/user/dashboard/summary/
#     All metrics in one call. Optional: ?team=Patch+Management
#     """
#     permission_classes = [IsAuthenticated]

#     def get(self, request):
#         try:
#             teams, admin_user = _get_user_context(request.user.email)

#             if not teams or not admin_user:
#                 return Response({
#                     "user_email": request.user.email,
#                     "teams": [],
#                     "total_assets": 0,
#                     "by_team_assets": {},
#                     "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
#                     "vulnerabilities_fixed": {"total_fixed": 0, "critical_fixed": 0, "high_fixed": 0, "medium_fixed": 0, "low_fixed": 0},
#                     "mitigation_timeline": None,
#                     "mean_time_to_remediate": None,
#                     "support_requests": {"total": 0, "pending": 0, "closed": 0},
#                     "message": "User is not linked to any team. Ask your admin to assign you a team."
#                 })

#             selected_team = request.query_params.get("team", "").strip()
#             active_teams  = [selected_team] if selected_team and selected_team in teams else teams
#             teams_lower   = _normalize_teams(active_teams)

#             with MongoContext() as db:
#                 nessus_doc = _load_latest_report(db, admin_user.id, admin_user.email)

#                 if not nessus_doc:
#                     return Response({
#                         "user_email": request.user.email,
#                         "teams": active_teams,
#                         "total_assets": 0,
#                         "by_team_assets": {},
#                         "vulnerabilities": {"critical": 0, "high": 0, "medium": 0, "low": 0},
#                         "vulnerabilities_fixed": {"total_fixed": 0, "critical_fixed": 0, "high_fixed": 0, "medium_fixed": 0, "low_fixed": 0},
#                         "mitigation_timeline": None,
#                         "mean_time_to_remediate": None,
#                         "support_requests": {"total": 0, "pending": 0, "closed": 0},
#                         "message": "No report uploaded yet."
#                     })

#                 report_id   = nessus_doc.get("report_id") or str(nessus_doc.get("_id", ""))
#                 plugin_risk = _build_plugin_risk_map(nessus_doc)
#                 admin_id    = str(admin_user.id)

#                 # Per-team buckets
#                 by_team_hosts  = {t: set() for t in active_teams}
#                 vuln_counts    = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#                 team_plugins   = set()

#                 # Build plugin_name -> matched_team from cards; count vulns
#                 plugin_team_map = {}
#                 for card in db[VULN_CARD_COLLECTION].find({"report_id": str(report_id)}):
#                     raw_team = (card.get("assigned_team") or "").strip()
#                     matched  = teams_lower.get(raw_team.lower())
#                     if not matched:
#                         continue
#                     pname = (card.get("vulnerability_name") or "").strip()
#                     if pname:
#                         team_plugins.add(pname)
#                         plugin_team_map[pname] = matched
#                     risk = plugin_risk.get(pname)
#                     if risk in vuln_counts:
#                         vuln_counts[risk] += 1

#                 # Count assets from nessus doc using host-ip fallback
#                 for host in (nessus_doc.get("vulnerabilities_by_host") or []):
#                     host_info = host.get("host_information") or {}
#                     h_name = (
#                         host.get("host_name") or host.get("host")
#                         or host_info.get("host-ip") or host_info.get("host-fqdn") or ""
#                     )
#                     if isinstance(h_name, str):
#                         h_name = h_name.strip()
#                     if not h_name:
#                         continue
#                     for v in (host.get("vulnerabilities") or []):
#                         pname = (
#                             v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
#                         ).strip()
#                         matched = plugin_team_map.get(pname)
#                         if matched:
#                             by_team_hosts[matched].add(h_name)

#                 all_hosts      = set().union(*by_team_hosts.values())
#                 by_team_assets = {t: len(hosts) for t, hosts in by_team_hosts.items()}

#                 # ---- Fixed vulnerabilities ----
#                 fixed_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
#                 for vuln in db[FIX_VULN_CLOSED_COLLECTION].find({
#                     "created_by": admin_id,
#                     "status": "closed",
#                     "report_id": str(report_id)
#                 }):
#                     pname = (vuln.get("plugin_name") or "").strip()
#                     if pname not in team_plugins:
#                         continue
#                     risk = (vuln.get("risk_factor") or vuln.get("severity") or "").strip().lower()
#                     if risk.startswith("crit"):
#                         fixed_counts["critical"] += 1
#                     elif risk.startswith("high"):
#                         fixed_counts["high"] += 1
#                     elif risk.startswith("med"):
#                         fixed_counts["medium"] += 1
#                     elif risk.startswith("low"):
#                         fixed_counts["low"] += 1

#                 # ---- Support requests ----
#                 base_q = {
#                     "admin_id": admin_id,
#                     "report_id": str(report_id),
#                     "vul_name": {"$in": list(team_plugins)}
#                 }
#                 support_coll  = db[SUPPORT_REQUEST_COLLECTION]
#                 pending_count = support_coll.count_documents({**base_q, "status": {"$ne": "closed"}})
#                 closed_count  = support_coll.count_documents({**base_q, "status": "closed"})

#             # ---- Risk criteria / timeline / MTTR ----
#             rc = _get_admin_riskcriteria(admin_user)
#             mitigation_timeline    = None
#             mean_time_to_remediate = None

#             if rc:
#                 c_d = _parse_timeline_to_days(rc.critical)
#                 h_d = _parse_timeline_to_days(rc.high)
#                 m_d = _parse_timeline_to_days(rc.medium)
#                 l_d = _parse_timeline_to_days(rc.low)
#                 t_d = c_d + h_d + m_d + l_d

#                 mitigation_timeline = {
#                     "critical": {"raw": rc.critical, "days": c_d, "label": _days_to_label(c_d)},
#                     "high":     {"raw": rc.high,     "days": h_d, "label": _days_to_label(h_d)},
#                     "medium":   {"raw": rc.medium,   "days": m_d, "label": _days_to_label(m_d)},
#                     "low":      {"raw": rc.low,       "days": l_d, "label": _days_to_label(l_d)},
#                     "total":    {"days": t_d, "hours": _days_to_hours(t_d), "label": _days_to_label(t_d)},
#                 }

#                 c_h  = _days_to_hours(c_d)
#                 h_h  = _days_to_hours(h_d)
#                 m_h  = _days_to_hours(m_d)
#                 l_h  = _days_to_hours(l_d)
#                 mttr = round((c_h + h_h + m_h + l_h) / 4)
#                 wdh  = _hours_to_wdh(mttr)

#                 mean_time_to_remediate = {
#                     "hours": mttr,
#                     "weeks": wdh["weeks"],
#                     "days":  wdh["days"],
#                     "hours_remaining": wdh["hours"],
#                     "label": _format_wdh_label(wdh)
#                 }

#             summary = {
#                 "user_email": request.user.email,
#                 "report_id": report_id,
#                 "teams": active_teams,
#                 "selected_team": selected_team or None,
#                 "total_assets": len(all_hosts),
#                 "by_team_assets": by_team_assets,
#                 "vulnerabilities": vuln_counts,
#                 "vulnerabilities_fixed": {
#                     "total_fixed": sum(fixed_counts.values()),
#                     "critical_fixed": fixed_counts["critical"],
#                     "high_fixed":     fixed_counts["high"],
#                     "medium_fixed":   fixed_counts["medium"],
#                     "low_fixed":      fixed_counts["low"],
#                 },
#                 "mitigation_timeline": mitigation_timeline,
#                 "mean_time_to_remediate": mean_time_to_remediate,
#                 "support_requests": {
#                     "total":   pending_count + closed_count,
#                     "pending": pending_count,
#                     "closed":  closed_count,
#                 },
#             }
#             return Response(summary)

#         except Exception as e:
#             import traceback; traceback.print_exc()
#             return Response({"detail": str(e)}, status=500)
