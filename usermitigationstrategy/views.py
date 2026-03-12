from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.parsers import JSONParser
from datetime import datetime
from django.utils.timezone import is_naive, make_aware
import pymongo

from vaptfix.mongo_client import MongoContext

NESSUS_COLLECTION          = "nessus_reports"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
VULN_CARD_COLLECTION       = "vulnerability_cards"


def _get_member_detail(user):
    """Fetch UserDetail for the logged-in member by email."""
    from users_details.models import UserDetail
    return UserDetail.objects.filter(email__iexact=user.email).first()


def _normalize_iso(dt):
    if not dt:
        return None
    if isinstance(dt, datetime):
        d = make_aware(dt) if is_naive(dt) else dt
        return d.isoformat()
    return str(dt)


class UserMitigationStrategyByTeamAPIView(APIView):
    """
    Returns vulnerabilities from the admin's latest nessus report,
    filtered to only the teams the logged-in member belongs to.

    GET /api/user/mitigation/by-team/
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        try:
            # Step 1: Get member detail → teams + admin_id
            user_detail = _get_member_detail(request.user)
            if not user_detail:
                return Response(
                    {"detail": "Member profile not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            member_teams = user_detail.Member_role or []
            if not member_teams:
                return Response(
                    {"detail": "No teams assigned to this member."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            admin_id = str(user_detail.admin.id)

            with MongoContext() as db:
                nessus_coll    = db[NESSUS_COLLECTION]
                closed_coll    = db[FIX_VULN_CLOSED_COLLECTION]
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                # Step 2: Latest report for this admin
                latest_doc = nessus_coll.find_one(
                    {"admin_id": admin_id},
                    sort=[("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin."},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))

                # Step 3: Build closed vulnerability keys set
                closed_vulns = set()
                for doc in closed_coll.find(
                    {"report_id": report_id, "created_by": admin_id}
                ):
                    closed_vulns.add((
                        doc.get("plugin_name", ""),
                        doc.get("host_name", ""),
                        str(doc.get("port", "")),
                    ))

                # Step 4: Bulk-fetch vulnerability_cards for this report
                vuln_cards = {}
                for card in vuln_card_coll.find({"report_id": report_id}):
                    key = (
                        card.get("vulnerability_name", ""),
                        card.get("host_name", ""),
                    )
                    vuln_cards[key] = card

                # Step 5: Filter by member's teams only
                teams = {name: [] for name in member_teams}

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""
                    host_info = host.get("host_information") or {}
                    os_value  = (
                        host_info.get("os")
                        or host_info.get("operating-system")
                        or host_info.get("operating_system")
                        or host_info.get("OS")
                        or ""
                    )

                    for v in host.get("vulnerabilities", []):
                        # Same filter as admin view
                        plugin_outputs = v.get("plugin_outputs", [])
                        if not isinstance(plugin_outputs, list) or len(plugin_outputs) <= 1:
                            continue

                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )
                        port     = v.get("port", "")
                        protocol = v.get("protocol", "")
                        risk_raw = (
                            v.get("risk_factor")
                            or v.get("severity")
                            or v.get("risk")
                            or ""
                        )
                        risk_factor = (
                            risk_raw.strip().title()
                            if isinstance(risk_raw, str)
                            else ""
                        )
                        vuln_status = (
                            "closed"
                            if (plugin_name, host_name, str(port)) in closed_vulns
                            else "open"
                        )

                        card = (
                            vuln_cards.get((plugin_name, host_name))
                            or vuln_cards.get((plugin_name, ""))
                        )
                        assigned_team = (card or {}).get("assigned_team", "") or ""

                        # Only include if assigned_team is in this member's teams
                        if assigned_team not in member_teams:
                            continue

                        row = {
                            "host_name":     host_name,
                            "os":            os_value,
                            "plugin_name":   plugin_name,
                            "risk_factor":   risk_factor,
                            "port":          port,
                            "protocol":      protocol,
                            "status":        vuln_status,
                            "assigned_team": assigned_team,
                        }
                        teams[assigned_team].append(row)

                teams_response = {
                    team_name: {
                        "count":           len(vulns),
                        "vulnerabilities": vulns,
                    }
                    for team_name, vulns in teams.items()
                }

                return Response(
                    {
                        "report_id":    report_id,
                        "member_teams": member_teams,
                        "uploaded_at":  _normalize_iso(latest_doc.get("uploaded_at")),
                        "teams":        teams_response,
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


class UserVulnerabilityAssetCountAPIView(APIView):
    """
    Returns each unique vulnerability name (in member's teams) with
    the count and list of assets it appears in.

    GET /api/user/mitigation/vuln-asset-count/
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            # Step 1: Get member detail → teams + admin_id
            user_detail = _get_member_detail(request.user)
            if not user_detail:
                return Response(
                    {"detail": "Member profile not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )

            member_teams = user_detail.Member_role or []
            if not member_teams:
                return Response(
                    {"detail": "No teams assigned to this member."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            admin_id = str(user_detail.admin.id)

            with MongoContext() as db:
                nessus_coll    = db[NESSUS_COLLECTION]
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                # Step 2: Latest report for this admin
                latest_doc = nessus_coll.find_one(
                    {"admin_id": admin_id},
                    sort=[("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin."},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))

                # Step 3: Bulk-fetch vulnerability_cards
                vuln_cards = {}
                for card in vuln_card_coll.find({"report_id": report_id}):
                    key = (
                        card.get("vulnerability_name", ""),
                        card.get("host_name", ""),
                    )
                    vuln_cards[key] = card

                # Step 4: Group plugin_name -> set of host_names (filtered by member teams)
                plugin_map = {}

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = host.get("host_name") or host.get("host") or ""

                    for v in host.get("vulnerabilities", []):
                        # Same filter as admin view
                        plugin_outputs = v.get("plugin_outputs", [])
                        if not isinstance(plugin_outputs, list) or len(plugin_outputs) <= 1:
                            continue

                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        ).strip()

                        if not plugin_name:
                            continue

                        card = (
                            vuln_cards.get((plugin_name, host_name))
                            or vuln_cards.get((plugin_name, ""))
                        )
                        assigned_team = (card or {}).get("assigned_team", "") or ""

                        # Only include if assigned_team is in member's teams
                        if assigned_team not in member_teams:
                            continue

                        if plugin_name not in plugin_map:
                            plugin_map[plugin_name] = set()
                        plugin_map[plugin_name].add(host_name)

                # Step 5: Build sorted result
                result = sorted(
                    [
                        {
                            "plugin_name": plugin_name,
                            "asset_count": len(assets),
                            "assets":      sorted(assets),
                        }
                        for plugin_name, assets in plugin_map.items()
                    ],
                    key=lambda x: x["asset_count"],
                    reverse=True,
                )

                return Response(
                    {
                        "report_id":                   report_id,
                        "member_teams":                member_teams,
                        "total_unique_vulnerabilities": len(result),
                        "vulnerabilities":             result,
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
