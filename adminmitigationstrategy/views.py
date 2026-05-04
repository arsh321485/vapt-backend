from django.shortcuts import render

# Create your views here.
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

from upload_report.models import UploadReport

# ── Collection names ────────────────────────────────────────────────────────
NESSUS_COLLECTION          = "nessus_reports"
FIX_VULN_CLOSED_COLLECTION = "fix_vulnerabilities_closed"
VULN_CARD_COLLECTION       = "vulnerability_cards"

TEAM_NAMES = [
    "Patch Management",
    "Network Security",
    "Architectural Flaws",
    "Configuration Management",
]

# ── Shared MongoDB connection pool ──────────────────────────────────────────
from vaptfix.mongo_client import MongoContext
from vaptfix.mongo_client import ensure_performance_indexes


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


# ── API View ─────────────────────────────────────────────────────────────────

class MitigationStrategyByTeamAPIView(APIView):
    """
    Returns vulnerabilities from latest nessus report, grouped by assigned_team.
    Team is fetched from vulnerability_cards collection (matched by report_id + vulnerability_name + host_name).

    GET /api/admin/adminmitigation-strategy/by-team/
    """

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [JSONParser]

    def get(self, request):
        try:
            current_admin_id    = str(request.user.id)
            current_admin_email = getattr(request.user, "email", None)

            with MongoContext() as db:
                ensure_performance_indexes(db)
                nessus_coll     = db[NESSUS_COLLECTION]
                closed_coll     = db[FIX_VULN_CLOSED_COLLECTION]
                vuln_card_coll  = db[VULN_CARD_COLLECTION]

                # Latest report for this admin
                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                latest_doc = nessus_coll.find_one(
                    {"$or": query_conditions},
                    {
                        "report_id": 1,
                        "admin_id": 1,
                        "uploaded_at": 1,
                        "vulnerabilities_by_host.host_name": 1,
                        "vulnerabilities_by_host.host": 1,
                        "vulnerabilities_by_host.host_information": 1,
                        "vulnerabilities_by_host.vulnerabilities.plugin_name": 1,
                        "vulnerabilities_by_host.vulnerabilities.pluginname": 1,
                        "vulnerabilities_by_host.vulnerabilities.name": 1,
                        "vulnerabilities_by_host.vulnerabilities.port": 1,
                        "vulnerabilities_by_host.vulnerabilities.protocol": 1,
                        "vulnerabilities_by_host.vulnerabilities.risk_factor": 1,
                        "vulnerabilities_by_host.vulnerabilities.severity": 1,
                        "vulnerabilities_by_host.vulnerabilities.risk": 1,
                    },
                    sort=[("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))
                admin_id  = latest_doc.get("admin_id", current_admin_id)

                # upload_reports status
                report_status = "unknown"
                try:
                    upload_obj = UploadReport.objects.filter(
                        _id=ObjectId(report_id)
                    ).first()
                    if upload_obj:
                        report_status = upload_obj.status or "unknown"
                except Exception as e:
                    logger.warning("Suppressed error: %s", e)

                # Build closed vulnerability keys set
                closed_vulns = set()
                for doc in closed_coll.find(
                    {"report_id": report_id, "created_by": admin_id},
                    {"plugin_name": 1, "host_name": 1, "port": 1},
                ):
                    closed_vulns.add((
                        doc.get("plugin_name", ""),
                        doc.get("host_name", ""),
                        str(doc.get("port", "")),
                    ))

                # Bulk-fetch all vulnerability_cards for this report
                vuln_cards = {}
                for card in vuln_card_coll.find(
                    {"report_id": report_id},
                    {"vulnerability_name": 1, "host_name": 1, "assigned_team": 1},
                ):
                    key = (
                        card.get("vulnerability_name", ""),
                        card.get("host_name", ""),
                    )
                    vuln_cards[key] = card

                # Pre-pass: find plugin_names that appear on 4+ different assets
                plugin_asset_map = {}
                for host in latest_doc.get("vulnerabilities_by_host", []):
                    _host_name = host.get("host_name") or host.get("host") or ""
                    for v in host.get("vulnerabilities", []):
                        _pname = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )
                        if _pname:
                            plugin_asset_map.setdefault(_pname, set()).add(_host_name)

                multi_asset_plugins = {
                    p for p, assets in plugin_asset_map.items() if len(assets) > 3
                }

                # Initialize team buckets
                teams = {name: [] for name in TEAM_NAMES}
                teams["Unassigned"] = []

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
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        )

                        # Only include vulns that appear on 2+ different assets
                        if plugin_name not in multi_asset_plugins:
                            continue

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

                        # Lookup assigned_team from vulnerability_cards
                        card = (
                            vuln_cards.get((plugin_name, host_name))
                            or vuln_cards.get((plugin_name, ""))
                        )
                        assigned_team = (card or {}).get("assigned_team", "") or ""

                        row = {
                            "id":            str(uuid.uuid4()),
                            "host_name":     host_name,
                            "os":            os_value,
                            "plugin_name":   plugin_name,
                            "risk_factor":   risk_factor,
                            "port":          port,
                            "protocol":      protocol,
                            "status":        vuln_status,
                            "assigned_team": assigned_team,
                        }

                        if assigned_team in teams:
                            teams[assigned_team].append(row)
                        else:
                            teams["Unassigned"].append(row)

                teams_response = {
                    team_name: {
                        "count": len(vulns),
                        "vulnerabilities": vulns,
                    }
                    for team_name, vulns in teams.items()
                }

                return Response(
                    {
                        "report_id":     report_id,
                        "report_status": report_status,
                        "admin_id":      current_admin_id,
                        "admin_email":   current_admin_email,
                        "uploaded_at":   _normalize_iso(latest_doc.get("uploaded_at")),
                        "teams":         teams_response,
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


class VulnerabilityAssetCountAPIView(APIView):
    """
    Returns each unique vulnerability name with the count and list of assets it appears in.

    GET /api/admin/adminmitigation-strategy/vuln-asset-count/
    """

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        try:
            current_admin_id    = str(request.user.id)
            current_admin_email = getattr(request.user, "email", None)

            with MongoContext() as db:
                ensure_performance_indexes(db)
                nessus_coll    = db[NESSUS_COLLECTION]
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                query_conditions = [{"admin_id": current_admin_id}]
                if current_admin_email:
                    query_conditions.append({"admin_email": current_admin_email})

                latest_doc = nessus_coll.find_one(
                    {"$or": query_conditions},
                    {
                        "report_id": 1,
                        "vulnerabilities_by_host.host_name": 1,
                        "vulnerabilities_by_host.host": 1,
                        "vulnerabilities_by_host.vulnerabilities.plugin_name": 1,
                        "vulnerabilities_by_host.vulnerabilities.pluginname": 1,
                        "vulnerabilities_by_host.vulnerabilities.name": 1,
                    },
                    sort=[("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your account"},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))

                # Build plugin_name -> assigned_team from vulnerability_cards
                plugin_team_map = {}
                for card in vuln_card_coll.find(
                    {"report_id": report_id},
                    {"vulnerability_name": 1, "assigned_team": 1}
                ):
                    vname = card.get("vulnerability_name", "")
                    team  = card.get("assigned_team", "") or ""
                    if vname and vname not in plugin_team_map:
                        plugin_team_map[vname] = team

                # Group: plugin_name -> set of host_names
                plugin_map = {}

                for host in latest_doc.get("vulnerabilities_by_host", []):
                    host_name = (host.get("host_name") or host.get("host") or "").strip()

                    for v in host.get("vulnerabilities", []):
                        plugin_name = (
                            v.get("plugin_name")
                            or v.get("pluginname")
                            or v.get("name")
                            or ""
                        ).strip()

                        if not plugin_name:
                            continue

                        if plugin_name not in plugin_map:
                            plugin_map[plugin_name] = set()
                        plugin_map[plugin_name].add(host_name)

                # Initialize team buckets
                teams = {name: [] for name in TEAM_NAMES}
                teams["Unassigned"] = []

                # Only include vulns that appear on 4+ DIFFERENT assets, grouped by team
                for plugin_name, assets in plugin_map.items():
                    if len(assets) <= 3:
                        continue
                    entry = {
                        "plugin_name": plugin_name,
                        "asset_count": len(assets),
                        "assets":      sorted(assets),
                    }
                    assigned_team = plugin_team_map.get(plugin_name, "")
                    if assigned_team in teams:
                        teams[assigned_team].append(entry)
                    else:
                        teams["Unassigned"].append(entry)

                # Sort each team's vulnerabilities by asset_count descending
                teams_response = {
                    team_name: {
                        "total_unique_vulnerabilities": len(vulns),
                        "vulnerabilities": sorted(vulns, key=lambda x: x["asset_count"], reverse=True),
                    }
                    for team_name, vulns in teams.items()
                }

                return Response(
                    {
                        "report_id": report_id,
                        "teams":     teams_response,
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
