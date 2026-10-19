from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status, permissions
from rest_framework.parsers import JSONParser
from datetime import datetime
from django.utils.timezone import is_naive, make_aware, utc
import pymongo
import uuid

from adminmitigationstrategy.views import (
    _SLUG_TO_TEAM,
    _qualifies_for_mitigation_strategy,
)
from vaptfix.mongo_client import MongoContext
from upload_report.team_utils import infer_assigned_team

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
        # Real bug report: these values come straight from raw MongoDB
        # dicts, written with plain datetime.utcnow() — always genuinely
        # UTC. make_aware() with no explicit timezone mislabels them using
        # the current TIME_ZONE (Asia/Kolkata) instead, shifting by 5:30
        # in the wrong direction. Pass utc explicitly.
        d = make_aware(dt, utc) if is_naive(dt) else dt
        return d.isoformat()
    return str(dt)


def _normalize_team_name(raw_team):
    raw = (raw_team or "").strip()
    return _SLUG_TO_TEAM.get(raw.lower(), raw)


class UserMitigationStrategyByTeamAPIView(APIView):
    """
    Returns vulnerabilities from the admin's latest nessus report,
    filtered to only the teams the logged-in member belongs to.

    GET /api/user/usermitigationstrategy/by-team/

    Only includes vulnerabilities present on 4+ distinct assets (more than 3).
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

            member_teams_normalized = {_normalize_team_name(t) for t in member_teams}

            # Optional: ?team=<team name> — narrows to just that one team
            # (must be one of the member's own teams); omitted/invalid falls
            # back to all of them, same as before. Matches the ?team=
            # convention already used by userdashboard's views, so the Home
            # page's team dropdown can carry its selection through here too.
            selected_team = _normalize_team_name(request.query_params.get("team", "").strip())
            if selected_team and selected_team in member_teams_normalized:
                member_teams_normalized = {selected_team}

            admin_id = str(user_detail.admin.id)

            with MongoContext() as db:
                nessus_coll    = db[NESSUS_COLLECTION]
                closed_coll    = db[FIX_VULN_CLOSED_COLLECTION]
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                # Step 2: this admin's REAL primary report — sorted by
                # total_vulnerabilities first, not just uploaded_at, so a
                # small claim-link auto-split fragment can't outrank this
                # admin's real, bigger, properly-merged report (same fix
                # as resolve_report_id_for_upload/admindashboard.views.
                # _load_latest_report_for_admin).
                latest_doc = nessus_coll.find_one(
                    {"admin_id": admin_id},
                    sort=[("total_vulnerabilities", pymongo.DESCENDING), ("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin."},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))

                # Step 3: Build closed vulnerability keys set
                # Real bug report: filtering on created_by=admin_id here
                # silently dropped every real closed doc, since a doc's own
                # "created_by" is whoever (the team member) actually closed
                # it, not the admin — report_id is already inherently
                # admin-scoped (matched to this admin's own report above),
                # so this extra filter is redundant and, per the identical
                # fix already applied on the admin-side endpoint
                # (adminmitigationstrategy.MitigationStrategyByTeamAPIView),
                # unsafe on top of that.
                closed_vulns = set()
                closed_vuln_host_set = set()
                for doc in closed_coll.find({"report_id": report_id}):
                    _pname = doc.get("plugin_name", "")
                    _hname = doc.get("host_name", "")
                    closed_vulns.add((_pname, _hname, str(doc.get("port", ""))))
                    # Real bug report: same fix as the admin-side endpoint —
                    # a vuln closed on one port of a host still had other
                    # ports of the same (vuln, host) pair open, collapsing
                    # the merged row back to "open". Match
                    # AllVulnerabilitiesAPIView's pair-level "closed"
                    # definition (no per-port requirement) instead.
                    closed_vuln_host_set.add((_pname, _hname))

                # Step 4: Bulk-fetch vulnerability_cards for this report
                vuln_cards = {}
                for card in vuln_card_coll.find({"report_id": report_id}):
                    key = (
                        card.get("vulnerability_name", ""),
                        card.get("host_name", ""),
                    )
                    vuln_cards[key] = card

                # Step 5: Pre-pass — find plugin_names on 4+ different assets
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
                    p for p, assets in plugin_asset_map.items()
                    if _qualifies_for_mitigation_strategy(len(assets))
                }
                plugin_asset_counts = {
                    p: len(assets) for p, assets in plugin_asset_map.items()
                }

                # Step 6: Filter by member's teams only
                teams = {name: [] for name in member_teams_normalized}

                # Same fix as the admin-side endpoint (adminmitigationstrategy.
                # MitigationStrategyByTeamAPIView) — the same vulnerability on
                # the same host but a different port produced a separate row
                # each time; one row per (host, vulnerability) here instead,
                # merging to "open" if any port instance is still open.
                seen_host_vuln_row = {}

                # Real bug report: "4+ assets" (multi_asset_plugins above)
                # was decided once, GLOBALLY across the whole report — a
                # finding common enough report-wide still showed up under a
                # team whose own assets barely touch it, with asset_count
                # reflecting the global total instead of that team's own.
                # Collect rows per team first, then decide per-team whether
                # a plugin genuinely has 4+ of THAT team's own assets.
                all_rows = []  # [(row, matched_teams)]
                team_plugin_hosts = {}

                def _add_team_plugin_host(team_name, plugin_name, host_name):
                    team_plugin_hosts.setdefault(team_name, {}).setdefault(plugin_name, set()).add(host_name)

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
                            if (plugin_name, host_name) in closed_vuln_host_set
                            else "open"
                        )

                        # Only include vulns on 4+ different assets
                        if plugin_name not in multi_asset_plugins:
                            continue

                        card = (
                            vuln_cards.get((plugin_name, host_name))
                            or vuln_cards.get((plugin_name, ""))
                        )
                        _raw_team = (card or {}).get("assigned_team", "") or ""
                        assigned_team = _normalize_team_name(_raw_team)
                        if assigned_team not in _SLUG_TO_TEAM.values():
                            # No card yet — infer deterministically instead of
                            # silently dropping this row until AI generation
                            # catches up and writes the real assigned_team.
                            assigned_team = infer_assigned_team(plugin_name)

                        # Real bug report: a member whose ONLY team is a
                        # custom team always saw an empty list here — this
                        # only ever checked the AI's own assigned_team
                        # (always one of the 4 fixed teams, or forced there
                        # by infer_assigned_team's fallback above), never
                        # additional_teams (see AssignTeamAPIView / the Add
                        # User checkbox picker's write path), so a card
                        # manually/checkbox-assigned to a custom team could
                        # never match member_teams_normalized. A card now
                        # can genuinely belong to more than one team at
                        # once (e.g. "Patch Management" AND a custom
                        # "demo") — match against the union and add the
                        # SAME row to every one of the member's teams it
                        # matches, not just one.
                        card_teams = {assigned_team} if assigned_team else set()
                        card_teams.update(t for t in (card or {}).get("additional_teams") or [] if t)
                        matched_teams = card_teams & member_teams_normalized
                        if not matched_teams:
                            continue

                        dedup_key = (host_name, plugin_name)
                        existing_row = seen_host_vuln_row.get(dedup_key)
                        if existing_row is not None:
                            if existing_row["status"] != "closed" and vuln_status == "closed":
                                existing_row["status"] = "closed"
                            row = existing_row
                        else:
                            # Real bug report: same "In Progress" badge gap as
                            # the admin-side by-team endpoint — always present
                            # (None -> JSON null), never an omitted key.
                            automation_status = ((card or {}).get("automation_card") or {}).get("automation_status")

                            row = {
                                "id":                str(uuid.uuid4()),
                                "host_name":         host_name,
                                "os":                os_value,
                                "plugin_name":       plugin_name,
                                "asset_count":       plugin_asset_counts.get(plugin_name, 0),
                                "risk_factor":       risk_factor,
                                "port":              port,
                                "protocol":          protocol,
                                "status":            vuln_status,
                                "assigned_team":     assigned_team,
                                "automation_status": automation_status,
                            }
                            seen_host_vuln_row[dedup_key] = row
                            for team_name in matched_teams:
                                _add_team_plugin_host(team_name, plugin_name, host_name)
                            all_rows.append((row, matched_teams))

                # Per-team "4+ assets" qualification — see the real bug
                # report above.
                team_qualified_plugins = {
                    team_name: {
                        p for p, hosts in plugin_map.items()
                        if _qualifies_for_mitigation_strategy(len(hosts))
                    }
                    for team_name, plugin_map in team_plugin_hosts.items()
                }
                for row, matched_teams in all_rows:
                    pname = row["plugin_name"]
                    for team_name in matched_teams:
                        if pname in team_qualified_plugins.get(team_name, ()):
                            teams.setdefault(team_name, []).append(row)

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
                        "member_teams": sorted(member_teams_normalized),
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

            member_teams_normalized = {_normalize_team_name(t) for t in member_teams}

            # Optional: ?team=<team name> — narrows to just that one team
            # (must be one of the member's own teams); omitted/invalid falls
            # back to all of them, same as before. Matches the ?team=
            # convention already used by userdashboard's views, so the Home
            # page's team dropdown can carry its selection through here too.
            selected_team = _normalize_team_name(request.query_params.get("team", "").strip())
            if selected_team and selected_team in member_teams_normalized:
                member_teams_normalized = {selected_team}

            admin_id = str(user_detail.admin.id)

            with MongoContext() as db:
                nessus_coll    = db[NESSUS_COLLECTION]
                vuln_card_coll = db[VULN_CARD_COLLECTION]

                # Step 2: this admin's REAL primary report — sorted by
                # total_vulnerabilities first, not just uploaded_at, so a
                # small claim-link auto-split fragment can't outrank this
                # admin's real, bigger, properly-merged report (same fix
                # as resolve_report_id_for_upload/admindashboard.views.
                # _load_latest_report_for_admin).
                latest_doc = nessus_coll.find_one(
                    {"admin_id": admin_id},
                    sort=[("total_vulnerabilities", pymongo.DESCENDING), ("uploaded_at", pymongo.DESCENDING)],
                )

                if not latest_doc:
                    return Response(
                        {"detail": "No reports found for your admin."},
                        status=status.HTTP_404_NOT_FOUND,
                    )

                report_id = str(latest_doc.get("report_id", ""))

                # Step 3: Build plugin_name -> assigned_team (+ additional_teams,
                # union across every card with this plugin_name — this view
                # aggregates at plugin_name granularity, not per-host) from
                # vulnerability_cards.
                plugin_team_map = {}
                plugin_additional_teams_map = {}
                for card in vuln_card_coll.find(
                    {"report_id": report_id},
                    {"vulnerability_name": 1, "assigned_team": 1, "additional_teams": 1}
                ):
                    vname = card.get("vulnerability_name", "")
                    team  = _normalize_team_name(card.get("assigned_team", "") or "")
                    if vname and vname not in plugin_team_map:
                        plugin_team_map[vname] = team
                    if vname:
                        plugin_additional_teams_map.setdefault(vname, set()).update(
                            t for t in (card.get("additional_teams") or []) if t
                        )

                # Step 4: Group plugin_name -> set of host_names
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

                        plugin_map.setdefault(plugin_name, set()).add(host_name)

                # Step 5: Group by member's teams, filter 4+ assets
                teams = {name: [] for name in member_teams_normalized}

                # Real bug report: same fix as the admin-side endpoint
                # (adminmitigationstrategy.VulnerabilityAssetCountAPIView)
                # — "4+ assets" was decided once globally per plugin, then
                # the same global asset list got attached to every matched
                # team, so a team whose own assets barely touch a finding
                # still showed it with a misleadingly large asset_count
                # that was really the whole report's, not that team's own.
                team_plugin_hosts = {}

                def _add_team_plugin_hosts(team_name, plugin_name, hosts):
                    team_plugin_hosts.setdefault(team_name, {}).setdefault(plugin_name, set()).update(hosts)

                for plugin_name, assets in plugin_map.items():
                    assigned_team = plugin_team_map.get(plugin_name, "")
                    if assigned_team not in _SLUG_TO_TEAM.values():
                        # No card yet — infer deterministically instead of
                        # silently dropping this row until AI generation
                        # catches up and writes the real assigned_team.
                        assigned_team = infer_assigned_team(plugin_name)

                    # Same multi-team fix as UserMitigationStrategyByTeamAPIView
                    # above — a custom-team-only member must match against
                    # additional_teams too, not just the AI's own
                    # assigned_team, and a finding can land in more than one
                    # of the member's teams at once.
                    plugin_teams = {assigned_team} if assigned_team else set()
                    plugin_teams.update(plugin_additional_teams_map.get(plugin_name) or set())
                    matched_teams = plugin_teams & member_teams_normalized
                    if not matched_teams:
                        continue

                    for team_name in matched_teams:
                        _add_team_plugin_hosts(team_name, plugin_name, assets)

                for team_name, plugin_map_for_team in team_plugin_hosts.items():
                    for plugin_name, hosts in plugin_map_for_team.items():
                        if not _qualifies_for_mitigation_strategy(len(hosts)):
                            continue
                        teams.setdefault(team_name, []).append({
                            "plugin_name": plugin_name,
                            "asset_count": len(hosts),
                            "assets":      sorted(hosts),
                        })

                teams_response = {
                    team_name: {
                        "total_unique_vulnerabilities": len(vulns),
                        "vulnerabilities": sorted(vulns, key=lambda x: x["asset_count"], reverse=True),
                    }
                    for team_name, vulns in teams.items()
                }

                return Response(
                    {
                        "report_id":    report_id,
                        "member_teams": sorted(member_teams_normalized),
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
