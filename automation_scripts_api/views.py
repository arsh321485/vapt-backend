import datetime
from pathlib import Path

from django.http import FileResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from vaptfix.mongo_client import MongoContext

BASE_DIR = Path(__file__).resolve().parent.parent

_SLUG_TO_TEAM = {
    "patch-management":         "Patch Management",
    "network-security":         "Network Security",
    "architectural-flaws":      "Architectural Flaws",
    "configuration-management": "Configuration Management",
}


# ── Shared helpers ────────────────────────────────────────────────────────────

def _fetch_script(plugin_id):
    with MongoContext() as db:
        return db["automation_scripts"].find_one({"plugin_id": int(plugin_id)}, {"_id": 0})


def _fetch_scripts_bulk(int_ids):
    with MongoContext() as db:
        return list(db["automation_scripts"].find(
            {"plugin_id": {"$in": int_ids}},
            {"_id": 0}
        ))


def _build_response(doc):
    return {
        "matched": True,
        "plugin_id": doc.get("plugin_id"),
        "severity": doc.get("severity"),
        "vulnerability": doc.get("vulnerability"),
        "port": doc.get("port"),
        "description": doc.get("description"),
        "os": doc.get("os"),
        "automation_possible": doc.get("automation_possible"),
        "script_description": doc.get("script_description"),
        "considerations_before": doc.get("considerations_before"),
        "considerations_after": doc.get("considerations_after"),
        "script_name": doc.get("script_name"),
        "libraries": doc.get("libraries"),
        "tested_manually": doc.get("tested_manually"),
        "what_can_be_automated": doc.get("what_can_be_automated"),
        "what_must_remain_manual": doc.get("what_must_remain_manual"),
        "recommended_approach": doc.get("recommended_approach"),
        "command_download_libraries": doc.get("command_download_libraries"),
        "command_run_script": doc.get("command_run_script"),
        "fix_script_name": doc.get("fix_script_name"),
        "fix_script_path": doc.get("fix_script_path"),
        "verify_script_name": doc.get("verify_script_name"),
        "verify_script_path": doc.get("verify_script_path"),
        "language": doc.get("language"),
        "download_count": doc.get("download_count", 0),
    }


def _not_found_response(plugin_id):
    return {
        "matched": False,
        "plugin_id": plugin_id,
        "message": "No automated fix available for this vulnerability.",
    }


def _build_stats(docs):
    """
    For each script, look up assigned_team from vulnerability_cards by vulnerability_name,
    then return the stats row.
    """
    if not docs:
        return []

    vuln_names = [d.get("vulnerability", "") for d in docs if d.get("vulnerability")]

    with MongoContext() as db:
        cards = db["vulnerability_cards"].find(
            {"vulnerability_name": {"$in": vuln_names}},
            {"vulnerability_name": 1, "assigned_team": 1, "_id": 0}
        )
        # Use first card found per vulnerability_name
        team_map = {}
        for card in cards:
            vname = card.get("vulnerability_name", "")
            if vname and vname not in team_map:
                raw = (card.get("assigned_team", "") or "").strip().lower()
                team_map[vname] = _SLUG_TO_TEAM.get(raw, card.get("assigned_team", "") or "")

    stats = []
    for d in docs:
        vuln = d.get("vulnerability", "")
        stats.append({
            "plugin_id": d.get("plugin_id"),
            "vulnerability": vuln,
            "severity": d.get("severity", ""),
            "download_count": d.get("download_count", 0),
            "team": team_map.get(vuln, ""),
        })
    return stats


# ── ADMIN VIEWS (read-only, no download) ─────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_match_script(request, plugin_id):
    doc = _fetch_script(plugin_id)
    if doc:
        return Response(_build_response(doc))
    return Response(_not_found_response(plugin_id))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_match_scripts_bulk(request):
    """Body: { "plugin_ids": [103669, 41028, 99999] }"""
    plugin_ids = request.data.get("plugin_ids", [])
    if not isinstance(plugin_ids, list):
        return Response({"error": "plugin_ids must be a list"}, status=400)

    int_ids = []
    for pid in plugin_ids:
        try:
            int_ids.append(int(pid))
        except (ValueError, TypeError):
            pass

    docs = _fetch_scripts_bulk(int_ids)
    matched_map = {doc["plugin_id"]: doc for doc in docs}
    results = [
        _build_response(matched_map[pid]) if pid in matched_map
        else _not_found_response(pid)
        for pid in int_ids
    ]
    return Response({"results": results})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_list_scripts(request):
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find({}, {"_id": 0}).sort("plugin_id", 1))
    return Response({"count": len(docs), "scripts": [_build_response(d) for d in docs]})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_download_stats(request):
    """
    Returns download stats for all scripts.
    Columns: Vulnerability Name | Severity | No. of Times Downloaded | Team
    """
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find(
            {},
            {"_id": 0, "plugin_id": 1, "vulnerability": 1, "severity": 1, "download_count": 1}
        ).sort("download_count", -1))

    stats = _build_stats(docs)
    return Response({"count": len(stats), "stats": stats})


# ── USER VIEWS ────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_match_script(request, plugin_id):
    doc = _fetch_script(plugin_id)
    if doc:
        return Response(_build_response(doc))
    return Response(_not_found_response(plugin_id))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_match_scripts_bulk(request):
    """Body: { "plugin_ids": [103669, 41028, 99999] }"""
    plugin_ids = request.data.get("plugin_ids", [])
    if not isinstance(plugin_ids, list):
        return Response({"error": "plugin_ids must be a list"}, status=400)

    int_ids = []
    for pid in plugin_ids:
        try:
            int_ids.append(int(pid))
        except (ValueError, TypeError):
            pass

    docs = _fetch_scripts_bulk(int_ids)
    matched_map = {doc["plugin_id"]: doc for doc in docs}
    results = [
        _build_response(matched_map[pid]) if pid in matched_map
        else _not_found_response(pid)
        for pid in int_ids
    ]
    return Response({"results": results})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_list_scripts(request):
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find({}, {"_id": 0}).sort("plugin_id", 1))
    return Response({"count": len(docs), "scripts": [_build_response(d) for d in docs]})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_download_script(request, plugin_id):
    """
    Download the fix script (.py) for a given plugin_id.
    Only users can access this endpoint. Increments download_count on each call.
    """
    doc = _fetch_script(plugin_id)
    if not doc:
        return Response(_not_found_response(plugin_id), status=404)

    fix_script_path = doc.get("fix_script_path")
    if not fix_script_path:
        return Response(
            {"error": "Script file not available for this vulnerability."},
            status=404
        )

    full_path = BASE_DIR / fix_script_path
    if not full_path.exists():
        return Response(
            {"error": f"Script file not found on server: {fix_script_path}"},
            status=404
        )

    with MongoContext() as db:
        db["automation_scripts"].update_one(
            {"plugin_id": int(plugin_id)},
            {"$inc": {"download_count": 1}}
        )

    return FileResponse(
        open(full_path, "rb"),
        as_attachment=True,
        filename=full_path.name,
        content_type="text/x-python",
    )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_download_stats(request):
    """
    Returns download stats visible to users.
    Columns: Vulnerability Name | Severity | No. of Times Downloaded | Team
    """
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find(
            {},
            {"_id": 0, "plugin_id": 1, "vulnerability": 1, "severity": 1, "download_count": 1}
        ).sort("download_count", -1))

    stats = _build_stats(docs)
    return Response({"count": len(stats), "stats": stats})
