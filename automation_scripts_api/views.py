from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from vaptfix.mongo_client import MongoContext


def _fetch_script(plugin_id):
    with MongoContext() as db:
        return db["automation_scripts"].find_one({"plugin_id": int(plugin_id)}, {"_id": 0})


def _fetch_scripts_bulk(int_ids):
    with MongoContext() as db:
        return list(db["automation_scripts"].find(
            {"plugin_id": {"$in": int_ids}},
            {"_id": 0}
        ))


def _script_matched_response(doc):
    return {
        "matched": True,
        "plugin_id": doc["plugin_id"],
        "vulnerability": doc["vulnerability"],
        "fix_script_name": doc.get("fix_script_name"),
        "fix_script_path": doc.get("fix_script_path"),
        "verify_script_name": doc.get("verify_script_name"),
        "verify_script_path": doc.get("verify_script_path"),
        "language": doc.get("language", "python"),
    }


def _script_not_found_response(plugin_id):
    return {
        "matched": False,
        "plugin_id": plugin_id,
        "message": "No automated fix available for this vulnerability.",
    }


# ─── ADMIN VIEWS (read-only info) ────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_match_script(request, plugin_id):
    doc = _fetch_script(plugin_id)
    if doc:
        return Response(_script_matched_response(doc))
    return Response(_script_not_found_response(plugin_id))


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
        _script_matched_response(matched_map[pid]) if pid in matched_map
        else _script_not_found_response(pid)
        for pid in int_ids
    ]
    return Response({"results": results})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_list_scripts(request):
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find({}, {"_id": 0}).sort("plugin_id", 1))
    return Response({"count": len(docs), "scripts": docs})


# ─── USER VIEWS (same data — frontend enables download/use buttons) ───────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_match_script(request, plugin_id):
    doc = _fetch_script(plugin_id)
    if doc:
        return Response(_script_matched_response(doc))
    return Response(_script_not_found_response(plugin_id))


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
        _script_matched_response(matched_map[pid]) if pid in matched_map
        else _script_not_found_response(pid)
        for pid in int_ids
    ]
    return Response({"results": results})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_list_scripts(request):
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find({}, {"_id": 0}).sort("plugin_id", 1))
    return Response({"count": len(docs), "scripts": docs})
