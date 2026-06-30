from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from vaptfix.mongo_client import MongoContext


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def match_script(request, plugin_id):
    with MongoContext() as db:
        doc = db["automation_scripts"].find_one({"plugin_id": int(plugin_id)}, {"_id": 0})

    if doc:
        return Response({
            "matched": True,
            "plugin_id": doc["plugin_id"],
            "vulnerability": doc["vulnerability"],
            "fix_script_name": doc.get("fix_script_name"),
            "fix_script_path": doc.get("fix_script_path"),
            "verify_script_name": doc.get("verify_script_name"),
            "verify_script_path": doc.get("verify_script_path"),
            "language": doc.get("language", "python"),
        })

    return Response({
        "matched": False,
        "plugin_id": plugin_id,
        "message": "No automated fix available for this vulnerability.",
    })


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def match_scripts_bulk(request):
    """
    Accept a list of plugin_ids and return match results for all.
    Body: { "plugin_ids": [103669, 41028, 99999] }
    """
    plugin_ids = request.data.get("plugin_ids", [])
    if not isinstance(plugin_ids, list):
        return Response({"error": "plugin_ids must be a list"}, status=400)

    int_ids = []
    for pid in plugin_ids:
        try:
            int_ids.append(int(pid))
        except (ValueError, TypeError):
            pass

    with MongoContext() as db:
        docs = list(db["automation_scripts"].find(
            {"plugin_id": {"$in": int_ids}},
            {"_id": 0}
        ))

    matched_map = {doc["plugin_id"]: doc for doc in docs}

    results = []
    for pid in int_ids:
        doc = matched_map.get(pid)
        if doc:
            results.append({
                "matched": True,
                "plugin_id": pid,
                "vulnerability": doc["vulnerability"],
                "fix_script_name": doc.get("fix_script_name"),
                "fix_script_path": doc.get("fix_script_path"),
                "verify_script_name": doc.get("verify_script_name"),
                "verify_script_path": doc.get("verify_script_path"),
                "language": doc.get("language", "python"),
            })
        else:
            results.append({
                "matched": False,
                "plugin_id": pid,
                "message": "No automated fix available for this vulnerability.",
            })

    return Response({"results": results})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def list_scripts(request):
    with MongoContext() as db:
        docs = list(
            db["automation_scripts"].find({}, {"_id": 0}).sort("plugin_id", 1)
        )
    return Response({"count": len(docs), "scripts": docs})
