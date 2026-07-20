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

# Same keyword order as mitigation_tool — used when no vulnerability_card match.
_TEAM_KEYWORDS = {
    "patch-management": [
        "missing patch", "missing patches", "unpatched", "outdated",
        "end of life", "eol", "kernel", "cve-", "upgrade", "obsolete",
        "out of date", "security update", "hotfix", "service pack",
        "out-of-date", "needs update", "vulnerable version", "patches",
        "cisco ios", "ios xe", "rce", "denial of service", " dos",
    ],
    "architectural-flaws": [
        "default credential", "default credentials", "credential",
        "default password", "weak password", "weak credential",
        "authentication bypass", "privilege escalation", "broken auth",
        "insecure design", "access control", "authorization", "default login",
        "hardcoded", "no authentication", "improper authentication",
    ],
    "network-security": [
        "ssl/tls", "weak cipher", "rc4", "3des", "tls 1.0", "tls 1.1",
        "open port", "telnet", "ftp ", "snmp", "firewall", "port scan",
        "smb", "rdp", "exposed service", "unnecessary service",
        "cipher suite", "ssl cipher", "tls cipher", "icmp", "nla",
        "network level authentication", "ssh ", "terrapin",
    ],
    "configuration-management": [
        "misconfigur", "missing header", "security header",
        "hsts", "csp", "x-frame", "cors", "default setting",
        "permission", "directory listing", "information disclosure",
        "banner", "version disclosure", "debug mode", "clickjacking",
        "ssl certificate", "self-signed", "autocomplete", "cleartext",
    ],
}


def _normalize_team_display(raw):
    """Map slug or display name → canonical team display name."""
    if not raw:
        return ""
    text = str(raw).strip()
    key = text.lower().replace(" ", "-")
    if key in _SLUG_TO_TEAM:
        return _SLUG_TO_TEAM[key]
    for display in _SLUG_TO_TEAM.values():
        if display.lower() == text.lower():
            return display
    return text


def _infer_team_from_name(vuln_name):
    """Keyword-based team when no vulnerability_cards match exists."""
    combined = (vuln_name or "").lower()
    for team_slug, keywords in _TEAM_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return _SLUG_TO_TEAM[team_slug]
    return _SLUG_TO_TEAM["configuration-management"]


def _vuln_name_lookup_keys(vuln):
    """Exact name + stripped 'Fix — …' / leading plugin-id variants for card match."""
    name = (vuln or "").strip()
    if not name:
        return []
    keys = [name]
    for marker in (" Fix —", " Fix –", " Fix -", " Fix:"):
        if marker in name:
            keys.append(name.split(marker, 1)[0].strip())
            break
    # "51192 - SSL Certificate…" / "Starting TLS 1.0 fix…"
    if " - " in name:
        left, right = name.split(" - ", 1)
        if left.strip().isdigit() and right.strip():
            keys.append(right.strip())
    # Dedupe while preserving order
    seen = set()
    out = []
    for k in keys:
        if k and k not in seen:
            seen.add(k)
            out.append(k)
    return out


# ── Shared helpers ────────────────────────────────────────────────────────────

def _fetch_script(plugin_id, os=None):
    """
    A plugin_id can now have multiple documents — one per OS (Windows, Linux,
    Cisco) — since automation scripts differ by target platform. Returns
    (matched_doc_or_None, available_os_list).

    If `os` is given, returns the document for that exact OS (case-insensitive).
    If not given, falls back to the first variant found (old single-script
    behavior) so existing callers that don't pass ?os= don't break outright.
    """
    with MongoContext() as db:
        variants = list(db["automation_scripts"].find(
            {"plugin_id": int(plugin_id)}, {"_id": 0}
        ))

    if not variants:
        return None, []

    available_os = [v.get("os") for v in variants if v.get("os")]

    if os:
        match = next(
            (v for v in variants if (v.get("os") or "").strip().lower() == os.strip().lower()),
            None,
        )
        return match, available_os

    return variants[0], available_os


def _fetch_scripts_bulk(int_ids, os=None):
    """Bulk variant of _fetch_script. Returns {plugin_id: (doc_or_None, available_os)}."""
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find(
            {"plugin_id": {"$in": int_ids}}, {"_id": 0}
        ))

    by_plugin = {}
    for doc in docs:
        by_plugin.setdefault(doc["plugin_id"], []).append(doc)

    result = {}
    for pid in int_ids:
        variants = by_plugin.get(pid, [])
        available_os = [v.get("os") for v in variants if v.get("os")]
        if not variants:
            result[pid] = (None, [])
        elif os:
            match = next(
                (v for v in variants if (v.get("os") or "").strip().lower() == os.strip().lower()),
                None,
            )
            result[pid] = (match, available_os)
        else:
            result[pid] = (variants[0], available_os)
    return result


def _build_response(doc, available_os=None):
    return {
        "matched": True,
        "plugin_id": doc.get("plugin_id"),
        "severity": doc.get("severity"),
        "vulnerability": doc.get("vulnerability"),
        "port": doc.get("port"),
        "description": doc.get("description"),
        "os": doc.get("os"),
        "available_os": available_os or ([doc.get("os")] if doc.get("os") else []),
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
    Build download-stats rows with team resolved for every script:
      1) vulnerability_cards by exact / stripped vulnerability name
      2) same plugin_id sibling that already resolved a team
      3) keyword inference (never leave team blank)
    """
    if not docs:
        return []

    lookup_names = []
    seen_names = set()
    for d in docs:
        for key in _vuln_name_lookup_keys(d.get("vulnerability", "")):
            if key not in seen_names:
                seen_names.add(key)
                lookup_names.append(key)

    team_by_name = {}
    team_by_plugin = {}

    with MongoContext() as db:
        if lookup_names:
            cards = db["vulnerability_cards"].find(
                {"vulnerability_name": {"$in": lookup_names}},
                {"vulnerability_name": 1, "assigned_team": 1, "plugin_id": 1, "_id": 0},
            )
            for card in cards:
                vname = (card.get("vulnerability_name") or "").strip()
                team = _normalize_team_display(card.get("assigned_team", ""))
                if not team:
                    continue
                if vname and vname not in team_by_name:
                    team_by_name[vname] = team
                pid = card.get("plugin_id")
                if pid is not None:
                    try:
                        team_by_plugin[int(pid)] = team
                    except (TypeError, ValueError):
                        pass

        # Also pull team from fix register rows that have plugin_id + assigned_team
        plugin_ids = []
        for d in docs:
            try:
                plugin_ids.append(int(d.get("plugin_id")))
            except (TypeError, ValueError):
                pass
        plugin_ids = list({p for p in plugin_ids})
        if plugin_ids:
            # plugin_id may be stored as int or string in register collections
            pid_query = list({*plugin_ids, *[str(p) for p in plugin_ids]})
            for coll_name in ("fix_vulnerabilities", "fix_vulnerabilities_closed"):
                for row in db[coll_name].find(
                    {"plugin_id": {"$in": pid_query}},
                    {"plugin_id": 1, "assigned_team": 1, "_id": 0},
                ):
                    team = _normalize_team_display(row.get("assigned_team", ""))
                    if not team:
                        continue
                    try:
                        pid = int(row.get("plugin_id"))
                    except (TypeError, ValueError):
                        continue
                    if pid not in team_by_plugin:
                        team_by_plugin[pid] = team

    # Pass 1: name match (+ seed plugin map from successful name matches)
    provisional = []
    for d in docs:
        vuln = d.get("vulnerability", "") or ""
        team = ""
        for key in _vuln_name_lookup_keys(vuln):
            team = team_by_name.get(key, "")
            if team:
                break
        pid = None
        try:
            pid = int(d.get("plugin_id"))
        except (TypeError, ValueError):
            pass
        if team and pid is not None and pid not in team_by_plugin:
            team_by_plugin[pid] = team
        provisional.append((d, vuln, pid, team))

    # Pass 2: same plugin_id sibling team; Pass 3: keyword inference
    stats = []
    for d, vuln, pid, team in provisional:
        if not team and pid is not None:
            team = team_by_plugin.get(pid, "")
        if not team:
            team = _infer_team_from_name(vuln)
            if pid is not None and pid not in team_by_plugin:
                team_by_plugin[pid] = team
        stats.append({
            "plugin_id": d.get("plugin_id"),
            "vulnerability": vuln,
            "severity": d.get("severity", ""),
            "download_count": d.get("download_count", 0),
            "team": team,
        })
    return stats


def _get_feedback_summary(plugin_id):
    """Return thumb_up_count, thumb_down_count, feedbacks list for a plugin_id."""
    with MongoContext() as db:
        docs = list(db["script_feedback"].find(
            {"plugin_id": int(plugin_id)},
            {"_id": 0, "user_email": 1, "working": 1, "created_at": 1}
        ).sort("created_at", -1))

    thumb_up = sum(1 for d in docs if d.get("working") is True)
    thumb_down = sum(1 for d in docs if d.get("working") is False)
    return {
        "thumb_up_count": thumb_up,
        "thumb_down_count": thumb_down,
        "feedbacks": docs,
    }


# ── ADMIN VIEWS (read-only, no download) ─────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_match_script(request, plugin_id):
    """?os=Windows|Linux|Cisco — optional; omit to get any available variant."""
    os_param = request.query_params.get("os")
    doc, available_os = _fetch_script(plugin_id, os=os_param)
    if doc:
        return Response(_build_response(doc, available_os))
    return Response(_not_found_response(plugin_id))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_match_scripts_bulk(request):
    """Body: { "plugin_ids": [103669, 41028, 99999], "os": "Windows" }"""
    plugin_ids = request.data.get("plugin_ids", [])
    os_param = request.data.get("os")
    if not isinstance(plugin_ids, list):
        return Response({"error": "plugin_ids must be a list"}, status=400)

    int_ids = []
    for pid in plugin_ids:
        try:
            int_ids.append(int(pid))
        except (ValueError, TypeError):
            pass

    by_plugin = _fetch_scripts_bulk(int_ids, os=os_param)
    results = [
        _build_response(by_plugin[pid][0], by_plugin[pid][1]) if by_plugin[pid][0]
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
    """Columns: Vulnerability Name | Severity | No. of Times Downloaded | Team"""
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find(
            {},
            {"_id": 0, "plugin_id": 1, "vulnerability": 1, "severity": 1, "download_count": 1}
        ).sort("download_count", -1))

    stats = _build_stats(docs)
    return Response({"count": len(stats), "stats": stats})


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_script_feedback(request, plugin_id):
    """Admin read-only: see thumb up/down feedback for a specific script."""
    doc, _ = _fetch_script(plugin_id)
    if not doc:
        return Response(_not_found_response(plugin_id), status=404)

    summary = _get_feedback_summary(plugin_id)
    return Response({
        "plugin_id": int(plugin_id),
        "vulnerability": doc.get("vulnerability", ""),
        "severity": doc.get("severity", ""),
        **summary,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_all_feedback(request):
    """Admin read-only: see thumb up/down counts for all scripts."""
    with MongoContext() as db:
        pipeline = [
            {"$group": {
                "_id": "$plugin_id",
                "thumb_up_count":   {"$sum": {"$cond": [{"$eq": ["$working", True]}, 1, 0]}},
                "thumb_down_count": {"$sum": {"$cond": [{"$eq": ["$working", False]}, 1, 0]}},
                "vulnerability":    {"$first": "$vulnerability"},
                "severity":         {"$first": "$severity"},
            }},
            {"$sort": {"_id": 1}},
        ]
        results = list(db["script_feedback"].aggregate(pipeline))

    data = [
        {
            "plugin_id":        r["_id"],
            "vulnerability":    r.get("vulnerability", ""),
            "severity":         r.get("severity", ""),
            "thumb_up_count":   r.get("thumb_up_count", 0),
            "thumb_down_count": r.get("thumb_down_count", 0),
        }
        for r in results
    ]
    return Response({"count": len(data), "feedback_summary": data})


# ── USER VIEWS ────────────────────────────────────────────────────────────────

@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_match_script(request, plugin_id):
    """?os=Windows|Linux|Cisco — optional; omit to get any available variant."""
    os_param = request.query_params.get("os")
    doc, available_os = _fetch_script(plugin_id, os=os_param)
    if doc:
        return Response(_build_response(doc, available_os))
    return Response(_not_found_response(plugin_id))


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_match_scripts_bulk(request):
    """Body: { "plugin_ids": [103669, 41028, 99999], "os": "Windows" }"""
    plugin_ids = request.data.get("plugin_ids", [])
    os_param = request.data.get("os")
    if not isinstance(plugin_ids, list):
        return Response({"error": "plugin_ids must be a list"}, status=400)

    int_ids = []
    for pid in plugin_ids:
        try:
            int_ids.append(int(pid))
        except (ValueError, TypeError):
            pass

    by_plugin = _fetch_scripts_bulk(int_ids, os=os_param)
    results = [
        _build_response(by_plugin[pid][0], by_plugin[pid][1]) if by_plugin[pid][0]
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
    Download fix script. Increments download_count. Admins cannot download.
    ?os=Windows|Linux|Cisco — optional; omit to get any available variant.
    """
    if request.user.is_staff or request.user.is_superuser:
        return Response(
            {"error": "Admins cannot download scripts. Read-only access only."},
            status=403
        )

    os_param = request.query_params.get("os")
    doc, available_os = _fetch_script(plugin_id, os=os_param)
    if not doc:
        return Response(_not_found_response(plugin_id), status=404)

    fix_script_path = doc.get("fix_script_path")
    if not fix_script_path:
        return Response({"error": "Script file not available for this vulnerability."}, status=404)

    full_path = BASE_DIR / fix_script_path
    if not full_path.exists():
        return Response({"error": f"Script file not found on server: {fix_script_path}"}, status=404)

    with MongoContext() as db:
        db["automation_scripts"].update_one(
            {"plugin_id": int(plugin_id), "os": doc.get("os")},
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
    """Columns: Vulnerability Name | Severity | No. of Times Downloaded | Team"""
    with MongoContext() as db:
        docs = list(db["automation_scripts"].find(
            {},
            {"_id": 0, "plugin_id": 1, "vulnerability": 1, "severity": 1, "download_count": 1}
        ).sort("download_count", -1))

    stats = _build_stats(docs)
    return Response({"count": len(stats), "stats": stats})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_submit_feedback(request):
    """
    User submits thumb up/down after running a script.
    Body: { "plugin_id": 103669, "working": true }
    Admin users are not allowed to submit feedback.
    """
    if request.user.is_staff or request.user.is_superuser:
        return Response(
            {"error": "Admins cannot submit feedback. Read-only access only."},
            status=403
        )

    plugin_id_raw = request.data.get("plugin_id")
    working = request.data.get("working")

    if plugin_id_raw is None:
        return Response({"error": "plugin_id is required."}, status=400)
    if working is None or not isinstance(working, bool):
        return Response({"error": "working must be true or false."}, status=400)

    try:
        plugin_id = int(plugin_id_raw)
    except (ValueError, TypeError):
        return Response({"error": "plugin_id must be a number."}, status=400)

    doc, _ = _fetch_script(plugin_id)
    if not doc:
        return Response(_not_found_response(plugin_id), status=404)

    user_email = request.user.email
    now = datetime.datetime.utcnow().isoformat()

    with MongoContext() as db:
        db["script_feedback"].update_one(
            {"plugin_id": plugin_id, "user_email": user_email},
            {"$set": {
                "plugin_id":     plugin_id,
                "vulnerability": doc.get("vulnerability", ""),
                "severity":      doc.get("severity", ""),
                "user_email":    user_email,
                "working":       working,
                "updated_at":    now,
            },
            "$setOnInsert": {"created_at": now}},
            upsert=True,
        )

    return Response({
        "success": True,
        "plugin_id": plugin_id,
        "working": working,
        "message": "Feedback submitted." ,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_get_feedback(request, plugin_id):
    """User sees their own feedback + overall counts for this script."""
    doc, _ = _fetch_script(plugin_id)
    if not doc:
        return Response(_not_found_response(plugin_id), status=404)

    user_email = request.user.email

    with MongoContext() as db:
        my_feedback = db["script_feedback"].find_one(
            {"plugin_id": int(plugin_id), "user_email": user_email},
            {"_id": 0, "working": 1, "updated_at": 1}
        )

    summary = _get_feedback_summary(plugin_id)
    return Response({
        "plugin_id":      int(plugin_id),
        "vulnerability":  doc.get("vulnerability", ""),
        "my_feedback":    my_feedback,
        **summary,
    })
