import datetime
import logging
import re
from pathlib import Path

from django.http import FileResponse, HttpResponse
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from vaptfix.mongo_client import MongoContext

logger = logging.getLogger(__name__)

try:
    from users_details.models import UserDetail
except Exception:
    UserDetail = None

BASE_DIR = Path(__file__).resolve().parent.parent

NESSUS_COLLECTION = "nessus_reports"
# AI-generated automation feasibility/script, one embedded sub-document per
# card — see upload_report/mitigation_tool.py's Automation Engineer output
# and upload_report/crew_agent/{agents,tasks}.py. Separate from
# "automation_scripts" (the small, human-curated Google-Sheet-driven library
# above) — this lives on every vulnerability_cards document instead.
VULN_CARD_COLLECTION = "vulnerability_cards"

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

def _resolve_admin_and_teams(request):
    """
    Returns (admin_id, admin_email, teams_or_None).
    - Admin/superadmin caller → (their own id/email, None) — None means
      "no team filter", they see everything from their latest report.
    - Team member caller → (their parent admin's id/email, their Member_role
      teams list) via UserDetail, same lookup userregister uses.
    """
    user = request.user
    if user.is_staff or user.is_superuser:
        return str(user.id), getattr(user, "email", None), None

    if not UserDetail:
        return None, None, []

    detail = UserDetail.objects.select_related("admin").filter(email=user.email).first()
    if not detail:
        return None, None, []

    teams = detail.Member_role if isinstance(detail.Member_role, list) else []
    if not teams and detail.team_name:
        teams = [detail.team_name]
    return str(detail.admin.id), getattr(detail.admin, "email", None), teams


def _premium_required_message(admin_id):
    """
    Same plan gate as user_download_script (assert_can_use_automation_scripts)
    and the same 'premium_required'/'message' convention admin_download_stats
    already uses — but checked up front here instead of only at download
    time. Real bug: the *_match_script*/ endpoints (what actually renders
    the automation-fix detail screen) returned the full script content with
    no indication at all that the plan doesn't allow it — a Freemium admin
    or member saw everything, with zero "upgrade" prompt, and would only
    find out the plan blocked them if they clicked Download. Mirrors the
    same fix already applied to Slack's _allvuln_detail_blocks.

    Takes admin_id directly rather than resolving it internally —
    _resolve_admin_and_teams keys off is_staff/is_superuser to decide
    "this caller IS the admin", which a real admin account can fail (confirmed:
    an actual report-owning admin here had is_staff=False), silently
    resolving to admin_id=None and never locking anything. admin_* call
    sites pass request.user.id directly (same as admin_download_stats
    already does); user_* call sites pass _resolve_admin_and_teams(request)'s
    own admin_id, which is correct for a genuine team-member caller.
    """
    from billing.enforcement import assert_can_use_automation_scripts, PlanLimitExceeded
    if not admin_id:
        return False, None
    try:
        assert_can_use_automation_scripts(admin_id)
        return False, None
    except PlanLimitExceeded as e:
        return True, str(e)


def _normalize_vuln_name(name: str) -> str:
    """Case/whitespace-insensitive key for matching a vulnerability name
    against the automation_scripts library's own "vulnerability" field.
    Collapses ALL whitespace runs (tabs, double spaces, newlines — not just
    leading/trailing) to a single space before lowercasing, so "TLS  Version
    1.0" / "tls version 1.0" / "TLS Version 1.0 " all resolve to the same key."""
    return re.sub(r"\s+", " ", (name or "")).strip().lower()


def _load_all_reports_plugin_ids(db, admin_id, admin_email):
    """
    Finds EVERY nessus_reports document belonging to this admin (not just
    the single most recent one — see upload_report/merge_service.py: only
    uploads on the SAME day merge into one doc via "today's report_id", so
    an admin who has uploaded on more than one day genuinely has multiple
    separate report_id rows) and returns the union of plugin_ids/vuln_names
    across all of them, plus every report_id.

    Previously this only looked at the single latest report, which meant
    any vulnerability belonging to an OLDER report (Nessus, AWS, or custom
    — doesn't matter which) silently lost automation-script visibility the
    moment a newer report was uploaded, even though its script was still
    perfectly available. Confirmed as the exact reported symptom: "SMB
    Signing Not Required" script disappearing after a second file upload.

    plugin_ids alone only ever works for native Nessus uploads — AWS
    Inspector and custom/CSV reports store a different ID scheme (or none
    at all: custom always has plugin_id=None) in that same field, so their
    vulnerabilities can never match automation_scripts (which is indexed
    by real Nessus plugin IDs) through plugin_id. The name set lets callers
    fall back to matching by vulnerability name for those report types.

    Returns (latest_report_id, latest_uploaded_at, all_report_ids,
    union_of_plugin_ids, union_of_normalized_vuln_names).
    """
    coll = db[NESSUS_COLLECTION]
    query = {"$or": [{"admin_id": str(admin_id)}, {"admin_email": admin_email}]} if admin_email else {"admin_id": str(admin_id)}
    docs = list(coll.find(query, sort=[("uploaded_at", -1)]))
    if not docs:
        return None, None, [], set(), set()

    plugin_ids = set()
    vuln_names = set()
    report_ids = []
    for doc in docs:
        rid = doc.get("report_id")
        if rid:
            report_ids.append(str(rid))
        for host in doc.get("vulnerabilities_by_host", []):
            for v in host.get("vulnerabilities", []):
                try:
                    plugin_ids.add(int(v.get("plugin_id")))
                except (TypeError, ValueError):
                    pass
                name = v.get("plugin_name") or v.get("pluginname") or v.get("name") or ""
                for key in _vuln_name_lookup_keys(name):
                    vuln_names.add(_normalize_vuln_name(key))

    latest = docs[0]
    return latest.get("report_id"), latest.get("uploaded_at"), report_ids, plugin_ids, vuln_names


def _fetch_scripts_by_name(name_keys, os=None):
    """
    automation_scripts docs whose "vulnerability" field matches one of the
    given normalized names — the fallback path for AWS/custom reports,
    whose vulnerabilities don't carry a real Nessus plugin_id to match on.
    automation_scripts is a small curated reference library (not one row
    per scan finding), so fetching it whole and matching in Python is fine.
    """
    if not name_keys:
        return []
    with MongoContext() as db:
        all_docs = list(db["automation_scripts"].find({}, {"_id": 0}))
    matched = [d for d in all_docs if _normalize_vuln_name(d.get("vulnerability", "")) in name_keys]
    if os:
        os_l = os.strip().lower()
        matched = [d for d in matched if (d.get("os") or "").strip().lower() == os_l]
    return matched


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


def _script_response(doc, available_os, premium_required, message):
    """
    Full script detail when the plan allows automation scripts; otherwise
    ONLY bare identifying fields plus the lock message — explicit request:
    a Freemium account must not receive any of the actual script content
    (script_description, recommended_approach, what_can_be_automated,
    libraries, command strings, etc.) at all, not just have the frontend
    hide it. Matches the same fix already applied to Slack's
    _format_vulndata_automation_detail.
    """
    if premium_required:
        return {
            "matched": True,
            "plugin_id": doc.get("plugin_id"),
            "vulnerability": doc.get("vulnerability"),
            "severity": doc.get("severity"),
            "premium_required": True,
            "message": message,
        }
    return {**_build_response(doc, available_os), "premium_required": False, "message": None}


def _not_found_response(plugin_id):
    return {
        "matched": False,
        "plugin_id": plugin_id,
        "message": "No automated fix available for this vulnerability.",
    }


def _build_stats(docs, report_id=None):
    """
    Build download-stats rows with team resolved for every script:
      1) vulnerability_cards by exact / stripped vulnerability name
         (scoped to `report_id` when given, so team assignment can't leak
         in from an unrelated admin's report sharing the same vuln name —
         `report_id` may be a single id or a list of ids, since an admin
         can have more than one report; either way this never reaches
         beyond that admin's own reports)
      2) same plugin_id sibling that already resolved a team
      3) keyword inference (never leave team blank)
    """
    if not docs:
        return []

    report_id_filter = {"$in": report_id} if isinstance(report_id, list) else report_id

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
            card_query = {"vulnerability_name": {"$in": lookup_names}}
            if report_id:
                card_query["report_id"] = report_id_filter
            cards = db["vulnerability_cards"].find(
                card_query,
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
                fix_query = {"plugin_id": {"$in": pid_query}}
                if report_id:
                    fix_query["report_id"] = report_id_filter
                for row in db[coll_name].find(
                    fix_query,
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

    # A plugin_id's OS variants are split across docs: the "vulnerability"
    # doc carries severity, its sibling "...Fix — <OS>" script doc usually
    # doesn't. Build a plugin_id -> severity fallback from whichever variant
    # in this same `docs` batch actually has one set.
    severity_by_plugin = {}
    for d in docs:
        sev = (d.get("severity") or "").strip()
        if not sev:
            continue
        try:
            pid = int(d.get("plugin_id"))
        except (TypeError, ValueError):
            continue
        if pid not in severity_by_plugin:
            severity_by_plugin[pid] = sev

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
        severity = (d.get("severity") or "").strip()
        if not severity and pid is not None:
            severity = severity_by_plugin.get(pid, "")
        stats.append({
            "plugin_id": d.get("plugin_id"),
            "vulnerability": vuln,
            "severity": severity,
            "download_count": d.get("download_count", 0),
            "team": team,
        })

    # A plugin_id can have multiple OS-variant docs (e.g. a Linux and a
    # Windows script for the same fix) — each produced its own row above,
    # but downloads only ever get attributed to whichever single OS variant
    # was actually fetched, leaving its sibling permanently stuck at 0. Left
    # unmerged this double-lists every multi-OS vulnerability and inflates
    # the total count. Collapse to one row per plugin_id, summing counts —
    # the variant that actually has downloads (or the first one, if none do)
    # supplies the displayed name/severity/team.
    by_plugin = {}
    order = []
    for s in stats:
        pid = s.get("plugin_id")
        if pid not in by_plugin:
            by_plugin[pid] = []
            order.append(pid)
        by_plugin[pid].append(s)

    merged = []
    for pid in order:
        variants = by_plugin[pid]
        total_downloads = sum(v.get("download_count", 0) for v in variants)
        primary = max(variants, key=lambda v: v.get("download_count", 0))
        severity = primary.get("severity") or next((v.get("severity") for v in variants if v.get("severity")), "")
        team = primary.get("team") or next((v.get("team") for v in variants if v.get("team")), "")
        merged.append({
            "plugin_id": pid,
            "vulnerability": primary.get("vulnerability"),
            "severity": severity,
            "download_count": total_downloads,
            "team": team,
        })
    return merged


def _ai_automation_stats_rows(db, report_ids, download_role=None):
    """
    Extends admin_download_stats/user_download_stats with rows sourced
    from the AI-generated vulnerability_cards.automation_card, merged in
    ALONGSIDE the curated automation_scripts library rows _build_stats
    already builds — same real gap the Teams/Slack Register->Script tabs
    had (see teams_bot/register_tab.py's own rebuild): the curated library
    only ever covers a fixed ~63 plugin_ids, so a real report's automation
    coverage (which the AI generates per-vulnerability, unbounded) was
    invisible here. Explicit product request: put this straight in the
    existing /stats/ response so every consumer already calling it
    (website included, which has no code in this repo to update directly)
    picks it up with zero endpoint/URL changes on their side.

    Only "full"/"partial" cards are included (a card with no automation
    yet, or genuinely not_possible, has nothing to show/download here).
    download_count is automation_card's own aggregate counter (incremented
    by user_download_ai_automation_script on every download, admin or
    member) — the curated library's separate per-member script_user_downloads
    breakdown has no AI-automation equivalent yet, so this is a team-wide
    total for both the admin and member view, not a per-member count.

    download_role=None -> no download_url on any row (admin view, which is
    read-only same as the curated rows here). download_role="user" ->
    populates download_url with the actual member-facing AI download path.
    """
    if not report_ids:
        return []
    # Real bug report (round 2): vaptcode_analysis.severity (the
    # Vulnerability Analyst agent's own reassessment) was made to win over
    # automation_card.severity — that closed most mismatches, but a live
    # report still showed one for a finding where the AI's own analysis
    # ALSO disagreed with what Nessus actually reported. Register's
    # severity was never an AI value at all — it's the raw Nessus
    # risk_factor from vulnerabilities_by_host. Build that same lookup
    # (see upload_report.views._true_severity_lookup, which every
    # Teams/Slack path reaches through VulnerabilityCardListView/
    # UserVulnerabilityCardListAPIView) directly here too, since this
    # queries vulnerability_cards straight from Mongo rather than through
    # that API layer.
    from upload_report.views import _true_severity_lookup
    severity_lookup = {}
    for rid in report_ids:
        severity_lookup.update(_true_severity_lookup(db, rid))

    rows = []
    for card in db[VULN_CARD_COLLECTION].find(
        {"report_id": {"$in": list(report_ids)}, "automation_card.automation_status": {"$in": ["full", "partial"]}},
        {"_id": 0, "card_id": 1, "vulnerability_name": 1, "host_name": 1, "assigned_team": 1, "automation_card": 1, "vaptcode_analysis": 1},
    ):
        automation = card.get("automation_card") or {}
        severity = (
            severity_lookup.get((card.get("vulnerability_name"), card.get("host_name")))
            or (card.get("vaptcode_analysis") or {}).get("severity")
            or automation.get("severity")
            or ""
        )
        row = {
            "plugin_id": None,
            "card_id": card.get("card_id"),
            "vulnerability": card.get("vulnerability_name") or "Unknown",
            # Real bug report: the SAME vulnerability name legitimately
            # appears once per affected asset (a separate
            # vulnerability_cards document each) — without a host field on
            # each row, that looked like exact duplicate entries in every
            # consumer (website Script table, Teams/Slack Scripts list).
            # host distinguishes them; curated-library rows never had a
            # per-host concept (one script entry serves the whole report),
            # so theirs stays "" and every consumer should render that as
            # blank/omitted rather than a literal empty string.
            "host": (card.get("host_name") or "").strip(),
            "severity": severity,
            "download_count": automation.get("download_count", 0),
            "team": (card.get("assigned_team") or "").strip() or "Unassigned",
            "source": "ai",
            "automation_status": automation.get("automation_status"),
        }
        if download_role and card.get("card_id"):
            row["download_url"] = f"/api/{download_role}/automation-scripts/ai/{card['card_id']}/download/?type=fix"
        rows.append(row)
    return rows


def _merge_ai_and_curated_stats(curated_stats, ai_rows):
    """
    Prefers the AI row for any vulnerability that has one (richer, covers
    the full report — not just the curated 63) and only keeps a curated
    row when nothing AI-generated exists for that same vulnerability name,
    so the same finding never lists twice under two different automation
    sources.
    """
    ai_by_name = {(r["vulnerability"] or "").strip().lower(): r for r in ai_rows}
    merged = list(ai_rows)
    for s in curated_stats:
        key = (s.get("vulnerability") or "").strip().lower()
        if key in ai_by_name:
            continue
        s.setdefault("source", "curated")
        s.setdefault("host", "")  # no per-host concept in the curated library
        merged.append(s)
    return merged


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
    premium_required, message = _premium_required_message(str(request.user.id))
    if doc:
        return Response(_script_response(doc, available_os, premium_required, message))
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
    premium_required, message = _premium_required_message(str(request.user.id))
    results = [
        _script_response(by_plugin[pid][0], by_plugin[pid][1], premium_required, message) if by_plugin[pid][0]
        else _not_found_response(pid)
        for pid in int_ids
    ]
    return Response({"results": results, "premium_required": premium_required, "message": message})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def admin_match_scripts_by_name(request):
    """
    Body: { "vulnerability_names": ["Outdated OpenSSL", "Missing HSTS Header"], "os": "Windows" }

    Same idea as /match/bulk/ but for AWS Inspector / custom-report
    vulnerabilities, which don't carry a real Nessus plugin_id to send
    there (AWS: its own finding ID; custom: always none) — matches against
    the automation_scripts library by vulnerability name instead. The
    returned doc's OWN plugin_id (a real Nessus ID from the script
    library) is what /download/<plugin_id>/ then takes.
    """
    names = request.data.get("vulnerability_names", [])
    os_param = request.data.get("os")
    if not isinstance(names, list):
        return Response({"error": "vulnerability_names must be a list"}, status=400)

    name_keys = {_normalize_vuln_name(n) for n in names if isinstance(n, str) and n.strip()}
    matched = _fetch_scripts_by_name(name_keys, os=os_param)
    matched_by_key = {_normalize_vuln_name(d.get("vulnerability", "")): d for d in matched}

    premium_required, message = _premium_required_message(str(request.user.id))
    results = []
    for n in names:
        doc = matched_by_key.get(_normalize_vuln_name(n)) if isinstance(n, str) else None
        if doc:
            results.append(_script_response(doc, None, premium_required, message))
        else:
            results.append({"matched": False, "vulnerability_name": n, "message": "No automated fix available for this vulnerability."})
    return Response({"results": results, "premium_required": premium_required, "message": message})


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
    Columns: Vulnerability Name | Severity | No. of Times Downloaded | Team
    Scoped to the plugin_ids present across ALL of the admin's uploaded
    reports (not just the latest — see _load_all_reports_plugin_ids) —
    `automation_scripts` itself is a global collection shared across every
    admin/report, so without this filter every admin sees every script ever
    loaded, not just the ones relevant to their own data.

    "No. of Times Downloaded" is this admin's OWN team's total (summed
    across every UserDetail under this admin from script_user_downloads),
    not the global all-admins-on-the-platform counter stored on
    automation_scripts.download_count.
    """
    admin_id = str(request.user.id)
    admin_email = getattr(request.user, "email", None)

    # Freemium admins can never actually download a script (see
    # assert_can_use_automation_scripts, enforced in user_download_script),
    # so script_user_downloads stays permanently empty for them and every
    # count below would show a plain "0" — indistinguishable from "nobody's
    # gotten around to it yet" on a Premium account. Surface WHY instead,
    # so the frontend can show an upgrade prompt rather than a misleading 0.
    from billing.enforcement import is_freemium, _is_unlimited_admin
    premium_required = is_freemium(request.user) and not _is_unlimited_admin(request.user)

    member_emails = []
    if UserDetail:
        member_emails = list(
            UserDetail.objects.filter(admin_id=admin_id).values_list("email", flat=True)
        )

    with MongoContext() as db:
        report_id, uploaded_at, report_ids, plugin_ids, vuln_names = _load_all_reports_plugin_ids(db, admin_id, admin_email)

        if not report_id:
            return Response(
                {"detail": "No reports found for your account", "count": 0, "stats": []},
                status=404,
            )

        docs = list(db["automation_scripts"].find(
            {"plugin_id": {"$in": list(plugin_ids)}},
            {"_id": 0, "plugin_id": 1, "vulnerability": 1, "severity": 1, "download_count": 1, "os": 1}
        ))
        # AWS/custom report vulnerabilities don't carry a real Nessus
        # plugin_id (AWS: its own finding ID; custom: always None) — match
        # those by vulnerability name instead, against the same library.
        seen_keys = {(d.get("plugin_id"), (d.get("os") or "").strip().lower()) for d in docs}
        for d in _fetch_scripts_by_name(vuln_names):
            key = (d.get("plugin_id"), (d.get("os") or "").strip().lower())
            if key not in seen_keys:
                seen_keys.add(key)
                docs.append({"plugin_id": d.get("plugin_id"), "vulnerability": d.get("vulnerability"), "severity": d.get("severity"), "download_count": d.get("download_count") or 0, "os": d.get("os")})
        docs.sort(key=lambda d: d.get("download_count", 0), reverse=True)

        all_plugin_ids = list({d.get("plugin_id") for d in docs if d.get("plugin_id") is not None})

        team_count_by_key = {}
        if member_emails and all_plugin_ids:
            for row in db["script_user_downloads"].find(
                {"plugin_id": {"$in": all_plugin_ids}, "user_email": {"$in": member_emails}},
                {"_id": 0, "plugin_id": 1, "os": 1, "download_count": 1},
            ):
                key = (row["plugin_id"], (row.get("os") or "").strip().lower())
                team_count_by_key[key] = team_count_by_key.get(key, 0) + row.get("download_count", 0)

    # Replace the global counter with this admin's own team's total before
    # formatting, matched by (plugin_id, os) since a plugin_id can have
    # multiple OS variants.
    for d in docs:
        key = (d.get("plugin_id"), (d.get("os") or "").strip().lower())
        d["download_count"] = team_count_by_key.get(key, 0)

    curated_stats = _build_stats(docs, report_id=report_ids)
    with MongoContext() as db:
        ai_rows = _ai_automation_stats_rows(db, report_ids)
    stats = _merge_ai_and_curated_stats(curated_stats, ai_rows)
    stats.sort(key=lambda s: s["download_count"], reverse=True)
    return Response({
        "report_id": str(report_id),
        "count": len(stats),
        "stats": stats,
        "premium_required": premium_required,
        "message": (
            "Automation scripts are not available on the Freemium plan — download counts will stay "
            "at 0 until you upgrade to Premium." if premium_required else None
        ),
    })


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
    _admin_id, _, _ = _resolve_admin_and_teams(request)
    premium_required, message = _premium_required_message(_admin_id)
    if doc:
        return Response(_script_response(doc, available_os, premium_required, message))
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
    _admin_id, _, _ = _resolve_admin_and_teams(request)
    premium_required, message = _premium_required_message(_admin_id)
    results = [
        _script_response(by_plugin[pid][0], by_plugin[pid][1], premium_required, message) if by_plugin[pid][0]
        else _not_found_response(pid)
        for pid in int_ids
    ]
    return Response({"results": results, "premium_required": premium_required, "message": message})


@api_view(["POST"])
@permission_classes([IsAuthenticated])
def user_match_scripts_by_name(request):
    """User-side counterpart to admin_match_scripts_by_name — same AWS/
    custom-report fallback, same request/response shape."""
    names = request.data.get("vulnerability_names", [])
    os_param = request.data.get("os")
    if not isinstance(names, list):
        return Response({"error": "vulnerability_names must be a list"}, status=400)

    name_keys = {_normalize_vuln_name(n) for n in names if isinstance(n, str) and n.strip()}
    matched = _fetch_scripts_by_name(name_keys, os=os_param)
    matched_by_key = {_normalize_vuln_name(d.get("vulnerability", "")): d for d in matched}

    _admin_id, _, _ = _resolve_admin_and_teams(request)
    premium_required, message = _premium_required_message(_admin_id)
    results = []
    for n in names:
        doc = matched_by_key.get(_normalize_vuln_name(n)) if isinstance(n, str) else None
        if doc:
            results.append(_script_response(doc, None, premium_required, message))
        else:
            results.append({"matched": False, "vulnerability_name": n, "message": "No automated fix available for this vulnerability."})
    return Response({"results": results, "premium_required": premium_required, "message": message})


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
    user_email = getattr(request.user, "email", "")
    if request.user.is_staff or request.user.is_superuser:
        logger.warning(f"[ScriptDownload] blocked — admin/superuser tried to download plugin_id={plugin_id} (email={user_email})")
        return Response(
            {"error": "Admins cannot download scripts. Read-only access only."},
            status=403
        )

    # 🔹 Plan gate — automation scripts are a Premium feature.
    from billing.enforcement import assert_can_use_automation_scripts, PlanLimitExceeded
    admin_id, _admin_email, _teams = _resolve_admin_and_teams(request)
    try:
        assert_can_use_automation_scripts(admin_id)
    except PlanLimitExceeded as e:
        logger.info(f"[ScriptDownload] plan-blocked — plugin_id={plugin_id} email={user_email} admin_id={admin_id}: {e}")
        return Response({"error": str(e)}, status=403)

    os_param = request.query_params.get("os")
    doc, available_os = _fetch_script(plugin_id, os=os_param)
    if not doc:
        # Real bug candidate: no logging existed anywhere in this view
        # before, so a silent 404 here (e.g. ?os= not matching any variant
        # this plugin_id actually has) was completely untraceable — looked
        # to the user like "I downloaded it" (whatever the frontend does
        # on a non-200) while download_count/script_user_downloads never
        # got touched at all.
        logger.warning(f"[ScriptDownload] no matching script — plugin_id={plugin_id} os_param={os_param!r} available_os={available_os} email={user_email}")
        return Response(_not_found_response(plugin_id), status=404)

    fix_script_path = doc.get("fix_script_path")
    if not fix_script_path:
        logger.warning(f"[ScriptDownload] doc has no fix_script_path — plugin_id={plugin_id} os={doc.get('os')} email={user_email}")
        return Response({"error": "Script file not available for this vulnerability."}, status=404)

    full_path = BASE_DIR / fix_script_path
    if not full_path.exists():
        logger.warning(f"[ScriptDownload] file missing on disk — plugin_id={plugin_id} os={doc.get('os')} path={full_path} email={user_email}")
        return Response({"error": f"Script file not found on server: {fix_script_path}"}, status=404)

    # Explicit UTC offset (not just .isoformat() on a naive value) so any
    # consumer that parses this string — a browser's `new Date(...)`
    # included — doesn't silently mistake it for its own local time.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with MongoContext() as db:
        db["automation_scripts"].update_one(
            {"plugin_id": int(plugin_id), "os": doc.get("os")},
            {"$inc": {"download_count": 1}}
        )
        # Per-user download record — lets user_download_stats show what THIS
        # user downloaded, separate from the global (all-users) counter above.
        result = db["script_user_downloads"].update_one(
            {"plugin_id": int(plugin_id), "os": doc.get("os"), "user_email": user_email},
            {
                "$inc": {"download_count": 1},
                "$set": {"last_downloaded_at": now},
                "$setOnInsert": {"first_downloaded_at": now},
            },
            upsert=True,
        )
    logger.info(
        f"[ScriptDownload] OK — plugin_id={plugin_id} os={doc.get('os')} email={user_email} "
        f"matched={result.matched_count} modified={result.modified_count} upserted_id={result.upserted_id}"
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
    Columns: Vulnerability Name | Severity | No. of Times Downloaded | Team
    Scoped to the plugin_ids present across ALL of the member's admin's
    uploaded reports, then further filtered to the member's own assigned team(s).
    ?team=Patch+Management — narrow to one specific team when the member
    belongs to more than one (same convention as register/latest/vulns/).

    "No. of Times Downloaded" here is THIS member's own downloads only —
    admin_download_stats (the admin's own view) is the one that shows the
    whole team's combined total; a member's Scripts tab shows just what
    they personally downloaded, not everyone's combined count.
    """
    admin_id, admin_email, teams = _resolve_admin_and_teams(request)
    if not admin_id or not teams:
        return Response(
            {"detail": "User is not linked to any team. Ask your admin to assign you a team.",
             "count": 0, "stats": []},
            status=403,
        )

    # See the matching comment in admin_download_stats — a Freemium admin's
    # members can never actually download a script, so this member's own
    # count will always show 0 too; surface why instead of leaving it
    # looking like a plain "haven't downloaded yet" count.
    from billing.enforcement import is_freemium, _is_unlimited_admin
    premium_required = is_freemium(admin_id) and not _is_unlimited_admin(admin_id)

    selected_team = request.query_params.get("team", "").strip()
    active_teams = [selected_team] if selected_team and selected_team in teams else teams
    teams_lower = {t.lower() for t in active_teams}

    member_emails = [request.user.email] if getattr(request.user, "email", None) else []

    with MongoContext() as db:
        report_id, uploaded_at, report_ids, plugin_ids, vuln_names = _load_all_reports_plugin_ids(db, admin_id, admin_email)

        if not report_id:
            return Response(
                {"detail": "No reports found for your admin account", "count": 0, "stats": []},
                status=404,
            )

        docs = list(db["automation_scripts"].find(
            {"plugin_id": {"$in": list(plugin_ids)}},
            {"_id": 0, "plugin_id": 1, "vulnerability": 1, "severity": 1, "download_count": 1, "os": 1}
        ))
        # AWS/custom report vulnerabilities don't carry a real Nessus
        # plugin_id — match those by vulnerability name against the library.
        seen_keys = {(d.get("plugin_id"), (d.get("os") or "").strip().lower()) for d in docs}
        for d in _fetch_scripts_by_name(vuln_names):
            key = (d.get("plugin_id"), (d.get("os") or "").strip().lower())
            if key not in seen_keys:
                seen_keys.add(key)
                docs.append({"plugin_id": d.get("plugin_id"), "vulnerability": d.get("vulnerability"), "severity": d.get("severity"), "download_count": d.get("download_count") or 0, "os": d.get("os")})
        docs.sort(key=lambda d: d.get("download_count", 0), reverse=True)

        all_plugin_ids = list({d.get("plugin_id") for d in docs if d.get("plugin_id") is not None})

        own_count_by_key = {}
        if member_emails and all_plugin_ids:
            for row in db["script_user_downloads"].find(
                {"plugin_id": {"$in": all_plugin_ids}, "user_email": {"$in": member_emails}},
                {"_id": 0, "plugin_id": 1, "os": 1, "download_count": 1},
            ):
                key = (row["plugin_id"], (row.get("os") or "").strip().lower())
                own_count_by_key[key] = own_count_by_key.get(key, 0) + row.get("download_count", 0)
    logger.info(
        f"[ScriptStats:user] email={member_emails} plugin_ids={all_plugin_ids} "
        f"own_download_rows_matched={len(own_count_by_key)} keys={list(own_count_by_key.keys())}"
    )

    # Replace the global counter with just THIS member's own count before
    # formatting, matched by (plugin_id, os) since a plugin_id can have
    # multiple OS variants.
    for d in docs:
        key = (d.get("plugin_id"), (d.get("os") or "").strip().lower())
        d["download_count"] = own_count_by_key.get(key, 0)

    curated_stats = [s for s in _build_stats(docs, report_id=report_ids) if s["team"].lower() in teams_lower]
    with MongoContext() as db:
        ai_rows = [
            r for r in _ai_automation_stats_rows(db, report_ids, download_role="user")
            if (r.get("team") or "").lower() in teams_lower
        ]
    stats = _merge_ai_and_curated_stats(curated_stats, ai_rows)
    stats.sort(key=lambda s: s["download_count"], reverse=True)
    return Response({
        "report_id": str(report_id),
        "teams": active_teams,
        "count": len(stats),
        "stats": stats,
        "premium_required": premium_required,
        "message": (
            "Automation scripts are not available on your admin's Freemium plan — download counts "
            "will stay at 0 until they upgrade to Premium." if premium_required else None
        ),
    })


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
    # Explicit UTC offset (not just .isoformat() on a naive value) so any
    # consumer that parses this string — a browser's `new Date(...)`
    # included — doesn't silently mistake it for its own local time.
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

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


# ── AI-GENERATED AUTOMATION (per vulnerability_cards document) ─────────────
#
# Separate from everything above: the ~63-plugin "automation_scripts"
# library is a small, human-curated, Google-Sheet-synced reference set.
# Every vulnerability_cards document (ANY finding, in ANY report — not just
# those 63) now also carries its OWN "automation_card" sub-document, written
# once by the Automation Engineer agent (see upload_report/mitigation_tool.py
# / upload_report/crew_agent/{agents,tasks}.py) and reused from then on for
# the same (vulnerability_name, description, os_category) — same caching
# already used for the manual mitigation card itself.

def _find_vuln_card(card_id, admin_id):
    with MongoContext() as db:
        return db[VULN_CARD_COLLECTION].find_one(
            {"card_id": card_id, "admin_id": str(admin_id)}, {"_id": 0}
        )


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def admin_view_ai_automation(request, card_id):
    """
    Admin read-only view of the AI automation-feasibility result for one
    vulnerability card. Same "admins cannot download, read-only only"
    convention as the curated library, and same Freemium lock on the actual
    script content (fix_script/verify_script stripped out; everything else
    — status, what can/can't be automated, considerations — stays visible).
    """
    if not (request.user.is_staff or request.user.is_superuser):
        return Response({"error": "Admin access only."}, status=403)

    admin_id = str(request.user.id)
    card = _find_vuln_card(card_id, admin_id)
    if not card:
        return Response({"error": "Vulnerability card not found or access denied"}, status=404)

    automation = card.get("automation_card") or {}
    if not automation:
        return Response({"matched": False, "message": "No automation analysis available for this card yet."}, status=404)

    premium_required, message = _premium_required_message(admin_id)
    safe = {k: v for k, v in automation.items() if k not in ("fix_script", "verify_script")}
    return Response({
        "matched": True,
        "card_id": card_id,
        "premium_required": premium_required,
        "message": message if premium_required else None,
        **safe,
    })


@api_view(["GET"])
@permission_classes([IsAuthenticated])
def user_download_ai_automation_script(request, card_id):
    """
    Member-side download of the AI-generated fix/verify script attached to
    one vulnerability card. Same plan gate (assert_can_use_automation_scripts),
    same "admins cannot download" rule, and same download_count bookkeeping
    convention as user_download_script already applies to the curated
    library — just sourced from vulnerability_cards.automation_card (a
    string in Mongo) instead of a file on disk.

    ?type=fix|verify — defaults to "fix".
    """
    if request.user.is_staff or request.user.is_superuser:
        return Response(
            {"error": "Admins cannot download scripts. Read-only access only."},
            status=403,
        )

    from billing.enforcement import assert_can_use_automation_scripts, PlanLimitExceeded
    admin_id, _admin_email, teams = _resolve_admin_and_teams(request)
    if not admin_id:
        return Response({"error": "You are not linked to any admin account."}, status=403)
    try:
        assert_can_use_automation_scripts(admin_id)
    except PlanLimitExceeded as e:
        return Response({"error": str(e)}, status=403)

    card = _find_vuln_card(card_id, admin_id)
    if not card:
        return Response({"error": "Vulnerability card not found."}, status=404)

    # Real gap found via frontend review: this only checked the card's
    # OWNING ADMIN (organization-level) — a team member could download an
    # automation script for a card assigned to a DIFFERENT team under the
    # same admin. Same team-isolation every other member-scoped endpoint
    # already enforces (e.g. userasset's UserAssetVulnerabilitiesByHostAPIView
    # only returns vulnerabilities whose assigned_team is one of the
    # caller's own teams) — apply it here too. teams is None for an admin/
    # superuser caller (already blocked above), so this only ever runs for
    # a genuine member.
    card_team = (card.get("assigned_team") or "").strip().lower()
    member_teams = {t.strip().lower() for t in (teams or [])}
    if not card_team or card_team not in member_teams:
        return Response({"error": "You do not have access to this vulnerability card."}, status=403)

    automation = card.get("automation_card") or {}
    if not automation or automation.get("automation_status") == "not_possible":
        return Response(
            {
                "error": (automation.get("reason_not_possible") if automation else None)
                or "Automation not possible for this vulnerability — manual remediation required.",
            },
            status=404,
        )

    script_type = (request.query_params.get("type") or "fix").strip().lower()
    if script_type not in ("fix", "verify"):
        return Response({"error": "type must be 'fix' or 'verify'."}, status=400)

    content = (automation.get(f"{script_type}_script") or "").strip()
    if not content:
        return Response(
            {"error": f"No {script_type} script available for this vulnerability."},
            status=404,
        )
    # automation_card.language is always "python" (see AUTOMATION_CARD_SCHEMA/
    # crew_agent/tasks.py's Automation Engineer prompt) — real bug report:
    # AUTOMATION_CARD_SCHEMA has never actually included a
    # *_script_filename field, so this fell back to a bare
    # "<card_id>_fix.txt" on every real card, which read as "not actually
    # a script" even when the content was a complete, real Python file.
    # Still honor an explicit *_script_filename if one is ever present
    # (forward-compatible), but build a real .py name from the AI's own
    # script_name otherwise.
    explicit_name = automation.get(f"{script_type}_script_filename")
    if explicit_name:
        filename = explicit_name
    else:
        base_name = re.sub(r"[^A-Za-z0-9_-]+", "_", automation.get("script_name") or card_id).strip("_") or card_id
        filename = f"{base_name}_{script_type}.py"

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with MongoContext() as db:
        db[VULN_CARD_COLLECTION].update_one(
            {"card_id": card_id},
            {
                "$inc": {"automation_card.download_count": 1},
                "$set": {"automation_card.last_downloaded_at": now},
            },
        )

    response = HttpResponse(content, content_type="text/x-python; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    return response
