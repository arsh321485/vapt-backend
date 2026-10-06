"""
Same-day report merging.

Business rule: if an admin uploads more than one file on the SAME calendar
day, the parsed data (hosts + vulnerabilities) all lands in the ONE report
that was created first that day — not as separate reports — so the
dashboard/asset/vuln views the admin sees always reflect everything
uploaded "today" as a single combined picture. The next calendar day starts
a fresh report again.

Each physical file still gets its own `UploadReport` row (for file storage
and hash-based duplicate detection) — only the Mongo-side `nessus_reports`
document (and downstream vulnerability_cards) are keyed off the shared
"today's report_id" once one exists.
"""
import datetime
import logging
import re

logger = logging.getLogger(__name__)

NESSUS_COLLECTION = "nessus_reports"


def _normalize_plugin_name(name: str) -> str:
    """
    Case/whitespace-insensitive key for the merge dedup below.

    Real bug report: re-uploading the SAME custom (AI-extracted) report
    file on the same day kept inflating the vulnerability count (6 -> 15
    -> 18 across repeated uploads of one unchanged PDF) even though the
    exact-string dedup here was working as designed. The AI extraction
    (custom_report_ai.py) re-parses the document fresh on every upload —
    GPT-4o-mini's wording for the same underlying finding can vary
    slightly between calls even at temperature=0 (extra/missing
    whitespace, punctuation, capitalization), so the same vulnerability
    came back as a *different* plugin_name string each time and the
    exact-match set below never recognized it as something it already
    had. Native Nessus/AWS reports don't hit this at all — their
    plugin_name comes from the scanner's own fixed plugin catalog, always
    byte-identical for the same finding. Collapsing whitespace/punctuation
    and case before comparing (not changing what's stored, only what's
    compared) catches the wording drift this specific report type can
    produce — including trailing punctuation the AI adds inconsistently
    between runs (e.g. "... Systems" vs "... Systems.", confirmed as a
    real miss when only whitespace/case were normalized) — without
    touching the intentional "no duplicate-file check" policy for
    Premium/unlimited admins.
    """
    return re.sub(r"[^a-z0-9]+", " ", (name or "").lower()).strip()


def get_merge_target_report_id(admin, exclude_pk=None) -> str | None:
    """
    Returns the report_id of this admin's most recent successfully-stored
    upload, regardless of day — every new upload (magic link or normal)
    merges into it, instead of only merging within the same calendar day.
    `exclude_pk` skips the upload currently being processed (its own row is
    saved before this runs, so it would otherwise be picked as its own target).
    """
    from .models import UploadReport
    from vaptfix.mongo_client import MongoContext

    qs = UploadReport.objects.filter(admin=admin)
    if exclude_pk is not None:
        qs = qs.exclude(pk=exclude_pk)
    candidates = [str(r._id) for r in qs.order_by("-uploaded_at")[:20]]
    if not candidates:
        return None
    # Only a row that actually has a stored nessus_reports document can be a
    # merge target — an upload row without one (e.g. a failed or extra row)
    # would otherwise silently swallow the new data.
    with MongoContext() as db:
        for rid in candidates:
            if db[NESSUS_COLLECTION].find_one({"report_id": rid}, {"_id": 1}):
                return rid
    return None


def get_todays_report_id(admin) -> str | None:
    """
    Returns the report_id (str) of this admin's FIRST successfully-processed
    upload today, or None if they haven't uploaded anything yet today.
    """
    from django.utils import timezone
    from .models import UploadReport

    now = timezone.now()
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    first_today = (
        UploadReport.objects.filter(admin=admin, uploaded_at__gte=start_of_today)
        .order_by("uploaded_at")
        .first()
    )
    return str(first_today._id) if first_today else None


_BARE_VERSION_HOST_RE = re.compile(r"^\d+(?:\.\d+){0,2}$")

DOWNSTREAM_REPORT_ID_COLLECTIONS = (
    "vulnerability_cards",
    "fix_vulnerabilities",
    "fix_vulnerabilities_closed",
    "hold_vulnerabilities",
    "deleted_vulnerabilities",
)


def heal_todays_reports(db, admin_id: str = None, admin_email: str = None) -> str | None:
    """
    Real bug report: the upload-time mutex (UploadReportView.post()) that's
    supposed to prevent same-day uploads splitting into separate reports
    has repeatedly failed to prevent exactly that in production, across
    several real admins — root cause still unconfirmed (a MongoDB trace
    added to that exact code path recorded ZERO hits across multiple
    fresh, confirmed-post-deploy tests, meaning whatever process actually
    serves uploads isn't running that code at all, for a reason that
    couldn't be pinned down from here without direct server access).

    Rather than depend on fixing that elusive write-time race, this heals
    the SYMPTOM on the READ side instead: called from the admin-facing
    endpoints users actually look at (dashboard summary, Register list),
    it finds every nessus_reports doc for this admin uploaded since local
    midnight and, if there's more than one, merges them all into the
    earliest one — same merge_hosts_into_report logic + downstream
    (vulnerability_cards/fix_vulnerabilities/hold/deleted) report_id
    repointing already used for every one-off manual fix of this same
    bug this session. Idempotent and cheap when there's nothing to heal
    (single query, no write) — safe to call on every request.

    Also folds in the "stray version-number host" cleanup (e.g. a bare
    "8.0" split off "Outdated Microsoft IIS 8.0" into its own fake host)
    for whatever survives as the final merged report, since that's shown
    up on every one of these split reports so far — see
    upload_report.custom_report_ai._merge_stray_version_hosts, which only
    ever runs at extraction time and never touches already-stored data.

    Returns the surviving (possibly newly-merged) report_id for today, or
    None if this admin hasn't uploaded anything today at all.
    """
    from django.utils import timezone

    if not admin_id and not admin_email:
        return None

    now = timezone.now()
    start_of_today = now.replace(hour=0, minute=0, second=0, microsecond=0)

    query_conditions = []
    if admin_id:
        query_conditions.append({"admin_id": str(admin_id)})
    if admin_email:
        query_conditions.append({"admin_email": admin_email})

    coll = db[NESSUS_COLLECTION]
    todays_docs = list(
        coll.find(
            {"$or": query_conditions, "uploaded_at": {"$gte": start_of_today}},
        ).sort("uploaded_at", 1)
    )
    if not todays_docs:
        return None

    target_doc = todays_docs[0]
    target_id = target_doc["report_id"]
    source_docs = todays_docs[1:]

    if source_docs:
        logger.warning(
            f"[MergeUpload] heal_todays_reports found {len(todays_docs)} reports for "
            f"admin_id={admin_id} admin_email={admin_email} today — merging "
            f"{len(source_docs)} into {target_id}"
        )
        for src in source_docs:
            sid = src["report_id"]
            try:
                merge_hosts_into_report(db, target_id, src.get("vulnerabilities_by_host") or [])
            except Exception:
                logger.exception(f"[MergeUpload] heal: merge of {sid} into {target_id} failed")
                continue

            # Carry over any already-computed asset classifications rather
            # than losing them (the merged host set gets re-classified
            # lazily anyway, but no need to throw away work already done).
            src_map = {r.get("host_name"): r.get("asset_type") for r in (src.get("asset_type_map") or [])}
            if src_map:
                tgt_fresh = coll.find_one({"report_id": target_id}, {"asset_type_map": 1}) or {}
                tgt_map = {r.get("host_name"): r.get("asset_type") for r in (tgt_fresh.get("asset_type_map") or [])}
                merged_map = {**src_map, **tgt_map}
                coll.update_one(
                    {"report_id": target_id},
                    {"$set": {"asset_type_map": [{"host_name": k, "asset_type": v} for k, v in merged_map.items()]}},
                )

            for coll_name in DOWNSTREAM_REPORT_ID_COLLECTIONS:
                db[coll_name].update_many({"report_id": sid}, {"$set": {"report_id": target_id}})

            coll.delete_one({"report_id": sid})

        # All merged content already had cards generated in its own
        # (now-deleted) source report — never re-trigger generation.
        coll.update_one({"report_id": target_id}, {"$set": {"cards_generation_complete": True}})

    # Stray version-number host cleanup (see docstring) — runs even when
    # there was only ever one report today, since a single extraction run
    # can produce this on its own.
    changed_hosts = _heal_stray_version_hosts(db, target_id)

    # Real bug report: healing MongoDB alone wasn't enough — every
    # per-metric dashboard endpoint (AdminTotalAssetsAPIView,
    # AdminVulnerabilitiesAPIView, etc.) keeps its OWN independent cache
    # (up to 300s), checked before it ever re-reads Mongo. Without busting
    # those too, a page loaded within that window kept showing the exact
    # stale per-file counts (e.g. "15") this heal had just fixed
    # underneath it. Only worth doing when something actually changed —
    # the common case (nothing to heal) shouldn't pay for a cache-clear
    # round trip on every single request.
    if source_docs or changed_hosts:
        _bust_dashboard_caches(admin_id)

    return target_id


def _bust_dashboard_caches(admin_id) -> None:
    if not admin_id:
        return
    from django.core.cache import cache

    for key in (
        f"admin_total_assets_{admin_id}",
        f"admin_avg_score_{admin_id}",
        f"admin_vulnerabilities_{admin_id}",
        f"admin_inprocess_timeline_{admin_id}",
        f"admin_dashboard_summary_{admin_id}",
        f"mitigation_by_team_v2_{admin_id}",
        f"admin_register_list_{admin_id}",
        f"admin_asset_list_{admin_id}",
    ):
        cache.delete(key)


def _heal_stray_version_hosts(db, report_id: str) -> None:
    doc = db[NESSUS_COLLECTION].find_one({"report_id": report_id}, {"vulnerabilities_by_host": 1})
    if not doc:
        return
    vbh = doc.get("vulnerabilities_by_host") or []
    stray_indices = [
        i for i, h in enumerate(vbh)
        if _BARE_VERSION_HOST_RE.match((h.get("host_name") or "").strip())
    ]
    if not stray_indices:
        return

    to_drop = set()
    for i in stray_indices:
        stray = vbh[i]
        for j in (i - 1, i + 1):
            if j < 0 or j >= len(vbh) or j in stray_indices:
                continue
            neighbor = vbh[j]
            if not neighbor.get("vulnerabilities"):
                neighbor.setdefault("vulnerabilities", []).extend(stray.get("vulnerabilities") or [])
                good_host = neighbor.get("host_name")
                bad_host = stray.get("host_name")
                logger.warning(
                    f"[MergeUpload] heal: dropped stray version-number host "
                    f"'{bad_host}' on report_id={report_id} — merged into '{good_host}'"
                )
                card = db["vulnerability_cards"].find_one({"report_id": report_id, "host_name": bad_host})
                if card:
                    db["vulnerability_cards"].update_one({"_id": card["_id"]}, {"$set": {"host_name": good_host}})
                fx = db["fix_vulnerabilities"].find_one({"report_id": report_id, "host_name": bad_host})
                if fx:
                    db["fix_vulnerabilities"].update_one({"_id": fx["_id"]}, {"$set": {"host_name": good_host}})
                to_drop.add(i)
                break

    if not to_drop:
        return
    new_vbh = [h for i, h in enumerate(vbh) if i not in to_drop]
    db[NESSUS_COLLECTION].update_one(
        {"report_id": report_id},
        {"$set": {"vulnerabilities_by_host": new_vbh, "total_hosts": len(new_vbh)}},
    )


def merge_hosts_into_report(db, target_report_id: str, new_hosts: list) -> dict:
    """
    Merges `new_hosts` (already run through _prepare_hosts_for_storage —
    same shape as what a fresh insert would store) into the existing
    nessus_reports document at report_id=target_report_id.

    - A host with a host_name that already exists in the target report has
      its vulnerabilities merged in (deduped by plugin_name — an existing
      finding for that host is left as-is, only genuinely new plugin_names
      are appended).
    - A host_name not already present is appended as a new host entry.

    Resets cards_generation_complete to False so the existing status-polling
    (UploadCardsStatusAPIView, used by both the website and the Slack
    watcher) correctly reports "still processing" until card generation for
    the newly-merged content finishes — the SAME mechanism used for a
    first-time upload, no separate progress system needed.

    Returns {"total_hosts": int, "total_vulnerabilities": int} for the
    merged document after the update.
    """
    coll = db[NESSUS_COLLECTION]
    existing = coll.find_one({"report_id": target_report_id})
    if not existing:
        raise ValueError(f"merge target report_id={target_report_id} has no stored report — refusing to report success")

    existing_hosts = existing.get("vulnerabilities_by_host") or []
    by_host_name = {h.get("host_name"): h for h in existing_hosts if h.get("host_name")}

    for new_host in new_hosts:
        host_name = new_host.get("host_name")
        if not host_name:
            continue

        if host_name not in by_host_name:
            # Brand new host this admin hasn't reported before — append whole.
            existing_hosts.append(new_host)
            by_host_name[host_name] = new_host
            continue

        # Host already exists — merge in only genuinely new vulnerabilities
        # (same plugin_name on this host = already have it, skip). Compared
        # normalized (see _normalize_plugin_name) so re-uploading the same
        # custom-report file doesn't inflate the count just because the AI
        # worded an already-known finding slightly differently this time.
        target_host = by_host_name[host_name]
        existing_plugin_names = {
            _normalize_plugin_name(v.get("plugin_name"))
            for v in (target_host.get("vulnerabilities") or []) if v.get("plugin_name")
        }
        for vuln in (new_host.get("vulnerabilities") or []):
            norm_name = _normalize_plugin_name(vuln.get("plugin_name"))
            if norm_name and norm_name not in existing_plugin_names:
                target_host.setdefault("vulnerabilities", []).append(vuln)
                existing_plugin_names.add(norm_name)

    total_hosts = len(existing_hosts)
    total_vulnerabilities = sum(len(h.get("vulnerabilities") or []) for h in existing_hosts)

    coll.update_one(
        {"report_id": target_report_id},
        {
            "$set": {
                "vulnerabilities_by_host": existing_hosts,
                "total_hosts": total_hosts,
                "total_vulnerabilities": total_vulnerabilities,
                "last_merged_at": datetime.datetime.utcnow(),
                # Let the existing status-polling machinery (shared by the
                # website and the Slack progress watcher) correctly show
                # "processing" again until the newly-merged vulnerabilities
                # have cards generated for them.
                "cards_generation_complete": False,
            }
        },
    )

    return {"total_hosts": total_hosts, "total_vulnerabilities": total_vulnerabilities}
