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
        logger.warning(f"[MergeUpload] target report_id={target_report_id} not found — nothing to merge into")
        return {"total_hosts": 0, "total_vulnerabilities": 0}

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
