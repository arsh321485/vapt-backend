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

logger = logging.getLogger(__name__)

NESSUS_COLLECTION = "nessus_reports"


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
        # (same plugin_name on this host = already have it, skip).
        target_host = by_host_name[host_name]
        existing_plugin_names = {
            v.get("plugin_name") for v in (target_host.get("vulnerabilities") or []) if v.get("plugin_name")
        }
        for vuln in (new_host.get("vulnerabilities") or []):
            if vuln.get("plugin_name") not in existing_plugin_names:
                target_host.setdefault("vulnerabilities", []).append(vuln)
                existing_plugin_names.add(vuln.get("plugin_name"))

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
