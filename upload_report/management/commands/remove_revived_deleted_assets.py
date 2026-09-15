"""
One-off cleanup for the real bug fixed in adminasset.AssetDeleteAPIView /
upload_report.views.unlock_freemium_hosts_for_admin — before those fixes,
deleting a Freemium-visible host that had an "overflow twin" entry in
locked_hosts (billing.enforcement.select_freemium_active_hosts' per-host
fair-share trimming) left that twin behind; a later Premium upgrade's
unlock_freemium_hosts_for_admin then found the host_name absent from
vulnerabilities_by_host and silently re-added it, reviving a deliberately
deleted asset.

Both code paths are now fixed going forward, but an admin whose
delete-then-upgrade sequence already happened under the OLD code has the
revived host sitting in vulnerabilities_by_host right now — the code fix
alone doesn't undo that. This command finds it and removes it again,
using the deleted_assets collection (adminasset.AssetDeleteAPIView's own
audit trail) as the source of truth for "this host_name was deliberately
deleted for this report_id".

Usage:
    python manage.py remove_revived_deleted_assets --dry-run
    python manage.py remove_revived_deleted_assets
    python manage.py remove_revived_deleted_assets --report-id <id>
"""
from django.core.management.base import BaseCommand
from vaptfix.mongo_client import get_shared_client, get_shared_db

NESSUS_COLLECTION = "nessus_reports"
DELETED_ASSETS_COLLECTION = "deleted_assets"


class Command(BaseCommand):
    help = "Re-remove any host that was deliberately deleted but got revived by the old unlock_freemium_hosts_for_admin bug"

    def add_arguments(self, parser):
        parser.add_argument("--report-id", help="Only check/fix this one report_id.")
        parser.add_argument("--dry-run", action="store_true", help="Report what would change without writing.")

    def handle(self, *args, **options):
        client = get_shared_client()
        db = get_shared_db(client)
        coll = db[NESSUS_COLLECTION]
        dry_run = options.get("dry_run")

        report_query = {"report_id": options["report_id"]} if options.get("report_id") else {}

        reports_checked = 0
        reports_fixed = 0
        total_revived_removed = 0

        for report in coll.find(report_query, {"report_id": 1, "vulnerabilities_by_host": 1}):
            reports_checked += 1
            report_id = report.get("report_id")

            deleted_host_names = {
                (d.get("host_name") or "").strip()
                for d in db[DELETED_ASSETS_COLLECTION].find({"report_id": str(report_id)}, {"host_name": 1})
                if d.get("host_name")
            }
            if not deleted_host_names:
                continue

            hosts = report.get("vulnerabilities_by_host") or []
            revived = [
                h for h in hosts
                if (h.get("host_name") or h.get("host") or "").strip() in deleted_host_names
            ]
            if not revived:
                continue

            remaining_hosts = [
                h for h in hosts
                if (h.get("host_name") or h.get("host") or "").strip() not in deleted_host_names
            ]
            total_vulns = sum(len(h.get("vulnerabilities") or []) for h in remaining_hosts)

            revived_names = [(h.get("host_name") or h.get("host") or "").strip() for h in revived]
            self.stdout.write(
                f"report_id={report_id}: {len(revived)} revived host(s) found — {revived_names} "
                f"-> would leave total_hosts={len(remaining_hosts)} total_vulnerabilities={total_vulns}"
            )
            reports_fixed += 1
            total_revived_removed += len(revived)

            if not dry_run:
                coll.update_one(
                    {"report_id": report_id},
                    {"$set": {
                        "vulnerabilities_by_host": remaining_hosts,
                        "total_hosts": len(remaining_hosts),
                        "total_vulnerabilities": total_vulns,
                    }},
                )

        if reports_fixed == 0:
            self.stdout.write(self.style.SUCCESS(f"Checked {reports_checked} report(s) — no revived deleted assets found."))
            return

        verb = "Would remove" if dry_run else "Removed"
        self.stdout.write(self.style.SUCCESS(
            f"Checked {reports_checked} report(s). {verb} {total_revived_removed} revived host(s) across {reports_fixed} report(s)."
        ))
        if dry_run:
            self.stdout.write(self.style.WARNING("--dry-run set, nothing written."))
