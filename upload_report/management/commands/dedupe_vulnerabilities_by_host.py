"""
One-off cleanup for the real bug fixed in
upload_report/views.py's unlock_freemium_hosts_for_admin (Freemium->Premium
upgrade unlock merge) — it concatenated locked_hosts' vulnerabilities onto
vulnerabilities_by_host's existing list WITHOUT deduping by plugin_name
(unlike merge_service.merge_hosts_into_report's same-day-reupload merge,
which always has). Any admin who upgraded before that fix now has literal
duplicate (host_name, plugin_name) rows sitting in their nessus_reports
doc's vulnerabilities_by_host — showing up as the same vulnerability
appearing twice on the same asset in Register/Fix/All Vulns everywhere.

This command finds every such report and collapses duplicate plugin_name
entries within each host back down to one (first one wins — matches
merge_hosts_into_report's own "already have it, skip" semantics), then
recomputes total_hosts/total_vulnerabilities.

Does NOT touch vulnerability_cards — those are already deduplicated by
their own (report_id, vulnerability_name, host_name) upsert key, so a
duplicate raw finding just means TWO generation attempts silently
collapsed into the one already-existing card; nothing to clean up there.

Usage:
    python manage.py dedupe_vulnerabilities_by_host --dry-run
    python manage.py dedupe_vulnerabilities_by_host
    python manage.py dedupe_vulnerabilities_by_host --report-id <id>
"""
from django.core.management.base import BaseCommand
from vaptfix.mongo_client import get_shared_client, get_shared_db

NESSUS_COLLECTION = "nessus_reports"


class Command(BaseCommand):
    help = "Collapse duplicate (host_name, plugin_name) rows in nessus_reports.vulnerabilities_by_host"

    def add_arguments(self, parser):
        parser.add_argument("--report-id", help="Only check/fix this one report_id.")
        parser.add_argument("--dry-run", action="store_true", help="Report what would change without writing.")

    def handle(self, *args, **options):
        client = get_shared_client()
        db = get_shared_db(client)
        coll = db[NESSUS_COLLECTION]

        query = {"report_id": options["report_id"]} if options.get("report_id") else {}
        dry_run = options.get("dry_run")

        reports_checked = 0
        reports_fixed = 0
        total_dupes_removed = 0

        for report in coll.find(query, {"report_id": 1, "vulnerabilities_by_host": 1, "admin_id": 1}):
            reports_checked += 1
            report_id = report.get("report_id")
            hosts = report.get("vulnerabilities_by_host") or []
            changed = False
            dupes_here = 0

            for host in hosts:
                vulns = host.get("vulnerabilities") or []
                seen = set()
                deduped = []
                for v in vulns:
                    key = v.get("plugin_name")
                    if key and key in seen:
                        dupes_here += 1
                        changed = True
                        continue
                    if key:
                        seen.add(key)
                    deduped.append(v)
                host["vulnerabilities"] = deduped

            if not changed:
                continue

            total_hosts = len(hosts)
            total_vulns = sum(len(h.get("vulnerabilities") or []) for h in hosts)
            self.stdout.write(
                f"report_id={report_id}: removed {dupes_here} duplicate row(s) "
                f"-> total_hosts={total_hosts} total_vulnerabilities={total_vulns}"
            )
            reports_fixed += 1
            total_dupes_removed += dupes_here

            if not dry_run:
                coll.update_one(
                    {"report_id": report_id},
                    {"$set": {
                        "vulnerabilities_by_host": hosts,
                        "total_hosts": total_hosts,
                        "total_vulnerabilities": total_vulns,
                    }},
                )
                admin_id = report.get("admin_id")
                if admin_id:
                    try:
                        from django.core.cache import cache as _cache
                        for _ck in (
                            f"admin_register_list_{admin_id}",
                            f"admin_asset_list_{admin_id}",
                            f"admin_vulnerabilities_{admin_id}",
                            f"admin_dashboard_summary_{admin_id}",
                            f"admin_total_assets_{admin_id}",
                            f"admin_avg_score_{admin_id}",
                            f"admin_inprocess_timeline_{admin_id}",
                            f"mitigation_by_team_v2_{admin_id}",
                        ):
                            _cache.delete(_ck)
                    except Exception as exc:
                        self.stdout.write(self.style.WARNING(f"cache invalidation failed for admin_id={admin_id}: {exc!r}"))

        if reports_fixed == 0:
            self.stdout.write(self.style.SUCCESS(f"Checked {reports_checked} report(s) — no duplicates found."))
            return

        verb = "Would remove" if dry_run else "Removed"
        self.stdout.write(self.style.SUCCESS(
            f"Checked {reports_checked} report(s). {verb} {total_dupes_removed} duplicate row(s) across {reports_fixed} report(s)."
        ))
        if dry_run:
            self.stdout.write(self.style.WARNING("--dry-run set, nothing written."))
