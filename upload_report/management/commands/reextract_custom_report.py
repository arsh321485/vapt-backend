"""
Re-runs GPT-4o-mini validate+extract (custom_report_ai.py) against the
ORIGINAL uploaded file of an already-stored "custom" report, and updates
its nessus_reports document in place.

Exists to fix reports that were saved before the "one finding, many
affected hosts" extraction bug was fixed — a pentest report organized by
FINDING (one write-up per vulnerability listing several affected hosts
under an "Affected Host(s)/IP(s)/URL(s)" heading) used to collapse into
one host per finding instead of one host per finding PER affected host,
so the saved report ended up with far fewer hosts than the document
actually describes. Re-running extraction with the fixed prompt against
the same original file corrects this without needing a re-upload.

Only report_type == "custom" is supported — native Nessus/AWS exports
were never affected (their parsers already produce one entry per host).

Usage:
    python manage.py reextract_custom_report --report-id <report_id>
    python manage.py reextract_custom_report --all-custom   # every custom report on file

Safe to run on a report more than once — it always re-derives
vulnerabilities_by_host from the original file's current text, so it just
overwrites with the same (or newly corrected) result rather than
duplicating anything. New (host, finding) pairs get fresh vulnerability
cards generated in the background; pairs that already had a card are
skipped (see _auto_generate_cards_bg's existing "already_exists" check) —
existing cards are never touched or regenerated.
"""
import os
import threading

from bson import ObjectId
from django.conf import settings
from django.core.management.base import BaseCommand

from upload_report.models import UploadReport


class Command(BaseCommand):
    help = "Re-run custom-report GPT extraction against a report's original file and update it in place"

    def add_arguments(self, parser):
        parser.add_argument("--report-id", help="Single report_id to re-extract.")
        parser.add_argument(
            "--all-custom", action="store_true",
            help="Re-extract every report_type='custom' report found in nessus_reports.",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="Parse and print the new host/vulnerability count without writing anything.",
        )

    def handle(self, *args, **options):
        from vaptfix.mongo_client import get_shared_client, get_shared_db
        from upload_report.parsers import dispatch_parse
        from upload_report.custom_report_ai import validate_and_extract_custom_report
        from upload_report.views import _auto_generate_cards_bg, NESSUS_COLLECTION
        from upload_report.admin import UploadReportAdmin
        from django.contrib import admin as django_admin

        report_id = options.get("report_id")
        all_custom = options.get("all_custom")
        dry_run = options.get("dry_run")

        if not report_id and not all_custom:
            self.stderr.write(self.style.ERROR("Pass --report-id <id> or --all-custom"))
            return

        client = get_shared_client()
        db = get_shared_db(client)

        if report_id:
            report_ids = [report_id]
        else:
            report_ids = [
                d["report_id"] for d in
                db[NESSUS_COLLECTION].find({"report_type": "custom"}, {"report_id": 1})
            ]

        if not report_ids:
            self.stdout.write("No custom reports found.")
            return

        # _prepare_hosts_for_storage groups vulnerabilities by plugin_name into
        # the plugin_outputs-array shape nessus_reports expects — reuse the
        # exact same logic the admin-panel upload path already uses instead of
        # re-implementing it here.
        prepare_hosts = UploadReportAdmin(UploadReport, django_admin.site)._prepare_hosts_for_storage

        for rid in report_ids:
            self.stdout.write(f"--- report_id={rid} ---")
            doc = db[NESSUS_COLLECTION].find_one({"report_id": rid})
            if not doc:
                self.stderr.write(self.style.ERROR(f"  no nessus_reports doc for report_id={rid}"))
                continue

            try:
                upload_report = UploadReport.objects.get(_id=ObjectId(rid))
            except Exception as exc:
                self.stderr.write(self.style.ERROR(f"  UploadReport not found: {exc}"))
                continue

            file_path = os.path.join(settings.MEDIA_ROOT, upload_report.file.name)
            if not os.path.exists(file_path):
                self.stderr.write(self.style.ERROR(
                    f"  file not found on this machine: {file_path} "
                    f"(uploaded via a different server? run this command there instead)"
                ))
                continue

            filename = os.path.basename(upload_report.file.name)
            parsed_data = dispatch_parse(file_path, filename)
            if "error" in parsed_data:
                self.stderr.write(self.style.ERROR(f"  parse failed: {parsed_data['error']}"))
                continue

            if parsed_data.get("type") not in ("pdf", "csv", "excel", "html", "docx", "doc"):
                self.stdout.write(self.style.WARNING(
                    f"  parsed type is '{parsed_data.get('type')}', not a custom-file type — skipping "
                    f"(native Nessus/AWS reports don't need re-extraction)"
                ))
                continue

            result = validate_and_extract_custom_report(parsed_data, filename)
            if not result.get("valid"):
                self.stderr.write(self.style.ERROR(f"  extraction rejected: {result.get('reason')}"))
                continue

            old_hosts = doc.get("total_hosts", 0)
            old_vulns = doc.get("total_vulnerabilities", 0)
            new_hosts = result.get("total_hosts", 0)
            new_vulns = result.get("total_vulnerabilities", 0)
            self.stdout.write(
                f"  hosts: {old_hosts} -> {new_hosts}   vulnerabilities: {old_vulns} -> {new_vulns}"
            )

            if dry_run:
                continue

            hosts_payload = prepare_hosts(result.get("vulnerabilities_by_host", []))
            db[NESSUS_COLLECTION].update_one(
                {"report_id": rid},
                {"$set": {
                    "total_hosts": new_hosts,
                    "total_vulnerabilities": new_vulns,
                    "vulnerabilities_by_host": hosts_payload,
                }},
            )
            self.stdout.write(self.style.SUCCESS(f"  updated nessus_reports for report_id={rid}"))

            # Real bug report: this only ever updated nessus_reports (Mongo)
            # — the Django UploadReport.parsed_count field (set once at
            # upload time, shown as "PARSED COUNT" on the Upload Reports
            # admin list) was never touched, so it stayed stuck at the
            # ORIGINAL, pre-re-extraction number forever. Confirmed real:
            # a report re-extracted from 16 to 24 vulnerabilities still
            # showed "16" in the admin list — the magic-link/client
            # dashboard (reads Mongo directly) correctly showed the new
            # number, but this one admin-facing field silently never
            # caught up, looking like the fix hadn't taken effect at all.
            UploadReport.objects.filter(_id=ObjectId(rid)).update(parsed_count=new_vulns)
            self.stdout.write(self.style.SUCCESS(f"  updated UploadReport.parsed_count -> {new_vulns}"))

            # Real bug report: running this command more than once on the
            # same report (e.g. after a fix landed, or because a previous
            # extraction attempt came back worse due to LLM recall
            # variance) left every earlier attempt's vulnerability_cards
            # sitting in Mongo forever — this command only ever ADDS new
            # cards, it never removed ones for a (host_name, plugin_name)
            # pair that the new extraction no longer produced. Confirmed
            # real: a report re-extracted 3 times ended up with 23 cards in
            # the database for a report that currently only has 10 real
            # findings, so the Script tab and Register kept showing
            # vulnerabilities that don't exist in the current data at all.
            # Safe to delete here — a card is just generated automation/
            # manual-fix content, cheap to regenerate if the same (host,
            # vulnerability) pair ever reappears in a later extraction.
            current_pairs = {
                (h.get("host_name") or "", v.get("plugin_name") or "")
                for h in result.get("vulnerabilities_by_host", [])
                for v in h.get("vulnerabilities", [])
            }
            all_cards = list(db["vulnerability_cards"].find(
                {"report_id": rid}, {"_id": 1, "host_name": 1, "vulnerability_name": 1}
            ))
            orphan_ids = [
                c["_id"] for c in all_cards
                if (c.get("host_name") or "", c.get("vulnerability_name") or "") not in current_pairs
            ]
            if orphan_ids:
                db["vulnerability_cards"].delete_many({"_id": {"$in": orphan_ids}})
                self.stdout.write(self.style.WARNING(
                    f"  removed {len(orphan_ids)} orphaned vulnerability_cards from earlier "
                    f"extraction attempt(s) — no longer present in the current extraction"
                ))

            admin_email = doc.get("admin_email", "")
            admin_id = doc.get("admin_id", "")
            t = threading.Thread(
                target=_auto_generate_cards_bg,
                args=(rid, admin_email, admin_id),
                daemon=True,
            )
            t.start()
            t.join()
            self.stdout.write(self.style.SUCCESS(f"  card generation pass complete for report_id={rid}"))

        self.stdout.write(self.style.SUCCESS("Done."))
