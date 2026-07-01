"""
Management command: sync automation scripts metadata from Google Sheet into MongoDB.

Manual run:
    python manage.py sync_automation_scripts

Schedule via Linux cron (e.g. every day at 2 AM):
    0 2 * * * cd /path/to/vaptfix && /path/to/venv/bin/python manage.py sync_automation_scripts >> /var/log/sync_scripts.log 2>&1
"""

import csv
import datetime
import io

import requests
from django.core.management.base import BaseCommand

from vaptfix.mongo_client import MongoContext

SHEET_CSV_URL = (
    "https://docs.google.com/spreadsheets/d/"
    "1ctRVrFS60_d_ZEdUZArNi5fCwFF-WcNl"
    "/export?format=csv&gid=1898467439"
)

COLUMN_MAP = {
    "Severity": "severity",
    "Vulnerability Name": "vulnerability",
    "Port": "port",
    "Description": "description",
    "OS": "os",
    "Automation Possible ( Yes / No / Partial )": "automation_possible",
    "Script Description": "script_description",
    "Considerations before execution": "considerations_before",
    "Considerations after execution": "considerations_after",
    "Script Name": "script_name",
    "Libraries": "libraries",
    "Tested Manually": "tested_manually",
    "✓ What can be automated": "what_can_be_automated",
    "✗ What must remain manual": "what_must_remain_manual",
    "Recommended approach": "recommended_approach",
    "Command to download libraries": "command_download_libraries",
    "Command to run script": "command_run_script",
}


class Command(BaseCommand):
    help = "Sync automation scripts metadata from Google Sheet into MongoDB automation_scripts collection"

    def handle(self, *args, **options):
        self.stdout.write("Fetching Google Sheet...")
        try:
            resp = requests.get(SHEET_CSV_URL, timeout=30)
            resp.raise_for_status()
        except Exception as e:
            self.stderr.write(self.style.ERROR(f"Failed to fetch sheet: {e}"))
            return

        reader = csv.DictReader(io.StringIO(resp.text))

        # Normalize headers (strip whitespace + BOM)
        raw_headers = reader.fieldnames or []
        normalized = {h.strip().lstrip("﻿"): h for h in raw_headers}

        if "Plugin ID" not in normalized:
            self.stderr.write(self.style.ERROR("'Plugin ID' column not found in sheet. Aborting."))
            return

        # Warn about any expected columns not found
        for col in list(COLUMN_MAP.keys()) + ["Plugin ID"]:
            if col not in normalized:
                self.stdout.write(self.style.WARNING(f"  WARNING: column '{col}' not in sheet — skipped"))

        total = 0
        skipped = 0

        with MongoContext() as db:
            collection = db["automation_scripts"]
            collection.create_index(
                [("plugin_id", 1)], unique=True, name="idx_automation_plugin_id"
            )

            for raw_row in reader:
                row = {
                    k.strip().lstrip("﻿"): (v.strip() if v else "")
                    for k, v in raw_row.items()
                }

                plugin_id_raw = row.get("Plugin ID", "")
                if not plugin_id_raw:
                    skipped += 1
                    continue

                try:
                    plugin_id = int(plugin_id_raw)
                except ValueError:
                    self.stdout.write(self.style.WARNING(f"  SKIP: non-numeric plugin_id '{plugin_id_raw}'"))
                    skipped += 1
                    continue

                doc = {"plugin_id": plugin_id}
                for sheet_col, mongo_field in COLUMN_MAP.items():
                    val = row.get(sheet_col, "")
                    if val:
                        doc[mongo_field] = val

                doc["sheet_updated_at"] = datetime.date.today().isoformat()

                collection.update_one({"plugin_id": plugin_id}, {"$set": doc}, upsert=True)
                vuln = doc.get("vulnerability", "")
                self.stdout.write(self.style.SUCCESS(f"  OK  {plugin_id}: {vuln[:65]}"))
                total += 1

        self.stdout.write(self.style.SUCCESS(
            f"\nDone. {total} records upserted, {skipped} skipped."
        ))
