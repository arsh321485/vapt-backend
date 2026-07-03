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
import re

import requests
from django.core.management.base import BaseCommand

from vaptfix.mongo_client import MongoContext


def _normalize_header(h: str) -> str:
    """
    Strip symbols (✓/✗/parens/etc.) and collapse whitespace so a sheet
    header matches COLUMN_MAP regardless of which Unicode checkmark variant,
    extra spaces, or punctuation Google Sheets' CSV export used — exact
    string matching was silently skipping columns like "✓ What can be
    automated" whenever the checkmark byte didn't match ours exactly.
    """
    cleaned = re.sub(r"[^a-zA-Z0-9 ]+", " ", h or "")
    return re.sub(r"\s+", " ", cleaned).strip().lower()

SHEET_CSV_URL = (
    "https://docs.google.com/spreadsheets/d/"
    "1ctRVrFS60_d_ZEdUZArNi5fCwFF-WcNl"
    "/export?format=csv&gid=1898467439"
)

def _normalize_os(raw: str) -> str:
    """
    Normalize any case/spelling variant of the sheet's OS column to the
    canonical value used everywhere else (load_scripts_to_db.py, the
    automation-scripts API's ?os= param) — so "windows", "WINDOWS", and
    "Windows" all resolve to the same (plugin_id, os) document instead of
    creating separate ones.
    """
    v = (raw or "").strip().lower()
    if not v:
        return ""
    if "win" in v:
        return "Windows"
    if "linux" in v or "ubuntu" in v or "unix" in v:
        return "Linux"
    if "cisco" in v or "ios" in v:
        return "Cisco"
    return (raw or "").strip()  # unrecognized — keep the original rather than dropping it


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
    "What can be automated": "what_can_be_automated",
    "What must remain manual": "what_must_remain_manual",
    "Recommended approach": "recommended_approach",
    "Command to download libraries": "command_download_libraries",
    "Command to run script": "command_run_script",
}

# Keyed by normalized header text so lookups are immune to checkmark
# variants, extra spaces, and punctuation differences in the sheet.
NORMALIZED_COLUMN_MAP = {_normalize_header(k): v for k, v in COLUMN_MAP.items()}
PLUGIN_ID_KEY = _normalize_header("Plugin ID")


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

        # Normalize headers (strip BOM, symbols, whitespace) so matching is
        # immune to Unicode checkmark variants / spacing differences.
        raw_headers = reader.fieldnames or []
        header_norm_to_raw = {_normalize_header(h.lstrip("﻿")): h for h in raw_headers}

        if PLUGIN_ID_KEY not in header_norm_to_raw:
            self.stderr.write(self.style.ERROR("'Plugin ID' column not found in sheet. Aborting."))
            return

        # Warn about any expected columns not found
        for col, col_norm in [("Plugin ID", PLUGIN_ID_KEY)] + [
            (k, _normalize_header(k)) for k in COLUMN_MAP
        ]:
            if col_norm not in header_norm_to_raw:
                self.stdout.write(self.style.WARNING(f"  WARNING: column '{col}' not in sheet — skipped"))

        total = 0
        skipped = 0

        with MongoContext() as db:
            collection = db["automation_scripts"]
            # plugin_id alone is no longer unique — a plugin can have separate
            # documents per OS (Windows/Linux/Cisco). Drop the old unique-on-
            # plugin_id-alone index if present so it doesn't reject a second
            # OS variant, and use a compound (plugin_id, os) unique index
            # instead — matches load_scripts_to_db.py's indexing.
            existing_index_names = set(collection.index_information().keys())
            if "idx_automation_plugin_id" in existing_index_names:
                collection.drop_index("idx_automation_plugin_id")
            collection.create_index([("plugin_id", 1)], name="idx_automation_plugin_id")
            collection.create_index(
                [("plugin_id", 1), ("os", 1)], unique=True, name="idx_automation_plugin_id_os"
            )

            for raw_row in reader:
                # Re-key each row by normalized header text (same normalization
                # used for the header check above) so column lookups below
                # work regardless of the exact symbol/whitespace in the sheet.
                row_norm = {
                    _normalize_header(k.lstrip("﻿")): (v.strip() if v else "")
                    for k, v in raw_row.items()
                }

                plugin_id_raw = row_norm.get(PLUGIN_ID_KEY, "")
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
                for col_norm, mongo_field in NORMALIZED_COLUMN_MAP.items():
                    val = row_norm.get(col_norm, "")
                    if val:
                        doc[mongo_field] = val

                if doc.get("os"):
                    doc["os"] = _normalize_os(doc["os"])

                doc["sheet_updated_at"] = datetime.date.today().isoformat()

                # Match on (plugin_id, os) when the sheet row has an OS value
                # — a plugin can have separate rows per OS. Falls back to
                # plugin_id alone for rows without an OS column value.
                match_filter = {"plugin_id": plugin_id}
                if doc.get("os"):
                    match_filter["os"] = doc["os"]
                collection.update_one(match_filter, {"$set": doc}, upsert=True)
                vuln = doc.get("vulnerability", "")
                self.stdout.write(self.style.SUCCESS(f"  OK  {plugin_id}: {vuln[:65]}"))
                total += 1

        self.stdout.write(self.style.SUCCESS(
            f"\nDone. {total} records upserted, {skipped} skipped."
        ))
