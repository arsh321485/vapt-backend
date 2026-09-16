#!/usr/bin/env python3
"""
Scoped ingestion script: reads ONLY 7 core columns from the same automation
Google Sheet as load_sheet_to_db.py (Plugin ID, Severity, Vulnerability Name,
Port, Description, OS, Automation Possible) and upserts them into MongoDB
'automation_scripts' — WITHOUT touching the other 11 script-metadata columns
(Script Description, Libraries, Commands, etc.) that load_sheet_to_db.py also
manages. Existing plugin_id records only get these 6 fields updated; a
plugin_id not yet in the collection gets a new record created with just
these fields (other fields stay absent until a fuller sync fills them in).

Usage (run from vaptfix/ folder):
    python update_automation_core_fields.py --dry-run   # preview only, no writes
    python update_automation_core_fields.py              # actually apply
"""

import argparse
import csv
import datetime
import io
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests
from dotenv import load_dotenv
import pymongo

SHEET_CSV_URL = (
    "https://docs.google.com/spreadsheets/d/"
    "1ctRVrFS60_d_ZEdUZArNi5fCwFF-WcNl"
    "/export?format=csv&gid=1898467439"
)

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGO_URI = os.getenv("MONGO_DB_URL") or os.getenv("MONGO_URI")
if not MONGO_URI:
    print("ERROR: MONGO_DB_URL / MONGO_URI not set in .env")
    sys.exit(1)

# ONLY these 7 columns — everything else in the sheet is ignored entirely.
# Plugin ID is the match key (not written as a "data" field beyond itself).
CORE_COLUMN_MAP = {
    "Severity": "severity",
    "Vulnerability Name": "vulnerability",
    "Port": "port",
    "Description": "description",
    "OS": "os",
    "Automation Possible ( Yes / No / Partial )": "automation_possible",
}


def get_db_name(uri: str) -> str:
    try:
        path = (urlparse(uri).path or "").lstrip("/")
        if path:
            name = re.split(r"[/?]", path)[0]
            if name:
                return name
    except Exception:
        pass
    return "vaptfix"


def fetch_csv() -> str:
    print(f"Fetching sheet: {SHEET_CSV_URL}")
    resp = requests.get(SHEET_CSV_URL, timeout=30)
    resp.raise_for_status()
    return resp.text


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", help="Preview changes only, write nothing.")
    args = parser.parse_args()

    csv_text = fetch_csv()
    reader = csv.DictReader(io.StringIO(csv_text))

    raw_headers = reader.fieldnames or []
    normalized = {h.strip().lstrip("﻿"): h for h in raw_headers}
    print(f"Sheet columns found: {list(normalized.keys())}\n")

    if "Plugin ID" not in normalized:
        print("ERROR: 'Plugin ID' column not found in sheet. Aborting.")
        sys.exit(1)

    for expected in list(CORE_COLUMN_MAP.keys()) + ["Plugin ID"]:
        if expected not in normalized:
            print(f"  WARNING: column '{expected}' not found in sheet — will be skipped for all rows")

    print("Connecting to MongoDB...")
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = client[get_db_name(MONGO_URI)]
    collection = db["automation_scripts"]

    new_count = 0
    updated_count = 0
    unchanged_count = 0
    skipped = 0

    for raw_row in reader:
        row = {k.strip().lstrip("﻿"): (v.strip() if v else "") for k, v in raw_row.items()}

        plugin_id_raw = row.get("Plugin ID", "")
        if not plugin_id_raw:
            skipped += 1
            continue
        try:
            plugin_id = int(plugin_id_raw)
        except ValueError:
            print(f"  SKIP: non-numeric plugin_id '{plugin_id_raw}'")
            skipped += 1
            continue

        new_fields = {}
        for sheet_col, mongo_field in CORE_COLUMN_MAP.items():
            val = row.get(sheet_col, "")
            if val:
                if mongo_field == "severity":
                    val = val.upper()
                new_fields[mongo_field] = val

        if not new_fields:
            skipped += 1
            continue

        existing = collection.find_one({"plugin_id": plugin_id})

        if existing is None:
            new_count += 1
            print(f"  [NEW]     {plugin_id}: {new_fields.get('vulnerability', '')[:60]}")
            if not args.dry_run:
                doc = {"plugin_id": plugin_id, **new_fields, "sheet_updated_at": datetime.date.today().isoformat()}
                collection.insert_one(doc)
        else:
            changed = {k: v for k, v in new_fields.items() if existing.get(k) != v}
            if changed:
                updated_count += 1
                print(f"  [UPDATE]  {plugin_id}: {new_fields.get('vulnerability', '')[:60]}")
                for k, v in changed.items():
                    print(f"              {k}: {existing.get(k)!r} -> {v!r}")
                if not args.dry_run:
                    collection.update_one(
                        {"plugin_id": plugin_id},
                        {"$set": {**changed, "sheet_updated_at": datetime.date.today().isoformat()}},
                    )
            else:
                unchanged_count += 1

    mode = "DRY RUN — nothing written" if args.dry_run else "APPLIED"
    print(f"\nDone ({mode}). new={new_count} updated={updated_count} unchanged={unchanged_count} skipped={skipped}")
    client.close()


if __name__ == "__main__":
    main()
