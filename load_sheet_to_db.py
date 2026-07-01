#!/usr/bin/env python3
"""
Ingestion script: reads automation scripts metadata from the public Google Sheet
and upserts all 18 columns into MongoDB 'automation_scripts' collection.

Usage (run from vaptfix/ folder):
    python load_sheet_to_db.py

This complements load_scripts_to_db.py (which adds fix/verify script file paths).
Run both scripts to get the full picture in MongoDB.
"""

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

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGO_URI = os.getenv("MONGO_DB_URL") or os.getenv("MONGO_URI")
if not MONGO_URI:
    print("ERROR: MONGO_DB_URL not set in .env")
    sys.exit(1)

# Exact sheet column header → MongoDB field name
# Keys must match the sheet header exactly (after strip)
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
    csv_text = fetch_csv()
    reader = csv.DictReader(io.StringIO(csv_text))

    # Normalize headers: strip whitespace and BOM
    raw_headers = reader.fieldnames or []
    normalized = {h.strip().lstrip("﻿"): h for h in raw_headers}

    print(f"Sheet columns found: {list(normalized.keys())}\n")

    # Warn about any expected columns missing from the sheet
    plugin_id_col = normalized.get("Plugin ID")
    if not plugin_id_col:
        print("ERROR: 'Plugin ID' column not found in sheet. Aborting.")
        sys.exit(1)

    for expected in list(COLUMN_MAP.keys()) + ["Plugin ID"]:
        if expected not in normalized:
            print(f"  WARNING: column '{expected}' not found in sheet — will be skipped")

    print("Connecting to MongoDB...")
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = client[get_db_name(MONGO_URI)]
    collection = db["automation_scripts"]
    collection.create_index(
        [("plugin_id", 1)], unique=True, name="idx_automation_plugin_id"
    )

    total = 0
    skipped = 0

    for raw_row in reader:
        # Strip whitespace from all keys and values
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

        doc = {"plugin_id": plugin_id}
        for sheet_col, mongo_field in COLUMN_MAP.items():
            val = row.get(sheet_col, "")
            if val:
                doc[mongo_field] = val

        doc["sheet_updated_at"] = datetime.date.today().isoformat()

        collection.update_one({"plugin_id": plugin_id}, {"$set": doc}, upsert=True)
        vuln = doc.get("vulnerability", "")
        print(f"  OK  {plugin_id}: {vuln[:65]}")
        total += 1

    print(f"\nDone. {total} records upserted, {skipped} skipped.")
    client.close()


if __name__ == "__main__":
    main()
