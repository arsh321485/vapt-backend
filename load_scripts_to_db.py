#!/usr/bin/env python3
"""
Ingestion script: scans vaptfix/automation_scripts/ folder,
extracts plugin_id and vulnerability name from each script's docstring,
and upserts into MongoDB 'automation_scripts' collection.

Usage (run from vaptfix/ folder):
    python load_scripts_to_db.py
"""

import ast
import datetime
import os
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv
import pymongo

BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

MONGO_URI = os.getenv("MONGO_DB_URL") or os.getenv("MONGO_URI")
if not MONGO_URI:
    print("ERROR: MONGO_DB_URL not set in .env")
    sys.exit(1)

SCRIPTS_DIR = BASE_DIR / "automation_scripts"


def extract_vuln_name(filepath: Path) -> str:
    try:
        source = filepath.read_text(encoding="utf-8")
        tree = ast.parse(source)
        docstring = ast.get_docstring(tree)
        if docstring:
            lines = [line.strip() for line in docstring.splitlines() if line.strip()]
            if len(lines) >= 2:
                return lines[1]
    except Exception as e:
        print(f"  WARNING: Could not parse {filepath.name}: {e}")
    return ""


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


def main():
    print(f"Connecting to MongoDB...")
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = client[get_db_name(MONGO_URI)]
    collection = db["automation_scripts"]

    collection.create_index([("plugin_id", 1)], unique=True, name="idx_automation_plugin_id")
    print(f"Scanning: {SCRIPTS_DIR}\n")

    total = 0
    skipped = 0

    for plugin_dir in sorted(SCRIPTS_DIR.iterdir()):
        if not plugin_dir.is_dir():
            continue

        try:
            plugin_id = int(plugin_dir.name)
        except ValueError:
            continue

        fix_file = plugin_dir / f"{plugin_dir.name}_fix_NS.py"
        verify_file = plugin_dir / f"{plugin_dir.name}_verify_NS.py"

        if not fix_file.exists():
            print(f"  SKIP {plugin_id}: fix script not found")
            skipped += 1
            continue

        vuln_name = extract_vuln_name(fix_file)
        if not vuln_name:
            print(f"  SKIP {plugin_id}: could not extract vulnerability name")
            skipped += 1
            continue

        doc = {
            "plugin_id": plugin_id,
            "vulnerability": vuln_name,
            "fix_script_name": fix_file.name,
            "fix_script_path": f"automation_scripts/{plugin_dir.name}/{fix_file.name}",
            "verify_script_name": verify_file.name if verify_file.exists() else None,
            "verify_script_path": (
                f"automation_scripts/{plugin_dir.name}/{verify_file.name}"
                if verify_file.exists()
                else None
            ),
            "language": "python",
            "created_at": datetime.date.today().isoformat(),
        }

        collection.update_one({"plugin_id": plugin_id}, {"$set": doc}, upsert=True)
        print(f"  OK  {plugin_id}: {vuln_name[:65]}")
        total += 1

    print(f"\nDone. {total} scripts stored, {skipped} skipped.")
    client.close()


if __name__ == "__main__":
    main()
