#!/usr/bin/env python3
"""
Ingestion script: scans vaptfix/automation_scripts/<plugin_id>/<OS>/ folder,
extracts plugin_id, OS, and vulnerability name from each script, and upserts
into MongoDB 'automation_scripts' collection — one document per
(plugin_id, os) pair, since a plugin can now have separate fix scripts for
different operating systems (e.g. Windows, Linux, Cisco).

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

# Folder name (as found on disk, case-insensitive) -> normalized "os" value
# stored in Mongo and used by the /autofix Slack command + automation-scripts
# API to pick the right script for a host.
OS_DIR_MAP = {
    "WIN": "Windows",
    "WINDOWS": "Windows",
    "UBUNTU": "Linux",
    "LINUX": "Linux",
    "CISCO": "Cisco",
}


def extract_vuln_name(filepath: Path) -> str:
    """
    Try a module docstring first (older Cisco scripts have one — vulnerability
    name is the 2nd line). Newer Windows/Linux scripts have no docstring and
    just print() a banner instead — fall back to the first non-separator,
    non-"Plugin N" print() line in that case.
    """
    try:
        source = filepath.read_text(encoding="utf-8")
        try:
            tree = ast.parse(source)
            docstring = ast.get_docstring(tree)
            if docstring:
                lines = [line.strip() for line in docstring.splitlines() if line.strip()]
                if len(lines) >= 2:
                    return lines[1]
        except SyntaxError:
            pass  # fall through to the print()-scan below

        for match in re.finditer(r'print\(\s*["\'](.+?)["\']\s*\)', source):
            text = match.group(1).strip()
            if not text or re.fullmatch(r"[=\-_#*]+", text):
                continue
            if text.lower().startswith("plugin "):
                continue
            return text
    except Exception as e:
        print(f"  WARNING: Could not parse {filepath.name}: {e}")
    return ""


def find_script(os_dir: Path, keyword: str):
    """Find the fix/verify script in an OS folder by keyword in the filename
    (case-insensitive) rather than assuming an exact naming pattern — the
    existing files aren't perfectly consistent (typos, casing differences)."""
    other = "verify" if keyword == "fix" else "fix"
    for f in sorted(os_dir.iterdir()):
        if not f.is_file() or f.suffix != ".py":
            continue
        name_lower = f.name.lower()
        if keyword in name_lower and other not in name_lower:
            return f
    return None


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
    print("Connecting to MongoDB...")
    client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    db = client[get_db_name(MONGO_URI)]
    collection = db["automation_scripts"]

    # plugin_id alone is no longer unique (a plugin can have Windows AND
    # Linux variants) — the real unique key is now (plugin_id, os).
    collection.create_index([("plugin_id", 1)], name="idx_automation_plugin_id")
    collection.create_index(
        [("plugin_id", 1), ("os", 1)], unique=True, name="idx_automation_plugin_id_os"
    )
    print(f"Scanning: {SCRIPTS_DIR}\n")

    total = 0
    skipped = 0
    seen_keys = set()

    for plugin_dir in sorted(SCRIPTS_DIR.iterdir()):
        if not plugin_dir.is_dir():
            continue

        try:
            plugin_id = int(plugin_dir.name)
        except ValueError:
            continue

        os_subdirs = [d for d in sorted(plugin_dir.iterdir()) if d.is_dir()]
        if not os_subdirs:
            print(f"  SKIP {plugin_id}: no OS subfolder found")
            skipped += 1
            continue

        for os_dir in os_subdirs:
            os_value = OS_DIR_MAP.get(os_dir.name.upper())
            if not os_value:
                print(f"  SKIP {plugin_id}/{os_dir.name}: unrecognized OS folder name")
                skipped += 1
                continue

            fix_file = find_script(os_dir, "fix")
            verify_file = find_script(os_dir, "verify")

            if not fix_file:
                print(f"  SKIP {plugin_id}/{os_value}: fix script not found")
                skipped += 1
                continue

            vuln_name = extract_vuln_name(fix_file)
            if not vuln_name:
                print(f"  WARN {plugin_id}/{os_value}: could not extract vulnerability name — storing without it")

            rel_dir = f"automation_scripts/{plugin_dir.name}/{os_dir.name}"
            doc = {
                "plugin_id": plugin_id,
                "os": os_value,
                "fix_script_name": fix_file.name,
                "fix_script_path": f"{rel_dir}/{fix_file.name}",
                "verify_script_name": verify_file.name if verify_file else None,
                "verify_script_path": f"{rel_dir}/{verify_file.name}" if verify_file else None,
                "language": "python",
                "updated_at": datetime.date.today().isoformat(),
            }
            if vuln_name:
                doc["vulnerability"] = vuln_name

            collection.update_one(
                {"plugin_id": plugin_id, "os": os_value},
                {"$set": doc, "$setOnInsert": {"created_at": datetime.date.today().isoformat()}},
                upsert=True,
            )
            seen_keys.add((plugin_id, os_value))
            print(f"  OK  {plugin_id}/{os_value}: {vuln_name[:60] if vuln_name else '(no name extracted)'}")
            total += 1

    # Replace semantics: remove any (plugin_id, os) documents that no longer
    # have a matching folder on disk (old data from a previous sync).
    stale_query = {"$nor": [{"plugin_id": pid, "os": osv} for pid, osv in seen_keys]} if seen_keys else {}
    if stale_query:
        stale_count = collection.count_documents(stale_query)
        if stale_count:
            collection.delete_many(stale_query)
            print(f"\nRemoved {stale_count} stale document(s) with no matching folder on disk.")

    print(f"\nDone. {total} scripts upserted, {skipped} skipped.")
    client.close()


if __name__ == "__main__":
    main()
