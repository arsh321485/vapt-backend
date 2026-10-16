"""
Permanent fix for a FUTURE re-upload of "TIPCO External VA Report
October 2026 v1.0.pdf" (file_hash below) — the cached extraction
(custom_extraction_cache, read on every re-upload of the exact same
file, see validate_and_extract_custom_report_cached) still has the
ORIGINAL, pre-fix contamination baked in:
  - "www.secureitlab.com" (the assessor's own domain — gets filtered
    out on every cache read by _is_assessor_own_domain) is the ONLY
    place "Web Application Vulnerable to Clickjacking" exists in this
    cache entry. Since that whole host gets dropped on read, its
    finding gets silently lost too, before the ground-truth cross-
    check even runs — so a future cache-hit re-upload would come back
    missing Clickjacking, the same gap just fixed by hand on the
    currently-live reports.
  - "122.55.241.122" is missing from the cache entirely (same missing-
    host bug fixed elsewhere today), even though it's confirmed in the
    source PDF with the same 4 findings as 112.199.95.18 plus
    Clickjacking.

Rewrites the cache entry directly so a future re-upload of this exact
file (which still bypasses a fresh GPT call) comes back already
correct, with no need to run the GPT recall-check again.

Run this yourself from your own terminal:
    python fix_external_va_cache.py
"""
import os
import copy

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from vaptfix.mongo_client import get_shared_client, get_shared_db
from upload_report.custom_report_ai import EXTRACTION_CACHE_COLLECTION

FILE_HASH = "d5bdededf40c2a281f1c5afb75f0cea50d8e0f7dcb5f79daac9fd12c9776616d"


def main():
    db = get_shared_db(get_shared_client())
    coll = db[EXTRACTION_CACHE_COLLECTION]
    doc = coll.find_one({"file_hash": FILE_HASH})
    if not doc:
        print("Cache entry not found — nothing to fix.")
        return

    vbh = doc.get("vulnerabilities_by_host", [])
    host_112 = next((h for h in vbh if h["host_name"] == "112.199.95.18"), None)
    www_host = next((h for h in vbh if h["host_name"] == "www.secureitlab.com"), None)
    already_has_122 = any(h["host_name"] == "122.55.241.122" for h in vbh)

    if already_has_122:
        print("122.55.241.122 already present in the cache entry — nothing to fix.")
        return
    if not host_112:
        print("112.199.95.18 not found in the cache entry — unexpected shape, aborting.")
        return

    clickjack_vuln = None
    if www_host:
        clickjack_vuln = next(
            (v for v in www_host.get("vulnerabilities") or [] if "Clickjacking" in (v.get("plugin_name") or "")),
            None,
        )

    new_122_vulns = [copy.deepcopy(v) for v in host_112.get("vulnerabilities") or []]
    if clickjack_vuln:
        new_122_vulns.append(copy.deepcopy(clickjack_vuln))

    new_122 = {"host_name": "122.55.241.122", "host_information": {}, "vulnerabilities": new_122_vulns}
    new_vbh = [h for h in vbh if h["host_name"] != "www.secureitlab.com"] + [new_122]
    new_total = sum(len(h.get("vulnerabilities") or []) for h in new_vbh)

    coll.update_one(
        {"file_hash": FILE_HASH},
        {"$set": {"vulnerabilities_by_host": new_vbh, "total_vulnerabilities": new_total, "total_hosts": len(new_vbh)}},
    )

    print("Updated cache entry. New host list:")
    for h in new_vbh:
        print(" ", h["host_name"], "->", [v.get("plugin_name") for v in h.get("vulnerabilities") or []])
    print("total_vulnerabilities:", new_total)


if __name__ == "__main__":
    main()
