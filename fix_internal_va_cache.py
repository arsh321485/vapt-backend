"""
Same permanent cache repair as fix_external_va_cache.py, for "TIPCO
Internal VA Report October 2026 v1.1.pdf" — its cached extraction still
has the pre-fix contamination: "www.secureitlab.com" (filtered out on
every read as the assessor's own domain) is the only place carrying
10.151.5.43's full finding set (SSL Medium/TLS 1.0/TLS 1.1/SMB Signing/
Outdated PHP), and both 10.151.13.131 and 10.151.5.43 are missing from
the cache entry entirely.

Run this yourself from your own terminal:
    python fix_internal_va_cache.py
"""
import os
import copy

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from vaptfix.mongo_client import get_shared_client, get_shared_db
from upload_report.custom_report_ai import EXTRACTION_CACHE_COLLECTION

FILE_HASH = "7063c7943af4f02d33db7225d30bab0de99201a9242d7e6d3c845ee55c154566"


def main():
    db = get_shared_db(get_shared_client())
    coll = db[EXTRACTION_CACHE_COLLECTION]
    doc = coll.find_one({"file_hash": FILE_HASH})
    if not doc:
        print("Cache entry not found — nothing to fix.")
        return

    vbh = doc.get("vulnerabilities_by_host", [])
    www_host = next((h for h in vbh if h["host_name"] == "www.secureitlab.com"), None)
    host_58 = next((h for h in vbh if h["host_name"] == "10.151.5.58"), None)

    already_has_both = (
        any(h["host_name"] == "10.151.13.131" for h in vbh)
        and any(h["host_name"] == "10.151.5.43" for h in vbh)
    )
    if already_has_both:
        print("10.151.13.131 and 10.151.5.43 already present — nothing to fix.")
        return
    if not www_host or not host_58:
        print("Expected template hosts not found — unexpected shape, aborting.")
        return

    new_5_43 = {
        "host_name": "10.151.5.43",
        "host_information": {},
        "vulnerabilities": [copy.deepcopy(v) for v in www_host.get("vulnerabilities") or []],
    }
    new_13_131 = {
        "host_name": "10.151.13.131",
        "host_information": {},
        "vulnerabilities": [copy.deepcopy(v) for v in host_58.get("vulnerabilities") or []],
    }

    new_vbh = [h for h in vbh if h["host_name"] != "www.secureitlab.com"] + [new_5_43, new_13_131]
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
