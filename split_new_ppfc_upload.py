"""
One-off: splits a new PPFC duplicate re-upload (6acf6669e182395939e1d7db)
out of the big shared report into its own standalone report + cards,
copied from the ORIGINAL PPFC upload's already-generated cards (same
client, same findings -- confirmed 23/23 match). This makes the new
upload independently claimable via a magic link, without entangling the
5 other, unrelated uploads sharing the big shared report.

Run this yourself from the project root:
    python split_new_ppfc_upload.py
"""
import os
import uuid as _uuid
import datetime
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from vaptfix.mongo_client import MongoContext
from upload_report.models import UploadReport
from bson import ObjectId

ORIGINAL_PPFC_UPLOAD_ID = "6acdd671414a76b4f88d64f9"
SHARED_REPORT_ID = "6ac3968fbc2429778e208e21"
NEW_UPLOAD_ID = "6acf6669e182395939e1d7db"

new_upload = UploadReport.objects.get(_id=ObjectId(NEW_UPLOAD_ID))
admin_id = str(new_upload.admin_id)
admin_email = new_upload.admin_email

with MongoContext() as db:
    existing = db["nessus_reports"].find_one({"report_id": NEW_UPLOAD_ID})
    if existing:
        print("A standalone report already exists for this id -- aborting, nothing changed.")
        raise SystemExit(1)

    source_cards = list(db["vulnerability_cards"].find({"source_upload_id": ORIGINAL_PPFC_UPLOAD_ID}))
    print("Source cards found:", len(source_cards))

    shared_doc = db["nessus_reports"].find_one(
        {"report_id": SHARED_REPORT_ID}, {"vulnerabilities_by_host": 1, "locked_hosts": 1}
    )
    all_hosts = list(shared_doc.get("vulnerabilities_by_host") or []) + list(shared_doc.get("locked_hosts") or [])
    by_host_name = {h.get("host_name"): h for h in all_hosts}

    new_hosts_by_name = {}
    matched = 0
    for card in source_cards:
        host_name = card.get("host_name")
        vuln_name = card.get("vulnerability_name")
        src_host = by_host_name.get(host_name)
        if not src_host:
            print(f"  SKIP (no host data): {host_name} / {vuln_name}")
            continue
        found_vuln = None
        for v in (src_host.get("vulnerabilities") or []):
            if (v.get("plugin_name") or "").strip() == vuln_name:
                found_vuln = v
                break
        if not found_vuln:
            print(f"  SKIP (no vuln data): {host_name} / {vuln_name}")
            continue
        matched += 1
        if host_name not in new_hosts_by_name:
            new_hosts_by_name[host_name] = {
                "host_name": host_name,
                "host_information": src_host.get("host_information", {}),
                "vulnerabilities": [],
            }
        new_hosts_by_name[host_name]["vulnerabilities"].append(dict(found_vuln))

    print(f"Matched {matched}/{len(source_cards)} cards to raw host/vuln data")
    new_vulnerabilities_by_host = list(new_hosts_by_name.values())
    total_vulnerabilities = sum(len(h["vulnerabilities"]) for h in new_vulnerabilities_by_host)
    now = datetime.datetime.utcnow()

    new_report_doc = {
        "report_id": NEW_UPLOAD_ID,
        "admin_id": admin_id,
        "admin_email": admin_email,
        "vulnerabilities_by_host": new_vulnerabilities_by_host,
        "locked_hosts": [],
        "total_hosts": len(new_vulnerabilities_by_host),
        "total_vulnerabilities": total_vulnerabilities,
        "cards_expected_count": len(source_cards),
        "cards_generated_count": len(source_cards),
        "cards_generation_complete": True,
        "cards_generation_started_at": now,
        "uploaded_at": now,
    }
    db["nessus_reports"].insert_one(new_report_doc)
    print("Inserted new standalone nessus_reports doc, report_id =", NEW_UPLOAD_ID)

    new_cards = []
    for card in source_cards:
        new_card = dict(card)
        new_card.pop("_id", None)
        new_card["card_id"] = str(_uuid.uuid4())
        new_card["report_id"] = NEW_UPLOAD_ID
        new_card["admin_id"] = admin_id
        new_card["admin_email"] = admin_email
        new_card["source_upload_id"] = NEW_UPLOAD_ID
        new_card["created_at"] = now
        new_cards.append(new_card)

    if new_cards:
        db["vulnerability_cards"].insert_many(new_cards)
    print(f"Inserted {len(new_cards)} new vulnerability_cards")

print("\nDONE.")
