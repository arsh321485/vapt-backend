"""
Correction to the previous script: adminvaptfix@gmail.com legitimately
claimed the TIPCO split-off report (6acdd74735b92a8d91a91011) via the
magic-link invite flow -- that was the CORRECT, intended result, not a
bug. The earlier version of this script wrongly reassigned the 46
vulnerability_cards back to feacbf06/malibharti.sitl@gmail.com, leaving
them inconsistent with the report document (which still correctly shows
adminvaptfix@gmail.com as the owner). This puts the cards back in sync
with the report -- both under the real claiming admin.

Run this yourself from the project root:
    python fix_admin_ownership.py
"""
import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from vaptfix.mongo_client import MongoContext

NEW_REPORT_ID = "6acdd74735b92a8d91a91011"

with MongoContext() as db:
    report_doc = db["nessus_reports"].find_one({"report_id": NEW_REPORT_ID}, {"admin_id": 1, "admin_email": 1})
    real_admin_id = report_doc.get("admin_id")
    real_admin_email = report_doc.get("admin_email")
    print("Report's real owner:", real_admin_id, real_admin_email)

    r = db["vulnerability_cards"].update_many(
        {"report_id": NEW_REPORT_ID},
        {"$set": {"admin_id": real_admin_id, "admin_email": real_admin_email}},
    )
    print("vulnerability_cards re-synced to the real owner:", r.modified_count)

print("\nDONE.")
