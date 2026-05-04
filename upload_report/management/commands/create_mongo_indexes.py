"""
Management command to create MongoDB indexes for performance.

Run once after deployment:
    python manage.py create_mongo_indexes
"""
from django.core.management.base import BaseCommand
from vaptfix.mongo_client import get_shared_client, get_shared_db
import pymongo


INDEXES = {
    "nessus_reports": [
        [("report_id", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING)],
        [("admin_email", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING), ("uploaded_at", pymongo.DESCENDING)],
        [("admin_email", pymongo.ASCENDING), ("uploaded_at", pymongo.DESCENDING)],
    ],
    "fix_vulnerabilities": [
        [("report_id", pymongo.ASCENDING)],
        [("created_by", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("created_by", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("admin_id", pymongo.ASCENDING)],
        [("host_name", pymongo.ASCENDING)],
    ],
    "fix_vulnerabilities_closed": [
        [("report_id", pymongo.ASCENDING)],
        [("created_by", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("created_by", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("admin_id", pymongo.ASCENDING)],
    ],
    "vulnerability_cards": [
        [("report_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("host_name", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("vulnerability_name", pymongo.ASCENDING)],
    ],
    "support_requests": [
        [("admin_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING)],
        [("host_name", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING), ("report_id", pymongo.ASCENDING)],
    ],
    "fix_vulnerability_steps": [
        [("fix_vuln_id", pymongo.ASCENDING)],
        [("fix_vulnerability_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING)],
        [("fix_vulnerability_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING)],
    ],
    "timeline_extension_requests": [
        [("admin_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING), ("report_id", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING), ("report_id", pymongo.ASCENDING), ("status", pymongo.ASCENDING)],
    ],
    "notifications_notification": [
        [("admin_id", pymongo.ASCENDING), ("recipient_type", pymongo.ASCENDING), ("is_read", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING), ("recipient_type", pymongo.ASCENDING), ("created_at", pymongo.DESCENDING)],
    ],
    "hold_assets": [
        [("report_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING), ("host_name", pymongo.ASCENDING)],
    ],
    "deleted_assets": [
        [("report_id", pymongo.ASCENDING)],
        [("admin_id", pymongo.ASCENDING)],
    ],
    "tickets": [
        [("admin_id", pymongo.ASCENDING)],
        [("report_id", pymongo.ASCENDING)],
    ],
    "card_gen_locks": [
        [("report_id", pymongo.ASCENDING)],
    ],
    "users_details_userdetail": [
        [("admin_id", pymongo.ASCENDING)],
        [("email", pymongo.ASCENDING)],
    ],
    "users_user": [
        [("email", pymongo.ASCENDING)],
        [("is_active", pymongo.ASCENDING)],
    ],
    "signup_otp_sessions": [
        [("email", pymongo.ASCENDING)],
        [("created_at", pymongo.ASCENDING)],
    ],
}


class Command(BaseCommand):
    help = "Create MongoDB indexes for performance optimization"

    def handle(self, *args, **options):
        client = get_shared_client()
        db = get_shared_db(client)

        total_created = 0
        for collection_name, index_specs in INDEXES.items():
            coll = db[collection_name]
            for spec in index_specs:
                try:
                    index_name = coll.create_index(spec)
                    self.stdout.write(
                        self.style.SUCCESS(f"  [{collection_name}] index created: {index_name}")
                    )
                    total_created += 1
                except Exception as e:
                    self.stdout.write(
                        self.style.WARNING(f"  [{collection_name}] skipped ({e})")
                    )

        self.stdout.write(self.style.SUCCESS(f"\nDone. {total_created} indexes created/verified."))
