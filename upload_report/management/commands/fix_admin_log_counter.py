"""
Fix djongo auto-increment counter for django_admin_log.

Run once to resolve "duplicate key error: id: 2" on admin panel actions:
    python manage.py fix_admin_log_counter
"""
from django.core.management.base import BaseCommand
from vaptfix.mongo_client import get_shared_client, get_shared_db


class Command(BaseCommand):
    help = "Reset the djongo auto-increment counter for django_admin_log"

    def handle(self, *args, **options):
        client = get_shared_client()
        db = get_shared_db(client)
        coll = db["django_admin_log"]

        # Find max existing id (exclude the internal __auto__ counter doc)
        max_doc = coll.find_one(
            {"id": {"$exists": True, "$type": "number"}},
            sort=[("id", -1)],
        )
        max_id = int(max_doc["id"]) if max_doc else 0
        self.stdout.write(f"Current max id in django_admin_log: {max_id}")

        # Show current __auto__ counter
        auto_doc = coll.find_one({"_id": "__auto__"})
        self.stdout.write(f"Current __auto__ counter: {auto_doc}")

        # Reset counter to max_id so next insert gets max_id + 1
        result = coll.update_one(
            {"_id": "__auto__"},
            {"$set": {"seq": max_id}},
            upsert=True,
        )
        self.stdout.write(
            self.style.SUCCESS(f"Counter reset to {max_id}. Next insert will use id={max_id + 1}.")
        )
