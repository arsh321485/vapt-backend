"""
Finds reports where vulnerability-card generation never actually finished
(e.g. a transient GPT-4o/Mongo failure left cards_generated_count short of
cards_expected_count) and retries them. Safe to run repeatedly — card
generation skips vulnerabilities that already have a card (see
_auto_generate_cards_bg's "already_exists" check), so this only fills in
what's actually missing.

Run manually:
    python manage.py retry_incomplete_card_generation

Or schedule it (e.g. every 15 min) to catch failures automatically.
"""
import datetime
import threading

from django.core.management.base import BaseCommand
from vaptfix.mongo_client import get_shared_client, get_shared_db

# A lock older than this is assumed to belong to a process that crashed
# without releasing it (e.g. server restart mid-generation) — not a job
# that's still genuinely running.
STALE_LOCK_MINUTES = 15


class Command(BaseCommand):
    help = "Retry vulnerability-card generation for reports that finished incomplete"

    def add_arguments(self, parser):
        parser.add_argument(
            "--report-id",
            help="Retry a single report_id instead of scanning for all incomplete ones.",
        )

    def handle(self, *args, **options):
        from upload_report.views import _auto_generate_cards_bg, NESSUS_COLLECTION

        client = get_shared_client()
        db = get_shared_db(client)

        # Clear stale locks so a report stuck behind a crashed process's lock
        # can actually be retried, not silently skipped forever.
        cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=STALE_LOCK_MINUTES)
        stale = db["card_gen_locks"].delete_many({"locked_at": {"$lt": cutoff}})
        if stale.deleted_count:
            self.stdout.write(self.style.WARNING(f"Cleared {stale.deleted_count} stale card_gen_locks."))

        single_report_id = options.get("report_id")
        if single_report_id:
            candidates = list(db[NESSUS_COLLECTION].find(
                {"report_id": single_report_id},
                {"report_id": 1, "admin_id": 1, "admin_email": 1,
                 "cards_expected_count": 1, "cards_generated_count": 1},
            ))
        else:
            candidates = list(db[NESSUS_COLLECTION].find(
                {
                    "cards_expected_count": {"$gt": 0},
                    "$expr": {
                        "$lt": [
                            {"$ifNull": ["$cards_generated_count", 0]},
                            "$cards_expected_count",
                        ]
                    },
                },
                {"report_id": 1, "admin_id": 1, "admin_email": 1,
                 "cards_expected_count": 1, "cards_generated_count": 1},
            ))

        if not candidates:
            self.stdout.write(self.style.SUCCESS("Nothing incomplete — all reports fully generated."))
            return

        self.stdout.write(f"Retrying {len(candidates)} incomplete report(s)...")

        threads = []
        for doc in candidates:
            report_id = doc.get("report_id")
            admin_email = doc.get("admin_email", "")
            admin_id = doc.get("admin_id", "")
            expected = doc.get("cards_expected_count", 0)
            got = doc.get("cards_generated_count", 0)
            self.stdout.write(f"  - report_id={report_id} ({got}/{expected} cards) — retrying")

            t = threading.Thread(
                target=_auto_generate_cards_bg,
                args=(report_id, admin_email, admin_id),
                daemon=True,
            )
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        self.stdout.write(self.style.SUCCESS(f"Done — retried {len(candidates)} report(s)."))
