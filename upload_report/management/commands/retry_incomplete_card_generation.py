"""
Finds reports where vulnerability-card generation never actually finished
(e.g. a transient GPT-4o/Mongo failure, or a server restart that killed
_auto_generate_cards_bg's thread mid-run, left cards_generated_count short
of cards_expected_count) and retries them. Safe to run repeatedly — card
generation skips vulnerabilities that already have a card (see
_auto_generate_cards_bg's "already_exists" check), so this only fills in
what's actually missing.

Run manually:
    python manage.py retry_incomplete_card_generation

Also runs automatically every 15 minutes in a background thread — see
run_retry's own docstring and upload_report/apps.py's ready().
"""
import datetime
import threading

from django.core.management.base import BaseCommand
from vaptfix.mongo_client import get_shared_client, get_shared_db

# A lock older than this is assumed to belong to a process that crashed
# without releasing it (e.g. server restart mid-generation) — not a job
# that's still genuinely running. Kept in lockstep with
# upload_report.views.STALE_LOCK_SECONDS (same heartbeat, same
# reasoning for why 5 minutes safely distinguishes "dead" from "slow").
STALE_LOCK_MINUTES = 5


def run_retry(report_id=None, join=True, log=None):
    """
    Core logic shared by the management command and the automatic
    background scheduler (upload_report/apps.py's ready()) — clears stale
    card_gen_locks rows, then re-triggers _auto_generate_cards_bg for every
    report still short of its expected card count (or just `report_id`, if
    given).

    Real bug report: this used to be manual-only — a stalled report (e.g.
    a deploy's server restart killing the generation thread mid-run) just
    sat there forever with nothing watching for it, until someone noticed
    the website's "Cards Status"/upload-progress page stuck incomplete and
    ran this command by hand. Confirmed happening repeatedly (different
    admins, different weeks) purely because nothing was actually scheduled
    to catch it, even though this command already existed and its own
    docstring suggested scheduling it. See apps.py for the automatic side.

    `log`: callable(str) for progress lines — self.stdout.write from the
    command, or a no-op from the background scheduler (which runs silently
    unless something actually needed retrying, logged via the `logging`
    module instead — see apps.py).
    Returns the number of reports retried.
    """
    log = log or (lambda *_a, **_k: None)
    from upload_report.views import _auto_generate_cards_bg, NESSUS_COLLECTION

    client = get_shared_client()
    db = get_shared_db(client)

    # Clear stale locks so a report stuck behind a crashed process's lock
    # can actually be retried, not silently skipped forever.
    cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=STALE_LOCK_MINUTES)
    stale = db["card_gen_locks"].delete_many({"locked_at": {"$lt": cutoff}})
    if stale.deleted_count:
        log(f"Cleared {stale.deleted_count} stale card_gen_locks.")

    if report_id:
        candidates = list(db[NESSUS_COLLECTION].find(
            {"report_id": report_id},
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
        log("Nothing incomplete — all reports fully generated.")
        return 0

    log(f"Retrying {len(candidates)} incomplete report(s)...")

    threads = []
    for doc in candidates:
        rid = doc.get("report_id")
        admin_email = doc.get("admin_email", "")
        admin_id = doc.get("admin_id", "")
        expected = doc.get("cards_expected_count", 0)
        got = doc.get("cards_generated_count", 0)
        log(f"  - report_id={rid} ({got}/{expected} cards) — retrying")

        t = threading.Thread(
            target=_auto_generate_cards_bg,
            args=(rid, admin_email, admin_id),
            daemon=True,
        )
        t.start()
        threads.append(t)

    if join:
        for t in threads:
            t.join()

        # Real bug report: _auto_generate_cards_bg wraps its whole body in
        # one try/except/finally — an exception ANYWHERE after the main
        # generation loop finishes but before its own flag write
        # (_normalize_team_and_automation_consistency, right before it, is
        # the likeliest spot) gets caught, logged, and swallowed, so the
        # thread exits cleanly (join() returns normally) without
        # cards_generation_complete ever flipping to True — even though
        # every card that was supposed to get generated, genuinely did.
        # Confirmed live: two reports stuck at cards_generated_count ==
        # cards_expected_count (471/471 and 426/426) with the flag still
        # False, both retried through this exact command. The Django
        # Admin "Cards" column (get_cards_status/_cards_progress) and
        # generate_claim_link's readiness gate both read this flag
        # directly, so a report can be 100% done and still show
        # "⚠️ Incomplete" / fail the claim-link gate forever. Independently
        # re-verify and backfill the flag here, after every join, as a
        # safety net that doesn't depend on _auto_generate_cards_bg's own
        # internal path reaching its flag write.
        for doc in candidates:
            rid = doc.get("report_id")
            try:
                actual = db["vulnerability_cards"].count_documents({"report_id": rid})
                rdoc = db[NESSUS_COLLECTION].find_one({"report_id": rid}, {"cards_expected_count": 1, "cards_generation_complete": 1})
                expected = (rdoc or {}).get("cards_expected_count", 0)
                if expected > 0 and actual >= expected and not (rdoc or {}).get("cards_generation_complete"):
                    db[NESSUS_COLLECTION].update_one(
                        {"report_id": rid},
                        {"$set": {"cards_generation_complete": True, "cards_generated_count": actual}},
                    )
                    log(f"  - report_id={rid}: backfilled cards_generation_complete (was stuck False at {actual}/{expected})")
            except Exception as e:
                log(f"  - report_id={rid}: completion-flag backfill check failed: {e}")

    log(f"Done — retried {len(candidates)} report(s).")
    return len(candidates)


class Command(BaseCommand):
    help = "Retry vulnerability-card generation for reports that finished incomplete"

    def add_arguments(self, parser):
        parser.add_argument(
            "--report-id",
            help="Retry a single report_id instead of scanning for all incomplete ones.",
        )

    def handle(self, *args, **options):
        count = run_retry(report_id=options.get("report_id"), join=True, log=self.stdout.write)
        if count:
            self.stdout.write(self.style.SUCCESS(f"Done — retried {count} report(s)."))
        else:
            self.stdout.write(self.style.SUCCESS("Nothing incomplete — all reports fully generated."))
