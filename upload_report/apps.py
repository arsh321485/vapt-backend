from django.apps import AppConfig


class UploadReportConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'upload_report'

    def ready(self):
        # Real bug report: a gunicorn worker restart (routine during a
        # deploy, or an OOM/crash) kills _auto_generate_cards_bg's thread
        # mid-run with nothing watching — its card_gen_locks row just sits
        # there, and the report stays permanently stuck short of its full
        # card count until a human happens to notice the website's "Cards
        # Status"/upload-progress page stuck incomplete and manually runs
        # `manage.py retry_incomplete_card_generation`. Confirmed happening
        # repeatedly (different admins, different weeks) purely because
        # nothing was actually scheduled to catch it automatically, even
        # though that command already existed and its own docstring
        # suggested scheduling it every ~15 min.
        #
        # Runs that exact same logic automatically now, in a background
        # daemon thread, on every process (management commands included —
        # same "safe to fire on every process" pattern as
        # admindashboard.apps.ready()'s index warmup; a one-off command's
        # own short-lived process just means this thread never gets to
        # fire a second time). A short initial delay lets the process
        # finish booting before the first pass; cheap no-op when nothing's
        # actually incomplete. Safe to run from multiple gunicorn workers
        # at once — card_gen_locks' distributed lock already serializes
        # real generation work across processes, so at most one worker's
        # retry attempt for a given report ever does anything.
        import threading

        def _auto_retry_loop():
            import time
            import logging
            logger = logging.getLogger(__name__)
            time.sleep(60)
            while True:
                try:
                    from upload_report.management.commands.retry_incomplete_card_generation import run_retry
                    count = run_retry(join=False, log=None)
                    if count:
                        logger.info(f"[AutoRetryCardGeneration] Resumed {count} incomplete report(s).")
                except Exception:
                    logger.exception("[AutoRetryCardGeneration] Scheduled retry pass failed")
                time.sleep(15 * 60)

        threading.Thread(target=_auto_retry_loop, daemon=True).start()
