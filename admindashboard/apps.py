from django.apps import AppConfig


class AdmindashboardConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'admindashboard'

    def ready(self):
        # Real bug report: ensure_performance_indexes() (vaptfix/mongo_client.py)
        # is guarded to run its ~13 create_index calls only ONCE per process
        # (module-global _indexes_ensured flag) — but "once" meant "on the
        # first admin dashboard request a given gunicorn worker happens to
        # serve", not "at worker startup". Confirmed live: the very first
        # call to AdminInProcessRemediationTimelineAPIView on a fresh
        # process took ~4s (vs ~1.9s once warm) — that ~2s of index
        # round-trips (almost always no-ops, since the indexes already
        # exist) was being paid by whichever admin's request happened to
        # land on a cold worker first, instead of during startup where
        # nobody is waiting on it. Runs in a daemon thread so it never
        # delays worker startup itself, and is safe to fire on every
        # process (management commands included) — ensure_performance_
        # indexes() is idempotent and already fails soft.
        import threading

        def _warm_indexes():
            try:
                from vaptfix.mongo_client import MongoContext, ensure_performance_indexes
                with MongoContext() as db:
                    ensure_performance_indexes(db)
            except Exception:
                pass  # best-effort warmup only — the lazy per-request call remains the fallback

        threading.Thread(target=_warm_indexes, daemon=True).start()
