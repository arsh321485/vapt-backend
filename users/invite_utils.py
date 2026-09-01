"""
Report-claim magic links — lets a superadmin hand off already-uploaded
report(s) to a client who doesn't have a VaptFix account yet.

We don't know the client's email in advance (that's the whole point — they
pick it themselves at signup via Slack / MS Teams / Email), so the link
itself is the sole authorization: whoever completes signup with a valid,
unexpired token gets the report(s) reassigned to their new account.

Storage: Django's shared cache (same FileBasedCache already used for the
Slack pending-upload flow) — a plain token -> dict mapping with a hard
15-minute TTL. No new DB table needed; expiry is handled by the cache
backend itself.
"""
import logging
import secrets

from django.core.cache import cache

logger = logging.getLogger(__name__)

INVITE_TTL_SECONDS = 900  # 15 minutes — explicit product decision, kept short on purpose
_CACHE_PREFIX = "report_claim_invite_"


def _cache_key(token: str) -> str:
    return f"{_CACHE_PREFIX}{token}"


def create_invite(report_ids: list, created_by_admin_id: str) -> str:
    """Generate a fresh token and store {report_ids, created_by} for 15 min."""
    token = secrets.token_urlsafe(24)
    cache.set(
        _cache_key(token),
        {"report_ids": list(report_ids), "created_by": str(created_by_admin_id)},
        timeout=INVITE_TTL_SECONDS,
    )
    return token


def peek_invite(token: str):
    """Read without consuming — used by the pre-signup validity check."""
    if not token:
        return None
    return cache.get(_cache_key(token))


def claim_invite(token: str, new_admin) -> int:
    """
    Consume the token (single-use — deleted immediately so it can't be
    replayed) and reassign its report(s) to new_admin. Returns how many
    report(s) were actually reassigned (0 if the token was missing/expired
    or already used).
    """
    if not token:
        return 0

    key = _cache_key(token)
    data = cache.get(key)
    if not data:
        return 0
    cache.delete(key)  # single-use, regardless of what happens below

    report_ids = data.get("report_ids") or []
    if not report_ids:
        return 0

    from vaptfix.mongo_client import get_shared_db
    from upload_report.models import UploadReport

    db = get_shared_db()
    result = db["nessus_reports"].update_many(
        {"report_id": {"$in": report_ids}},
        {"$set": {"admin_id": str(new_admin.id), "admin_email": new_admin.email}},
    )

    try:
        from bson import ObjectId
        from bson.errors import InvalidId
        # djongo's ObjectIdField.__in lookup doesn't coerce plain strings —
        # convert explicitly or the filter silently matches nothing.
        object_ids = []
        for rid in report_ids:
            try:
                object_ids.append(ObjectId(rid))
            except (InvalidId, TypeError):
                pass
        if object_ids:
            rows_updated = UploadReport.objects.filter(_id__in=object_ids).update(admin=new_admin)
            logger.info("[ReportInvite] UploadReport rows reassigned: %d", rows_updated)
    except Exception as e:
        # Mongo side already reassigned above — this is best-effort so a
        # djongo hiccup here doesn't undo the part that already succeeded.
        logger.warning("[ReportInvite] UploadReport reassignment failed for %s: %s", report_ids, e)

    logger.info(
        "[ReportInvite] Claimed token for new_admin=%s (%s) — reassigned %d report(s): %s",
        new_admin.id, new_admin.email, result.modified_count, report_ids,
    )
    return result.modified_count
