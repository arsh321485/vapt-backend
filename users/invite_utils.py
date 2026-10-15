"""
Report-claim magic links — lets a superadmin hand off already-uploaded
report(s) to a client who doesn't have a VaptFix account yet.

We don't know the client's email in advance (that's the whole point — they
pick it themselves at signup via Slack / MS Teams / Email), so the link
itself is the sole authorization: whoever completes signup with a valid,
unexpired token gets the report(s) reassigned to their new account.

Storage: Django's shared cache (same MongoDB-backed cache already used for
the Slack pending-upload flow) — a plain token -> dict mapping with a hard
7-hour TTL. No new DB table needed; expiry is handled by the cache
backend itself.
"""
import logging
import secrets

from django.core.cache import cache

logger = logging.getLogger(__name__)

INVITE_TTL_SECONDS = 7 * 60 * 60  # 7 hours
_CACHE_PREFIX = "report_claim_invite_"


def _cache_key(token: str) -> str:
    return f"{_CACHE_PREFIX}{token}"


def create_invite(report_ids: list, created_by_admin_id: str, mongo_report_ids: list = None) -> str:
    """Generate a fresh token and store {report_ids, mongo_report_ids,
    created_by} for 7 hours.

    `report_ids` are the UploadReport rows' own _ids — unchanged meaning,
    used for the pre-signup "You're claiming N report(s)" count
    (peek_invite) and for reassigning those rows' own `admin` FK on claim.

    `mongo_report_ids` are the ACTUAL nessus_reports.report_id value(s)
    the real data lives under — NOT always the same as an upload's own
    _id. Real bug report: claim_invite used to reassign nessus_reports by
    matching report_id == an upload's own _id directly, which is only
    true for the upload that ORIGINALLY created that document — never for
    one later merged into an admin's existing report (same admin
    re-uploading multiple files; see merge_service.py /
    UploadReportAdmin._cards_progress for the full merged-upload story).
    A claimed invite for a merged upload silently reassigned the
    UploadReport row but never the real report/cards, leaving the new
    admin's dashboard genuinely empty with no error anywhere. Defaults to
    `report_ids` when omitted, matching the old (broken-for-merged, but
    unchanged) behavior for any caller not yet updated to resolve and
    pass the real one."""
    token = secrets.token_urlsafe(24)
    cache.set(
        _cache_key(token),
        {
            "report_ids": list(report_ids),
            "mongo_report_ids": list(mongo_report_ids) if mongo_report_ids is not None else list(report_ids),
            "created_by": str(created_by_admin_id),
        },
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
    # mongo_report_ids is the real nessus_reports.report_id list — falls
    # back to report_ids for an invite created before this field existed
    # (standalone, non-merged uploads where the two were always equal
    # anyway, so the fallback is exact, not just approximate).
    mongo_report_ids = data.get("mongo_report_ids") or report_ids
    if not report_ids:
        return 0

    from vaptfix.mongo_client import get_shared_db
    from upload_report.models import UploadReport

    db = get_shared_db()
    result = db["nessus_reports"].update_many(
        {"report_id": {"$in": mongo_report_ids}},
        {"$set": {"admin_id": str(new_admin.id), "admin_email": new_admin.email}},
    )

    # Real bug report: this reassigned nessus_reports (and UploadReport,
    # below) but never vulnerability_cards — every claimed invite left
    # the claimed report's own cards still stamped with the ORIGINAL
    # admin's admin_id/admin_email, out of sync with the report doc they
    # belong to (confirmed live: a freshly claimed report showed the new
    # admin as owner, but its 46 cards still showed the old admin).
    # Harmless for anything that only ever queries vulnerability_cards by
    # report_id (most of the app), but a real landmine for the handful of
    # places that filter by admin_id/admin_email directly. Keep both
    # collections in sync on every claim, not just nessus_reports.
    db["vulnerability_cards"].update_many(
        {"report_id": {"$in": mongo_report_ids}},
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
                pass  # nosec B110 - best-effort, intentionally non-fatal
        if object_ids:
            rows_updated = UploadReport.objects.filter(_id__in=object_ids).update(admin=new_admin)
            logger.info("[ReportInvite] UploadReport rows reassigned: %d", rows_updated)
    except Exception as e:
        # Mongo side already reassigned above — this is best-effort so a
        # djongo hiccup here doesn't undo the part that already succeeded.
        logger.warning("[ReportInvite] UploadReport reassignment failed for %s: %s", report_ids, e)

    # Note: only new_admin's id/email and the reassigned report count/ids
    # are logged here — never the invite token value itself.
    logger.info(
        "[ReportInvite] Claimed invite for new_admin=%s (%s) — reassigned %d report(s): %s",
        new_admin.id, new_admin.email, result.modified_count, report_ids,
    )

    # Real request: the link's whole design is "whoever signs up with a
    # valid token gets it" — the recipient picks their own email at
    # signup, so there's no "expected" email to validate the claim
    # against (see this module's own docstring). That means a wrong-
    # account claim (e.g. testing from an already-logged-in session that
    # wasn't the intended one) is only ever visible by actually checking —
    # confirmed real: a set of reports meant for one test admin ended up
    # claimed by a different, similarly-named one, and nobody noticed
    # until that admin's own dashboard was checked much later. Notify
    # whoever GENERATED the link the moment it's actually used, so a
    # wrong claim is visible within the same session it happened in,
    # while it's still easy to sort out — not a prevention (the design
    # can't support one), but it closes the "nobody finds out" gap.
    created_by_admin_id = data.get("created_by")
    if result.modified_count > 0 and created_by_admin_id:
        try:
            from notifications.utils import create_notification
            create_notification(
                created_by_admin_id,
                "admin",
                "claim_link_used",
                "Claim link used",
                f"Your claim link for {result.modified_count} report(s) was just claimed by {new_admin.email}.",
                metadata={
                    "claimed_by_admin_id": str(new_admin.id),
                    "claimed_by_email": new_admin.email,
                    "report_ids": report_ids,
                },
            )
        except Exception as e:
            logger.warning("[ReportInvite] Could not notify link creator %s: %s", created_by_admin_id, e)

    # Real request: an admin who received their report via a magic-link
    # invite gets NO Freemium restrictions at all (automation scripts,
    # asset/vuln ceilings, everything) — see billing.enforcement.
    # _is_unlimited_admin, which checks this flag. Set unconditionally on
    # any successful claim (result.modified_count > 0 confirmed by the
    # caller already logging "claimed N report(s)" only when N > 0 above,
    # but this runs either way — harmless if 0 reports were actually
    # matched, since nothing else changes for this admin in that case).
    if result.modified_count > 0 and not new_admin.magic_link_unlimited:
        try:
            new_admin.magic_link_unlimited = True
            new_admin.save(update_fields=["magic_link_unlimited"])
        except Exception as e:
            logger.warning("[ReportInvite] Could not set magic_link_unlimited for %s: %s", new_admin.email, e)

    return result.modified_count
