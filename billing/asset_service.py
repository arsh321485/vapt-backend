"""
Computes an admin's billable asset count = number of unique hosts/IPs across
every Nessus/custom report they've uploaded (`nessus_reports` collection,
written by upload_report/views.py). This is the number the pricing-page
example ("80 IPs on Annual -> ...") refers to.
"""
import logging
from vaptfix.mongo_client import MongoContext

logger = logging.getLogger(__name__)

NESSUS_COLLECTION = "nessus_reports"


def get_admin_asset_count(admin_id: str) -> int:
    """
    Unique host_name count across all of this admin's uploaded reports.
    Mirrors how vulnerability_cards already dedupes by host_name, so the
    number stays consistent with what the admin sees elsewhere in the app.

    Matches on admin_id OR admin_email — every other nessus_reports lookup
    in the app (_load_latest_report in userregister/userdashboard/userasset,
    admindashboard's _load_latest_report_for_admin, ...) already falls back
    to admin_email when admin_id doesn't match; this one didn't, which is
    exactly why a report uploaded via Slack/Teams (whose write path can tag
    admin_email correctly while admin_id ends up stale/mismatched for that
    specific admin record) never showed up here — confirmed via a real
    report that was clearly visible everywhere else in the app but priced
    as "$0.00 / 0 assets" on this exact query alone.
    """
    try:
        conditions = [{"admin_id": str(admin_id)}]
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            admin_user = User.objects.filter(id=admin_id).first()
            if admin_user and admin_user.email:
                conditions.append({"admin_email": admin_user.email})
        except Exception:
            logger.exception(f"[Billing] could not resolve admin_email for admin_id={admin_id} (falling back to admin_id-only match)")

        with MongoContext() as db:
            pipeline = [
                {"$match": {"$or": conditions}},
                {"$unwind": "$vulnerabilities_by_host"},
                {"$match": {"vulnerabilities_by_host.host_name": {"$nin": [None, ""]}}},
                {"$group": {"_id": "$vulnerabilities_by_host.host_name"}},
                {"$count": "unique_hosts"},
            ]
            result = list(db[NESSUS_COLLECTION].aggregate(pipeline))
            return result[0]["unique_hosts"] if result else 0
    except Exception as e:
        logger.error(f"[Billing] asset count aggregation failed for admin_id={admin_id}: {e}")
        return 0


def get_admin_scope_asset_count(admin_id: str) -> int:
    """
    Unique target count across all of this admin's submitted scopes — the
    Management+Testing mode equivalent of get_admin_asset_count(). This mode
    never uploads a report, so nessus_reports has nothing to count; the
    billable assets are whatever was submitted via scope/create/ instead.
    """
    try:
        from scope.models import ScopeEntry
        # djongo can't translate COUNT(*) over a SELECT DISTINCT subquery
        # (.distinct().count()) — dedupe in Python instead.
        values = ScopeEntry.objects.filter(scope__admin_id=admin_id).values_list("value", flat=True)
        return len({v.lower() for v in values if v})
    except Exception as e:
        logger.error(f"[Billing] scope asset count failed for admin_id={admin_id}: {e}")
        return 0


def get_admin_scope_asset_breakdown(admin_id: str) -> dict:
    """
    Same dedupe as get_admin_scope_asset_count, but split by internal vs
    everything else (external IPs, subnets, and URLs — anything
    ScopeEntry.is_internal doesn't mark True) — Freemium is restricted to
    internal IPs only ("premium plan ke liye sare ip valid rahenge, jo
    freemium se jata hai usko sirf internal hi ip valid rahegi"), so
    routing needs to know not just the total count but whether any
    non-internal target is present at all.
    """
    try:
        from scope.models import ScopeEntry
        # dedupe in Python — see get_admin_scope_asset_count's note on why
        # djongo can't do SELECT DISTINCT here.
        seen_internal, seen_external = set(), set()
        for value, is_internal in ScopeEntry.objects.filter(scope__admin_id=admin_id).values_list("value", "is_internal"):
            if not value:
                continue
            (seen_internal if is_internal else seen_external).add(value.lower())
        return {
            "total": len(seen_internal | seen_external),
            "internal_count": len(seen_internal),
            "external_count": len(seen_external),
            "has_external": bool(seen_external),
        }
    except Exception as e:
        logger.error(f"[Billing] scope asset breakdown failed for admin_id={admin_id}: {e}")
        return {"total": 0, "internal_count": 0, "external_count": 0, "has_external": False}


def _latest_report_uploaded_at(admin_id: str):
    """Most recent uploaded_at across this admin's reports, or None.
    Same admin_id-OR-admin_email match as get_admin_asset_count, for the
    same reason — must find the SAME report that one counted, or the
    report-vs-scope recency comparison above wrongly treats an admin who
    genuinely has a report as having none."""
    try:
        conditions = [{"admin_id": str(admin_id)}]
        try:
            from django.contrib.auth import get_user_model
            User = get_user_model()
            admin_user = User.objects.filter(id=admin_id).first()
            if admin_user and admin_user.email:
                conditions.append({"admin_email": admin_user.email})
        except Exception:
            logger.exception(f"[Billing] could not resolve admin_email for admin_id={admin_id}")

        with MongoContext() as db:
            doc = db[NESSUS_COLLECTION].find_one(
                {"$or": conditions},
                {"uploaded_at": 1},
                sort=[("uploaded_at", -1)],
            )
            return doc.get("uploaded_at") if doc else None
    except Exception as e:
        logger.error(f"[Billing] latest report timestamp lookup failed for admin_id={admin_id}: {e}")
        return None


def _latest_scope_created_at(admin_id: str):
    """created_at of this admin's most recently submitted scope, or None."""
    try:
        from scope.models import Scope
        scope = Scope.objects.filter(admin_id=admin_id).order_by("-created_at").first()
        return scope.created_at if scope else None
    except Exception as e:
        logger.error(f"[Billing] latest scope timestamp lookup failed for admin_id={admin_id}: {e}")
        return None


def resolve_management_testing_asset_count(admin_id: str):
    """
    Management+Testing asset count — picks whichever of (uploaded report,
    submitted scope) is MORE RECENT, so an admin who just gave a scope
    manually gets priced off that scope, not a stale report from before
    (confirmed via real complaint: submitting scope still silently priced
    off an old report — "why is it asking like I already have a report").
    An admin who already has a report and hasn't touched scope still gets
    priced off that report, same as before. Only falls back to whichever
    one exists when the other is completely absent.

    Returns (asset_count, source) — source is "report" or "scope", so
    callers can label where the number came from.
    """
    report_count = get_admin_asset_count(admin_id)
    scope_count = get_admin_scope_asset_count(admin_id)

    if report_count and scope_count:
        report_at = _latest_report_uploaded_at(admin_id)
        scope_at = _latest_scope_created_at(admin_id)
        try:
            # nessus_reports.uploaded_at comes back from raw pymongo as a
            # naive datetime; Scope.created_at is timezone-aware (USE_TZ).
            # Strip tzinfo from both before comparing so this never raises
            # instead of just falling back to the old report-wins default.
            r = report_at.replace(tzinfo=None) if report_at else None
            s = scope_at.replace(tzinfo=None) if scope_at else None
            if s and r and s >= r:
                return scope_count, "scope"
        except Exception as e:
            logger.warning(f"[Billing] report/scope timestamp comparison failed for admin_id={admin_id}: {e}")
        return report_count, "report"
    if report_count:
        return report_count, "report"
    if scope_count:
        return scope_count, "scope"
    return 0, "scope"


def get_admin_asset_breakdown(admin_id: str):
    """Debug/detail helper — list of {host_name, report_count} for an admin's assets."""
    try:
        with MongoContext() as db:
            pipeline = [
                {"$match": {"admin_id": str(admin_id)}},
                {"$unwind": "$vulnerabilities_by_host"},
                {"$match": {"vulnerabilities_by_host.host_name": {"$nin": [None, ""]}}},
                {"$group": {
                    "_id": "$vulnerabilities_by_host.host_name",
                    "report_count": {"$sum": 1},
                }},
                {"$sort": {"_id": 1}},
            ]
            rows = list(db[NESSUS_COLLECTION].aggregate(pipeline))
            return [{"host_name": r["_id"], "report_count": r["report_count"]} for r in rows]
    except Exception as e:
        logger.error(f"[Billing] asset breakdown failed for admin_id={admin_id}: {e}")
        return []
