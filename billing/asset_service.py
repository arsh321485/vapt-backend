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
    """
    try:
        with MongoContext() as db:
            pipeline = [
                {"$match": {"admin_id": str(admin_id)}},
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


def _latest_report_uploaded_at(admin_id: str):
    """Most recent uploaded_at across this admin's reports, or None."""
    try:
        with MongoContext() as db:
            doc = db[NESSUS_COLLECTION].find_one(
                {"admin_id": str(admin_id)},
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
