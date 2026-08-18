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
