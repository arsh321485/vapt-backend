"""
Auto deadline notification checker.
Called automatically when admin fetches notifications — runs once per day per admin.
Generates ONE summary notification per severity (not per vulnerability).
"""
import re
import logging
from django.utils.timezone import now, make_aware, is_naive

from .utils import create_notification

logger = logging.getLogger(__name__)

NESSUS_COLLECTION = "nessus_reports"
SEVERITIES = ['critical', 'high', 'medium', 'low']


def _parse_days(value):
    if not value:
        return 0
    value = str(value).strip().lower()
    if value.isdigit():
        return int(value)
    total = 0
    w = re.search(r'(\d+)\s*week', value)
    if w:
        total += int(w.group(1)) * 7
    d = re.search(r'(\d+)\s*day|day\s*(\d+)', value)
    if d:
        num = d.group(1) or d.group(2)
        total += int(num)
    return total


def _remaining(base_dt, configured_days, now_utc):
    elapsed_seconds = (now_utc - base_dt).total_seconds()
    elapsed_days    = int(max(0, elapsed_seconds // 86400))
    remaining       = configured_days - elapsed_days
    if remaining < 0:
        return abs(remaining), 'overdue'
    return remaining, 'active'


def check_deadlines_for_admin(admin_id_str):
    """
    Generate deadline/overdue notifications for one admin.
    Creates at most 1 notification per severity per day (dedup per severity).
    Uses the shared MongoContext (pooled connection).
    """
    try:
        from risk_criteria.models import RiskCriteria
        from vaptfix.mongo_client import MongoContext

        NOTIF_COLLECTION = "notifications_notification"

        now_utc = now()
        if is_naive(now_utc):
            now_utc = make_aware(now_utc)

        today_start = now_utc.replace(hour=0, minute=0, second=0, microsecond=0)
        today_start_naive = today_start.replace(tzinfo=None)

        # Get risk criteria
        rc = RiskCriteria.objects.filter(admin=admin_id_str).order_by('-created_at').first()
        if not rc:
            try:
                from users.models import User
                user = User.objects.get(id=admin_id_str)
                rc = RiskCriteria.objects.filter(admin=user).order_by('-created_at').first()
            except Exception:
                pass
        if not rc:
            return

        # Use created_at as base — more stable than updated_at (auto_now can be unreliable)
        base_dt = rc.created_at
        if not base_dt:
            return
        if is_naive(base_dt):
            base_dt = make_aware(base_dt)

        # Verify admin has at least one report
        with MongoContext() as db:
            report = db[NESSUS_COLLECTION].find_one(
                {"admin_id": admin_id_str},
                {"_id": 1},
                sort=[("uploaded_at", -1)]
            )
        if not report:
            return

        # Per-severity+type dedup: collect (severity, notif_type) pairs already sent today
        with MongoContext() as db:
            already_sent = set()
            for doc in db[NOTIF_COLLECTION].find(
                {
                    "admin_id": admin_id_str,
                    "recipient_type": "admin",
                    "notif_type": {"$in": ["deadline_today", "deadline_tomorrow", "overdue"]},
                    "created_at": {"$gte": today_start_naive},
                },
                {"metadata.severity": 1, "notif_type": 1}
            ):
                sev = doc.get("metadata", {}).get("severity")
                nt  = doc.get("notif_type")
                if sev and nt:
                    already_sent.add((sev, nt))

        # One notification per (severity, type) per day
        for severity in SEVERITIES:
            configured_days = _parse_days(getattr(rc, severity, ""))
            if not configured_days:
                continue

            remaining_days, rem_status = _remaining(base_dt, configured_days, now_utc)

            if rem_status == 'overdue':
                notif_type = 'overdue'
            elif remaining_days == 0:
                notif_type = 'deadline_today'
            elif remaining_days == 1:
                notif_type = 'deadline_tomorrow'
            else:
                continue

            if (severity, notif_type) in already_sent:
                continue

            sev_label = severity.capitalize()

            if notif_type == 'overdue':
                title   = f"[{sev_label}] Overdue: Remediation Deadline Exceeded"
                message = (
                    f"[{sev_label}] The {sev_label} severity remediation deadline of "
                    f"{configured_days} day(s) has been exceeded by {remaining_days} day(s). "
                    f"Immediate action is required for all {sev_label} vulnerabilities."
                )
            elif notif_type == 'deadline_today':
                title   = f"[{sev_label}] Deadline Due Today"
                message = (
                    f"[{sev_label}] The {sev_label} severity remediation deadline of "
                    f"{configured_days} day(s) is due today. "
                    f"All {sev_label} vulnerabilities must be remediated today."
                )
            else:
                title   = f"[{sev_label}] Deadline Approaching Tomorrow"
                message = (
                    f"[{sev_label}] The {sev_label} severity remediation deadline of "
                    f"{configured_days} day(s) is due tomorrow. "
                    f"Please review progress on all {sev_label} vulnerabilities."
                )

            metadata = {
                "severity":        severity,
                "configured_days": configured_days,
                "remaining_days":  remaining_days,
            }

            create_notification(admin_id_str, 'admin', notif_type, title, message, metadata)
            create_notification(admin_id_str, 'user',  notif_type, title, message, metadata, recipient_email='')

    except Exception as exc:
        logger.error("check_deadlines_for_admin failed for %s: %s", admin_id_str, exc)
