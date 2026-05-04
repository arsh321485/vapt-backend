"""
Management command to create deadline notifications for vulnerabilities.

Run once per day via cron:
    python manage.py send_deadline_notifications

Creates ONE summary notification per severity that hits:
  - deadline_today    : remaining == 0
  - deadline_tomorrow : remaining == 1
  - overdue           : past deadline
"""
import re
import pymongo
from django.core.management.base import BaseCommand
from django.utils.timezone import now, make_aware, is_naive
from django.conf import settings

from risk_criteria.models import RiskCriteria
from notifications.utils import create_notification

NESSUS_COLLECTION = "nessus_reports"
SEVERITIES = ['critical', 'high', 'medium', 'low']


def _get_batch_db():
    """Separate MongoClient with long timeouts — for management commands only."""
    uri = (
        settings.DATABASES.get("default", {}).get("CLIENT", {}).get("host")
        or getattr(settings, "MONGO_DB_URL", None)
        or getattr(settings, "MONGO_URI", None)
    )
    client = pymongo.MongoClient(
        uri,
        serverSelectionTimeoutMS=60000,
        connectTimeoutMS=30000,
        socketTimeoutMS=120000,
    )
    db_name = settings.DATABASES.get("default", {}).get("NAME", "vaptfix")
    return client, client[db_name]


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


class Command(BaseCommand):
    help = 'Create deadline/overdue notifications — one per severity per admin'

    def add_arguments(self, parser):
        parser.add_argument('--verbose', action='store_true', help='Print debug info')

    def handle(self, *args, **options):
        verbose = options.get('verbose', False)

        now_utc = now()
        if is_naive(now_utc):
            now_utc = make_aware(now_utc)

        total_created = 0

        rc_list = list(RiskCriteria.objects.all())
        if verbose:
            self.stdout.write(f"[DEBUG] RiskCriteria records found: {len(rc_list)}")

        mongo_client, db = _get_batch_db()
        try:
            for rc in rc_list:
                try:
                    admin_id_str = str(rc.admin_id)

                    base_dt = rc.updated_at or rc.created_at
                    if is_naive(base_dt):
                        base_dt = make_aware(base_dt)

                    if verbose:
                        self.stdout.write(
                            f"[DEBUG] admin_id={admin_id_str}  base_dt={base_dt}  "
                            f"critical={rc.critical}  high={rc.high}  medium={rc.medium}  low={rc.low}"
                        )

                    # Verify report exists for this admin
                    report = db[NESSUS_COLLECTION].find_one(
                        {"admin_id": admin_id_str},
                        {"_id": 1},
                        sort=[("uploaded_at", -1)]
                    )
                    if not report:
                        if verbose:
                            self.stdout.write(f"[DEBUG] No report for admin_id={admin_id_str}, skipping")
                        continue

                    for severity in SEVERITIES:
                        configured_days = _parse_days(getattr(rc, severity, ""))
                        if not configured_days:
                            if verbose:
                                self.stdout.write(f"[DEBUG] {severity}: no days configured, skip")
                            continue

                        remaining_days, rem_status = _remaining(base_dt, configured_days, now_utc)

                        if verbose:
                            self.stdout.write(
                                f"[DEBUG] {severity}: days={configured_days} remaining={remaining_days} status={rem_status}"
                            )

                        if rem_status == 'overdue':
                            notif_type = 'overdue'
                        elif remaining_days == 0:
                            notif_type = 'deadline_today'
                        elif remaining_days == 1:
                            notif_type = 'deadline_tomorrow'
                        else:
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
                        total_created += 1
                        create_notification(admin_id_str, 'user', notif_type, title, message, metadata, recipient_email='')
                        total_created += 1

                except Exception as exc:
                    self.stderr.write(f"Error (admin_id={getattr(rc, 'admin_id', '?')}): {exc}")

        finally:
            mongo_client.close()

        self.stdout.write(self.style.SUCCESS(f"Done. {total_created} notifications created."))
