"""
Plan-limit gate — call these from other apps' views to enforce what the
Freemium plan is allowed to do (per the pricing-page feature list).

Admins with NO Subscription row yet (pre-billing legacy accounts) are
treated as Freemium — nobody gets suddenly locked out, they just can't
exceed Freemium's limits until they pick a paid plan.
"""
from rest_framework.exceptions import APIException
from rest_framework import status

from .models import Subscription
from .plans import PLAN_FREEMIUM, FREEMIUM_LIMITS


class PlanLimitExceeded(APIException):
    status_code = status.HTTP_403_FORBIDDEN
    default_code = "plan_limit_exceeded"
    default_detail = "This action requires a Premium plan."


def get_active_plan(admin):
    """Returns the admin's current Subscription, or None if they've never
    picked a plan (treated as Freemium by every check below)."""
    return (
        Subscription.objects.filter(admin=admin, status__in=["trialing", "active", "past_due"])
        .order_by("-created_at")
        .first()
    )


def is_freemium(admin) -> bool:
    sub = get_active_plan(admin)
    return sub is None or sub.plan == PLAN_FREEMIUM


def _is_unlimited_admin(admin) -> bool:
    """
    Emails in BILLING_UNLIMITED_ADMIN_EMAILS (settings/.env) skip the
    asset-count, automation-scripts, and testing/retesting Freemium limits —
    NOT is_freemium() itself, so assert_can_upload_report's 1-upload-per-day
    limit still applies to them like any other Freemium admin. Intended for
    internal/demo accounts that need to exercise the product without an
    actual paid plan, while still exercising the same-day-upload flow.

    `admin` is a User instance at some call sites (upload_report/views.py)
    but a plain admin_id string at others (automation_scripts_api/views.py's
    _resolve_admin_and_teams, userregister/views.py's closed-doc admin_id) —
    getattr(admin, "email", "") silently returns "" for a bare string, which
    made this always False (and every download blocked for an otherwise-
    exempt admin) at those call sites. Resolve a string to the real User
    first so the exemption actually applies everywhere it's checked.
    """
    from django.conf import settings
    if isinstance(admin, str):
        from users.models import User
        admin = User.objects.filter(id=admin).first()
    email = (getattr(admin, "email", "") or "").strip().lower()
    return bool(email) and email in getattr(settings, "BILLING_UNLIMITED_ADMIN_EMAILS", [])


def assert_can_upload_report(admin):
    """
    Freemium allows exactly one report upload, ever — matches the pricing
    page's "Report upload – 1 time". Any file after the first (whether
    that's a later day or a second file in the very same request) requires
    Premium. Premium's own multi-file same-day merge behavior
    (upload_report/merge_service.py) is untouched — this gate only blocks
    Freemium accounts that already have an upload on record at all.
    """
    if not is_freemium(admin):
        return
    from upload_report.models import UploadReport

    if UploadReport.objects.filter(admin=admin).exists():
        raise PlanLimitExceeded(
            "Freemium plan allows only 1 report upload total. "
            "Upgrade to Premium to upload more reports."
        )


def assert_asset_within_limit(admin, asset_count: int):
    if _is_unlimited_admin(admin) or not is_freemium(admin):
        return
    limit = FREEMIUM_LIMITS["max_internal_ips"]
    if asset_count > limit:
        raise PlanLimitExceeded(
            f"Freemium plan allows up to {limit} internal IPs — this report has {asset_count}. "
            "Upgrade to Premium to cover more assets."
        )


def assert_team_member_within_limit(admin):
    """
    Freemium allows up to FREEMIUM_LIMITS['max_team_members'] team members
    total across all teams for this admin. Call before creating a new
    UserDetail row.
    """
    if _is_unlimited_admin(admin) or not is_freemium(admin):
        return
    from users_details.models import UserDetail

    limit = FREEMIUM_LIMITS["max_team_members"]
    existing = UserDetail.objects.filter(admin=admin).count()
    if existing >= limit:
        raise PlanLimitExceeded(
            f"Freemium plan allows up to {limit} team members — you already have {existing}. "
            "Upgrade to Premium to add more."
        )


_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "informational": 1}


def select_freemium_active_hosts(vulnerabilities_by_host, admin):
    """
    Freemium gets at most FREEMIUM_LIMITS['max_internal_ips'] hosts, and at
    most FREEMIUM_LIMITS['max_vulnerabilities'] total findings across them.

    Step 1 — the `max_internal_ips` hosts with the FEWEST vulnerabilities
    become the candidate "active" set (whole hosts — every other host, in
    full, becomes `locked`).

    Step 2 — if those active hosts' vulnerabilities combined still exceed
    `max_vulnerabilities`, the LOWEST-severity findings are trimmed off
    first (Critical/High stay visible, Info/Low go first) until the total
    is exactly at the cap. Trimmed findings are never discarded — they
    move into `locked` as an extra entry for their same host_name, so an
    upgrade can restore them exactly (see billing/views.py's
    StripeWebhookView, which merges `locked` back into
    vulnerabilities_by_host by host_name on a successful upgrade — no
    re-upload needed).

    Returns (active_hosts, locked_hosts). For a Premium/unlimited admin, or
    a report already within both caps, this is a no-op: `active` is
    everything and `locked` is empty.
    """
    if _is_unlimited_admin(admin) or not is_freemium(admin):
        return list(vulnerabilities_by_host or []), []

    max_hosts = FREEMIUM_LIMITS["max_internal_ips"]
    max_vulns = FREEMIUM_LIMITS["max_vulnerabilities"]

    hosts = list(vulnerabilities_by_host or [])
    total_vulns = sum(len(h.get("vulnerabilities") or []) for h in hosts)
    if len(hosts) <= max_hosts and total_vulns <= max_vulns:
        return hosts, []

    ordered = sorted(hosts, key=lambda h: len(h.get("vulnerabilities") or []))
    active_hosts = [dict(h) for h in ordered[:max_hosts]]
    locked_hosts = list(ordered[max_hosts:])

    active_vuln_count = sum(len(h.get("vulnerabilities") or []) for h in active_hosts)
    if active_vuln_count > max_vulns:
        # (severity_rank, host_index, vuln) — sort ascending so the least
        # severe findings sort first and are the ones cut.
        flat = []
        for idx, h in enumerate(active_hosts):
            for v in (h.get("vulnerabilities") or []):
                rank = _SEVERITY_RANK.get(str(v.get("risk_factor") or "").strip().lower(), 0)
                flat.append((rank, idx, v))
        flat.sort(key=lambda t: t[0])

        num_to_drop = active_vuln_count - max_vulns
        dropped = flat[:num_to_drop]
        kept_ids = {id(v) for (_rank, _idx, v) in flat[num_to_drop:]}

        overflow_by_host = {}
        for _rank, idx, v in dropped:
            overflow_by_host.setdefault(idx, []).append(v)

        new_active_hosts = []
        for idx, h in enumerate(active_hosts):
            kept_vulns = [v for v in (h.get("vulnerabilities") or []) if id(v) in kept_ids]
            new_host = dict(h)
            new_host["vulnerabilities"] = kept_vulns
            new_active_hosts.append(new_host)
            if idx in overflow_by_host:
                overflow_host = dict(h)
                overflow_host["vulnerabilities"] = overflow_by_host[idx]
                locked_hosts.append(overflow_host)
        active_hosts = new_active_hosts

    return active_hosts, locked_hosts


def assert_can_use_automation_scripts(admin):
    if _is_unlimited_admin(admin):
        return
    if is_freemium(admin) and not FREEMIUM_LIMITS["automation_scripts"]:
        raise PlanLimitExceeded(
            "Automation scripts are not available on the Freemium plan. Upgrade to Premium."
        )


def assert_can_request_testing(admin):
    """Gates retest requests on already-closed vulnerabilities. NOT used on
    scope submission itself (scope/views.py ScopeCreateAPIView) — a Freemium
    admin has to be able to submit scope to get a Management+Testing quote
    and start checkout in the first place; VaptFix acting on it is the part
    that actually requires an active Premium subscription."""
    if _is_unlimited_admin(admin):
        return
    if is_freemium(admin) and not FREEMIUM_LIMITS["testing_retesting"]:
        raise PlanLimitExceeded(
            "Testing/retesting is not available on the Freemium plan. Upgrade to Premium."
        )
