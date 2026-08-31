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
    Emails in BILLING_UNLIMITED_ADMIN_EMAILS (settings/.env), OR any
    is_superuser account, skip the asset-count, automation-scripts, and
    testing/retesting Freemium limits — NOT is_freemium() itself, so
    assert_can_upload_report's 1-upload-per-day limit still applies to
    them like any other Freemium admin. Intended for internal/demo
    accounts that need to exercise the product without an actual paid
    plan, while still exercising the same-day-upload flow.

    The is_superuser exemption specifically covers Magic Pin Upload
    (upload_report/admin.py's MagicPinUploadAdmin) — explicit, repeated
    request: that upload path must show EVERYTHING with zero plan
    restriction. It attributes every report to request.user (the
    superadmin doing the upload, no "Select Admin" field at all), so
    without this, automation scripts on that data would still get locked
    whenever the superadmin's own account happened to have no paid
    subscription — the upload-time host/vuln trim being exempt
    (_MAGIC_LINK_NO_PLAN_LIMITS) wasn't enough on its own, since
    automation-script visibility is checked separately, per admin, at
    view time.

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
    if getattr(admin, "is_superuser", False):
        return True
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

    Step 1 — `max_internal_ips` hosts become the candidate "active" set
    (whole hosts — every other host, in full, becomes `locked`), preferring
    hosts that individually have at least `max_vulnerabilities //
    max_internal_ips` findings (their own "fair share") — lightest of
    those first — so the visible set can actually use close to the full
    vuln budget instead of being stuck with a handful of near-empty hosts.
    Only falls back to hosts below that threshold when there aren't enough
    qualifying ones to fill every slot.

    Step 2 — if those active hosts' vulnerabilities combined still exceed
    `max_vulnerabilities`, findings are trimmed down to the cap in two
    passes so every visible host still shows *something*, instead of a
    handful of hosts hogging the whole budget and others going to 0:

      2a. Fair share — each active host is guaranteed to keep its own
          highest-severity findings, up to `max_vulnerabilities //
          len(active_hosts)` (e.g. 10 // 5 = 2 per host at the default
          limits). A host with fewer than the fair share just keeps what
          it has. Real bug report: with the old single global sort, a host
          could easily end up with 0 visible findings while another kept
          most of the 10-vuln budget, even though both were shown as one
          of the 5 "active" assets.
      2b. Remaining budget — whatever's left of the cap after every host's
          fair share is filled goes to the highest-severity findings still
          left over (globally), regardless of which host they're on.

    Trimmed findings are never discarded — they move into `locked` as an
    extra entry for their same host_name, so an upgrade can restore them
    exactly (see billing/views.py's StripeWebhookView, which merges
    `locked` back into vulnerabilities_by_host by host_name on a
    successful upgrade — no re-upload needed).

    Returns (active_hosts, locked_hosts). For a Premium/unlimited admin, or
    a report already within both caps, this is a no-op: `active` is
    everything and `locked` is empty.
    """
    if _is_unlimited_admin(admin) or not is_freemium(admin):
        return list(vulnerabilities_by_host or []), []

    max_hosts = FREEMIUM_LIMITS["max_internal_ips"]
    max_vulns = FREEMIUM_LIMITS["max_vulnerabilities"]
    fair_share = max_vulns // max_hosts if max_hosts else 0

    hosts = list(vulnerabilities_by_host or [])
    total_vulns = sum(len(h.get("vulnerabilities") or []) for h in hosts)
    if len(hosts) <= max_hosts and total_vulns <= max_vulns:
        return hosts, []

    # Step 1 — prefer hosts that can each pull their own weight (at least
    # fair_share vulnerabilities), lightest-of-those-first. Real bug
    # report: the old version always took the max_hosts hosts with the
    # globally fewest vulnerabilities, full stop — a Freemium admin whose
    # 5 lightest hosts only had 1 vulnerability each ended up seeing 5
    # assets but only ~5 total vulnerabilities, nowhere near the intended
    # 5 x 2 = 10 allowance, even though the report had plenty of hosts
    # with 2+ vulnerabilities that got excluded in favor of even lighter
    # ones. Only falls back to hosts below fair_share when there genuinely
    # aren't enough qualifying hosts to fill all max_hosts slots.
    qualifying = sorted(
        (h for h in hosts if len(h.get("vulnerabilities") or []) >= fair_share),
        key=lambda h: len(h.get("vulnerabilities") or []),
    )
    selected = qualifying[:max_hosts]
    remaining_needed = max_hosts - len(selected)
    if remaining_needed > 0:
        selected_ids = {id(h) for h in selected}
        fallback = sorted(
            (h for h in hosts if id(h) not in selected_ids),
            key=lambda h: len(h.get("vulnerabilities") or []),
        )
        selected = selected + fallback[:remaining_needed]

    selected_ids = {id(h) for h in selected}
    active_hosts = [dict(h) for h in selected]
    locked_hosts = [h for h in hosts if id(h) not in selected_ids]

    active_vuln_count = sum(len(h.get("vulnerabilities") or []) for h in active_hosts)
    if active_vuln_count > max_vulns:
        fair_share = max_vulns // len(active_hosts) if active_hosts else 0

        # Per host, highest severity first — the front of each list is what
        # that host is guaranteed to keep; the rest is its own overflow
        # pool, still ranked highest-first for step 2b to draw from.
        per_host_sorted = []
        for h in active_hosts:
            vulns_sorted = sorted(
                h.get("vulnerabilities") or [],
                key=lambda v: -_SEVERITY_RANK.get(str(v.get("risk_factor") or "").strip().lower(), 0),
            )
            per_host_sorted.append(vulns_sorted)

        kept_ids = set()
        remaining_pool = []  # (severity_rank, host_idx, vuln) — highest first
        for idx, vulns_sorted in enumerate(per_host_sorted):
            guaranteed = vulns_sorted[:fair_share]
            overflow = vulns_sorted[fair_share:]
            kept_ids.update(id(v) for v in guaranteed)
            for v in overflow:
                rank = _SEVERITY_RANK.get(str(v.get("risk_factor") or "").strip().lower(), 0)
                remaining_pool.append((rank, idx, v))

        remaining_pool.sort(key=lambda t: -t[0])
        budget_left = max_vulns - len(kept_ids)
        for rank, idx, v in remaining_pool[:max(0, budget_left)]:
            kept_ids.add(id(v))

        overflow_by_host = {}
        for idx, vulns_sorted in enumerate(per_host_sorted):
            for v in vulns_sorted:
                if id(v) not in kept_ids:
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
