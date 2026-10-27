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
from .plans import (
    PLAN_FREEMIUM, PLAN_PREMIUM, MODE_MANAGEMENT, FREEMIUM_LIMITS,
    MANAGEMENT_ONLY_ASSET_CAP, MANAGEMENT_ONLY_VULN_CAP,
)


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


def _is_management_only_admin(admin) -> bool:
    """
    True for an admin on an active Premium "Management Only" subscription
    (plan=premium, mode=management) — the only plan the 100-asset/1,000-
    vulnerability cap (see billing.plans.MANAGEMENT_ONLY_ASSET_CAP/
    MANAGEMENT_ONLY_VULN_CAP) applies to. An unlimited admin is never
    capped, same exemption as every other limit in this file.
    """
    if _is_unlimited_admin(admin):
        return False
    sub = get_active_plan(admin)
    return bool(sub) and sub.plan == PLAN_PREMIUM and sub.mode == MODE_MANAGEMENT


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
    # Real request: an admin whose report was claimed via a magic-link
    # invite (users.invite_utils.claim_invite sets this) gets no Freemium
    # restrictions at all — same exemption tier as is_superuser/the fixed
    # email allowlist below.
    if getattr(admin, "magic_link_unlimited", False):
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
    if _is_unlimited_admin(admin) or not is_freemium(admin):
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


def _select_active_hosts(vulnerabilities_by_host, max_hosts, max_vulns):
    """
    Caps a report down to at most `max_hosts` hosts and `max_vulns` total
    findings across them — the plan-agnostic algorithm shared by
    select_freemium_active_hosts (5 hosts/10 vulns) and
    select_management_only_active_hosts (100 hosts/1,000 vulns); see
    select_freemium_active_hosts's own docstring for the full step-1/step-2
    explanation (host selection, then per-host fair-share + global-overflow
    finding trim). Pure function — no admin/plan gating, callers decide
    whether capping applies at all before calling this.

    Returns (active_hosts, locked_hosts). Already-within-both-caps input is
    a no-op: `active` is everything and `locked` is empty.
    """
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
                # This host_name is already counted in active_hosts — this
                # entry only carries its trimmed-off findings for later
                # restore (see unlock_freemium_hosts_for_admin), it is NOT
                # a second distinct asset. Flagged so every asset/host count
                # (get_admin_billable_asset_count, counts_from_report_doc,
                # ...) can exclude it and not double-bill this host — real
                # bug: a report with 49 real hosts priced as 50 because one
                # active host's vuln overflow landed in locked_hosts as if
                # it were a whole separate locked host.
                overflow_host["_vuln_overflow"] = True
                locked_hosts.append(overflow_host)
        active_hosts = new_active_hosts

    return active_hosts, locked_hosts


def select_freemium_active_hosts(vulnerabilities_by_host, admin):
    """
    Freemium gets at most FREEMIUM_LIMITS['max_internal_ips'] hosts, and at
    most FREEMIUM_LIMITS['max_vulnerabilities'] total findings across them
    — see _select_active_hosts's own docstring for exactly how hosts/
    findings are chosen (fair-share-first host selection, then a two-pass
    per-host-guarantee + global-overflow finding trim).

    Trimmed findings are never discarded — they move into `locked` as an
    extra entry for their same host_name, so an upgrade can restore them
    exactly (see upload_report.views.unlock_freemium_hosts_for_admin,
    called on a successful Premium/Custom checkout).

    Returns (active_hosts, locked_hosts). For a Premium/unlimited admin, or
    a report already within both caps, this is a no-op: `active` is
    everything and `locked` is empty.
    """
    if _is_unlimited_admin(admin) or not is_freemium(admin):
        return list(vulnerabilities_by_host or []), []
    return _select_active_hosts(
        vulnerabilities_by_host, FREEMIUM_LIMITS["max_internal_ips"], FREEMIUM_LIMITS["max_vulnerabilities"]
    )


def select_management_only_active_hosts(vulnerabilities_by_host, admin):
    """
    Same mechanism as select_freemium_active_hosts, applied to Premium
    "Management Only" admins instead — capped at
    MANAGEMENT_ONLY_ASSET_CAP hosts / MANAGEMENT_ONLY_VULN_CAP
    vulnerabilities (the $300/3-months plan's included allowance — see
    billing.plans). A report over either cap keeps the overflow in
    `locked_hosts` exactly like Freemium does; it's restored automatically
    by the SAME upload_report.views.unlock_freemium_hosts_for_admin used
    for Freemium upgrades — that function already unlocks every
    locked_hosts entry for an admin on ANY successful Premium/Custom
    checkout completion (billing/stripe_service.py's
    _on_checkout_completed), which already covers "pay $300 again for the
    next period" since that's still plan=premium. No separate unlock path
    needed for this cap.

    Returns (active_hosts, locked_hosts). No-op (everything active) for
    any admin who isn't currently on an active Management Only
    subscription — including Freemium (that's select_freemium_active_hosts's
    job, with its own much smaller caps) and every other Premium/Custom mode.
    """
    if not _is_management_only_admin(admin):
        return list(vulnerabilities_by_host or []), []
    return _select_active_hosts(vulnerabilities_by_host, MANAGEMENT_ONLY_ASSET_CAP, MANAGEMENT_ONLY_VULN_CAP)


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
