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


def assert_can_upload_report(admin):
    if not is_freemium(admin):
        return
    from upload_report.models import UploadReport
    existing = UploadReport.objects.filter(admin=admin).count()
    if existing >= FREEMIUM_LIMITS["report_upload_limit"]:
        raise PlanLimitExceeded(
            f"Freemium plan allows only {FREEMIUM_LIMITS['report_upload_limit']} report upload. "
            "Upgrade to Premium to upload more reports."
        )


def assert_asset_within_limit(admin, asset_count: int):
    if not is_freemium(admin):
        return
    limit = FREEMIUM_LIMITS["max_internal_ips"]
    if asset_count > limit:
        raise PlanLimitExceeded(
            f"Freemium plan allows up to {limit} internal IPs — this report has {asset_count}. "
            "Upgrade to Premium to cover more assets."
        )


def assert_can_use_automation_scripts(admin):
    if is_freemium(admin) and not FREEMIUM_LIMITS["automation_scripts"]:
        raise PlanLimitExceeded(
            "Automation scripts are not available on the Freemium plan. Upgrade to Premium."
        )


def assert_can_request_testing(admin):
    """Gates both new 'Management + Testing' scope submissions and
    retest requests on already-closed vulnerabilities."""
    if is_freemium(admin) and not FREEMIUM_LIMITS["testing_retesting"]:
        raise PlanLimitExceeded(
            "Testing/retesting is not available on the Freemium plan. Upgrade to Premium."
        )
