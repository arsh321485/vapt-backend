"""
Plan/pricing constants for VaptFix billing.

These mirror the vaptfix.ai/pricingplan design (Freemium / Premium / Custom).
Kept as plain constants (not DB-editable) for now — if pricing needs to change
at runtime without a deploy later, move this into an admin-editable model.
"""
from decimal import Decimal

PLAN_FREEMIUM = "freemium"
PLAN_PREMIUM = "premium"
PLAN_CUSTOM = "custom"
PLAN_CHOICES = [
    (PLAN_FREEMIUM, "Freemium"),
    (PLAN_PREMIUM, "Premium"),
    (PLAN_CUSTOM, "Custom"),
]

MODE_MANAGEMENT = "management"                 # "I already have a report" — flat $300/3mo, up to 100 assets/1,000 vulns
MODE_MANAGEMENT_TESTING = "management_testing"  # "I need VaptFix to run testing" — scope-based, $300 platform fee + per-asset-type
MODE_CHOICES = [
    (MODE_MANAGEMENT, "Management"),
    (MODE_MANAGEMENT_TESTING, "Management + Testing"),
]

# Kept only for the Subscription.billing_cycle field and the Custom tier
# (still annual-only, unaffected by this pricing redesign — see
# CUSTOM_RATE_PER_IP_ANNUAL below). Management Only and Management +
# Testing each now have exactly ONE fixed period (3 months / 6 months
# respectively — see MANAGEMENT_ONLY_PERIOD_MONTHS /
# MANAGEMENT_TESTING_PERIOD_MONTHS), so they no longer offer a cycle choice.
CYCLE_MONTHLY = "monthly"
CYCLE_QUARTERLY = "quarterly"      # Management Only's fixed 3-month period
CYCLE_SEMI_ANNUAL = "semi_annual"  # Management + Testing's fixed 6-month period
CYCLE_ANNUAL = "annual"            # Custom tier's fixed period
CYCLE_CHOICES = [
    (CYCLE_MONTHLY, "Monthly"),
    (CYCLE_QUARTERLY, "Quarterly"),
    (CYCLE_SEMI_ANNUAL, "Semi-Annual"),
    (CYCLE_ANNUAL, "Annual"),
]

# Freemium limits (enforced elsewhere — upload_report / automation_scripts / scope /
# users_details)
FREEMIUM_LIMITS = {
    "max_internal_ips": 5,
    "report_upload_limit": 1,
    "max_vulnerabilities": 10,
    "max_team_members": 3,
    "teams_enabled": 4,
    "testing_retesting": False,
    "automation_scripts": False,
    "trial_days": 30,
}

# Premium "Management Only" — a flat fee for a fixed 3-month period, NOT
# billed per asset. Covers up to MANAGEMENT_ONLY_ASSET_CAP assets and
# MANAGEMENT_ONLY_VULN_CAP vulnerabilities for that period; going over
# either cap means paying the flat fee again for the next 3-month period
# (see the pricing page's own "Over the limit: Next 3-month period, +$300"),
# not a forced upgrade to Custom.
MANAGEMENT_ONLY_FLAT_FEE = Decimal("300.00")
MANAGEMENT_ONLY_PERIOD_MONTHS = 3
MANAGEMENT_ONLY_ASSET_CAP = 100
MANAGEMENT_ONLY_VULN_CAP = 1000

# Premium "Management + Testing" — a flat platform fee plus per-asset-type
# pricing, for a fixed 6-month period (2 testing cycles/year — each cycle a
# test plus one rescan of mitigated vulnerabilities). No asset ceiling of
# its own ("Over the limit: Add more assets" on the pricing page) — an
# admin just buys more of whichever asset type they need.
MANAGEMENT_TESTING_PLATFORM_FEE = Decimal("300.00")
MANAGEMENT_TESTING_PERIOD_MONTHS = 6
MANAGEMENT_TESTING_RATE_PER_IP = Decimal("25.00")
MANAGEMENT_TESTING_RATE_PER_WEB_APP = Decimal("1250.00")
MANAGEMENT_TESTING_RATE_PER_MOBILE_APP = Decimal("1250.00")

# Custom tier (>250 assets) — unaffected by this redesign, still priced the
# same way it always was: annual-only, per-IP, uncapped.
CUSTOM_RATE_PER_IP_ANNUAL = Decimal("1.25")

# Shared ceiling: more than this many TOTAL assets routes to Custom instead
# of Premium, regardless of mode (see scope/views.py's own routing check).
# Independent of Management Only's own, smaller 100-asset cap above — that
# one is about what a single flat $300 period covers, not about when an
# admin must leave Premium for Custom entirely.
PREMIUM_ASSET_CEILING = 250


def calculate_management_amount(asset_count: int = 0) -> Decimal:
    """
    Management Only is a flat $300 for a 3-month period, regardless of
    asset count — the 100-asset/1,000-vulnerability cap is enforced
    separately (see billing.enforcement), not reflected in the price
    itself. asset_count is accepted (unused) so existing callers that
    still pass it don't need their own special-casing.
    """
    return MANAGEMENT_ONLY_FLAT_FEE


def calculate_management_testing_amount(ip_count: int = 0, web_app_count: int = 0, mobile_app_count: int = 0) -> Decimal:
    return (
        MANAGEMENT_TESTING_PLATFORM_FEE
        + Decimal(ip_count) * MANAGEMENT_TESTING_RATE_PER_IP
        + Decimal(web_app_count) * MANAGEMENT_TESTING_RATE_PER_WEB_APP
        + Decimal(mobile_app_count) * MANAGEMENT_TESTING_RATE_PER_MOBILE_APP
    )


def calculate_custom_amount(asset_count: int) -> Decimal:
    """
    Custom tier (>250 assets) — Annual-only, uncapped (no 250-asset
    ceiling), same per-IP rate it always had. Unaffected by the Management
    Only / Management + Testing pricing redesign.
    """
    return Decimal(asset_count) * CUSTOM_RATE_PER_IP_ANNUAL * 12
