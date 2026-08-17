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

MODE_MANAGEMENT = "management"                # "I already have a report" — upload report, billed per IP
MODE_MANAGEMENT_TESTING = "management_testing"  # "I need VaptFix to run testing" — scope-based, $20/IP/year
MODE_CHOICES = [
    (MODE_MANAGEMENT, "Management"),
    (MODE_MANAGEMENT_TESTING, "Management + Testing"),
]

CYCLE_MONTHLY = "monthly"
CYCLE_SEMI_ANNUAL = "semi_annual"
CYCLE_ANNUAL = "annual"
CYCLE_CHOICES = [
    (CYCLE_MONTHLY, "Monthly"),
    (CYCLE_SEMI_ANNUAL, "Semi-Annual"),
    (CYCLE_ANNUAL, "Annual"),
]

# Freemium limits (enforced elsewhere — upload_report / automation_scripts / scope)
FREEMIUM_LIMITS = {
    "max_internal_ips": 5,
    "report_upload_limit": 1,
    "max_vulnerabilities": 10,
    "teams_enabled": 1,
    "testing_retesting": False,
    "automation_scripts": False,
    "trial_days": 30,
}

# Premium "Management" mode — billed per IP, rate depends on billing cycle.
# rate_per_ip is a MONTHLY rate; the actual charge per billing event is
# rate_per_ip * months_in_cycle * asset_count (matches the pricing-page example:
# "80 IPs on Annual -> 80 x $1.25 x 12 = $1,200/year", "Monthly -> 80 x $2.00 = $160/month").
MANAGEMENT_BILLING_CYCLES = {
    CYCLE_MONTHLY: {
        "rate_per_ip": Decimal("2.00"),
        "months": 1,
        "stripe_interval": "month",
        "stripe_interval_count": 1,
    },
    CYCLE_SEMI_ANNUAL: {
        "rate_per_ip": Decimal("1.50"),
        "months": 6,
        "stripe_interval": "month",
        "stripe_interval_count": 6,
    },
    CYCLE_ANNUAL: {
        "rate_per_ip": Decimal("1.25"),
        "months": 12,
        "stripe_interval": "year",
        "stripe_interval_count": 1,
    },
}

# Premium "Management + Testing" mode — annual commitment only.
MANAGEMENT_TESTING_RATE_PER_IP_YEAR = Decimal("20.00")

# Ceiling shared by both Premium modes — above this, plan must be Custom.
PREMIUM_ASSET_CEILING = 250


def calculate_management_amount(asset_count: int, billing_cycle: str) -> Decimal:
    cfg = MANAGEMENT_BILLING_CYCLES[billing_cycle]
    return Decimal(asset_count) * cfg["rate_per_ip"] * cfg["months"]


def calculate_management_testing_amount(asset_count: int) -> Decimal:
    return Decimal(asset_count) * MANAGEMENT_TESTING_RATE_PER_IP_YEAR
