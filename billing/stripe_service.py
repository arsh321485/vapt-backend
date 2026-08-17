"""
All direct Stripe API calls live here — views.py stays thin and testable.
"""
import logging
from datetime import datetime, timezone as dt_timezone

import stripe
from django.conf import settings
from django.utils import timezone

from .models import BillingCustomer, Subscription, Invoice, StripeWebhookEvent
from .plans import (
    MODE_MANAGEMENT, MODE_MANAGEMENT_TESTING,
    MANAGEMENT_BILLING_CYCLES, MANAGEMENT_TESTING_RATE_PER_IP_YEAR,
    calculate_management_amount, calculate_management_testing_amount,
)

logger = logging.getLogger(__name__)

stripe.api_key = settings.STRIPE_SECRET_KEY


def _ts_to_dt(ts):
    if not ts:
        return None
    # Naive UTC — djongo rejects timezone-aware datetimes since this project
    # runs with USE_TZ=False (matches datetime.utcnow() used elsewhere here).
    return datetime.fromtimestamp(ts, tz=dt_timezone.utc).replace(tzinfo=None)


def get_or_create_customer(admin) -> str:
    """Returns the Stripe Customer ID for this admin, creating one if needed."""
    existing = BillingCustomer.objects.filter(admin=admin).first()
    if existing:
        return existing.stripe_customer_id

    customer = stripe.Customer.create(
        email=admin.email,
        metadata={"admin_id": str(admin.id)},
    )
    BillingCustomer.objects.create(admin=admin, stripe_customer_id=customer["id"])
    return customer["id"]


def create_setup_intent(admin) -> dict:
    """Used on the Freemium step to save a card without charging (per the
    pricing-page copy: 'No charge is processed on this screen yet')."""
    customer_id = get_or_create_customer(admin)
    intent = stripe.SetupIntent.create(
        customer=customer_id,
        usage="off_session",
        metadata={"admin_id": str(admin.id), "purpose": "freemium_card_on_file"},
    )
    return {"client_secret": intent["client_secret"], "customer_id": customer_id}


def create_premium_checkout_session(admin, mode: str, billing_cycle: str, asset_count: int) -> dict:
    """
    Builds a Stripe Checkout Session with a dynamic per-IP price (price_data) —
    no pre-created Stripe Price objects needed since the unit quantity (asset
    count) differs per admin.
    """
    customer_id = get_or_create_customer(admin)

    if mode == MODE_MANAGEMENT:
        cfg = MANAGEMENT_BILLING_CYCLES[billing_cycle]
        unit_amount_cents = int(cfg["rate_per_ip"] * cfg["months"] * 100)
        recurring = {"interval": cfg["stripe_interval"], "interval_count": cfg["stripe_interval_count"]}
        product_name = f"VaptFix Premium — Management ({billing_cycle})"
        amount_due = calculate_management_amount(asset_count, billing_cycle)
        price_per_ip = cfg["rate_per_ip"]
    elif mode == MODE_MANAGEMENT_TESTING:
        unit_amount_cents = int(MANAGEMENT_TESTING_RATE_PER_IP_YEAR * 100)
        recurring = {"interval": "year", "interval_count": 1}
        product_name = "VaptFix Premium — Management + Testing (Annual)"
        amount_due = calculate_management_testing_amount(asset_count)
        price_per_ip = MANAGEMENT_TESTING_RATE_PER_IP_YEAR
    else:
        raise ValueError(f"Unknown premium mode: {mode}")

    metadata = {
        "admin_id": str(admin.id),
        "plan": "premium",
        "mode": mode,
        "billing_cycle": billing_cycle,
        "asset_count": str(asset_count),
    }

    frontend_url = getattr(settings, "FRONTEND_URL", "https://vaptfix.ai").rstrip("/")
    session = stripe.checkout.Session.create(
        customer=customer_id,
        mode="subscription",
        payment_method_types=["card"],
        line_items=[{
            "price_data": {
                "currency": "usd",
                "product_data": {"name": product_name},
                "unit_amount": unit_amount_cents,
                "recurring": recurring,
            },
            "quantity": max(int(asset_count), 1),
        }],
        success_url=f"{frontend_url}/billing/success?session_id={{CHECKOUT_SESSION_ID}}",
        cancel_url=f"{frontend_url}/billing/cancel",
        metadata=metadata,
        subscription_data={"metadata": metadata},
    )

    Subscription.objects.create(
        admin=admin,
        plan="premium",
        mode=mode,
        billing_cycle=billing_cycle if mode == MODE_MANAGEMENT else "annual",
        asset_count=asset_count,
        price_per_ip=str(price_per_ip),
        amount_due=str(amount_due),
        status="incomplete",
        stripe_checkout_session_id=session["id"],
    )

    return {"checkout_url": session["url"], "session_id": session["id"], "amount_due": str(amount_due)}


def cancel_subscription(subscription: Subscription):
    if subscription.stripe_subscription_id:
        try:
            stripe.Subscription.modify(subscription.stripe_subscription_id, cancel_at_period_end=True)
        except stripe.error.InvalidRequestError as e:
            # Stripe-side subscription already gone/never existed (e.g. manual
            # cleanup, data drift) — still cancel locally rather than 500ing.
            logger.warning(
                f"[Billing] Stripe cancel failed for subscription {subscription.stripe_subscription_id}: {e}"
            )
    subscription.status = "canceled"
    subscription.canceled_at = timezone.now()
    subscription.save(update_fields=["status", "canceled_at", "updated_at"])


def update_subscription_asset_quantity(subscription: Subscription, new_asset_count: int):
    """Called when a new report changes the admin's billable asset count —
    updates Stripe's subscription item quantity with proration."""
    if not subscription.stripe_subscription_item_id:
        logger.warning(
            f"[Billing] Cannot update quantity for subscription {subscription._id} — "
            "no stripe_subscription_item_id on file yet."
        )
        return
    stripe.SubscriptionItem.modify(
        subscription.stripe_subscription_item_id,
        quantity=max(int(new_asset_count), 1),
        proration_behavior="create_prorations",
    )
    subscription.asset_count = new_asset_count
    if subscription.price_per_ip is not None:
        # Re-derive amount_due for display purposes (actual charge is Stripe's).
        from decimal import Decimal
        months = MANAGEMENT_BILLING_CYCLES.get(subscription.billing_cycle, {}).get("months", 1) \
            if subscription.mode == MODE_MANAGEMENT else 1
        subscription.amount_due = str(Decimal(subscription.price_per_ip) * new_asset_count * months)
    subscription.save(update_fields=["asset_count", "amount_due", "updated_at"])


# ---------------------------------------------------------------------------
# Webhook handling
# ---------------------------------------------------------------------------

def verify_and_parse_event(payload: bytes, sig_header: str):
    return stripe.Webhook.construct_event(payload, sig_header, settings.STRIPE_WEBHOOK_SECRET)


def handle_webhook_event(event) -> None:
    # stripe-python's Event/StripeObject only supports attribute/[] access,
    # not .get() — normalize to a plain (recursive) dict up front so the
    # rest of this module can use ordinary dict methods throughout.
    if hasattr(event, "to_dict"):
        event = event.to_dict()

    event_id = event.get("id")
    event_type = event.get("type")

    if not event_id:
        return

    # Idempotency — Stripe redelivers events; skip anything already processed.
    if StripeWebhookEvent.objects.filter(event_id=event_id).exists():
        logger.info(f"[Billing] Duplicate webhook event skipped: {event_id}")
        return
    StripeWebhookEvent.objects.create(event_id=event_id, event_type=event_type)

    data = event.get("data", {}).get("object", {})

    try:
        if event_type == "checkout.session.completed":
            _on_checkout_completed(data)
        elif event_type == "invoice.paid":
            _on_invoice_paid(data)
        elif event_type == "invoice.payment_failed":
            _on_invoice_failed(data)
        elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
            _on_subscription_updated(data, deleted=(event_type == "customer.subscription.deleted"))
        else:
            logger.info(f"[Billing] Unhandled webhook event type: {event_type}")
    except Exception as e:
        logger.error(f"[Billing] Error handling webhook {event_type} ({event_id}): {e}")
        raise


def _subscription_period(stripe_sub: dict):
    """
    current_period_start/end moved off the Subscription object onto its first
    item in newer Stripe API versions (e.g. 2025-03-31.basil and later) — fall
    back to the top-level fields for accounts still on an older API version.
    """
    items = (stripe_sub.get("items") or {}).get("data", [])
    if items and ("current_period_start" in items[0] or "current_period_end" in items[0]):
        return items[0].get("current_period_start"), items[0].get("current_period_end")
    return stripe_sub.get("current_period_start"), stripe_sub.get("current_period_end")


def _invoice_subscription_id(invoice: dict):
    """
    invoice.subscription moved to invoice.parent.subscription_details.subscription
    in newer Stripe API versions — fall back to the old top-level field.
    """
    parent = invoice.get("parent") or {}
    nested = (parent.get("subscription_details") or {}).get("subscription")
    return nested or invoice.get("subscription")


def _on_checkout_completed(session: dict):
    session_id = session.get("id")
    stripe_subscription_id = session.get("subscription")

    sub = Subscription.objects.filter(stripe_checkout_session_id=session_id).first()
    if not sub:
        logger.warning(f"[Billing] checkout.session.completed for unknown session {session_id}")
        return

    sub.status = "active"
    sub.stripe_subscription_id = stripe_subscription_id

    if stripe_subscription_id:
        stripe_sub = stripe.Subscription.retrieve(stripe_subscription_id).to_dict()
        items = stripe_sub.get("items", {}).get("data", [])
        if items:
            sub.stripe_subscription_item_id = items[0]["id"]
        period_start, period_end = _subscription_period(stripe_sub)
        sub.current_period_start = _ts_to_dt(period_start)
        sub.current_period_end = _ts_to_dt(period_end)

    sub.save()


def _on_invoice_paid(invoice: dict):
    _upsert_invoice(invoice, status="paid")


def _on_invoice_failed(invoice: dict):
    sub = _upsert_invoice(invoice, status="failed")
    if sub:
        sub.status = "past_due"
        sub.save(update_fields=["status", "updated_at"])


def _upsert_invoice(invoice: dict, status: str):
    stripe_subscription_id = _invoice_subscription_id(invoice)
    sub = Subscription.objects.filter(stripe_subscription_id=stripe_subscription_id).first()
    if not sub:
        logger.warning(f"[Billing] invoice event for unknown subscription {stripe_subscription_id}")
        return None

    Invoice.objects.update_or_create(
        stripe_invoice_id=invoice.get("id"),
        defaults={
            "subscription": sub,
            "admin": sub.admin,
            "stripe_payment_intent_id": invoice.get("payment_intent") or "",
            "amount": str((invoice.get("amount_paid") or invoice.get("amount_due") or 0) / 100),
            "currency": invoice.get("currency", "usd"),
            "asset_count": sub.asset_count,
            "status": status,
            "hosted_invoice_url": invoice.get("hosted_invoice_url") or "",
        },
    )
    return sub


def _on_subscription_updated(stripe_sub: dict, deleted: bool):
    sub = Subscription.objects.filter(stripe_subscription_id=stripe_sub.get("id")).first()
    if not sub:
        return
    if deleted:
        sub.status = "canceled"
        sub.canceled_at = timezone.now()
    else:
        status_map = {
            "active": "active",
            "trialing": "trialing",
            "past_due": "past_due",
            "unpaid": "past_due",
            "canceled": "canceled",
            "incomplete": "incomplete",
            "incomplete_expired": "canceled",
        }
        sub.status = status_map.get(stripe_sub.get("status"), sub.status)
        period_start, period_end = _subscription_period(stripe_sub)
        sub.current_period_start = _ts_to_dt(period_start)
        sub.current_period_end = _ts_to_dt(period_end)
    sub.save()
