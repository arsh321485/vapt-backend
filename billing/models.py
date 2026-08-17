from djongo import models
from bson import ObjectId
from django.utils import timezone
from users.models import User
from .plans import PLAN_CHOICES, MODE_CHOICES, CYCLE_CHOICES


class BillingCustomer(models.Model):
    """One Stripe Customer per admin — reused across Freemium/Premium subscriptions."""
    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    admin = models.OneToOneField(
        User, on_delete=models.CASCADE, related_name="billing_customer"
    )
    stripe_customer_id = models.CharField(max_length=255, unique=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_customers"

    def __str__(self):
        return f"{self.admin.email} -> {self.stripe_customer_id}"


class Subscription(models.Model):
    STATUS_CHOICES = [
        ("incomplete", "Incomplete"),   # checkout session created, payment not confirmed yet
        ("trialing", "Trialing"),       # freemium
        ("active", "Active"),
        ("past_due", "Past Due"),
        ("canceled", "Canceled"),
    ]

    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    admin = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="billing_subscriptions"
    )

    plan = models.CharField(max_length=20, choices=PLAN_CHOICES)
    mode = models.CharField(max_length=30, choices=MODE_CHOICES, null=True, blank=True)
    billing_cycle = models.CharField(max_length=20, choices=CYCLE_CHOICES, null=True, blank=True)

    # Snapshot of unique assets/IPs (from admin's uploaded reports) used for the current charge.
    # price_per_ip / amount_due are stored as strings (not DecimalField) — djongo's
    # Decimal128 handling breaks on update/read (this is the source of truth for
    # display only; Stripe's cent amounts are the actual billing source of truth).
    asset_count = models.IntegerField(default=0)
    price_per_ip = models.CharField(max_length=30, null=True, blank=True)
    amount_due = models.CharField(max_length=30, default="0.00")
    currency = models.CharField(max_length=10, default="usd")

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="incomplete")

    stripe_checkout_session_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    stripe_subscription_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    stripe_subscription_item_id = models.CharField(max_length=255, null=True, blank=True)

    current_period_start = models.DateTimeField(null=True, blank=True)
    current_period_end = models.DateTimeField(null=True, blank=True)
    trial_end = models.DateTimeField(null=True, blank=True)
    canceled_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "billing_subscriptions"
        indexes = [
            models.Index(fields=["admin", "status"]),
        ]

    def __str__(self):
        return f"{self.admin.email} - {self.plan}/{self.mode or '-'} ({self.status})"

    def is_current(self):
        return self.status in ("trialing", "active", "past_due")


class Invoice(models.Model):
    STATUS_CHOICES = [
        ("open", "Open"),
        ("paid", "Paid"),
        ("failed", "Failed"),
        ("void", "Void"),
    ]

    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    subscription = models.ForeignKey(
        Subscription, on_delete=models.CASCADE, related_name="invoices"
    )
    admin = models.ForeignKey(User, on_delete=models.CASCADE, related_name="billing_invoices")

    stripe_invoice_id = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    stripe_payment_intent_id = models.CharField(max_length=255, null=True, blank=True)

    amount = models.CharField(max_length=30, default="0.00")
    currency = models.CharField(max_length=10, default="usd")
    asset_count = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="open")
    hosted_invoice_url = models.CharField(max_length=1000, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_invoices"

    def __str__(self):
        return f"Invoice {self.stripe_invoice_id or self._id} - {self.status}"


class SalesLead(models.Model):
    """Custom-plan 'Contact Sales' lead capture — no payment involved."""
    STATUS_CHOICES = [
        ("new", "New"),
        ("contacted", "Contacted"),
        ("closed", "Closed"),
    ]

    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    admin = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="sales_leads"
    )
    full_name = models.CharField(max_length=255)
    work_email = models.EmailField()
    company = models.CharField(max_length=255, blank=True)
    estimated_assets = models.CharField(max_length=50, blank=True)  # free text, e.g. "300+"

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="new")
    notified = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "billing_sales_leads"

    def __str__(self):
        return f"{self.full_name} <{self.work_email}>"


class StripeWebhookEvent(models.Model):
    """Idempotency guard — Stripe can and will redeliver the same event."""
    _id = models.ObjectIdField(primary_key=True, default=ObjectId)

    event_id = models.CharField(max_length=255, unique=True)
    event_type = models.CharField(max_length=100)
    processed_at = models.DateTimeField(default=timezone.now)

    class Meta:
        db_table = "billing_stripe_webhook_events"

    def __str__(self):
        return f"{self.event_type} ({self.event_id})"
