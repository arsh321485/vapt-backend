from django.contrib import admin
from .models import BillingCustomer, Subscription, Invoice, SalesLead, StripeWebhookEvent, PromoCode


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ("admin", "plan", "mode", "billing_cycle", "asset_count", "amount_due", "status", "created_at")
    list_filter = ("plan", "mode", "status")
    search_fields = ("admin__email",)


@admin.register(Invoice)
class InvoiceAdmin(admin.ModelAdmin):
    list_display = ("admin", "subscription", "amount", "status", "asset_count", "created_at")
    list_filter = ("status",)
    search_fields = ("admin__email", "stripe_invoice_id")


@admin.register(SalesLead)
class SalesLeadAdmin(admin.ModelAdmin):
    list_display = ("full_name", "work_email", "company", "estimated_assets", "status", "notified", "created_at")
    list_filter = ("status", "notified")
    search_fields = ("full_name", "work_email", "company")


admin.site.register(BillingCustomer)
admin.site.register(StripeWebhookEvent)


@admin.register(PromoCode)
class PromoCodeAdmin(admin.ModelAdmin):
    # No list_filter on is_active (BooleanField) — djongo's SQL->Mongo
    # translator raises SQLDecodeError whenever is_active is combined into
    # the WHERE clause on this model (confirmed against production); the
    # admin changelist filter would crash the page the moment it's used.
    list_display = ("code", "is_active", "redeemed_count", "note", "created_at")
    search_fields = ("code", "note")
