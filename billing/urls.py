from django.urls import path
from .views import (
    PlanEstimateView, FreemiumActivateView, PremiumCheckoutView, PremiumCheckoutConfirmView,
    CustomCheckoutView,
    SubscriptionMeView, SubscriptionCancelView, SubscriptionSyncAssetsView,
    StripeWebhookView,
)

urlpatterns = [
    path("plans/estimate/", PlanEstimateView.as_view(), name="billing-plan-estimate"),
    path("checkout/freemium/", FreemiumActivateView.as_view(), name="billing-freemium-activate"),
    path("checkout/premium/", PremiumCheckoutView.as_view(), name="billing-premium-checkout"),
    path("checkout/custom/", CustomCheckoutView.as_view(), name="billing-custom-checkout"),
    path("checkout/confirm/", PremiumCheckoutConfirmView.as_view(), name="billing-premium-checkout-confirm"),
    # "leads/custom/" (CustomLeadView, the "Talk to sales" lead-capture
    # endpoint) removed — real request: the website pricing page dropped
    # the Custom tier entirely, so there's nothing for a "Talk to sales
    # about Custom" CTA to lead into anymore. View/model (SalesLead) left
    # in place, unrouted, not deleted — easy to re-wire if a generic
    # "Contact Sales" CTA is wanted again later.
    path("subscription/me/", SubscriptionMeView.as_view(), name="billing-subscription-me"),
    path("subscription/cancel/", SubscriptionCancelView.as_view(), name="billing-subscription-cancel"),
    path("subscription/sync-assets/", SubscriptionSyncAssetsView.as_view(), name="billing-subscription-sync-assets"),
    path("webhook/stripe/", StripeWebhookView.as_view(), name="billing-stripe-webhook"),
]
