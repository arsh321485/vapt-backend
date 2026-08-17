from django.urls import path
from .views import (
    PlanEstimateView, FreemiumActivateView, PremiumCheckoutView, CustomLeadView,
    SubscriptionMeView, SubscriptionCancelView, SubscriptionSyncAssetsView,
    StripeWebhookView,
)

urlpatterns = [
    path("plans/estimate/", PlanEstimateView.as_view(), name="billing-plan-estimate"),
    path("checkout/freemium/", FreemiumActivateView.as_view(), name="billing-freemium-activate"),
    path("checkout/premium/", PremiumCheckoutView.as_view(), name="billing-premium-checkout"),
    path("leads/custom/", CustomLeadView.as_view(), name="billing-custom-lead"),
    path("subscription/me/", SubscriptionMeView.as_view(), name="billing-subscription-me"),
    path("subscription/cancel/", SubscriptionCancelView.as_view(), name="billing-subscription-cancel"),
    path("subscription/sync-assets/", SubscriptionSyncAssetsView.as_view(), name="billing-subscription-sync-assets"),
    path("webhook/stripe/", StripeWebhookView.as_view(), name="billing-stripe-webhook"),
]
