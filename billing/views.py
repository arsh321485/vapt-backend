import logging

from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from users.utils import Util
from .asset_service import get_admin_asset_count
from .models import Subscription, SalesLead
from .plans import (
    PLAN_FREEMIUM, PLAN_PREMIUM, PLAN_CUSTOM,
    MODE_MANAGEMENT, MODE_MANAGEMENT_TESTING,
    FREEMIUM_LIMITS, PREMIUM_ASSET_CEILING,
    MANAGEMENT_BILLING_CYCLES, MANAGEMENT_TESTING_RATE_PER_IP_YEAR,
    calculate_management_amount, calculate_management_testing_amount,
)
from .serializers import (
    PlanEstimateRequestSerializer, PremiumCheckoutRequestSerializer,
    CustomLeadRequestSerializer, SubscriptionSerializer, InvoiceSerializer,
)
from . import stripe_service

logger = logging.getLogger(__name__)


class PlanEstimateView(APIView):
    """
    Step-2-of-3 'Review plan' preview — computes the admin's current asset
    count from their uploaded reports and returns the price breakdown,
    mirroring the pricing page's 'Example: 80 IPs on Annual -> ...' box.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PlanEstimateRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        plan = serializer.validated_data["plan"]
        mode = serializer.validated_data.get("mode")
        billing_cycle = serializer.validated_data.get("billing_cycle")

        asset_count = get_admin_asset_count(str(request.user.id))

        if plan == PLAN_FREEMIUM:
            return Response({
                "plan": plan,
                "asset_count": asset_count,
                "asset_limit": FREEMIUM_LIMITS["max_internal_ips"],
                "over_limit": asset_count > FREEMIUM_LIMITS["max_internal_ips"],
                "amount_due": "0.00",
                "currency": "usd",
            })

        if plan == PLAN_PREMIUM:
            if asset_count > PREMIUM_ASSET_CEILING:
                return Response({
                    "plan": plan,
                    "asset_count": asset_count,
                    "asset_ceiling": PREMIUM_ASSET_CEILING,
                    "over_ceiling": True,
                    "message": "250+ assets — this account must use the Custom plan.",
                })

            if mode == MODE_MANAGEMENT:
                if not billing_cycle:
                    return Response(
                        {"billing_cycle": "billing_cycle is required for Management mode."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                amount = calculate_management_amount(asset_count, billing_cycle)
                rate = MANAGEMENT_BILLING_CYCLES[billing_cycle]["rate_per_ip"]
            elif mode == MODE_MANAGEMENT_TESTING:
                amount = calculate_management_testing_amount(asset_count)
                rate = MANAGEMENT_TESTING_RATE_PER_IP_YEAR
                billing_cycle = "annual"
            else:
                return Response(
                    {"mode": "mode is required for Premium plan."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            return Response({
                "plan": plan,
                "mode": mode,
                "billing_cycle": billing_cycle,
                "asset_count": asset_count,
                "price_per_ip": str(rate),
                "amount_due": str(amount),
                "currency": "usd",
            })

        # Custom
        return Response({
            "plan": plan,
            "asset_count": asset_count,
            "asset_ceiling": PREMIUM_ASSET_CEILING,
            "message": "Contact sales for a custom quote.",
        })


class FreemiumActivateView(APIView):
    """Step 3 for Freemium — no charge, optional card-on-file via SetupIntent."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        admin = request.user
        asset_count = get_admin_asset_count(str(admin.id))

        existing = Subscription.objects.filter(admin=admin, status__in=["trialing", "active"]).first()
        if existing:
            return Response(
                {"detail": "An active subscription already exists.", "subscription": SubscriptionSerializer(existing).data},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from django.utils import timezone
        from datetime import timedelta

        sub = Subscription.objects.create(
            admin=admin,
            plan=PLAN_FREEMIUM,
            asset_count=asset_count,
            amount_due="0.00",
            status="trialing",
            trial_end=timezone.now() + timedelta(days=FREEMIUM_LIMITS["trial_days"]),
        )

        setup_intent = None
        collect_card = request.data.get("collect_card", True)
        if collect_card:
            try:
                setup_intent = stripe_service.create_setup_intent(admin)
            except Exception as e:
                logger.error(f"[Billing] SetupIntent creation failed for {admin.email}: {e}")

        return Response({
            "subscription": SubscriptionSerializer(sub).data,
            "setup_intent_client_secret": setup_intent["client_secret"] if setup_intent else None,
        }, status=status.HTTP_201_CREATED)


class PremiumCheckoutView(APIView):
    """Step 3 for Premium (Management or Management+Testing) — creates a Stripe Checkout Session."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = PremiumCheckoutRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        mode = serializer.validated_data["mode"]
        billing_cycle = serializer.validated_data.get("billing_cycle") or "annual"

        admin = request.user
        asset_count = get_admin_asset_count(str(admin.id))

        if asset_count > PREMIUM_ASSET_CEILING:
            return Response(
                {"detail": "250+ assets — use the Custom plan instead.", "asset_count": asset_count},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if asset_count == 0:
            return Response(
                {"detail": "Upload a report first — no assets found to bill for."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            result = stripe_service.create_premium_checkout_session(
                admin, mode=mode, billing_cycle=billing_cycle, asset_count=asset_count
            )
        except Exception as e:
            logger.error(f"[Billing] Checkout session creation failed for {admin.email}: {e}")
            return Response({"detail": "Could not start checkout. Please try again."}, status=500)

        return Response(result, status=status.HTTP_201_CREATED)


class CustomLeadView(APIView):
    """Step 3 for Custom — no payment, just captures the lead and notifies sales."""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CustomLeadRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        lead = SalesLead.objects.create(
            admin=request.user,
            full_name=serializer.validated_data["full_name"],
            work_email=serializer.validated_data["work_email"],
            company=serializer.validated_data.get("company", ""),
            estimated_assets=serializer.validated_data.get("estimated_assets", ""),
        )

        ok, err = Util.send_mail({
            "to_email": settings.BILLING_SALES_EMAIL,
            "subject": f"New Custom plan lead: {lead.company or lead.full_name}",
            "body": (
                f"Name: {lead.full_name}\n"
                f"Email: {lead.work_email}\n"
                f"Company: {lead.company}\n"
                f"Estimated assets: {lead.estimated_assets}\n"
                f"Admin account: {request.user.email}\n"
            ),
        })
        lead.notified = bool(ok)
        lead.save(update_fields=["notified"])
        if not ok:
            logger.error(f"[Billing] Sales lead email failed: {err}")

        return Response({"detail": "Request submitted. Our sales team will reach out."}, status=status.HTTP_201_CREATED)


class SubscriptionMeView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        sub = (
            Subscription.objects.filter(admin=request.user)
            .order_by("-created_at")
            .first()
        )
        if not sub:
            return Response({"subscription": None})

        invoices = sub.invoices.order_by("-created_at")[:20]
        return Response({
            "subscription": SubscriptionSerializer(sub).data,
            "invoices": InvoiceSerializer(invoices, many=True).data,
        })


class SubscriptionCancelView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        sub = Subscription.objects.filter(admin=request.user, status__in=["active", "trialing", "past_due"]).first()
        if not sub:
            return Response({"detail": "No active subscription found."}, status=status.HTTP_404_NOT_FOUND)
        stripe_service.cancel_subscription(sub)
        return Response({"detail": "Subscription will cancel at the end of the current period."})


class SubscriptionSyncAssetsView(APIView):
    """
    Recomputes the admin's asset count (e.g. after uploading a new report)
    and, if they're on an active Premium/Management subscription, updates
    the Stripe quantity with proration. Intended to be called both manually
    and from the upload_report pipeline after a report finishes parsing.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        admin = request.user
        asset_count = get_admin_asset_count(str(admin.id))

        sub = Subscription.objects.filter(
            admin=admin, plan=PLAN_PREMIUM, mode=MODE_MANAGEMENT, status="active"
        ).first()

        if sub and sub.asset_count != asset_count:
            try:
                stripe_service.update_subscription_asset_quantity(sub, asset_count)
            except Exception as e:
                logger.error(f"[Billing] Failed to sync Stripe quantity for {admin.email}: {e}")
                return Response({"detail": "Asset count updated locally; Stripe sync failed."}, status=500)

        return Response({"asset_count": asset_count})


@method_decorator(csrf_exempt, name="dispatch")
class StripeWebhookView(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]

    def post(self, request):
        payload = request.body
        sig_header = request.META.get("HTTP_STRIPE_SIGNATURE", "")

        try:
            event = stripe_service.verify_and_parse_event(payload, sig_header)
        except ValueError:
            logger.warning("[Billing] Stripe webhook: invalid payload")
            return Response({"detail": "Invalid payload"}, status=400)
        except Exception as e:
            logger.warning(f"[Billing] Stripe webhook: signature verification failed: {e}")
            return Response({"detail": "Invalid signature"}, status=400)

        try:
            stripe_service.handle_webhook_event(event)
        except Exception as e:
            logger.error(f"[Billing] Stripe webhook handling error: {e}")
            return Response({"detail": "Webhook handling error"}, status=500)

        return Response({"received": True})
