import logging

from django.conf import settings
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView

from users.utils import Util
from .asset_service import (
    get_admin_asset_count, get_admin_scope_asset_count, resolve_management_testing_asset_count,
    get_admin_billable_asset_count, get_admin_asset_breakdown_counts,
)
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

        if plan == PLAN_FREEMIUM:
            asset_count = get_admin_asset_count(str(request.user.id))
            return Response({
                "plan": plan,
                "asset_count": asset_count,
                "asset_limit": FREEMIUM_LIMITS["max_internal_ips"],
                "over_limit": asset_count > FREEMIUM_LIMITS["max_internal_ips"],
                "amount_due": "0.00",
                "currency": "usd",
            })

        if plan == PLAN_PREMIUM:
            if mode not in (MODE_MANAGEMENT, MODE_MANAGEMENT_TESTING):
                return Response(
                    {"mode": "mode is required for Premium plan."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Mode A bills on uploaded-report assets. Mode B prefers that
            # SAME report's asset count when one already exists (an admin
            # who already uploaded a report just wants testing added on
            # top, not a separate target list) — falls back to the scope
            # submitted via /api/admin/scope/create/ only when there's no
            # report at all.
            #
            # Premium billing uses get_admin_billable_asset_count (the
            # ORIGINAL file size — visible + locked), never
            # get_admin_asset_count (Freemium's visible-only cap of 5) —
            # real bug confirmed by the frontend: a 15-IP file uploaded on
            # Freemium (showing 5, 10 saved as locked_hosts) was still
            # pricing Premium at 5 IPs after the admin chose to upgrade.
            asset_source = "report"
            if mode == MODE_MANAGEMENT:
                asset_count = get_admin_billable_asset_count(str(request.user.id))
            else:
                asset_count, asset_source = resolve_management_testing_asset_count(str(request.user.id))

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
            else:
                amount = calculate_management_testing_amount(asset_count)
                rate = MANAGEMENT_TESTING_RATE_PER_IP_YEAR
                billing_cycle = "annual"

            response_data = {
                "plan": plan,
                "mode": mode,
                "billing_cycle": billing_cycle,
                "asset_count": asset_count,
                "price_per_ip": str(rate),
                "amount_due": str(amount),
                "currency": "usd",
            }
            # Explicit billing breakdown so the frontend never has to guess
            # which count is which — visible/locked only differ from
            # original/billable for a Management-mode admin who has
            # Freemium-trimmed hosts; Management+Testing (scope-based, no
            # report trimming involved) reports the same value for all four.
            if mode == MODE_MANAGEMENT:
                response_data.update(get_admin_asset_breakdown_counts(str(request.user.id)))
            else:
                response_data.update({
                    "visible_asset_count": asset_count,
                    "locked_asset_count": 0,
                    "original_asset_count": asset_count,
                    "billable_asset_count": asset_count,
                })
            if mode == MODE_MANAGEMENT_TESTING:
                # Lets the frontend show "priced from your uploaded report"
                # vs "priced from your submitted scope".
                response_data["asset_source"] = asset_source

            # Only genuinely nothing to price on — no uploaded report AND
            # no submitted scope. $0.00 alone would read as a real (wrong)
            # total, so flag it explicitly and point the frontend at the
            # endpoint that actually unblocks it.
            if mode == MODE_MANAGEMENT_TESTING and asset_count == 0:
                response_data["needs_scope"] = True
                response_data["message"] = (
                    "No report or scope found yet — pricing can't be calculated until "
                    "you upload a report or provide your target IPs/URLs."
                )
                response_data["scope_submit_endpoint"] = "/api/admin/scope/create/"

            return Response(response_data)

        # Custom
        asset_count = get_admin_asset_count(str(request.user.id)) + get_admin_scope_asset_count(str(request.user.id))
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
        # Mode A bills on uploaded-report assets. Mode B prefers that SAME
        # report's asset count when one exists, falling back to the
        # submitted scope only when there's no report at all — see
        # resolve_management_testing_asset_count(). Same billable-count fix
        # as PlanEstimateView — checkout must never create a Stripe session
        # for the Freemium visible-only count when locked_hosts exist.
        if mode == MODE_MANAGEMENT:
            asset_count = get_admin_billable_asset_count(str(admin.id))
            no_assets_detail = "Upload a report first — no assets found to bill for."
        else:
            asset_count, _asset_source = resolve_management_testing_asset_count(str(admin.id))
            no_assets_detail = "Upload a report or provide your scope first — no targets found to bill for."

        if asset_count > PREMIUM_ASSET_CEILING:
            return Response(
                {"detail": "250+ assets — use the Custom plan instead.", "asset_count": asset_count},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if asset_count == 0:
            return Response(
                {"detail": no_assets_detail},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            result = stripe_service.create_premium_checkout_session(
                admin, mode=mode, billing_cycle=billing_cycle, asset_count=asset_count
            )
        except Exception as e:
            # Surface the real reason instead of a generic "please try
            # again" — the frontend was showing our own hardcoded generic
            # string verbatim with no way to tell a Stripe configuration
            # problem apart from a real transient failure. stripe.error.*
            # exceptions carry a human-readable `user_message`/str(e)
            # (e.g. "No such customer", invalid API key, card errors) —
            # pass that through; only fall back to generic for a truly
            # unexpected (non-Stripe) exception.
            logger.exception(f"[Billing] Checkout session creation failed for {admin.email}")
            try:
                import stripe as _stripe
                if isinstance(e, _stripe.error.StripeError):
                    detail = getattr(e, "user_message", None) or str(e) or "Could not start checkout. Please try again."
                else:
                    detail = "Could not start checkout. Please try again."
            except Exception:
                detail = "Could not start checkout. Please try again."
            return Response({"detail": detail}, status=500)

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
            **get_admin_asset_breakdown_counts(str(request.user.id)),
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
        # Billable (visible + locked) — a Premium/active-Management admin
        # should never actually have locked_hosts (the trim only ever
        # applies to Freemium), but using the same billable-count function
        # here as estimate/checkout keeps this endpoint from ever silently
        # under-syncing if that assumption is ever wrong.
        asset_count = get_admin_billable_asset_count(str(admin.id))

        sub = Subscription.objects.filter(
            admin=admin, plan=PLAN_PREMIUM, mode=MODE_MANAGEMENT, status="active"
        ).first()

        if sub and sub.asset_count != asset_count:
            try:
                stripe_service.update_subscription_asset_quantity(sub, asset_count)
            except Exception as e:
                logger.error(f"[Billing] Failed to sync Stripe quantity for {admin.email}: {e}")
                return Response({"detail": "Asset count updated locally; Stripe sync failed."}, status=500)

        return Response({"asset_count": asset_count, **get_admin_asset_breakdown_counts(str(admin.id))})


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
