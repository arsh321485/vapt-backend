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
    resolve_management_testing_asset_type_counts, get_admin_vulnerability_count,
    get_admin_billable_asset_count, get_admin_asset_breakdown_counts,
)
from .models import Subscription, SalesLead
from .plans import (
    PLAN_FREEMIUM, PLAN_PREMIUM, PLAN_CUSTOM,
    MODE_MANAGEMENT, MODE_MANAGEMENT_TESTING,
    FREEMIUM_LIMITS, PREMIUM_ASSET_CEILING,
    CYCLE_QUARTERLY, CYCLE_SEMI_ANNUAL,
    MANAGEMENT_ONLY_ASSET_CAP, MANAGEMENT_ONLY_VULN_CAP,
    MANAGEMENT_TESTING_RATE_PER_IP, MANAGEMENT_TESTING_RATE_PER_WEB_APP, MANAGEMENT_TESTING_RATE_PER_MOBILE_APP,
    calculate_management_amount, calculate_management_testing_amount,
)
from .serializers import (
    PlanEstimateRequestSerializer, PremiumCheckoutRequestSerializer, CustomCheckoutRequestSerializer,
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

            if mode == MODE_MANAGEMENT:
                # Management Only is now a flat $300/3-months fee (see
                # billing.plans) — not billed per asset. Still uses
                # get_admin_billable_asset_count (the ORIGINAL file size —
                # visible + locked), never get_admin_asset_count
                # (Freemium's visible-only cap of 5), so the 100-asset/
                # 1,000-vulnerability cap check below reflects the file's
                # real size, same reasoning as the old per-IP pricing had.
                asset_count = get_admin_billable_asset_count(str(request.user.id))
                vuln_count = get_admin_vulnerability_count(str(request.user.id))
                asset_source = "report"

                amount = calculate_management_amount()
                response_data = {
                    "plan": plan,
                    "mode": mode,
                    "billing_cycle": CYCLE_QUARTERLY,
                    "asset_count": asset_count,
                    "vulnerability_count": vuln_count,
                    "asset_cap": MANAGEMENT_ONLY_ASSET_CAP,
                    "vulnerability_cap": MANAGEMENT_ONLY_VULN_CAP,
                    # Informational only — going over either cap does NOT
                    # block this estimate or checkout (Management Only has
                    # no per-asset price to scale), it just means the next
                    # 3-month period needs its own $300 (see the pricing
                    # page's "Over the limit: Next 3-month period, +$300").
                    "over_limit": asset_count > MANAGEMENT_ONLY_ASSET_CAP or vuln_count > MANAGEMENT_ONLY_VULN_CAP,
                    "amount_due": str(amount),
                    "currency": "usd",
                }
                response_data.update(get_admin_asset_breakdown_counts(str(request.user.id)))
                return Response(response_data)

            # Management + Testing — scope-priced per asset type (IP/web
            # app/mobile app). Mode prefers the SAME uploaded report's
            # asset count when one already exists (an admin who already
            # uploaded a report just wants testing added on top), falling
            # back to the scope submitted via /api/admin/scope/create/ only
            # when there's no report at all — see
            # resolve_management_testing_asset_type_counts(). A report has
            # no type information, so that fallback counts everything as IP.
            counts, asset_source = resolve_management_testing_asset_type_counts(str(request.user.id))
            ip_count = counts["ip_count"]
            web_app_count = counts["web_app_count"]
            mobile_app_count = counts["mobile_app_count"]
            asset_count = ip_count + web_app_count + mobile_app_count

            if asset_count > PREMIUM_ASSET_CEILING:
                return Response({
                    "plan": plan,
                    "asset_count": asset_count,
                    "asset_ceiling": PREMIUM_ASSET_CEILING,
                    "over_ceiling": True,
                    "message": "More than 250 assets — this account must use the Custom plan.",
                })

            amount = calculate_management_testing_amount(ip_count, web_app_count, mobile_app_count)

            response_data = {
                "plan": plan,
                "mode": mode,
                "billing_cycle": CYCLE_SEMI_ANNUAL,
                "asset_count": asset_count,
                "ip_count": ip_count,
                "web_app_count": web_app_count,
                "mobile_app_count": mobile_app_count,
                "rate_per_ip": str(MANAGEMENT_TESTING_RATE_PER_IP),
                "rate_per_web_app": str(MANAGEMENT_TESTING_RATE_PER_WEB_APP),
                "rate_per_mobile_app": str(MANAGEMENT_TESTING_RATE_PER_MOBILE_APP),
                "amount_due": str(amount),
                "currency": "usd",
                "visible_asset_count": asset_count,
                "locked_asset_count": 0,
                "original_asset_count": asset_count,
                "billable_asset_count": asset_count,
                # Lets the frontend show "priced from your uploaded report"
                # vs "priced from your submitted scope".
                "asset_source": asset_source,
            }

            # Only genuinely nothing to price on — no uploaded report AND
            # no submitted scope. $0.00 alone would read as a real (wrong)
            # total, so flag it explicitly and point the frontend at the
            # endpoint that actually unblocks it.
            if asset_count == 0:
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

        # "scope me freemium plan aayega hi nai" — Freemium is never
        # available once an admin has gone through "Enter Your Scope" (file
        # upload or manual entry), regardless of what scope/create/'s own
        # plan_recommendation said — that's only a suggestion the frontend
        # could otherwise route around by calling this endpoint directly.
        # Does NOT affect the separate "Upload Report" flow (report-only
        # admins keep normal Freemium access, trimmed as usual).
        from scope.models import ScopeEntry
        if ScopeEntry.objects.filter(scope__admin_id=str(admin.id)).exists():
            return Response(
                {"detail": "Freemium plan is not available for scope-based submissions. Please choose Premium or Custom."},
                status=status.HTTP_400_BAD_REQUEST,
            )

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

        # Real bug report: after choosing Freemium on the WEBSITE, the
        # Teams admin-dashboard channel kept showing the stale "Choose
        # Your Plan" card indefinitely — same gap already fixed for
        # Premium/Custom (see stripe_service.py's checkout.session.completed
        # handler, which calls this exact same function). Freemium never
        # goes through Stripe checkout at all (it's free), so that fix
        # never covered this path. Call it here too so the "needs_plan"
        # card gets replaced with the real next step (Set Risk Criteria,
        # since _admin_has_selected_plan(admin) now resolves True) within
        # seconds of activating, matching what the website itself shows
        # immediately. No-ops quietly if this admin never connected Teams.
        try:
            from teams_bot.onboarding import post_onboarding_step
            post_onboarding_step(admin)
        except Exception:
            logger.exception(f"[Billing] Teams onboarding-card refresh failed for {admin.email} after Freemium activation")

        # Same gap, Slack side — Slack's "Choose Your Plan" prompt never
        # refreshed to "Set Risk Criteria" on its own either after
        # activating Freemium (Freemium skips Stripe checkout entirely, so
        # nothing else naturally revisits this admin's Slack channel).
        try:
            from users.views import _post_slack_onboarding_step
            _post_slack_onboarding_step(admin)
        except Exception:
            logger.exception(f"[Billing] Slack onboarding-message refresh failed for {admin.email} after Freemium activation")

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

        admin = request.user
        # Management Only bills on uploaded-report assets (flat fee — see
        # billing.plans, asset_count here is informational/display only,
        # not part of the Stripe price). Management + Testing prefers the
        # SAME report's asset count when one exists, falling back to the
        # submitted scope only when there's no report at all — see
        # resolve_management_testing_asset_type_counts(). Same billable-
        # count fix as PlanEstimateView — checkout must never create a
        # Stripe session for the Freemium visible-only count when
        # locked_hosts exist.
        ip_count = web_app_count = mobile_app_count = 0
        if mode == MODE_MANAGEMENT:
            asset_count = get_admin_billable_asset_count(str(admin.id))
            no_assets_detail = "Upload a report first — no assets found to bill for."
        else:
            counts, _asset_source = resolve_management_testing_asset_type_counts(str(admin.id))
            ip_count = counts["ip_count"]
            web_app_count = counts["web_app_count"]
            mobile_app_count = counts["mobile_app_count"]
            asset_count = ip_count + web_app_count + mobile_app_count
            no_assets_detail = "Upload a report or provide your scope first — no targets found to bill for."

        if asset_count > PREMIUM_ASSET_CEILING:
            return Response(
                {"detail": "More than 250 assets — use the Custom plan instead.", "asset_count": asset_count},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if asset_count == 0:
            return Response(
                {"detail": no_assets_detail},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            result = stripe_service.create_premium_checkout_session(
                admin, mode=mode, asset_count=asset_count,
                ip_count=ip_count, web_app_count=web_app_count, mobile_app_count=mobile_app_count,
                source=serializer.validated_data.get("source"),
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


class PremiumCheckoutConfirmView(APIView):
    """
    GET /api/admin/billing/checkout/confirm/?session_id=cs_test_...

    Fallback for the /billing/success page — verifies and finalizes a
    Stripe Checkout Session directly against Stripe's API, independent of
    whether the checkout.session.completed webhook has (yet, or ever)
    been delivered.

    Real bug this fixes: marking a Subscription "active" and unlocking
    any Freemium-trimmed assets (see stripe_service._on_checkout_completed
    / upload_report.views.unlock_freemium_hosts_for_admin) previously
    happened ONLY inside that one webhook handler — nothing else ever
    called it. A webhook is inherently best-effort: delayed delivery, a
    signing-secret mismatch between Stripe's test and live modes (an easy
    misconfiguration during exactly the kind of test-mode checkout this
    was reported against — session ids starting "cs_test_"), a firewall
    blip, or the endpoint briefly returning non-2xx all leave the
    Subscription row stuck at status="incomplete" indefinitely — Stripe
    does retry failed webhooks, but not forever, and there was no OTHER
    path to recover. From the admin's side this looked exactly like "I
    paid, Stripe redirected me to success, but my dashboard still shows
    the Freemium-limited 5 assets" — because is_freemium()/the asset
    trim genuinely never got told the subscription is active.

    Reuses stripe_service._on_checkout_completed's exact logic — it's
    idempotent (looks the Subscription up by stripe_checkout_session_id,
    same key the webhook uses, and unlock_freemium_hosts_for_admin is
    itself a safe no-op once locked_hosts is already empty) — so calling
    this after the webhook already succeeded just confirms the same
    state again rather than double-processing anything.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        session_id = request.query_params.get("session_id")
        if not session_id:
            return Response({"detail": "session_id is required"}, status=status.HTTP_400_BAD_REQUEST)

        sub = Subscription.objects.filter(stripe_checkout_session_id=session_id, admin=request.user).first()
        if not sub:
            return Response({"detail": "No subscription found for this checkout session."}, status=status.HTTP_404_NOT_FOUND)

        if sub.status != "active":
            try:
                import stripe
                stripe_session = stripe.checkout.Session.retrieve(session_id)
                session_dict = stripe_session.to_dict() if hasattr(stripe_session, "to_dict") else dict(stripe_session)
            except Exception as e:
                logger.warning(f"[Billing] checkout confirm: could not retrieve session {session_id} from Stripe: {e}")
                return Response({"detail": "Could not verify this session with Stripe yet — please try again shortly."}, status=status.HTTP_502_BAD_GATEWAY)

            # payment_status=="paid" is the reliable signal for a
            # subscription-mode Checkout Session (status=="complete" can
            # also mean "no payment required", not relevant here since
            # every plan this app sells is a paid subscription).
            if session_dict.get("payment_status") == "paid":
                stripe_service._on_checkout_completed(session_dict)
                sub.refresh_from_db()
            else:
                logger.info(f"[Billing] checkout confirm: session {session_id} not yet paid (payment_status={session_dict.get('payment_status')})")

        invoices = sub.invoices.order_by("-created_at")[:20]
        return Response({
            "subscription": SubscriptionSerializer(sub).data,
            "invoices": InvoiceSerializer(invoices, many=True).data,
            **get_admin_asset_breakdown_counts(str(request.user.id)),
        })


class CustomCheckoutView(APIView):
    """
    POST /api/admin/billing/checkout/custom/

    Custom tier (>250 assets) — mirrors PremiumCheckoutView's Stripe
    Checkout Session pattern exactly, but takes asset_count directly from
    the request body instead of computing it server-side from the admin's
    report/scope (the frontend already showed the admin this exact number
    on the Confirm & Pay screen before they got here). Real bug report:
    this endpoint never existed — the frontend's Custom "Confirm & Pay"
    screen called it and got a 404 right after the (separate, already-
    working) sales-lead capture succeeded, blocking every Custom-tier
    checkout.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = CustomCheckoutRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        asset_count = serializer.validated_data["asset_count"]

        if asset_count <= PREMIUM_ASSET_CEILING:
            return Response(
                {
                    "detail": f"{PREMIUM_ASSET_CEILING} or fewer assets — use the Premium plan instead.",
                    "asset_count": asset_count,
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        admin = request.user
        try:
            result = stripe_service.create_custom_checkout_session(
                admin, asset_count=asset_count, source=serializer.validated_data.get("source"),
            )
        except Exception as e:
            # Same error-surfacing convention as PremiumCheckoutView — pass
            # through Stripe's own human-readable reason instead of a
            # generic message wherever one exists.
            logger.exception(f"[Billing] Custom checkout session creation failed for {admin.email}")
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
        # Real request: an admin whose report was claimed via a magic-link
        # invite has zero Freemium restrictions backend-side (see
        # billing.enforcement._is_unlimited_admin), but the frontend has no
        # way to know that from this response alone — a magic-link admin
        # with no Subscription row would otherwise still get "subscription:
        # null" here and could keep showing Freemium upgrade prompts /
        # greyed-out buttons for actions the backend would actually allow.
        magic_link_unlimited = bool(getattr(request.user, "magic_link_unlimited", False))
        if not sub:
            return Response({"subscription": None, "magic_link_unlimited": magic_link_unlimited})

        invoices = sub.invoices.order_by("-created_at")[:20]
        return Response({
            "subscription": SubscriptionSerializer(sub).data,
            "invoices": InvoiceSerializer(invoices, many=True).data,
            "magic_link_unlimited": magic_link_unlimited,
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
    and, if they're on an active Premium/Custom Management subscription,
    updates the Stripe quantity with proration. Intended to be called both
    manually and from the upload_report pipeline after a report finishes
    parsing.

    Real gap: this only ever matched plan=PLAN_PREMIUM — a Custom-tier
    subscription (same mode="management"/billing_cycle="annual" shape,
    just uncapped) silently never got its Stripe quantity synced after a
    new report changed the asset count.
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
            admin=admin, plan__in=[PLAN_PREMIUM, PLAN_CUSTOM], mode=MODE_MANAGEMENT, status="active"
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
