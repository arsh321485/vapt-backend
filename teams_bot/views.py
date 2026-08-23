"""
The single webhook Bot Framework posts every Teams activity to (messages,
card-button clicks, member-added events, ...). Mirrors the role
SlackEventsView/SlackSlashCommandView play for Slack, but Teams funnels
everything through one endpoint instead of separate slash-command and
interactivity URLs.
"""
import logging

import requests
from django.http import HttpResponse
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .auth import verify_bot_framework_request, BotAuthError
from . import bot_api, cards, actions
from .conversation_store import save_conversation_reference, save_team_channel_reference, resolve_team_id_from_thread_id
from .onboarding import post_onboarding_step

logger = logging.getLogger(__name__)


class TeamsDashboardImageView(APIView):
    """
    GET /api/admin/users/teams/dashboard-image/?token=...&kind=...

    Public (token-gated, not login-gated) — Bot Framework fetches this URL
    directly when rendering an Adaptive Card Image element, with no auth
    headers of ours. Reuses the EXACT same HTML-building + PNG-rendering
    pipeline already built for Slack (users.views._build_dashboard_html /
    _build_team_performance_html / _dashboard_png_bytes / the shared
    signer) — same real bento-grid design (matches Microsoft
    -Admin/home.html), just resolved via ms_team_id instead of
    slack_team_id, and fetched in-process instead of over HTTP.
    """
    permission_classes = []
    authentication_classes = []

    def get(self, request):
        from django.contrib.auth import get_user_model
        from users.views import (
            _dashboard_image_signer, _dashboard_png_bytes, _build_dashboard_html,
            _build_team_performance_html, _build_all_assets_html, _build_all_vulns_html,
            _build_common_vulns_html,
        )

        token = request.query_params.get("token", "")
        try:
            team_id = _dashboard_image_signer().unsign(token, max_age=600)
        except Exception:
            return HttpResponse(status=403)

        User = get_user_model()
        admin = User.objects.filter(ms_team_id=team_id).first()
        if not admin:
            return HttpResponse(status=404)

        kind = request.query_params.get("kind", "dashboard")
        selector = ".dash"
        try:
            if kind == "teamperf":
                from admindashboard.views import AdminDistributionByTeamDetailAPIView
                _status, data = actions._call_view_in_process(AdminDistributionByTeamDetailAPIView, admin, method="get")
                html = _build_team_performance_html(data if isinstance(data, dict) else {})
            elif kind in ("assets", "allvulns"):
                from adminregister.views import LatestSuperAdminVulnerabilityRegisterAPIView
                _status, data = actions._call_view_in_process(LatestSuperAdminVulnerabilityRegisterAPIView, admin, method="get")
                rows = (data.get("rows") or []) if isinstance(data, dict) else []
                html = _build_all_assets_html(rows) if kind == "assets" else _build_all_vulns_html(rows)
                selector = ".page-card"
            elif kind == "commonvulns":
                from adminmitigationstrategy.views import MitigationStrategyByTeamAPIView
                from users.views import SlackSlashCommandView
                _status, data = actions._call_view_in_process(MitigationStrategyByTeamAPIView, admin, method="get")
                grouped = SlackSlashCommandView()._group_common_vulns_by_team(data if isinstance(data, dict) else {})
                team_key = request.query_params.get("team") or "config"
                html = _build_common_vulns_html(grouped, team_key=team_key)
                selector = ".page-card"
            else:
                from admindashboard.views import AdminDashboardSummaryAPIView
                _status, data = actions._call_view_in_process(AdminDashboardSummaryAPIView, admin, method="get")
                html = _build_dashboard_html(data if isinstance(data, dict) else {})
            png_bytes = _dashboard_png_bytes(html, selector=selector)
        except Exception:
            logger.exception(f"[TeamsDashboardImage] render failed for team_id={team_id} kind={kind}")
            return HttpResponse(status=500)

        return HttpResponse(png_bytes, content_type="image/png")


class TeamsReportDownloadView(APIView):
    """
    GET /api/admin/users/teams/report-download/?token=...&type=html|pdf

    Public (token-gated, not login-gated) — same reasoning as
    TeamsDashboardImageView: an Action.OpenUrl button opens this in the
    clicker's own default browser, which has no way to carry the admin's
    website login session, so this can't just link to the website's
    /reports page and rely on Content-Disposition there. Calls the SAME
    AdminReportDownloadAPIView Slack's own /downloadreport already uses,
    in-process, and passes its response straight through — the browser
    downloads the file directly off the response's Content-Disposition
    header, no extra page needed.
    """
    permission_classes = []
    authentication_classes = []

    def get(self, request):
        from django.contrib.auth import get_user_model
        from rest_framework.test import APIRequestFactory, force_authenticate
        from users.views import _dashboard_image_signer
        from adminregister.views import AdminReportDownloadAPIView

        token = request.query_params.get("token", "")
        try:
            team_id = _dashboard_image_signer().unsign(token, max_age=600)
        except Exception:
            return HttpResponse(status=403)

        User = get_user_model()
        admin = User.objects.filter(ms_team_id=team_id).first()
        if not admin:
            return HttpResponse(status=404)

        fmt = request.query_params.get("type") or "html"
        try:
            factory = APIRequestFactory()
            inner_request = factory.get("/internal/", {"type": fmt})
            force_authenticate(inner_request, user=admin)
            response = AdminReportDownloadAPIView.as_view()(inner_request)
            if hasattr(response, "render"):
                response.render()
        except Exception:
            logger.exception(f"[TeamsReportDownload] failed for team_id={team_id} type={fmt}")
            return HttpResponse(status=500)
        # Success returns a plain HttpResponse with Content-Disposition
        # already set (see AdminReportDownloadAPIView.get) — pass it
        # straight through so the browser downloads it as-is.
        return response


class TeamsBotMessagesView(APIView):
    """POST /api/admin/users/teams/bot/messages/ — set as the Messaging
    endpoint on the Azure Bot resource."""
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        try:
            verify_bot_framework_request(request.META.get("HTTP_AUTHORIZATION", ""))
        except BotAuthError as e:
            logger.warning(f"[TeamsBot] Rejected unauthenticated request: {e}")
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        activity = request.data
        activity_type = activity.get("type")
        logger.info(f"[TeamsBot] Activity received: type={activity_type} from={((activity.get('from') or {}).get('name'))}")
        if activity_type == "message":
            try:
                import json as _json
                logger.info(f"[TeamsBot] RAW activity dump: {_json.dumps(activity)[:4000]}")
            except Exception:
                logger.exception("[TeamsBot] raw dump failed")

        try:
            save_conversation_reference(activity)
        except Exception:
            logger.exception("[TeamsBot] save_conversation_reference failed")

        # Adaptive Card Action.Execute clicks arrive as a synchronous
        # "invoke" activity, not a fire-and-forget "message" — Bot
        # Framework expects the new card back in THIS HTTP response body,
        # not as a separate Connector API call, so this branches BEFORE
        # the generic 200 below (see _handle_adaptive_card_invoke).
        if activity_type == "invoke" and activity.get("name") == "adaptiveCard/action":
            return self._handle_adaptive_card_invoke(activity)

        try:
            if activity_type == "message":
                self._handle_message(activity)
            elif activity_type == "conversationUpdate":
                self._handle_conversation_update(activity)
            # Other activity types (typing, unrecognized invokes, etc.) —
            # nothing to do.
        except Exception:
            logger.exception(f"[TeamsBot] Error handling activity type={activity_type}")

        # Bot Framework only cares that we returned 2xx promptly — actual
        # replies go out as separate REST calls (reply_to_activity/send_activity),
        # not in this response body.
        return Response(status=status.HTTP_200_OK)

    def _handle_adaptive_card_invoke(self, activity: dict):
        """
        Handles Action.Execute clicks. The client is BLOCKED waiting on
        this response — returning the new card here (instead of firing a
        separate reply/update REST call, like the old Action.Submit path
        did) is what makes the swap instant with no visible flicker and,
        critically, none of the "Your response was sent to the app" toast
        Action.Submit always shows (that toast is inherent to its fire-
        and-forget flow; there's no card-JSON setting that suppresses it
        while staying on Action.Submit — this invoke-response pattern is
        Teams' own documented fix).
        """
        value = activity.get("value") or {}
        action = value.get("action") or {}
        data = action.get("data") or {}

        admin, team_id = self._resolve_admin(activity)
        if not admin:
            card = cards.text_result_card(
                "🔒 Not linked",
                "This Teams workspace isn't linked to a VaptFix admin account yet — please log in from the website first.",
            )
        else:
            conversation_id = (activity.get("conversation") or {}).get("id")
            try:
                card = actions.handle_card_action(admin, team_id, conversation_id, data)
            except Exception:
                logger.exception("[TeamsBot] handle_card_action failed (invoke)")
                card = cards.text_result_card("❌ Something went wrong", "Please try that again.")

            # Keep the tracked "active" message id in sync too — other,
            # unrelated proactive pushes (post_onboarding_step after a
            # report upload, etc.) still edit/replace via that id.
            try:
                target_id = activity.get("replyToId") or activity.get("id")
                if team_id and target_id:
                    from .conversation_store import set_active_message_id
                    set_active_message_id(team_id, target_id)
            except Exception:
                logger.exception("[TeamsBot] set_active_message_id (invoke) failed")

        return Response(
            {"statusCode": 200, "type": "application/vnd.microsoft.card.adaptive", "value": card},
            status=status.HTTP_200_OK,
        )

    def _resolve_admin(self, activity: dict):
        # Bot Framework's channelData.team.id is a CONVERSATION/thread id
        # (format "19:...@thread.tacv2" — same shape as a channel id), NOT
        # the AAD Group id Microsoft Graph uses for /teams/{id} — the two
        # are entirely different values for the same team. Our DB's
        # ms_team_id is set from the Graph-side id (see auto_create_vaptfix_team
        # / CreateTeamView), so aadGroupId is the one that actually matches
        # it. Using team.id here silently never found the admin (confirmed
        # in prod logs: "bot added to team_id=19:Egr...@thread.tacv2 but no
        # admin has this ms_team_id yet").
        team = (activity.get("channelData") or {}).get("team") or {}
        thread_id = team.get("id")
        team_id = team.get("aadGroupId")
        if not team_id and thread_id:
            # Confirmed via real prod data: plain "message" activities
            # (typed text, Action.Submit clicks) never carry aadGroupId,
            # only the thread-id form — resolve it via whatever
            # conversationUpdate already recorded for this thread.
            team_id = resolve_team_id_from_thread_id(thread_id)
        if not team_id:
            team_id = thread_id
        if not team_id:
            return None, None
        from django.contrib.auth import get_user_model
        User = get_user_model()
        return User.objects.filter(ms_team_id=team_id).first(), team_id

    def _handle_message(self, activity: dict):
        service_url = activity.get("serviceUrl")
        conversation_id = (activity.get("conversation") or {}).get("id")
        activity_id = activity.get("id")

        logger.info(
            f"[TeamsBot] _handle_message: has_value={bool(activity.get('value'))} "
            f"has_attachments={bool(activity.get('attachments'))} "
            f"attachment_layout={activity.get('attachmentLayout')} "
            f"keys={sorted(activity.keys())}"
        )

        # Adaptive Card Action.Submit lands here with `value` populated and
        # `text` usually empty. `replyToId` is the id of the message that
        # CONTAINED the card that was clicked — editing THAT message in
        # place (PUT) is the clean, Slack-like behavior (zero visible
        # trace, no "message deleted" tombstone) and is tried first. It
        # only falls back to delete-old+send-new (onboarding.
        # replace_active_card) when the edit itself fails — e.g. a click
        # landing on a genuinely stale/orphaned card left over from before
        # this tracking existed — so a bad click still self-heals instead
        # of leaving two live cards, without paying the tombstone cost on
        # every normal click.
        if activity.get("value"):
            admin, team_id = self._resolve_admin(activity)
            if not admin:
                bot_api.reply_to_activity(
                    service_url, conversation_id, activity_id,
                    bot_api.text_message("This Teams workspace isn't linked to a VaptFix admin account yet — please log in from the website first."),
                )
                return
            try:
                card = actions.handle_card_action(admin, team_id, conversation_id, activity.get("value") or {})
            except Exception:
                logger.exception("[TeamsBot] handle_card_action failed")
                card = cards.text_result_card("❌ Something went wrong", "Please try that again.")

            target_id = activity.get("replyToId")
            updated_ok = False
            if target_id:
                resp = bot_api.update_activity(service_url, conversation_id, target_id, bot_api.card_message(card))
                updated_ok = resp is not None and resp.status_code < 300
                logger.info(
                    f"[TeamsBot] update_activity target_id={target_id} "
                    f"status={getattr(resp, 'status_code', None)} updated_ok={updated_ok}"
                )
            else:
                logger.info("[TeamsBot] no replyToId on this activity — skipping update_activity, going straight to replace_active_card")
            if updated_ok:
                from .conversation_store import set_active_message_id
                set_active_message_id(team_id, target_id)
            else:
                logger.info(f"[TeamsBot] falling back to replace_active_card (delete+resend) for team_id={team_id}")
                from .onboarding import replace_active_card
                new_message_id = replace_active_card(team_id, card)
                logger.info(f"[TeamsBot] replace_active_card returned new_message_id={new_message_id}")
                if new_message_id is None:
                    # No tracked channel reference yet (shouldn't normally
                    # happen once the bot's been added) — fall back to a
                    # plain reply so the click never just silently does
                    # nothing.
                    bot_api.reply_to_activity(service_url, conversation_id, activity_id, bot_api.card_message(card))
            return

        # A file the admin attached in response to "Attach your file" —
        # only relevant if we set a pending-upload intent for this
        # conversation via the Upload Report / CSV File buttons.
        attachments = activity.get("attachments") or []
        logger.info(
            f"[TeamsBot] message activity: attachments_count={len(attachments)} "
            f"content_types={[a.get('contentType') for a in attachments]} "
            f"has_text={bool((activity.get('text') or '').strip())}"
        )
        if attachments:
            self._handle_attachment(activity, service_url, conversation_id, activity_id, attachments)
            return

        text = (activity.get("text") or "").strip()
        # Teams prefixes @mentions into the text (e.g. "<at>VaptFix</at> hello") —
        # strip a leading mention tag if present so command matching is clean.
        if text.startswith("<at>"):
            close = text.find("</at>")
            if close != -1:
                text = text[close + len("</at>"):].strip()

        logger.info(f"[TeamsBot] Message text: {text!r}")

        reply_text = f"👋 VaptFix bot is alive. You said: \"{text}\"" if text else "👋 VaptFix bot is alive."
        bot_api.reply_to_activity(
            service_url, conversation_id, activity_id,
            bot_api.text_message(reply_text),
        )

    def _handle_attachment(self, activity, service_url, conversation_id, activity_id, attachments):
        # Resolve admin/team FIRST — the pending-upload flag is keyed by
        # team_id (see actions.set_pending_upload_intent), not
        # conversation_id, since a channel post and a reply inside its own
        # thread get different conversation ids in Teams.
        admin, team_id = self._resolve_admin(activity)
        logger.info(f"[TeamsBot] attachment: resolved admin={getattr(admin, 'email', None)} team_id={team_id}")
        if not admin:
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message("This Teams workspace isn't linked to a VaptFix admin account yet."),
            )
            return

        purpose = actions.pop_pending_upload_intent(team_id)
        logger.info(f"[TeamsBot] attachment: pending_upload_intent={purpose!r}")
        if not purpose:
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message("Got your file, but I wasn't expecting one right now — click \"Upload Report\" or \"CSV File\" first, then attach it."),
            )
            return

        # The "text/html" attachment Teams adds for an @mention has `content`
        # as a plain HTML string, not a dict — .get("downloadUrl") on that
        # crashed (confirmed in prod: "Error handling activity type=message"
        # right after this line). Only look for a real download URL on
        # attachments that actually carry one; @mention-only attachments
        # never do, so a mention with no real file correctly falls through
        # to "no file found" below instead of crashing.
        att, download_url, file_name = None, None, None
        for a in attachments:
            if (a.get("contentType") or "") == "text/html":
                continue
            content = a.get("content")
            url = content.get("downloadUrl") if isinstance(content, dict) else None
            url = url or a.get("contentUrl")
            if url:
                att, download_url, file_name = a, url, (a.get("name") or "upload")
                break
        logger.info(f"[TeamsBot] attachment: file_name={file_name!r} contentType={(att or {}).get('contentType')!r} download_url_set={bool(download_url)}")
        if not download_url:
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message("❌ I didn't see a file attached to that message — please attach the file (paperclip icon) and send again."),
            )
            return

        try:
            file_resp = requests.get(download_url, timeout=30)
            file_resp.raise_for_status()
            file_bytes = file_resp.content
            logger.info(f"[TeamsBot] attachment: downloaded {len(file_bytes)} bytes")
        except Exception:
            logger.exception("[TeamsBot] attachment download failed")
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message(f"❌ Could not download \"{file_name}\" — please try attaching it again."),
            )
            return

        try:
            if purpose == "report":
                status_code, data = actions.submit_report_file(admin, file_name, file_bytes)
            else:
                status_code, data = actions.submit_scope_csv(admin, file_name, file_bytes)
        except Exception:
            logger.exception(f"[TeamsBot] submit_{purpose} failed")
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message(f"❌ Something went wrong processing \"{file_name}\" — please try again."),
            )
            return

        logger.info(f"[TeamsBot] attachment: submit_{purpose} status={status_code} data={data}")
        if status_code >= 300:
            reason = (data or {}).get("message") or (data or {}).get("detail") or "Could not process that file."
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message(f"❌ {reason}"),
            )
            return

        noun = "report" if purpose == "report" else "scope"
        bot_api.reply_to_activity(
            service_url, conversation_id, activity_id,
            bot_api.text_message(f"✅ \"{file_name}\" received — your {noun} is being processed. I'll post here once it's ready."),
        )

        # Same follow-up the website/Slack flow does after an upload: once
        # processing catches up, the next real state is either the
        # risk-criteria prompt (first-ever report) or the completed navbar.
        try:
            post_onboarding_step(admin, team_id=team_id)
        except Exception:
            logger.exception("[TeamsBot] post_onboarding_step after upload failed")

    def _handle_conversation_update(self, activity: dict):
        """
        Fires when the bot is added to a team/channel, or a member
        joins/leaves. A team-scope add (bot installed on the whole team) is
        what puts the bot into the renamed 'General' channel — i.e. the
        'vaptfix admin dashboard' channel — so that's the trigger for the
        very first welcome/onboarding card.
        """
        members_added = activity.get("membersAdded") or []
        bot_id = (activity.get("recipient") or {}).get("id")
        bot_was_added = any(m.get("id") == bot_id for m in members_added)
        if not bot_was_added:
            return

        logger.info("[TeamsBot] Bot was added to a conversation/team.")
        team = (activity.get("channelData") or {}).get("team") or {}
        team_id = team.get("id")
        if not team_id:
            return

        try:
            save_team_channel_reference(activity)
        except Exception:
            logger.exception("[TeamsBot] save_team_channel_reference failed")

        admin, _ = self._resolve_admin(activity)
        if not admin:
            logger.info(f"[TeamsBot] bot added to team_id={team_id} but no admin has this ms_team_id yet")
            return

        try:
            post_onboarding_step(admin, team_id=team_id)
        except Exception:
            logger.exception("[TeamsBot] post_onboarding_step on team add failed")
