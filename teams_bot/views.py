"""
The single webhook Bot Framework posts every Teams activity to (messages,
card-button clicks, member-added events, ...). Mirrors the role
SlackEventsView/SlackSlashCommandView play for Slack, but Teams funnels
everything through one endpoint instead of separate slash-command and
interactivity URLs.
"""
import logging

import requests
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .auth import verify_bot_framework_request, BotAuthError
from . import bot_api, cards, actions
from .conversation_store import save_conversation_reference, save_team_channel_reference, resolve_team_id_from_thread_id
from .onboarding import post_onboarding_step

logger = logging.getLogger(__name__)


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

        try:
            save_conversation_reference(activity)
        except Exception:
            logger.exception("[TeamsBot] save_conversation_reference failed")

        try:
            if activity_type == "message":
                self._handle_message(activity)
            elif activity_type == "conversationUpdate":
                self._handle_conversation_update(activity)
            # Other activity types (typing, invoke, etc.) — Phase 2+.
        except Exception:
            logger.exception(f"[TeamsBot] Error handling activity type={activity_type}")

        # Bot Framework only cares that we returned 2xx promptly — actual
        # replies go out as separate REST calls (reply_to_activity/send_activity),
        # not in this response body.
        return Response(status=status.HTTP_200_OK)

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

        # Adaptive Card Action.Submit lands here with `value` populated and
        # `text` usually empty.
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
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.card_message(card),
            )
            return

        # A file the admin attached in response to "Attach your file" —
        # only relevant if we set a pending-upload intent for this
        # conversation via the Upload Report / CSV File buttons.
        attachments = activity.get("attachments") or []
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
        if not admin:
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message("This Teams workspace isn't linked to a VaptFix admin account yet."),
            )
            return

        purpose = actions.pop_pending_upload_intent(team_id)
        if not purpose:
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message("Got your file, but I wasn't expecting one right now — click \"Upload Report\" or \"CSV File\" first, then attach it."),
            )
            return

        att = next((a for a in attachments if a.get("contentType") != "text/html"), attachments[0])
        file_name = att.get("name") or "upload"
        download_url = (att.get("content") or {}).get("downloadUrl") or att.get("contentUrl")
        if not download_url:
            bot_api.reply_to_activity(
                service_url, conversation_id, activity_id,
                bot_api.text_message(f"❌ Could not read the attached file \"{file_name}\" — please try attaching it again."),
            )
            return

        try:
            file_resp = requests.get(download_url, timeout=30)
            file_resp.raise_for_status()
            file_bytes = file_resp.content
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
