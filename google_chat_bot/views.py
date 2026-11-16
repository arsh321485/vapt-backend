"""
POST /api/admin/users/google-chat/bot/messages/ — the HTTP endpoint
configured as the Chat app's "App URL" (Google Cloud Console -> Google
Chat API -> Configuration). Mirrors teams_bot.views.TeamsBotMessagesView's
structure: verify the request, dispatch by event type, acknowledge fast.

Only the bare ADDED_TO_SPACE / MESSAGE / CARD_CLICKED / REMOVED_FROM_SPACE
wiring is here so far — the actual onboarding/tab card bodies are still
TODO (see google_chat_bot/cards.py's own docstring). This lays down the
skeleton they'll plug into next, same shape as teams_bot/views.py grew.
"""
import logging

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status

from .auth import verify_chat_request, BotAuthError
from .space_store import save_space_reference

logger = logging.getLogger(__name__)


class GoogleChatBotMessagesView(APIView):
    """POST /api/admin/users/google-chat/bot/messages/ — set as the Chat
    app's App URL in Google Cloud Console."""
    permission_classes = []
    authentication_classes = []

    def post(self, request):
        try:
            verify_chat_request(request.META.get("HTTP_AUTHORIZATION", ""))
        except BotAuthError as e:
            logger.warning(f"[GoogleChatBot] Rejected unauthenticated request: {e}")
            return Response(status=status.HTTP_401_UNAUTHORIZED)

        event = request.data or {}
        event_type = event.get("type")
        space = event.get("space") or {}
        logger.info(f"[GoogleChatBot] Event received: type={event_type} space={space.get('name')}")

        try:
            save_space_reference(space.get("name"), space.get("displayName"), space.get("type"))
        except Exception:
            logger.exception("[GoogleChatBot] save_space_reference failed")

        try:
            # ADDED_TO_SPACE/MESSAGE/CARD_CLICKED all expect their reply
            # straight back in THIS HTTP response body (synchronous) —
            # same constraint as Teams' invoke-response pattern for card
            # actions (see teams_bot.views._handle_adaptive_card_invoke).
            if event_type == "ADDED_TO_SPACE":
                return Response(self._handle_added_to_space(event))
            elif event_type == "MESSAGE":
                return Response(self._handle_message(event))
            elif event_type == "CARD_CLICKED":
                return Response(self._handle_card_clicked(event))
            elif event_type == "REMOVED_FROM_SPACE":
                self._handle_removed_from_space(event)
            # Other event types — nothing to do yet.
        except Exception:
            logger.exception(f"[GoogleChatBot] Error handling event type={event_type}")

        return Response(status=status.HTTP_200_OK)

    def _handle_added_to_space(self, event: dict) -> dict:
        space = event.get("space") or {}
        display_name = space.get("displayName") or "there"
        return {
            "text": f"\U0001f44b VaptFix added to {display_name}. Onboarding is still being wired up — more soon.",
        }

    def _handle_message(self, event: dict) -> dict:
        return {
            "text": "VaptFix bot received your message. Interactive tabs are still being wired up — more soon.",
        }

    def _handle_card_clicked(self, event: dict) -> dict:
        action = event.get("action") or {}
        logger.info(f"[GoogleChatBot] Card click: {action.get('actionMethodName')} params={action.get('parameters')}")
        return {
            "actionResponse": {"type": "UPDATE_MESSAGE"},
            "text": "Handling for this action is still being wired up.",
        }

    def _handle_removed_from_space(self, event: dict):
        space = event.get("space") or {}
        logger.info(f"[GoogleChatBot] Bot removed from space {space.get('name')}")
