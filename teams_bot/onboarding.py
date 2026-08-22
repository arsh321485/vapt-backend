"""
Posts the right onboarding step into a team's admin-dashboard channel
("vaptfix admin dashboard" display name / the renamed General channel) —
the Teams counterpart of users/views.py's _post_admin_onboarding_message.
Reuses the SAME state function Slack and the website already use, so all
three surfaces can never drift out of sync on what "ready" means.
"""
import logging

from . import bot_api, cards
from .conversation_store import get_team_channel_reference

logger = logging.getLogger(__name__)


def _resolve_admin_by_team_id(team_id):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    return User.objects.filter(ms_team_id=team_id).first()


def post_onboarding_step(admin, team_id=None, force_state=None):
    """
    Posts whichever onboarding card matches the admin's current state
    ("no_report" -> welcome card, "needs_risk_criteria" -> risk-criteria
    prompt, "ready" -> the completed navbar) into the stored admin-dashboard
    channel conversation for this admin's team. No-op (logged, not raised)
    if the bot hasn't been added to that team yet — nothing has been saved
    to proactively message into.

    `force_state` lets callers that already know the transition (e.g.
    "risk criteria was just submitted, so definitely show the navbar now")
    skip the extra Mongo/RiskCriteria round trip _get_admin_onboarding_state
    would otherwise do.
    """
    team_id = team_id or getattr(admin, "ms_team_id", None)
    if not team_id:
        logger.info(f"[TeamsOnboarding] admin={getattr(admin, 'email', None)} has no ms_team_id — skipping")
        return None

    ref = get_team_channel_reference(team_id)
    if not ref:
        logger.info(f"[TeamsOnboarding] no stored admin-dashboard channel reference for team_id={team_id} — bot not added yet")
        return None

    if force_state:
        state = force_state
    else:
        from users.views import _get_admin_onboarding_state
        state = _get_admin_onboarding_state(admin)

    if state == "no_report":
        card = cards.welcome_card()
    elif state == "needs_risk_criteria":
        card = cards.risk_criteria_prompt_card()
    else:
        card = cards.nav_buttons_card(active_action_id="nav_home")

    bot_api.send_activity(
        ref["service_url"], ref["conversation_id"],
        bot_api.card_message(card),
    )
    logger.info(f"[TeamsOnboarding] Posted state={state} card into team_id={team_id}")
    return state


def post_onboarding_for_team_id(team_id, force_state=None):
    admin = _resolve_admin_by_team_id(team_id)
    if not admin:
        logger.info(f"[TeamsOnboarding] no admin found with ms_team_id={team_id}")
        return None
    return post_onboarding_step(admin, team_id=team_id, force_state=force_state)
