"""
Posts the right onboarding step into a team's admin-dashboard channel —
a dedicated standard channel named "vaptfix admin dashboard" (see
users.views.ADMIN_DASHBOARD_CHANNEL_NAME / _ensure_admin_dashboard_channel;
General is left as "General" now, unrelated to this — a genuinely private
version of this channel was tried and confirmed not to work reliably yet)
— the Teams counterpart of users/views.py's _post_admin_onboarding_message.
Reuses the SAME state function Slack and the website already use, so all
three surfaces can never drift out of sync on what "ready" means.
"""
import logging

from . import bot_api, cards
from .conversation_store import get_team_channel_reference, set_active_message_id, claim_post_slot, release_post_slot

logger = logging.getLogger(__name__)


def _resolve_admin_by_team_id(team_id):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    return User.objects.filter(ms_team_id=team_id).first()


def replace_active_card(team_id, card):
    """
    Deletes the previously-tracked "live" card for this team's
    admin-dashboard channel (if any) and posts `card` as a fresh message in
    its place, tracking the new message id for next time. This is the
    single source of truth for "only one card lives in the channel at a
    time" — used for onboarding state transitions AND for every nav/action
    card click (see TeamsBotMessagesView._handle_message).

    Confirmed via real production activity dumps that Bot Framework's
    update-activity PUT (editing a message "in place") does NOT reliably
    preserve a stable clickable identity in Teams — consecutive clicks on
    what looked like the same card kept arriving with different
    `replyToId` values, meaning every "edit" was effectively spawning a new
    independently-clickable message anyway. Delete-then-send is what
    actually keeps the channel down to one live card, since it doesn't
    depend on Teams preserving that identity across edits at all.

    Returns the new message id (or None if the channel reference isn't
    known yet / the send failed / a concurrent caller already claimed
    this post — see claim_post_slot).
    """
    ref = get_team_channel_reference(team_id)
    if not ref:
        logger.info(f"[TeamsOnboarding] no stored admin-dashboard channel reference for team_id={team_id} — bot not added yet")
        return None

    # Confirmed via real testing: on a fresh install, the synchronous
    # login-time repoint-and-post and the async webhook-driven one both
    # end up calling this for the same card, producing two identical
    # posts. Claim exclusivity first; if someone else already holds it,
    # skip rather than post a duplicate.
    if not claim_post_slot(team_id):
        logger.info(f"[TeamsOnboarding] replace_active_card: another post already in flight for team_id={team_id} — skipping duplicate")
        return None

    try:
        old_message_id = ref.get("active_message_id")
        logger.info(f"[TeamsOnboarding] replace_active_card: old_message_id={old_message_id}")
        if old_message_id:
            del_resp = bot_api.delete_activity(ref["service_url"], ref["conversation_id"], old_message_id)
            logger.info(f"[TeamsOnboarding] delete_activity({old_message_id}) -> {getattr(del_resp, 'status_code', None)}")

        resp = bot_api.send_activity(
            ref["service_url"], ref["conversation_id"],
            bot_api.card_message(card),
        )
        logger.info(f"[TeamsOnboarding] send_activity -> status={getattr(resp, 'status_code', None)} body={getattr(resp, 'text', '')[:300]}")
        try:
            new_message_id = resp.json().get("id") if resp is not None else None
        except Exception:
            new_message_id = None
        if new_message_id:
            set_active_message_id(team_id, new_message_id)
        return new_message_id
    finally:
        release_post_slot(team_id)


def post_onboarding_step(admin, team_id=None, force_state=None):
    """
    Posts whichever onboarding card matches the admin's current state
    ("no_report" -> welcome card, "needs_risk_criteria" -> risk-criteria
    prompt, "ready" -> the completed navbar) into the stored admin-dashboard
    channel conversation for this admin's team, replacing whatever card is
    currently live there (see replace_active_card). No-op (logged, not
    raised) if the bot hasn't been added to that team yet.

    `force_state` lets callers that already know the transition (e.g.
    "risk criteria was just submitted, so definitely show the navbar now")
    skip the extra Mongo/RiskCriteria round trip _get_admin_onboarding_state
    would otherwise do.
    """
    team_id = team_id or getattr(admin, "ms_team_id", None)
    if not team_id:
        logger.info(f"[TeamsOnboarding] admin={getattr(admin, 'email', None)} has no ms_team_id — skipping")
        return None

    if force_state:
        state = force_state
    else:
        from users.views import _get_admin_onboarding_state
        state = _get_admin_onboarding_state(admin)

    card = build_state_card(admin, team_id, state)
    new_message_id = replace_active_card(team_id, card)
    logger.info(f"[TeamsOnboarding] Posted state={state} card into team_id={team_id} (new_message_id={new_message_id})")
    return state


def build_state_card(admin, team_id, state):
    """The card content for a given onboarding state, WITHOUT posting it
    anywhere — factored out of post_onboarding_step so a caller that's
    about to return this same content as its own action response (e.g.
    actions.submit_risk_criteria) can do that directly instead of also
    triggering a separate proactive post here. Confirmed real bug: doing
    both raced two different "replace the active card" operations against
    each other — post_onboarding_step's own send would win, then the
    action handler's own response (a generic "Loading your dashboard…"
    placeholder) would immediately delete THAT and take over the active
    slot instead, permanently — the placeholder had nothing further ever
    update it, so it looked stuck."""
    if state == "no_report":
        return cards.welcome_card()
    if state == "needs_risk_criteria":
        return cards.risk_criteria_prompt_card()
    # Home tab's real content, not just the bare nav bar — confirmed via
    # real feedback that posting just the nav row (needing an extra click
    # on "Home" to see anything) looked broken/empty. Same image-rendering
    # call actions._handle_nav's nav_home branch uses; imported lazily to
    # avoid a circular import (actions.py imports from this module).
    try:
        home_body = cards.dashboard_image_card_body(team_id, kind="dashboard", title="VaptFix Admin Dashboard")
    except Exception:
        logger.exception("[TeamsOnboarding] dashboard image body failed, falling back to text summary")
        from . import actions as _actions
        home_body = _actions._home_summary_body(admin)
    return cards.nav_buttons_card(active_action_id="nav_home", extra_body=home_body)


def post_onboarding_for_team_id(team_id, force_state=None):
    admin = _resolve_admin_by_team_id(team_id)
    if not admin:
        logger.info(f"[TeamsOnboarding] no admin found with ms_team_id={team_id}")
        return None
    return post_onboarding_step(admin, team_id=team_id, force_state=force_state)


def watch_report_and_post_onboarding(admin, report_ids, max_wait_seconds=1800, poll_interval=6):
    """
    Teams counterpart of users/views.py's _watch_reports_and_post_onboarding
    — an admin uploading via the website's /admin-upload-report page (which
    is what Teams' "Upload Report"/"CSV File" buttons redirect to, since
    Teams channel bots can't receive files directly) should still see the
    risk-criteria prompt land automatically in their Teams admin-dashboard
    channel once mitigation cards are ready, not just on the website.
    Meant to run in a background thread (see the call in
    upload_report/views.py's notify_admin_report_uploaded hook).
    """
    import time as _time
    import requests
    from django.conf import settings
    from rest_framework_simplejwt.tokens import RefreshToken
    from .conversation_store import claim_report_watch, release_report_watch

    if not getattr(admin, "ms_team_id", None):
        return

    report_ids = [str(r) for r in (report_ids or []) if r]
    if not report_ids:
        return

    team_id = admin.ms_team_id
    # Confirmed via real testing: the risk-criteria prompt was appearing
    # twice — a duplicated/retried upload request starts two of these
    # background watchers for the same team, each polling independently
    # and each eventually calling post_onboarding_step once cards are
    # ready. claim_post_slot alone doesn't catch this since the two calls
    # land seconds-to-minutes apart, not concurrently. Claim exclusivity
    # for the whole watch up front; a second watcher for the same team
    # sees one already in flight and returns immediately instead of
    # polling and posting a duplicate.
    if not claim_report_watch(team_id, stale_after_seconds=max_wait_seconds + 120):
        logger.info(f"[TeamsOnboarding] a report-watch is already in flight for team_id={team_id} — skipping duplicate watcher")
        return

    try:
        backend = getattr(settings, "VAPTFIX_BACKEND_URL", "https://vaptbackend.secureitlab.com")
        token = str(RefreshToken.for_user(admin).access_token)
        headers = {"Authorization": f"Bearer {token}"}

        def _all_complete():
            for rid in report_ids:
                try:
                    resp = requests.get(
                        f"{backend}/api/admin/upload_report/upload/{rid}/status/",
                        headers=headers, timeout=15,
                    )
                    data = resp.json()
                except Exception:
                    logger.exception(f"[TeamsOnboarding] status check failed for report_id={rid}")
                    return False
                if not data.get("cards_generation_complete"):
                    return False
            return True

        deadline = _time.time() + max_wait_seconds
        try:
            while _time.time() < deadline:
                if _all_complete():
                    break
                _time.sleep(poll_interval)
        except Exception:
            logger.exception(f"[TeamsOnboarding] polling failed for report_ids={report_ids}")

        try:
            post_onboarding_step(admin)
        except Exception:
            logger.exception("[TeamsOnboarding] failed to post onboarding after upload watch")
    finally:
        release_report_watch(team_id)
