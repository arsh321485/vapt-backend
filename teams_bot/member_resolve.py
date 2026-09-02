"""
Identity + team-channel resolution for the "user side" (regular team
member) Teams cards — the admin-side equivalent of this lives inline in
TeamsBotMessagesView._resolve_admin, but a regular member additionally
needs: (a) their own UserDetail/User (not the admin's), and (b) which of
the admin's 4 team channels the activity came from, since that's what
decides whose/which team's data to show — mirrors Slack's channel-name ->
team-name gate (see users.views._authorize_channel_access /
SlackSlashCommandView._get_team_vulns's "not_member_of_team" check).
"""
import logging

from . import conversation_store

logger = logging.getLogger(__name__)


def _extract_channel_id(activity: dict):
    """
    The specific Teams channel (not the admin's whole Team) this activity
    happened in. NOT activity["channelId"] (that's the Bot Framework
    CHANNEL OF SERVICE, always the literal string "msteams" — a different,
    confusingly-named concept, see conversation_store.save_conversation_reference).
    channelData.channel.id is the real one; it's the same value as the
    Graph channel's own "id" field (see conversation_store.
    save_admin_dashboard_channel_reference's docstring), and for a plain
    channel post is also just activity.conversation.id — kept as a
    fallback for activity shapes that omit channelData.channel.
    """
    channel_data = activity.get("channelData") or {}
    channel_id = (channel_data.get("channel") or {}).get("id")
    if channel_id:
        return channel_id
    return (activity.get("conversation") or {}).get("id")


def _self_heal_team_name(team_id, channel_id):
    """
    Cache-miss fallback — covers teams whose 4 channels were created
    before save_sub_channel_team existed. One live Graph call, then
    cached for every future lookup (see conversation_store.save_sub_channel_team).
    """
    from users.views import _get_graph_app_token, _get_team_channels, TEAMS_CHANNEL_DISPLAY_NAMES

    token = _get_graph_app_token()
    if not token:
        return None
    headers = {"Authorization": f"Bearer {token}"}
    channels = _get_team_channels(team_id, headers)
    display_to_team = {v.strip().lower(): k for k, v in TEAMS_CHANNEL_DISPLAY_NAMES.items()}
    for ch in channels:
        if ch.get("id") != channel_id:
            continue
        display_name = (ch.get("displayName") or "").strip().lower()
        team_name = display_to_team.get(display_name)
        if team_name and team_name != "General":
            try:
                conversation_store.save_sub_channel_team(team_id, channel_id, team_name)
            except Exception:
                logger.exception("[TeamsBot] save_sub_channel_team (self-heal) failed")
            return team_name
        return None
    return None


def is_member_sender(activity: dict, admin) -> bool:
    """
    True if this activity's sender is a genuine TEAM MEMBER of `admin`'s
    org (a UserDetail.ms_teams_member_id match) rather than the admin
    themself or an unresolvable identity (the bot's own service account on
    conversationUpdate, etc.) — the single gate deciding whether an
    activity routes to user_actions (this new user-side path) or the
    existing admin-side dispatch in actions.py, so admin's own clicks/
    messages are completely unaffected by any of this. Deliberately
    conservative: any doubt (no aad id on the activity, no admin resolved
    yet) falls back to False, i.e. the existing admin-side handling, which
    is exactly today's behavior and known-safe.
    """
    if not admin:
        return False
    sender_aad_id = (activity.get("from") or {}).get("aadObjectId")
    if not sender_aad_id:
        return False
    # The admin's OWN aad id lives on a different field/model
    # (User.ms_teams_object_id) than a member's (UserDetail.
    # ms_teams_member_id) — never the same field, but checked explicitly
    # anyway so an admin clicking their own card is never misrouted even
    # if some future data quirk ever put a matching UserDetail row in too.
    if sender_aad_id == getattr(admin, "ms_teams_object_id", None):
        return False
    from users_details.models import UserDetail
    matched = UserDetail.objects.filter(admin=admin, ms_teams_member_id=sender_aad_id).exists()
    if not matched:
        # Diagnostic only — helps tell apart "this aad id isn't recorded
        # anywhere yet" from "it's recorded, but under a different admin
        # FK than the one _resolve_admin found" (e.g. the duplicate-admin-
        # account issue investigated earlier this session), since those
        # need very different fixes.
        any_admin_match = UserDetail.objects.filter(ms_teams_member_id=sender_aad_id).first()
        logger.info(
            f"[TeamsBot] is_member_sender: no match for aad_id={sender_aad_id} under admin.id={getattr(admin, 'id', None)} "
            f"(admin.email={getattr(admin, 'email', None)}) — "
            f"any_admin_match={'admin_id=' + str(any_admin_match.admin_id) + ' email=' + str(any_admin_match.email) if any_admin_match else 'NONE'}"
        )
    return matched


def resolve_member_context(activity: dict, admin, team_id: str):
    """
    `admin`/`team_id` are whatever TeamsBotMessagesView._resolve_admin
    already returned for this activity (same resolution regular-member
    handling piggybacks on, since both admin and member cards live in the
    same Team). Returns a dict:

      {"member_detail": UserDetail|None, "member_user": User|None,
       "team_name": str|None, "channel_id": str|None, "error": str|None}

    `error`, when set, is a plain-text message ready to send back
    as-is — callers should stop and show it instead of proceeding.
    Never raises — any lookup failure just becomes an `error` string.
    """
    result = {"member_detail": None, "member_user": None, "team_name": None, "channel_id": None, "error": None}
    if not admin:
        result["error"] = "This Teams workspace isn't linked to a VaptFix admin account yet — please log in from the website first."
        return result

    member_aad_id = (activity.get("from") or {}).get("aadObjectId")
    if not member_aad_id:
        result["error"] = "Couldn't identify you — please try again from Teams directly (not a forwarded message)."
        return result

    from users_details.models import UserDetail
    detail = UserDetail.objects.filter(admin=admin, ms_teams_member_id=member_aad_id).first()
    if not detail:
        result["error"] = "You haven't been added to VaptFix yet — please ask your admin to add you first."
        return result
    result["member_detail"] = detail

    channel_id = _extract_channel_id(activity)
    result["channel_id"] = channel_id
    team_name = conversation_store.get_team_name_for_channel(team_id, channel_id) if channel_id else None
    if not team_name and channel_id:
        try:
            team_name = _self_heal_team_name(team_id, channel_id)
        except Exception:
            logger.exception("[TeamsBot] _self_heal_team_name failed")
    if not team_name:
        # Real request: distinguish "you clicked in the admin-only
        # dashboard channel" (a specific, expected wrong-channel case)
        # from any other non-team-scoped channel with a clearer message —
        # best-effort (conversation_store's admin-dashboard reference can
        # itself get repointed by a later conversationUpdate, same as the
        # proactive-post routing it's also used for), so this only changes
        # the wording, never the actual access decision.
        if channel_id and conversation_store.is_admin_dashboard_channel(team_id, channel_id):
            result["error"] = "Only the admin can access this channel. Please use one of your own team channels instead."
        else:
            result["error"] = "This only works inside one of your team channels (e.g. \"vaptfix Configuration Management team\") — not here."
        return result
    result["team_name"] = team_name

    member_roles = list(detail.Member_role or [])
    if team_name not in member_roles:
        result["error"] = f"You're not part of the {team_name} team, so there's nothing to show here."
        return result

    from django.contrib.auth import get_user_model
    User = get_user_model()
    member_user, _ = User.objects.get_or_create(
        email=detail.email,
        defaults={"is_active": True, "login_provider": "microsoft_teams"},
    )
    result["member_user"] = member_user
    return result
