"""
Backend-only operation: create a Custom Team and add a team member for a
given admin, without going through the Slack/Teams/website UI.

Real request: support needs to do this directly on an admin's behalf
(admin tells us the team name + member details, we add it from the
backend). Team creation replicates CustomTeamListCreateView's own
validation directly (rather than calling that view in-process) so the
Slack/Teams channel creation can be done synchronously, in the
foreground — calling the view instead backgrounds that work on a daemon
thread, which a standalone management command can't reliably wait on
(confirmed live: produced an actual duplicate Teams channel once — see
the comment in handle() for the full story). Adding a member — whether
brand new or an existing one getting an additional role — still goes
through the real UserDetailCreateView / UserDetailRoleUpdateView
in-process (force_authenticate as the target admin), so duplicate-email
checks, the Freemium team-member plan gate, and the welcome/role emails
all run exactly as they would from the real UI.

Usage:
    python manage.py add_custom_team_and_user \\
        --admin-email yash@vaptfix.ai \\
        --team-name "demo vaptfix" \\
        --first-name Asha --last-name Singh \\
        --email asha@secureitlabservices.com \\
        [--role "demo vaptfix"] [--user-type external]

--role defaults to --team-name. --user-type auto-detects from whether the
member's email domain matches the admin's (see
users_details.serializers._enforce_user_type_email_domain) when not given.
"""
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate


def _refresh_ms_access_token(admin):
    """
    A standalone command runs whenever support happens to invoke it — not
    right after the admin's own login, like every other Graph call in
    this codebase is — so admin.ms_access_token (short-lived, ~1hr) is
    very likely already expired by the time this runs. Refreshes it via
    the stored ms_refresh_token first (same grant this project's other
    _refresh_admin_ms_token/_refresh_ms_token helpers use), so the Teams
    channel sync below gets a token that actually works. Returns the
    refreshed token, or the original (possibly stale) one if there's no
    refresh_token or the refresh call itself fails — never raises.
    """
    refresh_token = getattr(admin, "ms_refresh_token", None)
    if not refresh_token:
        return getattr(admin, "ms_access_token", None)
    try:
        import requests
        resp = requests.post(settings.MICROSOFT_TOKEN_URL, data={
            "grant_type": "refresh_token",
            "client_id": settings.MICROSOFT_CLIENT_ID,
            "client_secret": settings.MICROSOFT_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "scope": "https://graph.microsoft.com/.default offline_access",
        }, timeout=15)
        data = resp.json() if resp is not None else {}
        new_token = data.get("access_token")
        if not new_token:
            return getattr(admin, "ms_access_token", None)
        update_kwargs = {"ms_access_token": new_token}
        if data.get("refresh_token"):
            update_kwargs["ms_refresh_token"] = data["refresh_token"]
        get_user_model().objects.filter(pk=admin.pk).update(**update_kwargs)
        return new_token
    except Exception:
        return getattr(admin, "ms_access_token", None)


class Command(BaseCommand):
    help = "Create a Custom Team and add a team member for a given admin — backend-only, mirrors the real Add Team / Add User UI flow."

    def add_arguments(self, parser):
        parser.add_argument("--admin-email", required=True)
        parser.add_argument("--team-name", required=True)
        parser.add_argument("--first-name", required=True)
        parser.add_argument("--last-name", required=True)
        parser.add_argument("--email", required=True)
        parser.add_argument("--role", required=False, default=None, help="Defaults to --team-name")
        parser.add_argument("--user-type", required=False, default=None, choices=["internal", "external"])

    def _call(self, view_cls, admin, data, method="post", url_kwargs=None):
        factory = APIRequestFactory()
        factory_method = getattr(factory, method)
        request = factory_method("/internal/", data, format="json")
        force_authenticate(request, user=admin)
        response = view_cls.as_view()(request, **(url_kwargs or {}))
        if hasattr(response, "render"):
            response.render()
        return response.status_code, response.data

    def handle(self, *args, **options):
        User = get_user_model()
        admin_email = options["admin_email"].strip()
        admin = User.objects.filter(email=admin_email).first()
        if not admin or not admin.is_staff:
            raise CommandError(f"No admin account found for '{admin_email}'.")

        team_name = options["team_name"].strip()
        role = (options["role"] or team_name).strip()
        member_email = options["email"].strip()

        user_type = options["user_type"]
        if not user_type:
            admin_domain = admin_email.rsplit("@", 1)[-1].lower()
            member_domain = member_email.rsplit("@", 1)[-1].lower()
            user_type = "internal" if admin_domain == member_domain else "external"

        from users_details.views import UserDetailCreateView, UserDetailRoleUpdateView, _FIXED_TEAM_NAMES
        from users_details.models import UserDetail, CustomTeam

        # Real bug found live (confirmed via a real duplicate Teams
        # channel): going through CustomTeamListCreateView here — like the
        # very first version of this command did — starts the actual
        # Slack/Teams channel creation on a background daemon thread. That
        # thread is NOT reliably killed by this process exiting (it can
        # keep running for the few seconds the rest of this command is
        # still doing network calls) — so the "channel still missing,
        # create it now" fallback below could run WHILE that background
        # thread was mid-flight, and both ended up calling the Graph API
        # and creating two separate channels for the same team. Fixed by
        # never going through the view's own threaded side effect at all
        # here — doing the same validation it does, directly, then
        # creating the channel synchronously ourselves (the only place
        # that ever calls ensure_custom_team_teams_channel/
        # ensure_custom_team_slack_channel for this command run).
        team = CustomTeam.objects.filter(admin=admin, name__iexact=team_name).first()
        if team:
            self.stdout.write(self.style.WARNING(f"Custom team '{team_name}' already exists for {admin_email} — reusing it."))
        else:
            if team_name in _FIXED_TEAM_NAMES:
                raise CommandError(f'"{team_name}" is already one of the 4 standard teams — choose a different name.')
            team = CustomTeam.objects.create(admin=admin, name=team_name)
            self.stdout.write(self.style.SUCCESS(f"Custom team created: id={team._id} name={team.name}"))

        if team and not team.ms_teams_channel_id and getattr(admin, "ms_team_id", None):
            from users.views import ensure_custom_team_teams_channel
            self.stdout.write(f"Teams channel for '{team_name}' wasn't created yet — creating it now (foreground)...")
            channel_id = ensure_custom_team_teams_channel(admin, team)
            if channel_id:
                self.stdout.write(self.style.SUCCESS(f"Teams channel created: {channel_id}"))
            else:
                self.stdout.write(self.style.WARNING("Could not create the Teams channel (non-fatal — team still works, just no dedicated channel yet)."))
        if team and not team.slack_channel_id and getattr(admin, "slack_bot_token", None):
            from users.views import ensure_custom_team_slack_channel
            self.stdout.write(f"Slack channel for '{team_name}' wasn't created yet — creating it now (foreground)...")
            try:
                ensure_custom_team_slack_channel(admin, team)
            except Exception as exc:
                self.stdout.write(self.style.WARNING(f"Could not create the Slack channel (non-fatal): {exc}"))

        # Real gap found live: a member who already exists under this
        # admin (added earlier, for a different team) can't be "created"
        # again — UserDetailCreateView correctly rejects that as a
        # duplicate (409), so the team got created but the role silently
        # never did. For that case, add the new team as an ADDITIONAL
        # role on their existing record instead, via the same
        # UserDetailRoleUpdateView the MS Teams bot's own "Add to Team"
        # button uses (their other roles are left untouched). Passing
        # access_token/team_id explicitly — unlike UserDetailCreateView,
        # this view only Teams-syncs when they're in the request body, it
        # doesn't fall back to the admin's own ms_access_token/ms_team_id
        # on its own.
        existing = UserDetail.objects.filter(admin=admin, email=member_email).first()
        if existing:
            self.stdout.write(f"'{member_email}' already exists under {admin_email} — adding '{role}' as an additional role...")
            fresh_access_token = _refresh_ms_access_token(admin)
            status_code, data = self._call(
                UserDetailRoleUpdateView, admin,
                {
                    "new_roles": [role],
                    "access_token": fresh_access_token,
                    "team_id": getattr(admin, "ms_team_id", None),
                },
                method="patch", url_kwargs={"detail_id": str(existing._id)},
            )
            if status_code not in (200, 201):
                raise CommandError(f"Adding role failed ({status_code}): {data}")
            self.stdout.write(self.style.SUCCESS(f"Role added: {data}"))
            return

        self.stdout.write(f"Adding user '{member_email}' to {admin_email} with role '{role}' (user_type={user_type})...")
        status_code, data = self._call(UserDetailCreateView, admin, {
            "admin_id": str(admin.id),
            "first_name": options["first_name"].strip(),
            "last_name": options["last_name"].strip(),
            "user_type": user_type,
            "email": member_email,
            "Member_role": [role],
        })
        if status_code not in (200, 201):
            raise CommandError(f"User creation failed ({status_code}): {data}")
        self.stdout.write(self.style.SUCCESS(f"User added: {data}"))
