"""
Backend-only operation: create a Custom Team and add a team member for a
given admin, without going through the Slack/Teams/website UI.

Real request: support needs to do this directly on an admin's behalf
(admin tells us the team name + member details, we add it from the
backend). Calls the real CustomTeamListCreateView / UserDetailCreateView
in-process (force_authenticate as the target admin) instead of
re-implementing their logic — so duplicate-email checks, the Freemium
team-member plan gate, the welcome/role emails, and the automatic
Slack/Teams channel-creation side effects (CustomTeamListCreateView
backgrounds ensure_custom_team_teams_channel/ensure_custom_team_slack_channel
when the admin already has ms_team_id/slack_bot_token set) all run exactly
as they would from the real UI.

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
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate


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

    def _call(self, view_cls, admin, data):
        factory = APIRequestFactory()
        request = factory.post("/internal/", data, format="json")
        force_authenticate(request, user=admin)
        response = view_cls.as_view()(request)
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

        from users_details.views import CustomTeamListCreateView, UserDetailCreateView

        self.stdout.write(f"Creating custom team '{team_name}' for {admin_email}...")
        status_code, data = self._call(CustomTeamListCreateView, admin, {"name": team_name})
        if status_code not in (200, 201):
            raise CommandError(f"Custom team creation failed ({status_code}): {data}")
        self.stdout.write(self.style.SUCCESS(f"Custom team created: {data}"))

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
