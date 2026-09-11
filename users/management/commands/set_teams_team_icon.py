"""
One-off / retry tool for the VaptFix Teams team icon (the logo shown next
to the team's name in the left sidebar, and on its "VA" avatar tile).

Real gap: _set_vaptfix_team_icon(team_id, access_token) — in users/views.py
— is wired into every team-CREATION code path, but a team created before
that wiring existed (or one where the Graph PUT failed at creation time,
e.g. because the freshly-provisioned team/group wasn't yet consistent
enough to accept a photo upload — a known Graph eventual-consistency
timing issue) never got the icon set and has no automatic retry. This
command re-runs that same upload for an existing admin's team, using a
freshly refreshed access token (the stored one is very likely expired by
the time anyone notices the icon is missing).

Usage:
    python manage.py set_teams_team_icon --admin-email admin@example.com
    python manage.py set_teams_team_icon --team-id <ms_team_id>
    python manage.py set_teams_team_icon --all       # every admin with a team_id
"""
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from users.models import User
from users.views import _set_vaptfix_team_icon, _http_post


class Command(BaseCommand):
    help = "(Re)upload the VaptFix logo as an existing MS Teams team's icon"

    def add_arguments(self, parser):
        parser.add_argument("--admin-email", help="Set the icon for this one admin's team.")
        parser.add_argument("--team-id", help="Set the icon for this one ms_team_id directly (looks up its owning admin for the token).")
        parser.add_argument("--all", action="store_true", help="Set the icon for every admin that has a ms_team_id.")

    def _refresh_token(self, admin):
        refresh_token = getattr(admin, "ms_refresh_token", None)
        if not refresh_token:
            return None
        token_payload = {
            "grant_type": "refresh_token",
            "client_id": settings.MICROSOFT_CLIENT_ID,
            "client_secret": settings.MICROSOFT_CLIENT_SECRET,
            "refresh_token": refresh_token,
            "scope": "https://graph.microsoft.com/.default offline_access",
        }
        resp = _http_post(settings.MICROSOFT_TOKEN_URL, data=token_payload, timeout=15)
        data = resp.json() if resp is not None else {}
        new_token = data.get("access_token")
        if not new_token:
            self.stdout.write(self.style.ERROR(f"  token refresh failed for {admin.email}: {data}"))
            return None
        update_kwargs = {"ms_access_token": new_token}
        if data.get("refresh_token"):
            update_kwargs["ms_refresh_token"] = data["refresh_token"]
        User.objects.filter(pk=admin.pk).update(**update_kwargs)
        return new_token

    def _apply(self, admin):
        if not admin.ms_team_id:
            self.stdout.write(self.style.WARNING(f"  {admin.email}: no ms_team_id, skipping"))
            return False
        token = self._refresh_token(admin) or admin.ms_access_token
        if not token:
            self.stdout.write(self.style.ERROR(f"  {admin.email}: no usable access token (no refresh_token on file either)"))
            return False
        ok = _set_vaptfix_team_icon(admin.ms_team_id, token)
        if ok:
            self.stdout.write(self.style.SUCCESS(f"  {admin.email}: icon set for team_id={admin.ms_team_id}"))
        else:
            self.stdout.write(self.style.ERROR(f"  {admin.email}: icon upload failed for team_id={admin.ms_team_id} — check logs for the Graph error"))
        return ok

    def handle(self, *args, **options):
        if options.get("admin_email"):
            admin = User.objects.filter(email=options["admin_email"]).first()
            if not admin:
                raise CommandError(f"No user found with email={options['admin_email']}")
            self._apply(admin)
        elif options.get("team_id"):
            admin = User.objects.filter(ms_team_id=options["team_id"]).first()
            if not admin:
                raise CommandError(f"No admin found owning ms_team_id={options['team_id']}")
            self._apply(admin)
        elif options.get("all"):
            admins = User.objects.exclude(ms_team_id__isnull=True).exclude(ms_team_id="")
            if not admins:
                self.stdout.write(self.style.WARNING("No admins with a ms_team_id found."))
                return
            self.stdout.write(f"Setting icon for {len(admins)} admin(s)...")
            ok_count = sum(1 for a in admins if self._apply(a))
            self.stdout.write(self.style.SUCCESS(f"Done — {ok_count}/{len(admins)} succeeded."))
        else:
            raise CommandError("Provide --admin-email, --team-id, or --all.")
