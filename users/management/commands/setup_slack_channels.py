"""
Management command to rename Slack channels to the new VaptFix naming convention
and create the vaptfix-admin-dashboard channel.
Runs across ALL connected Slack workspaces automatically.

Usage:
    python manage.py setup_slack_channels
    python manage.py setup_slack_channels --dry-run
"""
import requests
from django.core.management.base import BaseCommand

REQUEST_TIMEOUT = 15

RENAME_MAP = {
    "patch-management":         "vaptfix-patch-management-team",
    "configuration-management": "vaptfix-configuration-management-team",
    "network-security":         "vaptfix-network-security-team",
    "architectural-flaws":      "vaptfix-architectural-flaws-team",
}
ADMIN_CHANNEL_NAME = "vaptfix-admin-dashboard"

# All 5 channels the admin should be a member of
ADMIN_ALL_CHANNELS = [
    "vaptfix-admin-dashboard",
    "vaptfix-patch-management-team",
    "vaptfix-configuration-management-team",
    "vaptfix-network-security-team",
    "vaptfix-architectural-flaws-team",
]


class Command(BaseCommand):
    help = "Rename VaptFix Slack channels to new naming convention and create admin channel across all workspaces."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without making any changes.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        tokens = self._get_all_valid_tokens()

        if not tokens:
            self.stderr.write("No valid Slack bot tokens found. Connect Slack first via the VaptFix UI.")
            return

        self.stdout.write(f"Found {len(tokens)} valid workspace(s).\n")

        for workspace_name, team_id, bot_token, email, slack_user_id in tokens:
            self.stdout.write("=" * 60)
            self.stdout.write(f"Workspace : {workspace_name}  (ID: {team_id})")
            self.stdout.write(f"Admin user: {email}  (Slack ID: {slack_user_id or 'NOT SET'})")
            self.stdout.write("=" * 60)

            channels = self._list_all_channels(bot_token)
            if channels is None:
                self.stdout.write(f"  SKIP: Could not fetch channels for this workspace.\n")
                continue

            self.stdout.write(f"  Found {len(channels)} channels.\n")
            name_to_id = {ch["name"]: ch["id"] for ch in channels}
            existing_names = set(name_to_id.keys())

            # Step 1: Rename team channels
            self.stdout.write("  --- Renaming team channels ---")
            for old_name, new_name in RENAME_MAP.items():
                if new_name in existing_names:
                    self.stdout.write(self.style.SUCCESS(f"  OK  '{new_name}' already exists - skipping."))
                    continue
                if old_name not in name_to_id:
                    self.stdout.write(self.style.WARNING(f"  WARN '{old_name}' not found - skipping."))
                    continue

                channel_id = name_to_id[old_name]
                self.stdout.write(f"  Renaming #{old_name} -> #{new_name} ...")
                if not dry_run:
                    ok, error = self._rename_channel(bot_token, channel_id, new_name)
                    if ok:
                        self.stdout.write(self.style.SUCCESS(f"  OK  Renamed successfully."))
                        name_to_id[new_name] = channel_id
                        existing_names.add(new_name)
                    else:
                        self.stdout.write(self.style.ERROR(f"  FAILED: {error}"))
                else:
                    self.stdout.write(f"  [DRY RUN] Would rename #{old_name} -> #{new_name}")

            # Step 2: Create admin channel
            self.stdout.write("\n  --- Admin channel ---")
            if ADMIN_CHANNEL_NAME in existing_names:
                admin_ch_id = name_to_id[ADMIN_CHANNEL_NAME]
                self.stdout.write(self.style.SUCCESS(f"  OK  '#{ADMIN_CHANNEL_NAME}' already exists (ID: {admin_ch_id})."))
            else:
                self.stdout.write(f"  Creating #{ADMIN_CHANNEL_NAME} ...")
                admin_ch_id = None
                if not dry_run:
                    ok, result = self._create_channel(bot_token, ADMIN_CHANNEL_NAME)
                    if ok:
                        admin_ch_id = result
                        name_to_id[ADMIN_CHANNEL_NAME] = admin_ch_id
                        existing_names.add(ADMIN_CHANNEL_NAME)
                        self.stdout.write(self.style.SUCCESS(f"  OK  Channel created (ID: {admin_ch_id})."))
                    else:
                        self.stdout.write(self.style.ERROR(f"  FAILED: {result}"))
                else:
                    self.stdout.write(f"  [DRY RUN] Would create #{ADMIN_CHANNEL_NAME}")

            # Step 3: Invite admin user to ALL 5 VaptFix channels
            self.stdout.write("\n  --- Inviting admin to all 5 VaptFix channels ---")
            if not slack_user_id:
                self.stdout.write(self.style.WARNING(
                    f"  WARN Admin '{email}' has no slack_user_id stored.\n"
                    "  Please log in via Slack OAuth in VaptFix UI first, then re-run this command."
                ))
            elif dry_run:
                for ch_name in ADMIN_ALL_CHANNELS:
                    self.stdout.write(f"  [DRY RUN] Would invite admin to #{ch_name}")
            else:
                for ch_name in ADMIN_ALL_CHANNELS:
                    ch_id = name_to_id.get(ch_name)
                    if not ch_id:
                        self.stdout.write(self.style.WARNING(f"  WARN #{ch_name} not found in workspace - skipping."))
                        continue
                    ok, err = self._invite_user(bot_token, ch_id, slack_user_id)
                    if ok:
                        self.stdout.write(self.style.SUCCESS(f"  OK  Admin invited to #{ch_name}."))
                    elif err == "already_in_channel":
                        self.stdout.write(self.style.SUCCESS(f"  OK  Admin already in #{ch_name}."))
                    else:
                        self.stdout.write(self.style.ERROR(f"  FAILED invite to #{ch_name}: {err}"))

            self.stdout.write("")

        self.stdout.write(self.style.SUCCESS("Done."))

    # ── Helpers ──────────────────────────────────────────────────────────

    def _get_all_valid_tokens(self):
        from users.models import User
        results = []
        seen_team_ids = set()

        users = User.objects.filter(
            slack_bot_token__isnull=False
        ).exclude(slack_bot_token="")

        for user in users:
            resp = requests.get(
                "https://slack.com/api/auth.test",
                headers={"Authorization": "Bearer " + user.slack_bot_token},
                timeout=REQUEST_TIMEOUT,
            ).json()

            if not resp.get("ok"):
                self.stdout.write(f"  Skip {user.email}: invalid token ({resp.get('error')})")
                continue

            team_id = resp.get("team_id")
            if team_id in seen_team_ids:
                continue
            seen_team_ids.add(team_id)

            workspace_name = resp.get("team", "unknown")
            slack_user_id = user.slack_user_id or ""
            results.append((workspace_name, team_id, user.slack_bot_token, user.email, slack_user_id))
            self.stdout.write(
                f"  Valid token: {user.email} -> workspace '{workspace_name}' ({team_id})"
                f"  slack_user_id={slack_user_id or 'NOT SET'}"
            )

        self.stdout.write("")
        return results

    def _list_all_channels(self, bot_token):
        channels = []
        cursor = None
        while True:
            params = {"limit": 200, "exclude_archived": "true", "types": "public_channel,private_channel"}
            if cursor:
                params["cursor"] = cursor
            resp = requests.get(
                "https://slack.com/api/conversations.list",
                headers={"Authorization": "Bearer " + bot_token},
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            data = resp.json()
            if not data.get("ok"):
                self.stderr.write(f"Slack API error: {data.get('error')}")
                return None
            channels.extend(data.get("channels", []))
            cursor = data.get("response_metadata", {}).get("next_cursor", "")
            if not cursor:
                break
        return channels

    def _rename_channel(self, bot_token, channel_id, new_name):
        resp = requests.post(
            "https://slack.com/api/conversations.rename",
            headers={"Authorization": "Bearer " + bot_token, "Content-Type": "application/json"},
            json={"channel": channel_id, "name": new_name},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        return data.get("ok"), data.get("error", "")

    def _create_channel(self, bot_token, name):
        resp = requests.post(
            "https://slack.com/api/conversations.create",
            headers={"Authorization": "Bearer " + bot_token, "Content-Type": "application/json"},
            json={"name": name, "is_private": False},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        if data.get("ok"):
            return True, data.get("channel", {}).get("id")
        return False, data.get("error", "unknown_error")

    def _invite_user(self, bot_token, channel_id, slack_user_id):
        resp = requests.post(
            "https://slack.com/api/conversations.invite",
            headers={"Authorization": "Bearer " + bot_token, "Content-Type": "application/json"},
            json={"channel": channel_id, "users": slack_user_id},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        return data.get("ok"), data.get("error", "")
