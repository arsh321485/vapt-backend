"""
Management command to rename Slack channels to the new VaptFix naming convention
and create the vaptfix-admin-dashboard channel.

Usage:
    python manage.py setup_slack_channels
"""
import requests
from django.core.management.base import BaseCommand
from django.conf import settings

REQUEST_TIMEOUT = 15

RENAME_MAP = {
    "patch-management":         "vaptfix-patch-management-team",
    "configuration-management": "vaptfix-configuration-management-team",
    "network-security":         "vaptfix-network-security-team",
    "architectural-flaws":      "vaptfix-architectural-flaws-team",
}
ADMIN_CHANNEL_NAME = "vaptfix-admin-dashboard"


class Command(BaseCommand):
    help = "Rename VaptFix Slack channels to new naming convention and create admin channel."

    def add_arguments(self, parser):
        parser.add_argument(
            "--dry-run",
            action="store_true",
            help="Show what would be done without making any changes.",
        )

    def handle(self, *args, **options):
        dry_run = options["dry_run"]
        bot_token = self._get_bot_token()
        if not bot_token:
            self.stderr.write(self.style.ERROR(
                "No Slack bot token found. Connect Slack first via the VaptFix UI."
            ))
            return

        self.stdout.write(f"{'[DRY RUN] ' if dry_run else ''}Fetching Slack channels...")
        channels = self._list_all_channels(bot_token)
        if channels is None:
            self.stderr.write(self.style.ERROR("Failed to fetch channel list from Slack."))
            return

        self.stdout.write(f"Found {len(channels)} channels in workspace.\n")

        # Build name → id map
        name_to_id = {ch["name"]: ch["id"] for ch in channels}
        existing_names = set(name_to_id.keys())

        # ── Step 1: Rename old channels ──────────────────────────────────
        self.stdout.write("--- Renaming team channels ---")
        for old_name, new_name in RENAME_MAP.items():
            if new_name in existing_names:
                self.stdout.write(self.style.SUCCESS(f"  ✓ '{new_name}' already exists — skipping."))
                continue
            if old_name not in name_to_id:
                self.stdout.write(self.style.WARNING(f"  ⚠ '{old_name}' not found — skipping."))
                continue

            channel_id = name_to_id[old_name]
            self.stdout.write(f"  Renaming #{old_name} -> #{new_name} ...")
            if not dry_run:
                ok, error = self._rename_channel(bot_token, channel_id, new_name)
                if ok:
                    self.stdout.write(self.style.SUCCESS(f"  OK Renamed successfully."))
                else:
                    self.stdout.write(self.style.ERROR(f"  FAILED: {error}"))
            else:
                self.stdout.write(f"  [DRY RUN] Would rename #{old_name} -> #{new_name}")

        # ── Step 2: Create vaptfix-admin-dashboard ───────────────────────
        self.stdout.write("\n--- Admin channel ---")
        if ADMIN_CHANNEL_NAME in existing_names:
            self.stdout.write(self.style.SUCCESS(
                f"  ✓ '#{ADMIN_CHANNEL_NAME}' already exists — nothing to do."
            ))
        else:
            self.stdout.write(f"  Creating #{ADMIN_CHANNEL_NAME} ...")
            if not dry_run:
                ok, result = self._create_channel(bot_token, ADMIN_CHANNEL_NAME)
                if ok:
                    self.stdout.write(self.style.SUCCESS(f"  ✓ Channel created successfully."))
                else:
                    self.stdout.write(self.style.ERROR(f"  ✗ Failed: {result}"))
            else:
                self.stdout.write(f"  [DRY RUN] Would create #{ADMIN_CHANNEL_NAME}")

        self.stdout.write(self.style.SUCCESS("\nDone."))

    # ── Helpers ──────────────────────────────────────────────────────────

    def _get_bot_token(self):
        from users.models import User
        admin = User.objects.filter(slack_bot_token__isnull=False).exclude(slack_bot_token="").first()
        return admin.slack_bot_token if admin else None

    def _list_all_channels(self, bot_token):
        channels = []
        cursor = None
        while True:
            params = {"limit": 200, "exclude_archived": "true", "types": "public_channel,private_channel"}
            if cursor:
                params["cursor"] = cursor
            resp = requests.get(
                "https://slack.com/api/conversations.list",
                headers={"Authorization": f"Bearer {bot_token}"},
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
            headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
            json={"channel": channel_id, "name": new_name},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        return data.get("ok"), data.get("error", "")

    def _create_channel(self, bot_token, name):
        resp = requests.post(
            "https://slack.com/api/conversations.create",
            headers={"Authorization": f"Bearer {bot_token}", "Content-Type": "application/json"},
            json={"name": name, "is_private": False},
            timeout=REQUEST_TIMEOUT,
        )
        data = resp.json()
        return data.get("ok"), data.get("error", "")
