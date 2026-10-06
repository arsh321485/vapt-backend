"""
Delete an admin account and everything tied to it, plus the team members
that admin added (only the login accounts that have no other admin link).

Dry-run by default — prints what WOULD be deleted, touches nothing:

    python manage.py delete_admin_data --email admin@example.com

Real delete needs --execute and typing the email again, and always writes a
JSON backup of every document it removes first:

    python manage.py delete_admin_data --email admin@example.com --execute --confirm-email admin@example.com

Deliberately never touched: vulnerability_cards (AI agent output) and any
billing collection (Stripe-linked records).
"""
import datetime
import json
import os

from django.conf import settings
from django.core.management.base import BaseCommand, CommandError

from vaptfix.mongo_client import MongoContext

# (collection, field-filter-builder key). Filter is applied as
# {"$or": [{"admin_id": id}, {"admin_email": email}]} — collections that
# store only one of those fields still match on whichever is present.
ADMIN_SCOPED_COLLECTIONS = [
    "nessus_reports",
    "upload_reports",
    "fix_vulnerabilities",
    "fix_vulnerabilities_closed",
    "fix_vulnerability_steps",
    "hold_vulnerabilities",
    "hold_assets",
    "deleted_assets",
    "deleted_vulnerabilities",
    "support_requests",
    "timeline_extension_requests",
    "notifications_notification",
    "risk_criteria_riskcriteria",
    "host_classification_overrides",
    "script_user_downloads",
    "teams_bot_team_channels",
    "teams_bot_sub_channels",
    "teams_bot_conversations",
]


class Command(BaseCommand):
    help = "Delete an admin account, its data, and team members added by it (dry-run unless --execute)."

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="Admin email to delete.")
        parser.add_argument("--execute", action="store_true", help="Actually delete. Without this, dry-run only.")
        parser.add_argument("--confirm-email", help="Must repeat --email exactly to execute.")

    def handle(self, *args, **opts):
        from users.models import User
        from users_details.models import UserDetail

        email = (opts["email"] or "").strip()
        admin = User.objects.filter(email__iexact=email).first()
        if not admin:
            raise CommandError(f"No user found for {email}")
        if admin.is_superuser:
            raise CommandError("Refusing to delete a superuser account from this command.")

        admin_id = str(admin.id)
        scope = {"$or": [{"admin_id": admin_id}, {"admin_email": admin.email}]}

        # Added team members: delete the team record for this admin always.
        # The login account is deleted only if that person has no link to any
        # other admin (someone can be a member of two admins' teams).
        member_details = list(UserDetail.objects.filter(admin=admin))
        member_accounts = []
        for d in member_details:
            other_links = UserDetail.objects.filter(email__iexact=d.email).exclude(admin=admin).exists()
            member_accounts.append({"email": d.email, "delete_login": not other_links})

        with MongoContext() as db:
            counts = {c: db[c].count_documents(scope) for c in ADMIN_SCOPED_COLLECTIONS}

        self.stdout.write(self.style.WARNING(f"Admin: {admin.email} (id={admin_id})"))
        self.stdout.write("Admin-scoped records:")
        for c, n in counts.items():
            if n:
                self.stdout.write(f"  {c}: {n}")
        self.stdout.write(f"Team member records (this admin): {len(member_details)}")
        for m in member_accounts:
            action = "delete login + team record" if m["delete_login"] else "team record only (has another admin link)"
            self.stdout.write(f"  {m['email']}: {action}")
        self.stdout.write(f"Admin login account (users_user): will delete")
        self.stdout.write("Not touched: vulnerability_cards, billing_*")

        if not opts["execute"]:
            self.stdout.write(self.style.SUCCESS("Dry-run only. Nothing deleted. Re-run with --execute --confirm-email <same email> to delete."))
            return

        if (opts.get("confirm_email") or "").strip().lower() != email.lower():
            raise CommandError("--confirm-email must match --email exactly to execute.")

        backup_dir = os.path.join(settings.BASE_DIR, "deleted_backups")
        os.makedirs(backup_dir, exist_ok=True)
        stamp = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        backup_path = os.path.join(backup_dir, f"{admin_id}-{stamp}.json")
        backup = {"admin": {"email": admin.email, "id": admin_id}, "collections": {}, "members": member_accounts}

        with MongoContext() as db:
            for c in ADMIN_SCOPED_COLLECTIONS:
                docs = list(db[c].find(scope))
                if docs:
                    backup["collections"][c] = [{k: str(v) for k, v in d.items()} for d in docs]
            for m in member_accounts:
                if m["delete_login"]:
                    user_docs = list(db["users_user"].find({"email": m["email"]}))
                    backup["collections"].setdefault("users_user", []).extend(
                        [{k: str(v) for k, v in d.items()} for d in user_docs]
                    )
            admin_docs = list(db["users_user"].find({"id": admin_id}))
            backup["collections"].setdefault("users_user", []).extend(
                [{k: str(v) for k, v in d.items()} for d in admin_docs]
            )

        with open(backup_path, "w", encoding="utf-8") as fh:
            json.dump(backup, fh, indent=2, default=str)

        with MongoContext() as db:
            for c in ADMIN_SCOPED_COLLECTIONS:
                db[c].delete_many(scope)
            for m in member_accounts:
                if m["delete_login"]:
                    db["users_user"].delete_many({"email": m["email"]})
            db["users_user"].delete_many({"id": admin_id})

        for d in member_details:
            d.delete()

        self.stdout.write(self.style.SUCCESS(f"Deleted. Backup saved to {backup_path}"))
