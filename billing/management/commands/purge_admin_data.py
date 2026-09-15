"""
Real bug report ("agar maine admin ki email database se remove kar di... aur
fir usi email se naya signup kiya, kya wo fresh/clean admin login hoga?"):
NO, not reliably — manually deleting an admin's User row (and maybe the one
report they remembered) leaves every other collection this app writes to
completely untouched, because almost every admin-scoped lookup in this app
falls back to matching on admin_email whenever admin_id doesn't match (see
billing/asset_service.py's get_admin_asset_count for one of many examples).
A fresh signup with that SAME email gets a brand-new admin_id, but old
Mongo documents still carrying the OLD email keep matching that fallback
and resurface under the "new" account — stale reports, vulnerability
cards, tickets, notifications, everything.

This command properly purges EVERYTHING tied to one email — every raw
Mongo collection and every Django ORM model this app's admin-lifecycle
code knows about (billing.account_lifecycle.purge_admin_records, the same
core logic already used when a lapsed Premium subscription auto-purges an
account) — and, unlike that automatic path, also deletes the User row
itself by default, since that row blocks re-signup with the same email
even while deactivated (AdminSignupSendOTPView's own
`User.objects.filter(email=email).exists()` check doesn't care about
is_active).

Financial/audit records are intentionally never touched here, matching
purge_admin_records' own behavior: billing.Subscription, billing.Invoice,
billing.BillingCustomer, billing.StripeWebhookEvent stay untouched (kept
regardless of what happens to the account — same reasoning as the
automatic lapsed-subscription purge).

Usage:
    python manage.py purge_admin_data --email admin@example.com --dry-run
    python manage.py purge_admin_data --email admin@example.com
    python manage.py purge_admin_data --email admin@example.com --admin-id <uuid> [--admin-id <uuid> ...]
    python manage.py purge_admin_data --email admin@example.com --keep-user
"""
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError

from billing.account_lifecycle import purge_admin_records


class Command(BaseCommand):
    help = (
        "Purge every trace of one admin's data (by email) across every Django "
        "model and raw Mongo collection this app writes to, so re-signing-up "
        "with the same email starts genuinely clean."
    )

    def add_arguments(self, parser):
        parser.add_argument("--email", required=True, help="The admin's email address.")
        parser.add_argument(
            "--admin-id", action="append", default=[], dest="admin_ids",
            help=(
                "An admin_id (UUID) this email has used in the past — e.g. one you "
                "noted before deleting the User row. Optional: most data is matched "
                "by email alone regardless of admin_id. Can be passed multiple times "
                "if this email has been signed up and deleted more than once."
            ),
        )
        parser.add_argument("--dry-run", action="store_true", help="Report what would be deleted without deleting anything.")
        parser.add_argument(
            "--keep-user", action="store_true",
            help=(
                "Don't delete the still-existing User row for this email (if any) — "
                "purge everything else only. NOTE: leaving the row in place (even "
                "deactivated) still blocks re-signup with this email."
            ),
        )

    def handle(self, *args, **options):
        email = (options["email"] or "").strip().lower()
        if not email:
            raise CommandError("--email is required")
        dry_run = options["dry_run"]
        explicit_admin_ids = list(dict.fromkeys(options["admin_ids"] or []))  # de-dupe, keep order

        User = get_user_model()
        existing_user = User.objects.filter(email__iexact=email).first()
        if existing_user:
            self.stdout.write(f"Found existing User row: id={existing_user.id}, is_active={existing_user.is_active}")
            admin_ids = [str(existing_user.id)] + [a for a in explicit_admin_ids if a != str(existing_user.id)]
        else:
            self.stdout.write("No existing User row for this email (already deleted, or never existed).")
            admin_ids = explicit_admin_ids or [""]

        self.stdout.write(f"\n{'Would purge' if dry_run else 'Purging'} data for email={email!r}, admin_id(s)={admin_ids}\n")

        total = {}
        for admin_id in admin_ids:
            counts = purge_admin_records(
                admin_id,
                email,
                admin=existing_user if (existing_user and admin_id == str(existing_user.id)) else None,
                dry_run=dry_run,
            )
            for k, v in counts.items():
                total[k] = total.get(k, 0) + v

        if total:
            self.stdout.write("Breakdown:")
            for name, count in sorted(total.items()):
                self.stdout.write(f"  {name}: {count}")
        else:
            self.stdout.write("Nothing found to purge in any known collection/model.")

        grand_total = sum(total.values())

        if existing_user and not options["keep_user"]:
            self.stdout.write(f"\n{'Would delete' if dry_run else 'Deleting'} the User row itself (id={existing_user.id}).")
            if not dry_run:
                existing_user.delete()
            grand_total += 1
        elif existing_user:
            self.stdout.write(
                f"\n--keep-user set: leaving User row (id={existing_user.id}) in place — "
                "re-signup with this email will still be blocked until it's removed."
            )

        verb = "Would remove" if dry_run else "Removed"
        self.stdout.write(self.style.SUCCESS(f"\n{verb} {grand_total} total row(s)/document(s) for {email}."))
        if dry_run:
            self.stdout.write(self.style.WARNING("--dry-run set, nothing was actually deleted."))
        elif not existing_user or not options["keep_user"]:
            self.stdout.write(self.style.SUCCESS(f"{email} can now sign up as a brand-new admin."))
