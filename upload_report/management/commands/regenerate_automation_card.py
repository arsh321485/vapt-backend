"""
Regenerates the AI-generated automation_card on one (or several) existing
vulnerability_cards documents — re-runs ONLY the standalone Automation
Engineer step (see mitigation_tool.generate_automation_for_existing_card),
reusing the card's already-stored mitigation_table/OS profile, same as the
Freemium->Premium upgrade backfill does. Does NOT touch the manual
mitigation_table/backup_card — those stay exactly as they are.

Real use case this was built for: cards generated before the Automation
Engineer prompt was locked to always emit Python (see crew_agent/tasks.py)
and before _parse_automation_card started syntax-validating fix_script/
verify_script via ast.parse — a stale card can carry a non-Python script,
or (confirmed live) a script with an actual Python syntax error that
should have been withheld. Regenerating re-runs it through both of those
guards.

Usage — one specific card, by vulnerability name + host (as shown on the
Fix tab / Teams / Slack):

    python manage.py regenerate_automation_card \
        --vulnerability "HP LaserJet Printers Multiple RCE" \
        --host 161.126.58.86

Narrow further with --report-id / --admin-email if the same vulnerability
name+host appears on more than one admin's data (rare, but possible across
different organizations scanning the same lab range).

Bulk mode — every card whose automation_card is missing, was generated
before the Python-only rule (language != "python"), or was withheld by the
new ast.parse safety net (generation_invalid=True):

    python manage.py regenerate_automation_card --stale-non-python
    python manage.py regenerate_automation_card --admin-email admin@x.com --stale-non-python

Bulk mode re-runs GPT-4o for every matched card — real cost, confirm the
count with --dry-run first.

--dedupe (bulk mode only): the same vulnerability commonly repeats across
many hosts on one report (e.g. "SSL Certificate Cannot Be Trusted" on 15
assets) — each of those is its own vulnerability_cards document, but the
Automation Engineer prompt forbids literal IPs/hostnames in the generated
script (crew_agent/tasks.py), so two cards with the same vulnerability_name
+ OS + manual mitigation plan produce the SAME fix_script/verify_script
either way. --dedupe groups matched cards by that (vulnerability_name, OS,
mitigation_table) key, calls GPT ONCE per unique group, and applies the
result to every card in it — typically a large multiple fewer GPT calls
than one-per-card:

    python manage.py regenerate_automation_card --stale-non-python --dedupe --dry-run
    python manage.py regenerate_automation_card --stale-non-python --dedupe
"""
import datetime
import hashlib
import json

from django.core.management.base import BaseCommand, CommandError
from vaptfix.mongo_client import get_shared_client, get_shared_db

VULN_CARD_COLLECTION = "vulnerability_cards"


class Command(BaseCommand):
    help = "Regenerate the AI automation_card on one or more existing vulnerability_cards documents"

    def add_arguments(self, parser):
        parser.add_argument("--vulnerability", help="Exact vulnerability_name to target (case-insensitive).")
        parser.add_argument("--host", help="Exact host_name to target, paired with --vulnerability.")
        parser.add_argument("--card-id", help="Target one card directly by its card_id, instead of name+host.")
        parser.add_argument("--report-id", help="Narrow to one report_id.")
        parser.add_argument("--admin-email", help="Narrow to one admin's cards.")
        parser.add_argument(
            "--stale-non-python", action="store_true",
            help="Bulk mode: every matching card whose automation_card is missing, "
                 "non-python, or was withheld by the syntax-validation safety net.",
        )
        parser.add_argument(
            "--dry-run", action="store_true",
            help="List what would be regenerated without calling GPT or writing anything.",
        )
        parser.add_argument(
            "--dedupe", action="store_true",
            help="Bulk mode only: group matched cards by (vulnerability_name, OS, "
                 "manual mitigation plan) and call GPT once per unique group instead "
                 "of once per card — see module docstring.",
        )

    def handle(self, *args, **options):
        from upload_report.mitigation_tool import generate_automation_for_existing_card

        client = get_shared_client()
        db = get_shared_db(client)
        coll = db[VULN_CARD_COLLECTION]

        query = {}
        if options.get("report_id"):
            query["report_id"] = options["report_id"]
        if options.get("admin_email"):
            query["admin_email"] = options["admin_email"]

        if options.get("card_id"):
            query["card_id"] = options["card_id"]
        elif options.get("stale_non_python"):
            query["$or"] = [
                {"automation_card": {"$exists": False}},
                {"automation_card": {}},
                {"automation_card": None},
                {"automation_card.automation_status": {"$in": ["full", "partial"]},
                 "automation_card.language": {"$ne": "python"}},
                {"automation_card.generation_invalid": True},
            ]
        else:
            vuln = options.get("vulnerability")
            host = options.get("host")
            if not vuln:
                raise CommandError(
                    "Provide --vulnerability (+ optional --host), --card-id, or --stale-non-python."
                )
            query["vulnerability_name"] = {"$regex": f"^{_escape(vuln)}$", "$options": "i"}
            if host:
                query["host_name"] = host

        cards = list(coll.find(query))
        if not cards:
            self.stdout.write(self.style.WARNING("No matching cards found."))
            return

        if options.get("dedupe"):
            return self._handle_dedupe(cards, coll, options)

        self.stdout.write(f"Matched {len(cards)} card(s):")
        for c in cards:
            existing = c.get("automation_card") or {}
            self.stdout.write(
                f"  - card_id={c.get('card_id')} '{c.get('vulnerability_name')}' "
                f"on {c.get('host_name')} (report_id={c.get('report_id')}, admin_email={c.get('admin_email')}) "
                f"— current language={existing.get('language') or '—'} "
                f"status={existing.get('automation_status') or '—'} "
                f"invalid={existing.get('generation_invalid', False)}"
            )

        if options.get("dry_run"):
            self.stdout.write(self.style.WARNING("--dry-run set, nothing regenerated."))
            return

        ok, failed = 0, 0
        for c in cards:
            card_id = c.get("card_id")
            self.stdout.write(f"Regenerating card_id={card_id} '{c.get('vulnerability_name')}'...")
            try:
                new_automation = generate_automation_for_existing_card(c)
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"  error: {exc}"))
                failed += 1
                continue

            if not new_automation:
                self.stdout.write(self.style.ERROR("  generation returned empty — check server logs for [AutomationBackfill]/[MitigationCrew] errors"))
                failed += 1
                continue

            coll.update_one(
                {"card_id": card_id},
                {"$set": {
                    "automation_card": new_automation,
                    "automation_regenerated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }},
            )
            status = new_automation.get("automation_status")
            lang = new_automation.get("language")
            invalid = new_automation.get("generation_invalid", False)
            self.stdout.write(self.style.SUCCESS(f"  done — status={status} language={lang} generation_invalid={invalid}"))
            ok += 1

        self.stdout.write(self.style.SUCCESS(f"Finished — {ok} regenerated, {failed} failed."))

    def _dedupe_key(self, card):
        """(vulnerability_name, OS, mitigation_table) — the exact three
        inputs build_standalone_automation_task actually feeds into the
        prompt (besides host_name, which the prompt is required to never
        reflect in the output — see AUTOMATION_CARD_SCHEMA's "no literal
        IPs/hostnames" rule). Two cards with an identical key are
        guaranteed to produce the same generation, so only one needs a
        real GPT call."""
        os_profile = card.get("vaptcode_os_profile") or {}
        os_name = (os_profile.get("display_name") or card.get("os_category") or "unknown").strip().lower()
        vuln = (card.get("vulnerability_name") or "").strip().lower()
        mt_json = json.dumps(card.get("mitigation_table") or [], sort_keys=True, default=str)
        mt_hash = hashlib.sha256(mt_json.encode("utf-8")).hexdigest()
        return (vuln, os_name, mt_hash)

    def _handle_dedupe(self, cards, coll, options):
        from upload_report.mitigation_tool import generate_automation_for_existing_card

        groups = {}
        for c in cards:
            groups.setdefault(self._dedupe_key(c), []).append(c)

        self.stdout.write(
            f"Matched {len(cards)} card(s) -> {len(groups)} unique "
            f"(vulnerability, OS, mitigation plan) group(s)."
        )
        for group_cards in groups.values():
            rep = group_cards[0]
            hosts = ", ".join(c.get("host_name", "?") for c in group_cards[:5])
            more = f" (+{len(group_cards) - 5} more)" if len(group_cards) > 5 else ""
            self.stdout.write(f"  - '{rep.get('vulnerability_name')}' x{len(group_cards)}: {hosts}{more}")

        if options.get("dry_run"):
            self.stdout.write(self.style.WARNING(
                f"--dry-run set, nothing regenerated. Would make {len(groups)} GPT call(s) "
                f"instead of {len(cards)}."
            ))
            return

        ok, failed = 0, 0
        for group_cards in groups.values():
            rep = group_cards[0]
            self.stdout.write(
                f"Regenerating group '{rep.get('vulnerability_name')}' "
                f"({len(group_cards)} card(s)) via representative card_id={rep.get('card_id')}..."
            )
            try:
                new_automation = generate_automation_for_existing_card(rep)
            except Exception as exc:
                self.stdout.write(self.style.ERROR(f"  error: {exc}"))
                failed += len(group_cards)
                continue

            if not new_automation:
                self.stdout.write(self.style.ERROR("  generation returned empty — check server logs for [AutomationBackfill]/[MitigationCrew] errors"))
                failed += len(group_cards)
                continue

            now = datetime.datetime.now(datetime.timezone.utc).isoformat()
            for c in group_cards:
                coll.update_one(
                    {"card_id": c.get("card_id")},
                    {"$set": {
                        "automation_card": new_automation,
                        "automation_regenerated_at": now,
                    }},
                )
            status = new_automation.get("automation_status")
            lang = new_automation.get("language")
            invalid = new_automation.get("generation_invalid", False)
            self.stdout.write(self.style.SUCCESS(
                f"  done — status={status} language={lang} generation_invalid={invalid} "
                f"-> applied to {len(group_cards)} card(s)"
            ))
            ok += len(group_cards)

        self.stdout.write(self.style.SUCCESS(
            f"Finished — {ok} card(s) regenerated via {len(groups)} GPT call(s), {failed} failed."
        ))


def _escape(text):
    """Escapes regex metacharacters in --vulnerability so parens/dots in a
    real vulnerability name (e.g. "SSL Certificate Chain Contains RSA Keys
    Less Than 2048 bits") don't get interpreted as regex syntax."""
    import re
    return re.escape(text)
