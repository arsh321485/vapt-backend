"""
Follow-up, targeted fix: "Outdated PHP version 8.1.27 - Multiple
Vulnerabilities" (High) was never attached to 10.151.5.43 anywhere,
even after fix_tipco_groundtruth.py.

Root cause: that script's ground-truth cross-check can only ADD a
missing (host, finding) pair when some OTHER host in the report
already carries that same finding, to copy its description/risk_factor
/solution text from (see _apply_host_affected_groundtruth's own
docstring) — it was run scoped per source-PDF host group, and within
the "internal_va" group (10.151.x hosts only) no host had ever been
extracted with "Outdated PHP" at all, so there was nothing to copy
inside that group.

Confirmed directly in TIPCO Internal VA Report's own text: it has its
own full "Outdated PHP version 8.1.27" write-up with
"Host(s) Affected: 10.151.5.43" — a real finding GPT's original
extraction of that file missed entirely (on every internal host), not
a mis-attribution this cross-check was ever designed to catch on its
own. Fixed here as a one-off, copying the already-correct
"Outdated PHP" card/finding from 122.55.241.122 (same report, same
finding, already fixed by the previous script) onto 10.151.5.43 too.

Run this yourself from your own terminal:
    python fix_10_151_5_43_php.py
"""
import os
import uuid
import copy

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from vaptfix.mongo_client import get_shared_client, get_shared_db

TARGET_HOST = "10.151.5.43"
TEMPLATE_HOST = "122.55.241.122"
FINDING_NAME = "Outdated PHP version 8.1.27 – Multiple Vulnerabilities"


def main():
    db = get_shared_db(get_shared_client())
    nessus_coll = db["nessus_reports"]
    cards_coll = db["vulnerability_cards"]

    report_ids = sorted({
        doc["report_id"]
        for doc in nessus_coll.find({"vulnerabilities_by_host.host_name": TARGET_HOST}, {"report_id": 1})
    })
    print(f"Found {len(report_ids)} report(s) with {TARGET_HOST}: {report_ids}\n")

    for report_id in report_ids:
        doc = nessus_coll.find_one({"report_id": report_id})
        vbh = doc.get("vulnerabilities_by_host", [])

        target_host_entry = next((h for h in vbh if h["host_name"] == TARGET_HOST), None)
        if not target_host_entry:
            continue

        already = any(v.get("plugin_name") == FINDING_NAME for v in target_host_entry.get("vulnerabilities") or [])
        if already:
            print(f"report_id={report_id}: {TARGET_HOST} already has the finding — skipped")
            continue

        template_host_entry = next((h for h in vbh if h["host_name"] == TEMPLATE_HOST), None)
        template_vuln = None
        if template_host_entry:
            template_vuln = next(
                (v for v in template_host_entry.get("vulnerabilities") or [] if v.get("plugin_name") == FINDING_NAME),
                None,
            )
        if not template_vuln:
            print(f"report_id={report_id}: no template finding found on {TEMPLATE_HOST} — skipped, nothing to copy")
            continue

        target_host_entry["vulnerabilities"].append(copy.deepcopy(template_vuln))
        new_total = sum(len(h.get("vulnerabilities") or []) for h in vbh)

        nessus_coll.update_one(
            {"report_id": report_id},
            {"$set": {"vulnerabilities_by_host": vbh, "total_vulnerabilities": new_total}},
        )
        print(f"report_id={report_id} (admin={doc.get('admin_email')}): added finding to {TARGET_HOST}, total_vulnerabilities -> {new_total}")

        template_card = cards_coll.find_one({"report_id": report_id, "vulnerability_name": FINDING_NAME})
        if not template_card:
            print(f"    WARNING: no card template found to copy for report_id={report_id} — card not created")
            continue
        new_card = copy.deepcopy(template_card)
        new_card.pop("_id", None)
        new_card["card_id"] = str(uuid.uuid4())
        new_card["host_name"] = TARGET_HOST
        cards_coll.insert_one(new_card)
        print(f"    created 1 card for ({TARGET_HOST}, {FINDING_NAME})")

    print("\nDone.")


if __name__ == "__main__":
    main()
