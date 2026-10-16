"""
One-off cleanup: apply the new ground-truth cross-check
(_apply_host_affected_groundtruth) directly to the 3 TIPCO test reports
that were already extracted (and contaminated) BEFORE that fix existed,
without needing to re-upload the source files.

Corrects, for each affected report_id:
  - Drops findings GPT wrongly attached to a host not in that finding's
    own "Host(s)/URL(s) Affected" list (e.g. "Outdated PHP..." on
    Tipco.com.ph, "Unencrypted Communications"/"Strict Transport
    Security Not Enforced" on andapower.com.ph).
  - Restores hosts GPT dropped entirely (122.55.241.122, 10.151.13.131,
    10.151.5.43), copying an existing card/finding's details from
    wherever GPT DID extract it correctly in the same report.
  - Recomputes nessus_reports.total_vulnerabilities for the whole
    document (only the TIPCO-related hosts are touched; every other
    host in a report — e.g. feacbf06's much bigger merged report — is
    left completely untouched).
  - Syncs vulnerability_cards the same way: deletes cards for removed
    (host, finding) pairs, and inserts a copy of an existing card (new
    card_id/_id, same automation/fix-script content) for each restored
    (host, finding) pair missing a card.

Run this yourself from your own terminal:
    python fix_tipco_groundtruth.py
"""
import os
import sys
import uuid
import copy

import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from PyPDF2 import PdfReader
from vaptfix.mongo_client import get_shared_client, get_shared_db
from upload_report.custom_report_ai import _fix_broken_hyphens, _apply_host_affected_groundtruth

FILES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "files")

SOURCE_FILES = {
    "webapp_va": "TIPCO External Web Application VA Report October 2026 v1.0.pdf",
    "external_va": "TIPCO External VA Report October 2026 v1.0.pdf",
    "internal_va": "TIPCO Internal VA Report October 2026 v1.1.pdf",
}

HOST_GROUPS = {
    "webapp_va": {"Tipco.com.ph", "https://multiplypaper.com.ph/", "Fifthdiscipline.com.ph", "andapower.com.ph"},
    "external_va": {"112.199.95.18", "122.55.241.122", "161.49.212.118", "116.50.231.67", "122.54.81.98"},
    "internal_va": {"10.151.5.30", "10.151.10.1", "10.151.5.58", "10.151.13.131", "10.151.5.40", "10.151.5.41", "10.151.5.43"},
}

ALL_TIPCO_HOSTS = set().union(*HOST_GROUPS.values())


def load_pdf_text(filename):
    path = os.path.join(FILES_DIR, filename)
    reader = PdfReader(path)
    texts = []
    for p in reader.pages:
        try:
            texts.append(p.extract_text() or "")
        except Exception:
            texts.append("")
    return _fix_broken_hyphens("\n".join(texts))


def main():
    pdf_text = {key: load_pdf_text(fname) for key, fname in SOURCE_FILES.items()}

    db = get_shared_db(get_shared_client())
    nessus_coll = db["nessus_reports"]
    cards_coll = db["vulnerability_cards"]

    report_ids = sorted({
        doc["report_id"]
        for doc in nessus_coll.find(
            {"vulnerabilities_by_host.host_name": {"$in": list(ALL_TIPCO_HOSTS)}},
            {"report_id": 1},
        )
    })

    print(f"Found {len(report_ids)} report(s) containing TIPCO hosts: {report_ids}\n")

    for report_id in report_ids:
        doc = nessus_coll.find_one({"report_id": report_id})
        vbh = doc.get("vulnerabilities_by_host", [])
        before_total = sum(len(h.get("vulnerabilities") or []) for h in vbh)

        other_hosts = [h for h in vbh if h.get("host_name") not in ALL_TIPCO_HOSTS]

        removed_pairs = []  # (host_name, plugin_name)
        added_pairs = []    # (host_name, plugin_name)
        corrected_tipco_hosts = []

        for group_key, group_host_names in HOST_GROUPS.items():
            subset = [copy.deepcopy(h) for h in vbh if h.get("host_name") in group_host_names]
            if not subset:
                continue
            before_names = {
                (h["host_name"], v.get("plugin_name"))
                for h in subset for v in h.get("vulnerabilities") or []
            }
            fixed_subset = _apply_host_affected_groundtruth(subset, pdf_text[group_key], SOURCE_FILES[group_key])
            after_names = {
                (h["host_name"], v.get("plugin_name"))
                for h in fixed_subset for v in h.get("vulnerabilities") or []
            }
            removed_pairs.extend(before_names - after_names)
            added_pairs.extend(after_names - before_names)
            corrected_tipco_hosts.extend(fixed_subset)

        new_vbh = other_hosts + corrected_tipco_hosts
        after_total = sum(len(h.get("vulnerabilities") or []) for h in new_vbh)

        print(f"--- report_id={report_id} (admin_email={doc.get('admin_email')}) ---")
        print(f"  total_vulnerabilities: {before_total} -> {after_total}")
        print(f"  removed {len(removed_pairs)} mis-attributed pairing(s): {removed_pairs}")
        print(f"  added {len(added_pairs)} missing pairing(s): {added_pairs}")

        nessus_coll.update_one(
            {"report_id": report_id},
            {"$set": {"vulnerabilities_by_host": new_vbh, "total_vulnerabilities": after_total}},
        )

        # Sync vulnerability_cards for this report
        for host_name, plugin_name in removed_pairs:
            result = cards_coll.delete_many({
                "report_id": report_id, "host_name": host_name, "vulnerability_name": plugin_name,
            })
            print(f"    deleted {result.deleted_count} card(s) for ({host_name}, {plugin_name})")

        for host_name, plugin_name in added_pairs:
            template_card = cards_coll.find_one({"report_id": report_id, "vulnerability_name": plugin_name})
            if not template_card:
                print(f"    WARNING: no existing card to copy for ({host_name}, {plugin_name}) — skipped, no card created")
                continue
            new_card = copy.deepcopy(template_card)
            new_card.pop("_id", None)
            new_card["card_id"] = str(uuid.uuid4())
            new_card["host_name"] = host_name
            cards_coll.insert_one(new_card)
            print(f"    created 1 card for ({host_name}, {plugin_name}) — copied from card_id={template_card.get('card_id')}")

        print()

    print("Done.")


if __name__ == "__main__":
    main()
