"""
Same class of gap as fix_10_151_5_43_php.py: "Web Application Vulnerable
to Clickjacking" (Low) has its own full write-up in TIPCO External VA
Report, with "Host(s) Affected: 122.55.241.122" explicitly stated — but
GPT's original extraction of that file missed this finding on every
host, so there is no existing card anywhere to copy a template from
(unlike the Outdated PHP case).

Adds the finding's text (read directly from the source PDF) to
122.55.241.122 in every report that currently has that host, then
leaves card generation to the existing retry_incomplete_card_generation
management command (run separately) so the card gets a real,
GPT-generated automation/fix writeup instead of a fabricated one.

Run this yourself from your own terminal:
    python fix_122_55_241_122_clickjacking.py
"""
import os
import django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vaptfix.settings")
django.setup()

from vaptfix.mongo_client import get_shared_client, get_shared_db

TARGET_HOST = "122.55.241.122"
FINDING_NAME = "Web Application Vulnerable to Clickjacking"
DESCRIPTION = (
    "The remote web server does not set an X-Frame-Options response header or a "
    "Content-Security-Policy (CSP) with the frame-ancestors directive in all content "
    "responses. This could expose the application to clickjacking or UI redress attacks. "
    "In a clickjacking attack, a user could be tricked into interacting with a page or "
    "interface different from what is perceived. This can result in unintended actions, "
    "such as performing unauthorized transactions or leaking sensitive information."
)
SOLUTION = (
    "Configure the web server to include the X-Frame-Options header set to DENY or "
    "SAMEORIGIN, or configure the CSP frame-ancestors directive to restrict which "
    "sources can embed the web page. Update the web server's response headers "
    "accordingly."
)

NEW_VULN = {
    "plugin_id": None,
    "plugin_name": FINDING_NAME,
    "synopsis": "",
    "description": DESCRIPTION,
    "description_points": [DESCRIPTION],
    "solution": SOLUTION,
    "see_also": [
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
        "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
    ],
    "risk_factor": "Low",
    "cvss_v3_base_score": "",
    "plugin_information": "",
    "plugin_output": "",
    "plugin_output_url": None,
}


def main():
    db = get_shared_db(get_shared_client())
    nessus_coll = db["nessus_reports"]

    report_ids = sorted({
        doc["report_id"]
        for doc in nessus_coll.find({"vulnerabilities_by_host.host_name": TARGET_HOST}, {"report_id": 1})
    })
    print(f"Found {len(report_ids)} report(s) with {TARGET_HOST}: {report_ids}\n")

    for report_id in report_ids:
        doc = nessus_coll.find_one({"report_id": report_id})
        vbh = doc.get("vulnerabilities_by_host", [])
        target = next((h for h in vbh if h["host_name"] == TARGET_HOST), None)
        if not target:
            continue
        already = any(v.get("plugin_name") == FINDING_NAME for v in target.get("vulnerabilities") or [])
        if already:
            print(f"report_id={report_id}: already has the finding — skipped")
            continue

        target.setdefault("vulnerabilities", []).append(dict(NEW_VULN))
        new_total = sum(len(h.get("vulnerabilities") or []) for h in vbh)
        nessus_coll.update_one(
            {"report_id": report_id},
            {"$set": {"vulnerabilities_by_host": vbh, "total_vulnerabilities": new_total}},
        )
        print(f"report_id={report_id} (admin={doc.get('admin_email')}): added finding, total_vulnerabilities -> {new_total}")

    print("\nDone. Now generate the missing card(s) for real (GPT-written, not copied) via:")
    print("    python manage.py retry_incomplete_card_generation")


if __name__ == "__main__":
    main()
